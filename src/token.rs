// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::encryption::decrypt_element;
use crate::error::{fail, Result};
use crate::names::{self, CM_BEARER, SAML, SAML1, TRUST13, TRUST2005, WSP, WSP15, WSU};
use crate::replay::MemoryReplayCache;
use crate::signature::{verify_signed, IdpCert};
use crate::xml::{self, XmlDoc};
use chrono::{DateTime, Utc};
use rsa::RsaPrivateKey;
use std::collections::HashMap;
use ua_cryptography_xml_c14n::roxmltree::Node;

#[derive(Clone, Debug)]
pub struct Login {
    pub name_id: String,
    pub name_id_format: Option<String>,
    pub name_qualifier: Option<String>,
    pub sp_name_qualifier: Option<String>,
    pub authn_instant: DateTime<Utc>,
    pub attributes: HashMap<String, Vec<String>>,
    pub attribute_friendly_names: HashMap<String, String>,
    pub issuer: String,
    pub realm: String,
    pub trust_version: String,
    pub encrypted: bool,
    pub assertion_id: String,
    pub not_on_or_after: DateTime<Utc>,
    pub session_index: Option<String>,
    pub session_not_on_or_after: Option<DateTime<Utc>>,
    pub authn_context_class_ref: Option<String>,
    pub request_id: Option<String>,
    pub relay_state: Option<String>,
}

pub struct TokenContext<'a> {
    pub realm: &'a str,
    pub reply_url: &'a str,
    pub idp_entity_id: &'a str,
    pub idp_certificates: &'a [IdpCert],
    pub decryption_key: Option<&'a RsaPrivateKey>,
    pub clock_skew_ms: i64,
    pub want_assertions_encrypted: bool,
    pub replay: &'a MemoryReplayCache,
    pub now: Option<DateTime<Utc>>,
}

fn invalid(message: impl Into<String>) -> crate::error::WsFedError {
    fail("validation", message)
}

fn malformed(message: impl Into<String>) -> crate::error::WsFedError {
    fail("message", message)
}

fn parse_instant(value: &str, what: &str) -> Result<Option<DateTime<Utc>>> {
    if value.is_empty() {
        return Ok(None);
    }
    let ok = value.len() >= 20
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value.as_bytes()[10] == b'T'
        && value.as_bytes()[13] == b':'
        && value.as_bytes()[16] == b':'
        && value.ends_with('Z')
        && value.bytes().all(|byte| byte.is_ascii_digit() || matches!(byte, b'-' | b'T' | b':' | b'.' | b'Z'));
    if !ok {
        return Err(invalid(format!("{what} is not a UTC dateTime: {value}")));
    }
    let normalized = value.replacen('Z', "+00:00", 1);
    let parsed = DateTime::parse_from_rfc3339(&normalized).map_err(|_| invalid(format!("{what} is not a dateTime: {value}")))?;
    Ok(Some(parsed.with_timezone(&Utc)))
}

fn millis(moment: DateTime<Utc>) -> i64 {
    moment.timestamp_millis()
}

fn iso_time(moment: DateTime<Utc>) -> String {
    format!("{}.{:03}Z", moment.format("%Y-%m-%dT%H:%M:%S"), moment.timestamp_subsec_millis())
}

fn ns_of(node: Node) -> String {
    match node.tag_name().namespace() {
        Some(uri) if !uri.is_empty() => uri.to_string(),
        _ => "no namespace".to_string(),
    }
}

fn element_children<'a>(node: Node<'a, 'a>) -> Vec<Node<'a, 'a>> {
    node.children().filter(|child| child.is_element()).collect()
}

fn first_child<'a>(node: Node<'a, 'a>, ns: &str, local: &str) -> Option<Node<'a, 'a>> {
    xml::children(node, ns, local).into_iter().next()
}

fn response_of<'a>(root: Node<'a, 'a>) -> Result<(Node<'a, 'a>, &'static str, &'static str)> {
    if xml::is_el(root, TRUST13, "RequestSecurityTokenResponseCollection") {
        let all = xml::children(root, TRUST13, "RequestSecurityTokenResponse");
        if all.len() != 1 {
            return Err(malformed(format!("the RequestSecurityTokenResponseCollection holds {} responses; exactly one is accepted", all.len())));
        }
        return Ok((all[0], TRUST13, "1.3"));
    }
    if xml::is_el(root, TRUST2005, "RequestSecurityTokenResponse") {
        return Ok((root, TRUST2005, "2005/02"));
    }
    if xml::is_el(root, TRUST13, "RequestSecurityTokenResponse") {
        return Ok((root, TRUST13, "1.3"));
    }
    Err(malformed(format!("wresult is a <{}> in {}, not a WS-Trust RequestSecurityTokenResponse", root.tag_name().name(), ns_of(root))))
}

struct Prepared {
    canonical: String,
    trust_version: String,
    encrypted: bool,
}

pub fn validate_token(wresult: &str, ctx: &TokenContext<'_>) -> Result<Login> {
    let now = ctx.now.unwrap_or_else(Utc::now);
    let now_ms = millis(now);
    let skew = ctx.clock_skew_ms;
    let doc = XmlDoc::parse(wresult, "wresult")?;
    let prepared = doc.with(|root| -> Result<Prepared> {
        xml::assert_unique_ids(root)?;
        let (rstr, trust, trust_version) = response_of(root)?;
        if let Some(token_type_el) = xml::child(rstr, trust, "TokenType")? {
            let token_type = xml::text_of(token_type_el);
            if !token_type.is_empty() && !names::is_saml2_token(&token_type) {
                return Err(malformed(format!("the response carries a token of type {token_type}; this relying party accepts SAML 2.0 assertions only")));
            }
        }
        let mut applies = xml::children(rstr, WSP, "AppliesTo");
        applies.extend(xml::children(rstr, WSP15, "AppliesTo"));
        if applies.len() > 1 {
            return Err(malformed("the response has more than one AppliesTo"));
        }
        if applies.len() == 1 {
            let scopes = xml::wsa_addresses(applies[0]);
            if !scopes.is_empty() && !scopes.iter().any(|scope| scope == ctx.realm) {
                return Err(invalid(format!("the response applies to {}, not to {}", scopes.join(", "), ctx.realm)));
            }
        }
        if let Some(lifetime) = xml::child(rstr, trust, "Lifetime")? {
            let raw = first_child(lifetime, WSU, "Expires").map(xml::text_of).unwrap_or_default();
            if let Some(expires) = parse_instant(&raw, "the response's Lifetime Expires")? {
                if millis(expires) <= now_ms - skew {
                    return Err(invalid(format!("the response expired at {}", iso_time(expires))));
                }
            }
        }
        let requested = xml::children(rstr, trust, "RequestedSecurityToken");
        if requested.len() != 1 {
            return Err(malformed(format!("the response holds {} RequestedSecurityToken elements; exactly one is accepted", requested.len())));
        }
        let tokens = element_children(requested[0]);
        if tokens.len() != 1 {
            return Err(malformed(format!("the RequestedSecurityToken holds {} tokens; exactly one is accepted", tokens.len())));
        }
        let token = tokens[0];
        let (assertion_xml, encrypted) = if xml::is_el(token, SAML, "Assertion") {
            if ctx.want_assertions_encrypted {
                return Err(invalid("the assertion is not encrypted, and wantAssertionsEncrypted is on"));
            }
            (None, false)
        } else if xml::is_el(token, SAML, "EncryptedAssertion") || xml::is_el(token, names::XENC, "EncryptedData") {
            let key = ctx.decryption_key.ok_or_else(|| fail("decryption", "the assertion is encrypted, and this relying party has no privateKey to decrypt it with"))?;
            let plain = decrypt_element(token, key)?;
            (Some(plain), true)
        } else if xml::is_el(token, SAML1, "Assertion") {
            return Err(malformed("the token is a SAML 1.1 assertion; this relying party accepts SAML 2.0 assertions only. Ask for SAML 2.0 (requestTokenType, the default), or configure the identity provider to issue it to this realm"));
        } else {
            return Err(malformed(format!("the RequestedSecurityToken holds a <{}>, not a SAML 2.0 assertion", token.tag_name().name())));
        };
        let canonical = if let Some(plain) = assertion_xml {
            let inner = XmlDoc::parse(&plain, "the decrypted assertion")?;
            inner.with(|assertion| -> Result<String> {
                xml::assert_unique_ids(assertion)?;
                if xml::is_el(assertion, SAML1, "Assertion") {
                    return Err(malformed("the encrypted token is a SAML 1.1 assertion; this relying party accepts SAML 2.0 assertions only"));
                }
                if !xml::is_el(assertion, SAML, "Assertion") {
                    return Err(invalid("the encrypted token does not hold a SAML 2.0 Assertion"));
                }
                signed_xml(assertion, ctx)
            })??
        } else {
            signed_xml(token, ctx)?
        };
        Ok(Prepared { canonical, trust_version: trust_version.to_string(), encrypted })
    })??;
    let signed = XmlDoc::parse(&prepared.canonical, "the signed assertion")?;
    signed.with(|assertion| read_assertion(assertion, ctx, &prepared, now_ms, skew))?
}

fn signed_xml(assertion: Node, ctx: &TokenContext<'_>) -> Result<String> {
    match verify_signed(assertion, ctx.idp_certificates, "the assertion")? {
        Some(xml) => Ok(xml),
        None => Err(invalid("the assertion is not signed; in WS-Federation its signature is the only one, so it is required")),
    }
}

fn attr_instant(node: Node, name: &str, what: &str) -> Result<Option<DateTime<Utc>>> {
    match xml::attr(node, name) {
        Some(value) => parse_instant(&value, what),
        None => Ok(None),
    }
}

fn read_assertion(assertion: Node, ctx: &TokenContext<'_>, prepared: &Prepared, now_ms: i64, skew: i64) -> Result<Login> {
    if xml::attr(assertion, "Version").as_deref() != Some("2.0") {
        return Err(invalid("the assertion is not version 2.0"));
    }
    let assertion_id = xml::attr(assertion, "ID").unwrap_or_default();
    if assertion_id.is_empty() {
        return Err(invalid("the assertion has no ID"));
    }
    let issuer = xml::child(assertion, SAML, "Issuer")?.ok_or_else(|| invalid("the assertion has no Issuer"))?;
    if let Some(format) = xml::attr(issuer, "Format") {
        if !format.is_empty() && format != "urn:oasis:names:tc:SAML:2.0:nameid-format:entity" {
            return Err(invalid(format!("the assertion's Issuer has the Format {format}")));
        }
    }
    let issuer_text = xml::text_of(issuer);
    if issuer_text != ctx.idp_entity_id {
        return Err(invalid(format!("the assertion was issued by {issuer_text}, not by {}", ctx.idp_entity_id)));
    }
    let subject = xml::child(assertion, SAML, "Subject")?.ok_or_else(|| invalid("the assertion has no Subject"))?;
    let name_owned = name_id_of(subject, ctx)?;
    let conditions = xml::child(assertion, SAML, "Conditions")?.ok_or_else(|| invalid("the assertion has no Conditions, so it names no audience"))?;
    let not_before = attr_instant(conditions, "NotBefore", "Conditions NotBefore")?;
    let not_on_or_after = attr_instant(conditions, "NotOnOrAfter", "Conditions NotOnOrAfter")?;
    let mut reasons = Vec::new();
    let mut confirmed_until = None;
    for confirmation in xml::children(subject, SAML, "SubjectConfirmation") {
        let method = xml::attr(confirmation, "Method").unwrap_or_default();
        if method != CM_BEARER {
            reasons.push(format!("method {method}"));
            continue;
        }
        let Some(data) = xml::child(confirmation, SAML, "SubjectConfirmationData")? else {
            if not_on_or_after.is_none() {
                reasons.push("no SubjectConfirmationData, and no Conditions NotOnOrAfter to bound it".to_string());
                continue;
            }
            confirmed_until = not_on_or_after;
            break;
        };
        let recipient = xml::attr(data, "Recipient");
        let mut until = attr_instant(data, "NotOnOrAfter", "SubjectConfirmationData NotOnOrAfter")?;
        if until.is_none() {
            until = not_on_or_after;
        }
        if recipient.as_ref().is_some_and(|value| value != ctx.reply_url) {
            reasons.push(format!("Recipient {}", recipient.unwrap_or_default()));
        } else if until.is_none() {
            reasons.push("no NotOnOrAfter, on the confirmation or the Conditions".to_string());
        } else if millis(until.unwrap()) <= now_ms - skew {
            reasons.push(format!("expired at {}", iso_time(until.unwrap())));
        } else if xml::attr(data, "NotBefore").is_some() {
            reasons.push("a NotBefore, which a bearer confirmation must not have".to_string());
        } else if let Some(irt) = xml::attr(data, "InResponseTo") {
            reasons.push(format!("InResponseTo {irt}, which answers a SAML request, not a WS-Federation sign-in"));
        } else {
            confirmed_until = until;
            break;
        }
    }
    let Some(confirmed_until) = confirmed_until else {
        let why = if reasons.is_empty() { "there is none".to_string() } else { reasons.join("; ") };
        return Err(invalid(format!("no bearer SubjectConfirmation of the assertion fits: {why}")));
    };
    if let Some(not_before) = not_before {
        if millis(not_before) > now_ms + skew {
            return Err(invalid(format!("the assertion is not valid before {}", iso_time(not_before))));
        }
    }
    if let Some(not_on_or_after) = not_on_or_after {
        if millis(not_on_or_after) <= now_ms - skew {
            return Err(invalid(format!("the assertion expired at {}", iso_time(not_on_or_after))));
        }
    }
    let restrictions = xml::children(conditions, SAML, "AudienceRestriction");
    if restrictions.is_empty() {
        return Err(invalid("the assertion has no AudienceRestriction"));
    }
    for restriction in restrictions {
        let ok = xml::children(restriction, SAML, "Audience").into_iter().any(|audience| xml::text_of(audience) == ctx.realm);
        if !ok {
            return Err(invalid(format!("the assertion is not for {}", ctx.realm)));
        }
    }
    let authn_all = xml::children(assertion, SAML, "AuthnStatement");
    if authn_all.is_empty() {
        return Err(invalid("the assertion has no AuthnStatement"));
    }
    let authn = authn_all[0];
    let authn_instant = attr_instant(authn, "AuthnInstant", "AuthnInstant")?.ok_or_else(|| invalid("the AuthnStatement has no AuthnInstant"))?;
    let session_not = attr_instant(authn, "SessionNotOnOrAfter", "SessionNotOnOrAfter")?;
    if let Some(session_not) = session_not {
        if millis(session_not) <= now_ms - skew {
            return Err(invalid("the identity provider's session has already ended"));
        }
    }
    let class_ref = xml::child(authn, SAML, "AuthnContext")?
        .and_then(|context| first_child(context, SAML, "AuthnContextClassRef"))
        .map(xml::text_of)
        .filter(|value| !value.is_empty());
    let mut attributes: HashMap<String, Vec<String>> = HashMap::new();
    let mut friendly = HashMap::new();
    for statement in xml::children(assertion, SAML, "AttributeStatement") {
        let mut decrypted = Vec::new();
        for encrypted_attr in xml::children(statement, SAML, "EncryptedAttribute") {
            let key = ctx.decryption_key.ok_or_else(|| fail("decryption", "an attribute is encrypted, and this relying party has no privateKey to decrypt it with"))?;
            let plain = decrypt_element(encrypted_attr, key)?;
            let parsed = XmlDoc::parse(&plain, "the decrypted attribute")?;
            let owned = parsed.with(|element| -> Result<(String, Vec<String>, Option<String>)> {
                if !xml::is_el(element, SAML, "Attribute") {
                    return Err(invalid("an EncryptedAttribute does not hold an Attribute"));
                }
                Ok(attribute_parts(element))
            })??;
            decrypted.push(owned);
        }
        for attribute in xml::children(statement, SAML, "Attribute") {
            let (name, values, friendly_name) = attribute_parts(attribute);
            push_attribute(&mut attributes, &mut friendly, name, values, friendly_name);
        }
        for (name, values, friendly_name) in decrypted {
            push_attribute(&mut attributes, &mut friendly, name, values, friendly_name);
        }
    }
    let mut keep = millis(confirmed_until);
    if let Some(not_on_or_after) = not_on_or_after {
        keep = keep.max(millis(not_on_or_after));
    }
    keep += skew;
    let replay_id = format!("{} {assertion_id}", ctx.idp_entity_id);
    if ctx.replay.check_and_record(&replay_id, keep)? {
        return Err(fail("replay", format!("the assertion {assertion_id} has been accepted before")));
    }
    let (name_id, name_id_format, name_qualifier, sp_name_qualifier) = name_owned;
    Ok(Login {
        name_id,
        name_id_format,
        name_qualifier,
        sp_name_qualifier,
        authn_instant,
        attributes,
        attribute_friendly_names: friendly,
        issuer: ctx.idp_entity_id.to_string(),
        realm: ctx.realm.to_string(),
        trust_version: prepared.trust_version.clone(),
        encrypted: prepared.encrypted,
        assertion_id,
        not_on_or_after: confirmed_until,
        session_index: xml::attr(authn, "SessionIndex").filter(|value| !value.is_empty()),
        session_not_on_or_after: session_not,
        authn_context_class_ref: class_ref,
        request_id: None,
        relay_state: None,
    })
}

fn attribute_parts(attribute: Node) -> (String, Vec<String>, Option<String>) {
    let name = xml::attr(attribute, "Name").unwrap_or_default();
    let values = xml::children(attribute, SAML, "AttributeValue").into_iter().map(xml::text_content).collect();
    let friendly_name = xml::attr(attribute, "FriendlyName").filter(|value| !value.is_empty());
    (name, values, friendly_name)
}

fn push_attribute(attributes: &mut HashMap<String, Vec<String>>, friendly: &mut HashMap<String, String>, name: String, values: Vec<String>, friendly_name: Option<String>) {
    if name.is_empty() {
        return;
    }
    attributes.entry(name.clone()).or_default().extend(values);
    if let Some(friendly_name) = friendly_name {
        friendly.insert(name, friendly_name);
    }
}

fn name_id_of(subject: Node, ctx: &TokenContext<'_>) -> Result<(String, Option<String>, Option<String>, Option<String>)> {
    if xml::child(subject, SAML, "NameID")?.is_none() {
        if let Some(encrypted) = xml::child(subject, SAML, "EncryptedID")? {
            let key = ctx.decryption_key.ok_or_else(|| fail("decryption", "the NameID is encrypted, and this relying party has no privateKey to decrypt it with"))?;
            let plain = decrypt_element(encrypted, key)?;
            let parsed = XmlDoc::parse(&plain, "the decrypted NameID")?;
            return parsed.with(|name| -> Result<(String, Option<String>, Option<String>, Option<String>)> {
                if !xml::is_el(name, SAML, "NameID") {
                    return Err(invalid("the EncryptedID does not hold a NameID"));
                }
                owned_name(name)
            })?;
        }
    }
    let name = xml::child(subject, SAML, "NameID")?.ok_or_else(|| invalid("the assertion's Subject has no NameID"))?;
    owned_name(name)
}

fn owned_name(name: Node) -> Result<(String, Option<String>, Option<String>, Option<String>)> {
    let text = xml::text_of(name);
    if text.is_empty() {
        return Err(invalid("the assertion's Subject has no NameID"));
    }
    Ok((
        text,
        xml::attr(name, "Format").filter(|value| !value.is_empty()),
        xml::attr(name, "NameQualifier").filter(|value| !value.is_empty()),
        xml::attr(name, "SPNameQualifier").filter(|value| !value.is_empty()),
    ))
}
