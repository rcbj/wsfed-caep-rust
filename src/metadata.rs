// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::error::{fail, Result};
use crate::httpclient;
use crate::names::{self, is_saml2_token, DS, FED, MD, SAML2_TOKEN, WSA, XSI};
use crate::signature::IdpCert;
use crate::x509util::{self, cert_from_der};
use crate::xml::{self, XmlDoc};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

pub struct IdpMetadata {
    pub entity_id: String,
    pub passive_requestor_endpoint: String,
    pub token_types_offered: Vec<String>,
    pub signing_certificates: Vec<IdpCert>,
}

const ENCRYPTION_METHODS: [&str; 4] = [
    "http://www.w3.org/2009/xmlenc11#aes256-gcm",
    "http://www.w3.org/2009/xmlenc11#aes128-gcm",
    "http://www.w3.org/2009/xmlenc11#rsa-oaep",
    "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
];

fn is_sts(node: ua_cryptography_xml_c14n::roxmltree::Node) -> bool {
    xml::is_el(node, MD, "RoleDescriptor") && xml::xsi_type(node).is_some_and(|(ns, local)| ns == FED && local == "SecurityTokenServiceType")
}

fn certificates_of(role: ua_cryptography_xml_c14n::roxmltree::Node, use_name: &str) -> Result<Vec<IdpCert>> {
    let mut out = Vec::new();
    for descriptor in xml::children(role, MD, "KeyDescriptor") {
        if let Some(declared) = xml::attr(descriptor, "use") {
            if !declared.is_empty() && declared != use_name { continue; }
        }
        for data in xml::descendants(descriptor, DS, "X509Data") {
            let first = xml::children(data, DS, "X509Certificate");
            if first.is_empty() { continue; }
            let body = xml::text_of(first[0]);
            let der = STANDARD.decode(body.chars().filter(|ch| !ch.is_whitespace()).collect::<String>()).map_err(|err| fail("metadata", format!("a {use_name} certificate in the identity provider's metadata cannot be read: {err}")))?;
            let cert = cert_from_der(&der).map_err(|err| fail("metadata", format!("a {use_name} certificate in the identity provider's metadata cannot be read: {err}")))?;
            out.push(cert);
        }
    }
    Ok(out)
}

fn fed_addresses(role: ua_cryptography_xml_c14n::roxmltree::Node, local: &str) -> Vec<String> {
    let mut out = Vec::new();
    for endpoint in xml::children(role, FED, local) {
        out.extend(xml::wsa_addresses(endpoint));
    }
    out
}

pub fn read_idp_metadata(xml_text: &str, entity_id: &str) -> Result<IdpMetadata> {
    let doc = XmlDoc::parse(xml_text, "the identity provider metadata")?;
    doc.with(|root| {
        let entity = if xml::is_el(root, MD, "EntityDescriptor") {
            root
        } else if xml::is_el(root, MD, "EntitiesDescriptor") {
            let all: Vec<_> = xml::descendants(root, MD, "EntityDescriptor").into_iter().filter(|item| xml::children(*item, MD, "RoleDescriptor").iter().any(|role| is_sts(*role))).collect();
            let found = if !entity_id.is_empty() {
                all.into_iter().find(|item| xml::attr(*item, "entityID").as_deref() == Some(entity_id))
            } else if all.len() == 1 {
                all.into_iter().next()
            } else {
                return Err(fail("metadata", format!("the metadata aggregate holds {} WS-Federation identity providers; name one with idpEntityId", all.len())));
            };
            found.ok_or_else(|| fail("metadata", format!("the metadata aggregate has no WS-Federation identity provider {entity_id}")))?
        } else {
            return Err(fail("metadata", "the identity provider metadata is not an EntityDescriptor"));
        };
        let identifier = xml::attr(entity, "entityID").unwrap_or_default();
        if identifier.is_empty() { return Err(fail("metadata", "the identity provider metadata has no entityID")); }
        if !entity_id.is_empty() && identifier != entity_id {
            return Err(fail("metadata", format!("the metadata describes {identifier}, not {entity_id}")));
        }
        let role = xml::children(entity, MD, "RoleDescriptor").into_iter().find(|item| is_sts(*item)).ok_or_else(|| fail("metadata", format!("{identifier}'s metadata has no fed:SecurityTokenServiceType RoleDescriptor, so it is not a WS-Federation identity provider")))?;
        let passive = fed_addresses(role, "PassiveRequestorEndpoint");
        if passive.is_empty() { return Err(fail("metadata", format!("{identifier}'s metadata names no PassiveRequestorEndpoint"))); }
        let endpoint = passive[0].clone();
        if !(endpoint.starts_with("https://") || endpoint.starts_with("http://")) || endpoint.trim_start_matches("https://").trim_start_matches("http://").is_empty() {
            return Err(fail("metadata", format!("{identifier}'s PassiveRequestorEndpoint {endpoint} is not an http(s) URL")));
        }
        let mut offered = Vec::new();
        for types in xml::children(role, FED, "TokenTypesOffered") {
            for token in xml::children(types, FED, "TokenType") {
                if let Some(uri) = xml::attr(token, "Uri") { if !uri.is_empty() { offered.push(uri); } }
            }
        }
        if !offered.is_empty() && !offered.iter().any(|token| is_saml2_token(token)) {
            return Err(fail("metadata", format!("{identifier} offers no SAML 2.0 token (it offers {})", offered.join(", "))));
        }
        let mut signing = certificates_of(role, "signing")?;
        if signing.is_empty() {
            if let Some(idp) = xml::children(entity, MD, "IDPSSODescriptor").into_iter().next() {
                signing = certificates_of(idp, "signing")?;
            }
        }
        if signing.is_empty() { return Err(fail("metadata", format!("{identifier}'s metadata names no signing certificate"))); }
        Ok(IdpMetadata { entity_id: identifier, passive_requestor_endpoint: endpoint, token_types_offered: offered, signing_certificates: signing })
    })?
}

pub fn write_rp_metadata(realm: &str, reply_url: &str, certificate: Option<&IdpCert>) -> String {
    let key = if let Some(certificate) = certificate {
        let methods = ENCRYPTION_METHODS.iter().map(|method| format!("\n      <md:EncryptionMethod Algorithm=\"{method}\"/>")).collect::<String>();
        format!("    <md:KeyDescriptor use=\"encryption\">\n      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>{methods}\n    </md:KeyDescriptor>\n", x509util::cert_pem_body(&certificate.der))
    } else { String::new() };
    let endpoint = |local: &str, address: &str| format!("    <fed:{local}><wsa:EndpointReference><wsa:Address>{}</wsa:Address></wsa:EndpointReference></fed:{local}>", xml::escape_xml(address));
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<md:EntityDescriptor xmlns:md=\"{MD}\" xmlns:ds=\"{DS}\" xmlns:fed=\"{FED}\" xmlns:wsa=\"{WSA}\" xmlns:xsi=\"{XSI}\" entityID=\"{}\">\n  <md:RoleDescriptor xsi:type=\"fed:ApplicationServiceType\" protocolSupportEnumeration=\"{FED}\">\n{key}    <fed:TokenTypesOffered><fed:TokenType Uri=\"{SAML2_TOKEN}\"/></fed:TokenTypesOffered>\n    <fed:TargetScopes><wsa:EndpointReference><wsa:Address>{}</wsa:Address></wsa:EndpointReference></fed:TargetScopes>\n{}\n{}\n{}\n  </md:RoleDescriptor>\n</md:EntityDescriptor>\n",
        xml::escape_xml(realm), xml::escape_xml(realm), endpoint("ApplicationServiceEndpoint", reply_url), endpoint("SingleSignOutNotificationEndpoint", reply_url), endpoint("PassiveRequestorEndpoint", reply_url)
    )
}

pub fn load_metadata_source(source: &str, ca: &str) -> Result<String> {
    if source.starts_with('<') { return Ok(source.to_string()); }
    if source.starts_with("http://") || source.starts_with("https://") {
        let tls = if ca.is_empty() { None } else { Some(httpclient::TlsMaterial { ca: Some(ca.to_string()), cert: None, key: None }) };
        let answer = httpclient::send(source, "GET", &[("accept", "application/samlmetadata+xml, application/xml, text/xml")], None, tls.as_ref(), "metadata")?;
        if answer.status != 200 { return Err(fail("metadata", format!("{source} answered HTTP {}", answer.status))); }
        return Ok(answer.body);
    }
    std::fs::read_to_string(source).map_err(|err| fail("metadata", format!("{source} cannot be read: {err}")))
}

pub fn _names() { let _ = names::FED; }
