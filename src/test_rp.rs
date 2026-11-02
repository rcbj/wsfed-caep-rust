// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use super::test_support::{self as stub, AssertionOptions, MetaOptions, WResultOptions};
use crate::config::resolve_config;
use crate::error::WsFedError;
use crate::names::{self, DEFAULT_SUBJECT_ATTRIBUTE, RSA_SHA256, STATUS_SUCCESS};
use crate::relying_party::{LoginOptions, ReplyBody, ReplyRequest, RelyingParty};
use crate::test_support::{rejects, IDP_ENTITY, PASSIVE, REALM, REPLY};
use serde_json::{json, Map, Value};
use std::path::Path;

fn obj(pairs: &[(&str, Value)]) -> Map<String, Value> {
    pairs.iter().map(|(key, value)| ((*key).to_string(), value.clone())).collect()
}

fn cfg(extra: &[(&str, Value)], meta: Option<&MetaOptions>) -> Map<String, Value> {
    let mut body = obj(&[
        ("realm", json!(REALM)),
        ("replyUrl", json!(REPLY)),
        ("privateKey", json!(stub::rp_key())),
        ("certificate", json!(stub::rp_cert())),
        ("idpMetadata", json!(stub::idp_metadata(meta.unwrap_or(&MetaOptions::default())))),
    ]);
    for (key, value) in extra { body.insert((*key).to_string(), value.clone()); }
    body
}

fn must_rp(config: &Map<String, Value>) -> RelyingParty {
    RelyingParty::create(config, Path::new(".")).unwrap_or_else(|err| panic!("{err}"))
}

fn post(rp: &RelyingParty, result: &str, request_id: Option<&str>, wctx: Option<&str>, ids: Option<Vec<String>>) -> Result<crate::token::Login, WsFedError> {
    let mut body = std::collections::HashMap::new();
    body.insert("wa".to_string(), "wsignin1.0".to_string());
    body.insert("wresult".to_string(), result.to_string());
    let wctx_owned;
    let wctx = if wctx.is_none() {
        if let Some(id) = request_id { wctx_owned = format!("id={id}"); Some(wctx_owned.as_str()) } else { None }
    } else { wctx };
    if let Some(wctx) = wctx { body.insert("wctx".to_string(), wctx.to_string()); }
    let ids = ids.unwrap_or_else(|| request_id.map(|id| vec![id.to_string()]).unwrap_or_default());
    rp.handle_reply(ReplyRequest { method: "POST".to_string(), url: "/wsfed".to_string(), body: ReplyBody::Map(body) }, &ids)
}

fn qparams(raw: &str) -> std::collections::HashMap<String, String> {
    let query = raw.split_once('?').map(|(_, query)| query).unwrap_or("");
    crate::relying_party::first_map(query)
}

fn same_config(left: &crate::config::Resolved, right: &crate::config::Resolved) -> bool {
    left.realm == right.realm && left.reply_url == right.reply_url && left.idp_metadata == right.idp_metadata
        && left.clock_skew_ms == right.clock_skew_ms && left.want_assertions_encrypted == right.want_assertions_encrypted
        && left.allow_unsolicited == right.allow_unsolicited && left.request_token_type == right.request_token_type
        && left.idp_ca == right.idp_ca && left.idp_entity_id == right.idp_entity_id
        && left.private_key.is_none() && right.private_key.is_none()
}

#[test]
fn configuration_requires_realm_reply_and_a_matching_key() {
    let mut bad = cfg(&[], None);
    bad.insert("realm".to_string(), json!(""));
    rejects(&RelyingParty::create(&bad, Path::new(".")).map(|_| ()), "config", "realm");
    let mut bad = cfg(&[], None);
    bad.insert("replyUrl".to_string(), json!("/wsfed"));
    rejects(&RelyingParty::create(&bad, Path::new(".")).map(|_| ()), "config", "absolute");
    let mut bad = cfg(&[], None);
    bad.insert("certificate".to_string(), json!(stub::idp_cert()));
    rejects(&RelyingParty::create(&bad, Path::new(".")).map(|_| ()), "config", "not for the private key");
    let missing = obj(&[("realm", json!(REALM)), ("replyUrl", json!(REPLY)), ("idpMetadata", json!(stub::idp_metadata(&MetaOptions::default()))), ("privateKey", json!(stub::rp_key()))]);
    rejects(&RelyingParty::create(&missing, Path::new(".")).map(|_| ()), "config", "together");
    let encrypted = obj(&[("realm", json!(REALM)), ("replyUrl", json!(REPLY)), ("idpMetadata", json!(stub::idp_metadata(&MetaOptions::default()))), ("wantAssertionsEncrypted", json!(true))]);
    rejects(&RelyingParty::create(&encrypted, Path::new(".")).map(|_| ()), "config", "needs privateKey");
    let keyless = must_rp(&obj(&[("realm", json!(REALM)), ("replyUrl", json!(REPLY)), ("idpMetadata", json!(stub::idp_metadata(&MetaOptions::default())))]));
    assert!(!keyless.metadata_xml().contains("KeyDescriptor"));
}

#[test]
fn signals_omitted_or_true_is_left_off() {
    let base = obj(&[("realm", json!(REALM)), ("replyUrl", json!(REPLY)), ("idpMetadata", json!("https://idp.example/FederationMetadata/2007-06/FederationMetadata.xml"))]);
    let omitted = resolve_config(&base, Path::new(".")).unwrap();
    assert!(!omitted.signals_set);
    assert_eq!(omitted.realm, REALM);
    assert!(omitted.request_token_type);
    let mut on = base.clone();
    on.insert("signals".to_string(), json!(true));
    let resolved = resolve_config(&on, Path::new(".")).unwrap();
    assert!(!resolved.signals_set && same_config(&resolved, &omitted));
}

#[test]
fn signals_false_is_recorded() {
    let base = obj(&[("realm", json!(REALM)), ("replyUrl", json!(REPLY)), ("idpMetadata", json!("https://idp.example/FederationMetadata/2007-06/FederationMetadata.xml"))]);
    let mut off_map = base.clone();
    off_map.insert("signals".to_string(), json!(false));
    let off = resolve_config(&off_map, Path::new(".")).unwrap();
    assert!(off.signals_set && !off.signals);
    let omitted = resolve_config(&base, Path::new(".")).unwrap();
    assert!(same_config(&off, &omitted));
}

#[test]
fn signals_must_be_true_or_false() {
    let mut bad = obj(&[("realm", json!(REALM)), ("replyUrl", json!(REPLY)), ("idpMetadata", json!("https://idp.example/metadata"))]);
    bad.insert("signals".to_string(), json!("no"));
    let err = resolve_config(&bad, Path::new("."));
    let Err(err) = err else { panic!("expected an error") };
    assert_eq!(err.code, "config");
    assert_eq!(err.message, "signals must be true or false");
}

#[test]
fn reads_the_security_token_service_role() {
    let rp = must_rp(&cfg(&[], None));
    let idp = rp.idp.as_ref().unwrap();
    assert_eq!(idp.entity_id, IDP_ENTITY);
    assert_eq!(idp.passive_requestor_endpoint, PASSIVE);
    assert!(idp.token_types_offered.iter().any(|item| item == names::SAML2_TOKEN));
    assert_eq!(idp.signing_certificates.len(), 1);
}

#[test]
fn xsi_type_and_idp_role_fallback() {
    let prefixed = MetaOptions { fed_prefix: "wsfed", ..MetaOptions::default() };
    assert_eq!(must_rp(&cfg(&[], Some(&prefixed))).idp.as_ref().unwrap().passive_requestor_endpoint, PASSIVE);
    let fallback = MetaOptions { key_in: "idpsso", ..MetaOptions::default() };
    assert_eq!(must_rp(&cfg(&[], Some(&fallback))).idp.as_ref().unwrap().signing_certificates.len(), 1);
}

#[test]
fn refuses_metadata_without_an_sts_or_saml2() {
    let no_sts = MetaOptions { no_sts: true, ..MetaOptions::default() };
    rejects(&RelyingParty::create(&cfg(&[], Some(&no_sts)), Path::new(".")).map(|_| ()), "metadata", "SecurityTokenServiceType");
    let types = MetaOptions { token_types: Some(vec!["urn:oasis:names:tc:SAML:1.0:assertion"]), ..MetaOptions::default() };
    rejects(&RelyingParty::create(&cfg(&[], Some(&types)), Path::new(".")).map(|_| ()), "metadata", "no SAML 2.0");
}

#[test]
fn writes_application_service_metadata() {
    let xml = must_rp(&cfg(&[], None)).metadata_xml();
    assert!(xml.contains(&format!("entityID=\"{REALM}\"")), "{xml}");
    assert!(xml.contains("xsi:type=\"fed:ApplicationServiceType\""));
    assert!(xml.contains(&format!("<fed:PassiveRequestorEndpoint><wsa:EndpointReference><wsa:Address>{REPLY}</wsa:Address>")));
    assert!(xml.contains(&format!("<fed:TargetScopes><wsa:EndpointReference><wsa:Address>{REALM}</wsa:Address>")));
    assert!(xml.contains("xmlenc11#aes256-gcm") && xml.contains("<md:KeyDescriptor use=\"encryption\">"));
}

#[test]
fn signin_names_realm_reply_wctx_and_saml2() {
    let rp = must_rp(&cfg(&[], None));
    let req = rp.login(&LoginOptions { relay_state: Some("/home é".to_string()), ..LoginOptions::default() }).unwrap();
    let params = qparams(&req.url);
    assert!(req.url.starts_with(PASSIVE));
    assert_eq!(params["wa"], "wsignin1.0");
    assert_eq!(params["wtrealm"], REALM);
    assert_eq!(params["wreply"], REPLY);
    let wctx = crate::relying_party::first_map(&params["wctx"]);
    assert_eq!(wctx["id"], req.id);
    assert_eq!(wctx["ru"], "/home é");
    assert!(params["wreq"].contains("<wst:TokenType>urn:oasis:names:tc:SAML:2.0:assertion</wst:TokenType>"));
    assert_eq!(params["wct"].len(), 20);
    assert!(!params.contains_key("wfresh"));
}

#[test]
fn force_authn_and_protocol_params() {
    let rp = must_rp(&cfg(&[("requestTokenType", json!(false))], None));
    let mut params = std::collections::HashMap::new();
    params.insert("login_hint".to_string(), "alice".to_string());
    let req = rp.login(&LoginOptions { force_authn: true, authentication_method: "http://schemas.microsoft.com/claims/multipleauthn".to_string(), home_realm: "urn:partner".to_string(), params, ..LoginOptions::default() }).unwrap();
    let got = qparams(&req.url);
    assert_eq!(got["wfresh"], "0");
    assert_eq!(got["wauth"], "http://schemas.microsoft.com/claims/multipleauthn");
    assert_eq!(got["whr"], "urn:partner");
    assert_eq!(got["login_hint"], "alice");
    assert!(!got.contains_key("wreq"));
    let mut evil = std::collections::HashMap::new();
    evil.insert("wtrealm".to_string(), "urn:evil".to_string());
    rejects(&rp.login(&LoginOptions { params: evil, ..LoginOptions::default() }).map(|_| ()), "config", "protocol's own");
    rejects(&rp.login(&LoginOptions { relay_state: Some("x".repeat(1025)), ..LoginOptions::default() }).map(|_| ()), "config", "1024 bytes");
}

#[test]
fn signout_request() {
    let rp = must_rp(&cfg(&[], None));
    let params = qparams(&rp.logout("https://rp.test/").unwrap());
    assert_eq!(params["wa"], "wsignout1.0");
    assert_eq!(params["wtrealm"], REALM);
    assert_eq!(params["wreply"], "https://rp.test/");
}

#[test]
fn signed_assertion_in_a_2005_response() {
    let rp = must_rp(&cfg(&[], None));
    let req = rp.login(&LoginOptions { relay_state: Some("/home".to_string()), ..LoginOptions::default() }).unwrap();
    let result = stub::wresult(&WResultOptions::default()).unwrap();
    let who = post(&rp, &result, Some(&req.id), Some(&req.wctx), None).unwrap();
    assert_eq!(who.name_id, "alice-1234");
    assert_eq!(who.name_id_format.as_deref(), Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"));
    assert_eq!(who.session_index.as_deref(), Some("_session1"));
    assert_eq!(who.relay_state.as_deref(), Some("/home"));
    assert_eq!(who.request_id.as_deref(), Some(req.id.as_str()));
    assert_eq!(who.trust_version, "2005/02");
    assert!(!who.encrypted);
    assert_eq!(who.attributes["http://schemas.microsoft.com/ws/2008/06/identity/claims/role"].join(","), "staff,admins");
    assert_eq!(who.attribute_friendly_names["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"], "mail");
    assert_eq!(who.authn_context_class_ref.as_deref(), Some("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"));
}

#[test]
fn trust_13_and_a_raw_form_body() {
    let rp = must_rp(&cfg(&[], None));
    let result = stub::wresult(&WResultOptions { trust: "1.3".to_string(), ..WResultOptions::default() }).unwrap();
    let who = post(&rp, &result, Some("_r"), None, None).unwrap();
    assert_eq!(who.trust_version, "1.3");
    let signed = stub::wresult(&WResultOptions::default()).unwrap();
    let raw = format!("wa=wsignin1.0&wresult={}&wctx=id%3D_s", crate::relying_party::query_escape(&signed));
    let who = rp.handle_reply(ReplyRequest { method: "POST".to_string(), url: "/wsfed".to_string(), body: ReplyBody::Text(raw) }, &["_x".to_string(), "_s".to_string()]).unwrap();
    assert_eq!(who.name_id, "alice-1234");
}

#[test]
fn recipient_optional_and_checked() {
    let rp = must_rp(&cfg(&[], None));
    let made = stub::signed_assertion(&AssertionOptions { recipient_set: true, recipient: Some(String::new()), ..AssertionOptions::default() }).unwrap();
    let result = stub::wresult(&WResultOptions { token: Some(made.xml), ..WResultOptions::default() }).unwrap();
    assert_eq!(post(&rp, &result, Some("_r"), None, None).unwrap().name_id, "alice-1234");
    let made = stub::signed_assertion(&AssertionOptions { recipient_set: true, recipient: Some("https://other.test/wsfed".to_string()), ..AssertionOptions::default() }).unwrap();
    let result = stub::wresult(&WResultOptions { token: Some(made.xml), ..WResultOptions::default() }).unwrap();
    rejects(&post(&rp, &result, Some("_r"), None, None).map(|_| ()), "validation", "Recipient");
}

#[test]
fn bare_bearer_confirmation() {
    let rp = must_rp(&cfg(&[], None));
    let made = stub::signed_assertion(&AssertionOptions { bare_confirmation: true, ..AssertionOptions::default() }).unwrap();
    let result = stub::wresult(&WResultOptions { token: Some(made.xml), ..WResultOptions::default() }).unwrap();
    let who = post(&rp, &result, Some("_r"), None, None).unwrap();
    assert_eq!(who.name_id, "alice-1234");
    assert!(who.not_on_or_after > chrono::Utc::now());
    let made = stub::signed_assertion(&AssertionOptions { bare_confirmation: true, not_on_or_after: chrono::Duration::seconds(-120), not_on_or_after_set: true, ..AssertionOptions::default() }).unwrap();
    let result = stub::wresult(&WResultOptions { token: Some(made.xml), ..WResultOptions::default() }).unwrap();
    rejects(&post(&rp, &result, Some("_r"), None, None).map(|_| ()), "validation", "expired");
    let made = stub::signed_assertion(&AssertionOptions { bare_confirmation: true, no_conditions_expiry: true, ..AssertionOptions::default() }).unwrap();
    let result = stub::wresult(&WResultOptions { token: Some(made.xml), ..WResultOptions::default() }).unwrap();
    rejects(&post(&rp, &result, Some("_r"), None, None).map(|_| ()), "validation", "nothing|no Conditions NotOnOrAfter");
}

#[test]
fn unsigned_assertion_is_refused() {
    let made = stub::assertion_xml(&AssertionOptions::default());
    let result = stub::wresult(&WResultOptions { token: Some(made.xml), ..WResultOptions::default() }).unwrap();
    rejects(&post(&must_rp(&cfg(&[], None)), &result, Some("_r"), None, None).map(|_| ()), "validation", "not signed");
}

#[test]
fn altered_or_wrong_key_is_refused() {
    let rp = must_rp(&cfg(&[], None));
    let made = stub::signed_assertion(&AssertionOptions::default()).unwrap();
    let result = stub::wresult(&WResultOptions { token: Some(made.xml.replace("alice-1234", "mallory")), ..WResultOptions::default() }).unwrap();
    rejects(&post(&rp, &result, Some("_r"), None, None).map(|_| ()), "signature", "");
    let plain = stub::assertion_xml(&AssertionOptions::default());
    let signed = stub::sign_xml(&plain.xml, &plain.id, stub::rp_key(), stub::rp_cert()).unwrap();
    let result = stub::wresult(&WResultOptions { token: Some(signed), ..WResultOptions::default() }).unwrap();
    rejects(&post(&rp, &result, Some("_r"), None, None).map(|_| ()), "signature", "does not verify");
}

#[test]
fn signature_wrapping() {
    let rp = must_rp(&cfg(&[], None));
    let signed = stub::signed_assertion(&AssertionOptions::default()).unwrap();
    let forged = stub::assertion_xml(&AssertionOptions { name_id: "mallory".to_string(), ..AssertionOptions::default() });
    let both = format!("{}{}", forged.xml, signed.xml);
    let result = stub::wresult(&WResultOptions { token: Some(both), ..WResultOptions::default() }).unwrap();
    rejects(&post(&rp, &result, Some("_r"), None, None).map(|_| ()), "message", "exactly one");
    let hidden = forged.xml.replacen(&format!("ID=\"{}\"", forged.id), &format!("ID=\"{}\"", signed.id), 1).replacen("</saml:Assertion>", &format!("<saml:Advice>{}</saml:Advice></saml:Assertion>", signed.xml), 1);
    let result = stub::wresult(&WResultOptions { token: Some(hidden), ..WResultOptions::default() }).unwrap();
    rejects(&post(&rp, &result, Some("_r"), None, None).map(|_| ()), "signature", "two elements");
    let decoy = stub::wresult(&WResultOptions { token: Some(signed.xml.clone()), ..WResultOptions::default() }).unwrap().replacen("<t:Lifetime>", &format!("<t:Lifetime xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"{}\">", signed.id), 1);
    rejects(&post(&rp, &decoy, Some("_r"), None, None).map(|_| ()), "signature", "two elements");
    let start = signed.xml.find("<ds:Signature").unwrap();
    let end = signed.xml.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
    let sig = &signed.xml[start..end];
    let moved = forged.xml.replacen("</saml:Issuer>", &format!("</saml:Issuer>{sig}"), 1);
    let result = stub::wresult(&WResultOptions { token: Some(moved), ..WResultOptions::default() }).unwrap();
    rejects(&post(&rp, &result, Some("_r"), None, None).map(|_| ()), "signature", "refers to");
}

#[test]
fn wrong_realm_issuer_or_expiry() {
    let rp = must_rp(&cfg(&[], None));
    let made = stub::signed_assertion(&AssertionOptions { audience: Some("https://other.test/".to_string()), ..AssertionOptions::default() }).unwrap();
    let result = stub::wresult(&WResultOptions { token: Some(made.xml), ..WResultOptions::default() }).unwrap();
    rejects(&post(&rp, &result, Some("_r"), None, None).map(|_| ()), "validation", "not for");
    let made = stub::signed_assertion(&AssertionOptions { issuer: "https://evil.test".to_string(), ..AssertionOptions::default() }).unwrap();
    let result = stub::wresult(&WResultOptions { token: Some(made.xml), ..WResultOptions::default() }).unwrap();
    rejects(&post(&rp, &result, Some("_r"), None, None).map(|_| ()), "validation", "issued by");
    let made = stub::signed_assertion(&AssertionOptions { not_on_or_after: chrono::Duration::seconds(-120), not_on_or_after_set: true, ..AssertionOptions::default() }).unwrap();
    let result = stub::wresult(&WResultOptions { token: Some(made.xml), ..WResultOptions::default() }).unwrap();
    rejects(&post(&rp, &result, Some("_r"), None, None).map(|_| ()), "validation", "expired");
    let result = stub::wresult(&WResultOptions { applies_to: "https://other.test/".to_string(), ..WResultOptions::default() }).unwrap();
    rejects(&post(&rp, &result, Some("_r"), None, None).map(|_| ()), "validation", "applies to");
    let result = stub::wresult(&WResultOptions { expires: chrono::Duration::seconds(-120), expires_set: true, ..WResultOptions::default() }).unwrap();
    rejects(&post(&rp, &result, Some("_r"), None, None).map(|_| ()), "validation", "response expired");
}

#[test]
fn in_response_to_is_refused() {
    let made = stub::signed_assertion(&AssertionOptions { in_response_to: "_samlreq".to_string(), ..AssertionOptions::default() }).unwrap();
    let result = stub::wresult(&WResultOptions { token: Some(made.xml), ..WResultOptions::default() }).unwrap();
    rejects(&post(&must_rp(&cfg(&[], None)), &result, Some("_r"), None, None).map(|_| ()), "validation", "InResponseTo");
}

#[test]
fn saml11_and_non_trust_are_refused() {
    let rp = must_rp(&cfg(&[], None));
    let token = stub::saml11();
    let result = stub::wresult(&WResultOptions { token: Some(token), token_type: "urn:oasis:names:tc:SAML:2.0:assertion".to_string(), ..WResultOptions::default() }).unwrap();
    rejects(&post(&rp, &result, Some("_r"), None, None).map(|_| ()), "message", "SAML 1\\.1");
    let result = stub::wresult(&WResultOptions { token_type: "urn:oasis:names:tc:SAML:1.0:assertion".to_string(), ..WResultOptions::default() }).unwrap();
    rejects(&post(&rp, &result, Some("_r"), None, None).map(|_| ()), "message", "SAML 2.0 assertions only");
    let made = stub::signed_assertion(&AssertionOptions::default()).unwrap();
    rejects(&post(&rp, &made.xml, Some("_r"), None, None).map(|_| ()), "message", "not a WS-Trust");
    let result = stub::wresult(&WResultOptions::default()).unwrap();
    rejects(&post(&rp, &format!("<!DOCTYPE x [<!ENTITY e \"x\">]>{result}"), Some("_r"), None, None).map(|_| ()), "xml", "DOCTYPE");
}

#[test]
fn unsolicited_and_unknown_requests() {
    let rp = must_rp(&cfg(&[], None));
    let result = stub::wresult(&WResultOptions::default()).unwrap();
    rejects(&post(&rp, &result, Some("_other"), Some("id=_r"), None).map(|_| ()), "validation", "not a sign-in this browser");
    rejects(&post(&rp, &result, None, Some("id=_r"), Some(Vec::new())).map(|_| ()), "validation", "not a sign-in this browser");
    rejects(&post(&rp, &result, None, None, Some(Vec::new())).map(|_| ()), "validation", "unsolicited");
    let open = must_rp(&cfg(&[("allowUnsolicited", json!(true))], None));
    let who = post(&open, &result, None, Some("ru=%2Fthere"), Some(Vec::new())).unwrap();
    assert!(who.request_id.is_none());
    assert_eq!(who.relay_state.as_deref(), Some("/there"));
}

#[test]
fn replay() {
    let rp = must_rp(&cfg(&[], None));
    let result = stub::wresult(&WResultOptions::default()).unwrap();
    post(&rp, &result, Some("_r"), None, None).unwrap();
    rejects(&post(&rp, &result, Some("_r"), None, None).map(|_| ()), "replay", "");
}

#[test]
fn decrypts_encrypted_assertions() {
    let rp = must_rp(&cfg(&[], None));
    for name in ["aes-256-gcm", "aes-128-cbc"] {
        let made = stub::signed_assertion(&AssertionOptions::default()).unwrap();
        let enc = stub::encrypt(&made.xml, name, "", "").unwrap();
        let result = stub::wresult(&WResultOptions { token: Some(enc), ..WResultOptions::default() }).unwrap();
        let who = post(&rp, &result, Some("_r"), None, None).unwrap_or_else(|err| panic!("{name} {err}"));
        assert_eq!(who.name_id, "alice-1234");
        assert!(who.encrypted, "{name}");
    }
    let made = stub::signed_assertion(&AssertionOptions::default()).unwrap();
    let enc = stub::encrypt(&made.xml, "aes-256-gcm", "oaep256", "none").unwrap();
    let result = stub::wresult(&WResultOptions { token: Some(enc), ..WResultOptions::default() }).unwrap();
    assert!(post(&rp, &result, Some("_r"), None, None).unwrap().encrypted);
}

#[test]
fn want_assertions_encrypted_and_tampered_ciphertext() {
    let rp = must_rp(&cfg(&[("wantAssertionsEncrypted", json!(true))], None));
    let result = stub::wresult(&WResultOptions::default()).unwrap();
    rejects(&post(&rp, &result, Some("_r"), None, None).map(|_| ()), "validation", "not encrypted");
    let plain = stub::assertion_xml(&AssertionOptions::default());
    let enc = stub::encrypt(&plain.xml, "", "", "").unwrap();
    let result = stub::wresult(&WResultOptions { token: Some(enc), ..WResultOptions::default() }).unwrap();
    rejects(&post(&rp, &result, Some("_r"), None, None).map(|_| ()), "validation", "not signed");
    let made = stub::signed_assertion(&AssertionOptions::default()).unwrap();
    let enc = stub::encrypt(&made.xml, "", "", "").unwrap();
    let start = enc.rfind("<xenc:CipherValue>").unwrap() + "<xenc:CipherValue>".len();
    let end = enc[start..].find("</xenc:CipherValue>").unwrap() + start;
    let last = enc[start..end].to_string();
    let mut raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &last).unwrap();
    raw[20] ^= 1;
    let replaced = enc.replacen(&last, &base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &raw), 1);
    let result = stub::wresult(&WResultOptions { token: Some(replaced), ..WResultOptions::default() }).unwrap();
    rejects(&post(&rp, &result, Some("_r"), None, None).map(|_| ()), "decryption", "");
}

#[test]
fn encrypted_attribute_and_missing_key() {
    let keyless = must_rp(&obj(&[("realm", json!(REALM)), ("replyUrl", json!(REPLY)), ("idpMetadata", json!(stub::idp_metadata(&MetaOptions::default())))]));
    let made = stub::signed_assertion(&AssertionOptions::default()).unwrap();
    let enc = stub::encrypt(&made.xml, "", "", "").unwrap();
    let result = stub::wresult(&WResultOptions { token: Some(enc), ..WResultOptions::default() }).unwrap();
    rejects(&post(&keyless, &result, Some("_r"), None, None).map(|_| ()), "decryption", "no privateKey");
    let rp = must_rp(&cfg(&[], None));
    let secret = stub::encrypt("<saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"employeeNumber\"><saml:AttributeValue>E-42</saml:AttributeValue></saml:Attribute>", "aes-256-gcm", "oaep256", "EncryptedAttribute").unwrap();
    let plain = stub::assertion_xml(&AssertionOptions { extra_attributes: secret, ..AssertionOptions::default() });
    let signed = stub::sign_xml(&plain.xml, &plain.id, "", "").unwrap();
    let result = stub::wresult(&WResultOptions { token: Some(signed), ..WResultOptions::default() }).unwrap();
    let who = post(&rp, &result, Some("_r"), None, None).unwrap();
    assert_eq!(who.attributes["employeeNumber"].join(","), "E-42");
}

#[test]
fn reply_url_refuses_get_wrong_wa_and_wresultptr() {
    let rp = must_rp(&cfg(&[], None));
    let result = stub::wresult(&WResultOptions::default()).unwrap();
    rejects(&rp.handle_reply(ReplyRequest { method: "GET".to_string(), url: format!("/wsfed?wa=wsignin1.0&wresult={}", crate::relying_party::query_escape(&result)), body: ReplyBody::Empty }, &[]).map(|_| ()), "message", "POSTed");
    let mut body = std::collections::HashMap::new();
    body.insert("wa".to_string(), "wattr1.0".to_string());
    body.insert("wresult".to_string(), result.clone());
    rejects(&rp.handle_reply(ReplyRequest { method: "POST".to_string(), url: "/wsfed".to_string(), body: ReplyBody::Map(body) }, &[]).map(|_| ()), "message", "not wsignin1.0");
    let mut body = std::collections::HashMap::new();
    body.insert("wa".to_string(), "wsignin1.0".to_string());
    body.insert("wresultptr".to_string(), "https://evil.test/".to_string());
    rejects(&rp.handle_reply(ReplyRequest { method: "POST".to_string(), url: "/wsfed".to_string(), body: ReplyBody::Map(body) }, &[]).map(|_| ()), "message", "wresultptr");
    let mut body = std::collections::HashMap::new();
    body.insert("wa".to_string(), "wsignin1.0".to_string());
    rejects(&rp.handle_reply(ReplyRequest { method: "POST".to_string(), url: "/wsfed".to_string(), body: ReplyBody::Map(body) }, &[]).map(|_| ()), "message", "no wresult");
}

#[test]
fn sign_out_cleanup() {
    let rp = must_rp(&cfg(&[], None));
    assert!(rp.is_sign_out_cleanup(&ReplyRequest { method: "GET".to_string(), url: "/wsfed?wa=wsignoutcleanup1.0".to_string(), body: ReplyBody::Empty }));
    assert!(rp.is_sign_out_cleanup(&ReplyRequest { method: "POST".to_string(), url: "/wsfed".to_string(), body: ReplyBody::Text("wa=wsignout1.0".to_string()) }));
    let mut body = std::collections::HashMap::new();
    body.insert("wa".to_string(), "wsignin1.0".to_string());
    assert!(!rp.is_sign_out_cleanup(&ReplyRequest { method: "POST".to_string(), url: "/wsfed".to_string(), body: ReplyBody::Map(body) }));
    rejects(&rp.handle_reply(ReplyRequest { method: "GET".to_string(), url: "/wsfed?wa=wsignoutcleanup1.0".to_string(), body: ReplyBody::Empty }, &[]).map(|_| ()), "message", "sign-out");
}

#[test]
fn status_success_constant() {
    assert_eq!(STATUS_SUCCESS, "urn:oasis:names:tc:SAML:2.0:status:Success");
    assert_eq!(RSA_SHA256, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    assert_eq!(DEFAULT_SUBJECT_ATTRIBUTE, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");
}
