// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::error::{Result, WsFedError};
use crate::signature::sign_enveloped;
use crate::x509util::{create_self_signed_key_pair, load_private_key};
use aes::Aes128;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use cbc::Encryptor;
use chrono::{Duration, Utc};
use cipher::{block_padding::Pkcs7, BlockModeEncrypt, KeyIvInit};
use rand::rngs::OsRng;
use rsa::traits::PublicKeyParts;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::Sha256;
use std::sync::OnceLock;

pub const IDP_ENTITY: &str = "https://idp.test";
pub const PASSIVE: &str = "https://idp.test/wsfed";
pub const REALM: &str = "https://rp.test/";
pub const REPLY: &str = "https://rp.test/wsfed";

struct Keys {
    rp_key: String,
    rp_cert: String,
    idp_key: String,
    idp_cert: String,
    rp_public: RsaPublicKey,
}

fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let rp = create_self_signed_key_pair("rp", 30, 2048).expect("rp key");
        let idp = create_self_signed_key_pair("idp", 30, 2048).expect("idp key");
        let private_key = load_private_key(&rp.private_key_pem).expect("rp parse");
        Keys {
            rp_public: rsa::RsaPublicKey::from(&private_key),
            rp_key: rp.private_key_pem,
            rp_cert: rp.certificate_pem,
            idp_key: idp.private_key_pem,
            idp_cert: idp.certificate_pem,
        }
    })
}

pub fn rp_key() -> &'static str { &keys().rp_key }
pub fn rp_cert() -> &'static str { &keys().rp_cert }
pub fn idp_key() -> &'static str { &keys().idp_key }
pub fn idp_cert() -> &'static str { &keys().idp_cert }

fn pem_body(value: &str) -> String {
    value.lines().filter(|line| !line.contains("-----") && !line.trim().is_empty()).map(str::trim).collect()
}

pub struct MetaOptions {
    pub key_in: &'static str,
    pub token_types: Option<Vec<&'static str>>,
    pub fed_prefix: &'static str,
    pub no_sts: bool,
}

impl Default for MetaOptions {
    fn default() -> Self { Self { key_in: "sts", token_types: None, fed_prefix: "fed", no_sts: false } }
}

pub fn idp_metadata(opts: &MetaOptions) -> String {
    let fed = opts.fed_prefix;
    let key = format!("<md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>", pem_body(idp_cert()));
    let types = opts.token_types.clone().unwrap_or_else(|| vec!["urn:oasis:names:tc:SAML:1.0:assertion", "urn:oasis:names:tc:SAML:2.0:assertion"]);
    let type_xml = types.iter().map(|token| format!("<{fed}:TokenType Uri=\"{token}\"/>")).collect::<String>();
    let sts_key = if opts.key_in == "idpsso" { String::new() } else { key.clone() };
    let sts = if opts.no_sts { String::new() } else {
        format!("\n  <md:RoleDescriptor xsi:type=\"{fed}:SecurityTokenServiceType\" protocolSupportEnumeration=\"http://docs.oasis-open.org/wsfed/federation/200706\">\n    {sts_key}\n    <{fed}:TokenTypesOffered>{type_xml}</{fed}:TokenTypesOffered>\n    <{fed}:SecurityTokenServiceEndpoint><wsa:EndpointReference><wsa:Address>https://idp.test/sts</wsa:Address></wsa:EndpointReference></{fed}:SecurityTokenServiceEndpoint>\n    <{fed}:PassiveRequestorEndpoint><wsa:EndpointReference><wsa:Address>{PASSIVE}</wsa:Address></wsa:EndpointReference></{fed}:PassiveRequestorEndpoint>\n  </md:RoleDescriptor>")
    };
    format!("<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:{fed}=\"http://docs.oasis-open.org/wsfed/federation/200706\" xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" entityID=\"{IDP_ENTITY}\">{sts}\n  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n    {key}\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp.test/saml2/sso\"/>\n  </md:IDPSSODescriptor>\n</md:EntityDescriptor>")
}

fn iso(offset: Duration) -> String {
    let moment = Utc::now() + offset;
    format!("{}.{:03}Z", moment.format("%Y-%m-%dT%H:%M:%S"), moment.timestamp_subsec_millis())
}

fn new_id() -> String {
    let bytes: [u8; 16] = rand::random();
    format!("_{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

pub struct AssertionOptions {
    pub audience: Option<String>,
    pub recipient: Option<String>,
    pub recipient_set: bool,
    pub in_response_to: String,
    pub not_on_or_after: Duration,
    pub not_on_or_after_set: bool,
    pub issuer: String,
    pub name_id: String,
    pub session_index: String,
    pub extra_attributes: String,
    pub bare_confirmation: bool,
    pub no_conditions_expiry: bool,
}

impl Default for AssertionOptions {
    fn default() -> Self {
        Self {
            audience: None, recipient: None, recipient_set: false, in_response_to: String::new(),
            not_on_or_after: Duration::seconds(300), not_on_or_after_set: false, issuer: String::new(),
            name_id: String::new(), session_index: String::new(), extra_attributes: String::new(),
            bare_confirmation: false, no_conditions_expiry: false,
        }
    }
}

pub struct Made { pub xml: String, pub id: String }

pub fn assertion_xml(opts: &AssertionOptions) -> Made {
    let aid = new_id();
    let recipient = if opts.recipient_set { opts.recipient.clone().unwrap_or_default() } else { REPLY.to_string() };
    let recipient_attr = if recipient.is_empty() { String::new() } else { format!(" Recipient=\"{recipient}\"") };
    let irt = if opts.in_response_to.is_empty() { String::new() } else { format!(" InResponseTo=\"{}\"", opts.in_response_to) };
    let offset = if opts.not_on_or_after_set { opts.not_on_or_after } else { Duration::seconds(300) };
    let confirmation = if opts.bare_confirmation {
        "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"/>".to_string()
    } else {
        format!("<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData{recipient_attr} NotOnOrAfter=\"{}\"{irt}/></saml:SubjectConfirmation>", iso(offset))
    };
    let expiry = if opts.no_conditions_expiry { String::new() } else { format!(" NotOnOrAfter=\"{}\"", iso(offset)) };
    let issuer = if opts.issuer.is_empty() { IDP_ENTITY } else { opts.issuer.as_str() };
    let name = if opts.name_id.is_empty() { "alice-1234" } else { opts.name_id.as_str() };
    let session = if opts.session_index.is_empty() { "_session1" } else { opts.session_index.as_str() };
    let audience = opts.audience.clone().unwrap_or_else(|| REALM.to_string());
    let claims = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims";
    let xml = format!(
        "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{aid}\" Version=\"2.0\" IssueInstant=\"{}\"><saml:Issuer>{issuer}</saml:Issuer><saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">{name}</saml:NameID>{confirmation}</saml:Subject><saml:Conditions NotBefore=\"{}\"{expiry}><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement><saml:Attribute Name=\"{claims}/nameidentifier\"><saml:AttributeValue>urn:uuid:alice</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"{claims}/emailaddress\" FriendlyName=\"mail\"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"http://schemas.microsoft.com/ws/2008/06/identity/claims/role\"><saml:AttributeValue>staff</saml:AttributeValue><saml:AttributeValue>admins</saml:AttributeValue></saml:Attribute>{}</saml:AttributeStatement><saml:AuthnStatement AuthnInstant=\"{}\" SessionIndex=\"{session}\"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>",
        iso(Duration::zero()), iso(Duration::seconds(-5)), opts.extra_attributes, iso(Duration::seconds(-1))
    );
    Made { xml, id: aid }
}

pub fn sign_xml(xml: &str, element_id: &str, key_pem: &str, cert_pem: &str) -> Result<String> {
    let key_pem = if key_pem.is_empty() { idp_key() } else { key_pem };
    let cert_pem = if cert_pem.is_empty() { idp_cert() } else { cert_pem };
    let key = load_private_key(key_pem)?;
    sign_enveloped(xml, element_id, &key, cert_pem)
}

pub fn signed_assertion(opts: &AssertionOptions) -> Result<Made> {
    let made = assertion_xml(opts);
    let xml = sign_xml(&made.xml, &made.id, "", "")?;
    Ok(Made { xml, id: made.id })
}

pub fn encrypt(plain: &str, cipher_name: &str, transport: &str, wrapper: &str) -> Result<String> {
    let cipher_name = if cipher_name.is_empty() { "aes-256-gcm" } else { cipher_name };
    let transport = if transport.is_empty() { "mgf1p" } else { transport };
    let wrapper = if wrapper.is_empty() { "EncryptedAssertion" } else { wrapper };
    let (key, value, alg) = match cipher_name {
        "aes-256-gcm" => {
            let key: [u8; 32] = rand::random();
            let iv: [u8; 12] = rand::random();
            let cipher = Aes256Gcm::new_from_slice(&key).map_err(|err| crate::fail("decryption", err.to_string()))?;
            let sealed = cipher.encrypt(&Nonce::from(iv), plain.as_bytes()).map_err(|err| crate::fail("decryption", err.to_string()))?;
            let mut value = iv.to_vec();
            value.extend(sealed);
            (key.to_vec(), value, "http://www.w3.org/2009/xmlenc11#aes256-gcm")
        }
        "aes-128-cbc" => {
            let key: [u8; 16] = rand::random();
            let iv: [u8; 16] = rand::random();
            let enc = Encryptor::<Aes128>::new_from_slices(&key, &iv).map_err(|err| crate::fail("decryption", err.to_string()))?;
            let mut buf = vec![0u8; plain.len() + 16];
            buf[..plain.len()].copy_from_slice(plain.as_bytes());
            let out = enc.encrypt_padded::<Pkcs7>(&mut buf, plain.len()).map_err(|err| crate::fail("decryption", err.to_string()))?.to_vec();
            let mut value = iv.to_vec();
            value.extend(out);
            (key.to_vec(), value, "http://www.w3.org/2001/04/xmlenc#aes128-cbc")
        }
        other => return Err(crate::fail("decryption", other)),
    };
    let public = &keys().rp_public;
    let _ = public.n();
    let (wrapped, key_method) = match transport {
        "mgf1p" => {
            let wrapped = public.encrypt(&mut OsRng, Oaep::new::<Sha1>(), &key).map_err(|err| crate::fail("decryption", err.to_string()))?;
            (wrapped, "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"/>".to_string())
        }
        "oaep256" => {
            let wrapped = public.encrypt(&mut OsRng, Oaep::new::<Sha256>(), &key).map_err(|err| crate::fail("decryption", err.to_string()))?;
            (wrapped, "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#rsa-oaep\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><xenc11:MGF xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" Algorithm=\"http://www.w3.org/2009/xmlenc11#mgf1sha256\"/></xenc:EncryptionMethod>".to_string())
        }
        other => return Err(crate::fail("decryption", other)),
    };
    let data = format!("<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><xenc:EncryptionMethod Algorithm=\"{alg}\"/><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><xenc:EncryptedKey>{key_method}<xenc:CipherData><xenc:CipherValue>{}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>{}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>", STANDARD.encode(wrapped), STANDARD.encode(value));
    if wrapper == "none" { return Ok(data); }
    Ok(format!("<saml:{wrapper} xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">{data}</saml:{wrapper}>"))
}

pub struct WResultOptions {
    pub token: Option<String>,
    pub trust: String,
    pub applies_to: String,
    pub token_type: String,
    pub expires: Duration,
    pub expires_set: bool,
}

impl Default for WResultOptions {
    fn default() -> Self {
        Self { token: None, trust: String::new(), applies_to: String::new(), token_type: String::new(), expires: Duration::hours(1), expires_set: false }
    }
}

pub fn wresult(opts: &WResultOptions) -> Result<String> {
    let body = if let Some(token) = &opts.token { token.clone() } else { signed_assertion(&AssertionOptions::default())?.xml };
    let ns = if opts.trust == "1.3" { "http://docs.oasis-open.org/ws-sx/ws-trust/200512" } else { "http://schemas.xmlsoap.org/ws/2005/02/trust" };
    let applies = if opts.applies_to.is_empty() { REALM } else { opts.applies_to.as_str() };
    let expires = if opts.expires_set { opts.expires } else { Duration::hours(1) };
    let token_type = if opts.token_type.is_empty() { "urn:oasis:names:tc:SAML:2.0:assertion" } else { opts.token_type.as_str() };
    let rstr = format!("<t:RequestSecurityTokenResponse xmlns:t=\"{ns}\"><t:Lifetime><wsu:Created xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">{}</wsu:Created><wsu:Expires xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">{}</wsu:Expires></t:Lifetime><wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\"><wsa:EndpointReference xmlns:wsa=\"http://www.w3.org/2005/08/addressing\"><wsa:Address>{applies}</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><t:RequestedSecurityToken>{body}</t:RequestedSecurityToken><t:TokenType>{token_type}</t:TokenType><t:RequestType>{ns}/Issue</t:RequestType><t:KeyType>{ns}/Bearer</t:KeyType></t:RequestSecurityTokenResponse>", iso(Duration::zero()), iso(expires));
    if opts.trust == "1.3" {
        return Ok(format!("<t:RequestSecurityTokenResponseCollection xmlns:t=\"{ns}\">{rstr}</t:RequestSecurityTokenResponseCollection>"));
    }
    Ok(rstr)
}

pub fn saml11() -> String {
    format!("<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" MajorVersion=\"1\" MinorVersion=\"1\" AssertionID=\"{}\" Issuer=\"{IDP_ENTITY}\" IssueInstant=\"{}\"><saml:AttributeStatement><saml:Subject><saml:NameIdentifier>alice</saml:NameIdentifier></saml:Subject></saml:AttributeStatement></saml:Assertion>", new_id(), iso(Duration::zero()))
}

pub fn rejects<T>(err: &std::result::Result<T, WsFedError>, code: &str, pattern: &str) {
    let Err(err) = err else { panic!("expected an error") };
    assert_eq!(err.code, code, "{}", err.message);
    if !pattern.is_empty() {
        let ok = pattern.split('|').any(|part| err.message.contains(&part.replace("\\.", ".")));
        assert!(ok, "pattern {pattern} not in {}", err.message);
    }
}

pub fn _unused_private() -> RsaPrivateKey { load_private_key(idp_key()).unwrap() }
