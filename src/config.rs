// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::error::{fail, Result};
use crate::signature::IdpCert;
use crate::x509util::{load_cert, load_private_key};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct Resolved {
    pub realm: String,
    pub reply_url: String,
    pub idp_metadata: String,
    pub clock_skew_ms: i64,
    pub want_assertions_encrypted: bool,
    pub allow_unsolicited: bool,
    pub request_token_type: bool,
    pub signals_set: bool,
    pub signals: bool,
    pub private_key: Option<RsaPrivateKey>,
    pub certificate: Option<IdpCert>,
    pub idp_ca: String,
    pub idp_entity_id: String,
}

fn is_pem(value: &str) -> bool { value.contains("-----BEGIN ") }

fn material(value: &str, base_dir: &Path, what: &str) -> Result<String> {
    let mut value = value.to_string();
    if let Some(name) = value.strip_prefix("env:") {
        value = std::env::var(name).ok().filter(|item| !item.is_empty()).ok_or_else(|| fail("config", format!("{what} environment variable {name} is not set")))?;
    }
    if let Some(rest) = value.strip_prefix("file:") { value = rest.to_string(); }
    if is_pem(&value) { return Ok(value); }
    let path = if Path::new(&value).is_absolute() { PathBuf::from(&value) } else { base_dir.join(&value) };
    std::fs::read_to_string(&path).map_err(|err| fail("config", format!("{what} is neither a PEM nor a readable file ({}): {err}", path.display())))
}

fn absolute_url(value: Option<&Value>, what: &str) -> Result<String> {
    let text = value.and_then(|item| item.as_str()).unwrap_or("").trim().to_string();
    if text.is_empty() { return Err(fail("config", format!("{what} is required"))); }
    if !(text.starts_with("https://") || text.starts_with("http://")) {
        return Err(fail("config", format!("{what} must be an absolute http(s) URL, not {text}")));
    }
    let rest = text.trim_start_matches("https://").trim_start_matches("http://");
    if rest.is_empty() || rest.starts_with('/') {
        return Err(fail("config", format!("{what} must be an absolute http(s) URL, not {text}")));
    }
    Ok(text)
}

fn flag(value: Option<&Value>, fallback: bool, what: &str) -> Result<bool> {
    match value {
        None | Some(Value::Null) => Ok(fallback),
        Some(Value::Bool(bit)) => Ok(*bit),
        _ => Err(fail("config", format!("{what} must be true or false"))),
    }
}

fn as_float(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        _ => None,
    }
}

fn idp_metadata_ref(value: &str, base_dir: &Path) -> Result<String> {
    let mut value = value.trim().to_string();
    if let Some(name) = value.strip_prefix("env:") {
        value = std::env::var(name).ok().filter(|item| !item.is_empty()).ok_or_else(|| fail("config", format!("idpMetadata environment variable {name} is not set")))?.trim().to_string();
    }
    if let Some(rest) = value.strip_prefix("file:") { value = rest.to_string(); }
    if value.starts_with("http://") || value.starts_with("https://") || value.starts_with('<') { return Ok(value); }
    if Path::new(&value).is_absolute() { return Ok(value); }
    Ok(base_dir.join(value).to_string_lossy().into_owned())
}

pub fn resolve_config(config: &Map<String, Value>, base_dir: &Path) -> Result<Resolved> {
    let realm = config.get("realm").and_then(|item| item.as_str()).unwrap_or("").trim().to_string();
    if realm.is_empty() { return Err(fail("config", "realm is required")); }
    let reply = absolute_url(config.get("replyUrl"), "replyUrl")?;
    let raw_meta = config.get("idpMetadata").and_then(|item| item.as_str()).unwrap_or("").trim().to_string();
    if raw_meta.is_empty() { return Err(fail("config", "idpMetadata is required")); }
    let meta = idp_metadata_ref(&raw_meta, base_dir)?;
    let mut skew = 60.0;
    if let Some(value) = config.get("clockSkewSeconds").filter(|item| !item.is_null()) {
        let parsed = as_float(value).ok_or_else(|| fail("config", "clockSkewSeconds must be a number from 0 to 600"))?;
        if !(0.0..=600.0).contains(&parsed) { return Err(fail("config", "clockSkewSeconds must be a number from 0 to 600")); }
        skew = parsed;
    }
    let skew_ms = (skew * 1000.0) as i64;
    let signals = flag(config.get("signals"), true, "signals")?;
    let want = flag(config.get("wantAssertionsEncrypted"), false, "wantAssertionsEncrypted")?;
    let allow = flag(config.get("allowUnsolicited"), false, "allowUnsolicited")?;
    let request_type = flag(config.get("requestTokenType"), true, "requestTokenType")?;
    let mut out = Resolved {
        realm, reply_url: reply, idp_metadata: meta, clock_skew_ms: skew_ms,
        want_assertions_encrypted: want, allow_unsolicited: allow, request_token_type: request_type,
        signals_set: false, signals: true, private_key: None, certificate: None, idp_ca: String::new(), idp_entity_id: String::new(),
    };
    if !signals {
        out.signals_set = true;
        out.signals = false;
    }
    let key_present = config.get("privateKey").is_some_and(|item| !item.is_null());
    let cert_present = config.get("certificate").is_some_and(|item| !item.is_null());
    if key_present != cert_present {
        return Err(fail("config", "privateKey and certificate go together: give both or neither"));
    }
    if key_present && cert_present {
        let key_text = config["privateKey"].as_str().ok_or_else(|| fail("config", "the private key or certificate cannot be read: not a string"))?;
        let cert_text = config["certificate"].as_str().ok_or_else(|| fail("config", "the private key or certificate cannot be read: not a string"))?;
        let key_pem = material(key_text, base_dir, "privateKey")?;
        let cert_pem = material(cert_text, base_dir, "certificate")?;
        let private_key = load_private_key(&key_pem)?;
        let certificate = load_cert(&cert_pem)?;
        if private_key.n() != certificate.public_key.n() || private_key.e() != certificate.public_key.e() {
            return Err(fail("config", "the certificate is not for the private key"));
        }
        out.private_key = Some(private_key);
        out.certificate = Some(certificate);
    } else if out.want_assertions_encrypted {
        return Err(fail("config", "wantAssertionsEncrypted needs privateKey and certificate: the assertion is encrypted to them"));
    }
    if let Some(ca) = config.get("idpCa").and_then(|item| item.as_str()) {
        if !ca.is_empty() { out.idp_ca = material(ca, base_dir, "idpCa")?; }
    }
    if let Some(id) = config.get("idpEntityId").and_then(|item| item.as_str()) {
        if !id.is_empty() { out.idp_entity_id = id.to_string(); }
    }
    Ok(out)
}

pub fn read_config_file(path: &str, overrides: Option<&Map<String, Value>>) -> Result<Resolved> {
    let raw = std::fs::read_to_string(path).map_err(|err| fail("config", format!("{path} cannot be read as JSON: {err}")))?;
    let mut parsed: Value = serde_json::from_str(&raw).map_err(|err| fail("config", format!("{path} cannot be read as JSON: {err}")))?;
    let object = parsed.as_object_mut().ok_or_else(|| fail("config", "the configuration must be an object"))?;
    if let Some(overrides) = overrides {
        for (key, value) in overrides {
            if !value.is_null() { object.insert(key.clone(), value.clone()); }
        }
    }
    let full = std::fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));
    let base = full.parent().unwrap_or(Path::new("."));
    resolve_config(object, base)
}

pub fn parse_object(text: &str) -> Result<Map<String, Value>> {
    let value: Value = serde_json::from_str(text).map_err(|err| fail("config", err.to_string()))?;
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(fail("config", "the configuration must be an object")),
    }
}
