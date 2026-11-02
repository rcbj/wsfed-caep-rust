// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::error::{fail, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use rsa::signature::Verifier;
use serde_json::{Map, Value};
use sha2::{Sha256, Sha384, Sha512};

const SUPPORTED: &str = "RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA, Ed25519";

fn b64url(value: &str, what: &str) -> Result<Vec<u8>> {
    if !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_') {
        return Err(fail("signature", format!("the SET's {what} is not base64url")));
    }
    URL_SAFE_NO_PAD.decode(value).map_err(|_| fail("signature", format!("the SET's {what} is not base64url")))
}

fn object_of(raw: &[u8]) -> Result<Map<String, Value>> {
    match serde_json::from_slice(raw) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(fail("signature", "the SET's header or payload is not JSON")),
    }
}

fn text_of(map: &Map<String, Value>, key: &str) -> String {
    map.get(key).and_then(|value| value.as_str()).unwrap_or("").to_string()
}

fn spec_of(alg: &str) -> Option<(&'static str, &'static str, bool)> {
    Some(match alg {
        "RS256" => ("RSA", "sha256", false),
        "RS384" => ("RSA", "sha384", false),
        "RS512" => ("RSA", "sha512", false),
        "PS256" => ("RSA", "sha256", true),
        "PS384" => ("RSA", "sha384", true),
        "PS512" => ("RSA", "sha512", true),
        "ES256" | "ES384" | "ES512" => ("EC", "", false),
        "EdDSA" | "Ed25519" => ("OKP", "", false),
        _ => return None,
    })
}

fn rsa_key(jwk: &Map<String, Value>) -> Option<RsaPublicKey> {
    let n = b64url(&text_of(jwk, "n"), "key").ok()?;
    let e = b64url(&text_of(jwk, "e"), "key").ok()?;
    RsaPublicKey::new(rsa::BigUint::from_bytes_be(&n), rsa::BigUint::from_bytes_be(&e)).ok()
}

fn verify_rsa(key: &RsaPublicKey, hash_name: &str, pss: bool, data: &[u8], signature: &[u8]) -> bool {
    if pss {
        let sig = rsa::pss::Signature::try_from(signature).ok();
        let Some(sig) = sig else { return false };
        return match hash_name {
            "sha256" => rsa::pss::VerifyingKey::<Sha256>::new(key.clone()).verify(data, &sig).is_ok(),
            "sha384" => rsa::pss::VerifyingKey::<Sha384>::new(key.clone()).verify(data, &sig).is_ok(),
            "sha512" => rsa::pss::VerifyingKey::<Sha512>::new(key.clone()).verify(data, &sig).is_ok(),
            _ => false,
        };
    }
    let sig = Signature::try_from(signature).ok();
    let Some(sig) = sig else { return false };
    match hash_name {
        "sha256" => VerifyingKey::<Sha256>::new(key.clone()).verify(data, &sig).is_ok(),
        "sha384" => VerifyingKey::<Sha384>::new(key.clone()).verify(data, &sig).is_ok(),
        "sha512" => VerifyingKey::<Sha512>::new(key.clone()).verify(data, &sig).is_ok(),
        _ => false,
    }
}

pub fn verify_compact_jws(token: &str, keys: &[Map<String, Value>]) -> Result<(Map<String, Value>, Map<String, Value>)> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(fail("signature", "the SET is not a compact JWS"));
    }
    let header = object_of(&b64url(parts[0], "header")?)?;
    let payload = object_of(&b64url(parts[1], "payload")?)?;
    let alg = text_of(&header, "alg");
    let Some((kty, hash_name, pss)) = spec_of(&alg) else {
        let shown = if alg.is_empty() { "(no alg)".to_string() } else { alg };
        return Err(fail("signature", format!("the SET is signed with {shown}, which this receiver does not verify ({SUPPORTED})")));
    };
    if header.contains_key("crit") {
        return Err(fail("signature", "the SET's header has a crit member this receiver does not understand"));
    }
    let kid = text_of(&header, "kid");
    let mut candidates = Vec::new();
    for key in keys {
        if !kid.is_empty() && text_of(key, "kid") != kid { continue; }
        if text_of(key, "kty") != kty { continue; }
        let use_name = text_of(key, "use");
        if !use_name.is_empty() && use_name != "sig" { continue; }
        let key_alg = text_of(key, "alg");
        if !key_alg.is_empty() && key_alg != alg { continue; }
        candidates.push(key);
    }
    if candidates.is_empty() {
        let suffix = if kid.is_empty() { String::new() } else { format!(" with kid {kid}") };
        return Err(fail("signature", format!("the transmitter publishes no {kty} signing key{suffix}")));
    }
    let data = format!("{}.{}", parts[0], parts[1]);
    let signature = b64url(parts[2], "signature")?;
    for jwk in candidates {
        if kty != "RSA" || hash_name.is_empty() {
            continue;
        }
        let Some(key) = rsa_key(jwk) else { continue };
        let _ = key.n();
        if verify_rsa(&key, hash_name, pss, data.as_bytes(), &signature) {
            return Ok((header, payload));
        }
    }
    Err(fail("signature", "the SET's signature does not verify against the transmitter's keys"))
}
