// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The embedded iya-sts PEP (the `pep` feature; rcbj/iya-sts#1206, this
//! repository's #40). The PEP itself is the shared `iya-pep` crate. This
//! library only wires it in:
//!
//! - **Configuration.** A `pep` section in `wsfed.json`, off unless present.
//!   `pdpUrl` defaults to the identity provider's entityID and `application`
//!   to `realm` (the wtrealm); `tlsCa` and `signals` follow the library's
//!   own unless the section says otherwise.
//!   - iya-sts publishes the realm's issuer as its WS-Federation entityID
//!     (one issuer per realm, in every protocol, iya-sts #523), and that is
//!     the service's base with the `/realm/<id>` prefix: what the PEP needs.
//!     The passive endpoint is that base plus `/wsfed`, and the metadata may
//!     be a file, so neither is a better source. An identity provider whose
//!     entityID is not an http(s) URL needs `pdpUrl` set.
//!   - iya-sts registers a WS-Federation relying party under its realm
//!     (`wsfedRealm`, the application's identifier), so the realm is the
//!     application the PEP is bound to.
//! - **Keys (D1).** The PEP's assertion key must differ from `privateKey`
//!   (the relying party's one key: it signs the metadata, decrypts
//!   assertions, and is the demo's Shared Signals client certificate key) and
//!   from the receiver's TLS client key. `RelyingParty::create` and
//!   `SignalsReceiver::new` refuse a configuration where two have the same
//!   JWK thumbprint.
//! - **The subject.** A validated sign-in (`Login`) becomes the PEP's
//!   subject: see [`subject_of`]. No request header is read.
//! - **Signals (D4).** A `SignalsReceiver` given the PEP asks for
//!   `pep-policies-changed` too (in `local` mode, or `central` with a Permit
//!   cache), verifies its SET like any other, and hands the event to the PEP.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde_json::{json, Map, Value};

use crate::config::Resolved;
use crate::error::{fail, Result};
use crate::token::Login;

pub use iya_pep::{Access, Decision, EventStream, Mode, Obligation, Pep, PepConfig, Status, Subject, POLICIES_CHANGED_EVENT};

/// The claim iya-sts puts the person's username in (its directory's
/// canonical uid), in both token types.
pub const NAME_CLAIM: &str = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
/// The claim that says how the person authenticated.
pub const AUTHENTICATION_METHOD_CLAIM: &str = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod";

/// Builds the PEP from the configuration's `pep` section, or `None` when
/// there is none. `issuer` is the identity provider's entityID, the default
/// `pdpUrl`. Checks that its key is not the relying party's.
pub(crate) fn build(config: &Resolved, issuer: &str) -> Result<Option<Arc<Pep>>> {
    let Some(section) = &config.pep else {
        return Ok(None);
    };
    let Some(map) = section.as_object() else {
        return Err(fail("config", "pep must be an object"));
    };
    let mut map = map.clone();
    // The library's own values, unless the section names its own.
    if !map.contains_key("signals") {
        map.insert("signals".into(), Value::Bool(config.signals));
    }
    if !map.contains_key("tlsCa") && config.idp_ca.contains("-----BEGIN") {
        map.insert("tlsCa".into(), Value::String(config.idp_ca.clone()));
    }
    let pep_config = PepConfig::from_json(&Value::Object(map), issuer, &config.realm).map_err(|err| fail("config", err.message))?;
    let pep = Pep::new(pep_config).map_err(|err| fail("config", err.message))?;
    if let Some(key) = &config.private_key {
        if rsa_thumbprint(key) == pep.key_thumbprint() {
            return Err(fail("config", "pep.assertionKey is the relying party's privateKey (its signing and decryption key); the PEP needs a key of its own"));
        }
    }
    Ok(Some(Arc::new(pep)))
}

/// The RFC 7638 thumbprint of an RSA key's public half.
fn rsa_thumbprint(key: &RsaPrivateKey) -> String {
    let jwk = json!({
        "kty": "RSA",
        "n": URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
        "e": URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
    });
    iya_pep::jwk_thumbprint(&jwk).unwrap_or_default()
}

/// The thumbprint of a PEM private key (RSA or EC P-256), or `None` for one
/// the PEP could not use anyway.
pub(crate) fn pem_thumbprint(pem: &str) -> Option<String> {
    iya_pep::key::SigningKey::from_pem(pem).ok().map(|key| key.thumbprint().to_string())
}

/// Whether a receiver given this PEP asks for `pep-policies-changed`.
pub(crate) fn wants_events(pep: &Pep) -> bool {
    pep.config().mode == Mode::Local || pep.config().permit_cache_ms > 0
}

/// The PEP's subject for a validated WS-Federation sign-in.
///
/// **The id** is what iya-sts's PIP resolves: a username. iya-sts's tokens
/// carry the username three ways, and two of them are usable:
/// - the `name` claim ([`NAME_CLAIM`]) is the directory's canonical uid
///   (`userFor()`'s `username`, after an alias typed at sign-in is
///   resolved), so it is preferred;
/// - the NameID is the session's username as well, so it is the fallback,
///   which also serves another identity provider that sends no `name`;
/// - the `nameidentifier` claim is the directory's opaque `sub`, which the
///   PIP does not look people up by, so it is never the id.
///
/// **The properties** are the assertion's attributes and how the person
/// authenticated. iya-sts's AuthZEN catalogue names a property with
/// `[A-Za-z0-9_$@:-]` segments joined by dots, so a claim URI
/// (`http://schemas.xmlsoap.org/...`) can never be declared: each attribute
/// is keyed by its FriendlyName, else the last segment of its Name
/// (`emailaddress`, `role`, `upn`), and one that has neither is left out. A
/// single value is a string, several an array. Then, from the signed
/// AuthnStatement and over any attribute of the same name:
/// - `acr`: the AuthnContextClassRef;
/// - `amr`: the `authenticationmethod` claim's values;
/// - `auth_time`: the AuthnInstant, in epoch seconds.
///
/// The PEP sends only the properties the realm's catalogue declares.
pub fn subject_of(login: &Login) -> Subject {
    let mut properties = Map::new();
    let mut names: Vec<&String> = login.attributes.keys().collect();
    names.sort();
    for name in names {
        let values = &login.attributes[name];
        let Some(key) = property_name(name, login.attribute_friendly_names.get(name).map(String::as_str)) else { continue };
        if values.is_empty() || properties.contains_key(&key) {
            continue;
        }
        let value = if values.len() == 1 { Value::String(values[0].clone()) } else { json!(values) };
        properties.insert(key, value);
    }
    if let Some(acr) = login.authn_context_class_ref.as_ref().filter(|value| !value.is_empty()) {
        properties.insert("acr".into(), Value::String(acr.clone()));
    }
    let methods: Vec<&String> = login.attributes.get(AUTHENTICATION_METHOD_CLAIM).map(|values| values.iter().filter(|value| !value.is_empty()).collect()).unwrap_or_default();
    if !methods.is_empty() {
        properties.insert("amr".into(), json!(methods));
    }
    properties.insert("auth_time".into(), json!(login.authn_instant.timestamp()));
    let username = login.attributes.get(NAME_CLAIM).and_then(|values| values.iter().find(|value| !value.is_empty()));
    let id = username.cloned().unwrap_or_else(|| login.name_id.clone());
    Subject::user(id, properties)
}

/// An attribute's property name: its FriendlyName, else the last segment of
/// its Name, when it is one the catalogue can declare.
fn property_name(name: &str, friendly: Option<&str>) -> Option<String> {
    let segment = |text: &str| !text.is_empty() && text.len() <= 64 && text.chars().all(|c| c.is_ascii_alphanumeric() || "_$@:-".contains(c));
    if let Some(friendly) = friendly.filter(|value| segment(value)) {
        return Some(friendly.to_string());
    }
    let last = name.rsplit('/').next().unwrap_or("");
    segment(last).then(|| last.to_string())
}
