// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use serde_json::Value;
use std::collections::HashMap;

pub fn event(name: &str) -> &'static str {
    match name {
        "session_revoked" => "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
        "token_claims_change" => "https://schemas.openid.net/secevent/caep/event-type/token-claims-change",
        "credential_change" => "https://schemas.openid.net/secevent/caep/event-type/credential-change",
        "assurance_level_change" => "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change",
        "device_compliance_change" => "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change",
        "session_established" => "https://schemas.openid.net/secevent/caep/event-type/session-established",
        "session_presented" => "https://schemas.openid.net/secevent/caep/event-type/session-presented",
        "risk_level_change" => "https://schemas.openid.net/secevent/caep/event-type/risk-level-change",
        "account_credential_change_required" => "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required",
        "account_purged" => "https://schemas.openid.net/secevent/risc/event-type/account-purged",
        "account_disabled" => "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
        "account_enabled" => "https://schemas.openid.net/secevent/risc/event-type/account-enabled",
        "identifier_changed" => "https://schemas.openid.net/secevent/risc/event-type/identifier-changed",
        "identifier_recycled" => "https://schemas.openid.net/secevent/risc/event-type/identifier-recycled",
        "credential_compromise" => "https://schemas.openid.net/secevent/risc/event-type/credential-compromise",
        "opt_in" => "https://schemas.openid.net/secevent/risc/event-type/opt-in",
        "opt_out_initiated" => "https://schemas.openid.net/secevent/risc/event-type/opt-out-initiated",
        "opt_out_cancelled" => "https://schemas.openid.net/secevent/risc/event-type/opt-out-cancelled",
        "opt_out_effective" => "https://schemas.openid.net/secevent/risc/event-type/opt-out-effective",
        "recovery_activated" => "https://schemas.openid.net/secevent/risc/event-type/recovery-activated",
        "recovery_information_changed" => "https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed",
        "sessions_revoked" => "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked",
        "verification" => "https://schemas.openid.net/secevent/ssf/event-type/verification",
        "stream_updated" => "https://schemas.openid.net/secevent/ssf/event-type/stream-updated",
        _ => "",
    }
}

pub fn caep_events() -> Vec<&'static str> {
    ["session_revoked", "token_claims_change", "credential_change", "assurance_level_change", "device_compliance_change", "session_established", "session_presented", "risk_level_change"].into_iter().map(event).collect()
}

pub fn risc_events() -> Vec<&'static str> {
    ["account_credential_change_required", "account_purged", "account_disabled", "account_enabled", "identifier_changed", "identifier_recycled", "credential_compromise", "opt_in", "opt_out_initiated", "opt_out_cancelled", "opt_out_effective", "recovery_activated", "recovery_information_changed", "sessions_revoked"].into_iter().map(event).collect()
}

pub fn default_events_requested() -> Vec<String> {
    ["session_revoked", "credential_change", "assurance_level_change", "token_claims_change", "account_disabled", "account_enabled", "account_purged", "credential_compromise", "sessions_revoked", "account_credential_change_required"].into_iter().map(|name| event(name).to_string()).collect()
}

pub fn default_ending_events() -> Vec<String> {
    ["session_revoked", "account_disabled", "account_purged", "credential_compromise", "sessions_revoked"].into_iter().map(|name| event(name).to_string()).collect()
}

fn string_of(value: Option<&Value>) -> String {
    value.and_then(|item| item.as_str()).unwrap_or("").to_string()
}

fn simple_subject(identifier: Option<&Value>, issuer: &str) -> HashMap<String, String> {
    let Some(item) = identifier.and_then(|value| value.as_object()) else { return HashMap::new() };
    let mut fmt = string_of(item.get("format"));
    if fmt.is_empty() { fmt = string_of(item.get("subject_type")); }
    let mut out = HashMap::new();
    match fmt.as_str() {
        "iss_sub" => {
            if let Some(sub) = item.get("sub").and_then(|value| value.as_str()) {
                if item.get("iss").is_none() || item.get("iss").and_then(|value| value.as_str()) == Some(issuer) {
                    out.insert("sub".to_string(), sub.to_string());
                }
            }
        }
        "email" => { if let Some(email) = item.get("email").and_then(|value| value.as_str()) { out.insert("email".to_string(), email.to_string()); } }
        "opaque" => { if let Some(id) = item.get("id").and_then(|value| value.as_str()) { out.insert("opaque".to_string(), id.to_string()); } }
        "aliases" => {
            if let Some(list) = item.get("identifiers").and_then(|value| value.as_array()) {
                for child in list {
                    for (key, value) in simple_subject(Some(child), issuer) { out.insert(key, value); }
                }
            }
        }
        _ => {}
    }
    out
}

pub fn subject_of(sub_id: &Value, issuer: &str) -> HashMap<String, String> {
    let Some(item) = sub_id.as_object() else { return HashMap::new() };
    let mut fmt = string_of(item.get("format"));
    if fmt.is_empty() { fmt = string_of(item.get("subject_type")); }
    let mut out = HashMap::new();
    if fmt == "complex" || (fmt.is_empty() && (item.get("user").is_some() || item.get("session").is_some())) {
        let user = simple_subject(item.get("user"), issuer);
        let session = simple_subject(item.get("session"), issuer);
        if let Some(sub) = user.get("sub") { if !sub.is_empty() { out.insert("person".to_string(), sub.clone()); } }
        if let Some(email) = user.get("email") { if !email.is_empty() { out.insert("email".to_string(), email.clone()); } }
        let session_id = session.get("opaque").cloned().filter(|value| !value.is_empty()).or_else(|| session.get("sub").cloned()).unwrap_or_default();
        if !session_id.is_empty() { out.insert("idp_session".to_string(), session_id); }
        return out;
    }
    let one = simple_subject(Some(sub_id), issuer);
    if let Some(sub) = one.get("sub") { if !sub.is_empty() { out.insert("person".to_string(), sub.clone()); } }
    if let Some(email) = one.get("email") { if !email.is_empty() { out.insert("email".to_string(), email.clone()); } }
    out
}
