// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::config::{self, Resolved};
use crate::error::{fail, Result};
use crate::metadata::{self, IdpMetadata};
use crate::names::{self, SAML2_TOKEN, TRUST13};
use crate::replay::MemoryReplayCache;
use crate::token::{self, Login, TokenContext};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_RELAY_STATE: usize = 1024;

const PROTOCOL_PARAMS: &[&str] = &["wa", "wtrealm", "wreply", "wctx", "wct", "wreq", "wreqptr", "wfresh", "wauth", "whr"];

#[derive(Clone, Debug)]
pub enum ReplyBody {
    Empty,
    Text(String),
    Map(HashMap<String, String>),
}

pub struct ReplyRequest {
    pub method: String,
    pub url: String,
    pub body: ReplyBody,
}

pub struct LoginOptions {
    pub relay_state: Option<String>,
    pub force_authn: bool,
    pub freshness: Option<i64>,
    pub authentication_method: String,
    pub home_realm: String,
    pub params: HashMap<String, String>,
}

impl Default for LoginOptions {
    fn default() -> Self {
        Self {
            relay_state: None,
            force_authn: false,
            freshness: None,
            authentication_method: String::new(),
            home_realm: String::new(),
            params: HashMap::new(),
        }
    }
}

pub struct LoginRequest {
    pub id: String,
    pub url: String,
    pub wctx: String,
}

pub struct RelyingParty {
    pub config: Resolved,
    pub idp: Option<IdpMetadata>,
    replay: MemoryReplayCache,
}

impl RelyingParty {
    pub fn create(config: &Map<String, Value>, base_dir: &std::path::Path) -> Result<Self> {
        let resolved = config::resolve_config(config, base_dir)?;
        let mut party = Self { config: resolved, idp: None, replay: MemoryReplayCache::new(0) };
        party.refresh_metadata()?;
        Ok(party)
    }

    pub fn from_file(path: &str, overrides: Option<Map<String, Value>>) -> Result<Self> {
        let resolved = config::read_config_file(path, overrides.as_ref())?;
        let mut party = Self { config: resolved, idp: None, replay: MemoryReplayCache::new(0) };
        party.refresh_metadata()?;
        Ok(party)
    }

    pub fn refresh_metadata(&mut self) -> Result<&IdpMetadata> {
        let xml = metadata::load_metadata_source(&self.config.idp_metadata, &self.config.idp_ca)?;
        let meta = metadata::read_idp_metadata(&xml, &self.config.idp_entity_id)?;
        self.idp = Some(meta);
        Ok(self.idp.as_ref().unwrap())
    }

    pub fn metadata_xml(&self) -> String {
        metadata::write_rp_metadata(&self.config.realm, &self.config.reply_url, self.config.certificate.as_ref())
    }

    pub fn login(&self, opts: &LoginOptions) -> Result<LoginRequest> {
        let idp = self.idp.as_ref().ok_or_else(|| fail("metadata", "the identity provider's metadata has not been loaded"))?;
        if let Some(relay) = &opts.relay_state {
            if relay.len() > MAX_RELAY_STATE {
                return Err(fail("config", format!("relayState is longer than {MAX_RELAY_STATE} bytes")));
            }
        }
        let request_id = new_id()?;
        let mut wctx = format!("id={}", query_escape(&request_id));
        if let Some(relay) = &opts.relay_state {
            wctx.push_str("&ru=");
            wctx.push_str(&query_escape(relay));
        }
        let mut pairs = Vec::new();
        pairs.push(("wa".to_string(), "wsignin1.0".to_string()));
        pairs.push(("wtrealm".to_string(), self.config.realm.clone()));
        pairs.push(("wreply".to_string(), self.config.reply_url.clone()));
        pairs.push(("wctx".to_string(), wctx.clone()));
        pairs.push(("wct".to_string(), wct_now()));
        if self.config.request_token_type {
            pairs.push(("wreq".to_string(), format!("<wst:RequestSecurityToken xmlns:wst=\"{TRUST13}\"><wst:TokenType>{SAML2_TOKEN}</wst:TokenType></wst:RequestSecurityToken>")));
        }
        if opts.force_authn {
            pairs.push(("wfresh".to_string(), "0".to_string()));
        } else if let Some(freshness) = opts.freshness {
            if freshness < 0 {
                return Err(fail("config", "freshness is a whole number of minutes"));
            }
            pairs.push(("wfresh".to_string(), freshness.to_string()));
        }
        if !opts.authentication_method.is_empty() {
            pairs.push(("wauth".to_string(), opts.authentication_method.clone()));
        }
        if !opts.home_realm.is_empty() {
            pairs.push(("whr".to_string(), opts.home_realm.clone()));
        }
        let mut extra: Vec<_> = opts.params.iter().collect();
        extra.sort_by(|left, right| left.0.cmp(right.0));
        for (key, value) in extra {
            if PROTOCOL_PARAMS.contains(&key.as_str()) {
                return Err(fail("config", format!("params cannot set {key}; it is the protocol's own")));
            }
            pairs.push((key.clone(), value.clone()));
        }
        Ok(LoginRequest { id: request_id, url: join_query(&idp.passive_requestor_endpoint, &encode_order(&pairs)), wctx })
    }

    pub fn handle_reply(&self, request: ReplyRequest, request_ids: &[String]) -> Result<Login> {
        let idp = self.idp.as_ref().ok_or_else(|| fail("metadata", "the identity provider's metadata has not been loaded"))?;
        let (form, query) = params_of(&request);
        let wa = form.get("wa").cloned().or_else(|| query.get("wa").cloned()).unwrap_or_default();
        if wa == "wsignoutcleanup1.0" || wa == "wsignout1.0" {
            return Err(fail("message", format!("the request is {wa}, a sign-out, not a sign-in response; see isSignOutCleanup()")));
        }
        if !request.method.eq_ignore_ascii_case("POST") {
            return Err(fail("message", "a sign-in response is POSTed (WS-Federation 13.2.2); this request is a GET"));
        }
        if wa != "wsignin1.0" {
            let shown = if wa.is_empty() { "(none)".to_string() } else { wa };
            return Err(fail("message", format!("the request's wa is {shown}, not wsignin1.0")));
        }
        if form.contains_key("wresultptr") {
            return Err(fail("message", "the response is by reference (wresultptr), which is never dereferenced; only wresult is accepted"));
        }
        let wresult = form.get("wresult").cloned().unwrap_or_default();
        if wresult.is_empty() {
            return Err(fail("message", "the request carries no wresult"));
        }
        let wctx = first_map(form.get("wctx").map(String::as_str).unwrap_or(""));
        let got_id = wctx.get("id").cloned();
        if let Some(got_id) = &got_id {
            if !request_ids.iter().any(|id| id == got_id) {
                return Err(fail("validation", format!("the response answers {got_id}, which is not a sign-in this browser has outstanding")));
            }
        } else if !self.config.allow_unsolicited {
            return Err(fail("validation", "the response is unsolicited (its wctx names no request), and unsolicited responses are not accepted"));
        }
        let mut token = token::validate_token(&wresult, &TokenContext {
            realm: &self.config.realm,
            reply_url: &self.config.reply_url,
            idp_entity_id: &idp.entity_id,
            idp_certificates: &idp.signing_certificates,
            decryption_key: self.config.private_key.as_ref(),
            clock_skew_ms: self.config.clock_skew_ms,
            want_assertions_encrypted: self.config.want_assertions_encrypted,
            replay: &self.replay,
            now: None,
        })?;
        token.request_id = got_id;
        token.relay_state = wctx.get("ru").cloned();
        let _ = names::STATUS_SUCCESS;
        Ok(token)
    }

    pub fn is_sign_out_cleanup(&self, request: &ReplyRequest) -> bool {
        let (form, query) = params_of(request);
        let wa = form.get("wa").cloned().or_else(|| query.get("wa").cloned()).unwrap_or_default();
        wa == "wsignoutcleanup1.0" || wa == "wsignout1.0"
    }

    pub fn logout(&self, reply: &str) -> Result<String> {
        let idp = self.idp.as_ref().ok_or_else(|| fail("metadata", "the identity provider's metadata has not been loaded"))?;
        let mut pairs = vec![
            ("wa".to_string(), "wsignout1.0".to_string()),
            ("wtrealm".to_string(), self.config.realm.clone()),
        ];
        if !reply.is_empty() {
            pairs.push(("wreply".to_string(), reply.to_string()));
        }
        Ok(join_query(&idp.passive_requestor_endpoint, &encode_order(&pairs)))
    }
}

fn new_id() -> Result<String> {
    let bytes: [u8; 20] = rand::random();
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn wct_now() -> String {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let whole = chrono::DateTime::<chrono::Utc>::from_timestamp(seconds as i64, 0).unwrap_or_else(chrono::Utc::now);
    whole.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn join_query(endpoint: &str, query: &str) -> String {
    let joiner = if endpoint.contains('?') { '&' } else { '?' };
    format!("{endpoint}{joiner}{query}")
}

fn encode_order(pairs: &[(String, String)]) -> String {
    let mut out = String::new();
    for (index, (key, value)) in pairs.iter().enumerate() {
        if index > 0 {
            out.push('&');
        }
        out.push_str(&query_escape(key));
        out.push('=');
        out.push_str(&query_escape(value));
    }
    out
}

pub fn query_escape(value: &str) -> String {
    let mut out = String::new();
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(*byte as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn percent_decode(input: &str) -> String {
    let plus = input.replace('+', " ");
    let bytes = plus.as_bytes();
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(value) = u8::from_str_radix(std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or(""), 16) {
                out.push(value);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn first_map(raw: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if raw.is_empty() {
        return out;
    }
    for part in raw.split('&') {
        if part.is_empty() {
            continue;
        }
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        let key = percent_decode(key);
        if out.contains_key(&key) {
            continue;
        }
        out.insert(key, percent_decode(value));
    }
    out
}

fn form_of(body: &ReplyBody) -> HashMap<String, String> {
    match body {
        ReplyBody::Empty => HashMap::new(),
        ReplyBody::Text(text) => first_map(text),
        ReplyBody::Map(map) => map.clone(),
    }
}

fn params_of(request: &ReplyRequest) -> (HashMap<String, String>, HashMap<String, String>) {
    let query = request.url.split_once('?').map(|(_, rest)| rest.split_once('#').map(|(q, _)| q).unwrap_or(rest)).unwrap_or("");
    let parsed = first_map(query);
    let form = if request.method.eq_ignore_ascii_case("POST") { form_of(&request.body) } else { HashMap::new() };
    (form, parsed)
}
