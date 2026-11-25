// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The WS-Federation demo: a signed-in page with three tabs (Session, CAEP &
//! RISC events, Policy enforcement), a user menu in the top bar, and, with
//! the `pep` feature, two pages the embedded PEP decides (`/orders/<id>` and
//! `/attribute-protected`). It mirrors oidc-caep-risc-rust's demo, adapted to
//! WS-Federation: there is one security token (a SAML 2.0 assertion inside a
//! WS-Trust response), no access or refresh token, and the Session tab shows
//! what the library verified in it. No token, assertion or key leaves this
//! process: the page shows facts and SHA-256 fingerprints, never a value.

use crate::config::parse_object;
use crate::error::Result;
use crate::names::{DS, XENC};
use crate::relying_party::{LoginOptions, ReplyBody, ReplyRequest, RelyingParty};
use crate::ssf::{events, ReceiverOptions, SignalEvent, SignalsReceiver, TlsConfig};
use crate::token::Login;
use crate::x509util::cert_pem_body;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use pem::Pem;
use rsa::pkcs8::EncodePrivateKey;
use serde_json::{json, Value};
use sha2::Sha256;
use ua_cryptography_xml_c14n::roxmltree::Node;
use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Response, Server, StatusCode};

const STYLES: &str = include_str!("../demo/public/styles.css");
/// The events tab's live log (polls `/api/signals`).
const APP_JS: &str = include_str!("../demo/public/app.js");
/// The Collapse all / Expand all toggle.
const PANES_JS: &str = include_str!("../demo/public/panes.js");
/// Closes the user menu on a click outside it or Escape.
const MENU_JS: &str = include_str!("../demo/public/menu.js");
/// The Policy enforcement tab's refresh (every 2 s, keeping closed panes closed).
const PEP_JS: &str = include_str!("../demo/public/pep.js");
/// The pages' Content-Security-Policy. `connect-src 'self'` lets the
/// scripts fetch `/pep-status.html` and `/api/signals`; there is no inline
/// script or style. No `form-action`: sign-out redirects to iya-sts.
const CSP: &str = "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'";
const GIF_B64: &str = "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";
/// The most events kept; the oldest go first.
const MAX_EVENTS: usize = 200;

type HmacSha256 = Hmac<Sha256>;
type Answer = (u16, Vec<(String, String)>, Vec<u8>);

/// One received Shared Signals event, as the CAEP & RISC events tab draws
/// it and `app.js` receives it from `/api/signals`.
#[derive(Clone)]
pub(crate) struct LiveEvent {
    pub(crate) id: u64,
    pub(crate) event_type: String,
    pub(crate) jti: String,
    /// CAEP, RISC, SSF (the stream's own) or STS (iya-sts's own).
    pub(crate) family: String,
    pub(crate) at: String,
    pub(crate) subject: String,
    pub(crate) members: Value,
    pub(crate) ended: bool,
}

/// What the demo noted about a sign-in's security token when it arrived:
/// the response as received, by fingerprint, and the facts in it that are
/// not in `Login` (token type, lifetime, signature and encryption methods).
#[derive(Clone)]
pub(crate) struct TokenFacts {
    pub(crate) rows: Vec<(String, String)>,
}

/// The WS-Federation demo. `GET /live-status` is JSON: signedIn, subject, receiver, and the
/// accepted Shared Signals events (type and jti). It never includes tokens or assertions.
pub struct App {
    pub rp: RelyingParty,
    pub receiver: Mutex<Option<Arc<SignalsReceiver>>>,
    pub receiver_state: Mutex<String>,
    events: Mutex<Vec<LiveEvent>>,
    event_seq: AtomicU64,
    sessions: Arc<Mutex<HashMap<String, Login>>>,
    /// Per session: what the security token held, for the Session tab.
    facts: Mutex<HashMap<String, TokenFacts>>,
    secret: Vec<u8>,
    reply_path: String,
    secure: String,
}

impl App {
    pub fn new(rp: RelyingParty, receiver: Option<Arc<SignalsReceiver>>) -> Self {
        let secret: [u8; 32] = rand::random();
        let reply = url::Url::parse(&rp.config.reply_url).ok();
        let path = reply.as_ref().map(|item| item.path().to_string()).filter(|item| !item.is_empty()).unwrap_or_else(|| "/wsfed".to_string());
        let secure = if reply.as_ref().is_some_and(|item| item.scheme() == "https") { "; Secure".to_string() } else { String::new() };
        Self {
            rp,
            receiver: Mutex::new(receiver),
            receiver_state: Mutex::new("not configured".to_string()),
            events: Mutex::new(Vec::new()),
            event_seq: AtomicU64::new(0),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            facts: Mutex::new(HashMap::new()),
            secret: secret.to_vec(),
            reply_path: path,
            secure,
        }
    }

    pub fn sessions_handle(&self) -> Arc<Mutex<HashMap<String, Login>>> { self.sessions.clone() }

    pub fn drop_session(&self, id: &str) {
        self.sessions.lock().unwrap().remove(id);
        self.facts.lock().unwrap().remove(id);
    }

    /// Record an accepted Shared Signals event for the events tab and `GET /live-status`.
    pub fn remember(&self, event: &SignalEvent) {
        let mut subject: Vec<String> = event.subject.iter().map(|(k, v)| format!("{k} {v}")).collect();
        subject.sort();
        let at = event.iat.map(|t| utc(t as i64)).unwrap_or_else(|| utc(Utc::now().timestamp()));
        let live = LiveEvent {
            id: self.event_seq.fetch_add(1, Ordering::Relaxed) + 1,
            event_type: event.event_type.clone(),
            jti: event.jti.clone(),
            family: family_of(&event.event_type).to_string(),
            at,
            subject: subject.join(", "),
            members: event.payload.clone(),
            ended: event.ended,
        };
        {
            let mut all = self.events.lock().unwrap();
            all.push(live);
            let over = all.len().saturating_sub(MAX_EVENTS);
            all.drain(..over);
        }
        // iya-sts main sets the WS-Federation assertion's SessionIndex to the
        // assertion id. The CAEP session-revoked subject names the sign-on
        // session instead, so the index finds nobody and the end callback is
        // not asked to drop this login. This demo has that one session.
        if event.event_type != events::event("session_revoked") || !event.sessions.is_empty() { return; }
        let ids: Vec<String> = self.sessions.lock().unwrap().drain().map(|(id, _)| id).collect();
        self.facts.lock().unwrap().clear();
        if let Some(receiver) = self.receiver.lock().unwrap().as_ref() {
            for id in &ids { receiver.untrack(id); }
        }
    }

    fn who(&self, sid: &str) -> Option<Login> {
        if sid.is_empty() { None } else { self.sessions.lock().unwrap().get(sid).cloned() }
    }

    fn live_status(&self, sid: &str) -> Answer {
        let who = self.who(sid);
        let events: Vec<Value> = self.events.lock().unwrap().iter().map(|e| json!({"type": e.event_type, "jti": e.jti})).collect();
        #[allow(unused_mut)]
        let mut body = json!({
            "signedIn": who.is_some(),
            "subject": who.as_ref().map(display_name),
            "receiver": self.receiver_state.lock().unwrap().clone(),
            "events": events,
        });
        // The embedded PEP's status() holds no secret; its syncToken is the
        // version of the policy held, not a credential.
        #[cfg(feature = "pep")]
        if let Some(pep) = self.rp.pep() {
            let status = pep.status();
            body["pep"] = json!({
                "name": status.name, "mode": status.mode.as_str(), "application": status.application,
                "registered": status.registered, "holdsPolicy": status.holds_policy, "policyCount": status.policy_count,
                "syncToken": status.sync_token, "decisions": status.decisions, "policyEvents": status.event_stream.as_str(),
                "lastError": status.last_error,
            });
        }
        (200, vec![("content-type".to_string(), "application/json".to_string()), no_store()], body.to_string().into_bytes())
    }

    pub(crate) fn sign(&self, value: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("hmac");
        mac.update(value.as_bytes());
        format!("{value}.{}", URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }

    fn unsign(&self, signed: &str) -> String {
        let Some((value, _)) = signed.rsplit_once('.') else { return String::new() };
        let again = self.sign(value);
        if again.len() == signed.len() && again.bytes().zip(signed.bytes()).fold(0u8, |acc, (left, right)| acc | (left ^ right)) == 0 { value.to_string() } else { String::new() }
    }

    fn pending(&self, value: &str, age: i64) -> String {
        let secure = if self.secure.is_empty() { "; Secure" } else { self.secure.as_str() };
        format!("wsfed_pending={value}; Path={}; HttpOnly; SameSite=None{secure}; Max-Age={age}", self.reply_path)
    }

    pub fn handle(&self, method: &str, target: &str, headers: &HashMap<String, String>, body: &[u8]) -> Answer {
        let path = target.split_once('?').map(|(path, _)| path).unwrap_or(target);
        let path = if path.is_empty() { "/" } else { path };
        let jar = cookies(headers.get("cookie").map(String::as_str).unwrap_or(""));
        let sid = self.unsign(jar.get("sid").map(String::as_str).unwrap_or(""));
        let method = method.to_ascii_uppercase();
        if path == "/healthz" && method == "GET" {
            return (200, vec![("content-type".to_string(), "text/plain".to_string())], b"ok".to_vec());
        }
        if path == "/live-status" && method == "GET" {
            return self.live_status(&sid);
        }
        if path == "/login" && method == "GET" {
            // "Sign in with another account" asks the identity provider to
            // authenticate again (wfresh=0) rather than reuse its session.
            let again = query_param(target, "prompt") == "login";
            let request = match self.rp.login(&LoginOptions { relay_state: Some("/".to_string()), force_authn: again, ..LoginOptions::default() }) {
                Ok(value) => value,
                Err(err) => return (500, vec![("content-type".to_string(), "text/plain".to_string())], err.to_string().into_bytes()),
            };
            return (302, vec![("location".to_string(), request.url), ("set-cookie".to_string(), self.pending(&self.sign(&request.id), 600))], Vec::new());
        }
        let probe = ReplyRequest { method: method.clone(), url: target.to_string(), body: ReplyBody::Empty };
        if path == self.reply_path && self.rp.is_sign_out_cleanup(&probe) {
            if !sid.is_empty() {
                self.drop_session(&sid);
                if let Some(receiver) = self.receiver.lock().unwrap().as_ref() { receiver.untrack(&sid); }
            }
            let gif = STANDARD.decode(GIF_B64).unwrap_or_default();
            return (200, vec![("content-type".to_string(), "image/gif".to_string()), ("set-cookie".to_string(), format!("sid=; Path=/; HttpOnly; Max-Age=0{}", self.secure))], gif);
        }
        if path == self.reply_path && method == "POST" {
            let pending = self.unsign(jar.get("wsfed_pending").map(String::as_str).unwrap_or(""));
            let ids = if pending.is_empty() { Vec::new() } else { vec![pending] };
            let form = String::from_utf8_lossy(body).into_owned();
            let who = self.rp.handle_reply(ReplyRequest { method: "POST".to_string(), url: target.to_string(), body: ReplyBody::Text(form.clone()) }, &ids);
            let who = match who {
                Ok(value) => value,
                Err(_) => return (400, vec![("content-type".to_string(), "text/plain".to_string())], b"Sign-in failed.".to_vec()),
            };
            let session_id = token_url(24);
            if let Some(receiver) = self.receiver.lock().unwrap().as_ref() { receiver.track(&session_id, &who, None); }
            let next = who.relay_state.clone().filter(|value| value.starts_with('/') && !value.starts_with("//")).unwrap_or_else(|| "/".to_string());
            // The response itself is not kept: only its fingerprint and the
            // facts the Session tab shows.
            let wresult = url::form_urlencoded::parse(form.as_bytes()).find(|(k, _)| k == "wresult").map(|(_, v)| v.into_owned()).unwrap_or_default();
            self.facts.lock().unwrap().insert(session_id.clone(), token_facts(&wresult, &self.rp));
            self.sessions.lock().unwrap().insert(session_id.clone(), who);
            return (303, vec![
                ("location".to_string(), next),
                ("set-cookie".to_string(), self.pending("", 0)),
                ("set-cookie".to_string(), format!("sid={}; Path=/; HttpOnly; SameSite=Lax{}", self.sign(&session_id), self.secure)),
            ], Vec::new());
        }
        if path == "/logout" && method == "POST" {
            if !sid.is_empty() {
                self.drop_session(&sid);
                if let Some(receiver) = self.receiver.lock().unwrap().as_ref() { receiver.untrack(&sid); }
            }
            let origin = reply_origin(&self.rp.config.reply_url);
            let location = match self.rp.logout(&origin) {
                Ok(value) => value,
                Err(err) => return (500, vec![("content-type".to_string(), "text/plain".to_string())], err.to_string().into_bytes()),
            };
            return (303, vec![("location".to_string(), location), ("set-cookie".to_string(), format!("sid=; Path=/; HttpOnly; Max-Age=0{}", self.secure))], Vec::new());
        }
        if path == "/FederationMetadata/2007-06/FederationMetadata.xml" && method == "GET" {
            return (200, vec![("content-type".to_string(), "application/samlmetadata+xml".to_string())], self.rp.metadata_xml().into_bytes());
        }
        if path == "/" && method == "GET" {
            return self.home(&sid, target);
        }
        for (name, script) in [("/app.js", APP_JS), ("/panes.js", PANES_JS), ("/menu.js", MENU_JS), ("/pep.js", PEP_JS)] {
            if path == name && method == "GET" {
                return (200, vec![("content-type".to_string(), "text/javascript; charset=utf-8".to_string())], script.as_bytes().to_vec());
            }
        }
        if (path == "/pep-status" || path == "/pep-status.html") && method == "GET" {
            // For a signed-in browser only, like the page that shows it.
            // Nothing in it is secret: counts, times, tokens naming policy
            // versions, and the PEP key's public thumbprint.
            if self.who(&sid).is_none() {
                return (401, vec![("content-type".to_string(), "text/plain; charset=utf-8".to_string())], b"sign in first".to_vec());
            }
            return if path.ends_with(".html") {
                (200, vec![("content-type".to_string(), "text/html; charset=utf-8".to_string()), no_store()], pep_fragment(&self.rp).into_bytes())
            } else {
                (200, vec![("content-type".to_string(), "application/json".to_string()), no_store()], pep_json(&self.rp).to_string().into_bytes())
            };
        }
        if path == "/api/signals" && method == "GET" {
            return self.signals_api(&sid, target);
        }
        if path == "/events" && method == "GET" {
            // No Server-Sent Events here: 204 tells app.js's EventSource to
            // give up, and it polls /api/signals every 3 s instead.
            return (204, vec![no_store()], Vec::new());
        }
        if path == "/signals/verify" && method == "POST" {
            return self.verify_signals(&sid, headers);
        }
        #[cfg(feature = "pep")]
        if path == "/attribute-protected" {
            return self.attribute_protected(&sid);
        }
        #[cfg(feature = "pep")]
        if let Some(id) = path.strip_prefix("/orders/").filter(|id| !id.is_empty() && !id.contains('/')) {
            return self.order(&sid, &method, id);
        }
        if path == "/styles.css" && method == "GET" {
            let body = if STYLES.is_empty() { b"body{font-family:sans-serif}\n".to_vec() } else { STYLES.as_bytes().to_vec() };
            return (200, vec![("content-type".to_string(), "text/css".to_string())], body);
        }
        (404, vec![("content-type".to_string(), "text/plain".to_string())], b"Not found".to_vec())
    }

    fn home(&self, sid: &str, target: &str) -> Answer {
        let Some(who) = self.who(sid) else {
            let issuer = self.rp.idp.as_ref().map(|idp| format!(" of <code>{}</code>", esc(&idp.entity_id))).unwrap_or_default();
            let body = format!("<h1>Sign in with WS-Federation</h1><p>This application is a WS-Federation relying party{issuer}. It sends the browser to the identity provider's passive endpoint (<code>wa=wsignin1.0</code>) and takes the signed security token it POSTs back.</p><p class=\"buttons\"><a class=\"button primary\" href=\"/login\">Sign in with WS-Federation</a></p>");
            return html(200, &page_for("Sign in", &body, None));
        };
        let tab = match query_param(target, "tab").as_str() {
            "pep" => "pep",
            "events" => "events",
            _ => "session",
        };
        let events = self.events.lock().unwrap().clone();
        let last_id = events.last().map(|e| e.id).unwrap_or(0);
        let state = self.receiver_state.lock().unwrap().clone();
        // Every tab's panes are collapsible; one toggle opens or closes every
        // pane on the tab shown (panes.js shows it).
        let toggle = "<p class=\"pane-tools\"><button type=\"button\" class=\"secondary small\" id=\"panes-toggle\" hidden>Collapse all</button></p>";
        let content = match tab {
            "pep" => format!("{toggle}<div id=\"pep-panel\" aria-live=\"polite\">{}</div><script src=\"/pep.js\" defer></script>", pep_fragment(&self.rp)),
            "events" => {
                let notice = match query_param(target, "verify").as_str() {
                    "sent" => "A verification event was requested; it appears below when the transmitter sends it.",
                    "refused" => "The transmitter refused the verification request.",
                    _ => "",
                };
                format!("{toggle}{}", events_panel(&events, &state, notice))
            }
            _ => {
                let facts = self.facts.lock().unwrap().get(sid).cloned();
                let tracked = self.receiver.lock().unwrap().as_ref().map(|receiver| receiver.is_tracked(sid));
                let held = self.sessions.lock().unwrap().len();
                format!("{toggle}{}", session_panes(&self.rp, &who, facts.as_ref(), &state, tracked, held))
            }
        };
        let tab_link = |id: &str, href: &str, label: &str| {
            let on = id == tab;
            format!("<a class=\"page-tab\" role=\"tab\" href=\"{href}\" aria-selected=\"{on}\"{}>{label}</a>", if on { " aria-current=\"page\"" } else { "" })
        };
        let count = if events.is_empty() { String::new() } else { events.len().to_string() };
        let body = format!(
            "<h1>Signed in as {}</h1><nav class=\"page-tabs\" role=\"tablist\" aria-label=\"Sections\">{}{}{}</nav><p id=\"signal-banner\" class=\"problem\" hidden></p><p id=\"signal-toast\" class=\"notice\" hidden></p><div role=\"tabpanel\" id=\"panel\" data-base=\"\" data-tab=\"{tab}\" data-last-id=\"{last_id}\">{content}</div><script src=\"/app.js\" defer></script><script src=\"/panes.js\" defer></script>",
            esc(&display_name(&who)),
            tab_link("session", "/", "Session"),
            tab_link("events", "/?tab=events", &format!("CAEP &amp; RISC events <span class=\"count\" id=\"signal-count\">{count}</span>")),
            tab_link("pep", "/?tab=pep", "Policy enforcement"),
        );
        html(200, &page_for("Signed in", &body, Some(&who)))
    }

    /// `GET /api/signals?after=<id>`: what arrived after the last event the
    /// page shows, and the stream's state. 401 once the session is gone,
    /// which `app.js` reads as signed out.
    fn signals_api(&self, sid: &str, target: &str) -> Answer {
        let json_type = ("content-type".to_string(), "application/json".to_string());
        if self.who(sid).is_none() {
            return (401, vec![json_type, no_store()], json!({"signedIn": false}).to_string().into_bytes());
        }
        let after = query_param(target, "after").parse::<u64>().unwrap_or(0);
        let events: Vec<Value> = self.events.lock().unwrap().iter().filter(|e| e.id > after).map(event_json).collect();
        let body = json!({"events": events, "streamStatus": {"status": self.receiver_state.lock().unwrap().clone(), "at": utc(Utc::now().timestamp())}});
        (200, vec![json_type, no_store()], body.to_string().into_bytes())
    }

    /// `POST /signals/verify`: asks the transmitter for a verification event
    /// on the stream. JSON for `app.js`, a redirect back to the tab without it.
    fn verify_signals(&self, sid: &str, headers: &HashMap<String, String>) -> Answer {
        if self.who(sid).is_none() {
            return (303, vec![("location".to_string(), "/".to_string())], Vec::new());
        }
        let state = format!("demo-{}", self.event_seq.load(Ordering::Relaxed) + 1);
        let receiver = self.receiver.lock().unwrap().clone();
        let outcome = match receiver.map(|receiver| receiver.verify(&state)) {
            Some(Ok(())) => "sent",
            Some(Err(err)) => {
                println!("ssf: verification request refused: {err}");
                "refused"
            }
            None => "refused",
        };
        if headers.get("accept").is_some_and(|value| value.contains("application/json")) {
            (200, vec![("content-type".to_string(), "application/json".to_string()), no_store()], json!({"outcome": outcome}).to_string().into_bytes())
        } else {
            (303, vec![("location".to_string(), format!("/?tab=events&verify={outcome}"))], Vec::new())
        }
    }
}

#[cfg(feature = "pep")]
impl App {
    /// The PEP's decision for a signed-in session: with a running receiver
    /// the session must still be tracked, so one ended by a Shared Signals
    /// event is a Deny.
    fn decide_for(&self, sid: &str, who: &Login, access: &crate::pep::Access) -> crate::pep::Decision {
        let receiver = self.receiver.lock().unwrap().clone();
        match receiver {
            Some(receiver) => self.rp.decide_session(&receiver, sid, who, access),
            None => self.rp.decide(who, access),
        }
    }

    /// A route the embedded PEP protects (the `pep` feature, iya-sts#1206):
    /// the signed-in person's access to one order, decided by the `pep`
    /// section's PEP. A GET is `read` and anything else `write`. No sign-in
    /// is 401, a Deny 403, and any other PEP failure 403 too (a decision
    /// that couldn't be made): an enforcement point that cannot say yes says
    /// no, and the page says which. Never served.
    fn order(&self, sid: &str, method: &str, id: &str) -> Answer {
        use crate::pep::{Access, Decision};
        let Some(who) = self.who(sid) else {
            return html(401, &page_for("Sign in", "<h1>Sign in first</h1><p><a href=\"/login\">Sign in</a></p>", None));
        };
        let action = if method == "GET" { "read" } else { "write" };
        let decision = self.decide_for(sid, &who, &Access::new(action, "order", id));
        // 200 for a Permit, 403 for anything else: the PEP's own answer.
        let status = decision.http_status();
        let (title, body) = match decision {
            Decision::Permit { obligations, .. } => {
                let note = if obligations.is_empty() { String::new() } else { format!("<p><small>{} obligation(s) to discharge.</small></p>", obligations.len()) };
                ("Order", format!("<h1>Order {}</h1><p>The PEP permitted <code>{action}</code>.</p>{note}", esc(id)))
            }
            Decision::Deny { why } => ("Forbidden", format!("<h1>Not allowed</h1><p>The PEP denied <code>{action}</code> on order {}: {}</p>", esc(id), esc(&why))),
            Decision::Unavailable { why } => ("Forbidden", format!("<h1>No decision</h1><p>The PEP could not decide: {}</p>", esc(&why))),
        };
        html(status, &page_for(title, &body, Some(&who)))
    }

    /// `GET /attribute-protected`: decided by the embedded PEP against the
    /// demo application's own (fine-grained authorization) policy, which
    /// permits it to a person whose directory attribute attr1 is abc123. The
    /// value is not in the assertion: the PEP asks iya-sts's PIP for it
    /// (`POST /xacml/pip`), in `local` mode as in `central`. 401 without a
    /// sign-in, 200 on a Permit, 403 on a Deny and on any other PEP failure,
    /// the page saying which.
    fn attribute_protected(&self, sid: &str) -> Answer {
        use crate::pep::{Access, Decision};
        let Some(who) = self.who(sid) else {
            return html(401, &page_for("Sign in", "<h1>Sign in first</h1><p><a href=\"/login\">Sign in</a></p>", None));
        };
        let what = "<p><small>The demo application's policy permits <code>read</code> on <code>attribute-protected</code> when your directory attribute <code>attr1</code> is <code>abc123</code>. The PEP asked iya-sts's PIP for it: it is not in your security token.</small></p>";
        let decision = self.decide_for(sid, &who, &Access::new("read", "attribute-protected", "attr1"));
        let status = decision.http_status();
        let (title, body) = match decision {
            Decision::Permit { .. } => ("Attribute-protected", format!("<h1>Allowed</h1><p class=\"notice\">The PEP permitted it: your <code>attr1</code> is <code>abc123</code>.</p>{what}")),
            Decision::Deny { why } => ("Forbidden", format!("<h1>Not allowed</h1><p class=\"problem\">The PEP denied it: {}</p>{what}", esc(&why))),
            Decision::Unavailable { why } => ("Forbidden", format!("<h1>No decision</h1><p class=\"problem\">The PEP could not decide: {}</p>{what}", esc(&why))),
        };
        html(status, &page_for(title, &body, Some(&who)))
    }
}

fn no_store() -> (String, String) {
    ("cache-control".to_string(), "no-store".to_string())
}

/// An HTML page's answer, with the pages' security headers.
fn html(status: u16, page: &str) -> Answer {
    (status, vec![
        ("content-type".to_string(), "text/html; charset=utf-8".to_string()),
        no_store(),
        ("content-security-policy".to_string(), CSP.to_string()),
        ("referrer-policy".to_string(), "no-referrer".to_string()),
        ("x-content-type-options".to_string(), "nosniff".to_string()),
        ("x-frame-options".to_string(), "DENY".to_string()),
    ], page.as_bytes().to_vec())
}

/// A page, with the top bar's links and user menu when someone is signed in.
pub(crate) fn page_for(title: &str, body: &str, who: Option<&Login>) -> String {
    let menu = who.map(user_menu).unwrap_or_default();
    let nav = if who.is_some() { site_nav() } else { String::new() };
    let script = if who.is_some() { "<script src=\"/menu.js\" defer></script>" } else { "" };
    format!("<!DOCTYPE html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>{}</title><link rel=\"stylesheet\" href=\"/styles.css\"></head>\n<body><header class=\"topbar\"><a href=\"/\">wsfed-caep demo</a>{nav}{menu}</header><main>\n{body}\n</main><footer>A traditional web application signing in with WS-Federation through wsfed-caep.</footer>{script}</body>\n</html>\n", esc(title))
}

/// The top bar's links between the demo's pages, for a signed-in person:
/// the demo itself, and (with the embedded PEP) the two pages the PEP
/// decides, so each is one click from the others.
pub(crate) fn site_nav() -> String {
    #[allow(unused_mut)]
    let mut links = vec![("/", "Demo home")];
    #[cfg(feature = "pep")]
    links.extend([("/attribute-protected", "Attribute-protected"), ("/orders/42", "Order 42")]);
    let items: Vec<String> = links.iter().map(|(href, label)| format!("<a href=\"{href}\">{label}</a>")).collect();
    format!("<nav class=\"site-nav\" aria-label=\"Demo pages\">{}</nav>", items.join(""))
}

/// The first non-empty value of an attribute named (by its Name's last
/// segment, or its FriendlyName) one of `names`, in that order.
fn attribute_named(login: &Login, names: &[&str]) -> String {
    for wanted in names {
        let mut keys: Vec<&String> = login.attributes.keys().collect();
        keys.sort();
        for key in keys {
            let last = key.rsplit(['/', ':', '#']).next().unwrap_or(key);
            let friendly = login.attribute_friendly_names.get(key).map(String::as_str).unwrap_or("");
            if last.eq_ignore_ascii_case(wanted) || friendly.eq_ignore_ascii_case(wanted) {
                if let Some(value) = login.attributes[key].iter().find(|v| !v.is_empty()) {
                    return value.clone();
                }
            }
        }
    }
    String::new()
}

/// The sign-in's username as the token's claims carry it: a `username`
/// claim, else `upn`, else the `name` claim (iya-sts's directory uid), else
/// `preferred_username`. Empty when none is there.
pub(crate) fn username_of(login: &Login) -> String {
    attribute_named(login, &["username", "upn", "name", "preferred_username"])
}

/// Who a sign-in is, as the heading, the menu and /live-status name them:
/// the username, and the NameID (the token's subject) only when no claim
/// names them.
pub(crate) fn display_name(login: &Login) -> String {
    [username_of(login), login.name_id.clone()].into_iter().find(|v| !v.is_empty()).unwrap_or_default()
}

/// The user menu's second line: the person's display name, else their
/// given and family names, else their email; never the name shown above it.
fn detail_of(login: &Login, shown: &str) -> String {
    let full = [attribute_named(login, &["givenname", "givenName"]), attribute_named(login, &["surname", "sn"])].into_iter().filter(|v| !v.is_empty()).collect::<Vec<_>>().join(" ");
    [attribute_named(login, &["displayName"]), full, attribute_named(login, &["emailaddress", "email", "mail"])].into_iter().find(|v| !v.is_empty() && v != shown).unwrap_or_default()
}

/// The top bar's user menu: the signed-in account, signing in with another
/// account, and signing out. This demo keeps one sign-in per browser, so
/// another account replaces this one rather than being switched to.
pub(crate) fn user_menu(login: &Login) -> String {
    let name = display_name(login);
    let initial = name.chars().find(|c| c.is_alphanumeric()).map(|c| c.to_uppercase().to_string()).unwrap_or_else(|| "?".into());
    let detail = detail_of(login, &name);
    let detail = if detail.is_empty() { String::new() } else { format!("<span class=\"muted small\">{}</span>", esc(&detail)) };
    format!(
        "<details class=\"acct-menu\"><summary aria-label=\"Account menu\"><span class=\"avatar\" aria-hidden=\"true\">{i}</span><span class=\"menu-name\" title=\"{n}\">{n}</span><span class=\"caret\" aria-hidden=\"true\">▾</span></summary>\
<div class=\"menu\" role=\"menu\"><p class=\"menu-head\">Signed in</p>\
<div class=\"menu-row static\"><span class=\"avatar\" aria-hidden=\"true\">{i}</span><span class=\"menu-who\"><span>{n}</span>{detail}</span></div>\
<div class=\"menu-sep\"></div>\
<a class=\"menu-row\" role=\"menuitem\" href=\"/login?prompt=login\"><span class=\"avatar plus\" aria-hidden=\"true\">+</span>Sign in with another account</a>\
<p class=\"muted small menu-note\">The identity provider asks who you are, even if it already knows (<code>wfresh=0</code>). This demo keeps one sign-in per browser: the new account replaces this one.</p>\
<div class=\"menu-sep\"></div>\
<form method=\"post\" action=\"/logout\"><button class=\"menu-row\" type=\"submit\" role=\"menuitem\">Sign out {n}</button></form></div></details>",
        i = esc(&initial),
        n = esc(&name)
    )
}

/// A collapsible pane: every block of text on the tabs is one.
pub(crate) fn pane(id: &str, title: &str, aside: &str, body: &str) -> String {
    let aside = if aside.is_empty() { String::new() } else { format!(" <span class=\"aside\">{}</span>", esc(aside)) };
    format!("<details class=\"card pane\" id=\"{id}\" open><summary><h2>{}</h2>{aside}</summary>{body}</details>", esc(title))
}

fn facts_table(rows: &[(String, String)]) -> String {
    let rows: String = rows.iter().map(|(k, v)| format!("<tr><th>{}</th><td>{}</td></tr>", esc(k), esc(v))).collect();
    format!("<table class=\"facts\">{rows}</table>")
}

/// A UTC timestamp, `YYYY-MM-DD HH:MM:SS UTC`.
pub(crate) fn utc(secs: i64) -> String {
    DateTime::from_timestamp(secs.max(0), 0).map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string()).unwrap_or_default()
}

/// A span of seconds in words: `1m 30s`, `1h 1m ago` for one in the past.
pub(crate) fn in_words(secs: i64) -> String {
    let s = secs.abs();
    let text = if s >= 3600 { format!("{}h {}m", s / 3600, s % 3600 / 60) } else if s >= 60 { format!("{}m {}s", s / 60, s % 60) } else { format!("{s}s") };
    if secs < 0 { format!("{text} ago") } else { text }
}

fn when(moment: DateTime<Utc>) -> String {
    format!("{} ({})", utc(moment.timestamp()), in_words(moment.timestamp() - Utc::now().timestamp()))
}

/// A short, non-reversible name for a value: what the page shows instead
/// of the value, which never leaves this process.
pub(crate) fn fingerprint(bytes: &[u8]) -> String {
    let digest = <Sha256 as sha2::Digest>::digest(bytes);
    let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("sha256 {hex}…")
}

/// The facts of a WS-Trust response as received that `Login` does not
/// hold: the token type, what it applies to, its lifetime, and how it is
/// signed or encrypted. Read for display only: the library has already
/// verified the response (`handle_reply`), and nothing here decides.
pub(crate) fn token_facts(wresult: &str, rp: &RelyingParty) -> TokenFacts {
    let mut rows = vec![("Response as received".to_string(), format!("{} bytes, {}", wresult.len(), fingerprint(wresult.as_bytes())))];
    let Ok(doc) = crate::xml::parse(wresult, "wresult") else {
        rows.push(("Read".into(), "not XML (the library refused nothing here, so this cannot happen)".into()));
        return TokenFacts { rows };
    };
    let root = doc.root_element();
    let first = |local: &str| root.descendants().find(|n| n.is_element() && n.tag_name().name() == local);
    let text = |local: &str| first(local).map(crate::xml::text_of).unwrap_or_default();
    rows.push(("Response".into(), format!("{} ({})", root.tag_name().name(), root.tag_name().namespace().unwrap_or(""))));
    let token_type = text("TokenType");
    rows.push(("TokenType".into(), if token_type.is_empty() { "not stated".into() } else { token_type }));
    if let Some(applies) = first("AppliesTo") {
        rows.push(("AppliesTo".into(), crate::xml::wsa_addresses(applies).join(", ")));
    }
    if let Some(lifetime) = first("Lifetime") {
        let part = |local: &str| lifetime.children().find(|n| n.is_element() && n.tag_name().name() == local).map(crate::xml::text_of).unwrap_or_default();
        rows.push(("Lifetime".into(), format!("created {}, expires {}", part("Created"), part("Expires"))));
    }
    let encrypted = root.descendants().find(|n| crate::xml::is_el(*n, XENC, "EncryptedData"));
    if let Some(data) = encrypted {
        rows.push(("Token".into(), "an encrypted assertion, decrypted with this relying party's private key".into()));
        rows.push(("Content encryption".into(), encryption_method(data)));
        if let Some(key) = root.descendants().find(|n| crate::xml::is_el(*n, XENC, "EncryptedKey")) {
            rows.push(("Key transport".into(), encryption_method(key)));
        }
        rows.push(("Signature".into(), "inside the encryption: the library verified it after decrypting".into()));
        return TokenFacts { rows };
    }
    rows.push(("Token".into(), "a SAML 2.0 assertion, signed, not encrypted".into()));
    let ds = |local: &str| root.descendants().find(|n| crate::xml::is_el(*n, DS, local));
    let algorithm = |local: &str| ds(local).and_then(|n| n.attribute("Algorithm")).unwrap_or("").to_string();
    rows.push(("Signature method".into(), algorithm("SignatureMethod")));
    rows.push(("Digest method".into(), algorithm("DigestMethod")));
    rows.push(("Canonicalization".into(), algorithm("CanonicalizationMethod")));
    let transforms: Vec<String> = root.descendants().filter(|n| crate::xml::is_el(*n, DS, "Transform")).filter_map(|n| n.attribute("Algorithm").map(str::to_string)).collect();
    if !transforms.is_empty() {
        rows.push(("Transforms".into(), transforms.join(", ")));
    }
    if let Some(reference) = ds("Reference") {
        rows.push(("Signed element".into(), reference.attribute("URI").unwrap_or("").to_string()));
    }
    if let Some(cert) = ds("X509Certificate") {
        let raw: String = crate::xml::text_of(cert).split_whitespace().collect();
        if let Ok(der) = STANDARD.decode(raw) {
            let known = rp.idp.as_ref().is_some_and(|idp| idp.signing_certificates.iter().any(|c| c.der == der));
            rows.push(("Signing certificate".into(), format!("{}{}", fingerprint_of_der(&der), if known { ", one the identity provider's metadata names" } else { ", sent in the token (the key that verified it is the metadata's)" })));
        }
    }
    TokenFacts { rows }
}

/// The Algorithm of an encrypted element's EncryptionMethod.
fn encryption_method(of: Node) -> String {
    of.children().find(|n| crate::xml::is_el(*n, XENC, "EncryptionMethod")).and_then(|n| n.attribute("Algorithm")).unwrap_or("").to_string()
}

/// A certificate as the page names it: its subject and a fingerprint.
fn fingerprint_of_der(der: &[u8]) -> String {
    let subject = crate::x509util::subject_string(der);
    if subject.is_empty() { fingerprint(der) } else { format!("{subject}, {}", fingerprint(der)) }
}

/// The Session tab: what protects the sign-in, who signed in, where the
/// sign-in is kept, and the credentials. The security token's value stays
/// in this process: the page shows what the library verified in it and a
/// fingerprint, never the token.
pub(crate) fn session_panes(rp: &RelyingParty, login: &Login, facts: Option<&TokenFacts>, stream: &str, tracked: Option<bool>, held: usize) -> String {
    let config = &rp.config;
    let certs = rp.idp.as_ref().map(|idp| idp.signing_certificates.len()).unwrap_or(0);
    let encrypted = if login.encrypted {
        "on: the assertion arrived encrypted to this relying party's key, and was decrypted here".to_string()
    } else {
        "off: the assertion came signed but not encrypted (wantAssertionsEncrypted is off), over TLS".to_string()
    };
    let solicited = if login.request_id.is_some() {
        "the response answers the sign-in this browser started: wctx's id matched a signed, short-lived cookie".to_string()
    } else {
        "unsolicited: accepted because allowUnsolicited is on".to_string()
    };
    let tls = if config.idp_ca.contains("-----BEGIN") {
        "the identity provider and the transmitter are verified against idpCa's trust chain"
    } else {
        "the identity provider and the transmitter are verified against the system's roots"
    };
    let cookie = if url::Url::parse(&config.reply_url).is_ok_and(|u| u.scheme() == "https") { "; Secure" } else { "" };
    let signals = match tracked {
        Some(true) => format!("{stream}; this session is tracked: an ending CAEP or RISC event ends it"),
        Some(false) => format!("{stream}; this session is not tracked"),
        None if stream.is_empty() => "not running".to_string(),
        None => stream.to_string(),
    };
    let protections = [
        ("Signed security token", format!("the assertion's XML signature verified (exclusive canonicalization) against the identity provider's metadata: {certs} signing certificate(s)")),
        ("Encryption", encrypted),
        ("Audience", format!("AudienceRestriction must name this realm ({}), and AppliesTo too when the response has one", config.realm)),
        ("Bearer confirmation", "Recipient is this reply URL, NotOnOrAfter checked; a NotBefore or InResponseTo is refused".to_string()),
        ("Validity", format!("Conditions and the response's Lifetime checked, with {} ms of clock skew", config.clock_skew_ms)),
        ("Replay", "each assertion id is accepted once, and remembered until it expires".to_string()),
        ("Solicited", solicited),
        ("TLS", tls.to_string()),
        ("Session cookie", format!("a random id, HMAC-signed, HttpOnly, SameSite=Lax{cookie}; the security token is never sent to the browser")),
        ("Shared Signals", signals),
    ];
    let list: String = protections.iter().map(|(k, v)| format!("<li><strong>{}</strong> <span class=\"muted\">{}</span></li>", esc(k), esc(v))).collect();
    let mut out = pane("security-card", "Protections in effect", "", &format!("<ul class=\"checks\">{list}</ul>"));

    let now = Utc::now().timestamp();
    let mut who = vec![
        ("NameID".to_string(), format!("{}{}", login.name_id, login.name_id_format.as_ref().map(|f| format!(" ({f})")).unwrap_or_default())),
        ("Issuer".into(), login.issuer.clone()),
        ("Realm".into(), login.realm.clone()),
        ("Authenticated".into(), when(login.authn_instant)),
        ("Authentication context".into(), login.authn_context_class_ref.clone().unwrap_or_else(|| "not stated".into())),
        ("SessionIndex".into(), login.session_index.clone().unwrap_or_else(|| "not stated".into())),
    ];
    if let Some(q) = &login.name_qualifier { who.push(("NameQualifier".into(), q.clone())); }
    if let Some(q) = &login.sp_name_qualifier { who.push(("SPNameQualifier".into(), q.clone())); }
    let mut names: Vec<&String> = login.attributes.keys().collect();
    names.sort();
    let claims: Vec<(String, String)> = names.iter().map(|name| {
        let label = match login.attribute_friendly_names.get(*name) {
            Some(friendly) => format!("{name} ({friendly})"),
            None => (*name).clone(),
        };
        (label, login.attributes[*name].join(", "))
    }).collect();
    let signed_in = format!("signed in {}", in_words(login.authn_instant.timestamp() - now));
    out.push_str(&pane("session-card", "Session", &signed_in, &format!(
        "{}<h3>Claims</h3>{}<p><small>Every attribute of the assertion this sign-in returned, as the library verified it. A claim URI is shown in full; the PEP names it by its FriendlyName or its last segment.</small></p>",
        facts_table(&who),
        if claims.is_empty() { "<p><small>The assertion carried no attributes.</small></p>".to_string() } else { facts_table(&claims) }
    )));

    let session_end = login.session_not_on_or_after.map(when).unwrap_or_else(|| "not stated: until sign-out or an ending event".into());
    let tracking = match tracked {
        Some(true) => "tracked by the receiver (an ending event removes it)",
        Some(false) => "not tracked by the receiver",
        None => "no receiver is running",
    };
    let cache = vec![
        ("Kept in".to_string(), "this process's memory, under the signed cookie's id; never sent to the browser".to_string()),
        ("Sign-ins held".into(), held.to_string()),
        ("Assertion valid until".into(), when(login.not_on_or_after)),
        ("Identity provider's session".into(), session_end),
        ("Shared Signals".into(), tracking.to_string()),
        ("Refresh".into(), "none: WS-Federation issues no refresh token. Sign in again when the session ends; the menu's Sign in with another account asks the identity provider to authenticate again.".into()),
    ];
    out.push_str(&pane("cache-card", "Credential cache", &format!("{held} sign-in(s)"), &facts_table(&cache)));

    let mut token = facts.map(|f| f.rows.clone()).unwrap_or_else(|| vec![("Response as received".to_string(), "not noted (this session began before the demo noted it)".to_string())]);
    token.insert(0, ("Assertion ID".into(), login.assertion_id.clone()));
    token.insert(1, ("WS-Trust version".into(), login.trust_version.clone()));
    let mut own = Vec::new();
    if let Some(cert) = &config.certificate {
        own.push(("Certificate".to_string(), fingerprint_of_der(&cert.der)));
    }
    own.push(("Private key".into(), if config.private_key.is_some() { "held in this process: it decrypts assertions, signs the metadata, and is the Shared Signals client certificate's key".into() } else { "none".to_string() }));
    let idp: Vec<(String, String)> = rp.idp.as_ref().map(|idp| idp.signing_certificates.iter().enumerate().map(|(i, c)| (format!("Signing certificate {}", i + 1), fingerprint_of_der(&c.der))).collect()).unwrap_or_default();
    out.push_str(&pane("credentials-card", "Credentials", "", &format!(
        "<p><small>The values stay in this process: each is shown by its facts and a SHA-256 fingerprint.</small></p><h3>The security token</h3>{}<h3>This relying party</h3>{}<h3>The identity provider</h3>{}",
        facts_table(&token),
        facts_table(&own),
        if idp.is_empty() { "<p><small>No metadata loaded.</small></p>".to_string() } else { facts_table(&idp) }
    )));
    out
}

/// The family a SET event type belongs to, for its badge.
pub(crate) fn family_of(event_type: &str) -> &'static str {
    if event_type.contains("/caep/") {
        "CAEP"
    } else if event_type.contains("/risc/") {
        "RISC"
    } else if event_type.contains("/ssf/") {
        "SSF"
    } else {
        "STS"
    }
}

pub(crate) fn event_json(event: &LiveEvent) -> Value {
    json!({
        "id": event.id, "type": event.event_type, "jti": event.jti, "family": event.family,
        "at": event.at, "subject": event.subject, "members": event.members, "ended": event.ended,
        "about": if event.family == "SSF" { "stream" } else { "subject" },
    })
}

/// One log entry: the same markup `app.js`'s `entryNode()` draws.
pub(crate) fn event_item(event: &LiveEvent) -> String {
    let short = event.event_type.rsplit("/event-type/").next().unwrap_or(&event.event_type);
    let outcome = if event.family == "SSF" {
        "about the stream: the verification this session asked for"
    } else if event.ended {
        "ended this session"
    } else {
        "recorded; this session continues"
    };
    let mut out = format!(
        "<li class=\"log-item\" data-id=\"{}\"><div class=\"log-top\"><span class=\"badge {}\">{}</span> <strong>{}</strong> <time>{}</time></div><p class=\"log-outcome{}\">{}</p>",
        event.id,
        esc(&event.family.to_lowercase()),
        esc(&event.family),
        esc(short),
        esc(&event.at),
        if event.ended { " ended" } else { "" },
        outcome
    );
    if !event.subject.is_empty() {
        out.push_str(&format!("<p><small>Subject: {}</small></p>", esc(&event.subject)));
    }
    if let Some(members) = event.members.as_object().filter(|m| !m.is_empty()) {
        out.push_str("<table class=\"facts members\">");
        for (name, value) in members {
            if name == "subject" {
                continue;
            }
            let text = match value {
                Value::String(s) => s.clone(),
                Value::Object(o) if !o.is_empty() && o.values().all(|v| v.is_string()) => o.values().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(" / "),
                other => other.to_string(),
            };
            out.push_str(&format!("<tr><th>{}</th><td>{}</td></tr>", esc(name), esc(&text)));
        }
        out.push_str("</table>");
    }
    out.push_str(&format!("<p><small>jti {}</small></p></li>", esc(&event.jti)));
    out
}

/// The CAEP & RISC events tab: whose events these are, the stream with its
/// verification request, and the log, newest first. `app.js` adds what
/// arrives without reloading.
pub(crate) fn events_panel(events: &[LiveEvent], stream: &str, notice: &str) -> String {
    let items: String = events.iter().rev().map(event_item).collect();
    let notice = if notice.is_empty() { String::new() } else { format!("<p class=\"notice\">{}</p>", esc(notice)) };
    // The one stream is the application's, so the log is too: a real
    // application shows a person only events about their own session or
    // account, and keeps the rest from them.
    let scope = pane("events-scope", "Whose events these are", "", "<p class=\"warning\"><strong>Every event this application received, for every user.</strong> This tab lists all the CAEP and RISC events the application's Shared Signals stream delivered: events about other people's sessions and accounts as well as yours. That is for this demonstration only. A real application must take additional safeguards: show a person only the events about their own session or account, and keep the others to the people whose job is to see them.</p>");
    let stream_pane = pane("events-stream", "Shared Signals stream", "", &format!(
        "<table class=\"facts\"><tr><th>Stream status</th><td id=\"stream-status\">{}</td></tr><tr><th>Live</th><td id=\"live-state\">connecting…</td></tr></table>\
<form id=\"verify-form\" method=\"post\" action=\"/signals/verify\"><button type=\"submit\">Ask for a verification event</button></form>",
        esc(stream)
    ));
    let count = if events.is_empty() { String::new() } else { format!("{} event(s)", events.len()) };
    let log_pane = pane("events-log", "Event log", &count, &format!(
        "<p><small>The CAEP and RISC events this application's receiver has accepted, about anybody, newest first, and the verification events it asked for. Each appears here within moments of the receiver getting it.</small></p>\
<ul class=\"log\" id=\"log\">{items}</ul>\
<p class=\"empty\" id=\"log-empty\"{}>No CAEP or RISC event yet. At iya-sts, change this person's password (credential-change), sign them out (session-revoked), or disable them (account-disabled), and watch this tab.</p>",
        if events.is_empty() { "" } else { " hidden" }
    ));
    format!("{notice}{scope}{stream_pane}{log_pane}")
}

fn reply_origin(reply: &str) -> String {
    let Some((scheme, rest)) = reply.split_once("://") else { return "/".to_string() };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() { "/".to_string() } else { format!("{scheme}://{host}/") }
}

fn cookies(header: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for part in header.split(';') {
        let part = part.trim();
        let Some((name, value)) = part.split_once('=') else { continue };
        if !name.is_empty() && !value.is_empty() && !out.contains_key(name) { out.insert(name.to_string(), value.to_string()); }
    }
    out
}

/// One query parameter of a request target, decoded, or empty.
pub(crate) fn query_param(target: &str, name: &str) -> String {
    let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
    url::form_urlencoded::parse(query.as_bytes()).find(|(k, _)| k == name).map(|(_, v)| v.into_owned()).unwrap_or_default()
}

/// The embedded PEP's `Status` as JSON (`GET /pep-status`), every time in
/// milliseconds. It holds no secret.
#[cfg(feature = "pep")]
pub(crate) fn pep_json(rp: &RelyingParty) -> Value {
    let Some(pep) = rp.pep() else {
        return json!({"enabled": false, "why": "no pep section is configured"});
    };
    let s = pep.status();
    let ms = |d: Option<std::time::Duration>| d.map(|d| d.as_millis() as u64);
    json!({
        "enabled": true,
        "name": s.name, "mode": s.mode.as_str(), "application": s.application, "pdpUrl": s.pdp_url,
        "protocolVersion": s.protocol_version, "registered": s.registered, "running": s.running,
        "eventStream": s.event_stream.as_str(), "keyThumbprint": s.key_thumbprint, "problems": s.last_error,
        "policy": {
            "held": s.holds_policy, "count": s.policy_count, "syncToken": s.sync_token,
            "catalogueToken": s.catalogue_token, "catalogueSubjectClaims": s.catalogue_subject_properties,
            "sinceUpdateMs": ms(s.since_policy_update), "sinceLastPullMs": ms(s.since_last_pull),
            "untilNextPullMs": ms(s.until_next_pull), "pulls": s.pulls, "pullsChanged": s.pulls_changed,
            "pullFailures": s.pull_failures, "eventsReceived": s.events_received, "eventsIgnored": s.events_ignored,
            "sinceLastEventMs": ms(s.since_last_event),
        },
        "decisions": {
            "total": s.decisions, "allowed": s.allowed, "denied": s.refused, "unavailable": s.unavailable,
            "undischargeable": s.undischargeable, "meanMicros": s.mean_decision_micros, "maxMicros": s.max_decision_micros,
            "permitCacheEntries": s.permit_cache_entries, "permitCacheHits": s.permit_cache_hits,
        },
        "controlPlane": {
            "uptimeMs": ms(s.uptime), "registrations": s.registrations, "heartbeats": s.heartbeats,
            "heartbeatFailures": s.heartbeat_failures, "sinceLastHeartbeatMs": ms(s.since_last_heartbeat),
            "untilNextHeartbeatMs": ms(s.until_next_heartbeat), "recordsQueued": s.records_queued,
            "recordsShipped": s.records_shipped, "recordsDropped": s.records_dropped,
        },
    })
}

#[cfg(not(feature = "pep"))]
pub(crate) fn pep_json(_rp: &RelyingParty) -> Value {
    json!({"enabled": false, "why": "this demo was built without the pep feature"})
}

/// A duration as a person reads it: `42 s ago`, `in 5 min 0 s`.
pub(crate) fn human(d: Option<std::time::Duration>, ago: bool) -> String {
    let Some(d) = d else { return "—".into() };
    let s = d.as_secs();
    if s == 0 {
        return if ago { "just now".into() } else { "now".into() };
    }
    let text = if s < 120 {
        format!("{s} s")
    } else if s < 7200 {
        format!("{} min {} s", s / 60, s % 60)
    } else {
        format!("{} h {} min", s / 3600, s % 3600 / 60)
    };
    if ago { format!("{text} ago") } else { format!("in {text}") }
}

/// The Policy enforcement tab's content, drawn here and fetched again every
/// 2 s by pep.js: collapsible panes with stable ids, everything escaped.
pub(crate) fn pep_fragment(rp: &RelyingParty) -> String {
    let v = pep_json(rp);
    if v["enabled"] != json!(true) {
        return pane("pep-none", "No embedded PEP", "", &format!(
            "<p class=\"notice\">No embedded PEP: {}. Add a <code>pep</code> section to the configuration (<code>python3 scripts/configure_iya_sts.py --pep local</code> sets one up) and build with the <code>local</code> (or <code>pep</code>) feature; see <code>docs/remote-pep.md</code>.</p>",
            esc(v["why"].as_str().unwrap_or(""))
        ));
    }
    let text = |x: &Value| match x {
        Value::String(s) if s.is_empty() => "—".to_string(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => if *b { "yes".into() } else { "no".into() },
        Value::Null => "—".into(),
        other => other.to_string(),
    };
    let dur = |x: &Value, ago: bool| human(x.as_u64().map(std::time::Duration::from_millis), ago);
    let micros = |x: &Value| x.as_u64().map(|m| if m >= 1000 { format!("{:.1} ms", m as f64 / 1000.0) } else { format!("{m} µs") }).unwrap_or_else(|| "—".into());
    let (p, d, c) = (&v["policy"], &v["decisions"], &v["controlPlane"]);
    let local = v["mode"] == json!("local");
    let mut decisions = vec![
        ("Decisions".to_string(), text(&d["total"])),
        ("Allowed".into(), text(&d["allowed"])),
        ("Denied".into(), text(&d["denied"])),
        ("Unavailable (no decision; refused)".into(), text(&d["unavailable"])),
        ("Stopped by an obligation".into(), text(&d["undischargeable"])),
        ("Mean time per decision".into(), micros(&d["meanMicros"])),
        ("Slowest decision".into(), micros(&d["maxMicros"])),
    ];
    if !local {
        decisions.push(("Permit cache".into(), format!("{} held, {} answered from it", text(&d["permitCacheEntries"]), text(&d["permitCacheHits"]))));
    }
    let mut policy = vec![
        ("Policies held".to_string(), if local { text(&p["count"]) } else { "— (central mode: iya-sts decides)".into() }),
        ("Last policy update".into(), dur(&p["sinceUpdateMs"], true)),
        ("Last pull (changed or not)".into(), dur(&p["sinceLastPullMs"], true)),
        ("Next scheduled pull".into(), dur(&p["untilNextPullMs"], false)),
        ("Pulls".into(), format!("{} ({} brought changes, {} failed)", text(&p["pulls"]), text(&p["pullsChanged"]), text(&p["pullFailures"]))),
        ("Policy-change events".into(), format!("{} acted on, {} for another PEP; last {}", text(&p["eventsReceived"]), text(&p["eventsIgnored"]), dur(&p["sinceLastEventMs"], true))),
        ("Catalogue claims sent".into(), text(&p["catalogueSubjectClaims"])),
    ];
    if local {
        policy.push(("Policy set version".into(), text(&p["syncToken"])));
    }
    policy.push(("Catalogue version".into(), text(&p["catalogueToken"])));
    let the_pep = vec![
        ("Name".to_string(), text(&v["name"])),
        ("Mode".into(), text(&v["mode"])),
        ("Application".into(), text(&v["application"])),
        ("iya-sts".into(), text(&v["pdpUrl"])),
        ("Registered".into(), text(&v["registered"])),
        ("Running".into(), format!("{} (up {})", text(&v["running"]), dur(&c["uptimeMs"], false).trim_start_matches("in "))),
        ("Policy-change events on the stream".into(), text(&v["eventStream"])),
        ("Protocol version".into(), text(&v["protocolVersion"])),
        ("Key thumbprint".into(), text(&v["keyThumbprint"])),
    ];
    let control = vec![
        ("Heartbeats".to_string(), format!("{} ({} failed)", text(&c["heartbeats"]), text(&c["heartbeatFailures"]))),
        ("Last heartbeat".into(), dur(&c["sinceLastHeartbeatMs"], true)),
        ("Next heartbeat".into(), dur(&c["untilNextHeartbeatMs"], false)),
        ("Registrations".into(), text(&c["registrations"])),
        ("Decision records".into(), format!("{} queued, {} sent, {} dropped", text(&c["recordsQueued"]), text(&c["recordsShipped"]), text(&c["recordsDropped"]))),
    ];
    let mut out = String::new();
    let problems = v["problems"].as_str().unwrap_or("");
    if !problems.is_empty() {
        out.push_str(&pane("pep-problems", "Problems", "", &format!("<p class=\"problem\">{}</p>", esc(problems))));
    }
    // The ids are stable, so pep.js keeps a pane the person closed closed.
    for (id, title, rows) in [("pep-decisions", "Decisions", decisions), ("pep-cached-policy", "Cached policy", policy), ("pep-the-pep", "The PEP", the_pep), ("pep-control-plane", "Control plane", control)] {
        out.push_str(&pane(id, title, "", &facts_table(&rows)));
    }
    out.push_str(&pane("pep-try", "Try it", "", "<ul class=\"checks\">\
<li><a href=\"/orders/42\">/orders/42</a> <span class=\"muted\">read an order: permitted when your sign-in carried an authentication context (acr)</span></li>\
<li><a href=\"/attribute-protected\">/attribute-protected</a> <span class=\"muted\">permitted when your directory attribute attr1 is abc123, which the PEP asks iya-sts's PIP for</span></li>\
</ul><p><small>Each is decided by this PEP against the demo application's own policy; the counters above move as you try them.</small></p>"));
    out.push_str("<p><small>Refreshed every 2 seconds. <a href=\"/pep-status\">As JSON</a>.</small></p>");
    out
}

fn esc(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn token_url(n: usize) -> String {
    let mut buf = vec![0u8; n];
    for byte in &mut buf { *byte = rand::random(); }
    URL_SAFE_NO_PAD.encode(buf)
}

pub fn serve<F>(port: u16, mut get_app: F) -> std::io::Result<()>
where
    F: FnMut() -> Result<Arc<App>>,
{
    let server = Server::http(format!("0.0.0.0:{port}")).map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    println!("wsfed-caep demo on port {port}");
    for mut request in server.incoming_requests() {
        let url = request.url().to_string();
        let path = url.split_once('?').map(|(path, _)| path).unwrap_or(url.as_str());
        if path == "/healthz" {
            let _ = request.respond(Response::from_string("ok").with_status_code(StatusCode(200)).with_header(header("content-type", "text/plain")));
            continue;
        }
        let app = match get_app() {
            Ok(value) => value,
            Err(err) => {
                let _ = request.respond(Response::from_string(format!("not ready: {err}\n")).with_status_code(StatusCode(503)).with_header(header("content-type", "text/plain")));
                continue;
            }
        };
        let mut headers = HashMap::new();
        for item in request.headers() {
            headers.insert(item.field.as_str().as_str().to_ascii_lowercase(), item.value.as_str().to_string());
        }
        let mut body = Vec::new();
        let _ = std::io::Read::read_to_end(request.as_reader(), &mut body);
        let (status, fields, payload) = app.handle(request.method().as_str(), &url, &headers, &body);
        let mut response = Response::from_data(payload).with_status_code(StatusCode(status));
        for (name, value) in fields { response.add_header(header(&name, &value)); }
        let _ = request.respond(response);
    }
    Ok(())
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).unwrap_or_else(|_| Header::from_bytes(b"x", b"x").unwrap())
}

fn loopback(host: &str) -> bool {
    let host = host.trim_matches(|ch| ch == '[' || ch == ']');
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

pub fn on_port(raw: &str, port: u16) -> String {
    let Ok(mut parsed) = url::Url::parse(raw) else { return raw.to_string() };
    let host = parsed.host_str().unwrap_or("").trim_matches(|ch| ch == '[' || ch == ']').to_string();
    if host.is_empty() || !loopback(&host) { return raw.to_string(); }
    if host.contains(':') {
        let _ = parsed.set_host(Some(&host));
        let _ = parsed.set_port(Some(port));
        return format!("{}://[{host}]:{port}{}", parsed.scheme(), path_query(&parsed));
    }
    let _ = parsed.set_port(Some(port));
    parsed.to_string()
}

fn path_query(parsed: &url::Url) -> String {
    let mut out = parsed.path().to_string();
    if let Some(query) = parsed.query() { out.push('?'); out.push_str(query); }
    if let Some(fragment) = parsed.fragment() { out.push('#'); out.push_str(fragment); }
    out
}

pub fn endpoints_for(realm: &str, reply: &str, public: &str, given: bool, port: u16) -> (String, String) {
    if given && !public.is_empty() {
        return (move_origin(realm, public), move_origin(reply, public));
    }
    if port > 0 { return (on_port(realm, port), on_port(reply, port)); }
    (realm.to_string(), reply.to_string())
}

fn move_origin(value: &str, public: &str) -> String {
    let public = public.trim_end_matches('/');
    let Ok(base) = url::Url::parse(&format!("{public}/")) else { return value.to_string() };
    let Ok(mut next) = url::Url::parse(value) else { return value.to_string() };
    let host = base.host_str().unwrap_or("");
    if next.set_scheme(base.scheme()).is_err() { return value.to_string(); }
    if host.contains(':') {
        let _ = next.set_host(Some(host));
        let _ = next.set_port(base.port());
        return format!("{}://[{host}]{}{}", next.scheme(), base.port().map(|port| format!(":{port}")).unwrap_or_default(), path_query(&next));
    }
    let _ = next.set_host(Some(host));
    let _ = next.set_port(base.port());
    next.to_string()
}

pub fn load_party(path: &str, port: u16, public: &str, given: bool) -> Result<(RelyingParty, serde_json::Map<String, serde_json::Value>)> {
    let raw_text = std::fs::read_to_string(path).map_err(|err| crate::fail("config", err.to_string()))?;
    let raw = parse_object(&raw_text)?;
    let realm = raw.get("realm").and_then(|item| item.as_str()).unwrap_or("").to_string();
    let reply = raw.get("replyUrl").and_then(|item| item.as_str()).unwrap_or("").to_string();
    let (realm, reply) = endpoints_for(&realm, &reply, public, given, port);
    let mut overrides = serde_json::Map::new();
    if !realm.is_empty() { overrides.insert("realm".to_string(), serde_json::Value::String(realm)); }
    if !reply.is_empty() { overrides.insert("replyUrl".to_string(), serde_json::Value::String(reply)); }
    let party = RelyingParty::from_file(path, Some(overrides))?;
    Ok((party, raw))
}

fn public_url(argv: &[String]) -> std::result::Result<(String, bool), String> {
    let mut public = std::env::var("PUBLIC_URL").unwrap_or_default();
    let mut given = !public.is_empty();
    public = public.trim_end_matches('/').to_string();
    let mut index = 0;
    while index < argv.len() {
        if argv[index] == "--public-url" {
            if index + 1 >= argv.len() || argv[index + 1].is_empty() { return Err("--public-url is empty".to_string()); }
            public = argv[index + 1].trim_end_matches('/').to_string();
            given = true;
            index += 1;
        }
        index += 1;
    }
    Ok((public, given))
}

fn config_path(argv: &[String]) -> String {
    let mut configured = std::env::var("WSFED_CONFIG").unwrap_or_default();
    for (index, arg) in argv.iter().enumerate() {
        if arg == "--config" && index + 1 < argv.len() { configured = argv[index + 1].clone(); }
    }
    if configured.is_empty() { "demo/wsfed.json".to_string() } else { configured }
}

fn arg_port(argv: &[String]) -> Option<u16> {
    argv.iter().position(|arg| arg == "--port").and_then(|index| argv.get(index + 1)).and_then(|text| text.parse().ok())
}

pub fn main_args() -> i32 {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut port = std::env::var("PORT").ok().and_then(|text| text.parse().ok()).unwrap_or(3000u16);
    if let Some(value) = arg_port(&argv) { port = value; }
    let (public, given) = match public_url(&argv) {
        Ok(value) => value,
        Err(err) => { eprintln!("{err}"); return 1; }
    };
    let path = config_path(&argv);
    let holder: Arc<Mutex<Option<Arc<App>>>> = Arc::new(Mutex::new(None));
    let holder_for = holder.clone();
    let err = serve(port, move || {
        if let Some(app) = holder_for.lock().unwrap().clone() { return Ok(app); }
        let (party, raw) = load_party(&path, port, &public, given)?;
        let sessions_slot: Arc<Mutex<Option<Arc<Mutex<HashMap<String, Login>>>>>> = Arc::new(Mutex::new(None));
        let app = Arc::new(App::new(party, None));
        *sessions_slot.lock().unwrap() = Some(app.sessions_handle());
        let signals_off = raw.get("signals").and_then(|item| item.as_bool()) == Some(false);
        let ssf_block = raw.get("ssf").and_then(|item| item.as_object());
        let transmitter_of = ssf_block.and_then(|ssf| ssf.get("transmitter")).and_then(|item| item.as_str()).unwrap_or("");
        let state = if signals_off {
            Some("not configured (signals are off)")
        } else if transmitter_of.is_empty() {
            Some("not configured (no ssf block in the configuration file)")
        } else if app.rp.config.private_key.is_none() {
            Some("not running: the relying party has no private key")
        } else {
            None
        };
        if let Some(state) = state { *app.receiver_state.lock().unwrap() = state.to_string(); }
        if !signals_off {
            if let Some(ssf) = ssf_block {
                let transmitter = ssf.get("transmitter").and_then(|item| item.as_str()).unwrap_or("");
                if !transmitter.is_empty() && app.rp.config.private_key.is_some() {
                    let interval = ssf.get("pollIntervalMs").and_then(|item| item.as_i64().or_else(|| item.as_f64().map(|n| n as i64))).filter(|n| *n > 0).unwrap_or(5000);
                    let cert = app.rp.config.certificate.as_ref().map(|item| format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", wrap64(&cert_pem_body(&item.der)))).unwrap_or_default();
                    let key = app.rp.config.private_key.as_ref().and_then(|item| item.to_pkcs8_der().ok()).map(|der| pem::encode(&Pem::new("PRIVATE KEY", der.as_bytes().to_vec()))).unwrap_or_default();
                    let sessions = app.sessions_handle();
                    match SignalsReceiver::new(transmitter, Arc::new(move |ids, _| { for id in ids { sessions.lock().unwrap().remove(id); } Ok(()) }), ReceiverOptions {
                        tls: Some(TlsConfig { ca: app.rp.config.idp_ca.clone(), cert, key }),
                        poll_interval_ms: interval,
                        #[cfg(feature = "pep")]
                        pep: app.rp.pep().cloned(),
                        ..ReceiverOptions::default()
                    }) {
                        Ok(receiver) => {
                            let weak = Arc::downgrade(&app);
                            receiver.on("*", Arc::new(move |event| {
                                if let Some(app) = weak.upgrade() { app.remember(event); }
                                Ok(())
                            }));
                            *app.receiver.lock().unwrap() = Some(receiver.clone());
                            match receiver.start() {
                                Ok(()) => {
                                    let stream_id = receiver.stream().get("stream_id").and_then(|item| item.as_str()).unwrap_or("").to_string();
                                    *app.receiver_state.lock().unwrap() = format!("polling stream {stream_id} at {transmitter}");
                                }
                                Err(err) => {
                                    *app.receiver.lock().unwrap() = None;
                                    *app.receiver_state.lock().unwrap() = format!("not running: {err}");
                                    println!("ssf: not started: {err}");
                                }
                            }
                        }
                        Err(err) => {
                            *app.receiver_state.lock().unwrap() = format!("not running: {err}");
                            println!("ssf: not started: {err}");
                        }
                    }
                }
            }
        }
        *holder_for.lock().unwrap() = Some(app.clone());
        Ok(app)
    });
    if let Err(err) = err { eprintln!("{err}"); return 1; }
    let _ = holder;
    0
}

fn wrap64(body: &str) -> String {
    body.as_bytes().chunks(64).map(|chunk| std::str::from_utf8(chunk).unwrap_or("")).collect::<Vec<_>>().join("\n")
}

pub fn write_stdout(bytes: &[u8]) { let _ = io::stdout().write_all(bytes); }
