// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use super::events::{self, subject_of};
use super::jws::verify_compact_jws;
use super::session::{tracked_from, MemorySessionIndex};
use crate::error::{fail, Result, WsFedError};
use crate::httpclient::{self, TlsMaterial};
use crate::token::Login;
use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const POLL_METHOD: &str = "urn:ietf:rfc:8936";

pub trait SignalsLog: Send + Sync {
    fn info(&self, message: &str);
    fn warn(&self, message: &str);
    fn error(&self, message: &str);
}

struct StdLog;
impl SignalsLog for StdLog {
    fn info(&self, message: &str) { println!("{message}"); }
    fn warn(&self, message: &str) { eprintln!("{message}"); }
    fn error(&self, message: &str) { eprintln!("{message}"); }
}

#[derive(Clone, Debug)]
pub struct SignalEvent {
    pub event_type: String,
    pub payload: Value,
    pub subject: HashMap<String, String>,
    pub jti: String,
    pub sessions: Vec<String>,
    pub ended: bool,
    pub iat: Option<f64>,
    pub txn: Option<String>,
}

pub struct TlsConfig {
    pub ca: String,
    pub cert: String,
    pub key: String,
}

type EndFn = Arc<dyn Fn(&[String], &SignalEvent) -> Result<()> + Send + Sync>;
type HandlerFn = Arc<dyn Fn(&SignalEvent) -> Result<()> + Send + Sync>;

pub struct ReceiverOptions {
    pub tls: Option<TlsConfig>,
    pub events_requested: Option<Vec<String>>,
    pub end_on: Option<Vec<String>>,
    pub index: Option<MemorySessionIndex>,
    pub subject_attribute: String,
    pub description: String,
    pub poll_interval_ms: i64,
    pub max_events: i64,
    pub log: Option<Arc<dyn SignalsLog>>,
}

impl Default for ReceiverOptions {
    fn default() -> Self {
        Self {
            tls: None,
            events_requested: None,
            end_on: None,
            index: None,
            subject_attribute: String::new(),
            description: String::new(),
            poll_interval_ms: 0,
            max_events: 0,
            log: None,
        }
    }
}

struct Flight {
    done: Mutex<bool>,
    cv: Condvar,
    result: Mutex<Option<std::result::Result<bool, WsFedError>>>,
}

struct State {
    config: Map<String, Value>,
    stream: Map<String, Value>,
    keys: Vec<Map<String, Value>>,
    keys_at: Option<Instant>,
    ack: Vec<String>,
    errs: Map<String, Value>,
    handlers: HashMap<String, Vec<HandlerFn>>,
}

pub struct SignalsReceiver {
    transmitter: String,
    on_end: EndFn,
    tls: Option<TlsMaterial>,
    events_requested: Vec<String>,
    end_on: Vec<String>,
    index: MemorySessionIndex,
    subject_attribute: String,
    description: String,
    poll_interval_ms: i64,
    max_events: i64,
    log: Arc<dyn SignalsLog>,
    state: Mutex<State>,
    running: AtomicBool,
    inflight: Mutex<Option<Arc<Flight>>>,
    stop_tx: Mutex<Option<Sender<()>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
    done_rx: Mutex<Option<Receiver<()>>>,
}

impl SignalsReceiver {
    pub fn new(transmitter: &str, on_end: EndFn, opts: ReceiverOptions) -> Result<Arc<Self>> {
        if !(transmitter.starts_with("http://") || transmitter.starts_with("https://")) {
            return Err(fail("config", "transmitter must be an http(s) URL"));
        }
        let tls = opts.tls.map(|item| TlsMaterial {
            ca: if item.ca.is_empty() { None } else { Some(item.ca) },
            cert: if item.cert.is_empty() { None } else { Some(item.cert) },
            key: if item.key.is_empty() { None } else { Some(item.key) },
        });
        Ok(Arc::new(Self {
            transmitter: transmitter.trim_end_matches('/').to_string(),
            on_end,
            tls,
            events_requested: opts.events_requested.unwrap_or_else(events::default_events_requested),
            end_on: opts.end_on.unwrap_or_else(events::default_ending_events),
            index: opts.index.unwrap_or_else(|| MemorySessionIndex::new(0)),
            subject_attribute: opts.subject_attribute,
            description: opts.description,
            poll_interval_ms: if opts.poll_interval_ms == 0 { 5000 } else { opts.poll_interval_ms },
            max_events: if opts.max_events == 0 { 50 } else { opts.max_events },
            log: opts.log.unwrap_or_else(|| Arc::new(StdLog)),
            state: Mutex::new(State { config: Map::new(), stream: Map::new(), keys: Vec::new(), keys_at: None, ack: Vec::new(), errs: Map::new(), handlers: HashMap::new() }),
            running: AtomicBool::new(false),
            inflight: Mutex::new(None),
            stop_tx: Mutex::new(None),
            thread: Mutex::new(None),
            done_rx: Mutex::new(None),
        }))
    }

    pub fn stream(&self) -> Map<String, Value> {
        self.state.lock().unwrap().stream.clone()
    }

    pub fn track(&self, local_id: &str, login: &Login, expires_at: Option<DateTime<Utc>>) {
        self.index.add(tracked_from(local_id, Some(login), &self.subject_attribute, expires_at));
    }

    pub fn untrack(&self, local_id: &str) { self.index.remove(local_id); }

    pub fn on(self: &Arc<Self>, event_type: &str, handler: HandlerFn) {
        self.state.lock().unwrap().handlers.entry(event_type.to_string()).or_default().push(handler);
    }

    pub fn start(self: &Arc<Self>) -> Result<()> {
        if self.running.load(Ordering::SeqCst) { return Ok(()); }
        let config = self.discover()?;
        self.state.lock().unwrap().config = config;
        self.jwks(true)?;
        let stream = self.ensure_stream()?;
        let endpoint = delivery_url(&stream);
        if endpoint.is_empty() { return Err(fail("ssf", "the stream has no poll endpoint_url")); }
        if self.running.load(Ordering::SeqCst) {
            self.state.lock().unwrap().stream = stream;
            return Ok(());
        }
        let delivered = stream.get("events_delivered").and_then(|value| value.as_array()).map(|list| list.len()).unwrap_or(0);
        let stream_id = text_of(&stream, "stream_id");
        self.log.info(&format!("ssf: polling stream {stream_id} at {endpoint}, delivering {delivered} event type(s)"));
        self.state.lock().unwrap().stream = stream;
        let (stop_tx, stop_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        *self.stop_tx.lock().unwrap() = Some(stop_tx);
        *self.done_rx.lock().unwrap() = Some(done_rx);
        self.running.store(true, Ordering::SeqCst);
        let this = Arc::clone(self);
        let handle = thread::spawn(move || {
            this.loop_poll(stop_rx);
            let _ = done_tx.send(());
        });
        *self.thread.lock().unwrap() = Some(handle);
        Ok(())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(tx) = self.stop_tx.lock().unwrap().take() { let _ = tx.send(()); }
        let done = self.done_rx.lock().unwrap().take();
        if let Some(done) = done {
            let _ = done.recv_timeout(Duration::from_secs(20));
        }
        if let Some(handle) = self.thread.lock().unwrap().take() {
            let _ = handle.join();
        }
    }

    fn loop_poll(&self, stop_rx: Receiver<()>) {
        while self.running.load(Ordering::SeqCst) {
            let mut delay = self.poll_interval_ms;
            match self.poll_once() {
                Ok(true) => delay = 0,
                Ok(false) => {}
                Err(err) => {
                    self.log.warn(&format!("ssf: poll failed: {err}"));
                    delay = (self.poll_interval_ms * 4).min(60_000);
                }
            }
            if !self.running.load(Ordering::SeqCst) { return; }
            match stop_rx.recv_timeout(Duration::from_millis(delay.max(0) as u64)) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    }

    pub fn poll_once(&self) -> Result<bool> {
        let flight = {
            let mut slot = self.inflight.lock().unwrap();
            if let Some(existing) = slot.clone() {
                drop(slot);
                let mut done = existing.done.lock().unwrap();
                while !*done { done = existing.cv.wait(done).unwrap(); }
                drop(done);
                return existing.result.lock().unwrap().clone().unwrap_or(Ok(false));
            }
            let flight = Arc::new(Flight { done: Mutex::new(false), cv: Condvar::new(), result: Mutex::new(None) });
            *slot = Some(flight.clone());
            flight
        };
        let result = self.poll_now();
        *flight.result.lock().unwrap() = Some(result.clone());
        {
            let mut slot = self.inflight.lock().unwrap();
            if slot.as_ref().is_some_and(|item| Arc::ptr_eq(item, &flight)) { *slot = None; }
        }
        *flight.done.lock().unwrap() = true;
        flight.cv.notify_all();
        result
    }

    fn poll_now(&self) -> Result<bool> {
        let (url, ack, set_errs) = {
            let mut state = self.state.lock().unwrap();
            let url = state.stream.get("delivery").and_then(|value| value.as_object()).map(|delivery| text_of(delivery, "endpoint_url")).unwrap_or_default();
            let ack = std::mem::take(&mut state.ack);
            let set_errs = std::mem::take(&mut state.errs);
            (url, ack, set_errs)
        };
        let mut body = Map::new();
        body.insert("maxEvents".to_string(), json!(self.max_events));
        body.insert("returnImmediately".to_string(), Value::Bool(true));
        if !ack.is_empty() { body.insert("ack".to_string(), json!(ack)); }
        if !set_errs.is_empty() { body.insert("setErrs".to_string(), Value::Object(set_errs.clone())); }
        let (status, parsed) = match self.call("POST", &url, Some(&Value::Object(body))) {
            Ok(value) => value,
            Err(err) => { self.restore(ack, set_errs); return Err(err); }
        };
        if status != 200 {
            self.restore(ack, set_errs);
            let mut text = parsed.to_string();
            if text.len() > 300 { text.truncate(300); }
            return Err(fail("ssf", format!("the poll answered {status}: {text}")));
        }
        let sets = parsed.get("sets").and_then(|value| value.as_object()).cloned().unwrap_or_default();
        for (jti, token) in sets {
            let text = token.as_str().unwrap_or("").to_string();
            if let Err(err) = self.handle(&jti, &text) {
                self.log.warn(&format!("ssf: SET {jti} refused: {err}"));
                let code = if err.code == "signature" { "invalid_key" } else { "invalid_request" };
                self.state.lock().unwrap().errs.insert(jti, json!({"err": code, "description": err.message}));
                continue;
            }
            self.state.lock().unwrap().ack.push(jti);
        }
        Ok(parsed.get("moreAvailable").and_then(|value| value.as_bool()).unwrap_or(false))
    }

    fn restore(&self, ack: Vec<String>, set_errs: Map<String, Value>) {
        let mut state = self.state.lock().unwrap();
        let mut merged = ack;
        merged.append(&mut state.ack);
        state.ack = merged;
        let mut errs = set_errs;
        for (key, value) in std::mem::take(&mut state.errs) { errs.insert(key, value); }
        state.errs = errs;
    }

    fn handle(&self, jti: &str, token: &str) -> Result<()> {
        let mut keys = self.jwks(false)?;
        let verified = match verify_compact_jws(token, &keys) {
            Ok(value) => value,
            Err(err) => {
                let message = err.message.clone();
                if message.contains("publishes no") || message.contains("does not verify") {
                    keys = self.jwks(true)?;
                    verify_compact_jws(token, &keys)?
                } else {
                    return Err(err);
                }
            }
        };
        let (header, payload) = verified;
        if let Some(typ) = header.get("typ") {
            if typ.as_str().unwrap_or(&typ.to_string()).to_ascii_lowercase() != "secevent+jwt" {
                return Err(fail("validation", format!("the SET's typ is {typ}")));
            }
        }
        let (issuer, stream) = {
            let state = self.state.lock().unwrap();
            (text_of(&state.config, "issuer"), state.stream.clone())
        };
        let got_iss = payload.get("iss").map(|value| value.as_str().unwrap_or(&value.to_string()).to_string()).unwrap_or_else(|| "null".to_string());
        if payload.get("iss").and_then(|value| value.as_str()).unwrap_or("") != issuer {
            return Err(fail("validation", format!("the SET was issued by {got_iss}, not {issuer}")));
        }
        let want = audience_list(stream.get("aud"));
        let got = audience_list(payload.get("aud"));
        if !want.is_empty() && !got.iter().any(|item| want.iter().any(|wanted| item == wanted)) {
            return Err(fail("validation", format!("the SET is for {}, not this stream", got.join(", "))));
        }
        if payload.get("jti").is_some() && text_value(payload.get("jti")) != jti {
            return Err(fail("validation", "the SET's jti is not the one it was delivered under"));
        }
        let events = payload.get("events").and_then(|value| value.as_object()).cloned().unwrap_or_default();
        if events.is_empty() { return Err(fail("validation", "the SET carries no events")); }
        for (event_type, body) in events {
            let sub = if payload.get("sub_id").is_some() { payload.get("sub_id").cloned().unwrap_or(Value::Null) } else { body.get("subject").cloned().unwrap_or(Value::Null) };
            let subject = subject_of(&sub, &issuer);
            let sessions = self.sessions_for(&event_type, &subject);
            let mut ended = self.end_on.iter().any(|item| item == &event_type) && !sessions.is_empty();
            let mut event = SignalEvent {
                event_type: event_type.clone(),
                payload: body,
                subject,
                jti: jti.to_string(),
                sessions: sessions.clone(),
                ended,
                iat: payload.get("iat").and_then(|value| value.as_f64()),
                txn: payload.get("txn").and_then(|value| value.as_str()).map(|value| value.to_string()),
            };
            if ended {
                if let Err(err) = (self.on_end)(&sessions, &event) {
                    self.log.error(&format!("ssf: onEndSessions threw for {event_type} (SET {jti} is still acknowledged): {err}"));
                    ended = false;
                    event.ended = false;
                }
                if ended {
                    for local_id in &sessions { self.index.remove(local_id); }
                }
            }
            let handlers = {
                let state = self.state.lock().unwrap();
                let mut handlers = state.handlers.get(&event_type).cloned().unwrap_or_default();
                if let Some(star) = state.handlers.get("*") { handlers.extend(star.clone()); }
                handlers
            };
            for handler in handlers {
                if let Err(err) = handler(&event) {
                    self.log.error(&format!("ssf: a handler for {event_type} threw (SET {jti} is still acknowledged): {err}"));
                }
            }
        }
        Ok(())
    }

    fn sessions_for(&self, event_type: &str, subject: &HashMap<String, String>) -> Vec<String> {
        if event_type == events::event("verification") || event_type == events::event("stream_updated") { return Vec::new(); }
        if let Some(idp_session) = subject.get("idp_session") {
            if !idp_session.is_empty() {
                let found = self.index.by_idp_session(idp_session);
                if !found.is_empty() || event_type == events::event("session_revoked") { return found; }
            }
        }
        if let Some(person) = subject.get("person") { if !person.is_empty() { return self.index.by_person(person); } }
        if let Some(email) = subject.get("email") { if !email.is_empty() { return self.index.by_email(email); } }
        Vec::new()
    }

    fn discover(&self) -> Result<Map<String, Value>> {
        let url = format!("{}/.well-known/ssf-configuration", self.transmitter);
        let (status, parsed) = self.call("GET", &url, None)?;
        let config = parsed.as_object().cloned().unwrap_or_default();
        if status != 200 || text_of(&config, "configuration_endpoint").is_empty() || text_of(&config, "jwks_uri").is_empty() {
            return Err(fail("ssf", format!("{url} answered {status} without a usable transmitter configuration")));
        }
        if let Some(supported) = config.get("delivery_methods_supported").and_then(|value| value.as_array()) {
            if !supported.iter().any(|item| item.as_str() == Some(POLL_METHOD)) {
                return Err(fail("ssf", "the transmitter does not offer poll delivery (RFC 8936)"));
            }
        }
        Ok(config)
    }

    fn jwks(&self, force: bool) -> Result<Vec<Map<String, Value>>> {
        {
            let state = self.state.lock().unwrap();
            if !force && !state.keys.is_empty() && state.keys_at.is_some_and(|at| at.elapsed() < Duration::from_secs(3600)) {
                return Ok(state.keys.clone());
            }
        }
        let uri = text_of(&self.state.lock().unwrap().config, "jwks_uri");
        let (status, parsed) = self.call("GET", &uri, None)?;
        let body = parsed.as_object().cloned().unwrap_or_default();
        let mut keys = Vec::new();
        if let Some(list) = body.get("keys").and_then(|value| value.as_array()) {
            for item in list {
                if let Some(key) = item.as_object() { keys.push(key.clone()); }
            }
        }
        if status != 200 || (keys.is_empty() && body.get("keys").is_none()) {
            return Err(fail("ssf", format!("the transmitter's JWKS answered {status}")));
        }
        let mut state = self.state.lock().unwrap();
        state.keys = keys.clone();
        state.keys_at = Some(Instant::now());
        Ok(keys)
    }

    fn ensure_stream(&self) -> Result<Map<String, Value>> {
        let endpoint = text_of(&self.state.lock().unwrap().config, "configuration_endpoint");
        let (status, parsed) = self.call("GET", &endpoint, None)?;
        if status == 200 {
            let all = match &parsed {
                Value::Array(list) => list.clone(),
                Value::Object(_) => vec![parsed.clone()],
                _ => Vec::new(),
            };
            for item in all {
                let Some(stream) = item.as_object() else { continue };
                if text_of(stream, "stream_id").is_empty() { continue; }
                let method = stream.get("delivery").and_then(|value| value.as_object()).map(|delivery| text_of(delivery, "method")).unwrap_or_default();
                if method == POLL_METHOD { return Ok(stream.clone()); }
            }
        } else if status != 404 {
            let mut text = parsed.to_string();
            if text.len() > 300 { text.truncate(300); }
            return Err(fail("ssf", format!("listing the streams at {endpoint} answered {status}: {text}")));
        }
        let mut body = Map::new();
        body.insert("delivery".to_string(), json!({"method": POLL_METHOD}));
        body.insert("events_requested".to_string(), json!(self.events_requested));
        if !self.description.is_empty() { body.insert("description".to_string(), json!(self.description)); }
        let (status, parsed) = self.call("POST", &endpoint, Some(&Value::Object(body)))?;
        let stream = parsed.as_object().cloned().unwrap_or_default();
        if (status != 200 && status != 201) || text_of(&stream, "stream_id").is_empty() {
            let mut text = parsed.to_string();
            if text.len() > 300 { text.truncate(300); }
            return Err(fail("ssf", format!("creating a stream at {endpoint} answered {status}: {text}")));
        }
        Ok(stream)
    }

    fn call(&self, method: &str, url: &str, body: Option<&Value>) -> Result<(u16, Value)> {
        let payload = body.map(|value| value.to_string());
        let mut headers = vec![("accept", "application/json")];
        if payload.is_some() { headers.push(("content-type", "application/json")); }
        let answer = httpclient::send(url, method, &headers, payload.as_deref(), self.tls.as_ref(), "ssf")?;
        let parsed = if answer.body.is_empty() { Value::Null } else { serde_json::from_str(&answer.body).unwrap_or(Value::String(answer.body)) };
        Ok((answer.status, parsed))
    }
}

fn text_of(map: &Map<String, Value>, key: &str) -> String {
    map.get(key).and_then(|value| value.as_str()).unwrap_or("").to_string()
}

fn text_value(value: Option<&Value>) -> String {
    value.and_then(|item| item.as_str()).unwrap_or("").to_string()
}

fn delivery_url(stream: &Map<String, Value>) -> String {
    stream.get("delivery").and_then(|value| value.as_object()).map(|delivery| text_of(delivery, "endpoint_url")).unwrap_or_default()
}

fn audience_list(value: Option<&Value>) -> Vec<String> {
    match value {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(list)) => list.iter().map(|item| item.as_str().unwrap_or("").to_string()).filter(|item| !item.is_empty()).collect(),
        Some(Value::String(text)) => if text.is_empty() { Vec::new() } else { vec![text.clone()] },
        Some(other) => {
            let text = other.to_string();
            if text.is_empty() { Vec::new() } else { vec![text] }
        }
    }
}
