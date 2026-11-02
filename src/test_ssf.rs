// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::error::{fail, Result};
use crate::names::DEFAULT_SUBJECT_ATTRIBUTE;
use crate::ssf::events::{self, subject_of};
use crate::ssf::{verify_compact_jws, MemorySessionIndex, ReceiverOptions, SignalEvent, SignalsLog, SignalsReceiver};
use crate::test_support::rejects;
use crate::token::Login;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Map, Value};
use sha2::Sha256;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn b64(data: &[u8]) -> String { URL_SAFE_NO_PAD.encode(data) }

fn jwk_of(key: &RsaPrivateKey, kid: &str) -> Map<String, Value> {
    let public = RsaPublicKey::from(key);
    json!({
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
        "n": b64(&public.n().to_bytes_be()),
        "e": b64(&public.e().to_bytes_be()),
    }).as_object().unwrap().clone()
}

fn sign_jws(payload: &Value, key: &RsaPrivateKey, header: Option<Value>) -> String {
    let header = header.unwrap_or_else(|| json!({"alg": "RS256", "kid": "k1", "typ": "secevent+jwt"}));
    let h = b64(&serde_json::to_vec(&header).unwrap());
    let p = b64(&serde_json::to_vec(payload).unwrap());
    let signing = SigningKey::<Sha256>::new(key.clone());
    let raw = signing.sign(format!("{h}.{p}").as_bytes()).to_bytes();
    format!("{h}.{p}.{}", b64(&raw))
}

struct State {
    queue: HashMap<String, String>,
    acked: Vec<String>,
    errs: Map<String, Value>,
    created: i64,
    streams: Vec<Value>,
    jwk: Map<String, Value>,
}

struct Stub {
    url: String,
    state: Arc<Mutex<State>>,
    key: RsaPrivateKey,
    other: RsaPrivateKey,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl Stub {
    fn new() -> Self {
        let key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let other = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}");
        let state = Arc::new(Mutex::new(State {
            queue: HashMap::new(),
            acked: Vec::new(),
            errs: Map::new(),
            created: 0,
            streams: Vec::new(),
            jwk: jwk_of(&key, "k1"),
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let state_for = state.clone();
        let stop_for = stop.clone();
        let url_for = url.clone();
        let join = thread::spawn(move || serve(listener, state_for, stop_for, url_for));
        Self { url, state, key, other, stop, join: Some(join) }
    }

    fn put(&self, event_type: &str, sub: Value, extra: Option<Value>, key: Option<&RsaPrivateKey>, aud: &str, iss: &str) -> String {
        let mut bytes = [0u8; 16];
        for byte in &mut bytes { *byte = rand::random(); }
        let jti = b64(&bytes);
        let mut body = extra.unwrap_or_else(|| json!({}));
        body.as_object_mut().unwrap().insert("event_timestamp".into(), json!(1));
        let aud = if aud.is_empty() { "my-app" } else { aud };
        let iss = if iss.is_empty() { self.url.as_str() } else { iss };
        let key = key.unwrap_or(&self.key);
        let payload = json!({
            "iss": iss,
            "aud": aud,
            "jti": jti,
            "iat": 1,
            "sub_id": sub,
            "events": { event_type: body },
        });
        let token = sign_jws(&payload, key, None);
        self.state.lock().unwrap().queue.insert(jti.clone(), token);
        jti
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.url.trim_start_matches("http://"));
        if let Some(join) = self.join.take() { let _ = join.join(); }
    }
}

fn serve(listener: TcpListener, state: Arc<Mutex<State>>, stop: Arc<AtomicBool>, url: String) {
    let _ = listener.set_nonblocking(false);
    while !stop.load(Ordering::SeqCst) {
        let Ok((mut stream, _)) = listener.accept() else { break };
        if stop.load(Ordering::SeqCst) { break; }
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let Some((method, path, body)) = read_http(&mut stream) else { continue };
        let path = path.split('?').next().unwrap_or("");
        let (status, payload) = answer(&state, &url, &method, path, &body);
        let raw = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
        let head = format!("HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", raw.len());
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(&raw);
    }
}

fn answer(state: &Mutex<State>, url: &str, method: &str, path: &str, body: &[u8]) -> (u16, Value) {
    let mut state = state.lock().unwrap();
    if path == "/.well-known/ssf-configuration" {
        return (200, json!({
            "issuer": url,
            "jwks_uri": format!("{url}/jwks"),
            "configuration_endpoint": format!("{url}/ssf/stream"),
            "verification_endpoint": format!("{url}/ssf/verify"),
            "delivery_methods_supported": ["urn:ietf:rfc:8936"],
        }));
    }
    if path == "/jwks" {
        return (200, json!({"keys": [state.jwk]}));
    }
    if path == "/ssf/stream" && method == "GET" {
        return (200, Value::Array(state.streams.clone()));
    }
    if path == "/ssf/stream" && method == "POST" {
        let parsed: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        state.created += 1;
        let id = state.created;
        let delivery = parsed.get("delivery").cloned().unwrap_or(Value::Null);
        let method_name = delivery.get("method").and_then(|item| item.as_str()).unwrap_or("");
        let stream = json!({
            "stream_id": format!("s{id}"),
            "iss": url,
            "aud": "my-app",
            "delivery": {"method": method_name, "endpoint_url": format!("{url}/ssf/poll/s{id}")},
            "events_requested": parsed.get("events_requested").cloned().unwrap_or(Value::Null),
            "events_delivered": parsed.get("events_requested").cloned().unwrap_or(Value::Null),
        });
        state.streams.push(stream.clone());
        return (201, stream);
    }
    if path.starts_with("/ssf/poll/") {
        let parsed: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        if let Some(ack) = parsed.get("ack").and_then(|item| item.as_array()) {
            for item in ack {
                let jti = item.as_str().unwrap_or("").to_string();
                state.acked.push(jti.clone());
                state.queue.remove(&jti);
            }
        }
        if let Some(errs) = parsed.get("setErrs").and_then(|item| item.as_object()) {
            for (jti, err_body) in errs {
                state.errs.insert(jti.clone(), err_body.clone());
                state.queue.remove(jti);
            }
        }
        let sets = serde_json::to_value(&state.queue).unwrap_or(json!({}));
        return (200, json!({"sets": sets, "moreAvailable": false}));
    }
    (404, json!({"err": "not found"}))
}

fn read_http(stream: &mut TcpStream) -> Option<(String, String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 { return None; }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
        if buf.len() > 1_048_576 { return None; }
    }
    let header = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut method = String::new();
    let mut path = String::new();
    let mut content_length = 0usize;
    for (index, line) in header.split("\r\n").enumerate() {
        if index == 0 {
            let mut parts = line.split_whitespace();
            method = parts.next().unwrap_or("").to_string();
            path = parts.next().unwrap_or("").to_string();
        }
        if let Some(rest) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = rest.trim().parse().unwrap_or(0);
        }
    }
    while buf.len() < header_end + content_length {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 { break; }
        buf.extend_from_slice(&tmp[..n]);
    }
    let end = (header_end + content_length).min(buf.len());
    Some((method, path, buf[header_end..end].to_vec()))
}

struct MemLog { errors: Mutex<Vec<String>> }
impl SignalsLog for MemLog {
    fn info(&self, _: &str) {}
    fn warn(&self, _: &str) {}
    fn error(&self, message: &str) { self.errors.lock().unwrap().push(message.to_string()); }
}

struct Stop(Arc<SignalsReceiver>);
impl Drop for Stop { fn drop(&mut self) { self.0.stop(); } }

fn login_of(person: &str, session: &str) -> Login {
    let mut attributes = HashMap::new();
    attributes.insert(DEFAULT_SUBJECT_ATTRIBUTE.to_string(), vec![format!("urn:uuid:{person}")]);
    attributes.insert("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress".to_string(), vec![format!("{person}@example.com")]);
    Login {
        name_id: person.to_string(),
        name_id_format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_string()),
        name_qualifier: None,
        sp_name_qualifier: None,
        authn_instant: Utc::now(),
        attributes,
        attribute_friendly_names: HashMap::new(),
        issuer: "x".to_string(),
        realm: "https://rp.test/".to_string(),
        trust_version: "2005/02".to_string(),
        encrypted: false,
        assertion_id: "a".to_string(),
        not_on_or_after: Utc::now() + chrono::Duration::hours(1),
        session_index: Some(session.to_string()),
        session_not_on_or_after: None,
        authn_context_class_ref: None,
        request_id: None,
        relay_state: None,
    }
}

fn has(list: &[String], value: &str) -> bool { list.iter().any(|item| item == value) }

fn opts(log: Arc<MemLog>, index: Option<MemorySessionIndex>, interval: i64) -> ReceiverOptions {
    ReceiverOptions { poll_interval_ms: interval, log: Some(log), index, ..ReceiverOptions::default() }
}

#[test]
fn verifies_a_set_and_refuses_the_wrong_key() {
    let key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
    let other = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
    let jwk = jwk_of(&key, "k1");
    let (_header, payload) = verify_compact_jws(&sign_jws(&json!({"a": 1}), &key, None), &[jwk.clone()]).unwrap();
    let value = payload.get("a").unwrap();
    assert!(value.as_i64() == Some(1) || value.as_u64() == Some(1) || value.as_f64() == Some(1.0));
    let err = verify_compact_jws(&sign_jws(&json!({"a": 1}), &other, None), &[jwk.clone()]);
    rejects(&err, "signature", "does not verify");
    let err = verify_compact_jws(&sign_jws(&json!({"a": 1}), &key, Some(json!({"alg": "RS256", "kid": "nope"}))), &[jwk.clone()]);
    rejects(&err, "signature", "no RSA signing key with kid nope");
    let err = verify_compact_jws(&sign_jws(&json!({"a": 1}), &key, Some(json!({"alg": "none"}))), &[jwk.clone()]);
    rejects(&err, "signature", "does not verify");
    let err = verify_compact_jws(&sign_jws(&json!({"a": 1}), &key, Some(json!({"alg": "HS256", "kid": "k1"}))), &[jwk]);
    rejects(&err, "signature", "does not verify");
}

#[test]
fn subjects() {
    let got = subject_of(&json!({"format": "complex", "user": {"format": "iss_sub", "iss": "https://i", "sub": "urn:uuid:a"}, "session": {"format": "opaque", "id": "S1"}}), "https://i");
    assert_eq!(got.get("person").map(String::as_str), Some("urn:uuid:a"));
    assert_eq!(got.get("idp_session").map(String::as_str), Some("S1"));
    assert!(subject_of(&json!({"format": "iss_sub", "iss": "https://other", "sub": "urn:uuid:a"}), "https://i").is_empty());
    let email = subject_of(&json!({"format": "email", "email": "A@x.com"}), "https://i");
    assert_eq!(email.get("email").map(String::as_str), Some("A@x.com"));
}

#[test]
fn poll_stream_ends_the_named_sessions() {
    let stub = Stub::new();
    let ended: Arc<Mutex<Vec<Vec<String>>>> = Arc::new(Mutex::new(Vec::new()));
    let seen: Arc<Mutex<Vec<SignalEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let ended_for = ended.clone();
    let log = Arc::new(MemLog { errors: Mutex::new(Vec::new()) });
    let receiver = SignalsReceiver::new(&stub.url, Arc::new(move |ids, _| {
        ended_for.lock().unwrap().push(ids.to_vec());
        Ok(())
    }), opts(log, None, 60_000)).unwrap();
    let _stop = Stop(receiver.clone());
    let seen_for = seen.clone();
    receiver.on("*", Arc::new(move |event| { seen_for.lock().unwrap().push(event.clone()); Ok(()) }));
    receiver.start().unwrap();
    receiver.stop();
    {
        let state = stub.state.lock().unwrap();
        assert_eq!(state.created, 1);
    }
    assert_eq!(receiver.stream().get("stream_id").and_then(|item| item.as_str()), Some("s1"));
    receiver.track("L-a1", &login_of("alice", "IDP-A1"), None);
    receiver.track("L-a2", &login_of("alice", "IDP-A2"), None);
    receiver.track("L-b1", &login_of("bob", "IDP-B1"), None);
    let j1 = stub.put(events::event("session_revoked"), json!({"format": "complex", "user": {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:alice"}, "session": {"format": "opaque", "id": "IDP-A1"}}), None, None, "", "");
    let j2 = stub.put(events::event("credential_change"), json!({"format": "complex", "user": {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:bob"}}), Some(json!({"credential_type": "password", "change_type": "update"})), None, "", "");
    receiver.poll_once().unwrap();
    {
        let ended = ended.lock().unwrap();
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0], vec!["L-a1".to_string()]);
    }
    let change = seen.lock().unwrap().iter().find(|event| event.jti == j2).cloned();
    let change = change.expect("credential change");
    assert!(!change.ended);
    assert_eq!(change.sessions, vec!["L-b1".to_string()]);
    let j3 = stub.put(events::event("account_disabled"), json!({"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:alice"}), None, None, "", "");
    receiver.poll_once().unwrap();
    {
        let ended = ended.lock().unwrap();
        assert_eq!(ended.len(), 2);
        assert_eq!(ended[1][0], "L-a2");
    }
    {
        let state = stub.state.lock().unwrap();
        assert!(has(&state.acked, &j1), "{:?}", state.acked);
        assert!(has(&state.acked, &j2), "{:?}", state.acked);
    }
    stub.put(events::event("credential_compromise"), json!({"format": "email", "email": "BOB@example.com"}), Some(json!({"credential_type": "password"})), None, "", "");
    receiver.poll_once().unwrap();
    assert_eq!(ended.lock().unwrap()[2][0], "L-b1");
    receiver.poll_once().unwrap();
    assert!(has(&stub.state.lock().unwrap().acked, &j3));
    let again = SignalsReceiver::new(&stub.url, Arc::new(|_, _| Ok(())), opts(Arc::new(MemLog { errors: Mutex::new(Vec::new()) }), None, 0)).unwrap();
    let _stop_again = Stop(again.clone());
    again.start().unwrap();
    again.stop();
    assert_eq!(stub.state.lock().unwrap().created, 1);
    assert_eq!(again.stream().get("stream_id").and_then(|item| item.as_str()), Some("s1"));
}

#[test]
fn forged_sets_are_reported() {
    let stub = Stub::new();
    let ended: Arc<Mutex<Vec<Vec<String>>>> = Arc::new(Mutex::new(Vec::new()));
    let ended_for = ended.clone();
    let index = MemorySessionIndex::new(0);
    let receiver = SignalsReceiver::new(&stub.url, Arc::new(move |ids, _| {
        ended_for.lock().unwrap().push(ids.to_vec());
        Ok(())
    }), opts(Arc::new(MemLog { errors: Mutex::new(Vec::new()) }), Some(index.clone()), 0)).unwrap();
    let _stop = Stop(receiver.clone());
    receiver.start().unwrap();
    receiver.stop();
    receiver.track("L-c1", &login_of("carol", "IDP-C1"), None);
    let subject = json!({"format": "complex", "user": {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:carol"}, "session": {"format": "opaque", "id": "IDP-C1"}});
    let forged = stub.put(events::event("session_revoked"), subject.clone(), None, Some(&stub.other), "", "");
    let mis = stub.put(events::event("session_revoked"), subject.clone(), None, None, "someone-else", "");
    let foreign = stub.put(events::event("session_revoked"), subject, None, None, "", "https://evil.example");
    receiver.poll_once().unwrap();
    assert!(ended.lock().unwrap().is_empty());
    assert_eq!(index.by_person("urn:uuid:carol"), vec!["L-c1".to_string()]);
    receiver.poll_once().unwrap();
    let errs = stub.state.lock().unwrap().errs.clone();
    for jti in [forged, mis, foreign] {
        assert!(errs.contains_key(&jti), "{jti} {errs:?}");
    }
}

#[test]
fn event_catalog() {
    assert_eq!(events::caep_events().len(), 8);
    assert_eq!(events::risc_events().len(), 14);
    assert!(events::caep_events().contains(&events::event("risk_level_change")));
    assert!(events::risc_events().contains(&events::event("opt_out_effective")));
}

#[test]
fn handler_and_on_end_errors_are_still_acknowledged() {
    let stub = Stub::new();
    let log = Arc::new(MemLog { errors: Mutex::new(Vec::new()) });
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let receiver = SignalsReceiver::new(&stub.url, Arc::new(|_, _| Err(fail("ssf", "store down"))), opts(log.clone(), None, 0)).unwrap();
    let _stop = Stop(receiver.clone());
    receiver.on(events::event("credential_change"), Arc::new(|_| Err(fail("ssf", "handler bug"))));
    let seen_for = seen.clone();
    receiver.on("*", Arc::new(move |event| { seen_for.lock().unwrap().push(event.jti.clone()); Ok(()) }));
    receiver.start().unwrap();
    receiver.stop();
    receiver.track("L-d1", &login_of("dave", "IDP-D1"), None);
    let j1 = stub.put(events::event("credential_change"), json!({"format": "complex", "user": {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:dave"}}), Some(json!({"credential_type": "password", "change_type": "update"})), None, "", "");
    let j2 = stub.put(events::event("session_revoked"), json!({"format": "complex", "user": {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:dave"}, "session": {"format": "opaque", "id": "IDP-D1"}}), None, None, "", "");
    for _ in 0..3 { receiver.poll_once().unwrap(); }
    let state = stub.state.lock().unwrap();
    assert!(has(&state.acked, &j1), "{:?}", state.acked);
    assert!(has(&state.acked, &j2), "{:?}", state.acked);
    assert!(!state.errs.contains_key(&j1));
    assert!(!state.errs.contains_key(&j2));
    drop(state);
    let seen = seen.lock().unwrap();
    assert!(has(&seen, &j1) && has(&seen, &j2), "{seen:?}");
    let errors = log.errors.lock().unwrap().clone();
    let handler = errors.iter().any(|message| message.contains("handler for") && message.contains("credential-change") && message.contains("threw"));
    let ended = errors.iter().any(|message| message.contains("onEndSessions threw"));
    assert!(handler && ended, "{errors:?}");
}

#[test]
fn overlapping_polls_handle_a_set_once() {
    let stub = Stub::new();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let receiver = SignalsReceiver::new(&stub.url, Arc::new(|_, _| Ok(())), opts(Arc::new(MemLog { errors: Mutex::new(Vec::new()) }), None, 0)).unwrap();
    let _stop = Stop(receiver.clone());
    let seen_for = seen.clone();
    receiver.on("*", Arc::new(move |event| { seen_for.lock().unwrap().push(event.jti.clone()); Ok(()) }));
    receiver.start().unwrap();
    receiver.stop();
    let jti = stub.put(events::event("account_enabled"), json!({"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:erin"}), None, None, "", "");
    let mut joins = Vec::new();
    for _ in 0..3 {
        let receiver = receiver.clone();
        joins.push(thread::spawn(move || { let _ = receiver.poll_once(); }));
    }
    for join in joins { join.join().unwrap(); }
    receiver.poll_once().unwrap();
    let count = seen.lock().unwrap().iter().filter(|item| item.as_str() == jti).count();
    assert_eq!(count, 1);
}

#[test]
fn refuses_a_transmitter_without_poll_delivery() {
    let receiver = SignalsReceiver::new("http://127.0.0.1:1", Arc::new(|_, _| Ok(())), opts(Arc::new(MemLog { errors: Mutex::new(Vec::new()) }), None, 0)).unwrap();
    let err: Result<()> = receiver.start();
    rejects(&err, "ssf", "");
}
