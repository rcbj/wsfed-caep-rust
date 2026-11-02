// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::config::parse_object;
use crate::error::Result;
use crate::relying_party::{LoginOptions, ReplyBody, ReplyRequest, RelyingParty};
use crate::ssf::{events, ReceiverOptions, SignalEvent, SignalsReceiver, TlsConfig};
use crate::token::Login;
use crate::x509util::cert_pem_body;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use pem::Pem;
use rsa::pkcs8::EncodePrivateKey;
use sha2::Sha256;
use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Response, Server, StatusCode};

const STYLES: &str = include_str!("../demo/public/styles.css");
const GIF_B64: &str = "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";

type HmacSha256 = Hmac<Sha256>;

/// The WS-Federation demo. `GET /live-status` is JSON: signedIn, subject, receiver, and the
/// accepted Shared Signals events (type and jti). It never includes tokens or assertions.
pub struct App {
    pub rp: RelyingParty,
    pub receiver: Mutex<Option<Arc<SignalsReceiver>>>,
    pub receiver_state: Mutex<String>,
    events: Mutex<Vec<(String, String)>>,
    sessions: Arc<Mutex<HashMap<String, Login>>>,
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
        Self { rp, receiver: Mutex::new(receiver), receiver_state: Mutex::new("not configured".to_string()), events: Mutex::new(Vec::new()), sessions: Arc::new(Mutex::new(HashMap::new())), secret: secret.to_vec(), reply_path: path, secure }
    }

    pub fn sessions_handle(&self) -> Arc<Mutex<HashMap<String, Login>>> { self.sessions.clone() }

    pub fn drop_session(&self, id: &str) { self.sessions.lock().unwrap().remove(id); }

    /// Record an accepted Shared Signals event for `GET /live-status`.
    pub fn remember(&self, event: &SignalEvent) {
        self.events.lock().unwrap().push((event.event_type.clone(), event.jti.clone()));
        // iya-sts main sets the WS-Federation assertion's SessionIndex to the
        // assertion id. The CAEP session-revoked subject names the sign-on
        // session instead, so the index finds nobody and the end callback is
        // not asked to drop this login. This demo has that one session.
        if event.event_type != events::event("session_revoked") || !event.sessions.is_empty() { return; }
        let ids: Vec<String> = self.sessions.lock().unwrap().drain().map(|(id, _)| id).collect();
        if let Some(receiver) = self.receiver.lock().unwrap().as_ref() {
            for id in &ids { receiver.untrack(id); }
        }
    }

    fn live_status(&self, sid: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
        let who = if sid.is_empty() { None } else { self.sessions.lock().unwrap().get(sid).cloned() };
        let events: Vec<serde_json::Value> = self.events.lock().unwrap().iter()
            .map(|(kind, jti)| serde_json::json!({"type": kind, "jti": jti}))
            .collect();
        let body = serde_json::json!({
            "signedIn": who.is_some(),
            "subject": who.as_ref().map(|item| item.name_id.clone()),
            "receiver": self.receiver_state.lock().unwrap().clone(),
            "events": events,
        });
        (200, vec![("content-type".to_string(), "application/json".to_string()), ("cache-control".to_string(), "no-store".to_string())], body.to_string().into_bytes())
    }

    fn sign(&self, value: &str) -> String {
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

    pub fn handle(&self, method: &str, target: &str, headers: &HashMap<String, String>, body: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
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
            let request = match self.rp.login(&LoginOptions { relay_state: Some("/".to_string()), ..LoginOptions::default() }) {
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
            let who = self.rp.handle_reply(ReplyRequest { method: "POST".to_string(), url: target.to_string(), body: ReplyBody::Text(String::from_utf8_lossy(body).into_owned()) }, &ids);
            let who = match who {
                Ok(value) => value,
                Err(_) => return (400, vec![("content-type".to_string(), "text/plain".to_string())], b"Sign-in failed.".to_vec()),
            };
            let session_id = token_url(24);
            if let Some(receiver) = self.receiver.lock().unwrap().as_ref() { receiver.track(&session_id, &who, None); }
            let next = who.relay_state.clone().filter(|value| value.starts_with('/') && !value.starts_with("//")).unwrap_or_else(|| "/".to_string());
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
            let who = if sid.is_empty() { None } else { self.sessions.lock().unwrap().get(&sid).cloned() };
            let page = if let Some(who) = who {
                format!("<p>Signed in as <strong>{}</strong> by {}.</p><form method=\"post\" action=\"/logout\"><button>Sign out</button></form>", esc(&who.name_id), esc(&who.issuer))
            } else {
                "<p><a href=\"/login\">Sign in with WS-Federation</a></p>".to_string()
            };
            let html = format!("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>WS-Federation</title><link rel=\"stylesheet\" href=\"/styles.css\"></head><body><main>{page}</main></body></html>");
            return (200, vec![("content-type".to_string(), "text/html; charset=utf-8".to_string())], html.into_bytes());
        }
        if path == "/styles.css" && method == "GET" {
            let body = if STYLES.is_empty() { b"body{font-family:sans-serif}\n".to_vec() } else { STYLES.as_bytes().to_vec() };
            return (200, vec![("content-type".to_string(), "text/css".to_string())], body);
        }
        (404, vec![("content-type".to_string(), "text/plain".to_string())], b"Not found".to_vec())
    }
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
