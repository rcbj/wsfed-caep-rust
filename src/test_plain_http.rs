// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! Plain http is refused for every fetch (federation metadata, the Shared
//! Signals transmitter) unless the host is loopback, before any connection
//! is opened, and the refusal names only the scheme and host.

use super::test_support::{self as stub, MetaOptions, IDP_ENTITY, REALM, REPLY};
use crate::error::WsFedError;
use crate::httpclient::is_loopback_host;
use crate::relying_party::RelyingParty;
use crate::ssf::{ReceiverOptions, SignalsLog, SignalsReceiver};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const REFUSED: &str = "is refused: plain http is allowed only to a loopback host";

struct Quiet;
impl SignalsLog for Quiet {
    fn info(&self, _: &str) {}
    fn warn(&self, _: &str) {}
    fn error(&self, _: &str) {}
}

/// A loopback stub: /md answers the stub IdP's metadata, /away a 302 to
/// http://example.com/md, anything else 404. It counts every request.
struct Stub { port: u16, hits: Arc<AtomicUsize> }

fn stub_server() -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = hits.clone();
    let metadata = stub::idp_metadata(&MetaOptions::default());
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            counted.fetch_add(1, Ordering::SeqCst);
            let path = request_path(&mut stream);
            let reply = match path.as_str() {
                "/md" => format!("HTTP/1.1 200 OK\r\ncontent-type: application/samlmetadata+xml\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{metadata}", metadata.len()),
                "/away" => "HTTP/1.1 302 Found\r\nlocation: http://example.com/md\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_string(),
                _ => "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_string(),
            };
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    Stub { port, hits }
}

fn request_path(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => break,
        }
    }
    let text = String::from_utf8_lossy(&head);
    text.split_whitespace().nth(1).unwrap_or("").split('?').next().unwrap_or("").to_string()
}

fn party(metadata_url: &str) -> Result<RelyingParty, WsFedError> {
    let config = serde_json::json!({
        "realm": REALM,
        "replyUrl": REPLY,
        "privateKey": stub::rp_key(),
        "certificate": stub::rp_cert(),
        "idpMetadata": metadata_url,
    });
    RelyingParty::create(config.as_object().unwrap(), Path::new("."))
}

fn receiver(transmitter: &str) -> Result<(), WsFedError> {
    let options = ReceiverOptions { log: Some(Arc::new(Quiet)), ..ReceiverOptions::default() };
    let receiver = SignalsReceiver::new(transmitter, Arc::new(|_, _| Ok(())), options)?;
    receiver.start()
}

fn refused(result: Result<(), WsFedError>, code: &str, shown: &str) -> WsFedError {
    let err = result.expect_err("the fetch was not refused");
    assert_eq!(err.code, code, "{}", err.message);
    assert!(err.message.starts_with(&format!("{shown} {REFUSED}")), "{}", err.message);
    assert!(!err.message.contains("s3cret"), "{}", err.message);
    for part in ["/md", "/ssf", "federationmetadata", "token="] {
        assert!(!err.message.contains(part), "{}", err.message);
    }
    err
}

#[test]
fn refuses_plain_http_metadata_off_loopback() {
    refused(party("http://example.com/federationmetadata.xml?token=s3cret").map(|_| ()), "metadata", "http://example.com");
}

#[test]
fn refuses_a_plain_http_transmitter_off_loopback() {
    refused(receiver("http://example.com/ssf"), "ssf", "http://example.com");
}

#[test]
fn refuses_before_connecting() {
    // On Linux http://0.0.0.0:<port> reaches a listener on 127.0.0.1, so an
    // empty backlog on this listener shows no connection was opened.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let plain = format!("http://0.0.0.0:{}", listener.local_addr().unwrap().port());
    refused(party(&format!("{plain}/md")).map(|_| ()), "metadata", &plain);
    refused(receiver(&plain), "ssf", &plain);
    listener.set_nonblocking(true).unwrap();
    thread::sleep(Duration::from_millis(300));
    assert!(listener.accept().is_err(), "a refused fetch opened a connection");
}

#[test]
fn userinfo_is_never_loopback_and_never_shown() {
    let stub = stub_server();
    let origin = format!("127.0.0.1:{}", stub.port);
    let err = refused(party(&format!("http://alice:s3cret@{origin}/md")).map(|_| ()), "metadata", &format!("http://{origin}"));
    assert!(!err.message.contains("alice"), "{}", err.message);
    refused(party("http://localhost:80@example.com/md").map(|_| ()), "metadata", "http://example.com");
    refused(receiver(&format!("http://alice:s3cret@{origin}/ssf")), "ssf", &format!("http://{origin}"));
    assert_eq!(stub.hits.load(Ordering::SeqCst), 0);
}

#[test]
fn refuses_whitespace_and_control_characters() {
    let stub = stub_server();
    for url in [
        format!("http://127.0.0.1:{} @example.com/md", stub.port),
        format!("http://127.0.0.1:{}/m\td", stub.port),
        format!("http://127.0.0.1:{}\u{0}@example.com/md", stub.port),
        "https://example.com/m\nd".to_string(),
    ] {
        let err = party(&url).map(|_| ()).expect_err("a URL with whitespace was fetched");
        assert_eq!(err.code, "metadata");
        assert!(err.message.contains("whitespace or a control character"), "{}", err.message);
    }
    let err = receiver(&format!("http://127.0.0.1:{}/s sf", stub.port)).expect_err("a URL with whitespace was fetched");
    assert_eq!(err.code, "ssf");
    assert_eq!(stub.hits.load(Ordering::SeqCst), 0);
}

#[test]
fn a_redirect_is_not_followed() {
    // Redirects are never followed, so a 302 to plain http off loopback is
    // the answer and example.com is never dialled.
    let stub = stub_server();
    let err = party(&format!("http://127.0.0.1:{}/away", stub.port)).map(|_| ()).expect_err("the redirect was followed");
    assert_eq!(err.code, "metadata");
    assert!(err.message.contains("answered HTTP 302"), "{}", err.message);
}

#[test]
fn plain_http_to_loopback_still_works() {
    let stub = stub_server();
    for host in ["127.0.0.1", "localhost"] {
        let rp = party(&format!("http://{host}:{}/md", stub.port)).unwrap();
        assert_eq!(rp.idp.as_ref().unwrap().entity_id, IDP_ENTITY);
        let before = stub.hits.load(Ordering::SeqCst);
        let err = receiver(&format!("http://{host}:{}/ssf", stub.port)).expect_err("the stub has no transmitter");
        assert_eq!(err.code, "ssf");
        assert!(!err.message.contains(REFUSED), "{}", err.message);
        assert!(stub.hits.load(Ordering::SeqCst) > before, "the transmitter on {host} was not reached");
    }
    assert!(is_loopback_host(&url::Host::parse("[::1]").unwrap()));
    assert!(is_loopback_host(&url::Host::parse("127.200.0.9").unwrap()));
    assert!(!is_loopback_host(&url::Host::parse("127.0.0.1.example.com").unwrap()));
    assert!(!is_loopback_host(&url::Host::parse("0.0.0.0").unwrap()));
}

#[test]
fn https_to_an_unreachable_host_is_a_connection_error_not_this_refusal() {
    let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let https = format!("https://127.0.0.1:{closed}");
    for err in [party(&format!("{https}/md")).map(|_| ()).unwrap_err(), receiver(&https).unwrap_err()] {
        assert!(!err.message.contains(REFUSED), "{}", err.message);
        assert!(err.message.starts_with(&https), "{}", err.message);
    }
}
