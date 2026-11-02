// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::error::{fail, Result};
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;
use ureq::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use ureq::rustls::{ClientConfig, RootCertStore};

pub const MAX_BYTES: usize = 2 * 1024 * 1024;

pub struct TlsMaterial {
    pub ca: Option<String>,
    pub cert: Option<String>,
    pub key: Option<String>,
}

pub struct HttpResult {
    pub status: u16,
    pub content_type: String,
    pub body: String,
}

/// Every fetch this library makes comes through here: the identity
/// provider's federation metadata (its signing keys) and the Shared Signals
/// transmitter (configuration, JWKS, stream and poll: the SETs and the bearer
/// token). None of them may travel in the clear off this machine, so plain
/// http is refused before any DNS lookup or connection unless the host is
/// loopback. Redirects are not followed (`redirects(0)`), so the URL checked
/// here is the only one ever dialled.
pub fn send(url: &str, method: &str, headers: &[(&str, &str)], body: Option<&str>, tls: Option<&TlsMaterial>, code: &str) -> Result<HttpResult> {
    refuse_unsafe_characters(url, code)?;
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err(fail(code, format!("{url} is not an http(s) URL")));
    }
    refuse_plain_http_off_loopback(url, code)?;
    let mut builder = ureq::AgentBuilder::new().timeout(Duration::from_secs(15)).redirects(0);
    if url.starts_with("https://") {
        if let Some(material) = tls {
            if material.ca.as_deref().is_some_and(|ca| !ca.is_empty()) || material.cert.as_deref().is_some_and(|cert| !cert.is_empty()) {
                let connector = rustls_config(material).map_err(|err| fail(code, format!("{url}: {err}")))?;
                builder = builder.tls_connector(Arc::new(Arc::new(connector)));
            }
        }
    }
    let agent = builder.build();
    let mut request = agent.request(method, url);
    for (name, value) in headers {
        request = request.set(*name, *value);
    }
    let response = if let Some(body) = body { request.send_string(body) } else { request.call() };
    let response = match response {
        Ok(response) => response,
        Err(ureq::Error::Status(_status, response)) => response,
        Err(err) => {
            let text = err.to_string();
            if text.to_ascii_lowercase().contains("timed out") || text.to_ascii_lowercase().contains("timeout") {
                return Err(fail(code, format!("{url} did not answer within 15 s")));
            }
            return Err(fail(code, format!("{url}: {text}")));
        }
    };
    let status = response.status();
    let content_type = response.header("content-type").unwrap_or("").to_string();
    let mut reader = response.into_reader().take(MAX_BYTES as u64 + 1);
    let mut raw = Vec::new();
    reader.read_to_end(&mut raw).map_err(|err| fail(code, format!("{url}: {err}")))?;
    if raw.len() > MAX_BYTES {
        return Err(fail(code, format!("{url} answered more than {MAX_BYTES} bytes")));
    }
    Ok(HttpResult { status, content_type, body: String::from_utf8_lossy(&raw).into_owned() })
}

/// Refuses a URL holding whitespace or a control character before it is
/// parsed, rather than risk two parsers disagreeing on its host (the WHATWG
/// parser ureq uses drops tabs and newlines silently). The URL itself is not
/// repeated: it may carry a secret.
pub(crate) fn refuse_unsafe_characters(url: &str, code: &str) -> Result<()> {
    if url.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        return Err(fail(code, "the URL is refused: it contains whitespace or a control character"));
    }
    Ok(())
}

/// Refuses a plain http URL unless it names a loopback host: 127.0.0.0/8,
/// ::1 or the name localhost, where the bytes never leave the machine. A URL
/// with userinfo is never loopback, so "http://localhost:80@host/" cannot pass
/// as localhost. The URL is parsed with the parser ureq dials with, and no
/// name is resolved. The message names the scheme and host[:port] only: never
/// userinfo, path, query or a secret.
pub(crate) fn refuse_plain_http_off_loopback(url: &str, code: &str) -> Result<()> {
    if !url.get(..7).is_some_and(|scheme| scheme.eq_ignore_ascii_case("http://")) { return Ok(()); }
    let Ok(parsed) = url::Url::parse(url) else {
        return Err(fail(code, "a plain http URL that cannot be parsed is refused; use https"));
    };
    let userinfo = !parsed.username().is_empty() || parsed.password().is_some();
    if !userinfo && parsed.host().is_some_and(|host| is_loopback_host(&host)) { return Ok(()); }
    let shown = match (parsed.host_str(), parsed.port()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_string(),
        (None, _) => "(no host)".to_string(),
    };
    Err(fail(code, format!("http://{shown} is refused: plain http is allowed only to a loopback host (127.0.0.0/8, ::1, localhost); use https")))
}

pub(crate) fn is_loopback_host<S: AsRef<str>>(host: &url::Host<S>) -> bool {
    match host {
        url::Host::Domain(name) => name.as_ref().eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(address) => address.is_loopback(),
        url::Host::Ipv6(address) => address.is_loopback(),
    }
}

fn pem_ders(pem_text: &str) -> std::result::Result<Vec<CertificateDer<'static>>, String> {
    let mut out = Vec::new();
    for block in pem_text.split("-----END CERTIFICATE-----") {
        let Some(body) = block.split("-----BEGIN CERTIFICATE-----").nth(1) else { continue };
        let compact: String = body.chars().filter(|ch| !ch.is_whitespace()).collect();
        let der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, compact).map_err(|err| err.to_string())?;
        out.push(CertificateDer::from(der));
    }
    if out.is_empty() { return Err("the CA certificate cannot be read".to_string()); }
    Ok(out)
}

fn rustls_config(material: &TlsMaterial) -> std::result::Result<ClientConfig, String> {
    let mut roots = RootCertStore::empty();
    if let Some(ca) = material.ca.as_deref() {
        if !ca.is_empty() {
            for der in pem_ders(ca)? { roots.add(der).map_err(|err| err.to_string())?; }
        }
    }
    if roots.is_empty() {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let builder = ClientConfig::builder().with_root_certificates(roots);
    if let (Some(cert), Some(key)) = (material.cert.as_deref(), material.key.as_deref()) {
        if !cert.is_empty() && !key.is_empty() {
            let certs = pem_ders(cert)?;
            let key_der = private_key(key)?;
            return builder.with_client_auth_cert(certs, key_der).map_err(|err| err.to_string());
        }
    }
    Ok(builder.with_no_client_auth())
}

fn private_key(pem_text: &str) -> std::result::Result<PrivateKeyDer<'static>, String> {
    let (tag, body) = if let Some(body) = pem_text.split("-----BEGIN PRIVATE KEY-----").nth(1) {
        ("pkcs8", body.split("-----END PRIVATE KEY-----").next().unwrap_or(""))
    } else if let Some(body) = pem_text.split("-----BEGIN RSA PRIVATE KEY-----").nth(1) {
        ("pkcs1", body.split("-----END RSA PRIVATE KEY-----").next().unwrap_or(""))
    } else {
        return Err("the client key cannot be read".to_string());
    };
    let compact: String = body.chars().filter(|ch| !ch.is_whitespace()).collect();
    let der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, compact).map_err(|err| err.to_string())?;
    Ok(match tag {
        "pkcs8" => PrivateKeyDer::Pkcs8(der.into()),
        _ => PrivateKeyDer::Pkcs1(der.into()),
    })
}

