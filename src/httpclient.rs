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

pub fn send(url: &str, method: &str, headers: &[(&str, &str)], body: Option<&str>, tls: Option<&TlsMaterial>, code: &str) -> Result<HttpResult> {
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err(fail(code, format!("{url} is not an http(s) URL")));
    }
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

