// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! idpCa holds iya-sts's whole listener CA trust chain (leaf, TLS Issuing CA,
//! Intermediate, Root). These tests serve HTTPS from such a chain, check that
//! scripts/trust_chain.py (what scripts/configure_iya_sts.py calls) writes all
//! of it to the file idpCa names, from GET /tls/server-certificate and from the
//! handshake when that is missing, and that the library takes that file as its
//! trust store. The chain is made with the openssl command, which the test
//! image carries.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::thread;

use ureq::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use ureq::rustls::{ServerConfig, ServerConnection, StreamOwned};

use super::test_support::{self as stub, MetaOptions};
use crate::relying_party::RelyingParty;

struct Chain {
    /// Leaf first, Root last: what iya-sts publishes and presents.
    pem: String,
    leaf: String,
    leaf_key: String,
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wsfed-trust-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn openssl(dir: &Path, args: &[&str]) {
    let out = Command::new("openssl").args(args).current_dir(dir).output().expect("openssl");
    assert!(out.status.success(), "openssl {args:?}: {}", String::from_utf8_lossy(&out.stderr));
}

fn read(dir: &Path, name: &str) -> String {
    std::fs::read_to_string(dir.join(name)).unwrap()
}

/// Root -> Intermediate -> TLS Issuing CA -> leaf for 127.0.0.1, all P-256.
fn chain(dir: &Path) -> Chain {
    std::fs::write(
        dir.join("ext.cnf"),
        "[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n\
         [leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n",
    )
    .unwrap();
    for name in ["root", "intermediate", "issuing", "leaf"] {
        openssl(dir, &["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", &format!("{name}.key")]);
    }
    openssl(dir, &[
        "req", "-x509", "-new", "-key", "root.key", "-subj", "/CN=test Root CA", "-days", "2",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", "root.crt",
    ]);
    let issue = |name: &str, cn: &str, parent: &str, section: &str, serial: &str| {
        openssl(dir, &["req", "-new", "-key", &format!("{name}.key"), "-subj", &format!("/CN={cn}"), "-out", &format!("{name}.csr")]);
        openssl(dir, &[
            "x509", "-req", "-in", &format!("{name}.csr"), "-CA", &format!("{parent}.crt"), "-CAkey", &format!("{parent}.key"),
            "-set_serial", serial, "-days", "2", "-extfile", "ext.cnf", "-extensions", section, "-out", &format!("{name}.crt"),
        ]);
    };
    issue("intermediate", "test Intermediate CA", "root", "ca", "2");
    issue("issuing", "test TLS Issuing CA", "intermediate", "ca", "3");
    issue("leaf", "127.0.0.1", "issuing", "leaf", "4");
    let leaf = read(dir, "leaf.crt");
    Chain {
        pem: format!("{}{}{}{}", leaf, read(dir, "issuing.crt"), read(dir, "intermediate.crt"), read(dir, "root.crt")),
        leaf,
        leaf_key: read(dir, "leaf.key"),
    }
}

fn ders(pem: &str) -> Vec<CertificateDer<'static>> {
    pem.split("-----END CERTIFICATE-----")
        .filter_map(|block| block.split("-----BEGIN CERTIFICATE-----").nth(1))
        .map(|body| {
            let compact: String = body.chars().filter(|ch| !ch.is_whitespace()).collect();
            CertificateDer::from(base64::Engine::decode(&base64::engine::general_purpose::STANDARD, compact).unwrap())
        })
        .collect()
}

fn key_der(pem: &str) -> PrivateKeyDer<'static> {
    let body = pem.split("-----BEGIN PRIVATE KEY-----").nth(1).unwrap().split("-----END PRIVATE KEY-----").next().unwrap();
    let compact: String = body.chars().filter(|ch| !ch.is_whitespace()).collect();
    PrivateKeyDer::Pkcs8(base64::Engine::decode(&base64::engine::general_purpose::STANDARD, compact).unwrap().into())
}

/// HTTPS on 127.0.0.1 presenting the whole chain. `published` decides whether
/// GET /tls/server-certificate answers the chain or 404. GET /metadata answers
/// the stub identity provider's metadata.
fn serve_tls(chain: &Chain, published: bool) -> String {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(ders(&chain.pem), key_der(&chain.leaf_key))
        .expect("server config");
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let chain_pem = chain.pem.clone();
    let metadata = stub::idp_metadata(&MetaOptions::default());
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let config = config.clone();
            let chain_pem = chain_pem.clone();
            let metadata = metadata.clone();
            thread::spawn(move || {
                let Ok(connection) = ServerConnection::new(config) else { return };
                let mut tls = StreamOwned::new(connection, stream);
                let mut request = Vec::new();
                let mut buffer = [0u8; 2048];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut buffer) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buffer[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&request);
                let path = text.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (status, body) = if path == "/tls/server-certificate" && published {
                    ("200 OK", chain_pem)
                } else if path == "/metadata" {
                    ("200 OK", metadata)
                } else {
                    ("404 Not Found", String::new())
                };
                let _ = write!(tls, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                let _ = tls.flush();
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    format!("https://127.0.0.1:{port}")
}

fn blocks(pem: &str) -> usize {
    pem.matches("-----BEGIN CERTIFICATE-----").count()
}

/// The registrar's save step, run the way configure_iya_sts.py runs it: the file
/// idpCa names in a wsfed.json, relative to that file's directory.
fn save_with_registrar(dir: &Path, origin: &str) -> String {
    let config = dir.join("wsfed.json");
    std::fs::write(
        &config,
        r#"{"realm": "http://localhost:3000/", "replyUrl": "http://localhost:3000/wsfed", "idpMetadata": "file:generated/idp-metadata.xml", "idpCa": "file:generated/idp-ca.pem"}"#,
    )
    .unwrap();
    let script = format!("{}/scripts/trust_chain.py", env!("CARGO_MANIFEST_DIR"));
    let out = Command::new("python3")
        .args([script.as_str(), "--config", config.to_str().unwrap(), "--idp", origin])
        .env_remove("WSFED_CONFIG")
        .output()
        .expect("python3");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success() && stdout.contains("4 certificate(s)"), "{stdout}{}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("trust anchor CN=test Root CA"), "{stdout}");
    read(&dir.join("generated"), "idp-ca.pem")
}

#[test]
fn the_registrar_writes_the_published_chain_to_idp_ca() {
    let dir = scratch("published");
    let chain = chain(&dir);
    let origin = serve_tls(&chain, true);
    let saved = save_with_registrar(&dir, &origin);
    assert_eq!(blocks(&saved), 4);
    assert_eq!(saved, chain.pem);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_registrar_falls_back_to_the_handshake_chain() {
    let dir = scratch("handshake");
    let chain = chain(&dir);
    let origin = serve_tls(&chain, false);
    let saved = save_with_registrar(&dir, &origin);
    assert_eq!(blocks(&saved), 4);
    assert_eq!(ders(&saved), ders(&chain.pem));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_library_trusts_the_whole_chain_in_idp_ca() {
    let dir = scratch("library");
    let chain = chain(&dir);
    let origin = serve_tls(&chain, true);
    std::fs::create_dir_all(dir.join("generated")).unwrap();
    std::fs::write(dir.join("generated").join("idp-ca.pem"), &chain.pem).unwrap();
    let config = serde_json::json!({
        "realm": stub::REALM,
        "replyUrl": stub::REPLY,
        "privateKey": stub::rp_key(),
        "certificate": stub::rp_cert(),
        "idpMetadata": format!("{origin}/metadata"),
        "idpCa": "file:generated/idp-ca.pem",
    });
    let map = config.as_object().unwrap().clone();
    let party = RelyingParty::create(&map, &dir).unwrap_or_else(|err| panic!("{err}"));
    assert_eq!(party.config.idp_ca, chain.pem);
    assert!(party.idp.is_some());

    // The whole file has to be read: its first block alone is the leaf, which
    // anchors nothing, and the metadata fetch is refused.
    std::fs::write(dir.join("generated").join("idp-ca.pem"), &chain.leaf).unwrap();
    assert!(RelyingParty::create(&map, &dir).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
