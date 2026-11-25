// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::cli;
use crate::x509util::{self, create_self_signed_key_pair};
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::os::unix::fs::PermissionsExt;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

const SKI_OID: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x0e];
const AKI_OID: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x23];

fn key_id_after(cert: &[u8], oid: &[u8]) -> Vec<u8> {
    let at = cert.windows(oid.len()).position(|window| window == oid).expect("oid");
    let rest = &cert[at + oid.len()..];
    let marker = rest.iter().position(|byte| *byte == 0x14).expect("marker");
    let start = at + oid.len() + marker + 1;
    cert[start..start + 20].to_vec()
}

#[test]
fn signs_itself_and_names_its_key() {
    let pair = create_self_signed_key_pair("rp", 30, 2048).unwrap();
    let (_, cert) = X509Certificate::from_der(&pair.certificate_der).unwrap();
    let key = rsa::RsaPublicKey::from(&pair.private_key);
    let sig = Signature::try_from(cert.signature_value.data.as_ref()).unwrap();
    VerifyingKey::<Sha256>::new(key).verify(cert.tbs_certificate.as_ref(), &sig).unwrap();
    let pkcs1 = pair.private_key.to_public_key().to_pkcs1_der().unwrap();
    let want = Sha1::digest(pkcs1.as_bytes());
    let der = &pair.certificate_der;
    assert_eq!(key_id_after(der, SKI_OID), want[..]);
    assert_eq!(key_id_after(der, AKI_OID), want[..]);
}

#[test]
fn two_certificates_of_one_name_have_different_key_identifiers() {
    let one = create_self_signed_key_pair("localhost:3000", 30, 2048).unwrap();
    let two = create_self_signed_key_pair("localhost:3000", 30, 2048).unwrap();
    assert_eq!(x509util::subject_string(&one.certificate_der), x509util::subject_string(&two.certificate_der));
    assert_ne!(key_id_after(&one.certificate_der, SKI_OID), key_id_after(&two.certificate_der, SKI_OID));
}

/// `generate-keys --config` into a fresh directory with `extra` arguments:
/// the certificate it wrote, and the key file's path.
fn generated(tag: &str, realm: &str, extra: &[&str]) -> (crate::signature::IdpCert, std::path::PathBuf, std::path::PathBuf, String) {
    let dir = std::env::temp_dir().join(format!("wsfed-x509-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("wsfed.json");
    std::fs::write(&config, format!(r#"{{"realm":"{realm}","replyUrl":"{realm}wsfed","idpMetadata":"x","privateKey":"k.pem","certificate":"c.pem"}}"#)).unwrap();
    let mut args: Vec<String> = vec!["generate-keys".into(), "--config".into(), config.display().to_string(), "--bits".into(), "2048".into()];
    args.extend(extra.iter().map(|item| item.to_string()));
    let mut out = Vec::new();
    let code = cli::main(&args, &mut out);
    let printed = String::from_utf8_lossy(&out).to_string();
    assert_eq!(code, 0, "{printed}");
    let cert = x509util::load_cert(&std::fs::read_to_string(dir.join("c.pem")).unwrap()).unwrap();
    (cert, dir.join("k.pem"), dir, printed)
}

#[test]
fn generate_keys_names_the_demo_rp_and_the_realm_it_serves() {
    // --realm, as the install script passes it: the realm as it runs.
    let (cert, key_path, dir, printed) = generated("realm", "http://localhost:3000/", &["--realm", "http://127.0.0.1:3048/"]);
    assert_eq!(x509util::subject_string(&cert.der), "CN=wsfed-caep-rust demo RP, OU=http://127.0.0.1:3048/");
    assert_eq!(x509util::subject_cn(&cert.der), cli::DEFAULT_COMMON_NAME);
    assert_eq!(x509util::subject_alt_uris(&cert.der), vec!["http://127.0.0.1:3048/".to_string()]);
    assert!(!x509util::subject_string(&cert.der).contains("nodejs") && !x509util::subject_string(&cert.der).contains(":3000"), "neither the Node name nor the old port");
    assert!(printed.contains("subject   CN=wsfed-caep-rust demo RP, OU=http://127.0.0.1:3048/") && printed.contains("SAN URI   http://127.0.0.1:3048/"), "{printed}");
    assert_eq!(std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(dir.join("c.pem")).unwrap().permissions().mode() & 0o777, 0o644);
    let _ = std::fs::remove_dir_all(&dir);

    // --public-url moves the configured realm's origin, as the demo does.
    let (cert, _, dir, _) = generated("public", "http://localhost:3000/", &["--public-url", "https://rp.example.test"]);
    assert_eq!(x509util::subject_alt_uris(&cert.der), vec!["https://rp.example.test/".to_string()]);
    let _ = std::fs::remove_dir_all(&dir);

    // Neither: the configured realm as the demo would serve it here (PORT
    // moves a loopback port), and --cn names it otherwise.
    let (cert, _, dir, _) = generated("config", "http://localhost:3000/", &["--cn", "orders portal RP"]);
    let want = cli::running_realm("http://localhost:3000/", &std::collections::HashMap::new());
    assert_eq!(x509util::subject_string(&cert.der), format!("CN=orders portal RP, OU={want}"));
    assert_eq!(x509util::subject_alt_uris(&cert.der), vec![want]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_long_realm_is_clipped_in_the_subject_and_whole_in_the_alt_name() {
    let realm = format!("https://rp.example.test/{}/", "a".repeat(80));
    let pair = x509util::create_named_key_pair(&x509util::CertificateName { common_name: "x".into(), unit: realm.clone(), uri: realm.clone() }, 30, 2048).unwrap();
    let subject = x509util::subject_string(&pair.certificate_der);
    assert_eq!(subject, format!("CN=x, OU={}", &realm[..64]), "RFC 5280: at most 64 characters");
    assert_eq!(x509util::subject_alt_uris(&pair.certificate_der), vec![realm]);
    let plain = create_self_signed_key_pair("rp", 30, 2048).unwrap();
    assert_eq!(x509util::subject_string(&plain.certificate_der), "CN=rp");
    assert!(x509util::subject_alt_uris(&plain.certificate_der).is_empty());
}
