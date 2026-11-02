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

#[test]
fn generate_keys_names_the_certificate_after_the_realm() {
    let dir = std::env::temp_dir().join(format!("wsfed-x509-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("wsfed.json");
    std::fs::write(&config, r#"{"realm":"http://localhost:3000/","replyUrl":"http://localhost:3000/wsfed","idpMetadata":"x","privateKey":"k.pem","certificate":"c.pem"}"#).unwrap();
    let mut out = Vec::new();
    let code = cli::main(&[
        "generate-keys".into(),
        "--config".into(),
        config.display().to_string(),
        "--bits".into(),
        "2048".into(),
    ], &mut out);
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&out));
    let cert_path = dir.join("c.pem");
    let key_path = dir.join("k.pem");
    let pem = std::fs::read_to_string(&cert_path).unwrap();
    let cert = x509util::load_cert(&pem).unwrap();
    let want = "CN=wsfed-caep-nodejs relying party http://localhost:3000/";
    assert_eq!(x509util::subject_string(&cert.der), want);
    assert_eq!(x509util::subject_cn(&cert.der), "wsfed-caep-nodejs relying party http://localhost:3000/");
    assert_eq!(std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(&cert_path).unwrap().permissions().mode() & 0o777, 0o644);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = out;
}
