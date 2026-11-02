// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::error::{fail, Result};
use crate::signature::IdpCert;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use pem::Pem;
use rand::rngs::OsRng;
use chrono::{Datelike, Timelike};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::signature::{SignatureEncoding, Signer};
use rsa::{pkcs1v15::SigningKey, RsaPrivateKey, RsaPublicKey};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use x509_parser::prelude::FromDer;
use x509_parser::certificate::X509Certificate;

pub struct KeyPair {
    pub private_key_pem: String,
    pub certificate_pem: String,
    pub certificate_der: Vec<u8>,
    pub private_key: RsaPrivateKey,
}

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let mut raw = Vec::new();
    let mut value = n;
    while value > 0 {
        raw.insert(0, (value & 0xff) as u8);
        value >>= 8;
    }
    let mut out = vec![0x80 | raw.len() as u8];
    out.extend(raw);
    out
}

fn tlv(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for part in parts {
        body.extend_from_slice(part);
    }
    let mut out = vec![tag];
    out.extend(der_len(body.len()));
    out.extend(body);
    out
}

fn seq(parts: &[&[u8]]) -> Vec<u8> { tlv(0x30, parts) }
fn set(parts: &[&[u8]]) -> Vec<u8> { tlv(0x31, parts) }

fn oid(dotted: &str) -> Vec<u8> {
    let nums: Vec<u64> = dotted.split('.').map(|part| part.parse().unwrap_or(0)).collect();
    let mut body = vec![(nums[0] * 40 + nums[1]) as u8];
    for number in nums.iter().skip(2) {
        let mut chunk = vec![(number & 0x7f) as u8];
        let mut value = number >> 7;
        while value > 0 {
            chunk.insert(0, ((value & 0x7f) | 0x80) as u8);
            value >>= 7;
        }
        body.extend(chunk);
    }
    tlv(0x06, &[&body])
}

fn der_time(moment: chrono::DateTime<chrono::Utc>) -> Vec<u8> {
    let iso = moment.format("%Y%m%d%H%M%S").to_string() + "Z";
    if moment.year() < 2050 {
        tlv(0x17, &[&iso.as_bytes()[2..]])
    } else {
        tlv(0x18, &[iso.as_bytes()])
    }
}

fn der_header(data: &[u8], at: usize) -> (usize, usize) {
    let first = data[at + 1];
    if first < 0x80 {
        let start = at + 2;
        return (start, start + first as usize);
    }
    let count = (first & 0x7f) as usize;
    let mut length = 0usize;
    for i in 0..count {
        length = length * 256 + data[at + 2 + i] as usize;
    }
    let start = at + 2 + count;
    (start, start + length)
}

fn subject_public_key_bits(spki: &[u8]) -> Vec<u8> {
    let (body, _) = der_header(spki, 0);
    let (_, alg_end) = der_header(spki, body);
    let (bits_body, bits_end) = der_header(spki, alg_end);
    spki[bits_body + 1..bits_end].to_vec()
}

fn der_name(common_name: &str) -> Vec<u8> {
    let cn = common_name.as_bytes();
    let utf8 = tlv(0x0c, &[cn]);
    let oid_cn = oid("2.5.4.3");
    let pair = seq(&[&oid_cn, &utf8]);
    let one = set(&[&pair]);
    seq(&[&one])
}

pub fn create_self_signed_key_pair(common_name: &str, days: i64, bits: usize) -> Result<KeyPair> {
    let days = if days <= 0 { 1095 } else { days };
    let bits = if bits == 0 { 3072 } else { bits };
    let private_key = RsaPrivateKey::new(&mut OsRng, bits).map_err(|err| fail("config", err.to_string()))?;
    let mut serial = rand::random::<[u8; 16]>();
    serial[0] &= 0x7f;
    if serial[0] == 0 { serial[0] = 1; }
    let not_before = chrono::Utc::now() - chrono::Duration::seconds(60);
    let not_before = not_before.with_nanosecond(0).unwrap_or(not_before);
    let not_after = not_before + chrono::Duration::days(days);
    let spki = private_key.to_public_key().to_public_key_der().map_err(|err| fail("config", err.to_string()))?.as_bytes().to_vec();
    let key_id = Sha1::digest(subject_public_key_bits(&spki)).to_vec();
    let ski = seq(&[&oid("2.5.29.14"), &tlv(0x04, &[&tlv(0x04, &[&key_id])])]);
    let aki_inner = seq(&[&tlv(0x80, &[&key_id])]);
    let aki = seq(&[&oid("2.5.29.35"), &tlv(0x04, &[&aki_inner])]);
    let bc = seq(&[&oid("2.5.29.19"), &tlv(0x01, &[&[0xff]]), &tlv(0x04, &[&seq(&[])])]);
    let ku = seq(&[&oid("2.5.29.15"), &tlv(0x01, &[&[0xff]]), &tlv(0x04, &[&tlv(0x03, &[&[0x05, 0xa0]])])]);
    let extensions = tlv(0xa3, &[&seq(&[&ski, &aki, &bc, &ku])]);
    let sha256_rsa = seq(&[&oid("1.2.840.113549.1.1.11"), &[0x05, 0x00]]);
    let name = der_name(common_name);
    let times = seq(&[&der_time(not_before), &der_time(not_after)]);
    let version = tlv(0xa0, &[&tlv(0x02, &[&[0x02]])]);
    let serial_der = tlv(0x02, &[&serial]);
    let tbs = seq(&[&version, &serial_der, &sha256_rsa, &name, &times, &name, &spki, &extensions]);
    let signing = SigningKey::<Sha256>::new(private_key.clone());
    let signature = signing.sign(&tbs).to_bytes();
    let bit = {
        let mut body = vec![0u8];
        body.extend_from_slice(&signature);
        tlv(0x03, &[&body])
    };
    let der = seq(&[&tbs, &sha256_rsa, &bit]);
    let certificate_pem = pem::encode(&Pem::new("CERTIFICATE", der.clone()));
    let pkcs8 = private_key.to_pkcs8_der().map_err(|err| fail("config", err.to_string()))?;
    let private_key_pem = pem::encode(&Pem::new("PRIVATE KEY", pkcs8.as_bytes().to_vec()));
    Ok(KeyPair { private_key_pem, certificate_pem, certificate_der: der, private_key })
}

pub fn load_private_key(pem_text: &str) -> Result<RsaPrivateKey> {
    if !pem_text.contains("-----BEGIN ") {
        return Err(fail("config", "the private key or certificate cannot be read: not a PEM"));
    }
    RsaPrivateKey::from_pkcs8_pem(pem_text).or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem_text)).map_err(|err| fail("config", format!("the private key or certificate cannot be read: {err}")))
}

pub fn load_cert(pem_text: &str) -> Result<IdpCert> {
    if !pem_text.contains("-----BEGIN ") {
        return Err(fail("config", "the private key or certificate cannot be read: not a PEM"));
    }
    let parsed = pem::parse(pem_text).map_err(|_| fail("config", "the private key or certificate cannot be read: not a PEM"))?;
    cert_from_der(parsed.contents())
}

pub fn cert_from_der(der: &[u8]) -> Result<IdpCert> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|err| fail("config", format!("the private key or certificate cannot be read: {err}")))?;
    let spki = cert.public_key().raw;
    let public_key = RsaPublicKey::from_public_key_der(spki).or_else(|_| {
        let bits = subject_public_key_bits(spki);
        RsaPublicKey::from_pkcs1_der(&bits)
    }).map_err(|err| fail("config", format!("the private key or certificate cannot be read: {err}")))?;
    Ok(IdpCert { der: der.to_vec(), public_key })
}

pub fn cert_pem_body(der: &[u8]) -> String {
    STANDARD.encode(der)
}

pub fn subject_cn(der: &[u8]) -> String {
    let Ok((_, cert)) = X509Certificate::from_der(der) else { return String::new() };
    let cn = cert.subject().iter_common_name().next().and_then(|name| name.as_str().ok()).unwrap_or("").to_string();
    cn
}

pub fn subject_string(der: &[u8]) -> String {
    let cn = subject_cn(der);
    if cn.is_empty() { String::new() } else { format!("CN={cn}") }
}
