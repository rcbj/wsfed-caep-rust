// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::error::{fail, Result};
use crate::names::{DS, XENC, XENC11};
use crate::xml;
use aes::Aes192;
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm};

type Aes192Gcm = AesGcm<Aes192, U12>;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rsa::Oaep;
use rsa::RsaPrivateKey;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use ua_cryptography_xml_c14n::roxmltree::Node;

struct CipherSpec {
    name: &'static str,
    gcm: bool,
    key_length: usize,
}

fn cipher_of(alg: &str) -> Option<CipherSpec> {
    Some(match alg {
        "http://www.w3.org/2009/xmlenc11#aes128-gcm" => CipherSpec { name: "aes-128-gcm", gcm: true, key_length: 16 },
        "http://www.w3.org/2009/xmlenc11#aes192-gcm" => CipherSpec { name: "aes-192-gcm", gcm: true, key_length: 24 },
        "http://www.w3.org/2009/xmlenc11#aes256-gcm" => CipherSpec { name: "aes-256-gcm", gcm: true, key_length: 32 },
        "http://www.w3.org/2001/04/xmlenc#aes128-cbc" => CipherSpec { name: "aes-128-cbc", gcm: false, key_length: 16 },
        "http://www.w3.org/2001/04/xmlenc#aes192-cbc" => CipherSpec { name: "aes-192-cbc", gcm: false, key_length: 24 },
        "http://www.w3.org/2001/04/xmlenc#aes256-cbc" => CipherSpec { name: "aes-256-cbc", gcm: false, key_length: 32 },
        _ => return None,
    })
}

fn dec(message: impl Into<String>) -> crate::error::WsFedError {
    fail("decryption", message)
}

fn b64(value: &str) -> Result<Vec<u8>> {
    let compact: String = value.chars().filter(|ch| !ch.is_whitespace()).collect();
    STANDARD.decode(compact).map_err(|err| fail("decryption", format!("the content could not be decrypted: {err}")))
}

fn oaep_name(alg: &str) -> Option<&'static str> {
    Some(match alg {
        "http://www.w3.org/2000/09/xmldsig#sha1" => "sha1",
        "http://www.w3.org/2001/04/xmlenc#sha256" => "sha256",
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => "sha384",
        "http://www.w3.org/2001/04/xmlenc#sha512" => "sha512",
        _ => return None,
    })
}

fn mgf_name(alg: &str) -> Option<&'static str> {
    Some(match alg {
        "http://www.w3.org/2009/xmlenc11#mgf1sha1" => "sha1",
        "http://www.w3.org/2009/xmlenc11#mgf1sha256" => "sha256",
        "http://www.w3.org/2009/xmlenc11#mgf1sha384" => "sha384",
        "http://www.w3.org/2009/xmlenc11#mgf1sha512" => "sha512",
        _ => return None,
    })
}

fn decrypt_oaep(key: &RsaPrivateKey, name: &str, blob: &[u8]) -> std::result::Result<Vec<u8>, rsa::Error> {
    match name {
        "sha256" => key.decrypt(Oaep::new::<Sha256>(), blob),
        "sha384" => key.decrypt(Oaep::new::<Sha384>(), blob),
        "sha512" => key.decrypt(Oaep::new::<Sha512>(), blob),
        _ => key.decrypt(Oaep::new::<Sha1>(), blob),
    }
}

fn unwrap_key(encrypted_key: Node, key: &RsaPrivateKey) -> Result<Vec<u8>> {
    let method = xml::child(encrypted_key, XENC, "EncryptionMethod")?;
    let alg = method.and_then(|node| xml::attr(node, "Algorithm")).unwrap_or_default();
    if alg != "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" && alg != "http://www.w3.org/2009/xmlenc11#rsa-oaep" {
        let shown = if alg.is_empty() { "(none)".to_string() } else { alg.clone() };
        return Err(dec(format!("the content key is wrapped with {shown}; only RSA-OAEP is accepted")));
    }
    let mut digest_name = "sha1".to_string();
    if let Some(method) = method {
        if let Some(digest_method) = xml::child(method, DS, "DigestMethod")? {
            let digest_alg = xml::attr(digest_method, "Algorithm").unwrap_or_default();
            if !digest_alg.is_empty() {
                digest_name = oaep_name(&digest_alg).ok_or_else(|| dec(format!("the OAEP digest {digest_alg} is not supported")))?.to_string();
            }
        }
        let mut mgf = "sha1".to_string();
        if alg == "http://www.w3.org/2009/xmlenc11#rsa-oaep" {
            if let Some(mgf_el) = xml::child(method, XENC11, "MGF")? {
                let mgf_alg = xml::attr(mgf_el, "Algorithm").unwrap_or_default();
                if !mgf_alg.is_empty() {
                    mgf = mgf_name(&mgf_alg).ok_or_else(|| dec(format!("the OAEP mask generation function {mgf_alg} is not supported")))?.to_string();
                }
            }
        }
        if mgf != digest_name {
            return Err(dec(format!("OAEP with digest {digest_name} and MGF1 {mgf} is not supported; node:crypto uses one hash for both")));
        }
    }
    let values = xml::descendants(encrypted_key, XENC, "CipherValue");
    let raw = values.first().map(|node| xml::text_of(*node)).unwrap_or_default();
    let blob = b64(&raw).map_err(|err| fail("decryption", format!("the content key could not be unwrapped with this relying party's key: {err}")))?;
    decrypt_oaep(key, &digest_name, &blob).map_err(|err| fail("decryption", format!("the content key could not be unwrapped with this relying party's key: {err}")))
}

pub fn decrypt_element(encrypted: Node, key: &RsaPrivateKey) -> Result<String> {
    let data = if xml::is_el(encrypted, XENC, "EncryptedData") {
        encrypted
    } else {
        xml::child(encrypted, XENC, "EncryptedData")?.ok_or_else(|| dec(format!("<{}> has no EncryptedData", encrypted.tag_name().name())))?
    };
    let method = xml::child(data, XENC, "EncryptionMethod")?;
    let alg = method.and_then(|node| xml::attr(node, "Algorithm")).unwrap_or_default();
    let Some(spec) = cipher_of(&alg) else {
        let shown = if alg.is_empty() { "(none)".to_string() } else { alg };
        return Err(dec(format!("the content is encrypted with {shown}, which is not supported")));
    };
    let keys = xml::descendants(encrypted, XENC, "EncryptedKey");
    if keys.is_empty() {
        return Err(dec(format!("<{}> carries no EncryptedKey", encrypted.tag_name().name())));
    }
    let content_key = unwrap_key(keys[0], key)?;
    if content_key.len() != spec.key_length {
        return Err(dec(format!("the content key is {} bytes; {} needs {}", content_key.len(), spec.name, spec.key_length)));
    }
    let cipher_data = xml::child(data, XENC, "CipherData")?;
    let value = match cipher_data {
        Some(node) => xml::child(node, XENC, "CipherValue")?,
        None => None,
    };
    let raw = b64(&value.map(xml::text_of).unwrap_or_default()).map_err(|_| dec("the content could not be decrypted"))?;
    if spec.gcm {
        if raw.len() < 28 {
            return Err(dec("the ciphertext is too short"));
        }
        let plain = decrypt_gcm(spec.key_length, &content_key, &raw[..12], &raw[12..]).map_err(|_| dec("the content could not be decrypted"))?;
        return String::from_utf8(plain).map_err(|err| dec(err.to_string()));
    }
    if raw.len() < 32 || raw.len() % 16 != 0 {
        return Err(dec("the ciphertext is not a whole number of blocks"));
    }
    let plain = decrypt_cbc(spec.key_length, &content_key, &raw[..16], &raw[16..])?;
    String::from_utf8(plain).map_err(|err| dec(err.to_string()))
}

fn decrypt_gcm(size: usize, key: &[u8], nonce: &[u8], data: &[u8]) -> std::result::Result<Vec<u8>, aes_gcm::Error> {
    let nonce = aes_gcm::Nonce::from_slice(nonce);
    match size {
        16 => Aes128Gcm::new_from_slice(key).map_err(|_| aes_gcm::Error)?.decrypt(nonce, data),
        24 => Aes192Gcm::new_from_slice(key).map_err(|_| aes_gcm::Error)?.decrypt(nonce, data),
        _ => Aes256Gcm::new_from_slice(key).map_err(|_| aes_gcm::Error)?.decrypt(nonce, data),
    }
}

fn decrypt_cbc(size: usize, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::{BlockDecryptMut, KeyIvInit};
    let mut buf = data.to_vec();
    let out = match size {
        16 => cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv).map_err(|err| dec(err.to_string()))?.decrypt_padded_mut::<block_padding::Pkcs7>(&mut buf).map_err(|_| dec("the content could not be decrypted"))?.to_vec(),
        24 => cbc::Decryptor::<aes::Aes192>::new_from_slices(key, iv).map_err(|err| dec(err.to_string()))?.decrypt_padded_mut::<block_padding::Pkcs7>(&mut buf).map_err(|_| dec("the content could not be decrypted"))?.to_vec(),
        _ => cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv).map_err(|err| dec(err.to_string()))?.decrypt_padded_mut::<block_padding::Pkcs7>(&mut buf).map_err(|_| dec("the content could not be decrypted"))?.to_vec(),
    };
    Ok(out)
}
