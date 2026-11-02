// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::error::{fail, Result};
use crate::names::{C14N10, C14N10_COMMENTS, DS, ENVELOPED, EXC_C14N, EXC_C14N_COMMENTS, RSA_SHA256};
use crate::xml::{self, XmlDoc};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256, Sha384, Sha512};
use ua_cryptography_xml_c14n::roxmltree::Node;
use ua_cryptography_xml_c14n::{canonicalize, Algorithm};

#[derive(Clone)]
pub struct IdpCert {
    pub der: Vec<u8>,
    pub public_key: rsa::RsaPublicKey,
}

fn sig_alg(uri: &str) -> Option<&'static str> {
    match uri {
        RSA_SHA256 => Some("sha256"),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => Some("sha384"),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => Some("sha512"),
        _ => None,
    }
}

fn digest_alg(uri: &str) -> Option<&'static str> {
    match uri {
        "http://www.w3.org/2001/04/xmlenc#sha256" => Some("sha256"),
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => Some("sha384"),
        "http://www.w3.org/2001/04/xmlenc#sha512" => Some("sha512"),
        _ => None,
    }
}

fn is_transform(alg: &str) -> bool {
    matches!(alg, ENVELOPED | EXC_C14N | EXC_C14N_COMMENTS | C14N10 | C14N10_COMMENTS)
}

fn algorithm_of(parent: Node, local: &str) -> String {
    xml::child(parent, DS, local).ok().flatten().and_then(|node| xml::attr(node, "Algorithm")).unwrap_or_default()
}

fn prefixes_of(method: Option<Node>) -> Vec<String> {
    let Some(method) = method else { return Vec::new() };
    for child in method.children() {
        if child.is_element() && child.tag_name().name() == "InclusiveNamespaces" {
            return xml::attr(child, "PrefixList").unwrap_or_default().split_whitespace().map(|item| item.to_string()).collect();
        }
    }
    Vec::new()
}

fn b64_text(node: Option<Node>) -> std::result::Result<Vec<u8>, String> {
    let raw = node.map(xml::text_content).unwrap_or_default();
    let compact: String = raw.chars().filter(|ch| !ch.is_whitespace()).collect();
    if compact.is_empty() {
        return Ok(Vec::new());
    }
    STANDARD.decode(&compact).or_else(|_| STANDARD.decode(compact.trim_end_matches('='))).map_err(|err| err.to_string())
}

fn digest(name: &str, data: &[u8]) -> Result<Vec<u8>> {
    Ok(match name {
        "sha256" => Sha256::digest(data).to_vec(),
        "sha384" => Sha384::digest(data).to_vec(),
        "sha512" => Sha512::digest(data).to_vec(),
        _ => return Err(fail("signature", "unsupported digest")),
    })
}

fn c14n_algorithm(uri: &str) -> Result<Algorithm> {
    Algorithm::from_uri(uri).ok_or_else(|| fail("signature", format!("canonicalization {uri} is refused")))
}

fn canon(node: Node, algorithm: &str, prefixes: &[String], excluded: Option<Node>) -> Result<Vec<u8>> {
    let method = c14n_algorithm(algorithm)?;
    let owned: Vec<&str> = prefixes.iter().map(|item| item.as_str()).collect();
    Ok(canonicalize(node, method, &owned, excluded))
}

pub fn verify_signed(element: Node, certs: &[IdpCert], what: &str) -> Result<Option<String>> {
    let Some(sig_el) = xml::child(element, DS, "Signature")? else { return Ok(None) };
    let element_id = xml::attr(element, "ID").unwrap_or_default();
    if element_id.is_empty() {
        return Err(fail("signature", format!("{what} is signed but has no ID for the signature to refer to")));
    }
    let Some(signed_info) = xml::child(sig_el, DS, "SignedInfo")? else {
        return Err(fail("signature", format!("{what}'s signature has no SignedInfo")));
    };
    let c14n_alg = algorithm_of(signed_info, "CanonicalizationMethod");
    if Algorithm::from_uri(&c14n_alg).is_none() {
        let shown = if c14n_alg.is_empty() { "(none)".to_string() } else { c14n_alg };
        return Err(fail("signature", format!("{what}'s signature uses the canonicalization {shown}, which is refused")));
    }
    let sig_method = algorithm_of(signed_info, "SignatureMethod");
    let Some(hash_name) = sig_alg(sig_method.as_str()) else {
        let shown = if sig_method.is_empty() { "(none)".to_string() } else { sig_method };
        return Err(fail("signature", format!("{what}'s signature uses {shown}, which is refused (SHA-1 and non-RSA algorithms are not accepted)")));
    };
    let refs = xml::children(signed_info, DS, "Reference");
    if refs.len() != 1 {
        return Err(fail("signature", format!("{}'s signature has {} references; exactly one is accepted", what, refs.len())));
    }
    let reference = refs[0];
    let uri = xml::attr(reference, "URI").unwrap_or_default();
    if uri != format!("#{element_id}") {
        let shown = if uri.is_empty() { "(nothing)".to_string() } else { uri };
        return Err(fail("signature", format!("{what}'s signature refers to {shown}, not to {what} itself (#{element_id})")));
    }
    let digest_method = algorithm_of(reference, "DigestMethod");
    let Some(digest_name) = digest_alg(&digest_method) else {
        let shown = if digest_method.is_empty() { "(none)".to_string() } else { digest_method };
        return Err(fail("signature", format!("{what}'s signature digests with {shown}, which is refused")));
    };
    let transforms = xml::child(reference, DS, "Transforms")?.map(|node| xml::children(node, DS, "Transform")).unwrap_or_default();
    for transform in &transforms {
        let alg = xml::attr(*transform, "Algorithm").unwrap_or_default();
        if !is_transform(&alg) {
            let shown = if alg.is_empty() { "(none)".to_string() } else { alg };
            return Err(fail("signature", format!("{what}'s signature uses the transform {shown}, which is refused")));
        }
    }
    if certs.is_empty() {
        return Err(fail("signature", format!("no signing certificate is known for the identity provider, so {what} cannot be verified")));
    }
    let mut ref_alg = EXC_C14N.to_string();
    let mut prefixes = Vec::new();
    let mut enveloped = false;
    for transform in &transforms {
        let alg = xml::attr(*transform, "Algorithm").unwrap_or_default();
        if alg == ENVELOPED {
            enveloped = true;
            continue;
        }
        if Algorithm::from_uri(&alg).is_some() {
            prefixes = prefixes_of(Some(*transform));
            ref_alg = alg;
        }
    }
    let excluded = if enveloped { Some(sig_el) } else { Some(sig_el) };
    let ref_c14n = canon(element, &ref_alg, &prefixes, excluded)?;
    let got = digest(digest_name, &ref_c14n)?;
    let want = b64_text(xml::child(reference, DS, "DigestValue")?).map_err(|_| fail("signature", format!("{what}'s signature does not verify against the identity provider's certificate: the signature does not verify")))?;
    if got != want {
        return Err(fail("signature", format!("{what}'s signature does not verify against the identity provider's certificate: the signature does not verify")));
    }
    let info_method = xml::child(signed_info, DS, "CanonicalizationMethod")?;
    let info_prefixes = prefixes_of(info_method);
    let info_bytes = canon(signed_info, &c14n_alg, &info_prefixes, None)?;
    let sig_bytes = b64_text(xml::child(sig_el, DS, "SignatureValue")?).map_err(|err| fail("signature", format!("{what}'s signature does not verify against the identity provider's certificate: {err}")))?;
    let mut reason = "the signature does not verify".to_string();
    for cert in certs {
        if !verify_pkcs1(&cert.public_key, hash_name, &info_bytes, &sig_bytes) {
            reason = "the signature does not verify".to_string();
            continue;
        }
        let text = String::from_utf8(ref_c14n).map_err(|err| fail("signature", err.to_string()))?;
        return Ok(Some(text));
    }
    Err(fail("signature", format!("{what}'s signature does not verify against the identity provider's certificate: {reason}")))
}

fn verify_pkcs1(key: &rsa::RsaPublicKey, hash_name: &str, message: &[u8], signature: &[u8]) -> bool {
    let sig = rsa::pkcs1v15::Signature::try_from(signature).ok();
    let Some(sig) = sig else { return false };
    match hash_name {
        "sha256" => VerifyingKey::<Sha256>::new(key.clone()).verify(message, &sig).is_ok(),
        "sha384" => VerifyingKey::<Sha384>::new(key.clone()).verify(message, &sig).is_ok(),
        "sha512" => VerifyingKey::<Sha512>::new(key.clone()).verify(message, &sig).is_ok(),
        _ => false,
    }
}

pub fn sign_enveloped(xml: &str, element_id: &str, key: &RsaPrivateKey, cert_pem: &str) -> Result<String> {
    let doc = XmlDoc::parse(xml, "the signed element")?;
    let digest_b64 = doc.with(|root| -> Result<String> {
        let target = xml::find_id(root, element_id).ok_or_else(|| fail("signature", format!("no element ID {element_id}")))?;
        let canon = canonicalize(target, Algorithm::Exclusive, &[], None);
        Ok(STANDARD.encode(Sha256::digest(&canon)))
    })??;
    let source = doc.text.as_str().to_string();
    let insert_at = doc.with(|root| -> Result<usize> {
        let target = xml::find_id(root, element_id).ok_or_else(|| fail("signature", format!("no element ID {element_id}")))?;
        Ok(match xml::child(target, crate::names::SAML, "Issuer")? {
            Some(issuer) => issuer.range().end,
            None => target.range().start,
        })
    })??;
    let sig = signature_xml(element_id, cert_pem, &digest_b64);
    let mut signed = String::new();
    signed.push_str(&source[..insert_at]);
    signed.push_str(&sig);
    signed.push_str(&source[insert_at..]);
    let doc2 = XmlDoc::parse(&signed, "the signed element")?;
    let info = doc2.with(|root| -> Result<Vec<u8>> {
        let target = xml::find_id(root, element_id).ok_or_else(|| fail("signature", "SignedInfo was not built"))?;
        let sig = xml::child(target, DS, "Signature")?.ok_or_else(|| fail("signature", "SignedInfo was not built"))?;
        let info = xml::child(sig, DS, "SignedInfo")?.ok_or_else(|| fail("signature", "SignedInfo was not built"))?;
        Ok(canonicalize(info, Algorithm::Exclusive, &[], None))
    })??;
    let signing = SigningKey::<Sha256>::new(key.clone());
    let raw = signing.sign(&info).to_bytes();
    let value = STANDARD.encode(raw);
    Ok(signed.replace("<ds:SignatureValue></ds:SignatureValue>", &format!("<ds:SignatureValue>{value}</ds:SignatureValue>")))
}

fn signature_xml(element_id: &str, cert_pem: &str, digest: &str) -> String {
    format!(
        "<ds:Signature xmlns:ds=\"{DS}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{EXC_C14N}\"/><ds:SignatureMethod Algorithm=\"{RSA_SHA256}\"/><ds:Reference URI=\"#{element_id}\"><ds:Transforms><ds:Transform Algorithm=\"{ENVELOPED}\"/><ds:Transform Algorithm=\"{EXC_C14N}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
        xml::pem_body(cert_pem)
    )
}
