// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::error::{fail, Result};
use crate::names::{WSA, WSA2004, XSI};
use ua_cryptography_xml_c14n::roxmltree::{Document, Node};
use ua_cryptography_xml_c14n::DocumentText;

pub struct XmlDoc {
    pub text: DocumentText,
}

impl XmlDoc {
    pub fn parse(xml: &str, what: &str) -> Result<Self> {
        let lower = xml.to_ascii_lowercase();
        if lower.contains("<!doctype") || lower.contains("<!entity") {
            return Err(fail("xml", format!("{what} carries a DOCTYPE or an entity declaration, which WS-Federation never needs")));
        }
        let text = DocumentText::decode(xml.as_bytes()).map_err(|err| fail("xml", format!("{what} is not XML: {err}")))?;
        text.parse().map_err(|err| fail("xml", format!("{what} is not XML: {err}")))?;
        Ok(Self { text })
    }

    pub fn with<T>(&self, f: impl FnOnce(Node<'_, '_>) -> T) -> Result<T> {
        let doc = self.text.parse().map_err(|err| fail("xml", err.to_string()))?;
        Ok(f(doc.root_element()))
    }
}

pub fn parse<'a>(xml: &'a str, what: &str) -> Result<Document<'a>> {
    let lower = xml.to_ascii_lowercase();
    if lower.contains("<!doctype") || lower.contains("<!entity") {
        return Err(fail("xml", format!("{what} carries a DOCTYPE or an entity declaration, which WS-Federation never needs")));
    }
    let options = ua_cryptography_xml_c14n::roxmltree::ParsingOptions { allow_dtd: false, ..Default::default() };
    Document::parse_with_options(xml, options).map_err(|err| fail("xml", format!("{what} is not XML: {err}")))
}

pub fn is_el(node: Node, ns: &str, local: &str) -> bool {
    node.is_element() && node.tag_name().namespace() == Some(ns) && node.tag_name().name() == local
}

pub fn children<'a>(node: Node<'a, 'a>, ns: &str, local: &str) -> Vec<Node<'a, 'a>> {
    node.children().filter(|child| is_el(*child, ns, local)).collect()
}

pub fn child<'a>(node: Node<'a, 'a>, ns: &str, local: &str) -> Result<Option<Node<'a, 'a>>> {
    let found = children(node, ns, local);
    if found.len() > 1 {
        return Err(fail("xml", format!("<{}> has {} {local} children; exactly one is accepted", node.tag_name().name(), found.len())));
    }
    Ok(found.into_iter().next())
}

pub fn descendants<'a>(node: Node<'a, 'a>, ns: &str, local: &str) -> Vec<Node<'a, 'a>> {
    node.descendants().filter(|child| is_el(*child, ns, local)).collect()
}

pub fn text_content(node: Node) -> String {
    let mut out = String::new();
    for desc in node.descendants() {
        if desc.is_text() {
            out.push_str(desc.text().unwrap_or(""));
        }
    }
    out
}

pub fn text_of(node: Node) -> String {
    text_content(node).trim().to_string()
}

pub fn attr(node: Node, name: &str) -> Option<String> {
    node.attributes().find(|item| item.namespace().is_none() && item.name() == name).map(|item| item.value().to_string())
}

pub fn attr_ns(node: Node, ns: &str, local: &str) -> Option<String> {
    node.attribute((ns, local)).map(|value| value.to_string())
}

pub fn xsi_type(node: Node) -> Option<(String, String)> {
    let value = attr_ns(node, XSI, "type")?;
    let (prefix, local) = match value.split_once(':') {
        Some((prefix, local)) => (prefix.to_string(), local.to_string()),
        None => (String::new(), value),
    };
    let ns = resolve_prefix(node, &prefix)?;
    Some((ns, local))
}

fn resolve_prefix(node: Node, prefix: &str) -> Option<String> {
    let mut current = Some(node);
    while let Some(item) = current {
        if item.is_element() {
            for ns in item.namespaces() {
                if ns.name().unwrap_or("") == prefix {
                    return Some(ns.uri().to_string());
                }
            }
        }
        current = item.parent();
    }
    if prefix.is_empty() { Some(String::new()) } else { None }
}

pub fn wsa_addresses(node: Node) -> Vec<String> {
    let mut out = Vec::new();
    for ns in [WSA, WSA2004] {
        for address in descendants(node, ns, "Address") {
            let text = text_of(address);
            if !text.is_empty() {
                out.push(text);
            }
        }
    }
    out
}

pub fn assert_unique_ids(root: Node) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for node in root.descendants() {
        if !node.is_element() {
            continue;
        }
        for attribute in node.attributes() {
            let name = attribute.name();
            if name != "ID" && name != "Id" && name != "id" {
                continue;
            }
            let value = attribute.value();
            if !seen.insert(value.to_string()) {
                return Err(fail("signature", format!("two elements carry the ID {value}")));
            }
        }
    }
    Ok(())
}

pub fn find_id<'a>(root: Node<'a, 'a>, id: &str) -> Option<Node<'a, 'a>> {
    root.descendants().find(|node| {
        node.is_element() && node.attributes().any(|attribute| {
            let name = attribute.name();
            (name == "ID" || name == "Id" || name == "id") && attribute.value() == id
        })
    })
}

pub fn escape_xml(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

pub fn pem_body(pem: &str) -> String {
    pem.lines().filter(|line| !line.starts_with("-----")).map(|line| line.trim()).collect::<Vec<_>>().join("")
}

pub fn to_pem(kind: &str, body: &str) -> String {
    let compact: String = body.chars().filter(|ch| !ch.is_whitespace()).collect();
    let mut out = format!("-----BEGIN {kind}-----\n");
    for chunk in compact.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str(&format!("-----END {kind}-----\n"));
    out
}
