// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use super::test_support::{self as stub, AssertionOptions, MetaOptions, WResultOptions};
use crate::demo::{endpoints_for, App};
use crate::relying_party::{first_map, RelyingParty};
use crate::test_support::{PASSIVE, REALM, REPLY};
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;

fn cookie(fields: &[(String, String)], name: &str) -> String {
    for (key, value) in fields {
        if !key.eq_ignore_ascii_case("set-cookie") { continue; }
        let pair = value.split(';').next().unwrap_or("");
        if let Some((found, raw)) = pair.split_once('=') {
            if found == name { return raw.to_string(); }
        }
    }
    String::new()
}

fn header(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs.iter().map(|(key, value)| ((*key).to_string(), (*value).to_string())).collect()
}

#[test]
fn sign_in_cleanup_and_logout() {
    let config = serde_json::json!({
        "realm": REALM,
        "replyUrl": REPLY,
        "privateKey": stub::rp_key(),
        "certificate": stub::rp_cert(),
        "idpMetadata": stub::idp_metadata(&MetaOptions::default()),
    });
    let map = config.as_object().unwrap().clone();
    let rp = RelyingParty::create(&map, Path::new(".")).unwrap();
    let app = App::new(rp, None);
    let (status, _, body) = app.handle("GET", "/healthz", &HashMap::new(), b"");
    assert_eq!(status, 200);
    assert_eq!(body, b"ok");
    let (status, fields, _) = app.handle("GET", "/login", &HashMap::new(), b"");
    assert_eq!(status, 302);
    let location = fields.iter().find(|(name, _)| name.eq_ignore_ascii_case("location")).map(|(_, value)| value.clone()).unwrap();
    let parsed = url::Url::parse(&location).unwrap();
    assert_eq!(format!("{}://{}{}", parsed.scheme(), parsed.host_str().unwrap(), parsed.path()), PASSIVE);
    let params = first_map(parsed.query().unwrap_or(""));
    assert_eq!(params.get("wa").map(String::as_str), Some("wsignin1.0"));
    let pending = cookie(&fields, "wsfed_pending");
    assert!(!pending.is_empty());
    let made = stub::signed_assertion(&AssertionOptions::default()).unwrap();
    let result = stub::wresult(&WResultOptions { token: Some(made.xml), ..WResultOptions::default() }).unwrap();
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("wa", "wsignin1.0")
        .append_pair("wresult", &result)
        .append_pair("wctx", params.get("wctx").map(String::as_str).unwrap_or(""))
        .finish();
    let (status, fields, msg) = app.handle("POST", "/wsfed", &header(&[("cookie", &format!("wsfed_pending={pending}"))]), form.as_bytes());
    assert_eq!(status, 303, "{}", String::from_utf8_lossy(&msg));
    let sid = cookie(&fields, "sid");
    assert!(!sid.is_empty());
    let (status, _, page) = app.handle("GET", "/", &header(&[("cookie", &format!("sid={sid}"))]), b"");
    assert_eq!(status, 200);
    let page = String::from_utf8_lossy(&page);
    assert!(page.contains("Signed in as <strong>alice-1234</strong>"), "{page}");
    assert!(page.contains(crate::test_support::IDP_ENTITY), "{page}");
    let (status, fields, _) = app.handle("GET", "/wsfed?wa=wsignoutcleanup1.0", &header(&[("cookie", &format!("sid={sid}"))]), b"");
    assert_eq!(status, 200);
    let content_type = fields.iter().find(|(name, _)| name.eq_ignore_ascii_case("content-type")).map(|(_, value)| value.clone()).unwrap();
    assert_eq!(content_type, "image/gif");
    let (_, _, page) = app.handle("GET", "/", &header(&[("cookie", &format!("sid={sid}"))]), b"");
    let page = String::from_utf8_lossy(&page);
    assert!(page.contains("Sign in with WS-Federation"), "{page}");
    let (status, fields, _) = app.handle("POST", "/logout", &HashMap::new(), b"");
    assert_eq!(status, 303);
    let location = fields.iter().find(|(name, _)| name.eq_ignore_ascii_case("location")).map(|(_, value)| value.clone()).unwrap();
    let parsed = url::Url::parse(&location).unwrap();
    assert_eq!(first_map(parsed.query().unwrap_or("")).get("wa").map(String::as_str), Some("wsignout1.0"));
    let (status, _, _) = app.handle("POST", "/wsfed", &HashMap::new(), b"wa=wsignin1.0&wresult=x&wctx=id%3Dabc");
    assert_eq!(status, 400);
    let _ = json!(null);
}

#[test]
fn loopback_follows_port_and_public_url_keeps_the_path() {
    let (realm, reply) = endpoints_for("http://localhost:3000/", "http://localhost:3000/wsfed", "", false, 19141);
    assert_eq!(realm, "http://localhost:19141/");
    assert_eq!(reply, "http://localhost:19141/wsfed");
    let (realm, reply) = endpoints_for("https://idp.example/realm", "https://idp.example/wsfed", "", false, 19141);
    assert_eq!(realm, "https://idp.example/realm");
    assert_eq!(reply, "https://idp.example/wsfed");
    let (realm, reply) = endpoints_for("http://127.0.0.1:3000/app/", "http://127.0.0.1:3000/app/wsfed", "https://rp.example", true, 19141);
    assert_eq!(realm, "https://rp.example/app/");
    assert_eq!(reply, "https://rp.example/app/wsfed");
    let (realm, reply) = endpoints_for("http://[::1]:3000/", "http://[::1]:3000/wsfed", "", false, 19141);
    assert_eq!(realm, "http://[::1]:19141/");
    assert_eq!(reply, "http://[::1]:19141/wsfed");
}
