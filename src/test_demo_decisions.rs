// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The demo's two PEP-protected pages with real decisions (#40):
//! `GET /attribute-protected` and `/orders/42` through the demo's own
//! `App::handle`, after a real sign-in through its routes, decided by a
//! `local`-mode PEP holding the demo application's own policy.
//!
//! - **The policy** is `src/test_demo_policy.json`: the ALFA the install
//!   script imports (`configure_iya_sts.orders_policy()`), as iya-sts's own
//!   compiler writes it (`scripts/live_authzen.py --compile`). Read on an
//!   `order` needs an `acr`; read on `attribute-protected` needs the
//!   directory attribute `attr1` == `abc123`; anything else is denied.
//! - **The stub PDP** is `test_authzen.rs`'s: the catalogue row
//!   `subject.acr` → `urn:example:acr` (the install script's), the policy
//!   pull with the demo's application enforcing its own policy, and the PIP
//!   (`POST /xacml/pip`) answering `attr1` per person. The AuthZEN endpoint
//!   is never asked: a local decision is made in process.
//! - **The people**: `ada` holds `attr1=abc123`, `bo` holds `not-abc123`,
//!   `cy` holds no `attr1`. Each signs in with the stub IdP's signed
//!   assertion naming them (the `name` claim, iya-sts's username), with the
//!   AuthnContextClassRef, or without it for the no-acr sign-in.

use std::collections::HashMap;
use std::sync::atomic::Ordering;

use serde_json::{json, Value};

use crate::demo::App;
use crate::pep::{Access, NAME_CLAIM};
use crate::test_authzen::{key_file, start_pdp, wait_for, Pdp};
use crate::test_demo::{party, sign_in, text};
use crate::test_support::{self as stub, AssertionOptions, REALM};

const ATTR1: &str = "urn:sts:xacml:attribute:attr1";

fn demo_policy() -> Value {
    serde_json::from_str(include_str!("test_demo_policy.json")).expect("src/test_demo_policy.json is JSON")
}

/// The stub PDP holding the demo's catalogue row, its people and its policy,
/// the demo's application enforcing that policy as its own.
fn pdp() -> &'static Pdp {
    let stub_table = json!({
        "catalogue": [{"object": "subject", "property": "acr", "attributeId": "urn:example:acr"}],
        "directory": [
            {"username": "ada", "attributes": {ATTR1: "abc123"}},
            {"username": "bo", "attributes": {ATTR1: "not-abc123"}},
            {"username": "cy", "attributes": {}},
        ],
    });
    let pdp = start_pdp(&stub_table);
    let held = &demo_policy()["policy"];
    *pdp.policies.lock().unwrap() = ("demo-policy-1".into(), vec![json!({
        "name": "wsfeddemo-orders", "policyId": held["policyId"], "kind": held["kind"], "version": held["version"],
        "isRoot": true, "description": "", "document": held["document"],
    })]);
    *pdp.fga_applications.lock().unwrap() = vec![REALM.to_string()];
    pdp
}

/// The demo with a `local` PEP that holds the policy.
fn demo(tag: &str) -> (App, &'static Pdp) {
    let pdp = pdp();
    let rp = party(json!({"pep": {
        "name": "pep-wsfed-demo", "mode": "local", "assertionKey": key_file(&format!("demo-{tag}")), "pdpUrl": pdp.url,
        "pollIntervalMs": 1000, "heartbeatIntervalMs": 60000,
    }}));
    wait_for(&rp, "registered and held the demo's policy", |s| s.registered && s.holds_policy);
    (App::new(rp, None), pdp)
}

/// The stub IdP's signed assertion for `who` (their `name` claim), with the
/// AuthnContextClassRef iya-sts sends, or with no AuthnContext at all.
fn token_for(who: &str, acr: bool) -> String {
    let made = stub::assertion_xml(&AssertionOptions {
        name_id: format!("urn:uuid:{who}"),
        extra_attributes: format!("<saml:Attribute Name=\"{NAME_CLAIM}\"><saml:AttributeValue>{who}</saml:AttributeValue></saml:Attribute>"),
        ..AssertionOptions::default()
    });
    let xml = if acr {
        made.xml
    } else {
        let start = made.xml.find("<saml:AuthnContext>").unwrap();
        let end = made.xml.find("</saml:AuthnContext>").unwrap() + "</saml:AuthnContext>".len();
        format!("{}{}", &made.xml[..start], &made.xml[end..])
    };
    stub::sign_xml(&xml, &made.id, "", "").unwrap()
}

/// Signs `who` in through the demo's routes; answers the cookie header.
fn signed_in(app: &App, who: &str, acr: bool) -> HashMap<String, String> {
    sign_in(app, Some(token_for(who, acr))).0
}

/// What the demo answered, and the status `Decision::http_status()` gives
/// the same session's decision asked directly.
fn visit(app: &App, cookie: &HashMap<String, String>, method: &str, path: &str, access: Access) -> (u16, String, u16) {
    let (status, fields, body) = app.handle(method, path, cookie, b"");
    assert!(fields.iter().any(|(k, v)| k == "content-type" && v.starts_with("text/html")), "{path} is a page");
    let sid = cookie["cookie"].trim_start_matches("sid=").rsplit_once('.').unwrap().0.to_string();
    let login = app.sessions_handle().lock().unwrap().get(&sid).cloned().expect("the session");
    let direct = app.rp.decide(&login, &access).http_status();
    (status, text(body), direct)
}

fn attribute_protected(app: &App, cookie: &HashMap<String, String>) -> (u16, String, u16) {
    visit(app, cookie, "GET", "/attribute-protected", Access::new("read", "attribute-protected", "attr1"))
}

fn order_42(app: &App, cookie: &HashMap<String, String>, method: &str) -> (u16, String, u16) {
    let action = if method == "GET" { "read" } else { "write" };
    visit(app, cookie, method, "/orders/42", Access::new(action, "order", "42"))
}

#[test]
fn the_stub_serves_the_policy_the_install_script_imports() {
    let held = demo_policy();
    assert_eq!(held["policy"]["policyId"], "urn:example:wsfeddemo-orders", "the install script's own PolicyId");
    let document = held["policy"]["document"].as_str().unwrap();
    for rule in ["RuleId=\"readOrder\" Effect=\"Permit\"", "RuleId=\"readAttributeProtected\" Effect=\"Permit\"", "RuleId=\"otherwise\" Effect=\"Deny\""] {
        assert!(document.contains(rule), "{rule}");
    }
    assert!(document.contains(&format!("AttributeId=\"{ATTR1}\"")) && document.contains(">abc123<") && document.contains("AttributeId=\"urn:example:acr\""));
    // The ALFA it was compiled from is the install script's today: a change
    // there without `scripts/live_authzen.py --compile` fails here.
    let code = "import sys; sys.path.insert(0, sys.argv[1]); import configure_iya_sts as c; sys.stdout.write(c.orders_policy())";
    let output = std::process::Command::new("python3").arg("-c").arg(code).arg(format!("{}/scripts", env!("CARGO_MANIFEST_DIR"))).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let alfa: Vec<String> = held["alfa"].as_array().unwrap().iter().map(|line| line.as_str().unwrap().to_string()).collect();
    assert_eq!(alfa.join("\n") + "\n", String::from_utf8(output.stdout).unwrap(), "src/test_demo_policy.json is stale: run scripts/live_authzen.py --compile");
}

#[test]
fn the_allowed_user_gets_both_protected_pages() {
    let (app, pdp) = demo("allowed");
    let cookie = signed_in(&app, "ada", true);
    let (status, page, direct) = attribute_protected(&app, &cookie);
    assert_eq!((status, direct), (200, 200), "attr1=abc123 from the PIP: {page}");
    assert!(page.contains("<title>Attribute-protected</title>") && page.contains("<h1>Allowed</h1>"), "{page}");
    assert!(page.contains("The PEP permitted it: your <code>attr1</code> is <code>abc123</code>."), "{page}");
    assert!(page.contains("title=\"ada\">ada</span>") && page.contains("href=\"/orders/42\">Order 42</a>"), "the menu names them, the top bar links the order");
    let (status, page, direct) = order_42(&app, &cookie, "GET");
    assert_eq!((status, direct), (200, 200), "read with an acr: {page}");
    assert!(page.contains("<title>Order</title>") && page.contains("<h1>Order 42</h1><p>The PEP permitted <code>read</code>.</p>"), "{page}");
    let status = app.rp.pep().unwrap().status();
    assert!(status.decisions >= 4, "every page was decided by the PEP: {}", status.decisions);
    assert_eq!(pdp.evaluations.load(Ordering::SeqCst), 0, "local: never the AuthZEN endpoint");
    app.rp.pep().unwrap().stop();
}

#[test]
fn a_denied_user_is_refused_the_attribute_protected_page() {
    let (app, pdp) = demo("denied");
    for (who, holds) in [("bo", "attr1=not-abc123"), ("cy", "no attr1 at all")] {
        let cookie = signed_in(&app, who, true);
        let (status, page, direct) = attribute_protected(&app, &cookie);
        assert_eq!((status, direct), (403, 403), "{who} ({holds}): {page}");
        assert!(page.contains("<title>Forbidden</title>") && page.contains("<h1>Not allowed</h1><p class=\"problem\">The PEP denied it:"), "{who}: a Deny, not a failure: {page}");
        assert!(!page.contains("could not decide"), "{who}: decided: {page}");
        assert!(page.contains(&format!("title=\"{who}\">{who}</span>")) && page.contains("attr1"), "{who}: with the menu, and says what the policy asks");
        // The same person may read an order: their sign-in carried an acr.
        let (status, page, direct) = order_42(&app, &cookie, "GET");
        assert_eq!((status, direct), (200, 200), "{who} reads order 42: {page}");
    }
    assert_eq!(pdp.evaluations.load(Ordering::SeqCst), 0);
    app.rp.pep().unwrap().stop();
}

#[test]
fn writing_an_order_is_refused_even_to_the_allowed_user() {
    let (app, _) = demo("write");
    let cookie = signed_in(&app, "ada", true);
    let (status, page, direct) = order_42(&app, &cookie, "POST");
    assert_eq!((status, direct), (403, 403), "write falls to the policy's otherwise: {page}");
    assert!(page.contains("<title>Forbidden</title>") && page.contains("<h1>Not allowed</h1><p>The PEP denied <code>write</code> on order 42:"), "{page}");
    assert_eq!(order_42(&app, &cookie, "GET").0, 200, "while read is permitted");
    app.rp.pep().unwrap().stop();
}

#[test]
fn a_sign_in_without_an_acr_is_refused_the_order() {
    let (app, _) = demo("noacr");
    let cookie = signed_in(&app, "ada", false);
    let sid = cookie["cookie"].trim_start_matches("sid=").rsplit_once('.').unwrap().0.to_string();
    assert_eq!(app.sessions_handle().lock().unwrap()[&sid].authn_context_class_ref, None, "the sign-in carried no AuthnContextClassRef");
    let (status, page, direct) = order_42(&app, &cookie, "GET");
    assert_eq!((status, direct), (403, 403), "read on an order needs an acr: {page}");
    assert!(page.contains("<h1>Not allowed</h1><p>The PEP denied <code>read</code> on order 42:"), "{page}");
    // attr1 is the directory's, not the token's: the page it guards is still hers.
    let (status, page, _) = attribute_protected(&app, &cookie);
    assert_eq!(status, 200, "{page}");
    // And a sign-in with one reads the order.
    let cookie = signed_in(&app, "ada", true);
    assert_eq!(order_42(&app, &cookie, "GET").0, 200);
    app.rp.pep().unwrap().stop();
}

#[test]
fn signed_out_is_401_before_the_pep_is_asked() {
    let (app, _) = demo("signedout");
    let before = app.rp.pep().unwrap().status().decisions;
    for (method, path) in [("GET", "/attribute-protected"), ("GET", "/orders/42"), ("POST", "/orders/42")] {
        let (status, _, body) = app.handle(method, path, &HashMap::new(), b"");
        assert_eq!(status, 401, "{method} {path}: {}", text(body));
    }
    assert_eq!(app.rp.pep().unwrap().status().decisions, before, "no decision without a sign-in");
    app.rp.pep().unwrap().stop();
}
