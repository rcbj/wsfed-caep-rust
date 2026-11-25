// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The demo's Policy enforcement tab (#40): the tab bar beside Session, the
//! four collapsible panes drawn from the PEP's `Status` with stable ids, the
//! escaping, the no-PEP notice, the durations, and `/pep-status(.html)`
//! refused without a sign-in, and any PEP failure on `/orders/<id>` a 403.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::demo::{human, pep_fragment, pep_json, query_param, App};
use crate::relying_party::RelyingParty;
use crate::test_ssf::login_of;
use crate::test_support::{self as stub, MetaOptions, REALM, REPLY};

fn party(extra: Value) -> RelyingParty {
    let mut config: Map<String, Value> = json!({
        "realm": REALM, "replyUrl": REPLY, "signals": false,
        "privateKey": stub::rp_key(), "certificate": stub::rp_cert(),
        "idpMetadata": stub::idp_metadata(&MetaOptions::default()),
    })
    .as_object()
    .unwrap()
    .clone();
    for (k, v) in extra.as_object().unwrap() {
        config.insert(k.clone(), v.clone());
    }
    RelyingParty::create(&config, Path::new(".")).unwrap()
}

/// The app with one signed-in session, and that session's cookie header.
fn signed_in(rp: RelyingParty) -> (App, HashMap<String, String>) {
    let app = App::new(rp, None);
    app.sessions_handle().lock().unwrap().insert("s-1".into(), login_of("alice<b>", "IDP-1"));
    let cookie = HashMap::from([("cookie".to_string(), format!("sid={}", app.sign("s-1")))]);
    (app, cookie)
}

fn text(body: Vec<u8>) -> String {
    String::from_utf8(body).unwrap()
}

#[test]
fn query_param_reads_one_parameter() {
    assert_eq!(query_param("/?tab=pep&x=1", "tab"), "pep");
    assert_eq!(query_param("/", "tab"), "");
    assert_eq!(query_param("/?x=a%20b", "x"), "a b");
}

#[test]
fn durations_read_as_a_person_reads_them() {
    assert_eq!(human(None, true), "—");
    assert_eq!(human(Some(Duration::from_millis(400)), true), "just now");
    assert_eq!(human(Some(Duration::from_millis(400)), false), "now");
    assert_eq!(human(Some(Duration::from_secs(42)), true), "42 s ago");
    assert_eq!(human(Some(Duration::from_secs(300)), false), "in 5 min 0 s");
    assert_eq!(human(Some(Duration::from_secs(7300)), true), "2 h 1 min ago");
}

#[test]
fn the_status_needs_a_sign_in_and_the_page_has_two_tabs() {
    let (app, cookie) = signed_in(party(json!({})));
    for path in ["/pep-status", "/pep-status.html"] {
        let (status, _, _) = app.handle("GET", path, &HashMap::new(), b"");
        assert_eq!(status, 401, "{path} without a sign-in");
        let (status, _, _) = app.handle("GET", path, &HashMap::from([("cookie".to_string(), "sid=forged.x".to_string())]), b"");
        assert_eq!(status, 401, "{path} with a cookie that isn't signed");
        let (status, _, _) = app.handle("GET", path, &cookie, b"");
        assert_eq!(status, 200, "{path} signed in");
    }
    let (status, fields, page) = app.handle("GET", "/", &cookie, b"");
    let page = text(page);
    assert_eq!(status, 200);
    assert!(page.contains("href=\"/\" aria-selected=\"true\" aria-current=\"page\">Session</a>"), "{page}");
    assert!(page.contains("href=\"/?tab=pep\" aria-selected=\"false\">Policy enforcement</a>"));
    assert!(page.contains("Signed in as <strong>alice&lt;b&gt;</strong>"), "the Session tab is unchanged, and escaped");
    let csp = fields.iter().find(|(k, _)| k == "content-security-policy").map(|(_, v)| v.clone()).unwrap_or_default();
    assert!(csp.contains("connect-src 'self'") && csp.contains("script-src 'self'"), "pep.js may fetch: {csp}");
    let (_, _, tab) = app.handle("GET", "/?tab=pep", &cookie, b"");
    let tab = text(tab);
    assert!(tab.contains("<div id=\"pep-panel\">") && tab.contains("<script src=\"/pep.js\" defer></script>"));
    assert!(tab.contains("No embedded PEP"), "no pep section, and the tab says so");
    let (status, fields, js) = app.handle("GET", "/pep.js", &HashMap::new(), b"");
    assert_eq!(status, 200);
    assert!(fields.iter().any(|(k, v)| k == "content-type" && v.starts_with("text/javascript")));
    assert!(text(js).contains("/pep-status.html"));
}

#[test]
fn no_pep_section_says_so() {
    let rp = party(json!({}));
    assert!(pep_fragment(&rp).contains("<p class=\"notice\">No embedded PEP"));
    assert_eq!(pep_json(&rp)["enabled"], false);
}

#[cfg(feature = "pep")]
#[test]
fn the_tab_draws_every_pane_counts_and_escapes() {
    let key = std::env::temp_dir().join(format!("wsfed-demo-tab-{}.pem", std::process::id()));
    std::fs::write(&key, stub::idp_key()).unwrap();
    // iya-sts is not there, so the decision is Unavailable and the PEP has a
    // problem to show; the application names markup the page must escape.
    let rp = party(json!({"pep": {
        "name": "pep-demo", "mode": "central", "assertionKey": key.to_string_lossy(),
        "pdpUrl": "http://127.0.0.1:9", "application": "urn:app:<script>", "timeoutMs": 300, "heartbeatIntervalMs": 60000,
    }}));
    let decision = rp.decide(&login_of("alice", "IDP-1"), &crate::pep::Access::new("read", "order", "1"));
    assert!(matches!(decision, crate::pep::Decision::Unavailable { .. }));
    let html = pep_fragment(&rp);
    for (id, title) in [("pep-decisions", "Decisions"), ("pep-cached-policy", "Cached policy"), ("pep-the-pep", "The PEP"), ("pep-control-plane", "Control plane")] {
        assert!(html.contains(&format!("<details class=\"card pane\" id=\"{id}\" open><summary><h2>{title}</h2></summary>")), "{title}: collapsible, open, with the id pep.js keeps it closed by");
    }
    assert!(html.contains("<th>Decisions</th><td>1</td>"), "the decision was counted");
    assert!(html.contains("<th>Unavailable (no decision; refused)</th><td>1</td>"));
    assert!(html.contains("<th>Allowed</th><td>0</td>"));
    assert!(html.contains("Permit cache"), "central mode shows the cache");
    assert!(html.contains("class=\"problem\""), "iya-sts is unreachable, and the page says so");
    assert!(html.contains("urn:app:&lt;script&gt;") && !html.contains("<script"), "escaped, and no script in the fragment");
    assert!(!html.contains("No embedded PEP"));
    let v = pep_json(&rp);
    assert_eq!((v["enabled"].clone(), v["mode"].clone(), v["decisions"]["unavailable"].clone()), (json!(true), json!("central"), json!(1)));
    rp.pep().unwrap().stop();
    let _ = std::fs::remove_file(&key);
}

#[cfg(feature = "pep")]
#[test]
fn a_pep_failure_on_the_protected_route_is_a_403() {
    // Without a pep section the PEP cannot decide (Unavailable): that is a
    // refusal like a Deny, 403, and the page says it was no decision.
    let (app, cookie) = signed_in(party(json!({})));
    let (status, _, body) = app.handle("GET", "/orders/42", &cookie, b"");
    let page = text(body);
    assert_eq!(status, 403, "{page}");
    assert!(page.contains("<title>Forbidden</title>"), "{page}");
    assert!(page.contains("<h1>No decision</h1><p>The PEP could not decide: no pep section is configured</p>"), "{page}");
}
