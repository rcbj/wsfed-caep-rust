// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The demo's pages (#40, after oidc-caep-risc-rust's demo): the Session
//! tab's panes drawn from a real sign-in (facts and fingerprints, never the
//! token), the CAEP & RISC events tab and its API, the user menu and the
//! name it shows, the top bar's links, every block a collapsible pane, the
//! page scripts each in its own scope, and the two pages the PEP decides.

use std::collections::HashMap;
use std::path::Path;

use serde_json::{json, Value};

use crate::demo::{display_name, event_json, events_panel, family_of, fingerprint, in_words, page_for, pep_fragment, session_panes, site_nav, token_facts, user_menu, utc, App, LiveEvent};
use crate::relying_party::{first_map, RelyingParty};
use crate::ssf::{events, SignalEvent};
use crate::test_ssf::login_of;
use crate::test_support::{self as stub, AssertionOptions, MetaOptions, WResultOptions, IDP_ENTITY, REALM, REPLY};

fn party(extra: Value) -> RelyingParty {
    let mut config = json!({
        "realm": REALM, "replyUrl": REPLY, "signals": false,
        "privateKey": stub::rp_key(), "certificate": stub::rp_cert(),
        "idpMetadata": stub::idp_metadata(&MetaOptions::default()),
    });
    for (k, v) in extra.as_object().unwrap() {
        config[k] = v.clone();
    }
    RelyingParty::create(config.as_object().unwrap(), Path::new(".")).unwrap()
}

fn text(body: Vec<u8>) -> String {
    String::from_utf8(body).unwrap()
}

fn set_cookie(fields: &[(String, String)], name: &str) -> String {
    fields.iter().filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie")).filter_map(|(_, v)| v.split(';').next()?.split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| v.to_string()).unwrap_or_default()
}

fn header(name: &str, value: &str) -> HashMap<String, String> {
    HashMap::from([(name.to_string(), value.to_string())])
}

/// Signs in through the demo's own routes with `token` (the stub's signed
/// assertion when `None`), and answers the session's cookie header and the
/// wresult it posted.
fn sign_in(app: &App, token: Option<String>) -> (HashMap<String, String>, String) {
    let (_, fields, _) = app.handle("GET", "/login", &HashMap::new(), b"");
    let location = fields.iter().find(|(k, _)| k == "location").map(|(_, v)| v.clone()).unwrap();
    let params = first_map(url::Url::parse(&location).unwrap().query().unwrap_or(""));
    let pending = set_cookie(&fields, "wsfed_pending");
    let token = token.unwrap_or_else(|| stub::signed_assertion(&AssertionOptions::default()).unwrap().xml);
    let wresult = stub::wresult(&WResultOptions { token: Some(token), ..WResultOptions::default() }).unwrap();
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("wa", "wsignin1.0")
        .append_pair("wresult", &wresult)
        .append_pair("wctx", params.get("wctx").map(String::as_str).unwrap_or(""))
        .finish();
    let (status, fields, body) = app.handle("POST", "/wsfed", &header("cookie", &format!("wsfed_pending={pending}")), form.as_bytes());
    assert_eq!(status, 303, "{}", String::from_utf8_lossy(&body));
    (header("cookie", &format!("sid={}", set_cookie(&fields, "sid"))), wresult)
}

#[test]
fn the_session_tab_shows_what_was_verified_and_never_the_token() {
    let app = App::new(party(json!({})), None);
    let (cookie, wresult) = sign_in(&app, None);
    let (status, fields, page) = app.handle("GET", "/", &cookie, b"");
    let page = text(page);
    assert_eq!(status, 200);
    for id in ["security-card", "session-card", "cache-card", "credentials-card"] {
        assert!(page.contains(&format!("<details class=\"card pane\" id=\"{id}\" open>")), "{id} is a collapsible pane: {page}");
    }
    assert!(page.contains("Signed security token") && page.contains("1 signing certificate(s)"), "{page}");
    assert!(page.contains("Recipient is this reply URL") && page.contains("each assertion id is accepted once"));
    assert!(page.contains("wctx&#x27;s id") || page.contains("wctx's id"), "a solicited response: {page}");
    assert!(page.contains("HMAC-signed, HttpOnly, SameSite=Lax; Secure"), "https reply URL: a Secure cookie");
    assert!(page.contains(IDP_ENTITY) && page.contains("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"));
    assert!(page.contains("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress (mail)") && page.contains("staff, admins"), "claims with their FriendlyName, values joined");
    assert!(page.contains("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"), "the signature method, read from the token: {page}");
    assert!(page.contains("one the identity provider&#x27;s metadata names") || page.contains("one the identity provider's metadata names"), "the signing certificate is the metadata's");
    assert!(page.contains("WS-Federation issues no refresh token"));
    assert!(page.contains(&fingerprint(wresult.as_bytes())), "the response by its fingerprint");
    // Nothing of the token's value: no XML, no signature or certificate bytes.
    assert!(!page.contains("<saml:") && !page.contains("SignatureValue") && !page.contains("&lt;saml"), "no assertion on the page");
    let cert_b64 = stub::idp_cert().lines().filter(|l| !l.starts_with("-----")).collect::<String>();
    assert!(!page.contains(&cert_b64[..40]), "a certificate by fingerprint, never its bytes");
    assert!(!page.contains("action=\"/logout\"><button>Sign out"), "sign-out lives in the menu only");
    assert_eq!(page.matches("action=\"/logout\"").count(), 1, "one sign-out, in the menu");
    assert!(page.contains("id=\"panes-toggle\" hidden>Collapse all") && page.contains("/panes.js") && page.contains("/app.js"));
    let csp = fields.iter().find(|(k, _)| k == "content-security-policy").map(|(_, v)| v.clone()).unwrap_or_default();
    assert!(csp.contains("connect-src 'self'") && !csp.contains("unsafe-inline"), "{csp}");
}

#[test]
fn an_encrypted_token_says_how_it_was_encrypted() {
    let rp = party(json!({}));
    let made = stub::signed_assertion(&AssertionOptions::default()).unwrap();
    let token = stub::encrypt(&made.xml, "aes-256-gcm", "oaep256", "").unwrap();
    let wresult = stub::wresult(&WResultOptions { token: Some(token.clone()), ..WResultOptions::default() }).unwrap();
    let facts = token_facts(&wresult, &rp);
    let row = |name: &str| facts.rows.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone()).unwrap_or_default();
    assert_eq!(row("Content encryption"), "http://www.w3.org/2009/xmlenc11#aes256-gcm");
    assert_eq!(row("Key transport"), "http://www.w3.org/2009/xmlenc11#rsa-oaep");
    assert!(row("Signature").contains("inside the encryption"));
    assert_eq!(row("TokenType"), "urn:oasis:names:tc:SAML:2.0:assertion");
    assert_eq!(row("AppliesTo"), REALM);
    let app = App::new(rp, None);
    let (cookie, _) = sign_in(&app, Some(token));
    let page = text(app.handle("GET", "/", &cookie, b"").2);
    assert!(page.contains("on: the assertion arrived encrypted"), "{page}");
}

#[test]
fn the_name_shown_is_the_username_claim_and_the_name_id_only_without_one() {
    let mut login = login_of("urn:opaque:7", "IDP-1");
    assert_eq!(display_name(&login), "urn:opaque:7", "no claim names them: the NameID");
    login.attributes.insert("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name".into(), vec!["alice".into()]);
    assert_eq!(display_name(&login), "alice", "iya-sts's name claim (its directory uid)");
    login.attributes.insert("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn".into(), vec!["alice@corp".into()]);
    assert_eq!(display_name(&login), "alice@corp", "upn before name");
    login.attributes.insert("urn:example:username".into(), vec!["ali".into()]);
    assert_eq!(display_name(&login), "ali", "a username claim first");
    let mut friendly = login_of("x", "IDP-2");
    friendly.attributes.insert("urn:oid:0.9.2342.19200300.100.1.99".into(), vec!["bob".into()]);
    friendly.attribute_friendly_names.insert("urn:oid:0.9.2342.19200300.100.1.99".into(), "preferred_username".into());
    assert_eq!(display_name(&friendly), "bob", "by FriendlyName too");
}

#[test]
fn the_user_menu_names_the_account_and_holds_sign_out() {
    let mut login = login_of("<Alice>", "IDP-1");
    login.attributes.insert("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname".into(), vec!["Alice".into()]);
    login.attributes.insert("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname".into(), vec!["Admin".into()]);
    let menu = user_menu(&login);
    assert!(menu.contains("<span class=\"avatar\" aria-hidden=\"true\">A</span>"), "{menu}");
    assert!(menu.contains("title=\"&lt;Alice&gt;\">&lt;Alice&gt;</span>") && !menu.contains("<Alice>"), "escaped");
    assert!(menu.contains("Alice Admin"), "given and family names are the detail line");
    assert!(menu.contains("href=\"/login?prompt=login\""), "another account always asks");
    assert!(menu.contains("<form method=\"post\" action=\"/logout\"><button class=\"menu-row\" type=\"submit\" role=\"menuitem\">Sign out &lt;Alice&gt;</button>"));
    let page = page_for("x", "<p>b</p>", Some(&login));
    assert!(page.contains("acct-menu") && page.contains("/menu.js") && page.contains("class=\"site-nav\""));
    assert!(!page_for("x", "", None).contains("acct-menu") && !page_for("x", "", None).contains("site-nav"), "nothing before a sign-in");
    let nav = site_nav();
    assert!(nav.contains("href=\"/\">Demo home</a>"));
    #[cfg(feature = "pep")]
    assert!(nav.contains("href=\"/attribute-protected\">Attribute-protected</a>") && nav.contains("href=\"/orders/42\">Order 42</a>"), "{nav}");
}

#[test]
fn another_account_asks_the_identity_provider_again() {
    let app = App::new(party(json!({})), None);
    let wfresh = |target: &str| {
        let (_, fields, _) = app.handle("GET", target, &HashMap::new(), b"");
        let location = fields.iter().find(|(k, _)| k == "location").map(|(_, v)| v.clone()).unwrap();
        first_map(url::Url::parse(&location).unwrap().query().unwrap_or("")).get("wfresh").cloned()
    };
    assert_eq!(wfresh("/login?prompt=login"), Some("0".to_string()));
    assert_eq!(wfresh("/login"), None, "the ordinary sign-in reuses the identity provider's session");
}

fn live(id: u64, event_type: &str, ended: bool) -> LiveEvent {
    LiveEvent {
        id,
        event_type: event_type.into(),
        jti: format!("j<{id}>"),
        family: family_of(event_type).into(),
        at: utc(1_795_000_000),
        subject: "format email, email <a@x>".into(),
        members: json!({"reason_admin": {"en": "<b>gone</b>"}, "subject": {"x": 1}}),
        ended,
    }
}

#[test]
fn the_events_tab_draws_each_event_newest_first_and_escapes() {
    let caep = events::event("session_revoked");
    let risc = "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
    let html = events_panel(&[live(1, caep, true), live(2, risc, false)], "polling <s>", "");
    assert!(html.find("data-id=\"2\"").unwrap() < html.find("data-id=\"1\"").unwrap(), "newest first");
    assert!(html.contains("<span class=\"badge caep\">CAEP</span> <strong>session-revoked</strong>"), "{html}");
    assert!(html.contains("<span class=\"badge risc\">RISC</span>"));
    assert!(html.contains("ended this session") && html.contains("recorded; this session continues"));
    assert!(html.contains("&lt;b&gt;gone&lt;/b&gt;") && !html.contains("<b>gone"), "members escaped");
    assert!(html.contains("polling &lt;s&gt;") && html.contains("j&lt;1&gt;"));
    assert!(!html.contains(">subject<"), "the subject member is the Subject line, not a row");
    assert!(html.contains("id=\"log-empty\" hidden"));
    assert!(events_panel(&[], "", "").contains("id=\"log-empty\">"));
    assert!(html.contains("class=\"warning\"><strong>Every event this application received, for every user.</strong>") && html.contains("additional safeguards"));
    for id in ["events-scope", "events-stream", "events-log"] {
        assert!(html.contains(&format!("<details class=\"card pane\" id=\"{id}\" open>")), "{id}");
    }
    assert!(html.contains("id=\"live-state\"") && html.contains("id=\"verify-form\"") && html.contains("id=\"stream-status\""), "app.js finds what it updates");
    let e = event_json(&live(7, "https://schemas.openid.net/secevent/ssf/event-type/verification", false));
    assert_eq!((e["id"].clone(), e["family"].clone(), e["about"].clone()), (json!(7), json!("SSF"), json!("stream")));
    assert_eq!(family_of("urn:iya:sts:secevent:event-type:pep-policies-changed"), "STS");
    assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
    assert_eq!(utc(1_795_000_000), "2026-11-18 11:06:40 UTC");
    assert_eq!(in_words(90), "1m 30s");
    assert_eq!(in_words(-3700), "1h 1m ago");
}

#[test]
fn the_signals_api_and_verify_need_a_sign_in() {
    let app = App::new(party(json!({})), None);
    let (status, _, _) = app.handle("GET", "/api/signals", &HashMap::new(), b"");
    assert_eq!(status, 401);
    let (status, fields, _) = app.handle("POST", "/signals/verify", &HashMap::new(), b"");
    assert_eq!((status, fields.iter().find(|(k, _)| k == "location").map(|(_, v)| v.as_str())), (303, Some("/")));
    let (cookie, _) = sign_in(&app, None);
    let event = |kind: &str, jti: &str| SignalEvent { event_type: kind.into(), payload: json!({"credential_type": "password"}), subject: HashMap::from([("format".to_string(), "email".to_string())]), jti: jti.into(), sessions: vec!["x".into()], ended: false, iat: Some(1_795_000_000.0), txn: None };
    app.remember(&event(events::event("credential_change"), "j-1"));
    app.remember(&event(events::event("session_revoked"), "j-2"));
    let (status, _, body) = app.handle("GET", "/api/signals?after=1", &cookie, b"");
    assert_eq!(status, 200);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["events"].as_array().unwrap().len(), 1, "only what came after 1: {v}");
    assert_eq!(v["events"][0]["jti"], "j-2");
    assert_eq!(v["events"][0]["at"], "2026-11-18 11:06:40 UTC");
    assert_eq!(v["streamStatus"]["status"], "not configured");
    let page = text(app.handle("GET", "/?tab=events", &cookie, b"").2);
    assert!(page.contains("data-tab=\"events\" data-last-id=\"2\"") && page.contains("id=\"signal-count\">2</span>"), "{page}");
    // No receiver running: the request is refused, and the page says so.
    let (status, _, body) = app.handle("POST", "/signals/verify", &{ let mut h = cookie.clone(); h.insert("accept".into(), "application/json".into()); h }, b"");
    assert_eq!((status, serde_json::from_slice::<Value>(&body).unwrap()["outcome"].clone()), (200, json!("refused")));
    let (status, fields, _) = app.handle("POST", "/signals/verify", &cookie, b"");
    assert_eq!((status, fields.iter().find(|(k, _)| k == "location").map(|(_, v)| v.as_str())), (303, Some("/?tab=events&verify=refused")));
    assert!(text(app.handle("GET", "/?tab=events&verify=refused", &cookie, b"").2).contains("The transmitter refused the verification request."));
    let (status, _, _) = app.handle("GET", "/events", &cookie, b"");
    assert_eq!(status, 204, "app.js falls back to polling");
    let live: Value = serde_json::from_slice(&app.handle("GET", "/live-status", &cookie, b"").2).unwrap();
    assert_eq!(live["events"], json!([{"type": events::event("credential_change"), "jti": "j-1"}, {"type": events::event("session_revoked"), "jti": "j-2"}]));
}

#[test]
fn the_panes_toggle_ships_hidden_and_every_script_keeps_its_names_to_itself() {
    let app = App::new(party(json!({})), None);
    let scripts = [("app.js", include_str!("../demo/public/app.js")), ("pep.js", include_str!("../demo/public/pep.js")), ("panes.js", include_str!("../demo/public/panes.js")), ("menu.js", include_str!("../demo/public/menu.js"))];
    for (name, src) in scripts {
        // The page's scripts share one global scope: two top-level `const
        // panel` would make the later one fail to load. Each is its own function.
        let code: Vec<&str> = src.lines().filter(|l| !l.trim_start().starts_with("//") && !l.trim().is_empty()).collect();
        assert_eq!(code.first().copied(), Some("(() => {"), "{name} opens its own scope");
        assert_eq!(code.last().copied(), Some("})();"), "{name} closes it");
        let (status, fields, body) = app.handle("GET", &format!("/{name}"), &HashMap::new(), b"");
        assert_eq!(status, 200, "{name} is served");
        assert!(fields.iter().any(|(k, v)| k == "content-type" && v.starts_with("text/javascript")));
        assert_eq!(text(body), src);
    }
    assert!(scripts[2].1.contains("panes-toggle") && scripts[2].1.contains("Expand all") && scripts[2].1.contains("panes-redrawn"));
    assert!(scripts[1].1.contains("panes-redrawn"), "pep.js tells the toggle when it redrew");
    assert!(include_str!("../demo/public/styles.css").contains("[hidden] { display: none !important; }"), "hidden hides a button too");
    assert!(pep_fragment(&party(json!({}))).contains("<details class=\"card pane\" id=\"pep-none\" open>"), "the no-PEP notice is a pane too");
}

#[test]
fn session_panes_say_when_the_receiver_tracks_the_session() {
    let rp = party(json!({}));
    let mut login = login_of("alice", "IDP-1");
    login.request_id = None;
    let tracked = session_panes(&rp, &login, None, "polling stream s1", Some(true), 3);
    assert!(tracked.contains("this session is tracked: an ending CAEP or RISC event ends it") && tracked.contains("3 sign-in(s)"));
    assert!(tracked.contains("unsolicited: accepted because allowUnsolicited is on"));
    assert!(tracked.contains("not noted"), "no facts: says so");
    assert!(session_panes(&rp, &login, None, "", None, 1).contains("no receiver is running"));
}

/// The two pages the PEP decides: 401 without a sign-in, and with no `pep`
/// section a refusal (403) that says no decision was made.
#[cfg(feature = "pep")]
#[test]
fn the_protected_pages_need_a_sign_in_and_fail_closed() {
    let app = App::new(party(json!({})), None);
    for path in ["/attribute-protected", "/orders/42"] {
        let (status, _, _) = app.handle("GET", path, &HashMap::new(), b"");
        assert_eq!(status, 401, "{path}");
    }
    let (cookie, _) = sign_in(&app, None);
    let (status, _, body) = app.handle("GET", "/attribute-protected", &cookie, b"");
    let page = text(body);
    assert_eq!(status, 403, "{page}");
    assert!(page.contains("<title>Forbidden</title>") && page.contains("The PEP could not decide: no pep section is configured"), "{page}");
    assert!(page.contains("attr1") && page.contains("acct-menu"), "says what the policy asks, with the menu");
    let tab = text(app.handle("GET", "/?tab=pep", &cookie, b"").2);
    assert!(tab.contains("No embedded PEP"));
}
