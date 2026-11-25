// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! This library's AuthZEN table for the embedded Remote PEP (#40), run
//! through its own API: a `Login` as `handle_reply` returns it, an `Access`,
//! and `RelyingParty::decide` or `decide_session`.
//!
//! - **The table** is `src/test_authzen.json`: the catalogue rows, the
//!   policies in ALFA, the directory people the policy reads through
//!   iya-sts's PIP, and the cases with the answer the host must see (Permit
//!   with the obligation types handed, Deny, or Unavailable). The XACML the
//!   offline run serves is `src/test_authzen_policies.json`, made from that
//!   ALFA by iya-sts's own compiler (`scripts/live_authzen.py --compile`).
//! - **Offline** (`cargo test`): every phase's cases through a `local`-mode
//!   party against a stub PDP that serves the table's catalogue and
//!   policies, answers the PIP from the table's directory, and refuses the
//!   AuthZEN endpoint (a local decision never asks it).
//! - **Live** (`authzen_live`, run by `scripts/live_authzen.py`): one party
//!   with a `central` PEP and one with a `local` PEP against a real iya-sts.
//!   Every case must get the same answer from both, and the table's. It does
//!   nothing unless `WSFED_AUTHZEN_LIVE` names the script's description of
//!   the iya-sts it provisioned.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};

use crate::pep::{Access, Decision, AUTHENTICATION_METHOD_CLAIM};
use crate::relying_party::RelyingParty;
use crate::ssf::{ReceiverOptions, SignalsReceiver};
use crate::test_support::{self as stub, MetaOptions, REALM, REPLY};
use crate::token::Login;

const ACCESS_SUBJECT: &str = "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject";
const XS_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
/// The entry DN the stub's registration answer names, as iya-sts names a
/// PEP's service account.
const STUB_PEP_DN: &str = "uid=pep-wsfed-authzen,ou=users,dc=example,dc=com";

fn table() -> Value {
    serde_json::from_str(include_str!("test_authzen.json")).expect("src/test_authzen.json is JSON")
}

fn compiled() -> Value {
    serde_json::from_str(include_str!("test_authzen_policies.json")).expect("src/test_authzen_policies.json is JSON")
}

fn cases<'a>(table: &'a Value, phase: &str) -> Vec<&'a Value> {
    table["cases"].as_array().unwrap().iter().filter(|case| case["phase"] == phase).collect()
}

// ---------------------------------------------------------------------------
// A case's sign-in and access.
// ---------------------------------------------------------------------------

/// `spec[key]` when the case names it (null included), else the base's.
fn pick<'a>(spec: &'a Value, base: &'a Value, key: &str) -> &'a Value {
    match spec.get(key) {
        Some(value) => value,
        None => base.get(key).unwrap_or(&Value::Null),
    }
}

/// The base's map with the case's members laid over it; a null removes one.
fn overlay(base: &Value, over: &Value) -> Map<String, Value> {
    let mut out = base.as_object().cloned().unwrap_or_default();
    for (key, value) in over.as_object().into_iter().flatten() {
        if value.is_null() {
            out.remove(key);
        } else {
            out.insert(key.clone(), value.clone());
        }
    }
    out
}

fn strings(value: &Value) -> Vec<String> {
    value.as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect()
}

/// The `Login` a case signs in with: what `handle_reply` would return for
/// a WS-Federation token carrying these claims.
fn login_for(table: &Value, spec: &Value, application: &str) -> Login {
    let base = &table["logins"][spec["base"].as_str().expect("a login names its base")];
    let uri = |short: &str| table["claims"][short].as_str().unwrap_or_else(|| panic!("no claim called {short}")).to_string();
    let mut attributes: HashMap<String, Vec<String>> = HashMap::new();
    for (short, values) in overlay(&base["claims"], spec.get("claims").unwrap_or(&Value::Null)) {
        attributes.insert(uri(&short), strings(&values));
    }
    let amr = strings(pick(spec, base, "amr"));
    if !amr.is_empty() {
        attributes.insert(AUTHENTICATION_METHOD_CLAIM.into(), amr);
    }
    let mut friendly = HashMap::new();
    for (short, name) in overlay(&base["friendly"], spec.get("friendly").unwrap_or(&Value::Null)) {
        friendly.insert(uri(&short), name.as_str().unwrap().to_string());
    }
    let auth_time = pick(spec, base, "auth_time").as_i64().expect("auth_time");
    let over = spec["session_over"].as_bool().unwrap_or(false);
    Login {
        name_id: pick(spec, base, "name_id").as_str().expect("name_id").to_string(),
        name_id_format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".into()),
        name_qualifier: None,
        sp_name_qualifier: None,
        authn_instant: DateTime::from_timestamp(auth_time, 0).unwrap(),
        attributes,
        attribute_friendly_names: friendly,
        issuer: "https://iya-sts.test".into(),
        realm: application.to_string(),
        trust_version: "2005/02".into(),
        encrypted: false,
        assertion_id: "_authzen".into(),
        not_on_or_after: Utc::now() + chrono::Duration::hours(1),
        session_index: Some("authzen-session".into()),
        session_not_on_or_after: over.then(|| Utc::now() - chrono::Duration::seconds(1)),
        authn_context_class_ref: pick(spec, base, "acr").as_str().map(str::to_string),
        request_id: None,
        relay_state: None,
    }
}

fn access_for(spec: &Value) -> Access {
    let text = |key: &str| spec[key].as_str().unwrap_or_else(|| panic!("access.{key}")).to_string();
    let mut access = Access::new(text("action"), text("type"), text("id"));
    let map = |key: &str| spec.get(key).and_then(Value::as_object).cloned().unwrap_or_default();
    access.resource_properties = map("resource");
    access.action_properties = map("action_properties");
    access.context = map("context");
    access
}

/// One case through `party`: `decide`, or `decide_session` when the case
/// names a session (`tracked`, or `ended`: tracked, then signed out).
fn run_case(table: &Value, party: &RelyingParty, receiver: &SignalsReceiver, case: &Value, application: &str) -> Decision {
    let login = login_for(table, &case["login"], application);
    let access = access_for(&case["access"]);
    let session = format!("authzen-{}", case["id"].as_str().unwrap());
    match case["session"].as_str() {
        None => party.decide(&login, &access),
        Some(kind) => {
            receiver.track(&session, &login, None);
            if kind == "ended" {
                receiver.untrack(&session);
            }
            party.decide_session(receiver, &session, &login, &access)
        }
    }
}

/// A decision at the level the host sees it. Obligations keep their type
/// and properties, so central and local are compared on both.
fn answer_of(decision: &Decision) -> Value {
    match decision {
        Decision::Permit { obligations, .. } => {
            let mut handed: Vec<Value> = obligations.iter().map(|o| json!({"type": o.kind, "properties": o.properties})).collect();
            handed.sort_by_key(|o| o.to_string());
            json!({"decision": "Permit", "obligations": handed})
        }
        Decision::Deny { .. } => json!({"decision": "Deny"}),
        Decision::Unavailable { .. } => json!({"decision": "Unavailable"}),
    }
}

/// Why a decision was what it was, for a mismatch's report.
fn why_of(decision: &Decision) -> String {
    match decision {
        Decision::Permit { .. } => String::new(),
        Decision::Deny { why } | Decision::Unavailable { why } => why.clone(),
    }
}

/// Whether an answer is the table's: the decision, and for a Permit the
/// obligation types handed (none when the case lists none).
fn as_expected(answer: &Value, case: &Value) -> bool {
    if answer["decision"] != case["expect"] {
        return false;
    }
    if answer["decision"] != "Permit" {
        return true;
    }
    let mut handed: Vec<String> = answer["obligations"].as_array().unwrap().iter().filter_map(|o| o["type"].as_str()).map(str::to_string).collect();
    let mut wanted = strings(case.get("obligations").unwrap_or(&json!([])));
    handed.sort();
    wanted.sort();
    handed == wanted
}

fn receiver() -> Arc<SignalsReceiver> {
    // Never started: decide_session only asks it which sessions are tracked.
    SignalsReceiver::new("http://127.0.0.1:1", Arc::new(|_, _| Ok(())), ReceiverOptions::default()).unwrap()
}

/// The table's policies for a phase, as the bound-application pull sends
/// them: the root (the realm's, or the application's own) first, then its
/// reference closure.
fn pulled_policies(table: &Value, phase: &str, application: &str) -> Vec<Value> {
    let documents = compiled();
    let mut rows: Vec<Value> = Vec::new();
    for policy in table["policies"].as_array().unwrap().iter().filter(|p| p["phase"] == phase) {
        let name = policy["name"].as_str().unwrap();
        let held = &documents["policies"][name];
        assert!(held.is_object(), "src/test_authzen_policies.json has no {name}: run scripts/live_authzen.py --compile");
        let is_root = policy["role"] != "referenced";
        rows.push(json!({
            "name": name, "policyId": held["policyId"], "kind": held["kind"], "version": held["version"],
            "isRoot": is_root, "description": "",
            "document": held["document"].as_str().unwrap().replace("{{application}}", application),
        }));
    }
    rows.sort_by_key(|row| !row["isRoot"].as_bool().unwrap());
    rows
}

// ---------------------------------------------------------------------------
// The table itself.
// ---------------------------------------------------------------------------

#[test]
fn the_table_covers_what_it_must_and_matches_its_compiled_policies() {
    let table = table();
    let documents = compiled();
    let mut ids = std::collections::HashSet::new();
    for case in table["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        assert!(ids.insert(id), "case {id} twice");
        assert!(["Permit", "Deny", "Unavailable"].contains(&case["expect"].as_str().unwrap()), "{id}");
        assert!(table["phases"].as_array().unwrap().contains(&case["phase"]), "{id}");
        let _ = login_for(&table, &case["login"], REALM);
        let _ = access_for(&case["access"]);
    }
    // The ALFA the live run imports is the ALFA the XACML was compiled from:
    // each document's PolicyId is the ALFA's, so a policy renamed in one and
    // not the other is caught here, and a changed rule by the live run.
    for policy in table["policies"].as_array().unwrap() {
        let name = policy["name"].as_str().unwrap();
        let alfa = strings(&policy["alfa"]).join("\n");
        let id = documents["policies"][name]["policyId"].as_str().unwrap_or_else(|| panic!("{name} is not compiled"));
        assert!(alfa.contains(&format!("id = \"{id}\"")), "{name}'s compiled PolicyId {id} is not in its ALFA");
    }
    let kinds: Vec<(&str, &str)> = table["catalogue"].as_array().unwrap().iter().map(|r| (r["object"].as_str().unwrap(), r.get("dataType").and_then(Value::as_str).unwrap_or("string"))).collect();
    for wanted in ["integer", "double", "boolean", "dateTime"] {
        assert!(kinds.iter().any(|(_, t)| *t == wanted), "a {wanted} row");
    }
    for object in ["subject", "resource", "action", "context"] {
        assert!(kinds.iter().any(|(o, _)| *o == object), "a {object} row");
    }
}

// ---------------------------------------------------------------------------
// The offline run: a stub PDP and a `local` party.
// ---------------------------------------------------------------------------

pub(crate) struct Pdp {
    pub(crate) url: String,
    rows: Value,
    directory: Value,
    pub(crate) policies: Mutex<(String, Vec<Value>)>,
    /// The catalogue's `fgaApplications`: the bound application in the
    /// `application` phase, where it enforces fine-grained authorization.
    pub(crate) fga_applications: Mutex<Vec<String>>,
    pub(crate) evaluations: AtomicUsize,
}

pub(crate) fn start_pdp(table: &Value) -> &'static Pdp {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    let pdp: &'static Pdp = Box::leak(Box::new(Pdp {
        url: format!("http://127.0.0.1:{port}"),
        rows: table["catalogue"].clone(),
        directory: table["directory"].clone(),
        policies: Mutex::new((String::new(), Vec::new())),
        fga_applications: Mutex::new(Vec::new()),
        evaluations: AtomicUsize::new(0),
    }));
    thread::spawn(move || {
        for mut request in server.incoming_requests() {
            let mut body = String::new();
            let _ = std::io::Read::read_to_string(request.as_reader(), &mut body);
            let path = request.url().split('?').next().unwrap_or("").to_string();
            let (status, kind, answer) = pdp_answer(pdp, &path, &body);
            let response = tiny_http::Response::from_string(answer)
                .with_status_code(status)
                .with_header(tiny_http::Header::from_bytes(&b"content-type"[..], kind.as_bytes()).unwrap());
            let _ = request.respond(response);
        }
    });
    pdp
}

fn pdp_answer(pdp: &Pdp, path: &str, body: &str) -> (u16, &'static str, String) {
    let ok = |value: Value| (200, "application/json", value.to_string());
    match path {
        "/oauth2/token" => ok(json!({"access_token": "pep-token", "token_type": "DPoP", "expires_in": 300})),
        // The service answers the PEP's entry DN, which `local` writes as
        // the caller fact.
        "/xacml/pep/register" => (201, "application/json", json!({"registered": true, "identity": STUB_PEP_DN}).to_string()),
        "/xacml/pep/heartbeat" => ok(json!({"acknowledged": true, "current": true})),
        "/xacml/pep/authzen-catalogue" => {
            let fga = pdp.fga_applications.lock().unwrap().clone();
            ok(json!({"syncToken": format!("authzen-rows-{}", fga.len()), "rows": pdp.rows, "fgaApplications": fga, "settings": {"obligationsProfile": true}}))
        }
        "/xacml/pep/policies" => {
            let (token, policies) = pdp.policies.lock().unwrap().clone();
            let root = policies.iter().find(|p| p["isRoot"] == true).map(|p| p["name"].clone()).unwrap_or(Value::Null);
            ok(json!({"syncToken": token, "root": root, "policies": policies, "withheld": [], "note": ""}))
        }
        "/xacml/pip" => (200, "application/xml", pip_answer(&pdp.directory, body)),
        "/admin-api/pep-audit" => ok(json!({"acknowledged": 0})),
        "/access/v1/evaluation" => {
            pdp.evaluations.fetch_add(1, Ordering::SeqCst);
            (500, "application/json", json!({"error": "server_error"}).to_string())
        }
        _ => (404, "application/json", json!({"error": "not_found"}).to_string()),
    }
}

/// The text between `start` and `end` after `from`.
fn between<'a>(text: &'a str, from: usize, start: &str, end: &str) -> Option<(&'a str, usize)> {
    let at = text[from..].find(start)? + from + start.len();
    let stop = text[at..].find(end)? + at;
    Some((&text[at..stop], stop))
}

/// Answers a `<PIPRequest>` from the table's directory: the subject-id's
/// person, each designator by its attribute name.
fn pip_answer(directory: &Value, query: &str) -> String {
    let subject = query
        .find("subject:subject-id")
        .and_then(|at| query[at..].find("<AttributeValue").map(|value| at + value))
        .and_then(|at| between(query, at, "\">", "</AttributeValue>"))
        .map(|(id, _)| id.to_string())
        .unwrap_or_default();
    let person = directory.as_array().unwrap().iter().find(|p| p["username"] == subject.as_str());
    let mut attributes = String::new();
    let mut from = 0;
    while let Some((designator, next)) = between(query, from, "<AttributeDesignator", "/>") {
        from = next;
        let id = between(designator, 0, "AttributeId=\"", "\"").map(|(v, _)| v).unwrap_or("");
        let category = between(designator, 0, "Category=\"", "\"").map(|(v, _)| v).unwrap_or("");
        let data_type = between(designator, 0, "DataType=\"", "\"").map(|(v, _)| v).unwrap_or("");
        let Some(value) = person.and_then(|p| p["attributes"][id].as_str()) else { continue };
        if category != ACCESS_SUBJECT || data_type != XS_STRING {
            continue;
        }
        attributes.push_str(&format!("<Attribute AttributeId=\"{id}\" IncludeInResult=\"false\"><AttributeValue DataType=\"{XS_STRING}\">{value}</AttributeValue></Attribute>"));
    }
    format!(
        "<PIPResponse xmlns=\"urn:sts:xacml:pip:1.0\"><Attributes xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" Category=\"{ACCESS_SUBJECT}\">{attributes}</Attributes></PIPResponse>"
    )
}

pub(crate) fn key_file(tag: &str) -> String {
    let path = std::env::temp_dir().join(format!("wsfed-authzen-{tag}-{}.pem", std::process::id()));
    std::fs::write(&path, stub::idp_key()).unwrap();
    path.to_string_lossy().into_owned()
}

/// Waits until `ready` holds for the party's PEP, or panics with its status.
pub(crate) fn wait_for(party: &RelyingParty, what: &str, ready: impl Fn(&crate::pep::Status) -> bool) {
    let pep = party.pep().expect("a PEP");
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let status = pep.status();
        if ready(&status) {
            return;
        }
        assert!(Instant::now() < deadline, "the {} PEP never {what}: {}", pep.config().name, status.last_error);
        thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn every_case_answers_as_the_table_says_in_local_mode() {
    let table = table();
    let pdp = start_pdp(&table);
    let receiver = receiver();
    let mut failures = Vec::new();
    let mut ran = 0;
    for phase in table["phases"].as_array().unwrap().iter().filter_map(Value::as_str) {
        *pdp.policies.lock().unwrap() = (format!("authzen-{phase}"), pulled_policies(&table, phase, REALM));
        *pdp.fga_applications.lock().unwrap() = if phase == "application" { vec![REALM.to_string()] } else { Vec::new() };
        let config = json!({
            "realm": REALM, "replyUrl": REPLY, "signals": false,
            "idpMetadata": stub::idp_metadata(&MetaOptions::default()),
            "pep": {
                "name": "pep-wsfed-authzen", "mode": "local", "assertionKey": key_file(phase), "pdpUrl": pdp.url,
                "pollIntervalMs": 1000, "heartbeatIntervalMs": 60000, "supportedObligations": ["step-up"],
            },
        });
        let party = RelyingParty::create(config.as_object().unwrap(), Path::new(".")).unwrap();
        // Registered too: the caller fact is the DN the registration answered.
        wait_for(&party, "registered and held the policy", |s| s.registered && s.holds_policy);
        for case in cases(&table, phase) {
            ran += 1;
            let decision = run_case(&table, &party, &receiver, case, REALM);
            let answer = answer_of(&decision);
            if !as_expected(&answer, case) {
                failures.push(format!("{} ({phase}): got {answer} ({}), want {}", case["id"], why_of(&decision), case["expect"]));
            }
        }
        party.pep().unwrap().stop();
    }
    assert_eq!(ran, table["cases"].as_array().unwrap().len(), "every case is in a phase");
    assert!(failures.is_empty(), "{} of {ran} cases:\n{}", failures.len(), failures.join("\n"));
    assert_eq!(pdp.evaluations.load(Ordering::SeqCst), 0, "a local decision never asks the AuthZEN endpoint");
}

// ---------------------------------------------------------------------------
// The live run: central and local against one iya-sts.
// ---------------------------------------------------------------------------

/// Run by `scripts/live_authzen.py`, which provisions iya-sts and names
/// what it made in the JSON file `WSFED_AUTHZEN_LIVE` points at:
/// `phase`, `application`, `replyUrl`, `idpMetadata` and `idpCa` (files),
/// and `peps` (`central` and `local`, each `name` and `key`). It prints its
/// findings as one `@@AUTHZEN@@` JSON line, then fails if central and local
/// disagree on any case or either is not the table's answer. Without the
/// variable, nothing is run.
#[test]
fn authzen_live() {
    let Ok(described) = std::env::var("WSFED_AUTHZEN_LIVE") else {
        eprintln!("authzen_live: WSFED_AUTHZEN_LIVE is not set; scripts/live_authzen.py runs this against iya-sts");
        return;
    };
    let live: Value = serde_json::from_str(&std::fs::read_to_string(&described).unwrap()).unwrap();
    let table = table();
    let phase = live["phase"].as_str().unwrap();
    let application = live["application"].as_str().unwrap();
    let party = |mode: &str| {
        let pep = &live["peps"][mode];
        let config = json!({
            "realm": application, "replyUrl": live["replyUrl"], "signals": false,
            "idpMetadata": format!("file:{}", live["idpMetadata"].as_str().unwrap()),
            "idpCa": format!("file:{}", live["idpCa"].as_str().unwrap()),
            "pep": {
                "name": pep["name"], "mode": mode, "assertionKey": pep["key"],
                "pollIntervalMs": 1000, "heartbeatIntervalMs": 30000, "supportedObligations": ["step-up"],
            },
        });
        RelyingParty::create(config.as_object().unwrap(), Path::new("/")).unwrap_or_else(|err| panic!("the {mode} party: {err}"))
    };
    let central = party("central");
    let local = party("local");
    wait_for(&central, "registered", |s| s.registered);
    wait_for(&local, "registered", |s| s.registered);
    // Both pull now, so each holds the catalogue (central: the subject
    // properties it may send) and local the policy, as they stand.
    for (mode, party) in [("central", &central), ("local", &local)] {
        party.pep().unwrap().pull_now().unwrap_or_else(|err| panic!("the {mode} PEP's pull: {err}"));
    }
    wait_for(&local, "held the policy", |s| s.holds_policy);
    let receiver = receiver();

    let mut rows = Vec::new();
    let mut mismatches = Vec::new();
    let (mut equal, mut expected) = (0, 0);
    for case in cases(&table, phase) {
        let from_central = run_case(&table, &central, &receiver, case, application);
        let from_local = run_case(&table, &local, &receiver, case, application);
        let (c, l) = (answer_of(&from_central), answer_of(&from_local));
        let same = c == l;
        let right = as_expected(&c, case) && as_expected(&l, case);
        equal += usize::from(same);
        expected += usize::from(right);
        let row = json!({
            "case": case["id"], "phase": phase, "central": c, "local": l,
            "expected": {"decision": case["expect"], "obligations": case.get("obligations").cloned().unwrap_or(json!([]))},
            "centralWhy": why_of(&from_central), "localWhy": why_of(&from_local), "equal": same, "asExpected": right,
        });
        if !same || !right {
            mismatches.push(row.clone());
        }
        rows.push(row);
    }
    let status = |party: &RelyingParty| {
        let s = party.pep().unwrap().status();
        json!({"decisions": s.decisions, "policyCount": s.policy_count, "syncToken": s.sync_token, "lastError": s.last_error})
    };
    let result = json!({
        "phase": phase, "cases": rows.len(), "equal": equal, "asExpected": expected,
        "mismatches": mismatches, "rows": rows, "central": status(&central), "local": status(&local),
    });
    // One line the script reads back (it holds no secret).
    println!("@@AUTHZEN@@{result}");
    central.pep().unwrap().stop();
    local.pep().unwrap().stop();
    let listed: Vec<String> = result["mismatches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| format!("{}: central {} ({}), local {} ({}), expected {}", m["case"], m["central"], m["centralWhy"], m["local"], m["localWhy"], m["expected"]))
        .collect();
    assert!(listed.is_empty(), "phase {phase}: {} of {} cases differ:\n{}", listed.len(), rows.len(), listed.join("\n"));
}
