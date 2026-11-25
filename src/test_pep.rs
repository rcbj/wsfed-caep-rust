// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The embedded PEP wired into the relying party (#40): the `pep` section
//! and its defaults, the distinct-keys refusal, the `Login` adapter,
//! `decide` and `decide_session` against a stub PDP, and the
//! `pep-policies-changed` event handed over by `SignalsReceiver`. The PEP's
//! own behaviour (the credential, both modes, the engine) is iya-pep's
//! suite.

#[cfg(not(feature = "pep"))]
#[test]
fn pep_section_is_refused_without_the_feature() {
    use crate::test_support::{self as stub, rejects, MetaOptions, REALM, REPLY};
    use serde_json::json;
    let config = json!({
        "realm": REALM, "replyUrl": REPLY, "idpMetadata": stub::idp_metadata(&MetaOptions::default()),
        "pep": {"name": "pep-demo", "assertionKey": "/k.pem"},
    });
    let err = crate::RelyingParty::create(config.as_object().unwrap(), std::path::Path::new(".")).map(|_| ());
    rejects(&err, "config", "the wsfed-caep `pep` feature");
}

#[cfg(feature = "pep")]
mod with_pep {
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;

    use chrono::Utc;
    use serde_json::{json, Map, Value};

    use crate::pep::{subject_of, Access, Decision, AUTHENTICATION_METHOD_CLAIM, NAME_CLAIM, POLICIES_CHANGED_EVENT};
    use crate::relying_party::{LoginOptions, ReplyBody, ReplyRequest, RelyingParty};
    use crate::ssf::{events, ReceiverOptions, SignalsReceiver, TlsConfig};
    use crate::test_ssf::{login_of, Stop, Stub};
    use crate::test_support::{self as stub, rejects, AssertionOptions, MetaOptions, WResultOptions, IDP_ENTITY, REALM, REPLY};
    use crate::token::Login;

    /// A stub PDP: the token endpoint, register, heartbeat, the catalogue,
    /// the policy pull and the AuthZEN evaluation. `decisions` are answered
    /// in order, then Permit.
    struct Pdp {
        url: String,
        seen: Mutex<Vec<(String, String)>>,
        decisions: Mutex<Vec<bool>>,
        /// `local`: whether the policy pull answers.
        policies_up: AtomicBool,
    }

    impl Pdp {
        fn count(&self, path: &str) -> usize {
            self.seen.lock().unwrap().iter().filter(|(p, _)| p == path).count()
        }

        fn bodies(&self, path: &str) -> Vec<Value> {
            self.seen.lock().unwrap().iter().filter(|(p, _)| p == path).map(|(_, b)| serde_json::from_str(b).unwrap_or(Value::Null)).collect()
        }
    }

    fn start_pdp() -> &'static Pdp {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let pdp: &'static Pdp = Box::leak(Box::new(Pdp {
            url: format!("http://127.0.0.1:{port}/realm/r1"),
            seen: Mutex::new(Vec::new()),
            decisions: Mutex::new(Vec::new()),
            policies_up: AtomicBool::new(true),
        }));
        thread::spawn(move || {
            for mut request in server.incoming_requests() {
                let mut body = String::new();
                let _ = std::io::Read::read_to_string(request.as_reader(), &mut body);
                let path = request.url().split('?').next().unwrap_or("").trim_start_matches("/realm/r1").to_string();
                let dpop = request.headers().iter().any(|h| h.field.equiv("authorization") && h.value.as_str().starts_with("DPoP "));
                let (status, answer) = answer(pdp, &path, &body, dpop);
                let response = tiny_http::Response::from_string(answer.to_string())
                    .with_status_code(status)
                    .with_header(tiny_http::Header::from_bytes(&b"content-type"[..], &b"application/json"[..]).unwrap());
                let _ = request.respond(response);
            }
        });
        pdp
    }

    fn answer(pdp: &Pdp, path: &str, body: &str, dpop: bool) -> (u16, Value) {
        pdp.seen.lock().unwrap().push((path.to_string(), body.to_string()));
        if path != "/oauth2/token" && !dpop {
            return (401, json!({"error": "invalid_token"}));
        }
        match path {
            "/oauth2/token" => (200, json!({"access_token": "pep-token", "token_type": "DPoP", "expires_in": 300})),
            "/xacml/pep/register" => (201, json!({"registered": true})),
            "/xacml/pep/heartbeat" => (200, json!({"acknowledged": true, "current": true})),
            "/xacml/pep/authzen-catalogue" => (
                200,
                json!({"syncToken": "c1", "realm": "r1", "rows": [
                    {"object": "subject", "property": "acr", "attributeId": "urn:example:acr"},
                    {"object": "subject", "property": "emailaddress", "attributeId": "urn:example:email"}
                ], "settings": {"obligationsProfile": false}}),
            ),
            "/xacml/pep/policies" if pdp.policies_up.load(Ordering::SeqCst) => (200, json!({"syncToken": "p1", "root": "orders", "policies": [{
                "name": "orders", "policyId": "orders", "kind": "Policy", "version": "1.0", "isRoot": true, "description": "",
                "combiningAlgId": "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit", "document": READ_ONLY}], "withheld": [], "note": ""})),
            "/xacml/pep/policies" => (503, json!({"error": "server_error", "error_description": "not now"})),
            "/admin-api/pep-audit" => (200, json!({"acknowledged": 0})),
            "/access/v1/evaluation" => {
                let mut queue = pdp.decisions.lock().unwrap();
                let decision = if queue.is_empty() { true } else { queue.remove(0) };
                (200, json!({"decision": decision}))
            }
            _ => (404, json!({"error": "not_found"})),
        }
    }

    /// Permits `read`, and nothing else.
    const READ_ONLY: &str = r#"<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicyId="orders" Version="1.0" RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit"><Target/><Rule RuleId="read" Effect="Permit"><Target><AnyOf><AllOf><Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">read</AttributeValue><AttributeDesignator Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action" AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id" DataType="http://www.w3.org/2001/XMLSchema#string" MustBePresent="false"/></Match></AllOf></AnyOf></Target></Rule></Policy>"#;

    fn key_file(tag: &str, pem: &str) -> String {
        let path = std::env::temp_dir().join(format!("wsfed-pep-{tag}-{}.pem", std::process::id()));
        std::fs::write(&path, pem).unwrap();
        path.to_string_lossy().into_owned()
    }

    /// The PEP's own key in these tests: the stub IdP's, which is neither
    /// the relying party's `privateKey` nor any receiver's TLS key.
    fn pep_key(tag: &str) -> String {
        key_file(tag, stub::idp_key())
    }

    fn pep_section(pdp: &Pdp, tag: &str, extra: Value) -> Value {
        // central by name: these tests ask the stub PDP for each decision, and
        // a section that names no mode is local (iya-pep's default).
        let mut section = json!({"name": "pep-demo", "mode": "central", "assertionKey": pep_key(tag), "pdpUrl": pdp.url, "heartbeatIntervalMs": 60000});
        for (k, v) in extra.as_object().unwrap() {
            section[k] = v.clone();
        }
        section
    }

    fn cfg(extra: Value) -> Map<String, Value> {
        let mut body = json!({
            "realm": REALM,
            "replyUrl": REPLY,
            "privateKey": stub::rp_key(),
            "certificate": stub::rp_cert(),
            "idpMetadata": stub::idp_metadata(&MetaOptions::default()),
        });
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        body.as_object().unwrap().clone()
    }

    fn create(extra: Value) -> crate::Result<RelyingParty> {
        RelyingParty::create(&cfg(extra), Path::new("."))
    }

    /// A sign-in with an authentication context, a name claim and the
    /// attributes iya-sts sends.
    fn login() -> Login {
        let mut login = login_of("alice", "IDP-A1");
        login.authn_context_class_ref = Some("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport".into());
        login.authn_instant = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        login.attributes.insert(NAME_CLAIM.into(), vec!["alice".into()]);
        login.attributes.insert(AUTHENTICATION_METHOD_CLAIM.into(), vec!["urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport".into()]);
        login
    }

    #[test]
    fn a_pep_section_builds_a_started_pep_with_the_librarys_defaults() {
        // pdpUrl defaults to the identity provider's entityID, application
        // to the realm; tlsCa and signals are the library's; a relative
        // assertionKey is the configuration directory's.
        let dir = std::env::temp_dir().join(format!("wsfed-pep-dir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("pep-key.pem"), stub::idp_key()).unwrap();
        let config = cfg(json!({"idpCa": stub::rp_cert(), "pep": {"name": "pep-demo", "assertionKey": "file:pep-key.pem", "timeoutMs": 500, "heartbeatIntervalMs": 60000}}));
        let rp = RelyingParty::create(&config, &dir).unwrap();
        let pep = rp.pep().expect("a PEP");
        assert_eq!(pep.config().pdp_url, IDP_ENTITY, "pdpUrl defaults to the identity provider's entityID");
        assert_eq!(pep.config().application, REALM, "application defaults to the realm");
        assert_eq!(pep.config().assertion_key, dir.join("pep-key.pem").to_string_lossy(), "relative to the configuration");
        assert_eq!(pep.config().tls_ca, stub::rp_cert(), "tlsCa defaults to idpCa");
        assert!(pep.config().signals, "signals follow the library's, on by default");
        assert!(pep.status().running);

        let pdp = start_pdp();
        let rp = create(json!({"pep": pep_section(pdp, "started", json!({}))})).unwrap();
        let register = pdp.bodies("/xacml/pep/register");
        assert!(!register.is_empty(), "registered at create");
        assert_eq!(register[0]["kind"], "embedded");
        assert_eq!(register[0]["application"], REALM);
        assert!(rp.pep().unwrap().status().registered);

        let off = create(json!({"signals": false, "pep": pep_section(pdp, "nosignals", json!({}))})).unwrap();
        assert!(!off.pep().unwrap().config().signals);
        let own = create(json!({"pep": pep_section(pdp, "own", json!({"signals": false, "application": "urn:orders"}))})).unwrap();
        assert!(!own.pep().unwrap().config().signals, "the section's own value wins");
        assert_eq!(own.pep().unwrap().config().application, "urn:orders");
        assert!(create(json!({})).unwrap().pep().is_none(), "no section, no PEP");
        assert!(create(json!({"pep": null})).unwrap().pep().is_none(), "null is no section");
    }

    /// `from_file` reads the `pep` section as `create` does, and the PEP it
    /// builds is started: the live run of oidc-caep-risc (its #46) found that
    /// library's file reader dropped the section, so this one is held to it
    /// too.
    #[test]
    fn from_file_keeps_the_pep_section() {
        let pdp = start_pdp();
        let dir = std::env::temp_dir().join(format!("wsfed-pep-from-file-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("pep-key.pem"), stub::idp_key()).unwrap();
        let doc = cfg(json!({"pep": {"name": "pep-demo", "assertionKey": "file:pep-key.pem", "pdpUrl": pdp.url, "heartbeatIntervalMs": 60000}}));
        let path = dir.join("wsfed.json");
        std::fs::write(&path, Value::Object(doc).to_string()).unwrap();
        let rp = RelyingParty::from_file(&path.to_string_lossy(), None).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let pep = rp.pep().expect("the configuration file's pep section built a PEP");
        assert_eq!(pep.config().name, "pep-demo");
        assert!(pep.config().assertion_key.ends_with("pep-key.pem") && Path::new(&pep.config().assertion_key).is_absolute(), "relative to the file's directory: {}", pep.config().assertion_key);
        assert!(pep.status().running);
        assert!(pdp.count("/xacml/pep/register") >= 1, "and started it");
    }

    #[test]
    fn a_bad_section_is_refused_at_create() {
        let pdp = start_pdp();
        for (section, says) in [
            (json!("on"), "pep must be an object"),
            (pep_section(pdp, "bad-mode", json!({"mode": "remote"})), "pep.mode"),
            (pep_section(pdp, "bad-member", json!({"polIntervalMs": 1})), "polIntervalMs"),
            (pep_section(pdp, "bad-name", json!({"name": "a b"})), "pep.name"),
            (pep_section(pdp, "bad-url", json!({"pdpUrl": "urn:idp"})), "pep.pdpUrl"),
            (json!({"name": "pep-demo", "pdpUrl": pdp.url}), "pep.assertionKey"),
            (json!({"name": "pep-demo", "assertionKey": "/nowhere.pem", "pdpUrl": pdp.url}), "nowhere"),
        ] {
            let err = create(json!({"pep": section})).map(|_| ());
            rejects(&err, "config", says);
        }
    }

    #[test]
    fn the_pep_key_must_differ_from_the_private_key_and_the_receivers_tls_key() {
        let pdp = start_pdp();
        // privateKey: the relying party's signing and decryption key.
        let same = json!({"name": "pep-demo", "assertionKey": key_file("rp", stub::rp_key()), "pdpUrl": pdp.url});
        let err = create(json!({"pep": same})).map(|_| ());
        rejects(&err, "config", "privateKey");
        // Without a privateKey there is nothing to compare it with.
        let mut keyless = cfg(json!({"pep": {"name": "pep-demo", "assertionKey": key_file("keyless", stub::rp_key()), "pdpUrl": pdp.url}}));
        keyless.remove("privateKey");
        keyless.remove("certificate");
        assert!(RelyingParty::create(&keyless, Path::new(".")).unwrap().pep().is_some());

        // The receiver's TLS client key.
        let rp = create(json!({"pep": pep_section(pdp, "tls", json!({}))})).unwrap();
        let tls = |key: &str| Some(TlsConfig { ca: String::new(), cert: String::new(), key: key.to_string() });
        let err = SignalsReceiver::new("http://127.0.0.1:1", Arc::new(|_, _| Ok(())), ReceiverOptions { tls: tls(stub::idp_key()), pep: rp.pep().cloned(), ..ReceiverOptions::default() }).map(|_| ());
        rejects(&err, "config", "TLS client key");
        // A key of its own each.
        assert!(SignalsReceiver::new("http://127.0.0.1:1", Arc::new(|_, _| Ok(())), ReceiverOptions { tls: tls(stub::rp_key()), pep: rp.pep().cloned(), ..ReceiverOptions::default() }).is_ok());
        assert!(SignalsReceiver::new("http://127.0.0.1:1", Arc::new(|_, _| Ok(())), ReceiverOptions { tls: tls(stub::idp_key()), ..ReceiverOptions::default() }).is_ok(), "no PEP, nothing to compare");
    }

    #[test]
    fn a_login_becomes_the_peps_subject() {
        let s = subject_of(&login());
        assert_eq!((s.kind.as_str(), s.id.as_str()), ("user", "alice"), "the name claim: the username the service's PIP resolves");
        assert_eq!(s.properties["acr"], "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
        assert_eq!(s.properties["amr"], json!(["urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"]));
        assert_eq!(s.properties["auth_time"], 1_700_000_000);
        assert_eq!(s.properties["emailaddress"], "alice@example.com", "a claim URI is keyed by its last segment");
        assert_eq!(s.properties["nameidentifier"], "urn:uuid:alice");
        assert!(s.properties.keys().all(|k| !k.contains('/')), "no claim URI, which a catalogue can't declare");

        let mut nameless = login();
        nameless.attributes.remove(NAME_CLAIM);
        nameless.authn_context_class_ref = None;
        nameless.attributes.insert("urn:oid:0.9.2342.19200300.100.1.3".into(), vec!["x@example.com".into()]);
        nameless.attributes.insert("http://schemas.microsoft.com/ws/2008/06/identity/claims/role".into(), vec!["staff".into(), "admins".into()]);
        nameless.attributes.insert("acr".into(), vec!["claimed-by-an-attribute".into()]);
        let s = subject_of(&nameless);
        assert_eq!(s.id, "alice", "the NameID when there is no name claim, never the opaque nameidentifier");
        assert_eq!(s.properties["role"], json!(["staff", "admins"]), "several values are an array");
        assert!(!s.properties.values().any(|v| v == "x@example.com"), "a name with no usable segment is left out");
        assert_eq!(s.properties["acr"], "claimed-by-an-attribute", "no AuthnContextClassRef, nothing to lay over it");

        // FriendlyName wins over the Name's segment; a signed AuthnStatement
        // wins over an attribute called acr.
        let mut friendly = login();
        friendly.attribute_friendly_names.insert("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress".into(), "mail".into());
        friendly.attributes.insert("acr".into(), vec!["claimed-by-an-attribute".into()]);
        let s = subject_of(&friendly);
        assert_eq!(s.properties["mail"], "alice@example.com");
        assert!(!s.properties.contains_key("emailaddress"));
        assert_eq!(s.properties["acr"], "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
    }

    #[test]
    fn a_validated_token_becomes_the_peps_subject() {
        let rp = create(json!({})).unwrap();
        let sign_in = |extra: &str| {
            let request = rp.login(&LoginOptions::default()).unwrap();
            let token = stub::signed_assertion(&AssertionOptions { extra_attributes: extra.to_string(), ..AssertionOptions::default() }).unwrap().xml;
            let result = stub::wresult(&WResultOptions { token: Some(token), ..WResultOptions::default() }).unwrap();
            let mut body = HashMap::new();
            body.insert("wa".to_string(), "wsignin1.0".to_string());
            body.insert("wresult".to_string(), result);
            body.insert("wctx".to_string(), request.wctx.clone());
            rp.handle_reply(ReplyRequest { method: "POST".into(), url: "/wsfed".into(), body: ReplyBody::Map(body) }, &[request.id]).unwrap()
        };
        let who = sign_in("");
        let s = subject_of(&who);
        assert_eq!(s.id, "alice-1234", "the NameID");
        assert_eq!(s.properties["acr"], "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
        assert_eq!(s.properties["auth_time"], who.authn_instant.timestamp());
        assert_eq!(s.properties["mail"], "alice@example.com");
        let who = sign_in(&format!("<saml:Attribute Name=\"{NAME_CLAIM}\"><saml:AttributeValue>alice</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"{AUTHENTICATION_METHOD_CLAIM}\"><saml:AttributeValue>urn:pwd</saml:AttributeValue></saml:Attribute>"));
        let s = subject_of(&who);
        assert_eq!(s.id, "alice", "the name claim");
        assert_eq!(s.properties["amr"], json!(["urn:pwd"]));
    }

    #[test]
    fn decide_asks_the_service_with_the_declared_claims_only() {
        let pdp = start_pdp();
        let rp = create(json!({"pep": pep_section(pdp, "decide", json!({}))})).unwrap();
        pdp.decisions.lock().unwrap().extend([true, false]);
        assert!(rp.decide(&login(), &Access::new("read", "order", "42")).is_permit());
        assert!(matches!(rp.decide(&login(), &Access::new("delete", "order", "42")), Decision::Deny { .. }));
        let bodies = pdp.bodies("/access/v1/evaluation");
        assert_eq!(bodies.len(), 2);
        let body = &bodies[0];
        assert_eq!(body["subject"], json!({"type": "user", "id": "alice", "properties": {
            "acr": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
            "emailaddress": "alice@example.com",
        }}), "amr, auth_time, name and nameidentifier are not in the catalogue");
        assert_eq!(body["action"]["name"], "read");
        assert_eq!(body["resource"], json!({"type": "order", "id": "42"}));
        assert_eq!(body["context"]["application"], REALM);

        let none = create(json!({})).unwrap();
        assert!(matches!(none.decide(&login(), &Access::new("read", "order", "42")), Decision::Unavailable { .. }), "no section never permits");
    }

    #[test]
    fn an_ended_session_is_denied_without_asking() {
        let pdp = start_pdp();
        let tx = Stub::new();
        let rp = create(json!({"pep": pep_section(pdp, "session", json!({}))})).unwrap();
        let receiver = SignalsReceiver::new(&tx.url, Arc::new(|_, _| Ok(())), ReceiverOptions { poll_interval_ms: 60_000, pep: rp.pep().cloned(), ..ReceiverOptions::default() }).unwrap();
        let _stop = Stop(receiver.clone());
        receiver.start().unwrap();
        receiver.stop();
        let access = Access::new("read", "order", "42");
        let asked = || pdp.count("/access/v1/evaluation");

        assert!(matches!(rp.decide_session(&receiver, "L1", &login(), &access), Decision::Deny { .. }), "never tracked");
        assert_eq!(asked(), 0);
        receiver.track("L1", &login(), None);
        assert!(rp.decide_session(&receiver, "L1", &login(), &access).is_permit());
        assert_eq!(asked(), 1);

        // Ended by CAEP session-revoked.
        tx.put(events::event("session_revoked"), json!({"format": "complex", "user": {"format": "iss_sub", "iss": tx.url, "sub": "urn:uuid:alice"}, "session": {"format": "opaque", "id": "IDP-A1"}}), None, None, "", "");
        receiver.poll_once().unwrap();
        assert!(matches!(rp.decide_session(&receiver, "L1", &login(), &access), Decision::Deny { .. }), "ended by the event");
        // Signed out.
        receiver.track("L2", &login(), None);
        receiver.untrack("L2");
        assert!(matches!(rp.decide_session(&receiver, "L2", &login(), &access), Decision::Deny { .. }), "untracked");
        // Past the identity provider's session.
        let mut over = login();
        over.session_not_on_or_after = Some(Utc::now() - chrono::Duration::seconds(1));
        receiver.track("L3", &login(), None);
        assert!(matches!(rp.decide_session(&receiver, "L3", &over, &access), Decision::Deny { .. }), "SessionNotOnOrAfter is over");
        assert_eq!(asked(), 1, "nothing ended was asked about");
    }

    /// A stream that names subjects carries only events about them (iya-sts
    /// under `default_subjects` ALL), and `pep-policies-changed` is about the
    /// application: a receiver that adds people names the application too,
    /// at `start`, as the event's `application` member.
    #[test]
    fn a_receiver_adding_subjects_names_the_application_its_pep_hears_about() {
        let pdp = start_pdp();
        let tx = Stub::new();
        tx.subject_endpoints();
        let local = create(json!({"pep": pep_section(pdp, "subjects", json!({"mode": "local"}))})).unwrap();
        let receiver = SignalsReceiver::new(&tx.url, Arc::new(|_, _| Ok(())), ReceiverOptions { poll_interval_ms: 60_000, pep: local.pep().cloned(), ..ReceiverOptions::default() }).unwrap();
        let _stop = Stop(receiver.clone());
        receiver.start().unwrap();
        let calls = tx.subject_calls();
        assert_eq!(calls, vec![("add".to_string(), json!({"stream_id": "s1", "subject": {"format": "opaque", "id": REALM}, "verified": true}))]);
        receiver.track("L1", &login(), None);
        receiver.untrack("L1");
        let calls = tx.subject_calls();
        assert_eq!(calls.len(), 3, "the person added and removed: {calls:?}");
        assert!(calls.iter().all(|(_, body)| body["subject"] != json!({"format": "opaque", "id": REALM}) || body.get("verified").is_some()), "the application is never removed");
        receiver.stop();

        // Switched off, or a PEP that wants no events (central, no Permit
        // cache): the application is not named.
        let tx = Stub::new();
        tx.subject_endpoints();
        let off = SignalsReceiver::new(&tx.url, Arc::new(|_, _| Ok(())), ReceiverOptions { poll_interval_ms: 60_000, add_subjects: false, pep: local.pep().cloned(), ..ReceiverOptions::default() }).unwrap();
        off.start().unwrap();
        off.stop();
        let central = create(json!({"pep": pep_section(pdp, "subjects-central", json!({}))})).unwrap();
        let quiet = SignalsReceiver::new(&tx.url, Arc::new(|_, _| Ok(())), ReceiverOptions { poll_interval_ms: 60_000, pep: central.pep().cloned(), ..ReceiverOptions::default() }).unwrap();
        quiet.start().unwrap();
        quiet.stop();
        assert!(tx.subject_calls().is_empty(), "{:?}", tx.subject_calls());
        local.pep().unwrap().stop();
    }

    #[test]
    fn the_receiver_asks_for_the_policy_event_and_hands_it_to_the_pep() {
        let pdp = start_pdp();
        let tx = Stub::new();
        // central with a Permit cache: the event clears it.
        let rp = create(json!({"pep": pep_section(pdp, "event", json!({"permitCacheMs": 30000}))})).unwrap();
        let plain = create(json!({"pep": pep_section(pdp, "plain", json!({}))})).unwrap();
        let without = SignalsReceiver::new(&tx.url, Arc::new(|_, _| Ok(())), ReceiverOptions { pep: None, ..ReceiverOptions::default() }).unwrap();
        assert!(!without.events_requested().iter().any(|e| e == POLICIES_CHANGED_EVENT), "no PEP, no event asked for");
        let uncached = SignalsReceiver::new(&tx.url, Arc::new(|_, _| Ok(())), ReceiverOptions { pep: plain.pep().cloned(), ..ReceiverOptions::default() }).unwrap();
        assert!(!uncached.events_requested().iter().any(|e| e == POLICIES_CHANGED_EVENT), "central without a Permit cache has no use for it");
        let receiver = SignalsReceiver::new(&tx.url, Arc::new(|_, _| Ok(())), ReceiverOptions { poll_interval_ms: 60_000, pep: rp.pep().cloned(), ..ReceiverOptions::default() }).unwrap();
        let _stop = Stop(receiver.clone());
        assert!(receiver.events_requested().iter().any(|e| e == POLICIES_CHANGED_EVENT), "asked for on the relying party's own stream");
        assert!(receiver.events_requested().iter().any(|e| e == events::event("session_revoked")), "beside the defaults");
        receiver.start().unwrap();
        receiver.stop();
        let delivered = receiver.stream().get("events_delivered").cloned().unwrap_or(Value::Null);
        assert!(delivered.as_array().unwrap().iter().any(|e| e == POLICIES_CHANGED_EVENT), "the stream was created asking for it");

        let access = Access::new("read", "order", "42");
        assert!(rp.decide(&login(), &access).is_permit());
        assert!(rp.decide(&login(), &access).is_permit());
        assert_eq!(pdp.count("/access/v1/evaluation"), 1, "the second came from the Permit cache");

        // A SET signed by another key is refused and never reaches the PEP.
        let subject = json!({"format": "opaque", "id": REALM});
        let forged = tx.put(POLICIES_CHANGED_EVENT, subject.clone(), Some(json!({"pep": "pep-demo", "changed": ["policies"]})), Some(&tx.other), "", "");
        receiver.poll_once().unwrap();
        receiver.poll_once().unwrap();
        assert!(tx.refused().contains(&forged), "refused");
        assert!(rp.decide(&login(), &access).is_permit());
        assert_eq!(pdp.count("/access/v1/evaluation"), 1, "an unverified event changes nothing");

        // A verified one is handed to the PEP, which clears its cache.
        let good = tx.put(POLICIES_CHANGED_EVENT, subject, Some(json!({"pep": "pep-demo", "changed": ["policies"], "sync_token": "p2"})), None, "", "");
        receiver.poll_once().unwrap();
        receiver.poll_once().unwrap();
        assert!(tx.acked().contains(&good));
        assert!(rp.decide(&login(), &access).is_permit());
        assert_eq!(pdp.count("/access/v1/evaluation"), 2, "the event cleared the cache");
    }

    /// Waits up to 10 s for a heartbeat whose `policyEvents` is `want`
    /// (one built before the receiver started can still be on its way).
    fn assert_policy_events(pdp: &Pdp, want: &str) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let last = pdp.bodies("/xacml/pep/heartbeat").last().map(|beat| beat["policyEvents"].clone());
            if last.as_ref().is_some_and(|value| value == want) {
                return;
            }
            assert!(std::time::Instant::now() < deadline, "no heartbeat said {want}; the last said {last:?}");
            thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    struct Errors(Mutex<Vec<String>>);
    impl crate::ssf::SignalsLog for Errors {
        fn info(&self, _: &str) {}
        fn warn(&self, _: &str) {}
        fn error(&self, message: &str) { self.0.lock().unwrap().push(message.to_string()); }
    }

    /// oidc-caep-risc's live run (#46): a stream made while the PEP was
    /// `central` (no event asked for) was found and reused by the `local`
    /// PEP's receiver, so iya-sts never sent it `pep-policies-changed`. A
    /// reused stream now gets the missing type PATCHed in, and the PEP's
    /// heartbeat says `requested`, or `excluded` when the transmitter won't.
    #[test]
    fn a_reused_stream_gets_the_policy_event_added() {
        let pdp = start_pdp();
        let caep = events::event("session_revoked");
        let old = |tx: &Stub, id: &str| json!({
            "stream_id": id, "iss": tx.url, "aud": "my-app",
            "delivery": {"method": "urn:ietf:rfc:8936", "endpoint_url": format!("{}/ssf/poll/{id}", tx.url)},
            "events_requested": [caep], "events_delivered": [caep]
        });
        let errors = Arc::new(Errors(Mutex::new(Vec::new())));
        let receiver_for = |tx: &Stub, rp: &RelyingParty| SignalsReceiver::new(&tx.url, Arc::new(|_, _| Ok(())), ReceiverOptions {
            poll_interval_ms: 60_000,
            log: Some(errors.clone() as Arc<dyn crate::ssf::SignalsLog>),
            pep: rp.pep().cloned(),
            ..ReceiverOptions::default()
        }).unwrap();
        // The section's signals false makes the PEP start out reporting
        // `none`: a `requested` heartbeat can only come from the receiver.
        let rp = create(json!({"pep": pep_section(pdp, "reuse", json!({"permitCacheMs": 30000, "heartbeatIntervalMs": 1000, "signals": false}))})).unwrap();
        let tx = Stub::new();
        tx.add_stream(old(&tx, "old"));
        let receiver = receiver_for(&tx, &rp);
        let _stop = Stop(receiver.clone());
        receiver.start().unwrap();
        assert_eq!(tx.created(), 0, "the stream was reused, not made again");
        let patches = tx.patches();
        assert_eq!(patches.len(), 1, "{patches:?}");
        assert_eq!(patches[0]["stream_id"], "old");
        let asked: Vec<&str> = patches[0]["events_requested"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
        assert!(asked.contains(&caep), "what it asked for before is kept: {asked:?}");
        assert!(asked.contains(&POLICIES_CHANGED_EVENT), "the policy event is added: {asked:?}");
        let stream = receiver.stream();
        assert!(stream["events_delivered"].as_array().unwrap().iter().any(|e| e == POLICIES_CHANGED_EVENT));
        assert_eq!(stream["delivery"]["endpoint_url"], format!("{}/ssf/poll/old", tx.url), "the delivery the listing gave is kept");
        assert!(errors.0.lock().unwrap().is_empty(), "{:?}", errors.0.lock().unwrap());
        assert_policy_events(pdp, "requested");
        receiver.stop();

        // Nothing missing: no PATCH.
        let again = receiver_for(&tx, &rp);
        let _stop_again = Stop(again.clone());
        again.start().unwrap();
        again.stop();
        assert_eq!(tx.patches().len(), 1, "a stream that already carries the event is left alone");

        // A transmitter that refuses: the receiver still starts, says so,
        // and the PEP's heartbeat reports the event excluded.
        let tx = Stub::new();
        tx.refuse_patch();
        tx.add_stream(old(&tx, "fixed"));
        let refused = receiver_for(&tx, &rp);
        let _stop_refused = Stop(refused.clone());
        refused.start().unwrap();
        assert_eq!(tx.patches().len(), 1);
        assert!(errors.0.lock().unwrap().iter().any(|l| l.contains("answered 405")), "{:?}", errors.0.lock().unwrap());
        let pep = rp.pep().cloned().unwrap();
        assert_eq!(pep.status().event_stream, crate::pep::EventStream::Excluded, "running, and the stream does not carry the event");
        assert_policy_events(pdp, "excluded");
        refused.stop();
        assert_eq!(pep.status().event_stream, crate::pep::EventStream::Down, "a stopped receiver hears nothing");
    }

    /// The PEP's view of the stream follows the receiver's polls: a failed
    /// poll is `down` (the PEP then polls its own policies), the next good
    /// one is what the stream carries again, and `stop` is `down`.
    #[test]
    fn the_peps_stream_state_follows_the_polls() {
        let pdp = start_pdp();
        let rp = create(json!({"pep": pep_section(pdp, "polls", json!({"permitCacheMs": 30000, "signals": true}))})).unwrap();
        let tx = Stub::new();
        let receiver = SignalsReceiver::new(&tx.url, Arc::new(|_, _| Ok(())), ReceiverOptions {
            poll_interval_ms: 60_000,
            pep: rp.pep().cloned(),
            ..ReceiverOptions::default()
        }).unwrap();
        let _stop = Stop(receiver.clone());
        let pep = rp.pep().cloned().unwrap();
        assert_eq!(pep.status().event_stream, crate::pep::EventStream::Down, "signals on, and nothing reported before the receiver starts");
        receiver.start().unwrap();
        assert_eq!(pep.status().event_stream, crate::pep::EventStream::Requested);
        tx.fail_polls(503);
        assert!(receiver.poll_once().is_err());
        assert_eq!(pep.status().event_stream, crate::pep::EventStream::Down, "a failed poll: down");
        tx.fail_polls(0);
        receiver.poll_once().unwrap();
        assert_eq!(pep.status().event_stream, crate::pep::EventStream::Requested, "a good poll: what the stream carries");
        receiver.stop();
        assert_eq!(pep.status().event_stream, crate::pep::EventStream::Down);
    }

    #[test]
    fn the_demo_route_needs_a_sign_in() {
        let pdp = start_pdp();
        let rp = create(json!({"pep": pep_section(pdp, "demo", json!({}))})).unwrap();
        let app = crate::demo::App::new(rp, None);
        let (status, _, _) = app.handle("GET", "/orders/42", &HashMap::new(), b"");
        assert_eq!(status, 401);
        assert_eq!(pdp.count("/access/v1/evaluation"), 0);
    }

    #[cfg(feature = "local")]
    #[test]
    fn local_mode_fails_closed_then_decides_in_process() {
        let pdp = start_pdp();
        pdp.policies_up.store(false, Ordering::SeqCst);
        let rp = create(json!({"signals": false, "pep": pep_section(pdp, "local", json!({"mode": "local", "pollIntervalMs": 1000}))})).unwrap();
        assert!(matches!(rp.decide(&login(), &Access::new("read", "order", "42")), Decision::Unavailable { .. }), "no policy held yet");

        pdp.policies_up.store(true, Ordering::SeqCst);
        let pep = rp.pep().unwrap();
        let held = (0..50).any(|_| {
            thread::sleep(std::time::Duration::from_millis(100));
            pep.status().holds_policy
        });
        assert!(held, "the poll (signals: false, pollIntervalMs) pulled once the service answered");
        assert!(rp.decide(&login(), &Access::new("read", "order", "42")).is_permit());
        assert!(matches!(rp.decide(&login(), &Access::new("write", "order", "42")), Decision::Deny { .. }));
        assert_eq!(pdp.count("/access/v1/evaluation"), 0, "decided in process");
        assert!(pdp.count("/xacml/pep/policies") > 0);
    }

    /// A `pep` section that names no mode is `local`: the PEP pulls the
    /// application's policies and decides in process.
    #[cfg(feature = "local")]
    #[test]
    fn a_section_without_a_mode_is_local() {
        let pdp = start_pdp();
        let mut section = pep_section(pdp, "default-mode", json!({}));
        section.as_object_mut().unwrap().remove("mode");
        let rp = create(json!({"signals": false, "pep": section})).unwrap();
        assert_eq!(rp.pep().unwrap().status().mode, crate::pep::Mode::Local);
    }
}
