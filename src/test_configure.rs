// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#[test]
fn configure_signals_behavior() {
    let root = env!("CARGO_MANIFEST_DIR");
    let script_dir = format!("{root}/scripts");
    let dir = std::env::temp_dir().join(format!("wsfed-configure-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let base = "{\n  \"realm\": \"http://localhost:3000/\",\n  \"replyUrl\": \"http://localhost:3000/wsfed\",\n  \"privateKey\": \"generated/rp.key\",\n  \"certificate\": \"generated/rp.crt\",\n  \"idpMetadata\": \"generated/idp-metadata.xml\",\n  \"idpCa\": \"generated/idp-ca.pem\"\n}";
    let write = |name: &str, body: &str| {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        path
    };
    let config = write("wsfed.json", base);
    let with_ssf = write("wsfed-ssf.json", &base.replacen("\n}", ",\n  \"ssf\": {\"transmitter\": \"https://localhost:8081\"}\n}", 1));
    let off = write("off.json", &base.replacen("\n}", ",\n  \"signals\": false,\n  \"ssf\": {\"transmitter\": \"https://localhost:8081\"}\n}", 1));
    let on = write("on.json", &base.replacen("\n}", ",\n  \"signals\": true,\n  \"ssf\": {\"transmitter\": \"https://localhost:8081\"}\n}", 1));
    let bad = write("bad.json", &base.replacen("\n}", ",\n  \"signals\": \"no\"\n}", 1));
    let code = r#"
import json, sys
sys.path.insert(0, sys.argv[1])
from configure_iya_sts import files_of, plan_for
base, with_ssf, off, on, bad = sys.argv[2:]
files = files_of(base)
ssf = files_of(with_ssf)
assert any(call["path"].endswith("/applications/add-certificate") for call in plan_for(ssf, "https://localhost:8081", ""))
assert not any(call["path"].endswith("/applications/add-certificate") for call in plan_for(files, "https://localhost:8081", ""))
off_files = files_of(off)
assert off_files["signals"] is False
assert off_files["ssf_transmitter"] == "https://localhost:8081"
assert off_files["realm"] == "http://localhost:3000/"
assert off_files["reply_url"] == "http://localhost:3000/wsfed"
assert not any(call["path"].endswith("/applications/add-certificate") for call in plan_for(off_files, "https://localhost:8081", ""))
assert not any(call["path"].endswith("/roles/add-member") for call in plan_for(off_files, "https://localhost:8081", ""))
assert "signals" not in files_of(on)
assert any(call["path"].endswith("/applications/add-certificate") for call in plan_for(files_of(on), "https://localhost:8081", ""))
try:
    files_of(bad)
except ValueError as err:
    assert str(err) == "signals must be true or false", str(err)
else:
    raise SystemExit("signals string was accepted")
print("ok")
"#;
    let output = std::process::Command::new("python3")
        .arg("-c")
        .arg(code)
        .arg(&script_dir)
        .arg(&config)
        .arg(&with_ssf)
        .arg(&off)
        .arg(&on)
        .arg(&bad)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout).to_string() + &String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{text}");
    assert!(text.contains("ok"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The install script's attribute-protected half (#40): the policy's new
/// rule, the test user's attr1, the admin:security token asked for only
/// that one call, the operator told what to do only when attr1 is truly
/// missing, and the application's policy rewritten only while it is the
/// script's own.
#[test]
fn configure_attribute_protected() {
    let root = env!("CARGO_MANIFEST_DIR");
    let script_dir = format!("{root}/scripts");
    let dir = std::env::temp_dir().join(format!("wsfed-configure-attr-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("generated")).unwrap();
    std::fs::write(dir.join("generated/pep-key.pem"), "not read: the key is kept").unwrap();
    let config = dir.join("wsfed.json");
    std::fs::write(&config, "{\"realm\": \"http://localhost:3000/\", \"replyUrl\": \"http://localhost:3000/wsfed\", \"privateKey\": \"generated/rp.key\", \"certificate\": \"generated/rp.crt\", \"idpMetadata\": \"generated/idp-metadata.xml\"}").unwrap();
    let code = r#"
import contextlib, io, json, sys
sys.path.insert(0, sys.argv[1])
import configure_iya_sts as c
config = sys.argv[2]

alfa = c.orders_policy()
assert 'attribute attr1 { category = subjectCat id = "urn:sts:xacml:attribute:attr1" type = string }' in alfa, alfa
rule = alfa[alfa.index("rule readAttributeProtected"):alfa.index("rule otherwise")]
for clause in ('act == "read"', 'rtype == "attribute-protected"', 'attr1 == "abc123"'):
    assert clause in rule, rule
assert alfa.index("rule readAttributeProtected") < alfa.index("rule otherwise"), "before the catch-all deny"
assert 'id = "urn:example:wsfeddemo-orders"' in alfa and "urn:example:wsfeddemo-orders" in c.OWN_POLICY_IDS
assert "urn:example:wsfeddemolocked-orders" not in c.OWN_POLICY_IDS, "the live run's flipped policy is not rewritten"
assert "rule readAttributeProtected" in c.orders_policy("wsfeddemolocked", "deny")

plan = c.plan_for(c.files_of(config), "https://sts/realm/r", "demo-user")
paths = [call["path"] for call in plan]
assert paths[-2].endswith("/policies/define-person-attribute") and paths[-1].endswith("/users/set-attribute"), paths
assert plan[-1]["body"] == {"user": "demo-user", "attribute": "attr1", "value": "abc123"}
assert not any(p.endswith("set-attribute") for p in [call["path"] for call in c.plan_for(c.files_of(config), "https://sts/realm/r", "")])

def fake(define, setting):
    seen = []
    def api(path, body, security=False):
        seen.append((path, security))
        answer = define if path == "/policies/define-person-attribute" else setting
        if isinstance(answer, Exception):
            raise answer
        return answer
    return api, seen

def run(define, setting):
    api, seen = fake(define, setting)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        held = c.set_test_attribute(api, "demo-user")
    return held, seen, out.getvalue()

ok = {"status": 200, "body": {"ok": True}}
held, seen, said = run(ok, ok)
assert held and seen == [("/policies/define-person-attribute", True), ("/users/set-attribute", False)], seen
assert "demo-user has attr1=abc123" in said, said
refused = RuntimeError('POST .../policies/define-person-attribute answered 403: {"errors": ["Only a Security Administrator may make this change"]}')
held, _, said = run(refused, ok)
assert held and "Security Administrator" not in said, "defined already: no instructions: " + said
held, _, said = run(refused, {"status": 200, "body": {"ok": False, "errors": ["attr1 is not an attribute of this realm"]}})
assert not held and "Directory > Policies > Attribute policy > Custom" in said and "SECURITY_ADMIN" in said, said
held, _, _ = run({"status": 200, "body": {"ok": False, "errors": ["attr1 already exists"]}}, ok)
assert held, "already defined is fine"
try:
    run({"status": 400, "body": {"ok": False, "errors": ["syntax must be one of"]}}, ok)
except RuntimeError as err:
    assert "refused (400)" in str(err)
else:
    raise SystemExit("an unexpected refusal was swallowed")

def setup(fga):
    calls = []
    def api(path, body, security=False):
        calls.append((path, body))
        return {"status": 200, "body": {"ok": True}}
    def get(path):
        if path.startswith("/users?"):
            return {"known": True}
        return {"page": {"fga": fga, "attributes": {}}}
    with contextlib.redirect_stdout(io.StringIO()):
        c.setup_pep(api, get, c.files_of(config), config, "pep-x", "local")
    return [path for path, _ in calls], calls

own = {"enforced": True, "policy": {"name": "app-policy", "policyId": "urn:example:wsfeddemo-orders"}}
paths, calls = setup(own)
assert "/xacml/import-alfa" in paths and "/applications/fga-create-policy" not in paths, paths
assert next(body for path, body in calls if path == "/xacml/import-alfa")["name"] == "app-policy"
paths, _ = setup({"enforced": True, "policy": {"name": "theirs", "policyId": "urn:example:someone-elses"}})
assert "/xacml/import-alfa" not in paths, "another PolicyId is left alone: " + str(paths)
assert json.load(open(config))["pep"]["mode"] == "local"
print("ok")
"#;
    let output = std::process::Command::new("python3").arg("-c").arg(code).arg(&script_dir).arg(&config).output().unwrap();
    let text = String::from_utf8_lossy(&output.stdout).to_string() + &String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{text}");
    assert!(text.contains("ok"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}
