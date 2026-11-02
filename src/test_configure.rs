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
