#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The embedded Remote PEP's AuthZEN table, live: central and local must agree (#40).

src/test_authzen.json is this library's own table: the catalogue rows, the
policies (ALFA), the directory people, and the evaluation cases with the answer
each must get. This script gives a fresh iya-sts all of it and runs every case
through two RelyingParty instances, one with a `central` PEP and one with a
`local` PEP, inside a rust:1-bookworm container (`cargo test --features local
--lib authzen_live`; Cargo never runs on the host). The Rust test fails when
central and local disagree on any case, or either differs from the table.

The order:
  1. iya-sts starts from IYA_STS_IMAGE (or builds main, as live_iya_sts.py
     does), on LIVE_STS_PORT (18517), as iya-sts-live-wsfed-caep-rust-authzen.
  2. The relying party is registered as a WS-Federation application; its realm
     is the application the PEPs are bound to. The IdP metadata and the
     listener chain are saved to a scratch directory.
  3. The directory people, the catalogue rows and the policies go in through
     /admin-api: import-alfa, add-policy-reference, set-root.
  4. TWO service accounts in remote-peps, `central` and `local`, each with a
     P-256 key made here (0600, never printed), certified with
     issue-pep-credential bound to the application.
  5. Phase `root`: the Rust test runs the root cases.
  6. Phase `application`: the application's own fine-grained authorization
     policy becomes a PolicySet referencing another policy, and the
     application enforces it (fga-enable). The Rust test runs those cases.
  7. The last thing printed is JSON: cases run, equal, as expected, mismatches.

--compile writes src/test_authzen_policies.json from the table's ALFA with
iya-sts's own compiler (xacml_alfa and xacml_xml in IYA_STS_IMAGE), adding each
`references` entry as a PolicyIdReference the way the editor's
add-policy-reference does. The offline run reads that file. The live run checks
that iya-sts stores the same documents.

Never binds 3000, 8081 or 18481 to 18495. No secret, password or key is
printed; the admin secret reaches docker run as -e NAME.
"""

import json
import re
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import live_iya_sts as live  # noqa: E402
from trust_chain import save_trust_chain  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TABLE = ROOT / "src" / "test_authzen.json"
COMPILED = ROOT / "src" / "test_authzen_policies.json"
STS_NAME = "iya-sts-live-wsfed-caep-rust-authzen"
CARGO_VOLUME = "iya-pep-cargo"
RUST_IMAGE = "rust:1-bookworm"
PEPS = {"central": "pep-wsfed-authzen-central", "local": "pep-wsfed-authzen-local"}
APPLICATION_POLICY = "{{application-policy}}"

# Reads the table on stdin and writes {name: {policyId, kind, version, document}}.
COMPILER = r"""
const alfa = require('/usr/src/sts/xacml/xacml_alfa');
const xml = require('/usr/src/sts/xacml/xacml_xml');
let text = '';
process.stdin.on('data', (chunk) => { text += chunk; });
process.stdin.on('end', () => {
  const table = JSON.parse(text);
  const out = {};
  for (const one of table.policies) {
    const model = alfa.parse(one.alfa.join('\n'));
    for (const ref of one.references || []) {
      model.children.push({ kind: 'PolicyIdReference', ref: ref, version: null });
    }
    out[one.name] = { policyId: model.id, kind: model.kind, version: model.version,
                      document: xml.writePolicy(model) };
  }
  process.stdout.write('@@COMPILED@@' + JSON.stringify(out) + '\n');
});
"""


def sts_image():
    image = os.environ.get("IYA_STS_IMAGE", "")
    if image:
        return image
    cloned = tempfile.mkdtemp(prefix="iya-sts-main-")
    try:
        live.run(["git", "clone", "--depth", "1", "--branch", "main", live.STS_REPO, cloned])
        live.run(["git", "-C", cloned, "submodule", "update", "--init", "--recursive"])
        live.docker("build", "-t", "iya-sts-live:main", cloned)
    finally:
        shutil.rmtree(cloned, ignore_errors=True)
    return "iya-sts-live:main"


def compile_policies(image, table):
    """The table's ALFA as XACML, by iya-sts's own compiler."""
    completed = subprocess.run(
        ["docker", "run", "--rm", "-i", "--entrypoint", "node", image, "-e", COMPILER],
        input=json.dumps(table), text=True, capture_output=True, check=False,
    )
    marked = [line for line in completed.stdout.splitlines() if line.startswith("@@COMPILED@@")]
    if completed.returncode != 0 or not marked:
        print(completed.stderr[-2000:], file=sys.stderr)
        raise RuntimeError("iya-sts's ALFA compiler refused the table's policies")
    return json.loads(marked[-1][len("@@COMPILED@@"):])


def write_compiled(image):
    table = json.loads(TABLE.read_text(encoding="utf-8"))
    compiled = compile_policies(image, table)
    COMPILED.write_text(json.dumps({
        "about": "Generated by python3 scripts/live_authzen.py --compile from src/test_authzen.json's ALFA, "
                 "with iya-sts's xacml_alfa and xacml_xml. Do not edit by hand.",
        "policies": compiled,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {COMPILED.relative_to(ROOT)} ({len(compiled)} policies)", flush=True)


def start_sts(image, port, secret):
    """A fresh iya-sts, as live_iya_sts.py starts one, under this script's own name."""
    given = os.environ.get("IYA_STS_URL", "").rstrip("/")
    if given:
        print("using the iya-sts IYA_STS_URL names", flush=True)
        return given, None
    live.docker_rm(STS_NAME)
    env = os.environ.copy()
    env["STS_ADMIN_API_CLIENT_SECRET"] = secret
    live.docker(
        "run", "-d", "--name", STS_NAME,
        "-e", f"STS_PORT={port}",
        "-e", "STS_PERSISTENCE_MODE=memory",
        "-e", "STS_CLUSTER_MODE=off",
        "-e", "STS_WORKERS_REQUEST_COUNT=0",
        "-e", "STS_WORKERS_SURFACE_COUNT=0",
        "-e", "STS_ADMIN_API_CLIENT_SECRET",
        "-e", "STS_LOG_LEVEL=info",
        "-p", f"127.0.0.1:{port}:{port}",
        image,
        env=env,
    )
    return f"https://127.0.0.1:{port}", STS_NAME


class Admin:
    """/admin-api with a token minted from the admin client secret."""

    def __init__(self, client, origin, token):
        self.client, self.origin, self.token = client, origin, token

    def get(self, path):
        status, parsed = live.admin_json(self.client, self.origin, self.token, "GET", path)
        if status != 200:
            raise RuntimeError(f"GET {path.split('?')[0]} answered {status}: {json.dumps(parsed)[:400]}")
        return parsed

    def post(self, path, body, what, tolerate=()):
        status, parsed = live.admin_json(self.client, self.origin, self.token, "POST", path, body)
        refused = status != 200 or parsed.get("ok") is False
        said = json.dumps(parsed)
        if refused and not any(word in said for word in tolerate):
            raise RuntimeError(f"{what}: POST {path} answered {status}: {said[:600]}")
        print(f"{what}: {status}{' (already so)' if refused else ''}", flush=True)
        return parsed


def make_pep_key(path, name, work):
    """A P-256 key (0600, never printed) and its certificate request."""
    old = os.umask(0o077)
    try:
        made = subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(path)],
                              check=False, capture_output=True, text=True)
    finally:
        os.umask(old)
    if made.returncode != 0:
        raise RuntimeError("openssl could not make a PEP key")
    # The cargo container reads it as another user.
    os.chmod(path, 0o644)
    csr = work / f"{name}.csr"
    asked = subprocess.run(["openssl", "req", "-new", "-key", str(path), "-subj", f"/CN={name}", "-out", str(csr)],
                           check=False, capture_output=True, text=True)
    if asked.returncode != 0:
        raise RuntimeError("openssl could not make a certificate request")
    return csr.read_text(encoding="utf-8")


def alfa_of(policy, application):
    return "\n".join(policy["alfa"]).replace("{{application}}", application)


def stored_document(admin, name):
    """The XACML iya-sts stores under `name`, from the editor view, or None."""
    view = admin.get("/admin-api/xacml/editor?policy=" + urllib.parse.quote(name))
    found = []

    def walk(value):
        if isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, str) and value.lstrip().startswith("<?xml") and ("<Policy" in value):
            found.append(value)

    walk(view)
    return found[0] if found else None


def check_stored(admin, compiled, table_name, stored_name, application):
    """Whether iya-sts stores the document the offline run serves."""
    want = compiled[table_name]["document"].replace("{{application}}", application)
    got = stored_document(admin, stored_name)
    if got is None:
        return "not shown"
    return "same" if got.strip() == want.strip() else "different"


def provision_common(admin, table, application, reply_url):
    admin.post("/admin-api/applications/create", {
        "identifier": application, "name": "wsfed-caep-rust AuthZEN", "protocols": ["wsfed"],
        "fields": {"wsfedRealm": [application], "wsfedReplyUrl": [reply_url]},
    }, "the relying party's application")
    for person in table["directory"]:
        attributes = {"cn": person["username"], "sn": "AuthZEN", "displayName": person["username"], **person["attributes"]}
        made = admin.post("/admin-api/users/create", {"username": person["username"], "invent": False,
                                                      "credential": "generate", "attributes": attributes},
                          "a directory person for the PIP")
        made.pop("password", None)
    for row in table["catalogue"]:
        admin.post("/admin-api/xacml/authzen/set-attribute", row, "a catalogue row")


def provision_peps(admin, application, work):
    keys = {}
    for mode, name in PEPS.items():
        admin.post("/admin-api/users/create", {
            "username": name, "invent": False, "credential": "none", "serviceAccount": True,
            "owners": ["admin-write"], "attributes": {"cn": name, "displayName": name},
        }, f"the {mode} PEP's service account")
        admin.post("/admin-api/groups/add-member", {"group": "remote-peps", "member": name}, f"the {mode} PEP in remote-peps")
        key = work / f"{name}.pem"
        csr = make_pep_key(key, name, work)
        admin.post("/admin-api/xacml/issue-pep-credential", {"name": name, "csr": csr, "application": application},
                   f"the {mode} PEP's key certified and bound to the application")
        keys[mode] = {"name": name, "key": str(key)}
    return keys


def provision_root(admin, table, compiled, application):
    checks = {}
    for policy in table["policies"]:
        if policy["role"] == "application":
            continue
        admin.post("/admin-api/xacml/import-alfa", {"name": policy["name"], "alfa": alfa_of(policy, application)},
                   f"the policy {policy['name']}")
        checks[policy["name"]] = check_stored(admin, compiled, policy["name"], policy["name"], application)
    root = next(p for p in table["policies"] if p["role"] == "root")
    admin.post("/admin-api/xacml/set-root", {"name": root["name"]}, "the realm root")
    return checks


def provision_application(admin, table, compiled, application):
    """The application's own policy: the table's PolicySet, its references
    added as the editor adds them, then enforced."""
    policy = next(p for p in table["policies"] if p["role"] == "application")
    page = admin.get("/admin-api/applications?application=" + urllib.parse.quote(application, safe=""))
    name = (((page.get("page") or {}).get("fga") or {}).get("policy") or {}).get("name")
    if not name:
        admin.post("/admin-api/applications/fga-create-policy", {"application": application}, "the application's own policy")
        page = admin.get("/admin-api/applications?application=" + urllib.parse.quote(application, safe=""))
        name = page["page"]["fga"]["policy"]["name"]
    admin.post("/admin-api/xacml/import-alfa", {"name": name, "alfa": alfa_of(policy, application)},
               "the application's own policy, rewritten")
    for ref in policy.get("references") or []:
        admin.post("/admin-api/xacml/add-policy-reference", {"policy": name, "path": "", "ref": ref},
                   "a PolicyIdReference in the application's policy")
    admin.post("/admin-api/applications/fga-enable", {"application": application}, "the application enforces it")
    page = admin.get("/admin-api/applications?application=" + urllib.parse.quote(application, safe=""))
    fga = page["page"]["fga"]
    if not fga.get("enforced"):
        raise RuntimeError(f"the application does not enforce: {json.dumps(fga)[:400]}")
    return {APPLICATION_POLICY: check_stored(admin, compiled, APPLICATION_POLICY, name, application)}


def sts_evidence(name):
    """iya-sts's own error lines about AuthZEN, XACML and fine-grained
    authorization, for a mismatch's report; URLs are blanked."""
    logs = subprocess.run(["docker", "logs", name], check=False, text=True, capture_output=True)
    wanted = ("STS-AUTHZEN-", "STS-FGA-", "STS-XACML-0013", "nresolved")
    lines = [line for line in (logs.stdout + logs.stderr).splitlines() if any(word in line for word in wanted)]
    return [re.sub(r"https?://\S+", "<url>", line)[:400] for line in lines[-12:]]


def run_phase(phase, described, work):
    """The Rust test for one phase, in rust:1-bookworm on the host network."""
    (work / f"live-{phase}.json").write_text(json.dumps({**described, "phase": phase}), encoding="utf-8")
    name = "wsfed-caep-rust-authzen-cargo"
    live.docker_rm(name)
    completed = subprocess.run([
        "docker", "run", "--rm", "--name", name, "--network", "host",
        "-v", f"{ROOT}:/src", "-w", "/src",
        "-v", f"{CARGO_VOLUME}:/cargo", "-e", "CARGO_HOME=/cargo", "-e", "CARGO_TARGET_DIR=/src/target/authzen-live",
        "-v", f"{work}:{work}", "-e", f"WSFED_AUTHZEN_LIVE={work / f'live-{phase}.json'}",
        RUST_IMAGE, "cargo", "test", "--features", "local", "--lib", "test_authzen::authzen_live", "--", "--exact", "--nocapture",
    ], check=False, text=True, capture_output=True)
    print(f"phase {phase}: the Rust test exited {completed.returncode}", flush=True)
    marked = [line for line in completed.stdout.splitlines() + completed.stderr.splitlines() if line.startswith("@@AUTHZEN@@")]
    if not marked:
        print(completed.stdout[-3000:], flush=True)
        print(completed.stderr[-3000:], file=sys.stderr, flush=True)
        raise RuntimeError(f"phase {phase}: the Rust test reported nothing")
    return json.loads(marked[-1][len("@@AUTHZEN@@"):])


def main():
    if "--compile" in sys.argv[1:]:
        write_compiled(sts_image())
        return
    sts_port = int(os.environ.get("LIVE_STS_PORT") or 18517)
    demo_port = int(os.environ.get("LIVE_DEMO_PORT") or 18617)
    if sts_port in live.FORBIDDEN_PORTS or demo_port in live.FORBIDDEN_PORTS or sts_port == demo_port:
        raise SystemExit("LIVE_STS_PORT and LIVE_DEMO_PORT must not be 3000, 8081, or 18481 to 18495")
    table = json.loads(TABLE.read_text(encoding="utf-8"))
    compiled = json.loads(COMPILED.read_text(encoding="utf-8"))["policies"]
    secret = os.environ.get("ADMIN_API_CLIENT_SECRET") or os.environ.get("STS_ADMIN_API_CLIENT_SECRET") or secrets.token_urlsafe(24)
    image = sts_image() if not os.environ.get("IYA_STS_URL") else ""
    work = Path(tempfile.mkdtemp(prefix="wsfed-caep-rust-authzen-"))
    os.chmod(work, 0o755)
    sts_name = None
    try:
        origin, sts_name = start_sts(image, sts_port, secret)
        live.wait_port(urllib.parse.urlsplit(origin).port or 443, 120)
        live.wait_ready(origin, 90)
        ca_file = work / "idp-ca.pem"
        chain = save_trust_chain(origin, str(ca_file))
        print(f"saved iya-sts's listener chain ({chain['count']} certificates)", flush=True)
        client = live.Client(ca_file)
        admin = Admin(client, origin, live.mint_admin(client, origin, secret))
        # The realm and reply URL are names only: nothing listens on the demo port.
        application = f"http://127.0.0.1:{demo_port}/authzen/"
        reply_url = application + "wsfed"
        provision_common(admin, table, application, reply_url)
        status, _headers, metadata = client.request(
            "GET", f"{origin}/wsfed/metadata/{urllib.parse.quote(application, safe='')}",
            headers={"accept": "application/samlmetadata+xml"})
        if status != 200:
            raise RuntimeError(f"the IdP metadata answered {status}")
        (work / "idp-metadata.xml").write_bytes(metadata)
        stored = provision_root(admin, table, compiled, application)
        peps = provision_peps(admin, application, work)
        described = {"application": application, "replyUrl": reply_url, "idpMetadata": str(work / "idp-metadata.xml"),
                     "idpCa": str(ca_file), "peps": peps}
        results = [run_phase("root", described, work)]
        stored.update(provision_application(admin, table, compiled, application))
        results.append(run_phase("application", described, work))
        mismatches = [m for r in results for m in r["mismatches"]]
        summary = {
            "ok": not mismatches,
            "cases": sum(r["cases"] for r in results),
            "equal": sum(r["equal"] for r in results),
            "asExpected": sum(r["asExpected"] for r in results),
            "phases": {r["phase"]: {"cases": r["cases"], "equal": r["equal"], "asExpected": r["asExpected"]} for r in results},
            "storedDocuments": stored,
            "mismatches": [{key: m[key] for key in ("case", "phase", "central", "local", "expected", "centralWhy", "localWhy")} for m in mismatches],
        }
        if mismatches and sts_name:
            summary["stsLog"] = sts_evidence(sts_name)
        print(json.dumps(summary, indent=2), flush=True)
        if mismatches:
            sys.exit(1)
    finally:
        if sts_name:
            live.docker_rm(sts_name)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(str(err), file=sys.stderr)
        sys.exit(1)
