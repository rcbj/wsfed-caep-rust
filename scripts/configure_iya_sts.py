#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Register the demo with a running iya-sts as a WS-Federation relying party.

The plan (what would be registered, and where) is pure and is what the tests call. Sending it needs
ADMIN_API_CLIENT_SECRET or STS_ADMIN_API_CLIENT_SECRET and a reachable identity provider.

  python scripts/configure_iya_sts.py --idp https://localhost:8081 --config demo/wsfed.json
  python scripts/configure_iya_sts.py --dry-run

A loopback realm and reply URL follow the port the demo listens on. The container's PORT wins over
the shell PORT. An explicit --public-url or PUBLIC_URL replaces the origin and keeps the path.
``signals: false`` skips Shared Signals registration even when an ssf block is present.

--pep [central|local] (local when left out) also sets the demo up with its embedded PEP, as docs/remote-pep.md's steps 2 to
6 describe: the PEP's service account in remote-peps, a P-256 key made here with openssl
(generated/pep-key.pem beside the configuration, 0600, never printed, kept out of the image by
.dockerignore), issue-pep-credential binding it to the demo's application, the catalogue row the
demo's policy reads (subject.acr), the application's OWN policy, which it then enforces (never the
realm root), and a `pep` section in the configuration. Run it again to switch the mode: the
account and the key are kept, and the policy is written again with the current rules while it
is this script's own (OWN_POLICY_IDS); a policy under another PolicyId is left alone. The test
user is given attr1=abc123 (a custom attribute, defined with an admin:security token), which
GET /attribute-protected is decided on.

Every run writes iya-sts's listener CA trust chain (leaf, TLS Issuing CA, Intermediate, Root) to the
file idpCa names, through scripts/trust_chain.py. The demo image build copies that file in, so
rebuild the image after running this against a different iya-sts.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

LOOPBACK = {"localhost", "127.0.0.1", "::1"}
MULTIPLE_ACCOUNTS = {"key": "authn.multipleAccounts", "value": True}
ROOT = Path(__file__).resolve().parent.parent

# The embedded PEP (--pep). The key's path is relative to the configuration's directory, which is
# also how the `pep` section names it: this library resolves assertionKey like privateKey.
PEP_MODES = ("central", "local")
PEP_NAME = "pep-wsfed-demo"
PEP_KEY = "generated/pep-key.pem"
PEP_KEY_IN_SECTION = "file:generated/pep-key.pem"
PEP_GROUP = "remote-peps"
PEP_EVENT = "urn:iya:sts:secevent:event-type:pep-policies-changed"
ACR_ATTRIBUTE = "urn:example:acr"
# The demo's attribute-protected resource (GET /attribute-protected): the test user carries a custom
# directory attribute, and the demo application's own policy permits the resource only to a person
# whose attr1 is abc123. The PEP asks iya-sts's PIP for it (POST /xacml/pip): it is a directory
# attribute, never a claim of the assertion.
TEST_ATTRIBUTE = "attr1"
TEST_ATTRIBUTE_VALUE = "abc123"
TEST_ATTRIBUTE_ID = "urn:sts:xacml:attribute:" + TEST_ATTRIBUTE
ATTRIBUTE_PROTECTED = "attribute-protected"
# The PolicyIds of the policies this script writes. While the demo application enforces one of
# these, a run writes the current version over it; a policy an administrator wrote under another
# PolicyId is left alone.
OWN_POLICY_IDS = ("urn:example:wsfeddemo-orders",)


def orders_policy(namespace: str = "wsfeddemo", read_effect: str = "permit") -> str:
    """ALFA for the demo application's own policy, the one its fine-grained authorization decisions
    are made with (GET /orders/<id> is read, anything else write):
    - read on an order is `read_effect`; a permit also needs the sign-in's acr (the assertion's
      AuthnContextClassRef), which only the catalogue row brings, so a 200 shows the claim arrived;
    - read on the attribute-protected resource is permitted when the person's directory attribute
      attr1 is abc123, which the PEP asks iya-sts's PIP for;
    - everything else is denied."""
    condition = "            condition integerGreaterThan(stringBagSize(acr), 0)\n" if read_effect == "permit" else ""
    return (
        f"namespace {namespace} {{\n"
        '    attribute act { category = actionCat id = "urn:oasis:names:tc:xacml:1.0:action:action-id" type = string }\n'
        '    attribute rtype { category = resourceCat id = "urn:sts:xacml:authzen:resource-type" type = string }\n'
        f'    attribute acr {{ category = subjectCat id = "{ACR_ATTRIBUTE}" type = string }}\n'
        f'    attribute {TEST_ATTRIBUTE} {{ category = subjectCat id = "{TEST_ATTRIBUTE_ID}" type = string }}\n'
        f"    policy {namespace}Orders {{\n"
        f'        id = "urn:example:{namespace}-orders"\n'
        "        apply firstApplicable\n"
        "        rule readOrder {\n"
        f"            {read_effect}\n"
        '            target clause act == "read" and rtype == "order"\n'
        f"{condition}"
        "        }\n"
        "        rule readAttributeProtected {\n"
        "            permit\n"
        '            target clause act == "read"\n'
        f'            target clause rtype == "{ATTRIBUTE_PROTECTED}"\n'
        f'            target clause {TEST_ATTRIBUTE} == "{TEST_ATTRIBUTE_VALUE}"\n'
        "        }\n"
        "        rule otherwise {\n"
        "            deny\n"
        "        }\n"
        "    }\n"
        "}\n"
    )

sys.path.insert(0, str(Path(__file__).resolve().parent))
from trust_chain import save_trust_chain  # noqa: E402


def usage() -> str:
    return """Usage: python scripts/configure_iya_sts.py [--config path] [--idp url] [--public-url url]
                                        [--test-user name | --no-test-user]
                                        [--pep [central|local]] [--pep-name name] [--dry-run]

  --config        The demo's WS-Federation configuration (default: demo/wsfed.json)
  --idp           iya-sts's base URL; the realm's, e.g. https://host/realm/acme, for a trust realm
                  (default: $IYA_STS_URL or https://localhost:8081)
  --public-url    Replace the origin of the file's realm and reply URL with this URL, and keep
                  their paths (default: unset; $PUBLIC_URL). Without it, a loopback realm and
                  reply URL follow the running demo's PORT, then $PORT. Any other host is left
                  as written.
  --test-user     The test user to create (default: wsfed-demo-user). Its password is
                  $WSFED_DEMO_USER_PASSWORD, or one is generated and written to
                  generated/<user>.password beside the configuration (mode 0600); only the
                  path is printed.
  --no-test-user  Do not create a test user.
  --pep [MODE]    Also set up the demo's embedded PEP in this mode, local (the default: it caches
                  the application's policies and decides in process) or central: its service
                  account, its key (generated/pep-key.pem beside the configuration, 0600, made
                  with openssl), its binding to the demo's application, the catalogue row and
                  the application's own policy (enforced), and a `pep` section written into the
                  configuration. Run it again with the other mode to switch; the account and
                  the key are kept, and the script's own policy (OWN_POLICY_IDS) is written
                  again with the current rules (any other policy is left alone).
  --pep-name      The PEP's service account (default: pep-wsfed-demo).
  --dry-run       Print what would be done, and send nothing.

The management API secret is ADMIN_API_CLIENT_SECRET or STS_ADMIN_API_CLIENT_SECRET."""


def _host_of(parsed: urllib.parse.SplitResult) -> str:
    return parsed.hostname or ""


def on_port(url: str, port: int) -> str:
    try:
        parsed = urllib.parse.urlsplit(url)
        if _host_of(parsed) not in LOOPBACK:
            return url
        host = _host_of(parsed)
        netloc = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))
    except Exception:
        return url


def endpoints_for(realm: str, reply_url: str, options: dict) -> dict:
    if options.get("public_url_given") and options.get("public_url"):
        public = options["public_url"]
        base = urllib.parse.urlsplit(public if public.endswith("/") else f"{public}/")

        def move(value: str) -> str:
            nxt = urllib.parse.urlsplit(value)
            host = base.hostname or ""
            netloc = f"[{host}]" if ":" in host else host
            if base.port:
                netloc = f"{netloc}:{base.port}"
            return urllib.parse.urlunsplit((base.scheme, netloc, nxt.path, nxt.query, nxt.fragment))

        return {"realm": move(realm), "reply_url": move(reply_url)}
    if options.get("port"):
        return {"realm": on_port(realm, options["port"]), "reply_url": on_port(reply_url, options["port"])}
    return {"realm": realm, "reply_url": reply_url}


def _parse_port(value) -> int | None:
    raw = str(value or "").strip()
    if not raw or not raw.isdigit():
        return None
    port = int(raw)
    if port < 1 or port > 65535:
        return None
    return port


def demo_port(env_port, container_port) -> int | None:
    return _parse_port(container_port) or _parse_port(env_port)


def parse_args(argv: list[str], env: dict | None = None) -> dict:
    env = os.environ if env is None else env
    out = {
        "config": str((ROOT / "demo" / "wsfed.json").resolve()),
        "idp": (env.get("IYA_STS_URL") or "https://localhost:8081").rstrip("/"),
        "public_url": (env.get("PUBLIC_URL") or "http://localhost:3000").rstrip("/"),
        "public_url_given": bool(env.get("PUBLIC_URL")),
        "test_user": "wsfed-demo-user",
        "dry_run": False,
        "help": False,
        "pep": "",
        "pep_name": PEP_NAME,
    }
    i = 0
    while i < len(argv):
        arg = argv[i]

        def value() -> str:
            nonlocal i
            i += 1
            if i >= len(argv):
                raise SystemExit(f"{arg} needs a value\n{usage()}")
            return argv[i]

        if arg in ("--help", "-h"):
            out["help"] = True
        elif arg == "--config":
            out["config"] = str(Path(value()).resolve())
        elif arg == "--idp":
            out["idp"] = value().rstrip("/")
        elif arg == "--public-url":
            out["public_url"] = value().rstrip("/")
            out["public_url_given"] = True
        elif arg == "--test-user":
            out["test_user"] = value().strip()
        elif arg == "--no-test-user":
            out["test_user"] = ""
        elif arg == "--dry-run":
            out["dry_run"] = True
        elif arg == "--pep":
            # The mode may be left out: then local, iya-pep's default (the
            # PEP caches the application's policies and decides in process).
            if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                out["pep"] = value().strip()
            else:
                out["pep"] = "local"
            if out["pep"] not in PEP_MODES:
                raise SystemExit(f"--pep must be central or local, not {out['pep']}")
        elif arg == "--pep-name":
            out["pep_name"] = value().strip()
            if not out["pep_name"]:
                raise SystemExit("--pep-name is empty")
        else:
            raise SystemExit(f"Unknown argument {arg}\n{usage()}")
        i += 1
    parsed = urllib.parse.urlsplit(out["idp"])
    if parsed.scheme != "https":
        raise SystemExit(f"--idp must be https, not {out['idp']}")
    if not out["public_url"]:
        raise SystemExit("--public-url is empty")
    return out


def _signals_off(value) -> bool:
    if value is None:
        return False
    if not isinstance(value, bool):
        raise ValueError("signals must be true or false")
    return value is False


def files_of(config_path: str) -> dict:
    raw = json.loads(Path(config_path).read_text(encoding="utf-8"))
    base = Path(config_path).resolve().parent

    def at(path, what: str) -> str:
        if not path or "-----BEGIN" in path or path.startswith(("http://", "https://", "<", "env:")):
            raise ValueError(f"{config_path}'s {what} must be a file path for this script to write")
        if path.startswith("file:"):
            path = path[5:]
        candidate = Path(path)
        return str(candidate if candidate.is_absolute() else (base / candidate).resolve())

    if not raw.get("realm"):
        raise ValueError(f"{config_path} has no realm")
    if not raw.get("replyUrl"):
        raise ValueError(f"{config_path} has no replyUrl")
    key = at(raw.get("privateKey"), "privateKey")
    files = {
        "realm": raw["realm"],
        "reply_url": raw["replyUrl"],
        "key": key,
        "cert": at(raw.get("certificate"), "certificate"),
        "idp_metadata": at(raw.get("idpMetadata"), "idpMetadata"),
        "idp_ca": at(raw["idpCa"], "idpCa") if raw.get("idpCa") else None,
        "rp_metadata": str((Path(key).parent / "rp-metadata.xml").resolve()),
        "ssf_transmitter": (raw.get("ssf") or {}).get("transmitter"),
    }
    if _signals_off(raw["signals"] if "signals" in raw else None):
        files["signals"] = False
    return files


def realm_of(idp: str) -> dict:
    parsed = urllib.parse.urlsplit(idp)
    path = parsed.path.rstrip("/")
    if path and not __import__("re").fullmatch(r"/realm/[^/]+", path):
        raise ValueError(f"--idp must be iya-sts's base URL or a realm's (/realm/<id>), not {idp}")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return {"origin": origin, "base": f"{origin}{path}"}


def idp_metadata_url(base: str, realm: str) -> str:
    return f"{base}/wsfed/metadata/{urllib.parse.quote(realm, safe='')}"


def ssf_calls(files: dict, base: str, certificate_pem: str) -> list[dict]:
    return [
        {"method": "POST", "path": f"{base}/admin-api/applications/add", "why": "declare the Shared Signals write scope",
         "body": {"application": files["realm"], "attribute": "oauthAllowedScope", "value": "ssf.manage"}},
        {"method": "POST", "path": f"{base}/admin-api/roles/add-member", "why": "hold SSF_MANAGE, which authorizes it",
         "body": {"role": "SSF_MANAGE", "kind": "application", "member": files["realm"]}},
        {"method": "POST", "path": f"{base}/admin-api/tls/trust/add", "why": "trust the RP certificate at the TLS handshake",
         "body": {"certificates": certificate_pem}},
        {"method": "POST", "path": f"{base}/admin-api/applications/add-certificate", "why": "store the RP certificate on the application",
         "body": {"application": files["realm"], "certificate": certificate_pem}},
    ]


def plan_for(files: dict, base: str, test_user: str) -> list[dict]:
    calls = [
        {"method": "POST", "path": f"{base}/admin-api/applications/create", "why": f"register the relying party {files['realm']}",
         "body": {"identifier": files["realm"], "name": "wsfed-caep-rust demo", "protocols": ["wsfed"],
                  "fields": {"wsfedRealm": [files["realm"]], "wsfedReplyUrl": [files["reply_url"]]}}},
        {"method": "POST", "path": f"{base}/admin-api/applications/add", "why": "(only if it already exists) register the reply URL on it",
         "body": {"application": files["realm"], "attribute": "wsfedReplyUrl", "value": files["reply_url"]}},
        {"method": "POST", "path": f"{base}/admin-api/config/set", "why": "let one browser hold several accounts", "body": MULTIPLE_ACCOUNTS},
        {"method": "GET", "path": idp_metadata_url(base, files["realm"]), "body": None, "why": f"fetch the IdP metadata into {files['idp_metadata']}"},
    ]
    if files.get("signals") is not False and files.get("ssf_transmitter"):
        calls[3:3] = ssf_calls(files, base, "<the RP certificate>")
    if test_user:
        calls.append({"method": "POST", "path": f"{base}/admin-api/users/create", "why": f"create the test user {test_user}", "body": {"username": test_user}})
        calls.append({"method": "POST", "path": f"{base}/admin-api/policies/define-person-attribute",
                      "why": f"define the realm's custom attribute {TEST_ATTRIBUTE} (an admin:security token; unless it is defined)",
                      "body": {"name": TEST_ATTRIBUTE, "label": "Attribute 1", "syntax": "string", "multiValued": False}})
        calls.append({"method": "POST", "path": f"{base}/admin-api/users/set-attribute", "why": f"give {test_user} {TEST_ATTRIBUTE}={TEST_ATTRIBUTE_VALUE}",
                      "body": {"user": test_user, "attribute": TEST_ATTRIBUTE, "value": TEST_ATTRIBUTE_VALUE}})
    return calls


def _metadata_xml(realm: str, reply_url: str) -> str:
    def endpoint(local: str, address: str) -> str:
        return f"    <fed:{local}><wsa:EndpointReference><wsa:Address>{address}</wsa:Address></wsa:EndpointReference></fed:{local}>"

    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
        'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706" '
        'xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        f'entityID="{realm}">\n'
        '  <md:RoleDescriptor xsi:type="fed:ApplicationServiceType" protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706">\n'
        '    <fed:TokenTypesOffered><fed:TokenType Uri="urn:oasis:names:tc:SAML:2.0:assertion"/></fed:TokenTypesOffered>\n'
        f"    <fed:TargetScopes><wsa:EndpointReference><wsa:Address>{realm}</wsa:Address></wsa:EndpointReference></fed:TargetScopes>\n"
        f"{endpoint('ApplicationServiceEndpoint', reply_url)}\n"
        f"{endpoint('SingleSignOutNotificationEndpoint', reply_url)}\n"
        f"{endpoint('PassiveRequestorEndpoint', reply_url)}\n"
        "  </md:RoleDescriptor>\n</md:EntityDescriptor>\n"
    )


def metadata_for(config_path: str, realm: str, reply_url: str) -> str:
    # Standard library only. There is no Python wsfed_caep package in this repository; the
    # demo serves its own full metadata (with its certificate) at
    # /FederationMetadata/2007-06/FederationMetadata.xml, and `wsfed-caep metadata` writes it.
    return _metadata_xml(realm, reply_url)


def container_port(cwd: str | None = None) -> str | None:
    import subprocess

    try:
        identity = subprocess.run(["docker", "compose", "ps", "-q", "wsfed-demo"], cwd=cwd or str(ROOT), check=False, capture_output=True, text=True).stdout.strip().split("\n")[0]
        if not identity:
            return None
        env = subprocess.run(["docker", "inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}", identity], check=False, capture_output=True, text=True).stdout
        for line in env.splitlines():
            if line.startswith("PORT="):
                return line[5:]
    except Exception:
        return None
    return None


def _request(url: str, method: str = "GET", headers: dict | None = None, body: bytes | None = None, ca: str | None = None) -> dict:
    context = None
    if url.startswith("https"):
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if ca:
            context.load_verify_locations(cadata=ca)
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, context=context, timeout=15) as response:
            raw = response.read(2 * 1024 * 1024)
            return {"status": response.status, "body": raw.decode("utf-8", "replace")}
    except urllib.error.HTTPError as err:
        raw = err.read(2 * 1024 * 1024)
        return {"status": err.code, "body": raw.decode("utf-8", "replace")}


def _json(url: str, ca: str | None, method: str = "GET", headers: dict | None = None, body: str | None = None) -> dict:
    answer = _request(url, method, headers, body.encode() if body is not None else None, ca)
    try:
        parsed = json.loads(answer["body"]) if answer["body"] else {}
    except json.JSONDecodeError as err:
        raise RuntimeError(f"{method} {url} answered {answer['status']} with non-JSON: {answer['body'][:300]}") from err
    if answer["status"] in (401, 403):
        raise RuntimeError(f"{method} {url} answered {answer['status']}: {json.dumps(parsed)[:300]}")
    return {"status": answer["status"], "body": parsed}


def _errors_of(body: dict) -> list[str]:
    return [str(item) for item in (body.get("errors") or [])]


def pep_plan(files: dict, base: str, name: str, mode: str) -> list[str]:
    """What --pep does, for --dry-run. No key and no request leaves here."""
    app = files["realm"]
    return [
        f"GET  {base}/admin-api/users?user={name}  # create the service account unless it exists",
        f"POST {base}/admin-api/users/create  # {name}: a service account, owned by admin-write, no credential",
        f"POST {base}/admin-api/groups/add-member  # {name} in {PEP_GROUP}",
        f"# make a P-256 key in {PEP_KEY} beside the configuration (0600) unless one is there",
        f"POST {base}/admin-api/xacml/issue-pep-credential  # its certificate request, bound to {app} (a new key or account)",
        f"POST {base}/admin-api/xacml/set-pep-application  # or, with both kept, the binding to {app} again",
        f"POST {base}/admin-api/xacml/authzen/set-attribute  # subject.acr -> {ACR_ATTRIBUTE}",
        f"POST {base}/admin-api/applications/fga-create-policy  # {app}'s own policy, unless it has one",
        f"POST {base}/admin-api/xacml/import-alfa  # the demo policy into it (while {app} enforces none, or this script's own)",
        f"POST {base}/admin-api/applications/fga-enable  # {app} enforces its own policy (the realm root is never touched)",
        f"POST {base}/admin-api/applications/add  # {PEP_EVENT} in ssfAllowedEvents, only if {app} restricts them",
        f"# write \"pep\": {{\"name\": \"{name}\", \"mode\": \"{mode}\", \"assertionKey\": \"{PEP_KEY_IN_SECTION}\"}} into the configuration",
    ]


def set_test_attribute(api, user: str) -> bool:
    """The realm's custom attribute attr1, and the test user's value of it, which GET
    /attribute-protected is decided on.

    Defining a custom attribute changes the realm's attribute policy, a Security Administrator's
    change: it needs a token carrying admin:security whose subject holds SECURITY_ADMIN. iya-sts
    seeds sts-api-client in that role, so the script defines attr1 itself with a token minted for
    that call alone. Where an operator has taken the client out of the role the definition is
    refused; that is not fatal: the value is tried anyway (attr1 may be defined already), and only
    when it cannot be set does the script say what a Security Administrator does instead. Answers
    whether the test user now holds the value."""
    try:
        defined = api("/policies/define-person-attribute", {
            "name": TEST_ATTRIBUTE, "label": "Attribute 1", "syntax": "string", "multiValued": False,
            "description": "The demo's attribute-protected resource is permitted when this is abc123.",
        }, security=True)
    except RuntimeError as err:
        # _json raises on 401 and 403; only the Security Administrator refusal is expected here.
        if "403" not in str(err) or "security administrator" not in str(err).lower():
            raise
        defined = {"status": 403, "body": {"errors": ["Only a Security Administrator may make this change"]}}
    words = " ".join(_errors_of(defined["body"])).lower()
    not_allowed = defined["status"] == 403 and "security administrator" in words
    if not not_allowed and not (defined["status"] == 200 and defined["body"].get("ok") is not False):
        if "already" not in words and "exists" not in words:
            raise RuntimeError(f"defining the custom attribute {TEST_ATTRIBUTE}: refused ({defined['status']}): {json.dumps(defined['body'])[:400]}")
    try:
        answered = api("/users/set-attribute", {"user": user, "attribute": TEST_ATTRIBUTE, "value": TEST_ATTRIBUTE_VALUE})
    except RuntimeError as err:
        answered = {"status": 0, "body": {"errors": [str(err)]}}
    if answered["status"] == 200 and answered["body"].get("ok") is not False:
        print(f"{user} has {TEST_ATTRIBUTE}={TEST_ATTRIBUTE_VALUE} (a custom attribute of the realm).")
        return True
    if not_allowed:
        # Only now does the refusal matter: the attribute is not defined, and this credential
        # cannot define it.
        print(f"The custom attribute {TEST_ATTRIBUTE} is not defined, and this credential cannot define it:")
        print("sts-api-client no longer holds SECURITY_ADMIN here (iya-sts seeds it there; an operator took it")
        print("out). Put it back on Roles, or sign in to the console as a Security Administrator")
        print("(the bootstrap administrator is), open Directory > Policies > Attribute policy > Custom")
        print(f"attributes, and add {TEST_ATTRIBUTE} (label \"Attribute 1\", syntax string, one value). Then run")
        print(f"this script again to give {user} {TEST_ATTRIBUTE}={TEST_ATTRIBUTE_VALUE}.")
    else:
        print(f"{user} does not have {TEST_ATTRIBUTE} yet: {' '.join(_errors_of(answered['body']))[:300]}")
    return False


def make_pep_key(key_file: Path) -> None:
    """A P-256 key made here with openssl, created 0600. Neither it nor its contents are printed;
    only its certificate request (pep_csr) is ever sent."""
    import subprocess

    key_file.parent.mkdir(parents=True, exist_ok=True)
    old = os.umask(0o077)
    try:
        made = subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(key_file)],
                              check=False, capture_output=True, text=True)
    finally:
        os.umask(old)
    if made.returncode != 0:
        raise RuntimeError("openssl could not make the PEP's key (is openssl installed?)")
    os.chmod(key_file, 0o600)


def pep_csr(key_file: Path, name: str) -> str:
    """The key's certificate request: the one thing about the key that leaves this machine."""
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as work:
        csr = Path(work) / "pep.csr"
        asked = subprocess.run(["openssl", "req", "-new", "-key", str(key_file), "-subj", f"/CN={name}", "-out", str(csr)],
                               check=False, capture_output=True, text=True)
        if asked.returncode != 0:
            raise RuntimeError("openssl could not make the PEP's certificate request from its key")
        return csr.read_text(encoding="utf-8")


def _ok(answer: dict, what: str, allow: str = "") -> bool:
    """An /admin-api act that worked (True), or one refused only because it is already so (False,
    `allow` matched in the refusal's words). Anything else raises."""
    body = answer["body"]
    if answer["status"] == 200 and body.get("ok") is not False:
        return True
    words = (" ".join(_errors_of(body)) + " " + str(body.get("why") or "")).lower()
    if allow and allow in words:
        return False
    raise RuntimeError(f"{what}: refused ({answer['status']}): {json.dumps(body)[:400]}")


def write_pep_section(config_path: str, name: str, mode: str) -> None:
    """The configuration's `pep` section: the name, the mode and the key; other members of the
    section and of the file are kept."""
    path = Path(config_path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    section = raw.get("pep") if isinstance(raw.get("pep"), dict) else {}
    section.update({"name": name, "mode": mode, "assertionKey": PEP_KEY_IN_SECTION})
    raw["pep"] = section
    path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")


def setup_pep(api, get, files: dict, config_path: str, name: str, mode: str) -> None:
    """docs/remote-pep.md's steps 2 to 6. Safe to run again: an account, a key and a policy that are
    there are kept, and the binding is set again."""
    from urllib.parse import quote

    app = files["realm"]
    # Step 2: the service account, in remote-peps.
    made_account = get(f"/users?user={quote(name)}").get("known") is not True
    if made_account:
        _ok(api("/users/create", {"username": name, "invent": False, "credential": "none", "serviceAccount": True,
                                  "owners": ["admin-write"], "attributes": {"cn": name, "displayName": name}}),
            f"creating the service account {name}")
        print(f"Created the PEP's service account {name}.")
    else:
        print(f"The PEP's service account {name} already exists.")
    _ok(api("/groups/add-member", {"group": PEP_GROUP, "member": name}), f"adding {name} to {PEP_GROUP}", allow="already")
    # Step 3: the key, certified from its own request, and the binding.
    key_file = Path(config_path).resolve().parent / PEP_KEY
    made_key = not key_file.exists()
    if made_key:
        make_pep_key(key_file)
        print(f"Generated the PEP's P-256 key in {key_file} (readable by you only).")
    if made_key or made_account:
        _ok(api("/xacml/issue-pep-credential", {"name": name, "csr": pep_csr(key_file, name), "application": app}),
            "certifying the PEP's key")
        print(f"Certified the PEP's key and bound {name} to {app}.")
    else:
        _ok(api("/xacml/set-pep-application", {"name": name, "application": app}), f"binding {name} to {app}")
        print(f"Kept the PEP's key; {name} is bound to {app}.")
    # Step 4: the claim the policy reads.
    _ok(api("/xacml/authzen/set-attribute", {"object": "subject", "property": "acr", "attributeId": ACR_ATTRIBUTE}),
        "the catalogue row subject.acr")
    # Step 5: the application's own policy. Written while it enforces none, and rewritten while it
    # enforces this script's own (by PolicyId), so a new rule reaches an existing install; a policy
    # an administrator wrote under another PolicyId is left as it is. The realm root is never
    # touched.
    page_path = f"/applications?application={quote(app, safe='')}"
    page = get(page_path).get("page") or {}
    fga = page.get("fga") or {}
    current_id = (fga.get("policy") or {}).get("policyId") or ""
    if fga.get("enforced") is True and current_id not in OWN_POLICY_IDS:
        print(f"{app} already enforces a policy of its own ({current_id or 'unnamed'}); it is left as it is.")
    elif fga.get("enforced") is True:
        policy = (fga.get("policy") or {}).get("name") or fga.get("reference")
        _ok(api("/xacml/import-alfa", {"name": policy, "alfa": orders_policy()}), f"writing {policy}")
        print(f"{app} enforces this script's policy {policy}; it now holds the current version.")
    else:
        _ok(api("/applications/fga-create-policy", {"application": app}), f"{app}'s own policy", allow="already")
        page = get(page_path).get("page") or {}
        fga = page.get("fga") or {}
        policy = (fga.get("policy") or {}).get("name") or fga.get("reference")
        if not policy:
            raise RuntimeError(f"{app}'s page names no policy of its own: {json.dumps(fga)[:300]}")
        _ok(api("/xacml/import-alfa", {"name": policy, "alfa": orders_policy()}), f"writing {policy}")
        _ok(api("/applications/fga-enable", {"application": app}), f"enforcing {app}'s own policy")
        print(f"{app} now enforces its own policy {policy}: read on an order needs an acr; read on {ATTRIBUTE_PROTECTED} needs {TEST_ATTRIBUTE}={TEST_ATTRIBUTE_VALUE}; anything else is denied.")
    # Step 6: only an application that restricts its streams needs the event named.
    allowed = (page.get("attributes") or {}).get("ssfAllowedEvents") or []
    if isinstance(allowed, str):
        allowed = [allowed]
    if allowed and PEP_EVENT not in allowed:
        _ok(api("/applications/add", {"application": app, "attribute": "ssfAllowedEvents", "value": PEP_EVENT}),
            "letting pep-policies-changed through ssfAllowedEvents", allow="already")
        print(f"Added {PEP_EVENT} to {app}'s ssfAllowedEvents.")
    write_pep_section(config_path, name, mode)
    print(f"Wrote a {mode} pep section into {config_path}.")


def _generate_keys(config_path: str) -> None:
    """Run this crate's `wsfed-caep generate-keys`. It is on PATH in the demo image.

    This script never builds anything: Cargo does not run on the host. On the host, generate the
    key pair first, inside the demo image:

      docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/demo:/app/demo" wsfed-caep-rust-demo wsfed-caep generate-keys --config demo/wsfed.json
    """
    import shutil
    import subprocess

    binary = shutil.which("wsfed-caep")
    if not binary:
        raise SystemExit(
            "No key pair yet, and wsfed-caep is not on PATH. Generate one inside the demo image:\n"
            '  docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/demo:/app/demo" wsfed-caep-rust-demo wsfed-caep generate-keys --config demo/wsfed.json'
        )
    completed = subprocess.run([binary, "generate-keys", "--config", config_path], check=False)
    if completed.returncode != 0:
        raise SystemExit(f"wsfed-caep generate-keys exited {completed.returncode}")


def main(argv: list[str] | None = None) -> None:
    args = parse_args(list(sys.argv[1:] if argv is None else argv))
    if args["help"]:
        print(usage())
        return
    files = files_of(args["config"])
    port = None if args["public_url_given"] else demo_port(os.environ.get("PORT"), container_port())
    endpoints = endpoints_for(files["realm"], files["reply_url"], {"public_url": args["public_url"], "public_url_given": args["public_url_given"], "port": port})
    files["realm"] = endpoints["realm"]
    files["reply_url"] = endpoints["reply_url"]
    found = realm_of(args["idp"])
    origin, base = found["origin"], found["base"]
    if args["dry_run"]:
        if not Path(files["key"]).exists():
            print(f"# would generate the key pair {files['key']}, {files['cert']}")
        if files["idp_ca"]:
            print(f"# would save {origin}'s listener CA trust chain to {files['idp_ca']}")
        print(f"# would write {files['rp_metadata']}")
        for call in plan_for(files, base, args["test_user"]):
            print(f"{call['method']} {call['path']}  # {call['why']}")
            if call.get("body") is not None:
                print(json.dumps(call["body"], indent=2))
        if args["pep"]:
            for line in pep_plan(files, base, args["pep_name"], args["pep"]):
                print(line)
        return
    if not Path(files["key"]).exists() and not Path(files["cert"]).exists():
        print("No key pair yet; generating one.")
        _generate_keys(args["config"])
    ca = None
    if files["idp_ca"]:
        try:
            chain = save_trust_chain(origin, files["idp_ca"])
        except Exception as error:
            raise SystemExit(f"could not read {origin}'s listener CA trust chain: {error}") from error
        ca = chain["pem"]
        subject = chain["anchor"].subject.rfc4514_string().replace("\n", ", ")
        print(f"Saved {origin}'s listener CA trust chain ({chain['count']} certificate(s)) to {files['idp_ca']} (trusted on first use)")
        print(f"  trust anchor {subject}")
        print(f"  sha256 {chain['fingerprint']}")
        print("  Compare the anchor with the Root CA on iya-sts's Server configuration, PKI page.")
        print("  The demo image copies this file in when it is built: rebuild it (docker compose up --build).")
    xml = metadata_for(args["config"], files["realm"], files["reply_url"])
    Path(files["rp_metadata"]).parent.mkdir(parents=True, exist_ok=True)
    Path(files["rp_metadata"]).write_text(xml, encoding="utf-8")
    print(f"Wrote the relying party metadata to {files['rp_metadata']}")
    secret = os.environ.get("ADMIN_API_CLIENT_SECRET") or os.environ.get("STS_ADMIN_API_CLIENT_SECRET") or ""
    if not secret:
        raise SystemExit("neither ADMIN_API_CLIENT_SECRET nor STS_ADMIN_API_CLIENT_SECRET is set, so no /admin-api token can be minted.")
    token = _mint(origin, base, ca, secret)
    security_token: list[str] = []

    def api(path: str, body: dict, security: bool = False) -> dict:
        # A change iya-sts counts as security (a Directory > Policies policy, such as the realm's
        # custom attributes) needs admin:security, held through SECURITY_ADMIN, which iya-sts seeds
        # sts-api-client in. That token is minted only when such a call is made, and used for it
        # alone; every other call carries admin:read and admin:write.
        bearer = token
        if security:
            if not security_token:
                security_token.append(_mint(origin, base, ca, secret, "admin:read admin:security"))
            bearer = security_token[0]
        return _json(f"{base}/admin-api{path}", ca, "POST", {"accept": "application/json", "content-type": "application/json", "authorization": f"Bearer {bearer}"}, json.dumps(body))

    create, add_reply = plan_for(files, base, args["test_user"])[:2]
    created = api("/applications/create", create["body"])
    if created["body"].get("ok"):
        print(f"Registered the relying party {files['realm']}, replying to {files['reply_url']}.")
    elif any("already in this registry" in item.lower() for item in _errors_of(created["body"])):
        added = api("/applications/add", add_reply["body"])
        if not added["body"].get("ok") and "already" not in " ".join(_errors_of(added["body"])).lower():
            raise RuntimeError(f"iya-sts refused the reply URL: {json.dumps(added['body'])[:500]}")
        print(f"{files['realm']} was registered already; {files['reply_url']} is one of its reply URLs.")
    else:
        raise RuntimeError(f"iya-sts refused to create {files['realm']}: {json.dumps(created['body'])[:500]}")
    multiple = api("/config/set", MULTIPLE_ACCOUNTS)
    if not multiple["body"].get("ok"):
        raise RuntimeError(f"setting authn.multipleAccounts was refused: {json.dumps(multiple['body'])[:300]}")
    print("authn.multipleAccounts is on: one browser may hold several signed-in people.")
    if files.get("signals") is not False and files.get("ssf_transmitter"):
        certificate = Path(files["cert"]).read_text(encoding="utf-8")
        for call in ssf_calls(files, base, certificate):
            path = call["path"][len(f"{base}/admin-api"):]
            reply = api(path, call["body"])
            errors = " ".join(_errors_of(reply["body"]))
            if not reply["body"].get("ok") and "already" not in errors.lower():
                raise RuntimeError(f"{call['why']}: refused: {json.dumps(reply['body'])[:400]}")
            if not reply["body"].get("ok"):
                print(f"  {call['why']}: already so ({errors[:160]})")
        print(f"Shared Signals: {files['realm']} holds SSF_MANAGE and authenticates to /ssf/* with its own certificate (mutual TLS).")
    url = idp_metadata_url(base, files["realm"])
    fetched = _request(url, headers={"accept": "application/samlmetadata+xml"}, ca=ca)
    if fetched["status"] != 200:
        raise RuntimeError(f"{url} answered {fetched['status']}")
    Path(files["idp_metadata"]).parent.mkdir(parents=True, exist_ok=True)
    Path(files["idp_metadata"]).write_text(fetched["body"], encoding="utf-8")
    print(f"Saved the IdP metadata to {files['idp_metadata']}")
    if args["test_user"]:
        _ensure_user(base, ca, token, args["test_user"], api, Path(args["config"]).resolve().parent / "generated")
        set_test_attribute(api, args["test_user"])
    if args["pep"]:
        def get(path: str) -> dict:
            return _json(f"{base}/admin-api{path}", ca, headers={"accept": "application/json", "authorization": f"Bearer {token}"})["body"]
        setup_pep(api, get, files, args["config"], args["pep_name"], args["pep"])
        print(f"pep:  {args['pep_name']}, {args['pep']} (GET /orders/<id> needs a sign-in with an acr; any other method is denied;")
        print(f"      GET /{ATTRIBUTE_PROTECTED} needs {TEST_ATTRIBUTE}={TEST_ATTRIBUTE_VALUE} in the directory)")
    print("Done. Start the demo with: docker compose up --build")


def _mint(origin: str, base: str, ca: str | None, secret: str, scope: str = "admin:read admin:write") -> str:
    import base64

    form = urllib.parse.urlencode({"grant_type": "client_credentials", "scope": scope, "resource": f"{base}/admin-api"})
    basic = base64.b64encode(f"sts-api-client:{secret}".encode()).decode()
    reply = _json(f"{base}/oauth2/token", ca, "POST", {"content-type": "application/x-www-form-urlencoded", "authorization": f"Basic {basic}"}, form)
    if reply["status"] != 200 or not isinstance(reply["body"].get("access_token"), str):
        raise RuntimeError(f"the token endpoint at {origin} answered {reply['status']} {json.dumps(reply['body'])[:300]}")
    return reply["body"]["access_token"]


def _ensure_user(base: str, ca: str | None, token: str, username: str, api, generated: Path) -> None:
    found = _json(f"{base}/admin-api/users?user={urllib.parse.quote(username)}", ca, headers={"accept": "application/json", "authorization": f"Bearer {token}"})
    password = os.environ.get("WSFED_DEMO_USER_PASSWORD") or ""
    if found["body"].get("known") is True and password:
        set_password = api("/users/set-password", {"user": username, "password": password, "passwordConfirm": password})
        if not set_password["body"].get("ok"):
            raise RuntimeError(f"setting {username}'s password was refused: {json.dumps(set_password['body'])[:300]}")
        print(f"User {username} already exists; its password is now WSFED_DEMO_USER_PASSWORD.")
    elif found["body"].get("known") is True:
        print(f"User {username} already exists; its password is unchanged (set WSFED_DEMO_USER_PASSWORD to replace it).")
    else:
        attributes = {"cn": f"WS-Fed Demo {username}", "givenName": "WS-Fed", "sn": "Demo", "displayName": f"WS-Fed Demo {username}", "mail": f"{username}@wsfed-demo.test"}
        body = {"username": username, "invent": False, "credential": "password", "password": password, "passwordConfirm": password, "attributes": attributes} if password else {"username": username, "invent": False, "credential": "generate", "attributes": attributes}
        made = api("/users/create", body)
        if not made["body"].get("ok"):
            raise RuntimeError(f"creating {username} was refused: {json.dumps(made['body'])[:300]}")
        print(f"Created user {username}.")
        if made["body"].get("password"):
            # Never printed: a password does not belong in a log. It goes to a file only its
            # owner can read, created 0600, in demo/generated, which never enters an image
            # (.dockerignore admits only idpCa's chain).
            saved = generated / f"{username}.password"
            saved.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(saved, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as out:
                os.fchmod(out.fileno(), 0o600)
                out.write(f"{made['body']['password']}\n")
            print(f"Generated a password for {username}; it is in {saved} (readable by you only).")


if __name__ == "__main__":
    try:
        main()
    except (SystemExit, KeyboardInterrupt):
        raise
    except Exception as err:
        print(str(err), file=sys.stderr)
        sys.exit(1)
