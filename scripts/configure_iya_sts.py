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


def usage() -> str:
    return """Usage: python scripts/configure_iya_sts.py [--config path] [--idp url] [--public-url url]
                                        [--test-user name | --no-test-user] [--dry-run]

  --config        The demo's WS-Federation configuration (default: demo/wsfed.json)
  --idp           iya-sts's base URL; the realm's, e.g. https://host/realm/acme, for a trust realm
                  (default: $IYA_STS_URL or https://localhost:8081)
  --public-url    Replace the origin of the file's realm and reply URL with this URL, and keep
                  their paths (default: unset; $PUBLIC_URL). Without it, a loopback realm and
                  reply URL follow the running demo's PORT, then $PORT. Any other host is left
                  as written.
  --test-user     The test user to create (default: wsfed-demo-user).
  --no-test-user  Do not create a test user.
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
         "body": {"identifier": files["realm"], "name": "wsfed-caep-nodejs demo", "protocols": ["wsfed"],
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
    raw = json.loads(Path(config_path).read_text(encoding="utf-8"))
    raw.pop("idpCa", None)
    raw["realm"] = realm
    raw["replyUrl"] = reply_url
    try:
        from wsfed_caep.config import resolve_config
        from wsfed_caep.relying_party import RelyingParty

        return RelyingParty(resolve_config(raw, str(Path(config_path).resolve().parent)), None).metadata()
    except ImportError:
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


def _generate_keys(config_path: str) -> None:
    try:
        from wsfed_caep.cli import main as cli_main
    except ImportError as err:
        raise SystemExit("generate-keys needs the wsfed-caep package on PYTHONPATH (pip install -e .) or the Java CLI") from err
    cli_main(["generate-keys", "--config", config_path])


def main(argv: list[str] | None = None) -> None:
    args = parse_args(list(sys.argv[1:] if argv is None else argv))
    if args["help"]:
        print(usage())
        return
    files = files_of(args["config"])
    port = demo_port(os.environ.get("PORT"), container_port())
    endpoints = endpoints_for(files["realm"], files["reply_url"], {"public_url": args["public_url"], "public_url_given": args["public_url_given"], "port": port})
    files["realm"] = endpoints["realm"]
    files["reply_url"] = endpoints["reply_url"]
    found = realm_of(args["idp"])
    origin, base = found["origin"], found["base"]
    if args["dry_run"]:
        if not Path(files["key"]).exists():
            print(f"# would generate the key pair {files['key']}, {files['cert']}")
        if files["idp_ca"] and not Path(files["idp_ca"]).exists():
            print(f"# would save {origin}'s TLS root to {files['idp_ca']}")
        print(f"# would write {files['rp_metadata']}")
        for call in plan_for(files, base, args["test_user"]):
            print(f"{call['method']} {call['path']}  # {call['why']}")
            if call.get("body") is not None:
                print(json.dumps(call["body"], indent=2))
        return
    if not Path(files["key"]).exists() and not Path(files["cert"]).exists():
        print("No key pair yet; generating one.")
        _generate_keys(args["config"])
    ca = None
    if files["idp_ca"]:
        if not Path(files["idp_ca"]).exists():
            root = _fetch_tls_root(origin)
            Path(files["idp_ca"]).parent.mkdir(parents=True, exist_ok=True)
            Path(files["idp_ca"]).write_text(root, encoding="utf-8")
            print(f"Saved {origin}'s TLS root to {files['idp_ca']} (trusted on first use).")
            print("  Compare it with the Root CA on iya-sts's Server configuration, PKI page.")
        ca = Path(files["idp_ca"]).read_text(encoding="utf-8")
    xml = metadata_for(args["config"], files["realm"], files["reply_url"])
    Path(files["rp_metadata"]).parent.mkdir(parents=True, exist_ok=True)
    Path(files["rp_metadata"]).write_text(xml, encoding="utf-8")
    print(f"Wrote the relying party metadata to {files['rp_metadata']}")
    secret = os.environ.get("ADMIN_API_CLIENT_SECRET") or os.environ.get("STS_ADMIN_API_CLIENT_SECRET") or ""
    if not secret:
        raise SystemExit("neither ADMIN_API_CLIENT_SECRET nor STS_ADMIN_API_CLIENT_SECRET is set, so no /admin-api token can be minted.")
    token = _mint(origin, base, ca, secret)

    def api(path: str, body: dict) -> dict:
        return _json(f"{base}/admin-api{path}", ca, "POST", {"accept": "application/json", "content-type": "application/json", "authorization": f"Bearer {token}"}, json.dumps(body))

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
        _ensure_user(base, ca, token, args["test_user"], api)
    print("Done. Start the demo with: docker compose up --build")


def _mint(origin: str, base: str, ca: str | None, secret: str) -> str:
    import base64

    form = urllib.parse.urlencode({"grant_type": "client_credentials", "scope": "admin:read admin:write", "resource": f"{base}/admin-api"})
    basic = base64.b64encode(f"sts-api-client:{secret}".encode()).decode()
    reply = _json(f"{base}/oauth2/token", ca, "POST", {"content-type": "application/x-www-form-urlencoded", "authorization": f"Basic {basic}"}, form)
    if reply["status"] != 200 or not isinstance(reply["body"].get("access_token"), str):
        raise RuntimeError(f"the token endpoint at {origin} answered {reply['status']} {json.dumps(reply['body'])[:300]}")
    return reply["body"]["access_token"]


def _ensure_user(base: str, ca: str | None, token: str, username: str, api) -> None:
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
            print(f"Generated password for {username} (shown once): {made['body']['password']}")


def _fetch_tls_root(origin: str) -> str:
    import socket

    parsed = urllib.parse.urlsplit(origin)
    host = parsed.hostname or ""
    port = parsed.port or 443
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=15) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            chain = getattr(tls._sslobj, "get_unverified_chain", lambda: None)()
            der = chain[-1] if chain else tls.getpeercert(True)
    pem_body = __import__("base64").b64encode(der if isinstance(der, (bytes, bytearray)) else bytes(der)).decode()
    lines = [pem_body[i:i + 64] for i in range(0, len(pem_body), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


if __name__ == "__main__":
    try:
        main()
    except (SystemExit, KeyboardInterrupt):
        raise
    except Exception as err:
        print(str(err), file=sys.stderr)
        sys.exit(1)
