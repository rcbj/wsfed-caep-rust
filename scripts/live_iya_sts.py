#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Sign this demo in to a fresh iya-sts and confirm two Shared Signals events.

Starts the latest main branch of iya-sts in memory mode, with persistence and
clustering off and no request workers, unless IYA_STS_URL is already set.
Registers the demo with the host's python3, signs in through it, emits a
credential-change and a session-revoked event, and requires the demo's
/live-status to show both. The second one also ends the local session.

iya-sts main sets the WS-Federation assertion SessionIndex to the assertion id.
The CAEP session-revoked subject names the sign-on session, so the index finds
nobody. The demo ends its one session from the event handler (App::remember in
src/demo.rs), as the Java demo does in Demo.java.

The unit suite stays `docker build --target test`. This file is the live half.
It uses the host's Python and Docker. The demo runs in a container. Key
generation runs `wsfed-caep generate-keys` inside that image. Configuring the
client is `python3 scripts/configure_iya_sts.py` on the host, standard library
only. Cargo never runs on the host. Do not bind port 3000, 8081, or 18481 to
18495.

The order is the one a user follows. The checkout is copied to a scratch build
context (never demo/generated, .git or target), and the demo image is built from
it so `wsfed-caep generate-keys` can write the key pair there. The registrar then
runs against that copy and writes iya-sts's listener CA trust chain where idpCa
names it (demo/generated/idp-ca.pem). THEN the demo image is built again, which
bakes that chain in (only the demo/ layer changes), and THEN the demo runs from
it. Nothing here fetches the CA for the demo, rewrites idpCa, or mounts a CA into
the demo container: only the key pair and the IdP metadata are mounted, file by
file. This script reads the saved chain for its own HTTPS client.

--pep (or LIVE_PEP=1) adds the demo's embedded PEP (#40), and needs an iya-sts
with #2026-#2028 (IYA_STS_IMAGE). The PEP is set up the way a user sets it up:
the install script runs with --pep central (the service account, a P-256 key in
demo/generated, 0600, never printed and never in the image, its certificate
bound to the demo's application, the catalogue row and the application's own
policy, enforced; never the realm root) and writes the pep section; a copy,
demo/wsfed.pep-local.json, says local. The demo runs central first: after the
sign-in GET /orders/42 must be 200 and POST /orders/42 403. After the two
events it runs again with WSFED_CONFIG naming the local copy: the same two,
then the application's own policy is rewritten to deny read, and within
PEP_FLIP_TIMEOUT seconds (30) the GET must be 403 with pep-policies-changed
received (the fallback poll stays at 300 s, so `via` is `event`).

With --pep a second test user, wsfed-demo-user-denied, is created after the
install script (which defines attr1 and gives the first user attr1=abc123) with
attr1=not-abc123. In each mode GET /attribute-protected must be 200 for the
first user and 403 (a Deny) for the denied one, who still reads /orders/42.

--authzen (or LIVE_AUTHZEN=1) runs scripts/live_authzen.py instead.

IYA_STS_URL, when set, uses an iya-sts that is already running and does not
stop it. This script never removes iya-sts-live-main, iya-sts-live-probe, or a
container whose name starts with sts. Otherwise it clones main (or builds
IYA_STS_SRC) and removes only the container it started. The demo container it
removes is wsfed-caep-rust-live-demo. The STS container it starts is
iya-sts-live-wsfed-caep-rust.
"""

import base64
import email.message
import http.client
import http.cookiejar
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STS_REPO = "https://github.com/rcbj/iya-sts.git"
CAEP = "https://schemas.openid.net/secevent/caep/event-type/"
CREDENTIAL_CHANGE = CAEP + "credential-change"
SESSION_REVOKED = CAEP + "session-revoked"
FORBIDDEN_PORTS = {3000, 8081, *range(18481, 18496)}
PROTECTED_CONTAINERS = {"iya-sts-live-main", "iya-sts-live-probe"}

PROFILE = {
    "repo": "wsfed-caep-rust",
    "login_path": "/login",
    "status_path": "/live-status",
    "configure": ["python3", "scripts/configure_iya_sts.py"],
    "config_file": "demo/wsfed.json",
    "password_env": "WSFED_DEMO_USER_PASSWORD",
    "test_user": "wsfed-demo-user",
}


class LoopbackCookiePolicy(http.cookiejar.DefaultCookiePolicy):
    """Send a Secure cookie to loopback HTTP. Browsers do this for localhost."""

    def _loopback(self, request):
        host = (request.host or "").split(":")[0].strip("[]")
        return host in ("localhost", "127.0.0.1", "::1")

    def set_ok_secure(self, cookie, request):
        if cookie.secure and self._loopback(request):
            return True
        return http.cookiejar.DefaultCookiePolicy.set_ok_secure(self, cookie, request)

    def return_ok_secure(self, cookie, request):
        if cookie.secure and self._loopback(request):
            return True
        return http.cookiejar.DefaultCookiePolicy.return_ok_secure(self, cookie, request)


class _CookieResponse:
    def __init__(self, headers):
        self._headers = email.message.Message()
        for name, value in headers:
            self._headers[name] = value

    def info(self):
        return self._headers


class FormFinder(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        found = {key.lower(): value for key, value in attrs}
        if tag == "form":
            self._form = {
                "action": found.get("action") or "",
                "method": (found.get("method") or "get").lower(),
                "fields": [],
            }
        elif tag == "input" and self._form is not None and found.get("name"):
            self._form["fields"].append((found["name"], found.get("value") or ""))

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


class Client:
    def __init__(self, ca_file):
        self.jar = http.cookiejar.CookieJar(policy=LoopbackCookiePolicy())
        self.ssl = ssl.create_default_context(cafile=str(ca_file))
        self.ssl.minimum_version = ssl.TLSVersion.TLSv1_2

    def request(self, method, url, body=None, headers=None, timeout=60):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise RuntimeError(f"refusing {url}")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        target = urllib.request.Request(url, headers=headers or {}, method=method)
        self.jar.add_cookie_header(target)
        sent = {key.lower(): value for key, value in (headers or {}).items()}
        cookie = target.get_header("Cookie")
        if cookie and "cookie" not in sent:
            sent["cookie"] = cookie
        if body is not None and "content-length" not in sent:
            sent["content-length"] = str(len(body))
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(parts.hostname, port, context=self.ssl, timeout=timeout)
        else:
            conn = http.client.HTTPConnection(parts.hostname, port, timeout=timeout)
        try:
            conn.request(method, path, body=body, headers=sent)
            response = conn.getresponse()
            payload = response.read()
            header_pairs = response.getheaders()
        finally:
            conn.close()
        self.jar.extract_cookies(_CookieResponse(header_pairs), target)
        return response.status, header_pairs, payload


def header_map(pairs):
    found = {}
    for name, value in pairs:
        found.setdefault(name.lower(), []).append(value)
    return found


def one_header(pairs, name):
    values = header_map(pairs).get(name.lower()) or []
    return values[-1] if values else ""


def resolve_url(base, location):
    return urllib.parse.urljoin(base, location)


def origin_of(url):
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def path_of(url):
    return urllib.parse.urlsplit(url).path or "/"


def query_of(url):
    return urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)


def run(command, **kwargs):
    print("+ " + " ".join(command), flush=True)
    completed = subprocess.run(command, check=False, text=True, **kwargs)
    if completed.returncode != 0:
        if completed.stdout:
            print(completed.stdout, flush=True)
        if completed.stderr:
            print(completed.stderr, file=sys.stderr, flush=True)
        raise RuntimeError(f"{command[0]} exited {completed.returncode}")
    return completed


def docker(*args, **kwargs):
    return run(["docker", *args], **kwargs)


def docker_rm(name):
    if not name:
        return
    if name in PROTECTED_CONTAINERS or name.startswith("sts"):
        raise RuntimeError(f"refusing to remove {name}")
    subprocess.run(["docker", "rm", "-f", name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def wait_port(port, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 2):
                return
        except OSError:
            time.sleep(1)
    raise RuntimeError(f"127.0.0.1:{port} did not accept a connection")


def wait_ready(origin, timeout):
    """Wait for iya-sts's /healthcheck. Unverified: nothing is trusted from it."""
    parts = urllib.parse.urlsplit(origin)
    context = ssl._create_unverified_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, context=context, timeout=10)
            try:
                conn.request("GET", "/healthcheck")
                response = conn.getresponse()
                response.read()
            finally:
                conn.close()
            if response.status == 200:
                return
            last = f"answered {response.status}"
        except OSError as err:
            last = str(err)
        time.sleep(2)
    raise RuntimeError(f"{origin}/healthcheck was not ready: {last}")


def copy_context(dest):
    """Copy the checkout to a build context, without .git, target or demo/generated."""

    def ignore(directory, names):
        here = Path(directory).resolve()
        skipped = {".git", "__pycache__"} & set(names)
        if here == ROOT:
            skipped |= {"target"} & set(names)
        if here == ROOT / "demo":
            skipped |= {"generated"} & set(names)
        return skipped

    shutil.copytree(ROOT, dest, ignore=ignore)


def rewrite_config(source, dest, sts_origin, demo_origin):
    raw = json.loads(source.read_text(encoding="utf-8"))
    ssf = raw.get("ssf")
    if isinstance(ssf, dict):
        ssf["transmitter"] = sts_origin
        ssf["pollIntervalMs"] = 1000
        raw["ssf"] = ssf
    for key in ("realm", "replyUrl", "reply_url"):
        value = raw.get(key)
        if not isinstance(value, str) or not value:
            continue
        parts = urllib.parse.urlsplit(value)
        if (parts.hostname or "") not in ("localhost", "127.0.0.1", "::1"):
            continue
        raw[key] = demo_origin.rstrip("/") + (parts.path or "/")
    dest.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")


def json_body(payload):
    try:
        parsed = json.loads(payload.decode() if payload else "{}")
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def autopost_form(payload):
    parser = FormFinder()
    try:
        parser.feed(payload.decode("utf-8", "replace"))
    except Exception:
        return None
    for form in parser.forms:
        names = {name for name, _value in form["fields"]}
        if names.intersection({"SAMLResponse", "wresult"}) and form["method"] == "post":
            return form
    return None


# What a sign-in request is logged as. A label is one of these constants, never
# text taken from the URL: the URLs carry pending-step handles, codes and state,
# and some come back from requests that carried the password.
LOG_PATHS = (
    "/authn-api/pending/",
    "/authn-api/consent/",
    "/authn-api/mfa/",
    "/authn/login",
    "/authn/mfa-setup",
    "/authn/post-login",
    "/oauth2/consent",
    "/oauth2/authorize",
    "/wsfed",
    "/saml2/",
    "/saml11/",
    "/callback",
    "/acs",
    "/login",
    "/live-status",
)


class Driver:
    def __init__(self, client, sts_origin, demo_origin, username, password):
        self.client = client
        self.sts_origin = sts_origin.rstrip("/")
        self.demo_origin = demo_origin.rstrip("/")
        self.username = username
        self.password = password

    def sts(self, url):
        return origin_of(url).rstrip("/") == self.sts_origin

    def label(self, url):
        """A constant naming where a request went, never text from the URL."""
        where = "iya-sts" if self.sts(url) else "demo" if origin_of(url).rstrip("/") == self.demo_origin else "elsewhere"
        path = path_of(url)
        for known in LOG_PATHS:
            if path.startswith(known):
                return f"{where} {known}"
        return f"{where} (another path)"

    def get(self, url):
        status, headers, payload = self.client.request("GET", url, headers={"accept": "text/html,application/json"})
        print(f"GET {status} {self.label(url)}", flush=True)
        return status, headers, payload

    def post_json(self, url, body, csrf):
        raw = json.dumps(body).encode()
        status, headers, payload = self.client.request("POST", url, body=raw, headers={
            "accept": "application/json",
            "content-type": "application/json",
            "origin": self.sts_origin,
            "x-csrf-token": csrf,
        })
        print(f"POST {status} {self.label(url)}", flush=True)
        return status, headers, payload

    def open_view(self, shell_url, api_url):
        status, headers, payload = self.get(shell_url)
        if status in (301, 302, 303, 307, 308):
            return {"redirect": resolve_url(shell_url, one_header(headers, "location"))}
        view_status, _headers, view_payload = self.client.request("GET", api_url, headers={"accept": "application/json"})
        print(f"GET {view_status} {self.label(api_url)}", flush=True)
        parsed = json_body(view_payload) or {}
        if view_status in (301, 302, 303, 307, 308):
            return {"redirect": resolve_url(api_url, one_header(_headers, "location"))}
        if not parsed.get("csrf"):
            snippet = (view_payload or payload or b"")[:400].decode("utf-8", "replace")
            raise RuntimeError(f"{api_url} answered {view_status} without a csrf token: {snippet}")
        return {"view": parsed.get("view") or {}, "csrf": parsed["csrf"], "json": parsed}

    def act(self, url):
        """One sign-in step. Returns the next absolute URL, or None when the demo has the browser."""
        status, headers, payload = self.get(url)
        if status in (301, 302, 303, 307, 308):
            return resolve_url(url, one_header(headers, "location"))
        path = path_of(url)
        query = query_of(url)
        if self.sts(url) and path.startswith("/authn/login"):
            pending = (query.get("authn") or [""])[0]
            opened = self.open_view(url, f"{self.sts_origin}/authn-api/pending/{urllib.parse.quote(pending)}")
            if opened.get("redirect"):
                return opened["redirect"]
            posted, post_headers, post_body = self.post_json(
                f"{self.sts_origin}/authn-api/pending/{urllib.parse.quote(pending)}/password",
                {"username": self.username, "password": self.password},
                opened["csrf"],
            )
            return self.after_act(url, posted, post_headers, post_body)
        if self.sts(url) and path.startswith("/oauth2/consent"):
            pending = (query.get("consent") or [""])[0]
            opened = self.open_view(url, f"{self.sts_origin}/authn-api/consent/{urllib.parse.quote(pending)}")
            if opened.get("redirect"):
                return opened["redirect"]
            posted, post_headers, post_body = self.post_json(
                f"{self.sts_origin}/authn-api/consent/{urllib.parse.quote(pending)}",
                {"action": "allow"},
                opened["csrf"],
            )
            return self.after_act(url, posted, post_headers, post_body)
        if self.sts(url) and (path.startswith("/authn/mfa-setup") or path.startswith("/authn/post-login")):
            return self.skip_step(url, path)
        if self.sts(url) and path.startswith("/gnap/approve/"):
            return self.approve_gnap(url)
        form = autopost_form(payload) if status == 200 else None
        if form:
            action = resolve_url(url, form["action"])
            encoded = urllib.parse.urlencode(form["fields"]).encode()
            posted, post_headers, _post_body = self.client.request("POST", action, body=encoded, headers={
                "content-type": "application/x-www-form-urlencoded",
                "origin": origin_of(url),
            })
            print(f"POST {posted} {self.label(action)}", flush=True)
            if posted in (301, 302, 303, 307, 308):
                return resolve_url(action, one_header(post_headers, "location"))
            if origin_of(action).rstrip("/") == self.demo_origin:
                return None
            raise RuntimeError(f"the auto-posted form stayed at {action} ({posted})")
        if origin_of(url).rstrip("/") == self.demo_origin and status < 400:
            return None
        snippet = payload[:500].decode("utf-8", "replace")
        raise RuntimeError(f"the sign-in stopped at {status} {url}: {snippet}")

    def after_act(self, url, status, headers, payload):
        parsed = json_body(payload) or {}
        if status in (301, 302, 303, 307, 308):
            return resolve_url(url, one_header(headers, "location"))
        if parsed.get("location"):
            nxt = parsed.get("next")
            step = parsed.get("step")
            location = resolve_url(self.sts_origin + "/", parsed["location"])
            if nxt == "mfa" and step == "enrol":
                return self.skip_step(location, path_of(location))
            return location
        if parsed.get("ok") is False:
            raise RuntimeError(f"the sign-in act was refused: {json.dumps(parsed)[:500]}")
        snippet = payload[:500].decode("utf-8", "replace")
        raise RuntimeError(f"the sign-in act answered {status} without a location: {snippet}")

    def skip_step(self, url, path):
        query = query_of(url)
        pending = (query.get("mfa") or query.get("authn") or [""])[0]
        if not pending:
            parts = [part for part in path.split("/") if part]
            pending = parts[-1] if parts else ""
        page = "post-login" if path.startswith("/authn/post-login") else "setup"
        operation = "post-login/skip" if page == "post-login" else "skip"
        opened = self.open_view(url, f"{self.sts_origin}/authn-api/mfa/{urllib.parse.quote(pending)}?page={page}")
        if opened.get("redirect"):
            return opened["redirect"]
        view = opened["view"]
        optional = page == "post-login" or (isinstance(view.get("setup"), dict) and view["setup"].get("optional"))
        if not optional:
            raise RuntimeError(f"a required step is in the way at {url}")
        posted, post_headers, post_body = self.post_json(
            f"{self.sts_origin}/authn-api/mfa/{urllib.parse.quote(pending)}/{operation}",
            {},
            opened["csrf"],
        )
        return self.after_act(url, posted, post_headers, post_body)

    def approve_gnap(self, url):
        approval_id = path_of(url).rstrip("/").split("/")[-1]
        opened = self.open_view(url, f"{self.sts_origin}/gnap-api/approve/{urllib.parse.quote(approval_id)}")
        if opened.get("redirect"):
            return opened["redirect"]
        view = opened["view"]
        rights = []
        for token in view.get("tokens") or []:
            for right in token.get("rights") or []:
                if right.get("field"):
                    rights.append(right["field"])
        body = {"action": "allow", "right": rights}
        if view.get("subject"):
            body["subject"] = "yes"
        posted, post_headers, post_body = self.post_json(
            f"{self.sts_origin}/gnap-api/approve/{urllib.parse.quote(approval_id)}",
            body,
            opened["csrf"],
        )
        return self.after_act(url, posted, post_headers, post_body)

    def sign_in(self):
        url = self.demo_origin + PROFILE["login_path"]
        for _hop in range(24):
            nxt = self.act(url)
            if not nxt:
                return
            url = nxt
        raise RuntimeError(f"the sign-in did not finish; last URL {url}")

    def status(self):
        status, _headers, payload = self.client.request(
            "GET", self.demo_origin + PROFILE["status_path"], headers={"accept": "application/json"}
        )
        parsed = json_body(payload)
        if status != 200 or not isinstance(parsed, dict):
            raise RuntimeError(f"/live-status answered {status}: {payload[:300]!r}")
        return parsed


def mint_admin(client, sts_origin, secret):
    raw = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "scope": "admin:read admin:write",
        "resource": sts_origin + "/admin-api",
    }).encode()
    token = base64.b64encode(f"sts-api-client:{secret}".encode()).decode()
    status, _headers, payload = client.request("POST", sts_origin + "/oauth2/token", body=raw, headers={
        "content-type": "application/x-www-form-urlencoded",
        "authorization": f"Basic {token}",
        "accept": "application/json",
    })
    parsed = json_body(payload) or {}
    if status != 200 or not isinstance(parsed.get("access_token"), str):
        raise RuntimeError(f"the admin token request answered {status}: {json.dumps(parsed)[:300]}")
    return parsed["access_token"]


def admin_json(client, sts_origin, token, method, path, body=None):
    headers = {"accept": "application/json", "authorization": f"Bearer {token}"}
    raw = None
    if body is not None:
        raw = json.dumps(body).encode()
        headers["content-type"] = "application/json"
    status, _headers, payload = client.request(method, sts_origin + path, body=raw, headers=headers)
    parsed = json_body(payload)
    if parsed is None:
        raise RuntimeError(f"{method} {path} answered {status} with non-JSON: {payload[:300]!r}")
    return status, parsed


def session_id_for(client, sts_origin, token, username):
    deadline = time.time() + 20
    while time.time() < deadline:
        _status, parsed = admin_json(client, sts_origin, token, "GET", "/admin-api/caep")
        sessions = parsed.get("sessions") or []
        for row in sessions:
            if str(row.get("username") or "") == username and str(row.get("state") or "") != "revoked":
                found = row.get("sessionId")
                if found:
                    return str(found)
        time.sleep(1)
    raise RuntimeError(f"no CAEP session for {username}: {json.dumps(sessions)[:500]}")


def emit(client, sts_origin, token, session_id, event_type):
    status, parsed = admin_json(client, sts_origin, token, "POST", "/admin-api/caep/emit", {
        "session_id": session_id,
        "type": event_type,
        "initiating_entity": "admin",
    })
    if status != 200 or parsed.get("ok") is False:
        raise RuntimeError(f"emitting {event_type} answered {status}: {json.dumps(parsed)[:500]}")
    message = str(parsed.get("message") or "")
    if "Nothing was sent" in message:
        raise RuntimeError(f"emitting {event_type} reached no stream: {message}")
    print(f"emitted {event_type}: {message or json.dumps(parsed)[:200]}", flush=True)


def wait_for(driver, predicate, what):
    deadline = time.time() + 30
    last = None
    while time.time() < deadline:
        last = driver.status()
        if predicate(last):
            return last
        time.sleep(1)
    raise RuntimeError(f"timed out waiting for {what}: {json.dumps(last)[:600]}")


def prepare_sts(sts_port, secret, name=None):
    given = os.environ.get("IYA_STS_URL", "").rstrip("/")
    if given:
        print(f"using {given}", flush=True)
        return given, None
    if sts_port in FORBIDDEN_PORTS:
        raise SystemExit(f"refusing to bind port {sts_port}")
    image = os.environ.get("IYA_STS_IMAGE", "")
    source = os.environ.get("IYA_STS_SRC", "")
    cloned = None
    if not image:
        if not source:
            cloned = tempfile.mkdtemp(prefix="iya-sts-main-")
            run(["git", "clone", "--depth", "1", "--branch", "main", STS_REPO, cloned])
            run(["git", "-C", cloned, "submodule", "update", "--init", "--recursive"])
            source = cloned
        image = "iya-sts-live:main"
        docker("build", "-t", image, source)
    name = name or "iya-sts-live-" + PROFILE["repo"]
    docker_rm(name)
    # The secret passes by name (-e NAME, the value in this child's environment):
    # it is neither on the printed command line nor written to a file.
    env = os.environ.copy()
    env["STS_ADMIN_API_CLIENT_SECRET"] = secret
    docker(
        "run", "-d", "--name", name,
        "-e", f"STS_PORT={sts_port}",
        "-e", "STS_PERSISTENCE_MODE=memory",
        "-e", "STS_CLUSTER_MODE=off",
        "-e", "STS_WORKERS_REQUEST_COUNT=0",
        "-e", "STS_WORKERS_SURFACE_COUNT=0",
        "-e", "STS_ADMIN_API_CLIENT_SECRET",
        "-e", "STS_LOG_LEVEL=info",
        "-p", f"127.0.0.1:{sts_port}:{sts_port}",
        image,
        env=env,
    )
    return f"https://127.0.0.1:{sts_port}", name


def generate_keys(image, work, config):
    """Write the relying-party key pair with this crate's CLI inside the demo image."""
    (work / "generated").mkdir(parents=True, exist_ok=True)
    docker(
        "run", "--rm",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "-v", f"{work}:/work",
        "-w", "/work",
        image,
        "wsfed-caep", "generate-keys", "--config", "/work/" + config.name,
    )


def configure_demo(config, sts_origin, demo_origin, username, password, secret, pep=None):
    """Register the relying party with the host's python3. It imports nothing outside the standard library."""
    env = os.environ.copy()
    env["ADMIN_API_CLIENT_SECRET"] = secret
    env["STS_ADMIN_API_CLIENT_SECRET"] = secret
    env[PROFILE["password_env"]] = password
    env["PUBLIC_URL"] = demo_origin
    env.pop("PORT", None)
    completed = run(
        [
            *PROFILE["configure"],
            "--config", str(config),
            "--idp", sts_origin,
            "--public-url", demo_origin,
            "--test-user", username,
            *(["--pep", pep] if pep else []),
        ],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
    )
    if completed.stdout:
        print(completed.stdout, flush=True)
    if completed.stderr:
        print(completed.stderr, file=sys.stderr, flush=True)


# The embedded PEP (#40): its names, key path and policy are the install script's.
from configure_iya_sts import PEP_EVENT, PEP_KEY, TEST_ATTRIBUTE, TEST_ATTRIBUTE_VALUE, orders_policy  # noqa: E402

PEP_LOCAL_CONFIG = "wsfed.pep-local.json"
# The second test user: signed in like the first, but its attr1 is not abc123, so the demo
# application's policy denies it GET /attribute-protected (403) and still permits GET /orders/42.
DENIED_USER = PROFILE["test_user"] + "-denied"
DENIED_VALUE = "not-" + TEST_ATTRIBUTE_VALUE


def create_denied_user(client, sts_origin, secret, password):
    """The denied test user, with attr1=not-abc123. Runs after the install script, which defines
    the realm's custom attribute attr1. The password is never printed."""
    token = mint_admin(client, sts_origin, secret)
    status, made = admin_json(client, sts_origin, token, "POST", "/admin-api/users/create", {
        "username": DENIED_USER, "invent": False, "credential": "password", "password": password, "passwordConfirm": password,
        "attributes": {"cn": "WS-Fed Demo denied", "givenName": "WS-Fed", "sn": "Denied", "displayName": "WS-Fed Demo denied",
                       "mail": DENIED_USER + "@wsfed-demo.test"},
    })
    if status != 200 or made.get("ok") is False:
        made.pop("password", None)
        raise RuntimeError(f"creating {DENIED_USER} answered {status}: {json.dumps(made)[:400]}")
    print(f"created the denied test user {DENIED_USER}", flush=True)
    admin_ok(client, sts_origin, token, "/admin-api/users/set-attribute",
             {"user": DENIED_USER, "attribute": TEST_ATTRIBUTE, "value": DENIED_VALUE},
             f"{DENIED_USER} has {TEST_ATTRIBUTE}={DENIED_VALUE}")


def admin_ok(client, sts_origin, token, path, body, what):
    status, parsed = admin_json(client, sts_origin, token, "POST", path, body)
    if status != 200 or parsed.get("ok") is False:
        raise RuntimeError(f"{what}: POST {path} answered {status}: {json.dumps(parsed)[:500]}")
    print(f"{what}: {status}", flush=True)
    return parsed


def local_copy(config, dest):
    """The install script wrote a central pep section; a copy says local."""
    raw = json.loads(config.read_text(encoding="utf-8"))
    if not isinstance(raw.get("pep"), dict) or raw["pep"].get("mode") != "central":
        raise RuntimeError(f"the install script did not write a central pep section: {json.dumps(raw.get('pep'))}")
    raw["pep"] = dict(raw["pep"], mode="local")
    dest.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
    return raw["realm"]


def flip_policy(client, sts_origin, token, application):
    """The application's own policy (the install script's) now denies read too. The realm root is
    never touched."""
    status, page = admin_json(client, sts_origin, token, "GET",
                              "/admin-api/applications?application=" + urllib.parse.quote(application, safe=""))
    fga = ((page.get("page") or {}).get("fga") or {}) if status == 200 else {}
    name = (fga.get("policy") or {}).get("name") or fga.get("reference")
    if not name or fga.get("enforced") is not True:
        raise RuntimeError(f"the application does not enforce a policy of its own: {json.dumps(fga)[:400]}")
    admin_ok(client, sts_origin, token, "/admin-api/xacml/import-alfa",
             {"name": name, "alfa": orders_policy("wsfeddemolocked", "deny")},
             "the application's own policy now denies read on an order")


def order(driver, method):
    url = driver.demo_origin + "/orders/42"
    status, _headers, payload = driver.client.request(method, url, body=b"" if method == "POST" else None,
                                                      headers={"accept": "text/html"})
    print(f"{method} {status} demo /orders/42", flush=True)
    return status, payload


def page(driver, method, path):
    url = driver.demo_origin + path
    status, _headers, payload = driver.client.request(method, url, body=b"" if method == "POST" else None,
                                                      headers={"accept": "text/html"})
    print(f"{method} {status} demo {path}", flush=True)
    return status, payload.decode("utf-8", "replace")


def attribute_checks(driver, allowed):
    """GET /attribute-protected: the allowed user (attr1=abc123) 200, the denied user
    (attr1=not-abc123) 403 by a Deny, not a failure; the denied user still reads order 42."""
    status, body = page(driver, "GET", "/attribute-protected")
    if allowed:
        ok = status == 200 and "<h1>Allowed</h1>" in body
        checks = {"attributeProtectedIs200": ok}
    else:
        ok = status == 403 and "<h1>Not allowed</h1>" in body and "could not decide" not in body
        read_status, read_body = page(driver, "GET", "/orders/42")
        checks = {"user": DENIED_USER, "attributeProtectedIs403": ok, "readIs200": read_status == 200}
        if read_status != 200:
            raise RuntimeError(f"the denied user: GET /orders/42 answered {read_status}: {read_body[:400]}")
    if not ok:
        who = "the allowed user" if allowed else "the denied user"
        raise RuntimeError(f"{who}: GET /attribute-protected answered {status}: {body[:600]}")
    return checks


def pep_checks(driver, mode):
    """GET is read (Permit, 200) and POST is write (Deny, 403); GET /attribute-protected is 200."""
    deadline = time.time() + 60
    state = {}
    while time.time() < deadline:
        state = driver.status().get("pep") or {}
        if state.get("registered") and (mode == "central" or state.get("holdsPolicy")):
            break
        time.sleep(1)
    else:
        raise RuntimeError(f"the {mode} PEP did not get ready: {json.dumps(state)[:600]}")
    read_status, read_body = order(driver, "GET")
    write_status, write_body = order(driver, "POST")
    checks = {"mode": state.get("mode"), "registered": bool(state.get("registered")),
              "readIs200": read_status == 200, "writeIs403": write_status == 403}
    if mode == "local":
        checks["policyCount"] = state.get("policyCount")
    if state.get("mode") != mode or read_status != 200 or write_status != 403:
        why = (read_body if read_status != 200 else write_body)[:400].decode("utf-8", "replace")
        raise RuntimeError(f"{mode}: GET /orders/42 answered {read_status}, POST {write_status}: {why}; pep {json.dumps(state)[:600]}")
    checks.update(attribute_checks(driver, allowed=True))
    return checks


def denied_checks(sts_origin, demo_origin, ca_file, password):
    """The denied user signs in with a browser of its own (its own cookies) and is checked."""
    denied = Driver(Client(ca_file), sts_origin, demo_origin, DENIED_USER, password)
    denied.sign_in()
    wait_for(denied, lambda row: row.get("signedIn") is True, "the denied user signed in")
    return attribute_checks(denied, allowed=False)


def flip_check(driver, client, sts_origin, token, application):
    """local: the application's policy moves to deny read, and the PEP hears of it by event."""
    before = driver.status().get("pep") or {}
    events_before = sum(1 for item in driver.status().get("events") or [] if item.get("type") == PEP_EVENT)
    flipped_at = time.time()
    flip_policy(client, sts_origin, token, application)
    limit = float(os.environ.get("PEP_FLIP_TIMEOUT") or 30)
    status = None
    while time.time() - flipped_at < limit:
        status, _body = order(driver, "GET")
        if status == 403:
            break
        time.sleep(1)
    after = driver.status()
    state = after.get("pep") or {}
    events = sum(1 for item in after.get("events") or [] if item.get("type") == PEP_EVENT)
    result = {
        "readIs403AfterFlip": status == 403,
        "seconds": round(time.time() - flipped_at, 1),
        "eventReceived": events > events_before,
        "syncTokenMoved": bool(state.get("syncToken")) and state.get("syncToken") != before.get("syncToken"),
        "policyEvents": state.get("policyEvents"),
    }
    # The fallback poll is left at its 300 s default, so a change applied
    # within the bound, with the event received, came through the event.
    result["via"] = "event" if result["eventReceived"] and result["readIs403AfterFlip"] and result["seconds"] < 300 else "poll"
    if status != 403 or result["via"] != "event":
        raise RuntimeError(f"local: after the flip {json.dumps(result)}; pep {json.dumps(state)[:600]}")
    return result


def start_demo(image, demo_name, demo_port, demo_origin, mounts, env=None):
    """A fresh demo container with only `mounts`, file by file and read-only."""
    docker_rm(demo_name)
    args = ["run", "-d", "--name", demo_name, "--network", "host", "--user", f"{os.getuid()}:{os.getgid()}"]
    for source, target in mounts:
        args += ["-v", f"{source}:{target}:ro"]
    args += ["-e", f"PORT={demo_port}", "-e", f"PUBLIC_URL={demo_origin}"]
    for name, value in (env or {}).items():
        args += ["-e", f"{name}={value}"]
    docker(*args, image)
    deadline = time.time() + 90
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", demo_port, timeout=3)
            conn.request("GET", "/healthz")
            response = conn.getresponse()
            body = response.read()
            conn.close()
            if response.status == 200 and body == b"ok":
                return
        except OSError:
            pass
        time.sleep(1)
    logs = subprocess.run(["docker", "logs", demo_name], check=False, text=True, capture_output=True)
    if logs.stdout:
        print(logs.stdout, flush=True)
    if logs.stderr:
        print(logs.stderr, file=sys.stderr, flush=True)
    raise RuntimeError("the demo /healthz did not answer ok")


def provision(work, sts_origin, demo_origin, username, password, secret, image, pep=None, denied_password=None):
    """What a user does, in order: the checkout copied to a build context, the demo image built,
    the key pair generated inside it, the install script (with --pep `pep`), the image built
    again with the trust chain, and the image's demo/generated checked. With a
    `denied_password`, the denied test user is created after the install script. Answers what
    the demo needs to run."""
    context = work / "context"
    copy_context(context)
    demo_dir = context / "demo"
    config = demo_dir / "wsfed.json"
    rewrite_config(ROOT / PROFILE["config_file"], config, sts_origin, demo_origin)
    # Built once without a chain (as a fresh clone would be) for the key pair;
    # the registrar writes the chain where idpCa names it; built again, which
    # changes only the demo/ layer.
    docker("build", "-t", image, str(context))
    generate_keys(image, demo_dir, config)
    configure_demo(config, sts_origin, demo_origin, username, password, secret, pep=pep)
    ca_file = demo_dir / "generated" / "idp-ca.pem"
    if not ca_file.exists():
        raise RuntimeError(f"the registrar did not write {ca_file}")
    out = {"demo_dir": demo_dir, "config": config, "ca_file": ca_file, "pep": {}}
    pep_key = demo_dir / PEP_KEY
    if pep:
        # The install script set the PEP up and wrote its section; for a
        # central run, a copy says local. Both go into the image; the key never does.
        if not pep_key.exists():
            raise RuntimeError("the install script did not make the PEP's key")
        written = json.loads(config.read_text(encoding="utf-8"))
        if (written.get("pep") or {}).get("mode") != pep:
            raise RuntimeError(f"the install script did not write a {pep} pep section: {json.dumps(written.get('pep'))}")
        out["pep"]["application"] = local_copy(config, demo_dir / PEP_LOCAL_CONFIG) if pep == "central" else written["realm"]
        out["pep"]["name"] = written["pep"]["name"]
    if denied_password:
        create_denied_user(Client(ca_file), sts_origin, secret, denied_password)
    docker("build", "-t", image, str(context))
    listed = docker("run", "--rm", image, "ls", "-A", "demo/generated", capture_output=True).stdout.split()
    if listed != ["idp-ca.pem"]:
        raise RuntimeError(f"the demo image's demo/generated holds {listed}, not only the trust chain")
    baked = docker("run", "--rm", image, "cat", "demo/generated/idp-ca.pem", capture_output=True)
    if baked.stdout != ca_file.read_text(encoding="utf-8"):
        raise RuntimeError("the demo image does not carry the chain the registrar wrote")
    out["chain_count"] = baked.stdout.count("BEGIN CERTIFICATE")
    print(f"the demo image carries the {out['chain_count']}-certificate chain at /app/demo/generated/idp-ca.pem", flush=True)
    mounts = [(demo_dir / "generated" / name, f"/app/demo/generated/{name}") for name in ("rp.key", "rp.crt", "idp-metadata.xml")]
    if pep:
        mounts.append((pep_key, "/app/demo/" + PEP_KEY))
    out["mounts"] = mounts
    return out


def checked_ports(sts_port, demo_port, sts_given):
    bound = [demo_port] if sts_given else [sts_port, demo_port]
    if any(port in FORBIDDEN_PORTS for port in bound) or len(set(bound)) != len(bound):
        raise SystemExit("LIVE_STS_PORT and LIVE_DEMO_PORT must not bind 3000, 8081, or 18481 to 18495")


def main():
    if "--authzen" in sys.argv[1:] or os.environ.get("LIVE_AUTHZEN", "") in ("1", "true", "yes"):
        import live_authzen
        return live_authzen.main()
    pep = "--pep" in sys.argv[1:] or os.environ.get("LIVE_PEP", "") in ("1", "true", "yes")
    sts_port = int(os.environ.get("LIVE_STS_PORT") or 18517)
    demo_port = int(os.environ.get("LIVE_DEMO_PORT") or 18617)
    checked_ports(sts_port, demo_port, bool(os.environ.get("IYA_STS_URL", "").strip()))
    secret = os.environ.get("ADMIN_API_CLIENT_SECRET") or os.environ.get("STS_ADMIN_API_CLIENT_SECRET") or secrets.token_urlsafe(24)
    password = os.environ.get(PROFILE["password_env"]) or secrets.token_urlsafe(18)
    denied_password = secrets.token_urlsafe(18) if pep else None
    username = PROFILE["test_user"]
    sts_origin, sts_name = prepare_sts(sts_port, secret)
    demo_origin = f"http://127.0.0.1:{demo_port}"
    demo_name = PROFILE["repo"] + "-live-demo"
    image = PROFILE["repo"] + "-live:demo"
    work = Path(tempfile.mkdtemp(prefix=PROFILE["repo"] + "-live-"))
    try:
        wait_port(urllib.parse.urlsplit(sts_origin).port or 443, 120)
        wait_ready(sts_origin, 90)
        made = provision(work, sts_origin, demo_origin, username, password, secret, image,
                         pep="central" if pep else None, denied_password=denied_password)
        ca_file, mounts, chain_count, pep_result = made["ca_file"], made["mounts"], made["chain_count"], made["pep"]
        start_demo(image, demo_name, demo_port, demo_origin, mounts)
        client = Client(ca_file)
        driver = Driver(client, sts_origin, demo_origin, username, password)
        driver.sign_in()
        signed_in = wait_for(
            driver,
            lambda row: row.get("signedIn") is True and "polling" in str(row.get("receiver") or ""),
            "a signed-in demo polling its stream",
        )
        print(f"signed in as {signed_in.get('subject')}; {signed_in.get('receiver')}", flush=True)
        if pep:
            pep_result["central"] = pep_checks(driver, "central")
            pep_result["central"]["denied"] = denied_checks(sts_origin, demo_origin, ca_file, denied_password)
        token = mint_admin(client, sts_origin, secret)
        session_id = session_id_for(client, sts_origin, token, username)
        emit(client, sts_origin, token, session_id, "credential-change")
        wait_for(
            driver,
            lambda row: row.get("signedIn") is True and any(
                item.get("type") == CREDENTIAL_CHANGE for item in row.get("events") or []
            ),
            "credential-change while still signed in",
        )
        emit(client, sts_origin, token, session_id, "session-revoked")
        finished = wait_for(
            driver,
            lambda row: row.get("signedIn") is False and any(
                item.get("type") == SESSION_REVOKED for item in row.get("events") or []
            ),
            "session-revoked to end the local session",
        )
        result = {"ok": True, "subject": signed_in.get("subject"), "idpCaInImage": chain_count, "events": finished.get("events")}
        if pep:
            # THEN local: the same image and iya-sts, the copy that says local.
            start_demo(image, demo_name, demo_port, demo_origin, mounts, env={"WSFED_CONFIG": "demo/" + PEP_LOCAL_CONFIG})
            local_driver = Driver(Client(ca_file), sts_origin, demo_origin, username, password)
            local_driver.sign_in()
            wait_for(local_driver, lambda row: row.get("signedIn") is True and "polling" in str(row.get("receiver") or ""),
                     "a signed-in local-mode demo polling its stream")
            local = pep_checks(local_driver, "local")
            local["denied"] = denied_checks(sts_origin, demo_origin, ca_file, denied_password)
            token = mint_admin(client, sts_origin, secret)
            local["policyChange"] = flip_check(local_driver, client, sts_origin, token, pep_result["application"])
            pep_result["local"] = local
            result["pep"] = pep_result
        print(json.dumps(result, indent=2))
    finally:
        docker_rm(demo_name)
        if sts_name:
            docker_rm(sts_name)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(str(err), file=sys.stderr)
        sys.exit(1)
