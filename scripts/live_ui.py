#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The demo's two PEP-protected pages through a real headless browser (#40).

`python3 scripts/live_ui.py` (needs IYA_STS_IMAGE with iya-sts #2026-#2028)
provisions the way scripts/live_iya_sts.py does, with its own functions: a
FRESH iya-sts container on this repo's live ports (LIVE_STS_PORT, 18517), the
checkout copied to a scratch build context, the demo image built, the key pair
generated inside it, the install script run with --pep local (which gives the
test user attr1=abc123), the second, denied test user created with
attr1=not-abc123, the image built again with the trust chain, and the demo run
(LIVE_DEMO_PORT, 18617) with only its keys and metadata mounted.

Then scripts/live_ui_browser.py drives Chromium in Playwright's official image
(PLAYWRIGHT_IMAGE, mcr.microsoft.com/playwright/python:v1.49.0-noble,
--network host). That image carries the browsers but not the Python package,
so the container installs playwright==1.49.0 into its own /tmp; nothing is
installed on the host. The browser signs in as the allowed user through the
demo's Sign in button and iya-sts's sign-in page, checks /attribute-protected
and /orders/42 are 200 (by URL and by the top bar's links), signs out from the
user menu, signs in as the denied user, and checks /attribute-protected 403,
GET /orders/42 200 and POST /orders/42 403 (page.request, the browser's
cookies). Each check is on the page response's HTTP status and its heading.

Screenshots go to LIVE_UI_OUT, or a new directory under the system temp
directory, never the checkout; the summary names it. The last thing printed is
JSON; any mismatch exits 1. Passwords reach the browser container as -e NAME
(the value in the child's environment) and are never printed.

Containers: iya-sts-live-wsfed-caep-rust-ui, wsfed-caep-rust-live-ui-demo,
wsfed-caep-rust-live-ui-browser; only these are removed. Never binds 3000,
8081 or 18481 to 18495.
"""

import http.client
import json
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

PLAYWRIGHT_IMAGE = os.environ.get("PLAYWRIGHT_IMAGE") or "mcr.microsoft.com/playwright/python:v1.49.0-noble"
PLAYWRIGHT_PACKAGE = "playwright==1.49.0"
STS_NAME = "iya-sts-live-" + live.PROFILE["repo"] + "-ui"
DEMO_NAME = live.PROFILE["repo"] + "-live-ui-demo"
BROWSER_NAME = live.PROFILE["repo"] + "-live-ui-browser"
IMAGE = live.PROFILE["repo"] + "-live-ui:demo"
BROWSER_SCRIPT = Path(__file__).resolve().parent / "live_ui_browser.py"


def pep_ready(demo_port, timeout=90):
    """/live-status (no sign-in needed) until the local PEP is registered and holds the policy."""
    deadline = time.time() + timeout
    state = {}
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", demo_port, timeout=5)
            conn.request("GET", "/live-status", headers={"accept": "application/json"})
            state = json.loads(conn.getresponse().read() or b"{}").get("pep") or {}
            conn.close()
            if state.get("registered") and state.get("holdsPolicy"):
                return state
        except (OSError, ValueError):
            pass
        time.sleep(1)
    raise RuntimeError(f"the local PEP did not get ready: {json.dumps(state)[:600]}")


def run_browser(out, sts_origin, demo_origin, users):
    """Playwright's container, on the host network, writing screenshots to `out`."""
    env = os.environ.copy()
    env.update({
        "UI_DEMO": demo_origin, "UI_STS": sts_origin, "UI_OUT": "/out",
        "UI_ALLOWED_USER": users["allowed"][0], "UI_ALLOWED_PASSWORD": users["allowed"][1],
        "UI_DENIED_USER": users["denied"][0], "UI_DENIED_PASSWORD": users["denied"][1],
    })
    live.docker_rm(BROWSER_NAME)
    command = [
        "docker", "run", "--rm", "--name", BROWSER_NAME, "--network", "host", "--ipc", "host",
        "--user", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp", "-e", "PLAYWRIGHT_BROWSERS_PATH=/ms-playwright",
        *[arg for name in ("UI_DEMO", "UI_STS", "UI_OUT", "UI_ALLOWED_USER", "UI_ALLOWED_PASSWORD", "UI_DENIED_USER", "UI_DENIED_PASSWORD") for arg in ("-e", name)],
        "-v", f"{out}:/out", "-v", f"{BROWSER_SCRIPT}:/ui/live_ui_browser.py:ro",
        PLAYWRIGHT_IMAGE, "sh", "-c",
        f"pip install --quiet --disable-pip-version-check --target /tmp/pw {PLAYWRIGHT_PACKAGE} && PYTHONPATH=/tmp/pw python3 /ui/live_ui_browser.py",
    ]
    print("+ " + " ".join(command), flush=True)
    completed = subprocess.run(command, env=env, text=True, capture_output=True, check=False)
    lines = completed.stdout.splitlines()
    for line in lines:
        if not line.startswith("@@UI@@"):
            print(line, flush=True)
    if completed.stderr:
        print(completed.stderr[-4000:], file=sys.stderr, flush=True)
    marked = [line for line in lines if line.startswith("@@UI@@")]
    if not marked:
        raise RuntimeError(f"the browser container exited {completed.returncode} without a result")
    return json.loads(marked[-1][len("@@UI@@"):])


def main():
    sts_port = int(os.environ.get("LIVE_STS_PORT") or 18517)
    demo_port = int(os.environ.get("LIVE_DEMO_PORT") or 18617)
    if os.environ.get("IYA_STS_URL", "").strip():
        raise SystemExit("live_ui.py always starts a fresh iya-sts; unset IYA_STS_URL")
    live.checked_ports(sts_port, demo_port, False)
    secret = os.environ.get("ADMIN_API_CLIENT_SECRET") or os.environ.get("STS_ADMIN_API_CLIENT_SECRET") or secrets.token_urlsafe(24)
    password = secrets.token_urlsafe(18)
    denied_password = secrets.token_urlsafe(18)
    username = live.PROFILE["test_user"]
    out = Path(os.environ.get("LIVE_UI_OUT") or tempfile.mkdtemp(prefix=live.PROFILE["repo"] + "-live-ui-"))
    out.mkdir(parents=True, exist_ok=True)
    if out.resolve().is_relative_to(live.ROOT):
        raise SystemExit("LIVE_UI_OUT must be outside the checkout (screenshots are not committed)")
    sts_origin, sts_name = live.prepare_sts(sts_port, secret, STS_NAME)
    demo_origin = f"http://127.0.0.1:{demo_port}"
    work = Path(tempfile.mkdtemp(prefix=live.PROFILE["repo"] + "-live-ui-work-"))
    try:
        live.wait_port(urllib.parse.urlsplit(sts_origin).port or 443, 120)
        live.wait_ready(sts_origin, 90)
        made = live.provision(work, sts_origin, demo_origin, username, password, secret, IMAGE,
                              pep="local", denied_password=denied_password)
        live.start_demo(IMAGE, DEMO_NAME, demo_port, demo_origin, made["mounts"])
        state = pep_ready(demo_port)
        browser = run_browser(out, sts_origin, demo_origin, {"allowed": (username, password), "denied": (live.DENIED_USER, denied_password)})
        summary = {
            "ok": bool(browser.get("ok")),
            "pep": {"mode": state.get("mode"), "name": state.get("name"), "application": state.get("application"), "policyCount": state.get("policyCount")},
            "users": {"allowed": username, "denied": live.DENIED_USER},
            "anotherAccount": browser.get("anotherAccount"),
            "checks": len(browser.get("checks") or []),
            "passed": sum(1 for row in browser.get("checks") or [] if row.get("ok")),
            "statuses": [{"user": row["user"], "check": row["check"], "got": row["got"]} for row in browser.get("checks") or [] if row["check"].endswith("status")],
            "mismatches": browser.get("mismatches") or [],
            "screenshotDir": str(out),
            "screenshots": browser.get("screenshots") or [],
        }
        print(json.dumps(summary, indent=2))
        if not summary["ok"]:
            sys.exit(1)
    finally:
        live.docker_rm(BROWSER_NAME)
        live.docker_rm(DEMO_NAME)
        if sts_name:
            live.docker_rm(sts_name)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as err:
        print(str(err), file=sys.stderr)
        sys.exit(1)
