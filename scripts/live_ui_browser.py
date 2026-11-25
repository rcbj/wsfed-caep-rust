#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The demo's UI in a real headless browser (#40). Runs INSIDE Playwright's
container (scripts/live_ui.py starts it); never on the host.

A person's path through the demo's real pages: open the demo, click Sign in,
follow the WS-Federation redirect to iya-sts's sign-in page, type the allowed
user's username and password and press Sign In, land back on the demo through
the wresult form post, then open /attribute-protected and /orders/42 (by URL
and by the top bar's links) and check each page response's HTTP status and
its visible text. Then Sign out from the user menu, sign in as the denied user
(through "Sign in with another account", wfresh=0, if iya-sts's session
lingers), and check /attribute-protected 403, GET /orders/42 200, and POST
/orders/42 403 through page.request with the browser's own cookies.

Reads UI_DEMO, UI_STS, UI_ALLOWED_USER, UI_ALLOWED_PASSWORD, UI_DENIED_USER,
UI_DENIED_PASSWORD and UI_OUT (the screenshot directory). Prints no password
and no URL beyond the two origins' paths. The last line is `@@UI@@` and the
JSON result.
"""

import json
import os
import sys
import traceback

from playwright.sync_api import sync_playwright

DEMO = os.environ["UI_DEMO"].rstrip("/")
STS = os.environ["UI_STS"].rstrip("/")
OUT = os.environ.get("UI_OUT", "/out")
TIMEOUT_MS = 30000

result = {"checks": [], "mismatches": [], "screenshots": []}
shot_no = [0]


def shot(page, name):
    shot_no[0] += 1
    path = os.path.join(OUT, f"{shot_no[0]:02d}-{name}.png")
    page.screenshot(path=path, full_page=True)
    result["screenshots"].append(os.path.basename(path))


def check(who, what, want, got, text=""):
    row = {"user": who, "check": what, "want": want, "got": got, "ok": want == got}
    if text:
        row["text"] = text
    result["checks"].append(row)
    if not row["ok"]:
        result["mismatches"].append(row)
    print(f"{'ok  ' if row['ok'] else 'FAIL'} {who}: {what}: want {want}, got {got}", flush=True)


def where(page):
    """Where the page is, without its query (it carries pending-step handles)."""
    url = page.url.split("?")[0].split("#")[0]
    return url.replace(DEMO, "demo").replace(STS, "iya-sts")


def heading(page):
    return page.locator("main h1").first.inner_text(timeout=TIMEOUT_MS).strip()


def sign_in_at_sts(page, username, password):
    """iya-sts's sign-in page, as a person completes it: the username, the
    password, Sign In. Optional later steps (MFA enrolment, post-login) are
    skipped by their own buttons."""
    page.wait_for_url(STS + "/authn/login**", timeout=TIMEOUT_MS)
    page.locator("#username").fill(username)
    page.locator("#password").fill(password)
    page.locator("#kc-login").click()
    for _ in range(6):
        page.wait_for_url(lambda url: url.startswith(DEMO) or "/authn/mfa-setup" in url or "/authn/post-login" in url, timeout=TIMEOUT_MS)
        if page.url.startswith(DEMO):
            break
        skip = page.locator("#post-login-skip, button[value='skip']").first
        skip.click()
    page.wait_for_url(DEMO + "/**", timeout=TIMEOUT_MS)
    page.wait_for_load_state("load")


def by_url(page, who, path, want, want_heading):
    response = page.goto(DEMO + path)
    status = response.status if response else None
    check(who, f"GET {path} (address bar) status", want, status)
    check(who, f"GET {path} (address bar) heading", want_heading, heading(page))
    return status


def by_link(page, who, label, path, want, want_heading):
    """The top bar's link, clicked: the navigation's own response."""
    with page.expect_navigation(url=DEMO + path, timeout=TIMEOUT_MS) as navigation:
        page.locator("nav.site-nav a", has_text=label).click()
    status = navigation.value.status
    check(who, f"GET {path} (top-bar link '{label}') status", want, status)
    check(who, f"GET {path} (top-bar link '{label}') heading", want_heading, heading(page))


def post_order(page, who, want, want_heading):
    """POST /orders/42 with the browser's cookies (the context's request)."""
    response = page.request.post(DEMO + "/orders/42", headers={"accept": "text/html"}, data="")
    body = response.text()
    check(who, "POST /orders/42 (page.request, browser cookies) status", want, response.status)
    check(who, "POST /orders/42 heading", True, f"<h1>{want_heading}</h1>" in body)


def menu_name(page):
    """The account the user menu names, by its local part: iya-sts sends a upn
    (username@realm-domain), which the menu shows before the name claim."""
    return page.locator("details.acct-menu .menu-name").first.inner_text(timeout=TIMEOUT_MS).strip().split("@")[0]


def main():
    allowed, denied = os.environ["UI_ALLOWED_USER"], os.environ["UI_DENIED_USER"]
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        # iya-sts's listener certificate is issued by its own CA; the browser
        # is told to accept it rather than given a trust store.
        context = browser.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 900})
        context.set_default_timeout(TIMEOUT_MS)
        page = context.new_page()
        try:
            # --- The allowed user -------------------------------------------
            response = page.goto(DEMO + "/")
            check("signed out", "GET / status", 200, response.status)
            shot(page, "signed-out")
            page.get_by_role("link", name="Sign in with WS-Federation").click()
            page.wait_for_url(STS + "/**")
            check(allowed, "Sign in went to iya-sts's sign-in page", "iya-sts/authn/login", where(page))
            page.locator("#username").wait_for(state="visible")  # the scripted page has drawn its form
            shot(page, "iya-sts-sign-in")
            sign_in_at_sts(page, allowed, os.environ["UI_ALLOWED_PASSWORD"])
            check(allowed, "back on the demo after the wresult form post", "demo/", where(page))
            check(allowed, "user menu names", allowed, menu_name(page))
            shot(page, "allowed-home")
            by_url(page, allowed, "/attribute-protected", 200, "Allowed")
            shot(page, "allowed-attribute-protected")
            by_url(page, allowed, "/orders/42", 200, "Order 42")
            shot(page, "allowed-order-42")
            by_link(page, allowed, "Attribute-protected", "/attribute-protected", 200, "Allowed")
            by_link(page, allowed, "Order 42", "/orders/42", 200, "Order 42")
            post_order(page, allowed, 403, "Not allowed")

            # --- Sign out from the user menu ---------------------------------
            page.locator("details.acct-menu > summary").click()
            shot(page, "user-menu")
            page.locator("details.acct-menu form[action='/logout'] button").click()
            page.wait_for_load_state("load")
            shot(page, "signed-out-at-iya-sts")
            response = page.goto(DEMO + "/attribute-protected")
            check("signed out", "GET /attribute-protected after sign-out status", 401, response.status)

            # --- The denied user ---------------------------------------------
            page.goto(DEMO + "/")
            page.get_by_role("link", name="Sign in with WS-Federation").click()
            page.wait_for_url(lambda url: url.startswith(STS + "/authn/login") or url.startswith(DEMO + "/"))
            result["anotherAccount"] = False
            if page.url.startswith(DEMO):
                # iya-sts's session lingered and signed the allowed user in
                # again: ask for another account (wfresh=0).
                result["anotherAccount"] = True
                page.locator("details.acct-menu > summary").click()
                page.get_by_role("menuitem", name="Sign in with another account").click()
            page.locator("#username").wait_for(state="visible")  # the scripted page has drawn its form
            shot(page, "iya-sts-sign-in-denied")
            sign_in_at_sts(page, denied, os.environ["UI_DENIED_PASSWORD"])
            check(denied, "user menu names", denied, menu_name(page))
            shot(page, "denied-home")
            by_url(page, denied, "/attribute-protected", 403, "Not allowed")
            shot(page, "denied-attribute-protected")
            by_link(page, denied, "Attribute-protected", "/attribute-protected", 403, "Not allowed")
            text = page.locator("main").inner_text()
            check(denied, "the 403 is a Deny, not a failure to decide", True, "The PEP denied it" in text and "could not decide" not in text)
            by_url(page, denied, "/orders/42", 200, "Order 42")
            shot(page, "denied-order-42")
            by_link(page, denied, "Order 42", "/orders/42", 200, "Order 42")
            post_order(page, denied, 403, "Not allowed")
        except Exception as err:  # a step that could not be taken is a mismatch
            result["mismatches"].append({"error": f"{type(err).__name__}: {str(err)[:600]}", "at": where(page)})
            traceback.print_exc()
            try:
                shot(page, "error")
            except Exception:
                pass
        finally:
            browser.close()
    result["ok"] = not result["mismatches"] and len(result["checks"]) > 0
    print("@@UI@@" + json.dumps(result), flush=True)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
