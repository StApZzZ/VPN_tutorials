#!/usr/bin/env python3
"""Acceptance kit: sign in to the panel through Keycloak like a browser does.

    python3 oidc_e2e.py --panel https://203.0.113.10 --user alice --expect admin
    python3 oidc_e2e.py --panel https://203.0.113.10 --user bob   --expect user
    python3 oidc_e2e.py --panel https://203.0.113.10 --user carol --expect denied

The password is read from the environment variable PASSWORD (never argv).
--insecure accepts the self-signed panel certificate. Standard library only.

Checks: /auth/oidc/start -> Keycloak login form -> credentials -> callback ->
the panel's landing page for the role (admin/operator "/", user "/me") and a
working session whose role GET /api/auth/me reports, or /login?error=denied
for a user without a VPN group. Exit code 0 = expectation met.
"""
from __future__ import annotations

import argparse
import html
import http.cookiejar
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


class LoginForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = ""
        self.fields: dict[str, str] = {}
        self._in_form = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form" and (a.get("id") == "kc-form-login" or not self.action):
            self.action = html.unescape(a.get("action", ""))
            self._in_form = True
        elif tag == "input" and self._in_form and a.get("name"):
            self.fields[a["name"]] = a.get("value", "") or ""

    def handle_endtag(self, tag):
        if tag == "form":
            self._in_form = False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--panel", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--expect", choices=["admin", "operator", "user", "denied"], required=True)
    ap.add_argument("--insecure", action="store_true")
    opts = ap.parse_args()
    password = os.environ.get("PASSWORD", "")
    if not password:
        print("set PASSWORD in the environment", file=sys.stderr)
        return 2

    ctx = ssl.create_default_context()
    if opts.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect(),
                                         urllib.request.HTTPSHandler(context=ctx))

    def request(url: str, data: dict | None = None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        try:
            resp = opener.open(urllib.request.Request(url, data=body), timeout=20)
        except urllib.error.HTTPError as exc:  # 3xx arrive here because redirects are not followed
            resp = exc
        return resp.status if hasattr(resp, "status") else resp.code, resp.headers, resp.read().decode("utf-8", "replace")

    panel = opts.panel.rstrip("/")
    status, headers, _ = request(f"{panel}/auth/oidc/start")
    location = headers.get("Location", "")
    if status != 302 or "/protocol/openid-connect/auth" not in location:
        print(f"FAIL start: {status} {location}")
        return 1

    status, headers, page = request(location)
    form = LoginForm()
    form.feed(page)
    if status != 200 or not form.action:
        print(f"FAIL: no Keycloak login form (HTTP {status})")
        return 1
    fields = {**form.fields, "username": opts.user, "password": password}
    status, headers, page = request(urllib.parse.urljoin(location, form.action), fields)
    callback = urllib.parse.urljoin(location, headers.get("Location", ""))
    if status not in (302, 303) or "/auth/oidc/callback" not in callback:
        print(f"FAIL: Keycloak did not redirect back (HTTP {status}); wrong password or redirect URI?")
        return 1

    status, headers, _ = request(callback)
    landing = headers.get("Location", "")
    if opts.expect == "denied":
        ok = landing.endswith(("/login?error=denied", "/login?error=groups_claim"))
        print(("PASS" if ok else "FAIL") + f": {opts.user} -> {landing or status} (expected a refusal)")
        return 0 if ok else 1
    want = "/me" if opts.expect == "user" else "/"
    if status != 302 or urllib.parse.urlparse(landing).path != want:
        print(f"FAIL: landing {status} {landing}, expected {want}")
        return 1
    # The role comes from the API, not from page text: the UI is translated.
    status, _, body = request(f"{panel}/api/auth/me")
    try:
        role = json.loads(body).get("role") if status == 200 else None
    except ValueError:
        role = None
    if role != opts.expect:
        print(f"FAIL: /api/auth/me HTTP {status}, role {role}; expected {opts.expect}")
        return 1
    print(f"PASS: {opts.user} signed in via OIDC as {opts.expect}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
