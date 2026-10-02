#!/usr/bin/env python3
"""Acceptance kit: sign in on the panel's login form (LDAP / AD or break-glass).

    PASSWORD=... python3 login_e2e.py --panel https://203.0.113.10 --insecure --user dave  --expect user
    PASSWORD=... python3 login_e2e.py --panel https://203.0.113.10 --insecure --user admin --expect admin

--expect admin|operator|user: the form signs the user in and GET /api/auth/me
reports that role. --expect failed|denied: the form refuses with that reason
(failed: wrong password or unknown user; denied: a valid account without VPN
access, e.g. in no VPN group or disabled in the directory); refused accepts
either. The password comes from the environment variable PASSWORD, which must
be set but may be empty (never argv). --insecure accepts a self-signed panel
certificate. Standard library only. Exit code 0 = expectation met.
"""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

ROLES = ("admin", "operator", "user")
REFUSALS = ("failed", "denied", "refused")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--panel", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--expect", choices=ROLES + REFUSALS, required=True)
    ap.add_argument("--insecure", action="store_true")
    opts = ap.parse_args()
    password = os.environ.get("PASSWORD")
    if password is None:
        print("set PASSWORD in the environment (it may be empty)", file=sys.stderr)
        return 2

    ctx = ssl.create_default_context()
    if opts.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                                         NoRedirect(), urllib.request.HTTPSHandler(context=ctx))

    def request(url: str, data: bytes | None = None, headers: dict | None = None):
        try:
            resp = opener.open(urllib.request.Request(url, data=data, headers=headers or {}), timeout=30)
        except urllib.error.HTTPError as exc:  # 3xx arrive here because redirects are not followed
            resp = exc
        return resp.status if hasattr(resp, "status") else resp.code, resp.headers, resp.read().decode("utf-8", "replace")

    panel = opts.panel.rstrip("/")
    form = urllib.parse.urlencode({"username": opts.user, "password": password}).encode()
    # The panel refuses cross-site form posts: send the Origin a browser would.
    status, headers, _ = request(f"{panel}/login", form,
                                 {"Origin": panel, "Content-Type": "application/x-www-form-urlencoded"})
    location = headers.get("Location", "")
    error = urllib.parse.parse_qs(urllib.parse.urlparse(location).query).get("error", [""])[0]
    if status not in (302, 303):
        print(f"FAIL: {opts.user}: POST /login answered HTTP {status}, not a redirect")
        return 1
    if opts.expect in REFUSALS:
        wanted = ("failed", "denied") if opts.expect == "refused" else (opts.expect,)
        ok = error in wanted
        print(("PASS" if ok else "FAIL") + f": {opts.user} -> {location} (expected a refusal: {opts.expect})")
        return 0 if ok else 1
    if error:
        print(f"FAIL: {opts.user} refused ({error}), expected role {opts.expect}")
        return 1
    status, _, body = request(f"{panel}/api/auth/me")
    try:
        role = json.loads(body).get("role") if status == 200 else None
    except ValueError:
        role = None
    ok = role == opts.expect
    print(("PASS" if ok else "FAIL") + f": {opts.user} signed in with the form; role {role}, expected {opts.expect}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
