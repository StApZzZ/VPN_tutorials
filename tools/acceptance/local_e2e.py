#!/usr/bin/env python3
"""Exercise local enrolment, MFA, reset, CSRF and token scopes on a lab gateway.

Use ADMIN_TOKEN in the environment. This creates two disposable accounts and
leaves them disabled; run only against your authorised acceptance environment.
"""
import argparse
import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
import re
import secrets
import ssl
import struct
import time
import urllib.error
import urllib.parse
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument("--panel", required=True)
parser.add_argument("--insecure", action="store_true", help="explicitly trust the lab's self-signed TLS")
args = parser.parse_args()
base = args.panel.rstrip("/")
admin = os.environ["ADMIN_TOKEN"]
context = ssl._create_unverified_context() if args.insecure else ssl.create_default_context()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *unused, **kwargs):
        return None


def session():
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect())


operator = session()


def call(path, method="GET", data=None, actor=None, form=False, csrf=""):
    headers = {"Origin": base}
    if actor is None:headers["Authorization"] = "Bearer " + admin
    if csrf:headers["X-CSRF-Token"] = csrf
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
        body = urllib.parse.urlencode(data).encode() if form else json.dumps(data).encode()
    else:body = None
    request = urllib.request.Request(base + path, data=body, method=method, headers=headers)
    try:
        response = (actor or operator).open(request, timeout=30)
    except urllib.error.HTTPError as exc:
        response = exc
    return response.status, response.read().decode(), response.headers


def api(path, method="GET", data=None):
    status, body, headers = call(path, method, data)
    assert status in (200, 201), (path.split("/")[:4], status)
    return json.loads(body)


def otp(secret, counter):
    digest = hmac.new(base64.b32decode(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return str((struct.unpack(">I", digest[offset:offset+4])[0] & 0x7fffffff) % 1000000).zfill(6)


created = []
issued_tokens = []
try:
    suffix = secrets.token_hex(4)
    password = secrets.token_urlsafe(24)
    for role in ("user", "admin"):
        user = api("/api/auth/local-users", "POST", {"username": "accept-"+role+"-"+suffix, "role": role})
        created.append(user["id"])
        invitation = api("/api/auth/local-users/"+user["id"]+"/invite", "POST")
        path = urllib.parse.urlsplit(invitation["invite_url"]).path
        assert path.rsplit("/",1)[1] not in call("/api/auth/local-users")[1]
        actor = session()
        status, page, _ = call(path, actor=actor)
        assert status == 200
        secret = re.search(r"<code>([A-Z2-7]+)</code>", page).group(1)
        counter = int(time.time())//30
        code = otp(secret, counter) if role == "admin" else ""
        status, page, _ = call(path, "POST", {"password": password, "otp": code}, actor=actor, form=True)
        assert status == 200
        recovery = re.findall(r"<li><code>([^<]+)</code></li>", page)
        assert call(path, "POST", {"password": password}, actor=session(), form=True)[0] == 400
        credentials = {"username": user["username"], "password": password, "otp": ""}
        if role == "admin":
            credentials["otp"] = code
            assert "error=failed" in call("/login", "POST", credentials, actor=session(), form=True)[2].get("Location", "")
            credentials["otp"] = otp(secret, counter+1)
        assert call("/login", "POST", credentials, actor=actor, form=True)[0] == 302
        assert call("/api/auth/me", actor=actor)[0] == 200
        if role == "user":
            assert call("/api/auth/local-users", actor=actor)[0] == 403
            assert call("/api/me/devices", "POST", {"name": "csrf-probe", "protocol": "wg"}, actor=actor)[0] == 403
        else:
            credentials["otp"] = recovery[0]
            assert call("/login", "POST", credentials, actor=session(), form=True)[0] == 302
            assert "error=failed" in call("/login", "POST", credentials, actor=session(), form=True)[2].get("Location", "")
        api("/api/auth/local-users/"+user["id"]+"/reset", "POST")
        assert call("/api/auth/me", actor=actor)[0] == 401
        assert "error=failed" in call("/login", "POST", credentials, actor=session(), form=True)[2].get("Location", "")
    for scope, path in (("metrics", "/metrics"), ("auditor", "/api/auth/audit/export?limit=1")):
        issued = api("/api/auth/tokens", "POST", {"name": "accept-"+scope+"-"+suffix, "role": scope, "ttl_days": 1})
        record = issued.get("record") or issued.get("token_record") or issued
        issued_tokens.append(record.get("id"))
        headers = {"Authorization": "Bearer " + issued["token"]}
        with operator.open(urllib.request.Request(base+path, headers=headers), timeout=30) as response:assert response.status == 200
        try:operator.open(urllib.request.Request(base+"/api/devices", headers=headers), timeout=30)
        except urllib.error.HTTPError as exc:assert exc.code == 403
        else:raise AssertionError("Read-only scope accessed device management")
    print("PASS: local invitations, password reset, TOTP replay, recovery replay, session invalidation, roles, CSRF, metrics and auditor scopes")
finally:
    for user_id in created:call("/api/auth/users/"+user_id+"/disable", "POST")
    for token_id in filter(None, issued_tokens):call("/api/auth/tokens/"+token_id, "DELETE")
