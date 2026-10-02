#!/usr/bin/env python3
"""Acceptance kit: the panel's HTTP API for run.sh (standard library only).

Admin commands authenticate with the break-glass token from the environment
variable PANEL_TOKEN (Authorization: Bearer). Portal commands sign in on the
login form as --user, like an employee, with the password from the environment
variable PASSWORD, and send the session's CSRF token. Secrets never go on the
command line or to stdout.

  admin (PANEL_TOKEN):
    whoami
    profile-set --backup FILE --mode full|split [--cidr CIDR]...
    profile-restore --backup FILE
    device-show --id ID
    device-revoke --id ID
    peer-config --ref PUBLIC_KEY --out FILE
    user-show --username NAME [--provider ldap|oidc|local]
    directory-sync
  portal (--user NAME, PASSWORD):
    device-create --protocol wg|awg|vless --name NAME
    device-config --id ID --variant wg|awg|json|link --out FILE

    PANEL_TOKEN=... python3 panel_api.py --panel https://203.0.113.10 --insecure whoami
    PASSWORD=... python3 panel_api.py --panel https://203.0.113.10 --insecure --user dave \\
        device-create --protocol wg --name laptop

profile-set points the DEFAULT access profile at a tunnel mode and subnets
(every protocol, room for 20 devices) and applies the network policy; the
first call saves the profile's own settings to the backup file (mode 600),
profile-restore puts them back and removes the file. Downloaded configs are
written with mode 600. Output: key=value lines. Exit code 1 on an API error,
2 on bad usage.
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
from html.parser import HTMLParser
from pathlib import Path

PROFILE_FIELDS = ("name", "description", "tunnel_mode", "allowed_cidrs", "dns_servers", "search_domains",
                  "protocols", "max_devices", "device_ttl_days")
PORTAL_COMMANDS = ("device-create", "device-config")


class ApiError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


class CsrfMeta(HTMLParser):
    """The session's CSRF token from <meta name="csrf-token" content="...">."""

    def __init__(self):
        super().__init__()
        self.token = ""

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "meta" and a.get("name") == "csrf-token" and not self.token:
            self.token = a.get("content") or ""


def _detail(body: bytes) -> str:
    try:
        detail = json.loads(body).get("detail")
    except (ValueError, AttributeError):
        detail = None
    text = detail if isinstance(detail, str) else body.decode("utf-8", "replace")
    return " ".join(text.split())[:200]


class Panel:
    def __init__(self, base: str, insecure: bool):
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.base = base.rstrip("/")
        self.headers: dict[str, str] = {}
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                                                  NoRedirect(), urllib.request.HTTPSHandler(context=ctx))

    def call(self, method: str, path: str, *, json_body=None, form=None, ok=(200,)):
        headers = dict(self.headers)
        data = None
        if json_body is not None:
            data = json.dumps(json_body).encode()
            headers["Content-Type"] = "application/json"
        elif form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if method not in ("GET", "HEAD"):
            headers["Origin"] = self.base  # the panel refuses cross-site writes
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            resp = self.opener.open(request, timeout=120)
        except urllib.error.HTTPError as exc:  # 3xx arrive here too: redirects are not followed
            resp = exc
        except urllib.error.URLError as exc:
            raise ApiError(f"{method} {path}: {exc.reason}") from exc
        status = resp.status if hasattr(resp, "status") else resp.code
        body = resp.read()
        if status not in ok:
            raise ApiError(f"{method} {path}: HTTP {status} {_detail(body)}")
        return status, resp.headers, body

    def json(self, method: str, path: str, **kwargs):
        return json.loads(self.call(method, path, **kwargs)[2] or b"null")

    def use_token(self, token: str) -> None:
        self.headers["Authorization"] = f"Bearer {token}"

    def sign_in(self, user: str, password: str) -> None:
        _, headers, _ = self.call("POST", "/login", form={"username": user, "password": password}, ok=(302, 303))
        location = headers.get("Location", "")
        if urllib.parse.urlparse(location).path.startswith("/login"):
            raise ApiError(f"sign-in as {user} refused ({location})")
        meta = CsrfMeta()
        meta.feed(self.call("GET", "/me")[2].decode("utf-8", "replace"))
        if not meta.token:
            raise ApiError("no CSRF token on /me")
        self.headers["X-CSRF-Token"] = meta.token


def out(**pairs) -> None:
    for key, value in pairs.items():
        print(f"{key}={value}")


def write_private(path: str, data: bytes) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def _quote(value: str) -> str:
    return urllib.parse.quote(value, safe="")


# ------------------------------------------------------------------ admin
def cmd_whoami(panel: Panel, opts) -> None:
    me = panel.json("GET", "/api/auth/me")
    out(role=me.get("role", ""), username=me.get("username", ""), via=me.get("via", ""))


def _default_profile(panel: Panel) -> dict:
    profiles = panel.json("GET", "/api/profiles")
    for profile in profiles:
        if profile.get("is_default"):
            return profile
    if profiles:
        return profiles[0]
    raise ApiError("the panel has no access profile")


def cmd_profile_set(panel: Panel, opts) -> None:
    profile = _default_profile(panel)
    if not Path(opts.backup).exists():  # only the first call sees the operator's own settings
        saved = {"id": profile["id"], "profile": {k: profile[k] for k in PROFILE_FIELDS}}
        write_private(opts.backup, json.dumps(saved).encode())
    body = {k: profile[k] for k in PROFILE_FIELDS}
    body.update(tunnel_mode=opts.mode, allowed_cidrs=opts.cidr or [], protocols=["wg", "awg", "vless"],
                max_devices=max(int(profile["max_devices"]), 20), device_ttl_days=0)
    panel.json("PUT", f"/api/profiles/{_quote(profile['id'])}", json_body=body)
    panel.json("POST", "/api/network/policy/apply")
    out(id=profile["id"], mode=opts.mode, cidrs=",".join(opts.cidr or []))


def cmd_profile_restore(panel: Panel, opts) -> None:
    backup = Path(opts.backup)
    if not backup.exists():
        out(restored="no")
        return
    saved = json.loads(backup.read_text(encoding="utf-8"))
    panel.json("PUT", f"/api/profiles/{_quote(saved['id'])}", json_body=saved["profile"])
    panel.json("POST", "/api/network/policy/apply")
    backup.unlink()
    out(restored="yes", id=saved["id"])


def _device(panel: Panel, device_id: str) -> dict:
    for device in panel.json("GET", "/api/devices?include_revoked=true"):
        if device.get("id") == device_id:
            return device
    raise ApiError(f"device {device_id} not found")


def cmd_device_show(panel: Panel, opts) -> None:
    device = _device(panel, opts.id)
    out(status=device.get("status", ""), protocol=device.get("protocol", ""), ref=device.get("ref", ""),
        owner=(device.get("owner") or {}).get("username", ""))


def cmd_device_revoke(panel: Panel, opts) -> None:
    out(status=panel.json("DELETE", f"/api/devices/{_quote(opts.id)}").get("status", ""))


def cmd_peer_config(panel: Panel, opts) -> None:
    data = panel.call("GET", f"/api/peers/{_quote(opts.ref)}/config?protocol=wg")[2]
    write_private(opts.out, data)
    out(file=opts.out, bytes=len(data))


def cmd_user_show(panel: Panel, opts) -> None:
    for user in panel.json("GET", "/api/auth/users"):
        if user.get("username") == opts.username and opts.provider in ("", user.get("provider")):
            out(status=user.get("status", ""), role=user.get("role", ""), provider=user.get("provider", ""))
            return
    raise ApiError(f"no user {opts.username}")


def cmd_directory_sync(panel: Panel, opts) -> None:
    summary = panel.json("POST", "/api/auth/sync")
    errors = [" ".join(str(e).split()) for e in summary.get("errors", [])]
    out(checked=summary.get("checked", 0),
        disabled=",".join(item.get("username", "") for item in summary.get("disabled", [])),
        errors=len(errors), error=errors[0] if errors else "")


# ----------------------------------------------------------------- portal
def cmd_device_create(panel: Panel, opts) -> None:
    device = panel.json("POST", "/api/me/devices", json_body={"name": opts.name, "protocol": opts.protocol},
                        ok=(201,))
    out(id=device["id"], status=device.get("status", ""), protocol=device.get("protocol", ""))


def cmd_device_config(panel: Panel, opts) -> None:
    query = urllib.parse.urlencode({"variant": opts.variant})
    data = panel.call("GET", f"/api/me/devices/{_quote(opts.id)}/config?{query}")[2]
    write_private(opts.out, data)
    out(file=opts.out, bytes=len(data))


COMMANDS = {
    "whoami": cmd_whoami,
    "profile-set": cmd_profile_set,
    "profile-restore": cmd_profile_restore,
    "device-show": cmd_device_show,
    "device-revoke": cmd_device_revoke,
    "peer-config": cmd_peer_config,
    "user-show": cmd_user_show,
    "directory-sync": cmd_directory_sync,
    "device-create": cmd_device_create,
    "device-config": cmd_device_config,
}


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--panel", required=True, help="panel URL, e.g. https://203.0.113.10")
    ap.add_argument("--insecure", action="store_true", help="accept a self-signed panel certificate")
    ap.add_argument("--user", default="", help="sign in on the login form as this user (portal commands)")
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("whoami")
    p = sub.add_parser("profile-set")
    p.add_argument("--backup", required=True)
    p.add_argument("--mode", choices=["full", "split"], required=True)
    p.add_argument("--cidr", action="append")
    sub.add_parser("profile-restore").add_argument("--backup", required=True)
    sub.add_parser("device-show").add_argument("--id", required=True)
    sub.add_parser("device-revoke").add_argument("--id", required=True)
    p = sub.add_parser("peer-config")
    p.add_argument("--ref", required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("user-show")
    p.add_argument("--username", required=True)
    p.add_argument("--provider", default="")
    sub.add_parser("directory-sync")
    p = sub.add_parser("device-create")
    p.add_argument("--protocol", choices=["wg", "awg", "vless"], required=True)
    p.add_argument("--name", required=True)
    p = sub.add_parser("device-config")
    p.add_argument("--id", required=True)
    p.add_argument("--variant", choices=["wg", "awg", "json", "link"], required=True)
    p.add_argument("--out", required=True)
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = parser()
    opts = ap.parse_args(argv)
    panel = Panel(opts.panel, opts.insecure)
    try:
        if opts.command in PORTAL_COMMANDS:
            if not opts.user:
                ap.error(f"{opts.command} needs --user")
            password = os.environ.get("PASSWORD")
            if password is None:
                print("set PASSWORD in the environment", file=sys.stderr)
                return 2
            panel.sign_in(opts.user, password)
        else:
            token = os.environ.get("PANEL_TOKEN", "")
            if not token:
                print("set PANEL_TOKEN in the environment", file=sys.stderr)
                return 2
            panel.use_token(token)
        COMMANDS[opts.command](panel, opts)
    except ApiError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
