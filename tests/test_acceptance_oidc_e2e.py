"""The acceptance kit (tools/acceptance), proven before a lab run.

Panel helpers (*.py) run against a live panel: uvicorn on a free localhost port,
each helper as a subprocess, exactly as run.sh starts it. OIDC: a Keycloak-like
login page serves the browser leg; the panel's back channel (discovery, token,
JWKS) goes to the FakeIdP of test_auth_oidc.py. LDAP: ldap_auth.authenticate /
lookup read a small in-memory directory. WireGuard peers are the in-memory
FakeWG. Shell helpers (*.sh) are sourced, which defines their functions without
running them, and their parsing is checked on sample input.
"""
import hashlib
import json
import os
import socket
import stat
import subprocess
import sys
import threading
import time
import types
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
import pytest
import uvicorn

import config
import main
from auth import ldap_auth, oidc, store
from auth.identity import AuthFailed, Identity
from device_support import TOKEN, break_glass_config
from models import Protocol
from test_auth_oidc import CLIENT_ID, ISSUER, FakeIdP

KIT = Path(__file__).resolve().parents[1] / "tools" / "acceptance"
USERS = {"alice": ("pw-alice", ["vpn-admins"]), "bob": ("pw-bob", ["vpn-users"]), "carol": ("pw-carol", [])}
VPN_USERS = "CN=vpn-users,CN=Users,DC=corp,DC=example"
PROFILE_FIELDS = ("name", "description", "tunnel_mode", "allowed_cidrs", "dns_servers", "search_domains",
                  "protocols", "max_devices", "device_ttl_days")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def serve_panel(port: int):
    server = uvicorn.Server(uvicorn.Config(main.app, host="127.0.0.1", port=port, log_level="warning",
                                           lifespan="off"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(5)


def kit(script: str, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    base = {k: v for k, v in os.environ.items() if k not in ("PASSWORD", "PANEL_TOKEN")}
    return subprocess.run([sys.executable, str(KIT / script), *args], capture_output=True, text=True,
                          env={**base, **(env or {})}, timeout=60)


def pairs(result: subprocess.CompletedProcess) -> dict:
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


# ------------------------------------------------------------------- OIDC
class LoginPage(BaseHTTPRequestHandler):
    """Keycloak's browser endpoints, reduced to what a login needs."""

    idp: FakeIdP
    pending: dict = {}

    def log_message(self, *args):  # keep pytest output clean
        pass

    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        LoginPage.pending = {k: v[0] for k, v in query.items()}
        self.idp.nonce = LoginPage.pending["nonce"]
        self.idp.challenge = LoginPage.pending["code_challenge"]
        page = ('<html><body><form id="kc-form-login" method="post" '
                'action="/realms/corp/login-actions/authenticate?session_code=abc&amp;tab_id=t1">'
                '<input type="hidden" name="credentialId" value="">'
                '<input name="username"><input name="password" type="password"></form></body></html>')
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(page.encode())

    def do_POST(self):
        assert "session_code=abc&tab_id=t1" in self.path  # &amp; was unescaped
        form = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        user, password = form["username"][0], form["password"][0]
        if USERS.get(user, ("",))[0] != password:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Invalid username or password")
            return
        self.idp.claims = {"sub": f"sub-{user}", "preferred_username": user, "email": f"{user}@corp.example",
                           "groups": USERS[user][1]}
        target = LoginPage.pending["redirect_uri"] + "?" + urlencode(
            {"code": "the-code", "state": LoginPage.pending["state"]})
        self.send_response(302)
        self.send_header("Location", target)
        self.end_headers()


@pytest.fixture
def lab(monkeypatch):
    idp = FakeIdP()
    kc_port, panel_port = free_port(), free_port()
    kc_base = f"http://127.0.0.1:{kc_port}"
    panel_url = f"http://127.0.0.1:{panel_port}"

    def backchannel(request: httpx.Request) -> httpx.Response:
        response = idp.handler(request)
        if str(request.url).endswith("/.well-known/openid-configuration"):
            meta = response.json()
            meta["authorization_endpoint"] = f"{kc_base}/realms/corp/protocol/openid-connect/auth"
            return httpx.Response(200, json=meta)
        return response

    monkeypatch.setattr(oidc, "_transport", httpx.MockTransport(backchannel))
    oidc.clear_cache()
    for name, value in {
        "OIDC_ENABLED": True, "OIDC_ALLOW_INSECURE_HTTP": True, "OIDC_DISCOVERY_URL": f"{ISSUER}/.well-known/openid-configuration",
        "OIDC_CLIENT_ID": CLIENT_ID, "OIDC_CLIENT_SECRET": "s3cret", "PANEL_PUBLIC_URL": panel_url,
        "OIDC_REDIRECT_URL": f"{panel_url}/auth/oidc/callback", "LDAP_ENABLED": False, "AUTH_DEFAULT_ROLE": "",
        "PANEL_SECRET_TOKEN": "lab-token",
    }.items():
        monkeypatch.setattr(config, name, value)
    store.create_policy("any", "vpn-admins", "admin", 10)
    store.create_policy("any", "vpn-users", "user", 20)

    LoginPage.idp = idp
    kc = ThreadingHTTPServer(("127.0.0.1", kc_port), LoginPage)
    threading.Thread(target=kc.serve_forever, daemon=True).start()
    with mock.patch.object(main.vm, "get_all_peers", return_value=[]), serve_panel(panel_port) as url:
        yield url
    kc.shutdown()


def run_script(panel_url, user, expect, password=None):
    env = {"PASSWORD": password if password is not None else USERS[user][0]}
    return kit("oidc_e2e.py", "--panel", panel_url, "--user", user, "--expect", expect, env=env)


def test_admin_user_and_refused_user(lab):
    admin = run_script(lab, "alice", "admin")
    assert admin.returncode == 0, admin.stdout + admin.stderr
    assert "PASS: alice signed in via OIDC as admin" in admin.stdout
    user = run_script(lab, "bob", "user")
    assert user.returncode == 0, user.stdout + user.stderr
    refused = run_script(lab, "carol", "denied")
    assert refused.returncode == 0, refused.stdout + refused.stderr


def test_wrong_expectation_and_bad_password_fail(lab):
    assert run_script(lab, "bob", "admin").returncode == 1
    bad = run_script(lab, "alice", "admin", password="nope")
    assert bad.returncode == 1 and "did not redirect back" in bad.stdout


def test_role_comes_from_the_api_not_the_page(lab):
    # admin and operator land on the same page: only /api/auth/me tells them apart
    wrong = run_script(lab, "alice", "operator")
    assert wrong.returncode == 1
    assert "/api/auth/me HTTP 200, role admin; expected operator" in wrong.stdout


# ------------------------------------------------- form sign-in and the API
class Directory:
    """LDAP stand-in behind ldap_auth.authenticate / ldap_auth.lookup."""

    def __init__(self):
        self.users = {"dave": ("pw-dave", [VPN_USERS]), "svc-corpvpn": ("pw-svc", [])}
        self.disabled: set[str] = set()

    def identity(self, username: str) -> Identity:
        return Identity(provider="ldap", external_id=f"id-{username}", username=username,
                        groups=list(self.users[username][1]), disabled=username in self.disabled,
                        directory_dn=f"CN={username},CN=Users,DC=corp,DC=example")

    def authenticate(self, username: str, password: str) -> Identity:
        entry = self.users.get(username)
        if not password or entry is None or entry[0] != password:
            raise AuthFailed("invalid credentials")
        return self.identity(username)

    def lookup(self, directory_dn: str, username: str):
        return self.identity(username) if username in self.users else None


@pytest.fixture
def panel(monkeypatch, wg):
    break_glass_config(monkeypatch)
    for name, value in {"LDAP_ENABLED": True, "LDAP_URL": "ldaps://dc.corp.example",
                        "LDAP_USER_BASE_DN": "DC=corp,DC=example", "AUTH_DEFAULT_ROLE": "",
                        "NETWORK_POLICY_MODE": "off"}.items():
        monkeypatch.setattr(config, name, value)
    directory = Directory()
    monkeypatch.setattr(ldap_auth, "authenticate", directory.authenticate)
    monkeypatch.setattr(ldap_auth, "lookup", directory.lookup)
    artifact = types.SimpleNamespace(protocol=Protocol.WG, peer=types.SimpleNamespace(name="laptop"),
                                     client_conf="[Interface]\nPrivateKey = x\nAddress = 10.66.0.2/32\n\n"
                                                 "[Peer]\nPublicKey = y\nAllowedIPs = 0.0.0.0/0\n")
    monkeypatch.setattr(main.pa, "resolve_peer_artifact", lambda ref, protocol=None: artifact)
    store.create_policy("any", "vpn-users", "user", 20)
    with serve_panel(free_port()) as url:
        yield types.SimpleNamespace(url=url, directory=directory)


def login(url, user, expect, password):
    env = {"PASSWORD": password} if password is not None else {}
    return kit("login_e2e.py", "--panel", url, "--user", user, "--expect", expect, env=env)


def api(url, *args, token=None, user=None, password=None):
    env = {}
    if token is not None:
        env["PANEL_TOKEN"] = token
    if password is not None:
        env["PASSWORD"] = password
    return kit("panel_api.py", "--panel", url, *(["--user", user] if user else []), *args, env=env)


def test_login_break_glass_and_directory_users(panel):
    admin = login(panel.url, "admin", "admin", TOKEN)
    assert admin.returncode == 0, admin.stdout + admin.stderr
    dave = login(panel.url, "dave", "user", "pw-dave")
    assert dave.returncode == 0 and "PASS: dave signed in with the form; role user" in dave.stdout
    assert login(panel.url, "svc-corpvpn", "denied", "pw-svc").returncode == 0   # in no VPN group
    assert login(panel.url, "dave", "failed", "wrong").returncode == 0
    assert login(panel.url, "dave", "failed", "").returncode == 0                # empty password: refused
    assert login(panel.url, "nobody", "failed", "x").returncode == 0
    assert login(panel.url, "admin", "failed", "not-the-token").returncode == 0


def test_login_refused_accepts_either_reason_and_mismatches_fail(panel):
    assert login(panel.url, "svc-corpvpn", "refused", "pw-svc").returncode == 0
    assert login(panel.url, "dave", "refused", "wrong").returncode == 0
    refused = login(panel.url, "dave", "user", "wrong")
    assert refused.returncode == 1 and "refused (failed), expected role user" in refused.stdout
    wrong_role = login(panel.url, "dave", "admin", "pw-dave")
    assert wrong_role.returncode == 1 and "role user, expected admin" in wrong_role.stdout
    assert login(panel.url, "dave", "denied", "pw-dave").returncode == 1
    assert login(panel.url, "dave", "user", None).returncode == 2               # PASSWORD not set


def test_api_token_and_usage_errors(panel):
    me = api(panel.url, "whoami", token=TOKEN)
    assert me.returncode == 0 and pairs(me)["role"] == "admin"
    rejected = api(panel.url, "whoami", token="wrong")
    assert rejected.returncode == 1 and "HTTP 401" in rejected.stderr
    assert api(panel.url, "whoami").returncode == 2                             # PANEL_TOKEN not set
    assert api(panel.url, "device-create", "--protocol", "wg", "--name", "x", password=TOKEN).returncode == 2


def test_api_profile_set_keeps_the_first_backup_and_restores_it(panel, tmp_path):
    before = store.default_profile()
    backup = tmp_path / "profile.json"
    split = api(panel.url, "profile-set", "--backup", str(backup), "--mode", "split", "--cidr", "172.30.0.0/24",
                token=TOKEN)
    assert split.returncode == 0, split.stderr
    now = store.default_profile()
    assert (now["id"], now["tunnel_mode"], now["allowed_cidrs"], now["max_devices"]) == \
        (before["id"], "split", ["172.30.0.0/24"], 20)
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    # a second change keeps the backup: it must hold the operator's own settings
    assert api(panel.url, "profile-set", "--backup", str(backup), "--mode", "full", token=TOKEN).returncode == 0
    assert store.default_profile()["tunnel_mode"] == "full"
    restored = api(panel.url, "profile-restore", "--backup", str(backup), token=TOKEN)
    assert pairs(restored)["restored"] == "yes" and not backup.exists()
    after = store.default_profile()
    assert {k: after[k] for k in PROFILE_FIELDS} == {k: before[k] for k in PROFILE_FIELDS}
    assert pairs(api(panel.url, "profile-restore", "--backup", str(backup), token=TOKEN))["restored"] == "no"


def test_api_portal_device_lifecycle(panel, tmp_path):
    created = api(panel.url, "device-create", "--protocol", "wg", "--name", "laptop", user="admin", password=TOKEN)
    assert created.returncode == 0, created.stderr
    device_id = pairs(created)["id"]
    conf = tmp_path / "laptop.conf"
    got = api(panel.url, "device-config", "--id", device_id, "--variant", "wg", "--out", str(conf),
              user="admin", password=TOKEN)
    assert got.returncode == 0, got.stderr
    assert "AllowedIPs = 0.0.0.0/0" in conf.read_text() and stat.S_IMODE(conf.stat().st_mode) == 0o600
    shown = pairs(api(panel.url, "device-show", "--id", device_id, token=TOKEN))
    assert shown["status"] == "active" and shown["ref"].startswith("PUBKEY") and shown["owner"] == "admin"
    operator_copy = tmp_path / "operator.conf"
    assert api(panel.url, "peer-config", "--ref", shown["ref"], "--out", str(operator_copy),
               token=TOKEN).returncode == 0
    assert "[Peer]" in operator_copy.read_text()
    assert pairs(api(panel.url, "device-revoke", "--id", device_id, token=TOKEN))["status"] == "revoked"
    assert pairs(api(panel.url, "device-show", "--id", device_id, token=TOKEN))["status"] == "revoked"
    refused = api(panel.url, "device-create", "--protocol", "wg", "--name", "x", user="admin", password="wrong")
    assert refused.returncode == 1 and "sign-in as admin refused" in refused.stderr


def test_api_users_and_directory_sync(panel):
    assert login(panel.url, "dave", "user", "pw-dave").returncode == 0
    dave = api(panel.url, "user-show", "--username", "dave", token=TOKEN)
    assert pairs(dave) == {"status": "active", "role": "user", "provider": "ldap"}
    panel.directory.disabled.add("dave")
    sync = api(panel.url, "directory-sync", token=TOKEN)
    assert pairs(sync) == {"checked": "1", "disabled": "dave", "errors": "0", "error": ""}
    assert pairs(api(panel.url, "user-show", "--username", "dave", token=TOKEN))["status"] == "disabled"
    assert login(panel.url, "dave", "refused", "pw-dave").returncode == 0
    missing = api(panel.url, "user-show", "--username", "erin", token=TOKEN)
    assert missing.returncode == 1 and "no user erin" in missing.stderr


# ----------------------------------------------------------- shell helpers
AWG_CONF = """[Interface]
PrivateKey = fake-key
Address = 10.66.4.2/32, fd00::2/128
DNS = 10.0.0.53, corp.example
MTU = 1280
Jc = 4
Jmin = 40
Jmax = 70
S1 = 0
H1 = 1234567
I1 =
# a comment

[Peer]
PublicKey = cHVibGljLWtleQ==
PresharedKey = cHNr
AllowedIPs = 172.30.0.0/24, 10.0.0.53/32
Endpoint = 203.0.113.10:51821
PersistentKeepalive = 25
"""


def sh(script: str, snippet: str, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    """Run a snippet with one of the kit's shell scripts sourced; $1.. are args."""
    return subprocess.run(["bash", "-c", f'source "$0"; {snippet}', str(KIT / script), *args],
                          capture_output=True, text=True, timeout=30, env={**os.environ, **(env or {})})


def test_vpn_client_keeps_only_what_setconf_accepts(tmp_path):
    conf = tmp_path / "awg.conf"
    conf.write_text(AWG_CONF)
    stripped = sh("vpn-client.sh", 'strip_conf "$1"', str(conf))
    # wg-quick keys (Address, DNS, MTU), comments and empty values would make setconf fail
    assert stripped.stdout.splitlines() == [
        "[Interface]", "PrivateKey = fake-key", "Jc = 4", "Jmin = 40", "Jmax = 70", "S1 = 0",
        "H1 = 1234567", "[Peer]", "PublicKey = cHVibGljLWtleQ==", "PresharedKey = cHNr",
        "AllowedIPs = 172.30.0.0/24, 10.0.0.53/32", "Endpoint = 203.0.113.10:51821", "PersistentKeepalive = 25"]


def test_vpn_client_reads_config_values(tmp_path):
    conf = tmp_path / "awg.conf"
    conf.write_text(AWG_CONF)
    values = sh("vpn-client.sh", 'for k in Address AllowedIPs PublicKey MTU; do conf_value "$1" $k; done; '
                                 'first_v4 "$(conf_value "$1" Address)"; first_v4 "fd00::2/128" || echo none', str(conf))
    assert values.stdout.splitlines() == ["10.66.4.2/32,fd00::2/128", "172.30.0.0/24,10.0.0.53/32",
                                          "cHVibGljLWtleQ==", "1280", "10.66.4.2/32", "none"]


def test_vpn_client_address_helpers():
    out = sh("vpn-client.sh", "next_address 172.30.0.0/24; next_address 10.66.0.0/22; next_address 192.0.2.7/32; "
                              "url_host https://1.1.1.1/cdn-cgi/trace; url_host http://172.30.0.2:8080/")
    assert out.stdout.splitlines() == ["172.30.0.1", "10.66.0.1", "192.0.2.7", "1.1.1.1", "172.30.0.2"]


def test_vpn_client_parses_the_egress_answer():
    out = sh("vpn-client.sh", 'for body in "$@"; do parse_egress "$body"; done',
             "fl=1\nh=1.1.1.1\nip=203.0.113.10\nts=1", "198.51.100.7\n", "<html>blocked</html>", "")
    assert out.stdout.splitlines() == ["203.0.113.10", "198.51.100.7", "none", "none"]


def test_vpn_client_without_a_command_prints_usage():
    usage = subprocess.run(["bash", str(KIT / "vpn-client.sh")], capture_output=True, text=True, timeout=30)
    assert usage.returncode == 2 and "usage: vpn-client.sh" in usage.stderr


def test_gateway_snapshot_items_are_short_hashes():
    out = sh("gateway.sh", 'item wg0.public-key "abc"; item awg0.peers ""')
    assert out.stdout.splitlines() == [f"wg0.public-key {hashlib.sha256(b'abc').hexdigest()[:16]}",
                                       "awg0.peers absent"]


def test_gateway_reads_the_reality_key_and_vless_clients(tmp_path):
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"inbounds": [
        {"protocol": "socks", "port": 1080},
        {"protocol": "vless", "settings": {"clients": [{"id": "b-id"}, {"id": "a-id"}]},
         "streamSettings": {"realitySettings": {"privateKey": "PRIV"}}},
    ]}))
    out = sh("gateway.sh", "xray_field private-key; xray_field clients", env={"XRAY_CONFIG": str(cfg)})
    assert out.stdout.splitlines() == ["PRIV", "a-id", "b-id"]
    missing = sh("gateway.sh", "xray_field private-key", env={"XRAY_CONFIG": str(tmp_path / "none.json")})
    assert missing.returncode == 0 and missing.stdout == ""


def test_gateway_hosts_entry_replaces_only_its_own_line(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n198.51.100.9 dc.corp.example # corpvpn-acceptance\n192.0.2.1 other\n")
    env = {"HOSTS_FILE": str(hosts)}
    run = sh("gateway.sh", "hosts_entry 198.51.100.20 dc.corp.example && hosts_entry 198.51.100.20 dc.corp.example",
             env=env)
    assert run.returncode == 0, run.stderr
    assert hosts.read_text() == ("127.0.0.1 localhost\n192.0.2.1 other\n"
                                 "198.51.100.20 dc.corp.example # corpvpn-acceptance\n")
    assert sh("gateway.sh", 'hosts_entry "198.51.100.20;true" dc.corp.example', env=env).returncode == 2
