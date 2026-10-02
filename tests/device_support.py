"""Shared helpers for the device / portal / network-policy tests.

The pytest fixtures built on these (wg, xray, client) live in conftest.py.
"""
import ipaddress
import re
import types

import config
from auth import sessions, store

TOKEN = "break-glass-token-123"
HTML = {"Accept": "text/html"}


class FakeWG:
    """In-memory stand-in for vpn_manager's peer operations."""

    def __init__(self):
        self.peers = {}
        self.n = 0

    def create_peer(self, name):
        self.n += 1
        key = f"PUBKEY{self.n:02d}".ljust(44, "=")
        self.peers[key] = {"name": name, "deactivated": False}
        return {"public_key": key}

    def activate_peer(self, key):
        self.peers[key]["deactivated"] = False

    def deactivate_peer(self, key):
        self.peers[key]["deactivated"] = True

    def delete_peer(self, key):
        self.peers.pop(key)

    def get_all_peers(self):
        from models import PeerInfo

        pool = ipaddress.ip_network(config.WG_NETWORK, strict=False)
        return [
            PeerInfo(public_key=k, name=v["name"], vpn_ip=str(pool[i + 2]), deactivated=v["deactivated"],
                     status="online" if not v["deactivated"] else "inactive")
            for i, (k, v) in enumerate(self.peers.items())
        ]


def make_user(username, role="user", profile_id=""):
    return store.upsert_user(provider="ldap", external_id=f"id-{username}", username=username, email="",
                             display_name=username.title(), role=role, groups=[], access_profile_id=profile_id)


def login_as(client, user):
    req = types.SimpleNamespace(client=types.SimpleNamespace(host="192.0.2.5"), headers={})
    raw, csrf = sessions.create(user, req)
    client.cookies.set(sessions.COOKIE_NAME, raw)
    return {"X-CSRF-Token": csrf}


def admin_session(client):
    client.post("/login", data={"username": "admin", "password": TOKEN}, follow_redirects=False)
    page = client.get("/", headers=HTML).text
    return {"X-CSRF-Token": re.search(r'name="csrf-token" content="([^"]+)"', page).group(1)}


def break_glass_config(monkeypatch):
    monkeypatch.setattr(config, "PANEL_SECRET_TOKEN", TOKEN)
    monkeypatch.setattr(config, "PANEL_USERNAME", "admin")
    monkeypatch.setattr(config, "OIDC_ENABLED", False)
    monkeypatch.setattr(config, "LDAP_ENABLED", False)
    monkeypatch.setattr(config, "AUTH_LOCAL_ALLOWED_CIDRS", ())
