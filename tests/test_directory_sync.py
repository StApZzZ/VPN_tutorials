"""directory_sync without a directory: OIDC attestation and the disable limit.

The LDAP side (errors, circuit breaker, "not found" twice) is in test_auth_ldap.py.
"""
from datetime import timedelta

import pytest
from sqlalchemy import text

import config
import directory_sync
from auth import store
from device_support import login_as


@pytest.fixture(autouse=True)
def oidc_only(monkeypatch):
    monkeypatch.setattr(config, "LDAP_ENABLED", False)
    monkeypatch.setattr(config, "AUTH_ATTESTATION_DAYS", 30)
    monkeypatch.setattr(config, "AUTH_ATTESTATION_WARN_DAYS", 7)


def oidc_user(name, signed_in_days_ago, warned_days_ago=None):
    user = store.upsert_user(provider="oidc", external_id=name, username=name, email=f"{name}@corp.example",
                             display_name="", role="user", groups=[])
    values = {"t": store.iso(store.now() - timedelta(days=signed_in_days_ago)), "id": user["id"],
              "w": store.iso(store.now() - timedelta(days=warned_days_ago)) if warned_days_ago is not None else ""}
    with store._engine().begin() as conn:
        conn.execute(text("UPDATE users SET last_login_at = :t, attestation_warned_at = :w WHERE id = :id"), values)
    return store.get_user(user["id"])


def test_attestation_warns_once_then_disables():
    oidc_user("fresh", 1)
    soon = oidc_user("soon", 25)
    oidc_user("stale", 31)
    summary = directory_sync.run()
    assert [d["username"] for d in summary["disabled"]] == ["stale"]
    assert summary["disabled"][0]["reason"] == "attestation_expired"
    assert summary["attestation_due"] == 1
    event = store.list_audit(action_prefix="directory.attestation_due")[0]
    assert event["target"] == soon["id"] and event["details"]["days_left"] == 4
    assert event["details"]["email"] == "soon@corp.example"
    # once per sign-in cycle, not on every timer run
    assert directory_sync.run()["attestation_due"] == 0
    stale = store.find_user("oidc", "stale")
    assert (stale["status"], stale["disabled_source"]) == ("disabled", "attestation")


def test_a_new_sign_in_cycle_warns_again():
    oidc_user("again", 24, warned_days_ago=40)  # warned in the previous cycle
    assert directory_sync.run()["attestation_due"] == 1


def test_portal_shows_the_days_left(client):
    user = oidc_user("ivan", 10)
    login_as(client, user)
    attestation = client.get("/api/auth/me").json()["attestation"]
    assert attestation["days_left"] == 19 and attestation["due_at"]
    listed = next(u for u in client.get("/api/auth/users", headers={"Authorization": "Bearer break-glass-token-123"})
                  .json() if u["username"] == "ivan")
    assert listed["attestation_due_at"] == attestation["due_at"]


def test_no_attestation_for_directory_users(client):
    user = store.upsert_user(provider="ldap", external_id="l", username="l", email="", display_name="",
                             role="user", groups=[])
    login_as(client, user)
    assert client.get("/api/auth/me").json()["attestation"] is None


@pytest.mark.parametrize("setting, active, limit", [
    ("10%", 20, 5),      # never below 5
    ("10%", 200, 20),
    ("10%", 201, 21),    # rounded up
    ("25", 1000, 25),
    ("0", 50, 0),        # no limit
    ("0%", 50, 0),
])
def test_disable_limit(monkeypatch, setting, active, limit):
    monkeypatch.setattr(config, "DIRECTORY_SYNC_MAX_DISABLE", setting)
    assert directory_sync.disable_limit(active) == limit
