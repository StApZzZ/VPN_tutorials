"""One-use enrolment, scrypt, replay resistance and role boundaries."""
from concurrent.futures import ThreadPoolExecutor
import base64
import types

import pytest
from sqlalchemy import text

import config
from auth import local_accounts as local, store, tokens
from device_support import admin_session, login_as, make_user

PASSWORD = "example-long-passphrase-2026"


@pytest.fixture(autouse=True)
def local_config(monkeypatch):
    monkeypatch.setattr(config, "LOCAL_ACCOUNTS_ENABLED", True)
    monkeypatch.setattr(config, "AUTH_LOCAL_TOTP", "admins")
    monkeypatch.setattr(config, "PANEL_USERNAME", "admin")
    monkeypatch.setattr(config, "PANEL_PUBLIC_URL", "http://testserver")
    monkeypatch.setattr(local, "time", types.SimpleNamespace(time=lambda: 1800000000))


def enrol(role="user", name="employee"):
    user = local.create(name, role)
    token = local.invite(user["id"])
    factor = local.begin_totp(user["id"])
    code = local.totp(factor["secret"], 60000000) if role == "admin" else ""
    accepted, codes = local.accept_invite(token, PASSWORD, code)
    return accepted, factor, codes, token


def test_password_salt_normalization_and_bounds():
    a = local.hash_password(PASSWORD)
    assert a.startswith("scrypt$") and PASSWORD not in a
    assert a != local.hash_password(PASSWORD)
    assert local.check_password(PASSWORD, a)
    assert not local.check_password("wrong", a)
    assert local.check_password("Cafe\u0301-password-12", local.hash_password("Caf\u00e9-password-12"))
    for password in ("short", "x" * 129):
        with pytest.raises(store.StoreError):
            local.hash_password(password)


def test_one_use_invite_not_stored_or_listed():
    user, _, _, token = enrol()
    with local.engine().connect() as conn:
        assert token != conn.execute(text("SELECT token_hash FROM local_invites")).scalar()
    with pytest.raises(store.StoreError, match="invite"):
        local.accept_invite(token, PASSWORD, "")
    assert local.authenticate("EMPLOYEE", PASSWORD, "")["id"] == user["id"]
    assert not {"password_hash", "totp_secret", "recovery_json"} & local.users()[0].keys()


def test_admin_needs_mfa_and_failed_enrolment_does_not_consume_invite():
    user = local.create("manager", "admin")
    token = local.invite(user["id"])
    with pytest.raises(store.StoreError):
        local.accept_invite(token, PASSWORD, "")
    factor = local.begin_totp(user["id"])
    assert local.begin_totp(user["id"]) == factor
    code = local.totp(factor["secret"], 60000000)
    _, recovery = local.accept_invite(token, PASSWORD, code)
    assert len(recovery) == 10
    assert not local.authenticate("manager", PASSWORD, code)  # enrolment consumed this step
    assert not local.authenticate("manager", PASSWORD, "")
    assert local.authenticate("manager", PASSWORD, recovery[0])
    assert not local.authenticate("manager", PASSWORD, recovery[0])
    cred = local.credentials(user["id"])
    assert factor["secret"] not in cred["totp_secret"]
    assert recovery[1] not in cred["recovery_json"]
    with pytest.raises(store.StoreError, match="already_enabled"):
        local.begin_totp(user["id"])


def test_totp_and_recovery_are_atomic_under_concurrency(monkeypatch):
    user, factor, recovery, _ = enrol("admin")
    monkeypatch.setattr(local, "time", types.SimpleNamespace(time=lambda: 1800000030))
    code = local.totp(factor["secret"], 60000001)
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(lambda _: local.verify_factor(user["id"], code), range(8))) == 1
        assert sum(pool.map(lambda _: local.verify_factor(user["id"], recovery[0]), range(8))) == 1


def test_parallel_invitation_claim_has_one_winner():
    user = local.create("employee", "user")
    token = local.invite(user["id"])
    def claim(_):
        try:
            local.accept_invite(token, PASSWORD, "")
            return True
        except store.StoreError:
            return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(claim, range(2))) == 1


def test_expiry_disabled_account_and_reset(monkeypatch):
    user, _, _, old = enrol()
    new = local.invite(user["id"])
    assert not local.authenticate("employee", PASSWORD, "")
    with pytest.raises(store.StoreError):
        local.invitation(old)
    store.set_user_status(user["id"], "disabled", "admin")
    with pytest.raises(store.StoreError, match="disabled"):
        local.accept_invite(new, PASSWORD, "")
    store.set_user_status(user["id"], "active", "admin")
    monkeypatch.setattr(local, "time", types.SimpleNamespace(time=lambda: 1800000000 + 72*3600))
    with pytest.raises(store.StoreError, match="expired"):
        local.invitation(new)


def test_key_creation_is_atomic_and_private():
    with ThreadPoolExecutor(max_workers=8) as pool:
        encrypted = list(pool.map(lambda _: local.crypt().encrypt(b"test"), range(8)))
    assert all(local.crypt().decrypt(value) == b"test" for value in encrypted)
    from pathlib import Path
    assert Path(config.LOCAL_DATA_KEY_PATH).stat().st_mode & 0o777 == 0o600


def test_rfc6238_known_vector():
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert local.totp(secret, 1, digits=8) == "94287082"


def test_management_csrf_role_and_secret_boundaries(client):
    assert client.get("/api/auth/local-users").status_code == 401
    login_as(client, make_user("helpdesk", role="operator"))
    assert client.get("/api/auth/local-users").status_code == 403
    client.cookies.clear()
    headers = admin_session(client)
    assert client.post("/api/auth/local-users", json={"username":"employee"}).status_code == 403
    result = client.post("/api/auth/local-users", json={"username":"employee"}, headers=headers)
    assert result.status_code == 201
    user = result.json()
    issued = client.post("/api/auth/local-users/"+user["id"]+"/invite", headers=headers).json()
    assert issued["expires_in"] == 259200
    token = issued["invite_url"].rsplit("/",1)[1]
    page = client.get("/invite/"+token)
    assert page.status_code == 200 and page.headers["cache-control"] == "no-store"
    assert client.post("/invite/"+token,data={"password":PASSWORD},headers={"Origin":"https://evil.example"}).status_code == 403
    assert client.post("/invite/"+token,data={"password":PASSWORD}).status_code == 200
    listing = client.get("/api/auth/local-users").text
    assert PASSWORD not in listing and token not in listing and "password_hash" not in listing
    assert {"user.create","user.invite","password.set"} <= {row["action"] for row in store.list_audit()}


def test_paginated_audit_equal_timestamps_and_scopes(client):
    for n in range(7):
        store.audit("test.event",actor="test",target=str(n))
    with store._engine().begin() as conn:
        conn.execute(text("UPDATE audit_log SET ts='2026-10-01T00:00:00Z'"))
    raw,_ = tokens.create("siem", "auditor", "test")
    headers={"Authorization":"Bearer "+raw}
    cursor=""; seen=[]
    while True:
        result=client.get("/api/auth/audit/export",params={"limit":2,"cursor":cursor},headers=headers)
        assert result.status_code == 200
        import json
        seen += [json.loads(line)["target"] for line in result.text.splitlines()]
        cursor=result.headers.get("X-Next-Cursor", "")
        if not cursor: break
    assert set(seen)==set(map(str,range(7))) and len(seen)==7
    assert client.get("/api/auth/audit/export?cursor=bad",headers=headers).status_code == 422
    assert client.get("/api/auth/audit/export?from_ts=bad",headers=headers).status_code == 422
    metrics,_=tokens.create("metrics","metrics","test")
    assert client.get("/api/auth/audit/export",headers={"Authorization":"Bearer "+metrics}).status_code == 403
