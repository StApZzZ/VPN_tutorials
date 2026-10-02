"""Devices, access profiles, employee portal, API tokens and audit."""
import json
import socket
import threading
import time
from datetime import timedelta
from unittest import mock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

import config
import config_links as cl
import devices
import main
import xray_clients as xc
from auth import identity, store
from device_support import HTML, TOKEN, admin_session, login_as, make_user


@pytest.fixture(autouse=True)
def _no_kernel_policy(monkeypatch):
    monkeypatch.setattr(config, "NETWORK_POLICY_MODE", "off")


# ------------------------------------------------------------------ portal
def test_employee_creates_downloads_and_revokes_own_device(client, wg):
    user = make_user("ivan")
    h = login_as(client, user)
    created = client.post("/api/me/devices", json={"name": "Ноутбук", "protocol": "awg"}, headers=h)
    assert created.status_code == 201, created.text
    device = created.json()
    assert "ref" not in device and len(wg.peers) == 1
    listing = client.get("/api/me/devices").json()
    assert listing["profile"]["name"] == store.default_profile()["name"]
    assert [d["name"] for d in listing["devices"]] == ["Ноутбук"]
    assert "ref" not in listing["devices"][0]

    conf = client.get(f"/api/me/devices/{device['id']}/config")
    assert conf.status_code == 200
    disposition = conf.headers["content-disposition"]
    assert 'filename="device-awg.conf"' in disposition
    assert "filename*=UTF-8''%D0%9D%D0%BE%D1%83%D1%82%D0%B1%D1%83%D0%BA-awg.conf" in disposition
    assert conf.headers["cache-control"] == "no-store"
    qr = client.get(f"/api/me/devices/{device['id']}/qr?variant=wg")
    assert qr.status_code == 200 and qr.headers["content-type"] == "image/png"

    assert client.delete(f"/api/me/devices/{device['id']}", headers=h).status_code == 200
    assert wg.peers == {}
    assert client.get(f"/api/me/devices/{device['id']}/config").status_code == 404
    actions = [a["action"] for a in store.list_audit()]
    assert {"device.create", "device.download", "device.revoke"} <= set(actions)


def test_portal_needs_csrf_and_hides_other_peoples_devices(client, wg):
    ivan, olga = make_user("ivan"), make_user("olga")
    theirs = devices.create(olga, "phone", "wg", actor="test")
    h = login_as(client, ivan)
    assert client.post("/api/me/devices", json={"name": "x", "protocol": "wg"}).status_code == 403
    assert client.get(f"/api/me/devices/{theirs['id']}/config").status_code == 404
    assert client.delete(f"/api/me/devices/{theirs['id']}", headers=h).status_code == 404
    assert client.get("/api/devices").status_code == 403  # operator API


def test_profile_limits_protocols_and_ttl(client, wg, xray):
    profile = store.create_profile({"name": "Подрядчики", "max_devices": 1, "device_ttl_days": 7,
                                    "protocols": ["wg"], "tunnel_mode": "split",
                                    "allowed_cidrs": ["10.20.0.0/16"]})
    user = make_user("contractor", profile_id=profile["id"])
    h = login_as(client, user)
    assert client.post("/api/me/devices", json={"name": "x", "protocol": "vless"}, headers=h).status_code == 400
    first = client.post("/api/me/devices", json={"name": "laptop", "protocol": "wg"}, headers=h)
    assert first.status_code == 201
    expires = store.parse_iso(first.json()["expires_at"])
    assert timedelta(days=6) < expires - store.now() <= timedelta(days=7)
    second = client.post("/api/me/devices", json={"name": "phone", "protocol": "wg"}, headers=h)
    assert second.status_code == 400 and "limit" in second.json()["detail"]


def test_expired_devices_are_suspended_and_stay_so(wg):
    user = make_user("ivan")
    device = devices.create(user, "laptop", "wg", actor="test")
    store.update_device(device["id"], expires_at=store.iso(store.now() - timedelta(minutes=1)))
    assert devices.enforce_expiry() == 1
    row = store.get_device(device["id"])
    assert row["status"] == "suspended" and row["suspend_reason"] == "expired"
    assert wg.peers[device["ref"]]["deactivated"] is True
    with pytest.raises(devices.DeviceError):
        devices.set_active(device["id"], True, actor="op")


# -------------------------------------------------------------- offboarding
def test_disabling_a_user_suspends_devices_and_enabling_restores_only_those(client, wg):
    user = make_user("ivan")
    auto = devices.create(user, "laptop", "wg", actor="test")
    manual = devices.create(user, "phone", "awg", actor="test")
    devices.set_active(manual["id"], False, actor="op")  # an operator paused this one
    h = admin_session(client)
    assert client.post(f"/api/auth/users/{user['id']}/disable", headers=h).status_code == 200
    assert store.get_device(auto["id"])["status"] == "suspended"
    assert wg.peers[auto["ref"]]["deactivated"] is True
    assert client.post(f"/api/auth/users/{user['id']}/enable", headers=h).status_code == 200
    assert store.get_device(auto["id"])["status"] == "active"
    assert store.get_device(manual["id"])["status"] == "suspended"  # stays paused


def test_directory_denial_suspends_and_readmission_resumes(wg):
    store.create_policy("any", "VPN-Users", "user", 10)
    ident = identity.Identity(provider="ldap", external_id="guid-1", username="ivan", groups=["VPN-Users"])
    user = identity.admit(ident)
    device = devices.create(user, "laptop", "wg", actor="test")
    with pytest.raises(identity.AccessDenied):
        identity.admit(identity.Identity(provider="ldap", external_id="guid-1", username="ivan", groups=[]))
    assert store.get_device(device["id"])["status"] == "suspended"
    identity.admit(ident)
    assert store.get_device(device["id"])["status"] == "active"


def test_policy_profile_is_applied_at_sign_in():
    profile = store.create_profile({"name": "Разработчики", "max_devices": 5})
    store.create_policy("any", "Dev", "user", 10, access_profile_id=profile["id"])
    user = identity.admit(identity.Identity(provider="oidc", external_id="s", username="dev", groups=["Dev"]))
    assert user["access_profile_id"] == profile["id"]
    assert devices.profile_for(user)["max_devices"] == 5


# ------------------------------------------------------------------ VLESS
def test_vless_device_uses_xray_and_rolls_back_on_apply_failure(wg, xray):
    user = make_user("ivan")
    device = devices.create(user, "phone", "vless", actor="test")
    assert xc.get_client(device["ref"]).enabled
    art = devices.artifact(device)
    assert art["share_link"].startswith(f"vless://{device['ref']}@vpn.example.com:443")
    devices.set_active(device["id"], False, actor="op")
    assert not xc.get_client(device["ref"]).enabled
    xray.side_effect = RuntimeError("xray -test failed")
    with pytest.raises(RuntimeError):
        devices.revoke(device["id"], actor="op")
    assert xc.get_client(device["ref"])  # rolled back: client still there
    assert store.get_device(device["id"])["status"] == "suspended"


def test_vless_ids_are_not_exposed_in_listings(wg, xray):
    user = make_user("ivan")
    device = devices.create(user, "phone", "vless", actor="test")
    listed = devices.describe([store.get_device(device["id"])])[0]
    assert listed["ref"] == ""


# -------------------------------------------------------- operators / adoption
def test_existing_peers_are_adopted_and_can_be_assigned(client, wg):
    wg.create_peer("old laptop")
    ivan = make_user("ivan")
    h = admin_session(client)
    listed = client.get("/api/devices").json()
    assert len(listed) == 1 and listed[0]["owner"]["unassigned"] is True
    assigned = client.post(f"/api/devices/{listed[0]['id']}/assign", json={"user_id": ivan["id"]}, headers=h)
    assert assigned.json()["user_id"] == ivan["id"]
    assert devices.adopt_unmanaged() == 0  # idempotent


def test_operator_issues_suspends_and_revokes(client, wg):
    ivan = make_user("ivan")
    op = make_user("helpdesk", role="operator")
    h = login_as(client, op)
    issued = client.post("/api/devices", json={"user_id": ivan["id"], "name": "desk", "protocol": "wg"}, headers=h)
    assert issued.status_code == 201
    did = issued.json()["id"]
    assert client.post(f"/api/devices/{did}/suspend", headers=h).json()["status"] == "suspended"
    assert client.post(f"/api/devices/{did}/resume", headers=h).json()["status"] == "active"
    assert client.delete(f"/api/devices/{did}", headers=h).json()["status"] == "revoked"
    assert client.post("/api/profiles", json={"name": "x"}, headers=h).status_code == 403  # admin only


def test_legacy_peer_delete_revokes_the_device(client, wg):
    user = make_user("ivan")
    device = devices.create(user, "laptop", "wg", actor="test")
    with mock.patch.object(main, "_peer_by_id", return_value=object()), \
            mock.patch.object(main.vm, "delete_peer", wg.delete_peer):
        r = client.delete(f"/api/peers/{device['ref']}", headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200
    assert store.get_device(device["id"])["status"] == "revoked"


# ----------------------------------------------------------------- profiles
@pytest.mark.parametrize("payload, message", [
    ({"name": "a", "tunnel_mode": "split"}, "split tunnel"),
    ({"name": "a", "allowed_cidrs": ["10.0.0.0/33"]}, "invalid CIDR"),
    ({"name": "a", "dns_servers": ["dns.example"]}, "invalid DNS"),
    ({"name": "a", "protocols": ["pptp"]}, "protocols"),
])
def test_profile_validation(payload, message):
    with pytest.raises(store.StoreError, match=message):
        store.create_profile(payload)


def test_default_and_used_profiles_cannot_be_deleted():
    default = store.default_profile()
    with pytest.raises(store.StoreError):
        store.delete_profile(default["id"])
    used = store.create_profile({"name": "used"})
    store.create_policy("any", "G", "user", access_profile_id=used["id"])
    with pytest.raises(store.StoreError):
        store.delete_profile(used["id"])
    spare = store.create_profile({"name": "spare"})
    store.set_default_profile(spare["id"])
    assert store.default_profile()["id"] == spare["id"]
    assert store.delete_profile(default["id"]) is True


# ------------------------------------------------------------------- tokens
def test_named_api_tokens(client, wg):
    h = admin_session(client)
    created = client.post("/api/auth/tokens", json={"name": "ci deploy", "role": "operator"}, headers=h).json()
    raw = created["token"]
    assert raw.startswith("cvpn_")
    assert all(raw not in json.dumps(t) for t in client.get("/api/auth/tokens").json())
    other = TestClient(main.app)
    auth = {"Authorization": f"Bearer {raw}"}
    assert other.get("/api/peers", headers=auth).status_code == 200
    assert other.get("/api/routing/overrides", headers=auth).status_code == 403
    assert store.list_api_tokens()[0]["last_used_at"]
    assert client.delete(f"/api/auth/tokens/{created['id']}", headers=h).status_code == 200
    assert other.get("/api/peers", headers=auth).status_code == 401


def test_expired_token_is_rejected(client):
    from auth import tokens

    raw, row = tokens.create("short", "admin", "test", ttl_days=1)
    with store._engine().begin() as conn:
        conn.execute(text("UPDATE api_tokens SET expires_at = '2020-01-01T00:00:00Z'"))
    assert client.get("/api/peers", headers={"Authorization": f"Bearer {raw}"}).status_code == 401


# -------------------------------------------------------------------- audit
def test_every_mutating_api_call_is_audited_and_exportable(client, wg):
    h = admin_session(client)
    with mock.patch.object(main.vm, "create_peer", return_value={"public_key": "k"}):
        client.post("/api/peers", json={"name": "x"}, headers=h)
    entry = next(a for a in store.list_audit() if a["action"] == "api.post")
    assert entry["target"] == "/api/peers" and entry["actor"] == "local:admin" and entry["details"]["status"] == 201
    export = client.get("/api/auth/audit/export")
    assert export.headers["content-type"].startswith("application/x-ndjson")
    lines = [json.loads(line) for line in export.text.splitlines()]
    assert any(item["action"] == "api.post" for item in lines)


def test_audit_is_shipped_to_syslog(monkeypatch):
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.bind(("127.0.0.1", 0))
    sink.settimeout(3)
    monkeypatch.setattr(config, "AUDIT_SYSLOG_ADDRESS", f"127.0.0.1:{sink.getsockname()[1]}")
    store.audit("device.create", actor="ldap:ivan", target="dev-1", details={"name": "Ноутбук"})
    datagram = sink.recv(65535).decode("utf-8")
    sink.close()
    assert "corpvpn-audit:" in datagram
    payload = json.loads(datagram.split("corpvpn-audit: ", 1)[1].strip("\x00\n"))
    assert payload["action"] == "device.create" and payload["details"]["name"] == "Ноутбук"


# ---------------------------------------------------------------- migration
def test_database_without_profile_columns_is_migrated(tmp_path, monkeypatch):
    path = tmp_path / "early.db"
    engine = create_engine(f"sqlite:///{path}")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE users (id TEXT PRIMARY KEY, provider TEXT NOT NULL, external_id TEXT NOT NULL, "
                          "username TEXT NOT NULL, email TEXT NOT NULL DEFAULT '', display_name TEXT NOT NULL DEFAULT '', "
                          "role TEXT NOT NULL, status TEXT NOT NULL, groups_json TEXT NOT NULL DEFAULT '[]', "
                          "directory_dn TEXT NOT NULL DEFAULT '', disabled_reason TEXT NOT NULL DEFAULT '', "
                          "created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_login_at TEXT NOT NULL DEFAULT '', "
                          "UNIQUE (provider, external_id))"))
        conn.execute(text("INSERT INTO users VALUES ('u1','ldap','g','ivan','','', 'user','active','[]','','',"
                          "'2026-09-01T00:00:00Z','2026-09-01T00:00:00Z','')"))
        conn.execute(text("CREATE TABLE group_policies (id TEXT PRIMARY KEY, provider TEXT NOT NULL, group_name TEXT NOT NULL, "
                          "role TEXT NOT NULL, priority INTEGER NOT NULL DEFAULT 100, created_at TEXT NOT NULL, "
                          "UNIQUE (provider, group_name))"))
    engine.dispose()
    monkeypatch.setattr(config, "CORPVPN_DB_PATH", str(path))
    store.reset_schema_cache()
    user = store.get_user("u1")
    assert user["access_profile_id"] == "" and user["username"] == "ivan"
    assert store.default_profile()["is_default"] is True       # seeded on first open
    assert store.create_policy("any", "G", "user")["access_profile_id"] == ""


def test_pages_render_per_role(client, wg):
    admin_session(client)
    page = client.get("/", headers=HTML).text
    assert 'data-tab="Devices"' in page and 'data-tab="Access profiles"' in page and 'data-tab="API tokens"' in page
    op_client = TestClient(main.app)
    login_as(op_client, make_user("helpdesk", role="operator"))
    op_page = op_client.get("/", headers=HTML).text
    assert 'data-tab="Devices"' in op_page and 'data-tab="Access profiles"' not in op_page
    user_client = TestClient(main.app)
    login_as(user_client, make_user("ivan"))
    me = user_client.get("/me", headers=HTML).text
    assert 'data-page="portal"' in me and "/static/ui.js" in me and 'name="csrf-token"' in me


# ------------------------------------------------------ concurrency and limits
def test_parallel_creates_cannot_exceed_the_device_limit(wg, monkeypatch):
    profile = store.create_profile({"name": "Two", "max_devices": 2})
    user = make_user("ivan", profile_id=profile["id"])
    slow_create = wg.create_peer

    def create_peer(name):
        time.sleep(0.05)                                            # widen the race window
        return slow_create(name)

    monkeypatch.setattr(devices.vm, "create_peer", create_peer)
    barrier = threading.Barrier(6)
    results = []

    def run(index):
        barrier.wait()
        try:
            results.append(devices.create(user, f"device {index}", "wg", actor="test")["id"])
        except devices.DeviceError as exc:
            results.append(str(exc))

    threads = [threading.Thread(target=run, args=(i,)) for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert len(store.list_devices(user_id=user["id"])) == 2
    assert sum("limit" in r for r in results) == 4


def test_a_user_disabled_while_a_create_waits_gets_no_device(wg):
    user = make_user("ivan")
    outcome = []

    def create():
        try:
            devices.create(user, "laptop", "wg", actor="test")
            outcome.append("created")
        except devices.DeviceError as exc:
            outcome.append(str(exc))

    with devices.backend_lock():
        worker = threading.Thread(target=create)
        worker.start()
        time.sleep(0.2)                                             # blocked on the lock
        store.set_user_status(user["id"], "disabled", "left the company")
    worker.join(5)
    assert outcome == ["the user is disabled"] and wg.peers == {}


def test_vless_device_for_a_long_upn(client, wg, xray):
    user = make_user("aleksandra.konstantinopolskaya-rimskaya@subsidiary.example.com")
    h = login_as(client, user)
    created = client.post("/api/me/devices", json={"name": "Рабочий ноутбук Lenovo T14s", "protocol": "vless"},
                          headers=h)
    assert created.status_code == 201, created.text
    name = xc.list_clients()[0].name
    assert len(name) <= 80 and name.endswith("… · Рабочий ноутбук Lenovo T14s")
    with mock.patch.object(devices.xc, "create_client", side_effect=xc.XrayClientValidationError("bad name")):
        refused = client.post("/api/me/devices", json={"name": "x", "protocol": "vless"}, headers=h)
    assert refused.status_code == 400 and refused.json()["detail"] == "bad name"


# ------------------------------------------------------------- batched Xray
def test_offboarding_restarts_xray_once_for_all_vless_devices(wg, xray):
    user = make_user("ivan")
    for name in ("phone", "tablet", "laptop"):
        devices.create(user, name, "vless", actor="test")
    xray.reset_mock()
    assert devices.suspend_user_devices(user["id"], actor="directory_sync") == 3
    assert xray.call_count == 1
    assert not any(c.enabled for c in xc.list_clients())
    xray.reset_mock()
    with devices.batch("directory sync"):                           # a whole run: still one
        devices.resume_user_devices(user["id"], actor="directory_sync")
        devices.enforce_expiry()
    assert xray.call_count == 1 and all(c.enabled for c in xc.list_clients())


def test_a_failed_batched_apply_keeps_the_suspension(wg, xray, caplog):
    user = make_user("ivan")
    device = devices.create(user, "phone", "vless", actor="test")
    xray.side_effect = RuntimeError("xray down")
    assert devices.suspend_user_devices(user["id"], actor="directory_sync") == 1
    assert store.get_device(device["id"])["status"] == "suspended"
    assert not xc.get_client(device["ref"]).enabled                 # the store holds the intent
    assert "periodic refresh retries" in caplog.text


def test_concurrent_adoption_adopts_each_credential_once(wg):
    wg.create_peer("old laptop")
    wg.create_peer("old phone")
    barrier = threading.Barrier(4)

    def run():
        barrier.wait()
        devices.adopt_unmanaged()

    threads = [threading.Thread(target=run) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    refs = [d["ref"] for d in store.list_devices()]
    assert len(refs) == 2 and len(set(refs)) == 2


def test_unassigned_owner_has_a_neutral_name():
    legacy = store.upsert_user(provider="local", external_id=devices.UNASSIGNED_EXTERNAL_ID, username="unassigned",
                               email="", display_name="Без владельца", role="user", groups=[], login=False)
    owner = devices.unassigned_user()
    assert owner["id"] == legacy["id"] and owner["display_name"] == "Unassigned"


# ------------------------------------------------------------- assignment
def test_operators_assign_only_unowned_devices_and_only_to_users(client, wg):
    wg.create_peer("old laptop")
    ivan, olga, boss = make_user("ivan"), make_user("olga"), make_user("boss", role="admin")
    op = make_user("helpdesk", role="operator")
    h = login_as(client, op)
    adopted = client.get("/api/devices").json()[0]
    url = f"/api/devices/{adopted['id']}/assign"
    assert client.post(url, json={"user_id": boss["id"]}, headers=h).status_code == 400
    assert client.post(url, json={"user_id": op["id"]}, headers=h).status_code == 400
    ok = client.post(url, json={"user_id": ivan["id"]}, headers=h)
    assert ok.status_code == 200 and ok.json()["user_id"] == ivan["id"]
    moved = client.post(url, json={"user_id": olga["id"]}, headers=h)   # now an employee's device
    assert moved.status_code == 400 and "no owner" in moved.json()["detail"]


def test_assignment_checks_the_new_owners_profile_and_is_audited(wg):
    tight = store.create_profile({"name": "Tight", "max_devices": 1, "protocols": ["wg"]})
    wide = store.create_profile({"name": "Wide", "max_devices": 5})
    kate = make_user("kate", profile_id=tight["id"])
    devices.create(kate, "laptop", "wg", actor="test")
    wg.create_peer("spare")
    devices.adopt_unmanaged()
    spare = next(d for d in store.list_devices() if d["name"] == "spare")
    with pytest.raises(devices.DeviceError, match="limit"):
        devices.assign(spare["id"], kate["id"], actor="admin")
    gone = make_user("gone")
    store.set_user_status(gone["id"], "disabled", "left")
    with pytest.raises(devices.DeviceError, match="disabled"):
        devices.assign(spare["id"], gone["id"], actor="admin")
    ivan = make_user("ivan", profile_id=wide["id"])
    devices.assign(spare["id"], ivan["id"], actor="local:admin")
    entry = next(a for a in store.list_audit() if a["action"] == "device.assign")
    assert entry["details"]["previous_user"] == "unassigned" and entry["details"]["profile"] == "Wide"


def test_operator_responses_never_carry_vless_credentials(client, wg, xray):
    ivan = make_user("ivan")
    h = login_as(client, make_user("helpdesk", role="operator"))
    issued = client.post("/api/devices", json={"user_id": ivan["id"], "name": "phone", "protocol": "vless"}, headers=h)
    assert issued.status_code == 201 and issued.json()["ref"] == ""
    assert client.post(f"/api/devices/{issued.json()['id']}/suspend", headers=h).json()["ref"] == ""
    laptop = client.post("/api/devices", json={"user_id": ivan["id"], "name": "laptop", "protocol": "wg"}, headers=h)
    assert laptop.json()["ref"]                                     # a WireGuard public key is public


# ---------------------------------------------------- backend reconciliation
def test_suspending_again_fixes_a_peer_reenabled_elsewhere(wg):
    device = devices.create(make_user("ivan"), "laptop", "wg", actor="test")
    devices.set_active(device["id"], False, actor="op")
    wg.peers[device["ref"]]["deactivated"] = False                  # re-enabled on a low-level page
    devices.set_active(device["id"], False, actor="op")
    assert wg.peers[device["ref"]]["deactivated"] is True


def test_suspending_a_device_revokes_its_open_config_links(wg):
    user = make_user("ivan")
    device = devices.create(user, "laptop", "awg", actor="test")
    link = cl.create_link(peer_public_key=device["ref"])
    devices.suspend_user_devices(user["id"], actor="directory_sync")
    assert cl.get_link(link["code"])["state"] == cl.STATUS_REVOKED
