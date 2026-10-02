"""LDAP / AD sign-in and directory_sync against an ldap3 MOCK_SYNC directory."""
from unittest import mock

import pytest
from fastapi.testclient import TestClient
from ldap3 import MOCK_SYNC, MODIFY_REPLACE, Connection, Server

import config
import devices
import directory_sync
import main
from auth import ldap_auth, sessions, store

BASE = "dc=corp,dc=local"
SVC_DN = f"cn=svc-vpn,ou=Service,{BASE}"
IVAN_DN = f"cn=Ivan Petrov,ou=Users,{BASE}"
IVAN_ID = "3f1c2d4e-0000-4000-8000-000000000001"
OLGA_DN = f"cn=Olga Smirnova,ou=Users,{BASE}"
GROUP_USERS = f"CN=VPN-Users,OU=Groups,{BASE}"


@pytest.fixture
def directory(monkeypatch):
    server = Server("fake-ad")
    admin = Connection(server, user=SVC_DN, password="svc-pw", client_strategy=MOCK_SYNC)
    add = admin.strategy.add_entry
    add(BASE, {"objectClass": "domain"})
    add(SVC_DN, {"objectClass": "person", "userPassword": "svc-pw"})
    add(IVAN_DN, {
        "objectClass": ["person", "user"], "userPassword": "ivan-pw", "sAMAccountName": "ipetrov",
        "mail": "ipetrov@corp.local", "displayName": "Ivan Petrov", "memberOf": [GROUP_USERS],
        "userAccountControl": 512, "entryUUID": "3f1c2d4e-0000-4000-8000-000000000001",
    })
    add(OLGA_DN, {
        "objectClass": ["person", "user"], "userPassword": "olga-pw", "sAMAccountName": "osmirnova",
        "mail": "os@corp.local", "displayName": "Olga Smirnova", "memberOf": [],
        "userAccountControl": 512, "entryUUID": "3f1c2d4e-0000-4000-8000-000000000002",
    })
    # Olga reaches VPN-Admins only through group membership (nested-group path)
    add(f"cn=VPN-Admins,ou=Groups,{BASE}", {"objectClass": "group", "cn": "VPN-Admins", "member": [OLGA_DN]})
    assert admin.bind()  # the fixture edits the directory through this connection

    monkeypatch.setattr(ldap_auth, "_server_factory", lambda: server)
    monkeypatch.setattr(ldap_auth, "_strategy", MOCK_SYNC)
    for name, value in {
        "LDAP_ENABLED": True, "LDAP_URL": "ldaps://dc1.corp.local", "LDAP_BIND_DN": SVC_DN,
        "LDAP_BIND_PASSWORD": "svc-pw", "LDAP_USER_BASE_DN": BASE, "LDAP_GROUP_BASE_DN": BASE,
        "LDAP_USER_FILTER": "(&(objectClass=user)(sAMAccountName={username}))",
        # generic LDAP form; the mock does not implement AD's in-chain matching rule
        "LDAP_GROUP_SEARCH_FILTER": "(&(objectClass=group)(member={user_dn}))",
        "OIDC_ENABLED": False, "AUTH_DEFAULT_ROLE": "", "AUTH_ATTESTATION_DAYS": 0,
        "PANEL_SECRET_TOKEN": "break-glass-token-123", "PANEL_USERNAME": "admin",
    }.items():
        monkeypatch.setattr(config, name, value)
    store.create_policy("ldap", "VPN-Users", "operator", 20)
    store.create_policy("any", "VPN-Admins", "admin", 10)
    return admin


@pytest.fixture
def client(directory, monkeypatch):
    monkeypatch.setattr(main.vm, "get_all_peers", lambda: [])
    yield TestClient(main.app)


def login(client, username, password):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=False)


def test_login_with_member_of_group(client):
    response = login(client, "ipetrov", "ivan-pw")
    assert response.headers["location"] == "/"
    user = store.find_user("ldap", "3f1c2d4e-0000-4000-8000-000000000001")
    assert user["role"] == "operator" and user["email"] == "ipetrov@corp.local"
    assert user["directory_dn"] == IVAN_DN
    assert client.get("/api/peers").status_code == 200
    assert client.get("/api/routing/overrides").status_code == 403


def test_group_search_grants_admin(client):
    assert login(client, "osmirnova", "olga-pw").headers["location"] == "/"
    assert store.find_user("ldap", "3f1c2d4e-0000-4000-8000-000000000002")["role"] == "admin"


def test_wrong_password(client):
    assert login(client, "ipetrov", "wrong").headers["location"] == "/login?error=failed"
    assert store.list_users() == []
    assert "invalid credentials" in store.list_audit(action_prefix="auth.failed")[0]["details"]["reason"]


def test_empty_password_never_binds(client):
    with mock.patch.object(ldap_auth, "_bind", wraps=ldap_auth._bind) as bind:
        assert login(client, "ipetrov", "").headers["location"] == "/login?error=failed"
    assert bind.call_count == 0


def test_filter_injection_is_escaped(client):
    assert login(client, "*", "ivan-pw").headers["location"] == "/login?error=failed"
    assert login(client, "ipetrov)(sAMAccountName=*", "ivan-pw").headers["location"] == "/login?error=failed"


def test_disabled_account_is_denied(client, directory):
    directory.modify(IVAN_DN, {"userAccountControl": [(MODIFY_REPLACE, ["514"])]})
    assert login(client, "ipetrov", "ivan-pw").headers["location"] == "/login?error=denied"


def test_user_without_vpn_group_is_denied(client, directory):
    directory.modify(IVAN_DN, {"memberOf": [(MODIFY_REPLACE, ["CN=Accounting,OU=Groups," + BASE])]})
    assert login(client, "ipetrov", "ivan-pw").headers["location"] == "/login?error=denied"


def test_cyrillic_account_name_signs_in(client, directory):
    # The break-glass check runs first and used to raise TypeError on non-ASCII.
    directory.strategy.add_entry(f"cn=Иван Иванов,ou=Users,{BASE}", {
        "objectClass": ["person", "user"], "userPassword": "пароль-123", "sAMAccountName": "иванов",
        "memberOf": [GROUP_USERS], "userAccountControl": 512, "entryUUID": "3f1c2d4e-0000-4000-8000-000000000003",
    })
    assert login(client, "иванов", "неверный").headers["location"] == "/login?error=failed"
    assert login(client, "иванов", "пароль-123").headers["location"] == "/"
    assert store.find_user("ldap", "3f1c2d4e-0000-4000-8000-000000000003")["username"] == "иванов"


def test_break_glass_still_works_with_ldap_enabled(client):
    assert login(client, "admin", "break-glass-token-123").headers["location"] == "/"


def test_failed_logins_lock_before_hitting_the_directory(client, monkeypatch):
    monkeypatch.setattr(config, "AUTH_MAX_FAILURES", 2)
    login(client, "ipetrov", "x")
    login(client, "ipetrov", "y")
    with mock.patch.object(ldap_auth, "authenticate") as auth:
        assert login(client, "ipetrov", "ivan-pw").headers["location"] == "/login?error=locked"
    auth.assert_not_called()


def test_username_budget_spans_all_source_ips(client, monkeypatch):
    # A spray from many addresses must not reach the AD lockout threshold.
    monkeypatch.setattr(config, "AUTH_MAX_FAILURES", 3)
    addresses = iter(f"198.51.100.{n}" for n in range(1, 100))
    monkeypatch.setattr(sessions, "client_ip", lambda request: next(addresses))
    with mock.patch.object(ldap_auth, "authenticate", wraps=ldap_auth.authenticate) as auth:
        outcomes = [login(client, "ipetrov", f"guess-{n}").headers["location"] for n in range(9)]
    assert auth.call_count == 3
    assert outcomes[3:] == ["/login?error=locked"] * 6
    # other accounts are not affected
    assert login(client, "osmirnova", "olga-pw").headers["location"] == "/"


def test_sync_removes_user_dropped_from_groups_and_kills_sessions(client, directory):
    login(client, "ipetrov", "ivan-pw")
    assert client.get("/api/peers").status_code == 200
    directory.modify(IVAN_DN, {"memberOf": [(MODIFY_REPLACE, [])]})
    summary = directory_sync.run()
    assert summary["disabled"] == [{"username": "ipetrov", "reason": "no_vpn_group"}]
    assert client.get("/api/peers").status_code == 401
    assert store.list_audit(action_prefix="directory.disable")[0]["details"]["sessions_revoked"] == 1


def test_sync_disables_deleted_and_directory_disabled_accounts(client, directory):
    login(client, "ipetrov", "ivan-pw")
    client.cookies.clear()
    login(client, "osmirnova", "olga-pw")
    directory.delete(IVAN_DN)
    directory.modify(OLGA_DN, {"userAccountControl": [(MODIFY_REPLACE, ["514"])]})
    first = directory_sync.run()
    # "not found" needs a second run in a row (an account moving between OUs)
    assert first["disabled"] == [{"username": "osmirnova", "reason": "directory_disabled"}]
    assert first["missing"] == ["ipetrov"]
    assert store.find_user("ldap", IVAN_ID)["status"] == "active"
    assert directory_sync.run()["disabled"] == [{"username": "ipetrov", "reason": "directory_missing"}]


def test_a_user_found_again_loses_the_missing_mark(client, directory):
    login(client, "ipetrov", "ivan-pw")
    moved = f"cn=Ivan Petrov,ou=Moved,{BASE}"
    directory.delete(IVAN_DN)
    assert directory_sync.run()["missing"] == ["ipetrov"]
    directory.strategy.add_entry(moved, {
        "objectClass": ["person", "user"], "userPassword": "ivan-pw", "sAMAccountName": "ipetrov",
        "memberOf": [GROUP_USERS], "userAccountControl": 512, "entryUUID": IVAN_ID,
    })
    summary = directory_sync.run()
    assert summary["disabled"] == [] and summary["missing"] == []
    user = store.find_user("ldap", IVAN_ID)
    assert user["directory_missing_since"] == "" and user["directory_dn"] == moved


def test_sync_refuses_a_mass_disable(client, directory, monkeypatch, wg):
    sign_in_both(client)
    device = devices.create(store.find_user("ldap", IVAN_ID), "laptop", "wg", actor="test")
    monkeypatch.setattr(config, "DIRECTORY_SYNC_MAX_DISABLE", "1")
    # e.g. the service account lost read access to the group memberships
    directory.modify(IVAN_DN, {"memberOf": [(MODIFY_REPLACE, [])]})
    directory.modify(f"cn=VPN-Admins,ou=Groups,{BASE}", {"member": [(MODIFY_REPLACE, [])]})
    summary = directory_sync.run()
    assert summary["disabled"] == [] and "refused to disable 2 of 2" in summary["errors"][0]
    assert {u["status"] for u in store.list_users(provider="ldap")} == {"active"}
    assert store.get_device(device["id"])["status"] == "active"
    aborted = store.list_audit(action_prefix="directory.sync_aborted")[0]["details"]
    assert aborted["would_disable"] == 2 and aborted["limit"] == 1
    monkeypatch.setattr(config, "DIRECTORY_SYNC_MAX_DISABLE", "0")  # no limit
    assert len(directory_sync.run()["disabled"]) == 2


def test_sync_brings_back_users_the_directory_allows_again(client, directory, wg):
    login(client, "ipetrov", "ivan-pw")
    user = store.find_user("ldap", IVAN_ID)
    device = devices.create(user, "laptop", "wg", actor="test")
    directory.modify(IVAN_DN, {"memberOf": [(MODIFY_REPLACE, [])]})
    directory_sync.run()
    assert store.get_device(device["id"])["status"] == "suspended"
    directory.modify(IVAN_DN, {"memberOf": [(MODIFY_REPLACE, [GROUP_USERS])]})
    summary = directory_sync.run()
    assert summary["enabled"] == [{"username": "ipetrov", "previous_reason": "no_vpn_group"}]
    assert store.find_user("ldap", IVAN_ID)["status"] == "active"
    assert store.get_device(device["id"])["status"] == "active"


def test_sync_never_undoes_an_admin_disable(client):
    login(client, "ipetrov", "ivan-pw")
    user = store.find_user("ldap", IVAN_ID)
    store.set_user_status(user["id"], "disabled", "admin", source="admin")
    summary = directory_sync.run()
    assert summary["enabled"] == [] and store.get_user(user["id"])["status"] == "disabled"


def test_one_ambiguous_account_does_not_stop_the_others(client, directory):
    sign_in_both(client)
    directory.delete(IVAN_DN)
    for n in (1, 2):
        directory.strategy.add_entry(f"cn=Ivan Petrov {n},ou=Users,{BASE}", {
            "objectClass": ["person", "user"], "userPassword": "x", "sAMAccountName": "ipetrov",
            "memberOf": [GROUP_USERS], "userAccountControl": 512, "entryUUID": f"3f1c2d4e-0000-4000-8000-00000000001{n}",
        })
    directory.modify(OLGA_DN, {"userAccountControl": [(MODIFY_REPLACE, ["514"])]})
    summary = directory_sync.run()
    assert summary["errors"] and summary["errors"][0].startswith("ipetrov:")
    assert summary["disabled"] == [{"username": "osmirnova", "reason": "directory_disabled"}]
    assert store.find_user("ldap", IVAN_ID)["status"] == "active"


def test_only_one_sync_runs_at_a_time(client):
    login(client, "ipetrov", "ivan-pw")
    with directory_sync._exclusive() as mine:
        assert mine
        summary = directory_sync.run()
    assert summary["errors"] == ["another directory sync is running"] and summary["checked"] == 0
    assert directory_sync.run()["errors"] == []


def test_admin_disable_survives_the_next_ldap_sign_in(client, wg):
    admin = {"Authorization": "Bearer break-glass-token-123"}
    login(client, "ipetrov", "ivan-pw")
    user = store.find_user("ldap", IVAN_ID)
    device = devices.create(user, "laptop", "wg", actor="test")
    assert client.post(f"/api/auth/users/{user['id']}/disable", headers=admin).status_code == 200
    client.cookies.clear()
    # The AD password still works, but the panel decision stands.
    assert login(client, "ipetrov", "ivan-pw").headers["location"] == "/login?error=denied"
    user = store.find_user("ldap", IVAN_ID)
    assert (user["status"], user["disabled_source"], user["disabled_reason"]) == ("disabled", "admin", "admin")
    assert store.get_device(device["id"])["status"] == "suspended" and wg.peers[device["ref"]]["deactivated"]
    assert "user.enable" not in [a["action"] for a in store.list_audit()]

    assert client.post(f"/api/auth/users/{user['id']}/enable", headers=admin).json()["status"] == "active"
    assert store.get_device(device["id"])["status"] == "active"
    assert login(client, "ipetrov", "ivan-pw").headers["location"] == "/"


def test_sign_in_lifts_a_directory_disable(client, directory, wg):
    login(client, "ipetrov", "ivan-pw")
    user = store.find_user("ldap", IVAN_ID)
    device = devices.create(user, "laptop", "wg", actor="test")
    directory.modify(IVAN_DN, {"memberOf": [(MODIFY_REPLACE, [])]})
    directory_sync.run()
    assert store.find_user("ldap", IVAN_ID)["disabled_source"] == "directory"
    directory.modify(IVAN_DN, {"memberOf": [(MODIFY_REPLACE, [GROUP_USERS])]})
    client.cookies.clear()
    assert login(client, "ipetrov", "ivan-pw").headers["location"] == "/"
    assert store.find_user("ldap", IVAN_ID)["status"] == "active"
    assert store.get_device(device["id"])["status"] == "active"
    enabled = store.list_audit(action_prefix="user.enable")[0]
    assert enabled["details"]["previous_reason"] == "no_vpn_group"


def test_sync_updates_role_changes(client, directory):
    login(client, "ipetrov", "ivan-pw")
    directory.modify(f"cn=VPN-Admins,ou=Groups,{BASE}", {"member": [(MODIFY_REPLACE, [OLGA_DN, IVAN_DN])]})
    summary = directory_sync.run()
    assert summary["updated"] == 1
    assert store.find_user("ldap", "3f1c2d4e-0000-4000-8000-000000000001")["role"] == "admin"


def test_sync_changes_nothing_when_directory_is_unreachable(client, monkeypatch):
    login(client, "ipetrov", "ivan-pw")
    monkeypatch.setattr(config, "LDAP_BIND_PASSWORD", "rotated-and-wrong")
    summary = directory_sync.run()
    assert summary["errors"] and summary["disabled"] == []
    assert store.find_user("ldap", "3f1c2d4e-0000-4000-8000-000000000001")["status"] == "active"


def test_oidc_attestation(monkeypatch):
    monkeypatch.setattr(config, "LDAP_ENABLED", False)
    monkeypatch.setattr(config, "AUTH_ATTESTATION_DAYS", 30)
    user = store.upsert_user(provider="oidc", external_id="s1", username="stale", email="",
                             display_name="", role="user", groups=[])
    fresh = store.upsert_user(provider="oidc", external_id="s2", username="fresh", email="",
                              display_name="", role="user", groups=[])
    from sqlalchemy import text

    with store._engine().begin() as conn:
        conn.execute(text("UPDATE users SET last_login_at = '2020-01-01T00:00:00Z' WHERE id = :id"), {"id": user["id"]})
    disabled = [d["username"] for d in directory_sync.run()["disabled"]]
    assert disabled == ["stale"]
    assert store.get_user(fresh["id"])["status"] == "active"


def test_provider_test_endpoint(client):
    login(client, "admin", "break-glass-token-123")
    page = client.get("/", headers={"Accept": "text/html"})
    import re

    csrf = re.search(r'name="csrf-token" content="([^"]+)"', page.text).group(1)
    result = client.post("/api/auth/providers/test", headers={"X-CSRF-Token": csrf}).json()
    assert result["ldap"]["ok"] is True and result["ldap"]["code"] == "ok"
    assert sessions.COOKIE_NAME in client.cookies


# ------------------------------------------------ directory errors are errors
GROUP_SEARCH = "member="  # a fragment of LDAP_GROUP_SEARCH_FILTER in the fixture


def answer_searches(monkeypatch, code, description, *, only=None, partial=False, raises=None):
    """Make the directory answer searches (all, or those whose filter contains
    `only`) with a result code, optionally keeping the entries found so far
    (a partial result), or raise like a timed-out connection."""
    real = Connection.search

    def search(self, search_base, search_filter, *args, **kwargs):
        if only is not None and only not in search_filter:
            return real(self, search_base, search_filter, *args, **kwargs)
        if raises is not None:
            raise raises
        ok = real(self, search_base, search_filter, *args, **kwargs) if partial else False
        if not partial:
            self.response, self._entries = [], []
        self.result = {"result": code, "description": description, "message": "", "dn": "",
                       "referrals": None, "type": "searchResDone"}
        return ok

    monkeypatch.setattr(Connection, "search", search)


def sign_in_both(client):
    assert login(client, "ipetrov", "ivan-pw").headers["location"] == "/"
    client.cookies.clear()
    assert login(client, "osmirnova", "olga-pw").headers["location"] == "/"
    client.cookies.clear()


def assert_nobody_disabled(summary):
    assert summary["errors"] and summary["disabled"] == []
    assert {u["status"] for u in store.list_users(provider="ldap")} == {"active"}


@pytest.mark.parametrize("code, description", [(51, "busy"), (52, "unavailable"), (50, "insufficientAccessRights"),
                                               (11, "adminLimitExceeded"), (10, "referral")])
def test_sync_changes_nothing_when_the_user_search_fails(client, monkeypatch, code, description):
    sign_in_both(client)
    answer_searches(monkeypatch, code, description)
    assert_nobody_disabled(directory_sync.run())


def test_sync_ignores_a_partial_group_search(client, monkeypatch):
    # Olga is an admin only through the (nested) group search.
    sign_in_both(client)
    answer_searches(monkeypatch, 3, "timeLimitExceeded", only=GROUP_SEARCH, partial=True)
    assert_nobody_disabled(directory_sync.run())
    assert store.find_user("ldap", "3f1c2d4e-0000-4000-8000-000000000002")["role"] == "admin"


def test_sync_survives_a_search_timeout(client, monkeypatch, wg):
    from ldap3.core.exceptions import LDAPResponseTimeoutError

    sign_in_both(client)
    user = store.find_user("ldap", IVAN_ID)
    device = devices.create(user, "laptop", "wg", actor="test")
    store.update_device(device["id"], expires_at=store.iso(store.now()))  # due for expiry
    answer_searches(monkeypatch, 0, "", raises=LDAPResponseTimeoutError("no response from server"))
    summary = directory_sync.run()
    assert_nobody_disabled(summary)
    # The rest of the run still happens.
    assert summary["expired_devices"] == 1


def test_sign_in_during_a_failing_group_search_does_not_disable(client, monkeypatch, wg):
    sign_in_both(client)
    olga = store.find_user("ldap", "3f1c2d4e-0000-4000-8000-000000000002")
    device = devices.create(olga, "laptop", "wg", actor="test")
    monkeypatch.setattr(config, "AUTH_MAX_FAILURES", 1)
    answer_searches(monkeypatch, 51, "busy", only=GROUP_SEARCH)
    for _ in range(2):  # not a wrong password: nothing counts against her
        assert login(client, "osmirnova", "olga-pw").headers["location"] == "/login?error=unavailable"
    assert store.get_user(olga["id"])["status"] == "active"
    assert store.get_device(device["id"])["status"] == "active"
    assert store.list_audit(action_prefix="auth.error")[0]["details"]["reason"].startswith("LDAP search failed")


def test_sign_in_during_a_search_timeout_is_not_a_500(client, monkeypatch):
    from ldap3.core.exceptions import LDAPResponseTimeoutError

    answer_searches(monkeypatch, 0, "", raises=LDAPResponseTimeoutError("no response from server"))
    assert login(client, "ipetrov", "ivan-pw").headers["location"] == "/login?error=unavailable"


def test_ambiguous_username_is_refused(client, directory):
    directory.strategy.add_entry(f"cn=Ivan Petrov 2,ou=Users,{BASE}", {
        "objectClass": ["person", "user"], "userPassword": "ivan-pw", "sAMAccountName": "ipetrov",
        "userAccountControl": 512, "entryUUID": "3f1c2d4e-0000-4000-8000-000000000009",
    })
    assert login(client, "ipetrov", "ivan-pw").headers["location"] == "/login?error=failed"
    assert store.list_users() == []


def test_rejected_service_bind_names_the_credentials(client, monkeypatch):
    monkeypatch.setattr(config, "LDAP_BIND_PASSWORD", "rotated-and-wrong")
    result = ldap_auth.test_connection()
    assert result["ok"] is False and result["code"] == "bind" and "LDAP_BIND_PASSWORD" in result["detail"]
    assert login(client, "ipetrov", "ivan-pw").headers["location"] == "/login?error=unavailable"


# --------------------------------------------------- expired / locked accounts
def filetime(moment):
    from datetime import datetime, timezone

    return str(int((moment - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000))


@pytest.mark.parametrize("value, disabled", [
    (None, False),
    ("0", False),
    ("9223372036854775807", False),
    ("past", True),
    ("future", False),
])
def test_account_expiry_counts_as_disabled(client, directory, value, disabled):
    from datetime import timedelta

    login(client, "ipetrov", "ivan-pw")
    if value in ("past", "future"):
        value = filetime(store.now() + (timedelta(days=-1) if value == "past" else timedelta(days=30)))
    if value is not None:
        directory.modify(IVAN_DN, {"accountExpires": [(MODIFY_REPLACE, [value])]})
    summary = directory_sync.run()
    expected = [{"username": "ipetrov", "reason": "directory_disabled"}] if disabled else []
    assert summary["disabled"] == expected


def test_expiry_given_as_a_datetime_by_a_schema_aware_connection():
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    assert ldap_auth._expired({"accountExpires": [now - timedelta(hours=1)]})
    assert not ldap_auth._expired({"accountExpires": [now + timedelta(days=1)]})
    assert not ldap_auth._expired({"accountExpires": [datetime(1601, 1, 1, tzinfo=timezone.utc)]})
    assert not ldap_auth._expired({"accountExpires": [datetime(9999, 12, 31, tzinfo=timezone.utc)]})


def test_disabled_filter_for_other_directories(client, directory, monkeypatch):
    # FreeIPA / 389-DS lock an account with nsAccountLock; the bind may still
    # work for sync purposes, the entry says "locked".
    login(client, "ipetrov", "ivan-pw")
    monkeypatch.setattr(config, "LDAP_DISABLED_FILTER", "(nsAccountLock=TRUE)")
    assert directory_sync.run()["disabled"] == []
    directory.modify(IVAN_DN, {"nsAccountLock": [(MODIFY_REPLACE, ["TRUE"])]})
    assert directory_sync.run()["disabled"] == [{"username": "ipetrov", "reason": "directory_disabled"}]
    client.cookies.clear()
    assert login(client, "ipetrov", "ivan-pw").headers["location"] == "/login?error=denied"


# ----------------------------------------------------------- connection settings
def test_referrals_are_never_chased(monkeypatch):
    monkeypatch.setattr(ldap_auth, "_server_factory", None)
    monkeypatch.setattr(config, "LDAP_URL", "ldaps://127.0.0.1:1")
    monkeypatch.setattr(config, "LDAP_TIMEOUT", 2)
    server = ldap_auth._server()
    assert server.allowed_referral_hosts == []
    assert isinstance(server.tls, ldap_auth._Tls)
    seen = {}
    real = ldap_auth.Connection

    def recording(*args, **kwargs):
        seen.update(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(ldap_auth, "Connection", recording)
    with pytest.raises(ldap_auth.DirectoryUnavailable) as failed:
        ldap_auth._service()
    assert seen["auto_referrals"] is False
    assert failed.value.code == "unreachable"


@pytest.mark.parametrize("attribute,value", [("msDS-User-Account-Control-Computed",16), ("msDS-User-Account-Control-Computed",8388608), ("pwdLastSet",0)])
def test_ad_login_restrictions_offboard_and_recover(client, directory, attribute, value):
    assert login(client,"ipetrov","ivan-pw").status_code == 302
    directory.modify(IVAN_DN,{attribute:[(MODIFY_REPLACE,[value])]})
    summary=directory_sync.run()
    assert summary["disabled"] == [{"username":"ipetrov","reason":"directory_disabled"}]
    assert store.find_user("ldap",IVAN_ID)["status"] == "disabled"
    assert login(client,"ipetrov","ivan-pw").headers["location"] == "/login?error=denied"
    directory.modify(IVAN_DN,{attribute:[(MODIFY_REPLACE,[1 if attribute=="pwdLastSet" else 0])]})
    assert directory_sync.run()["enabled"] == [{"username":"ipetrov","previous_reason":"directory_disabled"}]
