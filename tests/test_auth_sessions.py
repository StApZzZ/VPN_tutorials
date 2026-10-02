"""Break-glass login, server-side sessions, CSRF, roles and the admin access API."""
import base64
import re
import types
from datetime import timedelta
from unittest import mock

import pytest
from fastapi.testclient import TestClient

import config
import main
from auth import sessions, store

TOKEN = "break-glass-token-123"


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "PANEL_SECRET_TOKEN", TOKEN)
    monkeypatch.setattr(config, "PANEL_USERNAME", "admin")
    monkeypatch.setattr(config, "AUTH_LOCAL_ENABLED", True)
    monkeypatch.setattr(config, "AUTH_API_TOKEN_ENABLED", True)
    monkeypatch.setattr(config, "AUTH_LOCAL_ALLOWED_CIDRS", ())
    monkeypatch.setattr(config, "OIDC_ENABLED", False)
    monkeypatch.setattr(config, "LDAP_ENABLED", False)
    monkeypatch.setattr(config, "WG_CONFIG_PATH", str(tmp_path / "wg0.conf"))
    monkeypatch.setattr(config, "WG_CLIENTS_TABLE", str(tmp_path / "clientsTable"))
    monkeypatch.setattr(main.vm, "get_all_peers", lambda: [])
    yield TestClient(main.app)


HTML = {"Accept": "text/html"}


def login_break_glass(client, password=TOKEN, **headers):
    return client.post("/login", data={"username": "admin", "password": password}, headers=headers, follow_redirects=False)


def csrf_from_dashboard(client) -> str:
    page = client.get("/", headers=HTML)
    assert page.status_code == 200
    return re.search(r'name="csrf-token" content="([^"]+)"', page.text).group(1)


def session_for(client, role, provider="ldap", username=None):
    """Create a user with `role` and attach a live session cookie to the client."""
    user = store.upsert_user(
        provider=provider, external_id=f"{role}-id", username=username or role,
        email="", display_name=role.title(), role=role, groups=[],
    )
    fake_request = types.SimpleNamespace(client=types.SimpleNamespace(host="192.0.2.10"), headers={})
    raw, csrf = sessions.create(user, fake_request)
    client.cookies.set(sessions.COOKIE_NAME, raw)
    return user, csrf


def test_login_page_offers_only_password_form_without_sso(client):
    page = client.get("/login")
    assert page.status_code == 200
    assert 'name="password"' in page.text
    assert "/auth/oidc/start" not in page.text


def test_unauthenticated_html_redirects_and_api_is_401(client):
    assert client.get("/", headers=HTML, follow_redirects=False).headers["location"] == "/login"
    assert client.get("/api/peers").status_code == 401


def test_break_glass_login_sets_hardened_cookie(client):
    response = login_break_glass(client)
    assert response.status_code == 302 and response.headers["location"] == "/"
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{sessions.COOKIE_NAME}=")
    assert "HttpOnly" in cookie and "samesite=lax" in cookie.lower()
    assert TOKEN not in cookie  # the old panel stored the admin token in the cookie
    assert client.get("/api/peers").status_code == 200
    assert store.list_audit(action_prefix="auth.login")[0]["actor"] == "local:admin"


def test_wrong_password_is_rejected_and_audited(client):
    response = login_break_glass(client, password="nope")
    assert response.headers["location"] == "/login?error=failed"
    assert sessions.COOKIE_NAME not in response.cookies
    assert store.list_audit(action_prefix="auth.failed")


def test_session_requires_csrf_on_unsafe_requests(client):
    login_break_glass(client)
    csrf = csrf_from_dashboard(client)
    with mock.patch.object(main.vm, "create_peer", return_value={"public_key": "k"}):
        assert client.post("/api/peers", json={"name": "laptop"}).status_code == 403
        assert client.post("/api/peers", json={"name": "laptop"}, headers={"X-CSRF-Token": "forged"}).status_code == 403
        assert client.post("/api/peers", json={"name": "laptop"}, headers={"X-CSRF-Token": csrf}).status_code == 201


def test_bearer_token_is_admin_without_csrf(client):
    auth = {"Authorization": f"Bearer {TOKEN}"}
    assert client.get("/api/routing/overrides", headers=auth).status_code == 200
    with mock.patch.object(main.vm, "create_peer", return_value={"public_key": "k"}):
        assert client.post("/api/peers", json={"name": "x"}, headers=auth).status_code == 201
    assert client.get("/api/peers", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_basic_auth_needs_the_admin_username(client):
    good = base64.b64encode(f"admin:{TOKEN}".encode()).decode()
    bad = base64.b64encode(f"someone:{TOKEN}".encode()).decode()
    assert client.get("/api/peers", headers={"Authorization": f"Basic {good}"}).status_code == 200
    assert client.get("/api/peers", headers={"Authorization": f"Basic {bad}"}).status_code == 401


def test_logout_revokes_the_session(client):
    login_break_glass(client)
    csrf = csrf_from_dashboard(client)
    raw = client.cookies.get(sessions.COOKIE_NAME)
    response = client.post("/logout", data={"csrf_token": csrf}, follow_redirects=False)
    assert response.headers["location"] == "/login"
    client.cookies.set(sessions.COOKIE_NAME, raw)  # replay the old cookie
    assert client.get("/api/peers").status_code == 401


def test_logout_without_csrf_is_refused(client):
    login_break_glass(client)
    assert client.post("/logout", data={}, follow_redirects=False).status_code == 403
    assert client.get("/api/peers").status_code == 200


def test_idle_and_absolute_expiry(client, monkeypatch):
    user, _ = session_for(client, "operator")
    raw = client.cookies.get(sessions.COOKIE_NAME)
    assert client.get("/api/peers").status_code == 200
    old = store.iso(store.now() - timedelta(minutes=config.SESSION_IDLE_MINUTES + 1))
    store.touch_session(sessions._hash(raw), store.parse_iso(old))
    assert client.get("/api/peers").status_code == 401  # idle timeout, row deleted
    assert store.get_session(sessions._hash(raw)) is None

    session_for(client, "operator")
    raw = client.cookies.get(sessions.COOKIE_NAME)
    monkeypatch.setattr(config, "SESSION_TTL_HOURS", 0)
    with store._engine().begin() as conn:
        from sqlalchemy import text

        conn.execute(text("UPDATE sessions SET expires_at = :t"), {"t": store.iso(store.now() - timedelta(seconds=1))})
    assert client.get("/api/peers").status_code == 401


def test_operator_cannot_reach_routing_or_access_admin(client):
    session_for(client, "operator")
    assert client.get("/api/peers").status_code == 200
    assert client.get("/api/routing/overrides").status_code == 403
    assert client.get("/api/auth/users").status_code == 403
    assert client.get("/metrics").status_code == 403
    page = client.get("/", headers=HTML)
    assert page.status_code == 200
    assert 'id="page-routing"' not in page.text and 'id="page-access"' not in page.text


def test_user_role_is_sent_to_the_portal(client):
    session_for(client, "user", username="ivan")
    response = client.get("/", headers=HTML, follow_redirects=False)
    assert response.status_code == 302 and response.headers["location"] == "/me"
    me = client.get("/me", headers=HTML)
    assert me.status_code == 200 and "ivan" in me.text
    assert client.get("/api/peers").status_code == 403


def test_disabling_a_user_kills_their_session(client):
    user, _ = session_for(client, "operator")
    assert client.get("/api/peers").status_code == 200
    store.set_user_status(user["id"], "disabled", "left the company")
    assert client.get("/api/peers").status_code == 401


def test_local_login_can_be_limited_to_networks(client, monkeypatch):
    monkeypatch.setattr(config, "AUTH_LOCAL_ALLOWED_CIDRS", ("10.0.0.0/8",))
    # TestClient's peer address is not in 10/8
    assert login_break_glass(client).headers["location"] == "/login?error=failed"
    assert client.get("/api/peers", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 401


def test_repeated_failures_lock_the_form(client, monkeypatch):
    monkeypatch.setattr(config, "AUTH_MAX_FAILURES_PER_IP", 3)
    for _ in range(3):
        assert login_break_glass(client, password="bad").headers["location"] == "/login?error=failed"
    assert login_break_glass(client).headers["location"] == "/login?error=locked"
    for _ in range(3):  # refused attempts are audited once per window, not each time
        login_break_glass(client)
    assert len(store.list_audit(action_prefix="auth.locked")) == 1


def test_break_glass_name_cannot_be_locked_by_its_username_budget(client, monkeypatch):
    # the per-username budget protects directory accounts; the emergency login
    # has none, and someone failing on purpose must not lock it
    monkeypatch.setattr(config, "AUTH_MAX_FAILURES", 1)
    for _ in range(3):
        login_break_glass(client, password="bad")
    assert login_break_glass(client).headers["location"] == "/"


def test_wrong_api_tokens_count_against_the_ip(client, monkeypatch):
    monkeypatch.setattr(config, "AUTH_MAX_FAILURES_PER_IP", 3)
    for guess in ("a", "b", "cvpn_c"):
        assert client.get("/api/peers", headers={"Authorization": f"Bearer {guess}"}).status_code == 401
    # over budget: not even the right token is checked
    assert client.get("/api/peers", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 401
    assert login_break_glass(client).headers["location"] == "/login?error=locked"


def test_oversized_username_is_refused_before_anything_else(client):
    response = client.post("/login", data={"username": "x" * 100_000, "password": "p"}, follow_redirects=False)
    assert response.status_code == 400
    assert store.list_audit(action_prefix="auth.failed") == []  # refused before database writes


def test_cross_origin_login_post_is_refused(client):
    response = login_break_glass(client, Origin="https://evil.example")
    assert response.headers["location"] == "/login?error=origin"


def test_non_ascii_credentials_are_refused_not_500(client):
    # secrets.compare_digest() on non-ASCII str raised TypeError -> HTTP 500
    wrong_layout = client.post("/login", data={"username": "шмфтщм", "password": "x"}, follow_redirects=False)
    assert wrong_layout.headers["location"] == "/login?error=failed"
    assert login_break_glass(client, password="пароль").headers["location"] == "/login?error=failed"
    basic = base64.b64encode("админ:токен".encode()).decode()
    assert client.get("/api/peers", headers={"Authorization": f"Basic {basic}"}).status_code == 401
    assert client.get("/api/peers", headers={"Authorization": "Bearer токен".encode()}).status_code == 401
    session_for(client, "operator")
    forged = client.post("/api/peers", json={"name": "x"}, headers={"X-CSRF-Token": "подделка".encode()})
    assert forged.status_code == 403


def test_admin_manages_policies_and_users_with_audit(client):
    login_break_glass(client)
    csrf = csrf_from_dashboard(client)
    h = {"X-CSRF-Token": csrf}
    created = client.post("/api/auth/policies", json={"group_name": "VPN-Admins", "role": "admin"}, headers=h)
    assert created.status_code == 201
    pid = created.json()["id"]
    assert client.post("/api/auth/policies", json={"group_name": "VPN-Admins", "role": "user"}, headers=h).status_code == 400
    assert client.put(f"/api/auth/policies/{pid}", json={"group_name": "VPN-Admins", "role": "operator", "priority": 5},
                      headers=h).json()["role"] == "operator"

    other, _ = session_for(TestClient(main.app), "operator", username="petr")
    assert client.post(f"/api/auth/users/{other['id']}/disable", headers=h).json()["status"] == "disabled"
    assert store.get_user(other["id"])["status"] == "disabled"
    assert client.post(f"/api/auth/users/{other['id']}/enable", headers=h).json()["status"] == "active"
    assert client.delete(f"/api/auth/policies/{pid}", headers=h).status_code == 200

    actions = [a["action"] for a in client.get("/api/auth/audit").json()]
    for expected in ("policy.create", "policy.update", "user.disable", "user.enable", "policy.delete"):
        assert expected in actions


def test_admin_cannot_disable_themselves(client):
    login_break_glass(client)
    csrf = csrf_from_dashboard(client)
    me = store.find_user("local", "admin")
    response = client.post(f"/api/auth/users/{me['id']}/disable", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 400 and response.json()["detail"] == "cannot_disable_self"


def test_break_glass_account_is_controlled_by_config_not_the_panel(client):
    login_break_glass(client)
    row = store.find_user("local", "admin")
    response = client.post(f"/api/auth/users/{row['id']}/disable", headers={"Authorization": f"Bearer {TOKEN}"})
    assert response.status_code == 400 and response.json()["detail"] == "break_glass_managed_by_config"
    # A row disabled some other way comes back with the next break-glass sign-in.
    store.set_user_status(row["id"], "disabled", "admin", source="admin")
    client.cookies.clear()
    assert login_break_glass(client).headers["location"] == "/"
    assert client.get("/api/peers").status_code == 200


def test_admin_dashboard_has_access_and_routing_pages(client):
    login_break_glass(client)
    page = client.get("/", headers=HTML).text
    assert 'data-tab="Local users"' in page and 'data-tab="Routing"' in page
    assert 'action="/logout"' in page and 'name="csrf_token"' in page
