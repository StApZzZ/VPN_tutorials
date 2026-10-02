"""OIDC sign-in against an in-process fake IdP (real RS256 signatures, PKCE)."""
import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

import config
import main
from auth import oidc, store

ISSUER = "https://sso.example.com/realms/corp"
CLIENT_ID = "corpvpn"
PANEL = "https://vpn.example.com"


class FakeIdP:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk.update({"kid": "k1", "use": "sig", "alg": "RS256"})
        self.jwks = {"keys": [jwk]}
        self.nonce = ""
        self.challenge = ""
        self.claims = {}
        self.userinfo = {}
        self.overrides = {}
        self.token_requests = []
        self.alg = "RS256"

    def id_token(self):
        now = int(time.time())
        claims = {
            "iss": ISSUER, "aud": CLIENT_ID, "sub": "user-123", "iat": now, "exp": now + 300,
            "nonce": self.nonce, "preferred_username": "ipetrov", "email": "ipetrov@corp.example",
            "name": "Иван Петров", "groups": ["/corp/vpn-admins"],
        }
        claims.update(self.claims)
        for k, v in self.overrides.items():
            if v is None:
                claims.pop(k, None)
            else:
                claims[k] = v
        if self.alg == "HS256":
            return jwt.encode(claims, "shared-secret-guess-that-is-long-enough-32b", algorithm="HS256", headers={"kid": "k1"})
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "k1"})

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={
                "issuer": ISSUER,
                "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
                "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
                "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
                "userinfo_endpoint": f"{ISSUER}/protocol/openid-connect/userinfo",
                "end_session_endpoint": f"{ISSUER}/protocol/openid-connect/logout",
            })
        if url.endswith("/certs"):
            return httpx.Response(200, json=self.jwks)
        if url.endswith("/token"):
            form = parse_qs(request.content.decode())
            self.token_requests.append((form, request.headers.get("authorization", "")))
            verifier = form["code_verifier"][0]
            expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            if expected != self.challenge or form["code"][0] != "the-code":
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(200, json={"id_token": self.id_token(), "access_token": "at-1", "token_type": "Bearer"})
        if url.endswith("/userinfo"):
            assert request.headers["authorization"] == "Bearer at-1"
            return httpx.Response(200, json=self.userinfo)
        return httpx.Response(404)


@pytest.fixture
def idp(monkeypatch):
    fake = FakeIdP()
    monkeypatch.setattr(oidc, "_transport", httpx.MockTransport(fake.handler))
    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    monkeypatch.setattr(config, "OIDC_DISCOVERY_URL", f"{ISSUER}/.well-known/openid-configuration")
    monkeypatch.setattr(config, "OIDC_CLIENT_ID", CLIENT_ID)
    monkeypatch.setattr(config, "OIDC_CLIENT_SECRET", "s3cret")
    monkeypatch.setattr(config, "OIDC_REDIRECT_URL", f"{PANEL}/auth/oidc/callback")
    monkeypatch.setattr(config, "PANEL_PUBLIC_URL", PANEL)
    monkeypatch.setattr(config, "LDAP_ENABLED", False)
    monkeypatch.setattr(config, "AUTH_DEFAULT_ROLE", "")
    store.create_policy("any", "vpn-admins", "admin", 10)
    store.create_policy("oidc", "VPN-Users", "user", 20)
    return fake


@pytest.fixture
def client(idp, monkeypatch):
    monkeypatch.setattr(main.vm, "get_all_peers", lambda: [])
    yield TestClient(main.app, base_url=PANEL)


def begin(client, idp):
    start = client.get("/auth/oidc/start", follow_redirects=False)
    assert start.status_code == 302
    params = parse_qs(urlparse(start.headers["location"]).query)
    assert params["code_challenge_method"] == ["S256"]
    assert params["redirect_uri"] == [f"{PANEL}/auth/oidc/callback"]
    idp.nonce = params["nonce"][0]
    idp.challenge = params["code_challenge"][0]
    return params["state"][0]


def finish(client, state, code="the-code"):
    return client.get(f"/auth/oidc/callback?code={code}&state={state}", follow_redirects=False)


def test_login_page_shows_the_sso_button(client):
    assert "/auth/oidc/start" in client.get("/login").text


def test_full_login_creates_admin_from_keycloak_group_path(client, idp):
    response = finish(client, begin(client, idp))
    assert response.status_code == 302 and response.headers["location"] == "/"
    assert "secure" in response.headers["set-cookie"].lower()  # https base URL
    user = store.find_user("oidc", "user-123")
    assert user["role"] == "admin" and user["username"] == "ipetrov" and user["email"] == "ipetrov@corp.example"
    form, basic = idp.token_requests[-1]
    assert basic.startswith("Basic ") and "client_secret" not in form  # client_secret_basic
    assert client.get("/api/auth/users").status_code == 200


def test_client_secret_post(client, idp, monkeypatch):
    monkeypatch.setattr(config, "OIDC_TOKEN_AUTH_METHOD", "client_secret_post")
    finish(client, begin(client, idp))
    form, basic = idp.token_requests[-1]
    assert form["client_secret"] == ["s3cret"] and not basic


def test_groups_fall_back_to_userinfo(client, idp):
    idp.overrides = {"groups": None}
    idp.userinfo = {"sub": "user-123", "groups": ["VPN-Users"]}
    response = finish(client, begin(client, idp))
    assert response.headers["location"] == "/me"
    assert store.find_user("oidc", "user-123")["role"] == "user"


def test_userinfo_for_another_subject_is_rejected(client, idp):
    idp.overrides = {"groups": None}
    idp.userinfo = {"sub": "someone-else", "groups": ["vpn-admins"]}
    assert finish(client, begin(client, idp)).headers["location"] == "/login?error=sso"


def test_adfs_style_group_claim(client, idp):
    idp.overrides = {"groups": None, "group": "VPN-Users"}
    assert finish(client, begin(client, idp)).headers["location"] == "/me"


def test_user_outside_vpn_groups_is_denied_and_audited(client, idp):
    idp.overrides = {"groups": ["Accounting"]}
    assert finish(client, begin(client, idp)).headers["location"] == "/login?error=denied"
    assert store.find_user("oidc", "user-123") is None
    assert store.list_audit(action_prefix="auth.denied")


def test_removed_from_groups_disables_existing_user(client, idp):
    finish(client, begin(client, idp))
    assert store.find_user("oidc", "user-123")["status"] == "active"
    client.cookies.clear()
    idp.overrides = {"groups": []}
    assert finish(client, begin(client, idp)).headers["location"] == "/login?error=denied"
    user = store.find_user("oidc", "user-123")
    assert (user["status"], user["disabled_source"], user["disabled_reason"]) == ("disabled", "directory", "no_vpn_group")
    # Back in a VPN group: the next sign-in re-checked it and lifts the disable.
    idp.overrides = {}
    assert finish(client, begin(client, idp)).headers["location"] == "/"
    assert store.find_user("oidc", "user-123")["status"] == "active"


def test_admin_disable_survives_the_next_sso_sign_in(client, idp):
    finish(client, begin(client, idp))
    user = store.find_user("oidc", "user-123")
    # IdP session still alive, groups unchanged: the panel decision must stand.
    store.set_user_status(user["id"], "disabled", "admin", source="admin")
    client.cookies.clear()
    assert finish(client, begin(client, idp)).headers["location"] == "/login?error=denied"
    assert store.find_user("oidc", "user-123")["status"] == "disabled"
    assert store.list_audit(action_prefix="auth.denied")[0]["details"]["reason"] == "admin"


@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "another-client"},
        {"iss": "https://evil.example.com"},
        {"exp": int(time.time()) - 3600},
        {"nonce": "replayed-nonce"},
    ],
)
def test_bad_id_token_claims_are_rejected(client, idp, overrides):
    idp.overrides = overrides
    assert finish(client, begin(client, idp)).headers["location"] == "/login?error=sso"
    assert store.find_user("oidc", "user-123") is None


def test_symmetric_alg_is_rejected(client, idp):
    idp.alg = "HS256"
    assert finish(client, begin(client, idp)).headers["location"] == "/login?error=sso"


def test_token_signed_by_another_key_is_rejected(client, idp):
    idp.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # jwks still has the old key
    assert finish(client, begin(client, idp)).headers["location"] == "/login?error=sso"


def test_state_is_single_use(client, idp):
    state = begin(client, idp)
    assert finish(client, state).headers["location"] == "/"
    client.cookies.clear()
    assert finish(client, state).headers["location"] == "/login?error=sso"


def test_unknown_state_and_idp_error(client, idp):
    begin(client, idp)
    assert finish(client, "not-a-state").headers["location"] == "/login?error=sso"
    r = client.get("/auth/oidc/callback?error=access_denied&error_description=nope", follow_redirects=False)
    assert r.headers["location"] == "/login?error=sso"


def test_wrong_code_verifier_fails_at_token_endpoint(client, idp):
    state = begin(client, idp)
    idp.challenge = "tampered"
    assert finish(client, state).headers["location"] == "/login?error=sso"


def test_logout_ends_the_idp_session(client, idp):
    finish(client, begin(client, idp))
    page = client.get("/", headers={"Accept": "text/html"})
    import re

    csrf = re.search(r'name="csrf-token" content="([^"]+)"', page.text).group(1)
    response = client.post("/logout", data={"csrf_token": csrf}, follow_redirects=False)
    location = response.headers["location"]
    assert location.startswith(f"{ISSUER}/protocol/openid-connect/logout?")
    assert "post_logout_redirect_uri=https%3A%2F%2Fvpn.example.com%2Flogin" in location
    assert client.get("/api/auth/me").status_code == 401
    assert not client.cookies.get(SESSION_COOKIE)


# ------------------------------------------------- browser binding and cookies
SESSION_COOKIE = "__Host-corpvpn_session"
FLOW_COOKIE = "__Host-corpvpn_oidc"


def test_callback_in_another_browser_is_refused(client, idp):
    # login CSRF: the attacker starts the flow, the victim opens the callback URL
    state = begin(client, idp)
    victim = TestClient(main.app, base_url=PANEL)
    assert finish(victim, state).headers["location"] == "/login?error=sso"
    assert store.find_user("oidc", "user-123") is None
    assert "another browser" in store.list_audit(action_prefix="auth.failed")[0]["details"]["reason"]
    # nor with a flow cookie of the victim's own (another) sign-in
    begin(victim, idp)
    attacker_state = begin(client, idp)
    assert finish(victim, attacker_state).headers["location"] == "/login?error=sso"


def test_cookies_are_host_prefixed_and_secure(client, idp):
    start = client.get("/auth/oidc/start", follow_redirects=False)
    flow = start.headers["set-cookie"]
    assert flow.startswith(f"{FLOW_COOKIE}=") and "Secure" in flow and "HttpOnly" in flow and "Path=/" in flow
    params = parse_qs(urlparse(start.headers["location"]).query)
    idp.nonce, idp.challenge = params["nonce"][0], params["code_challenge"][0]
    done = finish(client, params["state"][0])
    cookies = done.headers.get_list("set-cookie")
    assert any(c.startswith(f"{SESSION_COOKIE}=") and "Secure" in c for c in cookies)
    assert any(c.startswith(f"{FLOW_COOKIE}=") and "Max-Age=0" in c for c in cookies)  # used up
    assert client.get("/api/auth/me").status_code == 200


def test_public_url_decides_secure_cookies_behind_a_tls_proxy(idp):
    # TLS ends at a proxy; the panel itself sees plain http
    plain = TestClient(main.app, base_url="http://vpn.example.com")
    cookie = plain.get("/auth/oidc/start", follow_redirects=False).headers["set-cookie"]
    assert cookie.startswith(f"{FLOW_COOKIE}=") and "Secure" in cookie


# ------------------------------------------------------ missing groups claim
def test_missing_groups_claim_does_not_offboard(client, idp):
    finish(client, begin(client, idp))
    client.cookies.clear()
    idp.overrides = {"groups": None}
    idp.userinfo = {"sub": "user-123"}  # no groups there either (a removed claim mapper)
    assert finish(client, begin(client, idp)).headers["location"] == "/login?error=groups_claim"
    assert store.find_user("oidc", "user-123")["status"] == "active"
    assert store.list_audit(action_prefix="auth.failed")[0]["details"]["reason"].endswith("no group information")


def test_entra_group_overage_is_not_no_groups(client, idp):
    finish(client, begin(client, idp))
    client.cookies.clear()
    idp.overrides = {"groups": None, "_claim_names": {"groups": "src1"},
                     "_claim_sources": {"src1": {"endpoint": "https://graph.microsoft.com/v1.0/users/x/getMemberObjects"}}}
    idp.userinfo = {"sub": "user-123"}
    assert finish(client, begin(client, idp)).headers["location"] == "/login?error=groups_claim"
    assert store.find_user("oidc", "user-123")["status"] == "active"


def test_default_role_covers_unknown_groups(client, idp, monkeypatch):
    monkeypatch.setattr(config, "AUTH_DEFAULT_ROLE", "user")
    idp.overrides = {"groups": None}
    idp.userinfo = {"sub": "user-123"}
    assert finish(client, begin(client, idp)).headers["location"] == "/me"
    assert store.find_user("oidc", "user-123")["role"] == "user"


# ------------------------------------------------------- MFA for privileged roles
def test_admin_without_mfa_is_refused_and_left_alone(client, idp, monkeypatch):
    monkeypatch.setattr(config, "OIDC_REQUIRED_AMR", ("mfa",))
    idp.overrides = {"amr": ["pwd"]}
    assert finish(client, begin(client, idp)).headers["location"] == "/login?error=mfa"
    assert store.find_user("oidc", "user-123") is None
    assert store.list_audit(action_prefix="auth.mfa_required")[0]["details"]["role"] == "admin"
    idp.overrides = {"amr": ["pwd", "mfa"]}
    assert finish(client, begin(client, idp)).headers["location"] == "/"


def test_mfa_requirement_applies_only_to_the_listed_roles(client, idp, monkeypatch):
    monkeypatch.setattr(config, "OIDC_REQUIRED_ACR", ("gold",))
    idp.overrides = {"groups": ["VPN-Users"], "acr": "silver"}
    assert finish(client, begin(client, idp)).headers["location"] == "/me"  # role user
    client.cookies.clear()
    idp.overrides = {"acr": "silver"}
    assert finish(client, begin(client, idp)).headers["location"] == "/login?error=mfa"
    idp.overrides = {"acr": "gold"}
    assert finish(client, begin(client, idp)).headers["location"] == "/"


def test_disabled_oidc_hides_routes(client, monkeypatch):
    monkeypatch.setattr(config, "OIDC_ENABLED", False)
    assert client.get("/auth/oidc/start").status_code == 404


def test_provider_rejects_cleartext_metadata_and_credentials(monkeypatch):
    monkeypatch.setattr(config, "OIDC_ALLOW_INSECURE_HTTP", False)
    with pytest.raises(oidc.AuthFailed, match="HTTPS"):
        oidc._transport_url("http://sso.example.com/token")
    with pytest.raises(oidc.AuthFailed):
        oidc._transport_url("https://user:password@sso.example.com/token")
    oidc._transport_url("https://sso.example.com/token")
