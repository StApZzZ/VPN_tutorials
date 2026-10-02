"""OpenID Connect authorization-code flow with PKCE.

Works with any OpenID Provider that publishes a discovery document: Keycloak,
ADFS 2016+, Entra ID, Authentik, Okta... See docs/IDP-*.md for per-IdP setup.

Security properties:
  * state is random, single use and expires after 10 minutes (store.oidc_states)
  * the state is bound to the browser that started the flow: a random value in
    an HttpOnly cookie, its hash stored with the state, compared before the code
    exchange (otherwise a callback URL from someone else's flow signs the victim
    into that account: login CSRF)
  * PKCE S256 on every request
  * id_token signature verified against the provider JWKS; iss, aud, exp, iat
    and nonce are checked; only asymmetric algorithms are accepted
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
from typing import Any, Optional
from urllib.parse import urlencode, urlsplit

import httpx
import jwt

import config
from auth import store
from auth.identity import AuthFailed, Identity, secure_equals

ALLOWED_ALGS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512")
_CACHE_SECONDS = 3600

# Tests inject httpx.MockTransport here.
_transport: Optional[httpx.BaseTransport] = None
_cache: dict[str, tuple[float, Any]] = {}


def enabled() -> bool:
    return bool(
        config.OIDC_ENABLED
        and config.OIDC_DISCOVERY_URL
        and config.OIDC_CLIENT_ID
        and config.OIDC_REDIRECT_URL
    )


def _client() -> httpx.Client:
    return httpx.Client(transport=_transport, timeout=config.OIDC_HTTP_TIMEOUT, follow_redirects=False)


def _transport_url(url: str) -> None:
    parsed = urlsplit(url)
    schemes = {"https", "http"} if config.OIDC_ALLOW_INSECURE_HTTP else {"https"}
    if parsed.scheme not in schemes or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise AuthFailed("OIDC requires an HTTPS provider URL; insecure HTTP is for isolated labs only")


def _get_json(url: str, **kwargs) -> dict[str, Any]:
    _transport_url(url)
    with _client() as client:
        response = client.get(url, **kwargs)
    if response.status_code != 200:
        raise AuthFailed(f"GET {url} -> HTTP {response.status_code}")
    return response.json()


def clear_cache() -> None:
    _cache.clear()


def discovery(force: bool = False) -> dict[str, Any]:
    hit = _cache.get("discovery")
    if hit and not force and time.monotonic() - hit[0] < _CACHE_SECONDS:
        return hit[1]
    doc = _get_json(config.OIDC_DISCOVERY_URL)
    for key in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not doc.get(key):
            raise AuthFailed(f"discovery document has no {key}")
    for key in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint", "end_session_endpoint"):
        if doc.get(key):
            _transport_url(doc[key])
    _cache["discovery"] = (time.monotonic(), doc)
    return doc


def _jwks(force: bool = False) -> dict[str, Any]:
    hit = _cache.get("jwks")
    if hit and not force and time.monotonic() - hit[0] < _CACHE_SECONDS:
        return hit[1]
    keys = _get_json(discovery()["jwks_uri"])
    _cache["jwks"] = (time.monotonic(), keys)
    return keys


def _signing_key(kid: Optional[str], alg: str):
    for force in (False, True):  # a new kid after key rotation -> refetch once
        for jwk in _jwks(force=force).get("keys", []):
            if jwk.get("use", "sig") != "sig":
                continue
            if kid and jwk.get("kid") != kid:
                continue
            return jwt.PyJWK(jwk, algorithm=alg).key
    raise AuthFailed(f"no signing key for kid={kid!r}")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _binding_hash(binding: str) -> str:
    return hashlib.sha256(binding.encode("utf-8")).hexdigest()


def start_url(binding: str, ip: str = "") -> str:
    """Authorization URL; `binding` is the random value the caller puts in the
    browser's flow cookie."""
    doc = discovery()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    store.put_oidc_state(state, nonce, verifier, binding_hash=_binding_hash(binding), ip=ip)
    params = {
        "response_type": "code",
        "client_id": config.OIDC_CLIENT_ID,
        "redirect_uri": config.OIDC_REDIRECT_URL,
        "scope": config.OIDC_SCOPES,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    sep = "&" if "?" in doc["authorization_endpoint"] else "?"
    return f"{doc['authorization_endpoint']}{sep}{urlencode(params)}"


def _exchange(code: str, verifier: str) -> dict[str, Any]:
    doc = discovery()
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": config.OIDC_REDIRECT_URL,
        "code_verifier": verifier,
    }
    auth = None
    if config.OIDC_TOKEN_AUTH_METHOD == "client_secret_post":
        data["client_id"] = config.OIDC_CLIENT_ID
        data["client_secret"] = config.OIDC_CLIENT_SECRET
    else:
        auth = (config.OIDC_CLIENT_ID, config.OIDC_CLIENT_SECRET)
    with _client() as client:
        response = client.post(doc["token_endpoint"], data=data, auth=auth, headers={"Accept": "application/json"})
    if response.status_code != 200:
        raise AuthFailed(f"token endpoint -> HTTP {response.status_code}: {response.text[:200]}")
    tokens = response.json()
    if not tokens.get("id_token"):
        raise AuthFailed("token response has no id_token")
    return tokens


def _verify_id_token(id_token: str, nonce: str) -> dict[str, Any]:
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError as exc:
        raise AuthFailed(f"malformed id_token: {exc}") from exc
    alg = header.get("alg", "")
    if alg not in ALLOWED_ALGS:
        raise AuthFailed(f"id_token alg {alg!r} not allowed")
    key = _signing_key(header.get("kid"), alg)
    try:
        claims = jwt.decode(
            id_token,
            key=key,
            algorithms=[alg],
            audience=config.OIDC_CLIENT_ID,
            issuer=discovery()["issuer"],
            leeway=60,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise AuthFailed(f"id_token rejected: {exc}") from exc
    if not secure_equals(str(claims.get("nonce", "")), nonce):
        raise AuthFailed("id_token nonce mismatch")
    return claims


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v is not None]
    return [str(value)]


def _first_claim(claims: dict[str, Any], names: str) -> str:
    for name in (n.strip() for n in names.split(",")):
        value = claims.get(name)
        if value:
            return str(value)
    return ""


def _groups(claims: dict[str, Any]) -> tuple[list[str], bool]:
    """(groups, known). Unknown when none of OIDC_GROUPS_CLAIMS is present, or the
    IdP signals that the groups did not fit into the token (Entra ID's overage:
    _claim_names.groups / hasgroups instead of a groups claim)."""
    names = [n.strip() for n in config.OIDC_GROUPS_CLAIMS.split(",") if n.strip()]
    overage = claims.get("hasgroups") in (True, "true") or any(
        name in (claims.get("_claim_names") or {}) for name in names
    )
    present = False
    groups: list[str] = []
    for name in names:
        if name in claims:
            present = True
            groups.extend(_as_list(claims[name]))
    return groups, present and not overage


def callback(params: dict[str, str], binding: str) -> Identity:
    """`binding` is the flow cookie of the browser that brought the callback."""
    if params.get("error"):
        raise AuthFailed(f"IdP returned error={params.get('error')}: {params.get('error_description', '')[:200]}")
    state = params.get("state", "")
    code = params.get("code", "")
    if not state or not code:
        raise AuthFailed("callback without state or code")
    pending = store.pop_oidc_state(state)
    if pending is None:
        raise AuthFailed("unknown, reused or expired state")
    if not binding or not pending.get("binding_hash") or not secure_equals(_binding_hash(binding),
                                                                            pending["binding_hash"]):
        raise AuthFailed("state was started in another browser")
    tokens = _exchange(code, pending["code_verifier"])
    claims = _verify_id_token(tokens["id_token"], pending["nonce"])

    groups, known = _groups(claims)
    userinfo_endpoint = discovery().get("userinfo_endpoint")
    if not known and userinfo_endpoint and tokens.get("access_token"):
        info = _get_json(userinfo_endpoint, headers={"Authorization": f"Bearer {tokens['access_token']}"})
        if str(info.get("sub", "")) != str(claims["sub"]):
            raise AuthFailed("userinfo sub does not match id_token")
        claims = {**info, **{k: v for k, v in claims.items() if k not in ("_claim_names", "_claim_sources")}}
        groups, known = _groups(claims)

    username = _first_claim(claims, config.OIDC_USERNAME_CLAIMS) or str(claims["sub"])
    return Identity(
        provider="oidc",
        external_id=str(claims["sub"]),
        username=username,
        email=str(claims.get("email", "") or ""),
        display_name=str(claims.get("name", "") or username),
        groups=groups,
        groups_known=known,
        acr=str(claims.get("acr", "") or ""),
        amr=_as_list(claims.get("amr")),
    )


def end_session_url(post_logout_redirect: str) -> Optional[str]:
    if not (enabled() and config.OIDC_LOGOUT_AT_IDP):
        return None
    try:
        endpoint = discovery().get("end_session_endpoint")
    except AuthFailed:
        return None
    if not endpoint:
        return None
    params = {"client_id": config.OIDC_CLIENT_ID}
    if post_logout_redirect:
        params["post_logout_redirect_uri"] = post_logout_redirect
    sep = "&" if "?" in endpoint else "?"
    return f"{endpoint}{sep}{urlencode(params)}"
