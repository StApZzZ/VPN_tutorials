"""Server-side sessions and the panel's cookies.

The cookie carries a random 256-bit id; only its SHA-256 is stored, so a leaked
database does not yield usable sessions. Each session has its own CSRF token,
required on unsafe requests authenticated by the cookie.

On an HTTPS panel every cookie is Secure and carries the __Host- prefix, so a
sibling or parent domain cannot plant one (session fixation, login CSRF).
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta
from typing import Any, Optional

from fastapi import Request, Response

import config
from auth import store

COOKIE_NAME = "corpvpn_session"
# Short-lived cookies of the sign-in flows (see routes.py).
OIDC_COOKIE = "corpvpn_oidc"
MFA_COOKIE = "corpvpn_mfa"
HOST_PREFIX = "__Host-"
_TOUCH_EVERY = timedelta(seconds=60)


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def secure_cookies(request: Request) -> bool:
    """Secure (and __Host-) cookies? PANEL_PUBLIC_URL decides when it is set: behind
    a TLS-terminating proxy the panel itself may only see http. Without it the
    request scheme decides (uvicorn runs with --proxy-headers)."""
    if config.PANEL_PUBLIC_URL:
        return config.PANEL_PUBLIC_URL.lower().startswith("https://")
    return request.url.scheme == "https"


def cookie_name(request: Request, base: str = COOKIE_NAME) -> str:
    return f"{HOST_PREFIX}{base}" if secure_cookies(request) else base


def read_cookie(request: Request, base: str = COOKIE_NAME) -> str:
    # Only the name for the current scheme: on HTTPS a plain-named cookie may
    # have been planted by another host of the domain.
    return request.cookies.get(cookie_name(request, base), "")


def create(user: dict[str, Any], request: Request) -> tuple[str, str]:
    raw = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    moment = store.now()
    store.insert_session(
        {
            "id_hash": _hash(raw),
            "user_id": user["id"],
            "provider": user["provider"],
            "csrf": csrf,
            "created_at": store.iso(moment),
            "expires_at": store.iso(moment + timedelta(hours=config.SESSION_TTL_HOURS)),
            "last_seen_at": store.iso(moment),
            "ip": client_ip(request),
            "user_agent": (request.headers.get("user-agent") or "")[:300],
        }
    )
    return raw, csrf


def resolve(raw: str) -> Optional[tuple[dict[str, Any], dict[str, Any]]]:
    """(session, user) for a live session of an active user, else None."""
    if not raw:
        return None
    id_hash = _hash(raw)
    session = store.get_session(id_hash)
    if session is None:
        return None
    moment = store.now()
    expires = store.parse_iso(session["expires_at"])
    last_seen = store.parse_iso(session["last_seen_at"])
    idle_limit = timedelta(minutes=config.SESSION_IDLE_MINUTES)
    if expires is None or expires <= moment or last_seen is None or moment - last_seen > idle_limit:
        store.delete_session(id_hash)
        return None
    user = store.get_user(session["user_id"])
    if user is None or user["status"] != "active":
        store.delete_session(id_hash)
        return None
    if moment - last_seen > _TOUCH_EVERY:
        store.touch_session(id_hash, moment)
    return session, user


def revoke(raw: str) -> None:
    if raw:
        store.delete_session(_hash(raw))


def set_flow_cookie(response: Response, request: Request, base: str, value: str, max_age: int,
                    samesite: str = "lax") -> None:
    response.set_cookie(
        cookie_name(request, base),
        value,
        max_age=max_age,
        httponly=True,
        samesite=samesite,
        secure=secure_cookies(request),
        path="/",  # __Host- requires it
    )


def clear_flow_cookie(response: Response, request: Request, base: str) -> None:
    response.delete_cookie(cookie_name(request, base), path="/", secure=secure_cookies(request), httponly=True)


def set_cookie(response: Response, raw: str, request: Request) -> None:
    # Lax, not Strict: after the OIDC callback the browser follows a redirect
    # chain that started on the IdP; a Strict cookie would not be sent on it.
    set_flow_cookie(response, request, COOKIE_NAME, raw, config.SESSION_TTL_HOURS * 3600)


def clear_cookie(response: Response, request: Request) -> None:
    clear_flow_cookie(response, request, COOKIE_NAME)
