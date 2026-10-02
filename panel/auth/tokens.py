"""Named API tokens for automation (replaces sharing the break-glass token).

The raw token is shown once at creation; only its SHA-256 is stored. A token has a
role (admin or operator) or a read-only scope (metrics, auditor: see
store.TOKEN_SCOPES), an optional expiry and can be revoked; every use updates
last_used_at. Like the break-glass token it only works from
AUTH_LOCAL_ALLOWED_CIDRS when that is set.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta
from typing import Any, Optional

from auth import store

PREFIX = "cvpn_"
TOKEN_ROLES = ("admin", "operator") + store.TOKEN_SCOPES


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def create(name: str, role: str, created_by: str, ttl_days: int = 0) -> tuple[str, dict[str, Any]]:
    name = " ".join((name or "").split())
    if not name or len(name) > 60:
        raise store.StoreError("token name must be 1-60 characters")
    if role not in TOKEN_ROLES:
        raise store.StoreError("role must be one of: " + ", ".join(TOKEN_ROLES))
    if ttl_days < 0:
        raise store.StoreError("ttl_days must be >= 0")
    raw = PREFIX + secrets.token_urlsafe(32)
    expires = store.iso(store.now() + timedelta(days=ttl_days)) if ttl_days else ""
    row = store.insert_api_token(
        {"name": name, "token_hash": _hash(raw), "role": role, "created_by": created_by, "expires_at": expires}
    )
    row.pop("token_hash", None)
    return raw, row


def verify(raw: str) -> Optional[dict[str, Any]]:
    if not raw or not raw.startswith(PREFIX):
        return None
    row = store.find_api_token(_hash(raw))
    if row is None:
        return None
    if row["expires_at"] and store.parse_iso(row["expires_at"]) <= store.now():
        return None
    store.touch_api_token(row["id"])
    return row
