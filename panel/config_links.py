"""
One-shot config links: hand an existing peer's AmneziaWG config to its owner.

An admin mints a single-use, expiring URL for a peer and sends it to the
employee over any channel (mail, chat); the public /awg/<code> routes in main.py
serve the config behind that code. Also the way to re-issue a profile after the
gateway address changes.

The link is a *pure read* of the peer that already exists: nothing here creates,
rotates or touches a WireGuard key (see agent.md, Invariants). Suspending or
revoking the device revokes its open links.

Single-use semantics are split across two HTTP methods on purpose. Chat apps
fetch a link preview with GET, so a GET that consumed the code would burn it
before the recipient ever tapped it — hence GET is idempotent and only POST
/awg/<code>/claim consumes, via the conditional UPDATE in consume_link().
"""

from __future__ import annotations

import hashlib
import hmac

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import config
import db
from sqlalchemy import text as _sql

_DDL = """
CREATE TABLE IF NOT EXISTS config_links (
    code             TEXT PRIMARY KEY,
    peer_public_key  TEXT NOT NULL,
    user_id          TEXT,
    protocol         TEXT NOT NULL DEFAULT 'amneziawg',
    label            TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'active',
    created_at       TEXT NOT NULL,
    expires_at       TEXT NOT NULL,
    consumed_at      TEXT NOT NULL DEFAULT ''
)
"""


def _engine():
    # Resolved per call so config.CONFIG_LINKS_DB_PATH can be repointed (tests).
    return db.get_engine(str(config.CONFIG_LINKS_DB_PATH), _DDL)


STATUS_ACTIVE = "active"
STATUS_CONSUMED = "consumed"
STATUS_REVOKED = "revoked"

# Synthetic state returned by link_state()/get_link() for a row that is still
# `active` in the table but past its expires_at. Never stored.
STATE_EXPIRED = "expired"

DEFAULT_PROTOCOL = "amneziawg"

# A link hands out a private key to whoever holds the URL: it never lives longer.
MAX_TTL_DAYS = 30

# These codes are clicked from a message, never typed by hand, so use full
# entropy (~192 bits). token_urlsafe output is [A-Za-z0-9_-].
_CODE_BYTES = 24
_CODE_ALPHABET = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
)
_CODE_MAX_LENGTH = 128


class ConfigLinkError(RuntimeError):
    pass


class ConfigLinkNotFound(ConfigLinkError):
    pass


class ConfigLinkExpired(ConfigLinkError):
    pass


class ConfigLinkAlreadyUsed(ConfigLinkError):
    pass


class ConfigLinkRevoked(ConfigLinkError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _fmt(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def generate_code() -> str:
    return secrets.token_urlsafe(_CODE_BYTES)


def normalize_code(value: Any) -> str:
    """Trim a code taken from the URL path; case is significant here.

    Not upper-cased: token_urlsafe is case-sensitive. Anything outside the
    token_urlsafe alphabet is dropped, so junk from a mangled link can never
    reach the query.
    """
    if not isinstance(value, str):
        return ""
    cleaned = "".join(ch for ch in value.strip() if ch in _CODE_ALPHABET)
    return cleaned[:_CODE_MAX_LENGTH]


def link_state(link: dict[str, Any], now: datetime | None = None) -> str:
    """active / consumed / revoked / expired — expiry wins over a stale 'active'."""
    now = (now or _now()).astimezone(timezone.utc)
    status = str(link.get("status") or "")
    if status in (STATUS_CONSUMED, STATUS_REVOKED):
        return status
    expires_at = _parse(link.get("expires_at"))
    if expires_at is None or expires_at <= now:
        return STATE_EXPIRED
    return STATUS_ACTIVE


def _row_to_dict(row: Any, now: datetime | None = None) -> dict[str, Any]:
    record = dict(row)
    if record.get("user_id") is not None:
        # User ids are hex strings; older databases typed the column INTEGER.
        record["user_id"] = str(record["user_id"])
    # `state` is computed, not a column: callers must never see an expired row
    # as usable just because its stored status still says 'active'.
    record["state"] = link_state(record, now=now)
    return record


def get_link(code: str) -> dict[str, Any] | None:
    """Pure read. The returned dict carries the computed `state` key."""
    code = normalize_code(code)
    if not code:
        return None
    with _engine().connect() as conn:
        row = conn.execute(
            _sql("SELECT * FROM config_links WHERE code = :code"),
            {"code": code},
        ).mappings().first()
    return _row_to_dict(row) if row else None


def create_link(
    peer_public_key: str,
    user_id: str | None = None,
    label: str = "",
    protocol: str = DEFAULT_PROTOCOL,
    ttl_days: int | None = None,
    code: str | None = None,
) -> dict[str, Any]:
    peer_public_key = (peer_public_key or "").strip()
    if not peer_public_key:
        raise ConfigLinkError("peer_public_key is required")
    user_id = (str(user_id).strip() or None) if user_id is not None else None

    now = _now()
    ttl = ttl_days if ttl_days is not None else config.CONFIG_LINK_TTL_DAYS
    expires_at = now + timedelta(days=min(max(1, ttl), MAX_TTL_DAYS))
    record = {
        "peer_public_key": peer_public_key,
        "user_id": user_id,
        "protocol": (protocol or DEFAULT_PROTOCOL).strip() or DEFAULT_PROTOCOL,
        "label": (label or "").strip(),
        "status": STATUS_ACTIVE,
        "created_at": _fmt(now),
        "expires_at": _fmt(expires_at),
        "consumed_at": "",
    }

    # Retry on the astronomically unlikely code collision.
    for _ in range(8):
        candidate = normalize_code(code) if code else generate_code()
        if not candidate:
            raise ConfigLinkError("config link code is empty")
        record["code"] = candidate
        try:
            with _engine().begin() as conn:
                conn.execute(
                    _sql(
                        "INSERT INTO config_links "
                        "(code, peer_public_key, user_id, protocol, label, "
                        " status, created_at, expires_at, consumed_at) "
                        "VALUES (:code, :peer_public_key, :user_id, :protocol, "
                        " :label, :status, :created_at, :expires_at, :consumed_at)"
                    ),
                    record,
                )
            return _row_to_dict(record, now=now)
        except Exception:
            if code:
                raise ConfigLinkError("config link code already exists")
            continue
    raise ConfigLinkError("could not allocate a unique config link code")


def consume_link(code: str) -> dict[str, Any]:
    """Burn the link exactly once and return the consumed row.

    The whole point of this module: a single conditional UPDATE decides the
    winner, so two concurrent clicks (or a click racing a retry) can never both
    be served. A read-then-write would double-deliver. `expires_at > :now` is a
    lexicographic comparison, which is exact because every timestamp is written
    by _fmt() in the same fixed-width UTC "...Z" form.

    Raises ConfigLinkNotFound / ConfigLinkAlreadyUsed / ConfigLinkRevoked /
    ConfigLinkExpired so the caller can render the right message.
    """
    code = normalize_code(code)
    if not code:
        raise ConfigLinkNotFound("config link was not found")

    now = _now()
    with _engine().begin() as conn:
        result = conn.execute(
            _sql(
                "UPDATE config_links SET status = :consumed, consumed_at = :now "
                "WHERE code = :code AND status = :active AND expires_at > :now"
            ),
            {
                "consumed": STATUS_CONSUMED,
                "active": STATUS_ACTIVE,
                "now": _fmt(now),
                "code": code,
            },
        )
        won = result.rowcount == 1

    link = get_link(code)
    if link is None:
        raise ConfigLinkNotFound("config link was not found")
    if won:
        return link

    state = link["state"]
    if state == STATUS_CONSUMED:
        raise ConfigLinkAlreadyUsed("config link was already used")
    if state == STATUS_REVOKED:
        raise ConfigLinkRevoked("config link is revoked")
    raise ConfigLinkExpired("config link is expired")


def revoke_link(code: str) -> dict[str, Any]:
    code = normalize_code(code)
    link = get_link(code)
    if link is None:
        raise ConfigLinkNotFound("config link was not found")
    # Only an unused link can be revoked; a consumed one keeps its history.
    with _engine().begin() as conn:
        conn.execute(
            _sql(
                "UPDATE config_links SET status = :revoked "
                "WHERE code = :code AND status = :active"
            ),
            {"revoked": STATUS_REVOKED, "active": STATUS_ACTIVE, "code": code},
        )
    link = get_link(code)
    if link is None:
        raise ConfigLinkNotFound("config link was not found")
    return link


def revoke_links_for_peer(peer_public_key: str) -> int:
    """Revoke every unused link of a peer (its device was suspended or revoked):
    a link must not hand the key out again once access has been taken away."""
    with _engine().begin() as conn:
        result = conn.execute(
            _sql(
                "UPDATE config_links SET status = :revoked "
                "WHERE peer_public_key = :peer AND status = :active"
            ),
            {"revoked": STATUS_REVOKED, "active": STATUS_ACTIVE, "peer": peer_public_key},
        )
    return int(result.rowcount or 0)


def list_links(
    status: str | None = None,
    user_id: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    """Newest first, for the panel UI."""
    query = "SELECT * FROM config_links"
    params: dict[str, Any] = {}
    clauses: list[str] = []
    if status:
        clauses.append("status = :status")
        params["status"] = status
    if user_id is not None:
        clauses.append("user_id = :user_id")
        params["user_id"] = str(user_id)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY created_at DESC, code DESC LIMIT :limit"
    params["limit"] = max(1, int(limit))

    now = _now()
    with _engine().connect() as conn:
        rows = conn.execute(_sql(query), params).mappings().all()
    return [_row_to_dict(row, now=now) for row in rows]


def purge_expired(now: datetime | None = None) -> int:
    """Delete rows whose TTL has passed, whatever their status.

    A consumed link is kept until it expires so the landing page can still say
    "already used" instead of the generic "invalid"; after that the row carries
    no useful information.
    """
    now = (now or _now()).astimezone(timezone.utc)
    with _engine().begin() as conn:
        result = conn.execute(
            _sql("DELETE FROM config_links WHERE expires_at <= :now"),
            {"now": _fmt(now)},
        )
    return int(result.rowcount or 0)


def management_record(record):
    public = dict(record)
    public["code"] = hashlib.sha256(record["code"].encode()).hexdigest()
    return public


def resolve_handle(value):
    with _engine().connect() as conn:
        codes = conn.execute(_sql("SELECT code FROM config_links")).scalars().all()
    for code in codes:
        if hmac.compare_digest(hashlib.sha256(code.encode()).hexdigest(), value):
            return code
    return value
