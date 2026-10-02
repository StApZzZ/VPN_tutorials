"""Persistence for users, sessions, OIDC state, group policies, access profiles,
devices, API tokens and the audit log.

Plain SQL through db.get_engine() like the other stores, so CORPVPN_DB_PATH can be
a SQLite path or a PostgreSQL URL. Ids are text UUIDs (portable across both);
timestamps are ISO-8601 UTC strings.
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import inspect, text

import config
import db

ROLES = ("user", "operator", "admin")
ROLE_RANK = {role: rank for rank, role in enumerate(ROLES, start=1)}
# Read-only scopes for automation that is not a person (API tokens only): they
# have no rank, so they never pass require_user / require_operator / require_admin.
#   metrics  GET /metrics (a Prometheus server)
#   auditor  reading and exporting the audit log (a SIEM)
TOKEN_SCOPES = ("metrics", "auditor")
PROVIDERS = ("local", "oidc", "ldap")
POLICY_PROVIDERS = ("any", "oidc", "ldap")
DEVICE_PROTOCOLS = ("wg", "awg", "vless")
DEVICE_STATUSES = ("active", "suspended", "revoked")
TUNNEL_MODES = ("full", "split")
# Who disabled a user (users.disabled_source). Only an administrator's decision
# survives a successful sign-in; the others are lifted by the directory check
# that sign-in performs.
DISABLE_SOURCES = ("admin", "directory", "attestation")

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS users (
        id              TEXT PRIMARY KEY,
        provider        TEXT NOT NULL,
        external_id     TEXT NOT NULL,
        username        TEXT NOT NULL,
        email           TEXT NOT NULL DEFAULT '',
        display_name    TEXT NOT NULL DEFAULT '',
        role            TEXT NOT NULL,
        status          TEXT NOT NULL,
        groups_json     TEXT NOT NULL DEFAULT '[]',
        directory_dn    TEXT NOT NULL DEFAULT '',
        disabled_reason TEXT NOT NULL DEFAULT '',
        created_at      TEXT NOT NULL,
        updated_at      TEXT NOT NULL,
        last_login_at   TEXT NOT NULL DEFAULT '',
        UNIQUE (provider, external_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sessions (
        id_hash      TEXT PRIMARY KEY,
        user_id      TEXT NOT NULL,
        provider     TEXT NOT NULL,
        csrf         TEXT NOT NULL,
        created_at   TEXT NOT NULL,
        expires_at   TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        ip           TEXT NOT NULL DEFAULT '',
        user_agent   TEXT NOT NULL DEFAULT ''
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS oidc_states (
        state         TEXT PRIMARY KEY,
        nonce         TEXT NOT NULL,
        code_verifier TEXT NOT NULL,
        created_at    TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS group_policies (
        id         TEXT PRIMARY KEY,
        provider   TEXT NOT NULL,
        group_name TEXT NOT NULL,
        role       TEXT NOT NULL,
        priority   INTEGER NOT NULL DEFAULT 100,
        created_at TEXT NOT NULL,
        UNIQUE (provider, group_name)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        id           TEXT PRIMARY KEY,
        ts           TEXT NOT NULL,
        actor        TEXT NOT NULL,
        action       TEXT NOT NULL,
        target       TEXT NOT NULL DEFAULT '',
        details_json TEXT NOT NULL DEFAULT '{}',
        ip           TEXT NOT NULL DEFAULT ''
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS access_profiles (
        id                  TEXT PRIMARY KEY,
        name                TEXT NOT NULL UNIQUE,
        description         TEXT NOT NULL DEFAULT '',
        tunnel_mode         TEXT NOT NULL DEFAULT 'full',
        allowed_cidrs_json  TEXT NOT NULL DEFAULT '[]',
        dns_servers_json    TEXT NOT NULL DEFAULT '[]',
        search_domains_json TEXT NOT NULL DEFAULT '[]',
        protocols_json      TEXT NOT NULL DEFAULT '["wg","awg","vless"]',
        max_devices         INTEGER NOT NULL DEFAULT 3,
        device_ttl_days     INTEGER NOT NULL DEFAULT 0,
        is_default          INTEGER NOT NULL DEFAULT 0,
        created_at          TEXT NOT NULL,
        updated_at          TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS devices (
        id             TEXT PRIMARY KEY,
        user_id        TEXT NOT NULL,
        name           TEXT NOT NULL,
        protocol       TEXT NOT NULL,
        ref            TEXT NOT NULL,
        status         TEXT NOT NULL,
        suspend_reason TEXT NOT NULL DEFAULT '',
        created_by     TEXT NOT NULL DEFAULT '',
        created_at     TEXT NOT NULL,
        updated_at     TEXT NOT NULL,
        expires_at     TEXT NOT NULL DEFAULT ''
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS api_tokens (
        id           TEXT PRIMARY KEY,
        name         TEXT NOT NULL,
        token_hash   TEXT NOT NULL UNIQUE,
        role         TEXT NOT NULL,
        created_by   TEXT NOT NULL DEFAULT '',
        created_at   TEXT NOT NULL,
        expires_at   TEXT NOT NULL DEFAULT '',
        last_used_at TEXT NOT NULL DEFAULT '',
        revoked      INTEGER NOT NULL DEFAULT 0
    )
    """,
    "CREATE INDEX IF NOT EXISTS devices_user ON devices (user_id)",
    "CREATE INDEX IF NOT EXISTS devices_ref ON devices (ref)",
    "CREATE INDEX IF NOT EXISTS sessions_user ON sessions (user_id)",
    "CREATE INDEX IF NOT EXISTS audit_ts ON audit_log (ts)",
)

_ready: set[str] = set()
_lock = threading.Lock()


class StoreError(ValueError):
    """Invalid input for a store operation."""


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: str) -> Optional[datetime]:
    if not value:
        return None
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _engine():
    path = config.CORPVPN_DB_PATH
    engine = db.get_engine(path)
    if path not in _ready:
        with _lock:
            if path not in _ready:
                with engine.begin() as conn:
                    for statement in _SCHEMA:
                        conn.execute(text(statement))
                    _migrate_columns(conn)
                    _ensure_default_profile(conn)
                _ready.add(path)
    return engine


# Columns added after a table first shipped (databases from 2.0 pre-releases).
_ADDED_COLUMNS = (
    ("users", "access_profile_id", "TEXT NOT NULL DEFAULT ''"),
    ("group_policies", "access_profile_id", "TEXT NOT NULL DEFAULT ''"),
    ("users", "disabled_source", "TEXT NOT NULL DEFAULT ''"),
    # directory_sync: first run that did not find the user (disabled on the second)
    ("users", "directory_missing_since", "TEXT NOT NULL DEFAULT ''"),
    # OIDC attestation: when the "sign in again soon" event was raised
    ("users", "attestation_warned_at", "TEXT NOT NULL DEFAULT ''"),
    # OIDC: hash of the cookie that binds a pending sign-in to its browser
    ("oidc_states", "binding_hash", "TEXT NOT NULL DEFAULT ''"),
    ("oidc_states", "ip", "TEXT NOT NULL DEFAULT ''"),
)


def _migrate_columns(conn) -> None:
    inspector = inspect(conn)
    known: dict[str, set[str]] = {}
    for table, column, ddl in _ADDED_COLUMNS:
        existing = known.setdefault(table, {c["name"] for c in inspector.get_columns(table)})
        if column not in existing:
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
            existing.add(column)
            if (table, column) == ("users", "disabled_source"):
                _backfill_disabled_source(conn)


def _backfill_disabled_source(conn) -> None:
    """Classify users disabled before the source was recorded, and turn the old
    English reasons into the reason codes used since. Anything not written by the
    directory checks counts as an administrator's decision, so it stays sticky."""
    conn.execute(text(
        "UPDATE users SET disabled_source = CASE "
        "WHEN disabled_reason LIKE 'no sign-in for %' THEN 'attestation' "
        "WHEN disabled_reason IN ('not found in directory', 'disabled in directory', "
        "'removed from VPN groups', 'not in any VPN group') THEN 'directory' "
        "ELSE 'admin' END WHERE status = 'disabled'"
    ))
    conn.execute(text(
        "UPDATE users SET disabled_reason = CASE "
        "WHEN disabled_reason LIKE 'no sign-in for %' THEN 'attestation_expired' "
        "WHEN disabled_reason LIKE 'disabled by %' THEN 'admin' "
        "WHEN disabled_reason = 'not found in directory' THEN 'directory_missing' "
        "WHEN disabled_reason = 'disabled in directory' THEN 'directory_disabled' "
        "WHEN disabled_reason IN ('removed from VPN groups', 'not in any VPN group') THEN 'no_vpn_group' "
        "ELSE disabled_reason END WHERE status = 'disabled'"
    ))


def _ensure_default_profile(conn) -> None:
    if conn.execute(text("SELECT COUNT(*) FROM access_profiles")).scalar():
        return
    stamp = iso(now())
    conn.execute(
        text(
            "INSERT INTO access_profiles (id, name, description, tunnel_mode, max_devices, "
            "device_ttl_days, is_default, created_at, updated_at) VALUES (:id, :n, :d, 'full', 3, 0, 1, :t, :t)"
        ),
        {"id": uuid.uuid4().hex, "n": "Default", "d": "Default full tunnel access profile", "t": stamp},
    )


def reset_schema_cache() -> None:
    """Tests repoint CORPVPN_DB_PATH; forget which paths were initialised."""
    _ready.clear()


def _user(row) -> dict[str, Any]:
    user = dict(row)
    user["groups"] = json.loads(user.pop("groups_json") or "[]")
    return user


# --------------------------------------------------------------------------- users
def get_user(user_id: str) -> Optional[dict[str, Any]]:
    with _engine().connect() as conn:
        row = conn.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id}).mappings().first()
    return _user(row) if row else None


def find_user(provider: str, external_id: str) -> Optional[dict[str, Any]]:
    with _engine().connect() as conn:
        row = conn.execute(
            text("SELECT * FROM users WHERE provider = :p AND external_id = :e"),
            {"p": provider, "e": external_id},
        ).mappings().first()
    return _user(row) if row else None


def list_users(provider: Optional[str] = None, status: Optional[str] = None) -> list[dict[str, Any]]:
    clauses, params = [], {}
    if provider:
        clauses.append("provider = :p")
        params["p"] = provider
    if status:
        clauses.append("status = :s")
        params["s"] = status
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with _engine().connect() as conn:
        rows = conn.execute(text(f"SELECT * FROM users {where} ORDER BY username"), params).mappings().all()
    return [_user(r) for r in rows]


def upsert_user(
    *,
    provider: str,
    external_id: str,
    username: str,
    email: str,
    display_name: str,
    role: str,
    groups: list[str],
    directory_dn: str = "",
    login: bool = True,
    access_profile_id: str = "",
) -> dict[str, Any]:
    """Create the user, or refresh a known one from its identity provider.

    The status is left alone: whether a disabled user may come back is decided by
    the caller (identity.admit), never by the mere fact that they signed in.
    """
    if provider not in PROVIDERS:
        raise StoreError(f"unknown provider {provider!r}")
    if role not in ROLE_RANK:
        raise StoreError(f"unknown role {role!r}")
    stamp = iso(now())
    values = {
        "provider": provider,
        "external_id": external_id,
        "username": username,
        "email": email or "",
        "display_name": display_name or "",
        "role": role,
        "groups_json": json.dumps(sorted(set(groups)), ensure_ascii=False),
        "directory_dn": directory_dn or "",
        "profile": access_profile_id or "",
        "now": stamp,
        "last_login": stamp if login else "",
    }
    existing = find_user(provider, external_id)
    if existing is None:
        values["id"] = uuid.uuid4().hex
        try:
            with _engine().begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO users (id, provider, external_id, username, email, display_name, "
                        "role, status, groups_json, directory_dn, access_profile_id, created_at, "
                        "updated_at, last_login_at) "
                        "VALUES (:id, :provider, :external_id, :username, :email, :display_name, "
                        ":role, 'active', :groups_json, :directory_dn, :profile, :now, :now, :last_login)"
                    ),
                    values,
                )
            return find_user(provider, external_id)
        except Exception as exc:
            if not _unique_violation(exc):
                raise
            # A concurrent first sign-in (or device adoption) created the row.
            existing = find_user(provider, external_id)
    if not login:
        values["last_login"] = existing.get("last_login_at", "")
    with _engine().begin() as conn:
        conn.execute(
            text(
                "UPDATE users SET username = :username, email = :email, "
                "display_name = :display_name, role = :role, "
                "groups_json = :groups_json, directory_dn = :directory_dn, "
                "access_profile_id = :profile, directory_missing_since = '', "
                "updated_at = :now, last_login_at = :last_login "
                "WHERE provider = :provider AND external_id = :external_id"
            ),
            values,
        )
    return find_user(provider, external_id)


def update_user_directory(
    user_id: str, *, role: str, groups: list[str], access_profile_id: str = "", directory_dn: str = ""
) -> None:
    """directory_sync: refresh role, groups, profile and DN without counting as a
    login. The directory found the user, so a pending "not found" mark goes."""
    with _engine().begin() as conn:
        conn.execute(
            text(
                "UPDATE users SET role = :r, groups_json = :g, access_profile_id = :p, "
                "directory_dn = CASE WHEN :dn = '' THEN directory_dn ELSE :dn END, "
                "directory_missing_since = '', updated_at = :now WHERE id = :id"
            ),
            {
                "r": role,
                "g": json.dumps(sorted(set(groups)), ensure_ascii=False),
                "p": access_profile_id or "",
                "dn": directory_dn or "",
                "now": iso(now()),
                "id": user_id,
            },
        )


def set_directory_missing(user_id: str, since: str) -> None:
    """Mark ("" clears) that directory_sync did not find the user."""
    with _engine().begin() as conn:
        conn.execute(text("UPDATE users SET directory_missing_since = :s WHERE id = :id"),
                     {"s": since, "id": user_id})


def set_attestation_warned(user_id: str, moment: str) -> None:
    with _engine().begin() as conn:
        conn.execute(text("UPDATE users SET attestation_warned_at = :t WHERE id = :id"),
                     {"t": moment, "id": user_id})


def set_user_status(user_id: str, status: str, reason: str = "", source: str = "admin") -> None:
    """Disable (with a reason code and who decided it, see DISABLE_SOURCES) or enable."""
    if status not in ("active", "disabled"):
        raise StoreError(f"unknown status {status!r}")
    if status == "disabled" and source not in DISABLE_SOURCES:
        raise StoreError(f"unknown disable source {source!r}")
    disabled = status == "disabled"
    with _engine().begin() as conn:
        conn.execute(
            text(
                "UPDATE users SET status = :s, disabled_reason = :r, disabled_source = :src, "
                "updated_at = :now WHERE id = :id"
            ),
            {"s": status, "r": reason if disabled else "", "src": source if disabled else "",
             "now": iso(now()), "id": user_id},
        )


# ------------------------------------------------------------------------ sessions
def insert_session(values: dict[str, Any]) -> None:
    with _engine().begin() as conn:
        conn.execute(
            text(
                "INSERT INTO sessions (id_hash, user_id, provider, csrf, created_at, expires_at, "
                "last_seen_at, ip, user_agent) VALUES (:id_hash, :user_id, :provider, :csrf, "
                ":created_at, :expires_at, :last_seen_at, :ip, :user_agent)"
            ),
            values,
        )


def get_session(id_hash: str) -> Optional[dict[str, Any]]:
    with _engine().connect() as conn:
        row = conn.execute(text("SELECT * FROM sessions WHERE id_hash = :h"), {"h": id_hash}).mappings().first()
    return dict(row) if row else None


def touch_session(id_hash: str, moment: datetime) -> None:
    with _engine().begin() as conn:
        conn.execute(text("UPDATE sessions SET last_seen_at = :t WHERE id_hash = :h"), {"t": iso(moment), "h": id_hash})


def delete_session(id_hash: str) -> None:
    with _engine().begin() as conn:
        conn.execute(text("DELETE FROM sessions WHERE id_hash = :h"), {"h": id_hash})


def delete_user_sessions(user_id: str) -> int:
    with _engine().begin() as conn:
        result = conn.execute(text("DELETE FROM sessions WHERE user_id = :u"), {"u": user_id})
    return result.rowcount or 0


def count_sessions_by_user() -> dict[str, int]:
    with _engine().connect() as conn:
        rows = conn.execute(text("SELECT user_id, COUNT(*) AS n FROM sessions GROUP BY user_id")).all()
    return {row[0]: int(row[1]) for row in rows}


def purge_expired_sessions(moment: datetime) -> int:
    with _engine().begin() as conn:
        result = conn.execute(text("DELETE FROM sessions WHERE expires_at < :t"), {"t": iso(moment)})
    return result.rowcount or 0


# --------------------------------------------------------------------- OIDC state
# Pending sign-ins per client IP: /auth/oidc/start needs no credentials, so an
# anonymous loop must not grow the table beyond this.
OIDC_STATES_PER_IP = 20


def put_oidc_state(state: str, nonce: str, code_verifier: str, binding_hash: str = "", ip: str = "") -> None:
    with _engine().begin() as conn:
        conn.execute(
            text("DELETE FROM oidc_states WHERE created_at < :cutoff"),
            {"cutoff": iso(now() - timedelta(minutes=10))},
        )
        if ip:
            pending = conn.execute(
                text("SELECT state FROM oidc_states WHERE ip = :ip ORDER BY created_at DESC, state"), {"ip": ip}
            ).scalars().all()
            for old in pending[OIDC_STATES_PER_IP - 1:]:
                conn.execute(text("DELETE FROM oidc_states WHERE state = :s"), {"s": old})
        conn.execute(
            text(
                "INSERT INTO oidc_states (state, nonce, code_verifier, created_at, binding_hash, ip) "
                "VALUES (:s, :n, :v, :t, :b, :ip)"
            ),
            {"s": state, "n": nonce, "v": code_verifier, "t": iso(now()), "b": binding_hash, "ip": ip},
        )


def pop_oidc_state(state: str) -> Optional[dict[str, Any]]:
    """Single use: the row is deleted in the same transaction that reads it."""
    with _engine().begin() as conn:
        row = conn.execute(text("SELECT * FROM oidc_states WHERE state = :s"), {"s": state}).mappings().first()
        if row is None:
            return None
        conn.execute(text("DELETE FROM oidc_states WHERE state = :s"), {"s": state})
    record = dict(row)
    created = parse_iso(record["created_at"])
    if created is None or now() - created > timedelta(minutes=10):
        return None
    return record


# ---------------------------------------------------------------- group policies
def list_policies() -> list[dict[str, Any]]:
    with _engine().connect() as conn:
        rows = conn.execute(text("SELECT * FROM group_policies ORDER BY priority, group_name")).mappings().all()
    return [dict(r) for r in rows]


def _validate_policy(provider: str, group_name: str, role: str, priority: int) -> tuple[str, str, str, int]:
    provider = (provider or "any").strip().lower()
    group_name = (group_name or "").strip()
    role = (role or "").strip().lower()
    if provider not in POLICY_PROVIDERS:
        raise StoreError("provider must be one of: " + ", ".join(POLICY_PROVIDERS))
    if not group_name:
        raise StoreError("group_name must not be empty")
    if role not in ROLE_RANK:
        raise StoreError("role must be one of: " + ", ".join(ROLES))
    if not isinstance(priority, int) or priority < 0:
        raise StoreError("priority must be a non-negative integer")
    return provider, group_name, role, priority


def _validate_profile_ref(access_profile_id: str) -> str:
    access_profile_id = (access_profile_id or "").strip()
    if access_profile_id and get_profile(access_profile_id) is None:
        raise StoreError("unknown access profile")
    return access_profile_id


def create_policy(
    provider: str, group_name: str, role: str, priority: int = 100, access_profile_id: str = ""
) -> dict[str, Any]:
    provider, group_name, role, priority = _validate_policy(provider, group_name, role, priority)
    access_profile_id = _validate_profile_ref(access_profile_id)
    policy_id = uuid.uuid4().hex
    try:
        with _engine().begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO group_policies (id, provider, group_name, role, priority, access_profile_id, "
                    "created_at) VALUES (:id, :p, :g, :r, :pr, :ap, :t)"
                ),
                {"id": policy_id, "p": provider, "g": group_name, "r": role, "pr": priority,
                 "ap": access_profile_id, "t": iso(now())},
            )
    except Exception as exc:  # unique violation (dialect-specific class)
        if "UNIQUE" in str(exc).upper() or "DUPLICATE" in str(exc).upper():
            raise StoreError("a policy for this provider and group already exists") from exc
        raise
    return get_policy(policy_id)


def get_policy(policy_id: str) -> Optional[dict[str, Any]]:
    with _engine().connect() as conn:
        row = conn.execute(text("SELECT * FROM group_policies WHERE id = :id"), {"id": policy_id}).mappings().first()
    return dict(row) if row else None


def update_policy(
    policy_id: str, provider: str, group_name: str, role: str, priority: int, access_profile_id: str = ""
) -> Optional[dict[str, Any]]:
    provider, group_name, role, priority = _validate_policy(provider, group_name, role, priority)
    access_profile_id = _validate_profile_ref(access_profile_id)
    with _engine().begin() as conn:
        result = conn.execute(
            text(
                "UPDATE group_policies SET provider = :p, group_name = :g, role = :r, priority = :pr, "
                "access_profile_id = :ap WHERE id = :id"
            ),
            {"p": provider, "g": group_name, "r": role, "pr": priority, "ap": access_profile_id, "id": policy_id},
        )
    return get_policy(policy_id) if result.rowcount else None


def delete_policy(policy_id: str) -> bool:
    with _engine().begin() as conn:
        result = conn.execute(text("DELETE FROM group_policies WHERE id = :id"), {"id": policy_id})
    return bool(result.rowcount)


def seed_policies_from_config() -> int:
    """Create policies from AUTH_*_GROUPS only while the table is empty."""
    if list_policies():
        return 0
    created = 0
    for role, raw, priority in (
        ("admin", config.AUTH_ADMIN_GROUPS, 10),
        ("operator", config.AUTH_OPERATOR_GROUPS, 20),
        ("user", config.AUTH_USER_GROUPS, 30),
    ):
        for group in (g.strip() for g in raw.split(",")):
            if group:
                create_policy("any", group, role, priority)
                created += 1
    return created


# ----------------------------------------------------------------------- audit
_syslog_logger: Optional[logging.Logger] = None
_syslog_address = ""


def _syslog() -> Optional[logging.Logger]:
    """Logger shipping audit events to AUDIT_SYSLOG_ADDRESS, or None."""
    global _syslog_logger, _syslog_address
    address = config.AUDIT_SYSLOG_ADDRESS
    if not address:
        return None
    if _syslog_logger is not None and address == _syslog_address:
        return _syslog_logger
    if address.startswith("/"):
        target = address
    else:
        host, _, port = address.rpartition(":")
        target = (host or address, int(port) if port.isdigit() else 514)
    handler = logging.handlers.SysLogHandler(
        address=target, facility=logging.handlers.SysLogHandler.LOG_AUTHPRIV
    )
    handler.setFormatter(logging.Formatter("corpvpn-audit: %(message)s"))
    audit_logger = logging.getLogger("corpvpn.audit.syslog")
    audit_logger.handlers = [handler]
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False
    _syslog_logger, _syslog_address = audit_logger, address
    return audit_logger


def audit(action: str, *, actor: str, target: str = "", details: Optional[dict] = None, ip: str = "") -> None:
    with _engine().begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_log (id, ts, actor, action, target, details_json, ip) "
                "VALUES (:id, :ts, :a, :ac, :t, :d, :ip)"
            ),
            {
                "id": uuid.uuid4().hex,
                "ts": iso(now()),
                "a": actor or "",
                "ac": action,
                "t": target or "",
                "d": json.dumps(details or {}, ensure_ascii=False, default=str),
                "ip": ip or "",
            },
        )
    try:
        sink = _syslog()
        if sink is not None:
            sink.info(json.dumps(
                {"action": action, "actor": actor, "target": target, "ip": ip, "details": details or {}},
                ensure_ascii=False, default=str,
            ))
    except Exception:  # the database copy is authoritative; never fail the request
        logging.getLogger(__name__).exception("audit syslog delivery failed")


def list_audit(limit: int = 200, action_prefix: str = "") -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 1000))
    params: dict[str, Any] = {"lim": limit}
    where = ""
    if action_prefix:
        where = "WHERE action LIKE :prefix"
        params["prefix"] = f"{action_prefix}%"
    with _engine().connect() as conn:
        rows = conn.execute(
            text(f"SELECT * FROM audit_log {where} ORDER BY ts DESC, id DESC LIMIT :lim"), params
        ).mappings().all()
    out = []
    for row in rows:
        item = dict(row)
        item["details"] = json.loads(item.pop("details_json") or "{}")
        out.append(item)
    return out


# ------------------------------------------------------------ access profiles
def _profile(row) -> dict[str, Any]:
    item = dict(row)
    for key in ("allowed_cidrs", "dns_servers", "search_domains", "protocols"):
        item[key] = json.loads(item.pop(f"{key}_json") or "[]")
    item["is_default"] = bool(item["is_default"])
    return item


def list_profiles() -> list[dict[str, Any]]:
    with _engine().connect() as conn:
        rows = conn.execute(text("SELECT * FROM access_profiles ORDER BY is_default DESC, name")).mappings().all()
    return [_profile(r) for r in rows]


def get_profile(profile_id: str) -> Optional[dict[str, Any]]:
    if not profile_id:
        return None
    with _engine().connect() as conn:
        row = conn.execute(text("SELECT * FROM access_profiles WHERE id = :id"), {"id": profile_id}).mappings().first()
    return _profile(row) if row else None


def default_profile() -> dict[str, Any]:
    with _engine().connect() as conn:
        row = conn.execute(
            text("SELECT * FROM access_profiles ORDER BY is_default DESC, created_at LIMIT 1")
        ).mappings().first()
    return _profile(row)


def _profile_values(data: dict[str, Any]) -> dict[str, Any]:
    name = str(data.get("name", "")).strip()
    if not name:
        raise StoreError("profile name must not be empty")
    mode = str(data.get("tunnel_mode", "full")).strip().lower()
    if mode not in TUNNEL_MODES:
        raise StoreError("tunnel_mode must be full or split")
    protocols = [p for p in data.get("protocols", list(DEVICE_PROTOCOLS)) if p]
    if not protocols or any(p not in DEVICE_PROTOCOLS for p in protocols):
        raise StoreError("protocols must be a non-empty subset of: " + ", ".join(DEVICE_PROTOCOLS))
    max_devices = int(data.get("max_devices", 3))
    ttl = int(data.get("device_ttl_days", 0))
    if max_devices < 1 or ttl < 0:
        raise StoreError("max_devices must be >= 1 and device_ttl_days >= 0")
    import ipaddress

    cidrs = []
    for raw in data.get("allowed_cidrs", []):
        raw = str(raw).strip()
        if not raw:
            continue
        try:
            cidrs.append(str(ipaddress.ip_network(raw, strict=False)))
        except ValueError as exc:
            raise StoreError(f"invalid CIDR: {raw}") from exc
    if mode == "split" and not cidrs:
        raise StoreError("split tunnel needs at least one allowed CIDR")
    dns = []
    for raw in data.get("dns_servers", []):
        raw = str(raw).strip()
        if not raw:
            continue
        try:
            dns.append(str(ipaddress.ip_address(raw)))
        except ValueError as exc:
            raise StoreError(f"invalid DNS server: {raw}") from exc
    domains = [str(d).strip().lower() for d in data.get("search_domains", []) if str(d).strip()]
    return {
        "name": name,
        "description": str(data.get("description", "")).strip(),
        "tunnel_mode": mode,
        "allowed_cidrs_json": json.dumps(cidrs),
        "dns_servers_json": json.dumps(dns),
        "search_domains_json": json.dumps(domains),
        "protocols_json": json.dumps(sorted(set(protocols), key=DEVICE_PROTOCOLS.index)),
        "max_devices": max_devices,
        "device_ttl_days": ttl,
    }


def _unique_violation(exc: Exception) -> bool:
    return "UNIQUE" in str(exc).upper() or "DUPLICATE" in str(exc).upper()


def create_profile(data: dict[str, Any]) -> dict[str, Any]:
    values = _profile_values(data)
    values.update({"id": uuid.uuid4().hex, "t": iso(now())})
    try:
        with _engine().begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO access_profiles (id, name, description, tunnel_mode, allowed_cidrs_json, "
                    "dns_servers_json, search_domains_json, protocols_json, max_devices, device_ttl_days, "
                    "is_default, created_at, updated_at) VALUES (:id, :name, :description, :tunnel_mode, "
                    ":allowed_cidrs_json, :dns_servers_json, :search_domains_json, :protocols_json, "
                    ":max_devices, :device_ttl_days, 0, :t, :t)"
                ),
                values,
            )
    except Exception as exc:
        if _unique_violation(exc):
            raise StoreError("a profile with this name already exists") from exc
        raise
    return get_profile(values["id"])


def update_profile(profile_id: str, data: dict[str, Any]) -> Optional[dict[str, Any]]:
    values = _profile_values(data)
    values.update({"id": profile_id, "t": iso(now())})
    try:
        with _engine().begin() as conn:
            result = conn.execute(
                text(
                    "UPDATE access_profiles SET name = :name, description = :description, "
                    "tunnel_mode = :tunnel_mode, allowed_cidrs_json = :allowed_cidrs_json, "
                    "dns_servers_json = :dns_servers_json, search_domains_json = :search_domains_json, "
                    "protocols_json = :protocols_json, max_devices = :max_devices, "
                    "device_ttl_days = :device_ttl_days, updated_at = :t WHERE id = :id"
                ),
                values,
            )
    except Exception as exc:
        if _unique_violation(exc):
            raise StoreError("a profile with this name already exists") from exc
        raise
    return get_profile(profile_id) if result.rowcount else None


def set_default_profile(profile_id: str) -> None:
    if get_profile(profile_id) is None:
        raise StoreError("unknown access profile")
    with _engine().begin() as conn:
        conn.execute(text("UPDATE access_profiles SET is_default = 0"))
        conn.execute(text("UPDATE access_profiles SET is_default = 1 WHERE id = :id"), {"id": profile_id})


def delete_profile(profile_id: str) -> bool:
    profile = get_profile(profile_id)
    if profile is None:
        return False
    if profile["is_default"]:
        raise StoreError("the default profile cannot be deleted")
    with _engine().connect() as conn:
        used = conn.execute(
            text("SELECT (SELECT COUNT(*) FROM group_policies WHERE access_profile_id = :id) + "
                 "(SELECT COUNT(*) FROM users WHERE access_profile_id = :id)"),
            {"id": profile_id},
        ).scalar()
    if used:
        raise StoreError("the profile is used by group policies or users")
    with _engine().begin() as conn:
        conn.execute(text("DELETE FROM access_profiles WHERE id = :id"), {"id": profile_id})
    return True


# -------------------------------------------------------------------- devices
def insert_device(values: dict[str, Any]) -> dict[str, Any]:
    stamp = iso(now())
    row = {
        "id": uuid.uuid4().hex,
        "suspend_reason": "",
        "created_by": "",
        "expires_at": "",
        "created_at": stamp,
        "updated_at": stamp,
        **values,
    }
    with _engine().begin() as conn:
        conn.execute(
            text(
                "INSERT INTO devices (id, user_id, name, protocol, ref, status, suspend_reason, created_by, "
                "created_at, updated_at, expires_at) VALUES (:id, :user_id, :name, :protocol, :ref, :status, "
                ":suspend_reason, :created_by, :created_at, :updated_at, :expires_at)"
            ),
            row,
        )
    return get_device(row["id"])


def get_device(device_id: str) -> Optional[dict[str, Any]]:
    with _engine().connect() as conn:
        row = conn.execute(text("SELECT * FROM devices WHERE id = :id"), {"id": device_id}).mappings().first()
    return dict(row) if row else None


def list_devices(user_id: Optional[str] = None, include_revoked: bool = False) -> list[dict[str, Any]]:
    clauses, params = [], {}
    if user_id:
        clauses.append("user_id = :u")
        params["u"] = user_id
    if not include_revoked:
        clauses.append("status <> 'revoked'")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with _engine().connect() as conn:
        rows = conn.execute(text(f"SELECT * FROM devices {where} ORDER BY created_at"), params).mappings().all()
    return [dict(r) for r in rows]


def delete_device(device_id: str) -> None:
    """Only for a device whose backend credential was never created."""
    with _engine().begin() as conn:
        conn.execute(text("DELETE FROM devices WHERE id = :id"), {"id": device_id})


def update_device(device_id: str, **fields: Any) -> None:
    allowed = {"status", "suspend_reason", "user_id", "name", "expires_at"}
    if not fields or set(fields) - allowed:
        raise StoreError("invalid device fields")
    assignments = ", ".join(f"{k} = :{k}" for k in fields)
    with _engine().begin() as conn:
        conn.execute(
            text(f"UPDATE devices SET {assignments}, updated_at = :now WHERE id = :id"),
            {**fields, "now": iso(now()), "id": device_id},
        )


# ------------------------------------------------------------------ API tokens
def insert_api_token(values: dict[str, Any]) -> dict[str, Any]:
    row = {"id": uuid.uuid4().hex, "created_at": iso(now()), "expires_at": "", **values}
    with _engine().begin() as conn:
        conn.execute(
            text(
                "INSERT INTO api_tokens (id, name, token_hash, role, created_by, created_at, expires_at) "
                "VALUES (:id, :name, :token_hash, :role, :created_by, :created_at, :expires_at)"
            ),
            row,
        )
    return get_api_token(row["id"])


def get_api_token(token_id: str) -> Optional[dict[str, Any]]:
    with _engine().connect() as conn:
        row = conn.execute(text("SELECT * FROM api_tokens WHERE id = :id"), {"id": token_id}).mappings().first()
    return dict(row) if row else None


def find_api_token(token_hash: str) -> Optional[dict[str, Any]]:
    with _engine().connect() as conn:
        row = conn.execute(
            text("SELECT * FROM api_tokens WHERE token_hash = :h AND revoked = 0"), {"h": token_hash}
        ).mappings().first()
    return dict(row) if row else None


def list_api_tokens() -> list[dict[str, Any]]:
    with _engine().connect() as conn:
        rows = conn.execute(text("SELECT * FROM api_tokens ORDER BY created_at DESC")).mappings().all()
    out = []
    for row in rows:
        item = dict(row)
        item.pop("token_hash", None)
        item["revoked"] = bool(item["revoked"])
        out.append(item)
    return out


def touch_api_token(token_id: str) -> None:
    with _engine().begin() as conn:
        conn.execute(text("UPDATE api_tokens SET last_used_at = :t WHERE id = :id"), {"t": iso(now()), "id": token_id})


def revoke_api_token(token_id: str) -> bool:
    with _engine().begin() as conn:
        result = conn.execute(text("UPDATE api_tokens SET revoked = 1 WHERE id = :id AND revoked = 0"), {"id": token_id})
    return bool(result.rowcount)


def audit_page(limit=1000, from_ts="", to_ts="", cursor=""):
    """Stable keyset pagination; duplicate timestamps cannot lose events."""
    import base64
    params = {"limit": max(1, min(int(limit), 1000))}
    conditions = []
    for name, value, op in (("start", from_ts, ">="), ("end", to_ts, "<=")):
        if value:
            parse_iso(value)
            conditions.append("ts " + op + " :" + name)
            params[name] = value
    if cursor:
        stamp, event_id = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
        parse_iso(stamp)
        conditions.append("(ts < :stamp OR (ts = :stamp AND id < :event_id))")
        params.update(stamp=stamp, event_id=event_id)
    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    with _engine().connect() as conn:
        rows = conn.execute(text("SELECT * FROM audit_log " + where + " ORDER BY ts DESC,id DESC LIMIT :limit"), params).mappings().all()
    items = []
    for row in rows:
        item = dict(row)
        item["details"] = json.loads(item.pop("details_json"))
        items.append(item)
    next_cursor = base64.urlsafe_b64encode(json.dumps([items[-1]["ts"], items[-1]["id"]]).encode()).decode().rstrip("=") if len(items) == params["limit"] else ""
    return items, next_cursor


def prune_audit():
    if config.AUDIT_RETENTION_DAYS <= 0:
        return 0
    before = iso(now() - timedelta(days=config.AUDIT_RETENTION_DAYS))
    with _engine().begin() as conn:
        return conn.execute(text("DELETE FROM audit_log WHERE ts<:before"), {"before": before}).rowcount
