from __future__ import annotations

import json
from typing import Any

import config
import db
from sqlalchemy import text

# ---------------------------------------------------------------------------
# Errors (unchanged public interface)
# ---------------------------------------------------------------------------

class AwgSettingsError(RuntimeError):
    """Base error for AmneziaWG settings."""


class AwgSettingsNotConfigured(AwgSettingsError):
    """Raised when AWG settings have not been saved yet."""


class AwgSettingsValidationError(AwgSettingsError):
    """Raised when AWG settings contain invalid values."""


# ---------------------------------------------------------------------------
# Constants (unchanged)
# ---------------------------------------------------------------------------

INTERFACE_INT_KEYS = ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4")
INTERFACE_TEXT_KEYS = ("I1", "I2", "I3", "I4", "I5")

_DDL = """
CREATE TABLE IF NOT EXISTS awg_settings (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    endpoint_host         TEXT NOT NULL DEFAULT '',
    endpoint_port         INTEGER NOT NULL DEFAULT 0,
    dns_servers           TEXT NOT NULL DEFAULT '',
    persistent_keepalive  INTEGER NOT NULL DEFAULT 25,
    Jc   INTEGER NOT NULL DEFAULT 0,
    Jmin INTEGER NOT NULL DEFAULT 0,
    Jmax INTEGER NOT NULL DEFAULT 0,
    S1   INTEGER NOT NULL DEFAULT 0,
    S2   INTEGER NOT NULL DEFAULT 0,
    S3   INTEGER NOT NULL DEFAULT 0,
    S4   INTEGER NOT NULL DEFAULT 0,
    H1   INTEGER NOT NULL DEFAULT 0,
    H2   INTEGER NOT NULL DEFAULT 0,
    H3   INTEGER NOT NULL DEFAULT 0,
    H4   INTEGER NOT NULL DEFAULT 0,
    I1   TEXT NOT NULL DEFAULT '',
    I2   TEXT NOT NULL DEFAULT '',
    I3   TEXT NOT NULL DEFAULT '',
    I4   TEXT NOT NULL DEFAULT '',
    I5   TEXT NOT NULL DEFAULT ''
)
"""

def _engine():
    # Resolved per call so config.AWG_DB_PATH can be repointed (tests).
    return db.get_engine(config.AWG_DB_PATH, _DDL)

# ---------------------------------------------------------------------------
# Validation helpers (unchanged from original)
# ---------------------------------------------------------------------------

def _validate_non_negative_int(key: str, value: Any) -> int:
    if not isinstance(value, int) or value < 0:
        raise AwgSettingsValidationError(f"{key} must be a non-negative integer")
    return value


def _validate_optional_text(key: str, value: Any) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise AwgSettingsValidationError(f"{key} must be a string")
    return value.strip()


# ---------------------------------------------------------------------------
# Public API (identical signatures to original)
# ---------------------------------------------------------------------------

def load_settings() -> dict[str, Any]:
    """Load AWG settings from SQLite. Raises AwgSettingsNotConfigured if not set."""
    with _engine().connect() as conn:
        row = conn.execute(text("SELECT * FROM awg_settings WHERE id = 1")).mappings().first()

    if row is None:
        raise AwgSettingsNotConfigured("AWG settings have not been configured yet")

    endpoint_host = str(row["endpoint_host"] or "").strip()
    if not endpoint_host:
        raise AwgSettingsNotConfigured("AWG settings have not been configured yet")

    endpoint_port = row["endpoint_port"]
    if not isinstance(endpoint_port, int) or endpoint_port < 1 or endpoint_port > 65535:
        raise AwgSettingsValidationError("endpoint_port must be an integer between 1 and 65535")

    dns_servers = str(row["dns_servers"] or config.DNS_SERVERS).strip()
    if not dns_servers:
        raise AwgSettingsValidationError("dns_servers must not be empty")

    result: dict[str, Any] = {
        "endpoint_host": endpoint_host,
        "endpoint_port": endpoint_port,
        "dns_servers": dns_servers,
        "persistent_keepalive": row["persistent_keepalive"],
    }
    result["persistent_keepalive"] = _validate_non_negative_int(
        "persistent_keepalive", result["persistent_keepalive"]
    )

    for key in INTERFACE_INT_KEYS:
        result[key] = _validate_non_negative_int(key, row[key])
    for key in INTERFACE_TEXT_KEYS:
        result[key] = _validate_optional_text(key, row[key])

    return result


def save_settings(payload: dict[str, Any]) -> None:
    """Persist AWG settings to SQLite (upsert on id=1)."""
    cols = (
        "endpoint_host", "endpoint_port", "dns_servers", "persistent_keepalive",
        *INTERFACE_INT_KEYS, *INTERFACE_TEXT_KEYS,
    )
    values = {col: payload.get(col, 0 if col in INTERFACE_INT_KEYS else "") for col in cols}
    values["id"] = 1

    col_list = ", ".join(["id"] + list(cols))
    placeholder_list = ", ".join([f":{c}" for c in ["id"] + list(cols)])
    update_list = ", ".join([f"{c} = :{c}" for c in cols])

    stmt = (
        f"INSERT INTO awg_settings ({col_list}) VALUES ({placeholder_list}) "
        f"ON CONFLICT(id) DO UPDATE SET {update_list}"
    )
    with _engine().begin() as conn:
        conn.execute(text(stmt), values)


def is_configured() -> bool:
    try:
        load_settings()
    except AwgSettingsNotConfigured:
        return False
    return True


def seed_from_json(path: str, force: bool = False) -> bool:
    """Import settings from an Ansible-rendered JSON file into awg.db.

    Only when awg.db is not configured yet (or force=True): the live settings are
    edited in the panel afterwards, and obfuscation params must never change under
    distributed clients just because a deploy re-ran. Returns True when written.
    """
    if not force and is_configured():
        return False
    with open(path, encoding="utf-8") as fh:
        payload = json.load(fh)
    if not str(payload.get("endpoint_host") or "").strip():
        raise AwgSettingsValidationError("endpoint_host must be set in " + path)
    for key in ("endpoint_port", "persistent_keepalive", *INTERFACE_INT_KEYS):
        if key in payload:
            payload[key] = int(payload[key])
    save_settings(payload)
    load_settings()  # validate what was written
    return True


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Seed awg.db from a JSON settings file.")
    parser.add_argument("--seed-from-json", required=True, metavar="PATH")
    parser.add_argument("--force", action="store_true", help="overwrite existing settings")
    args = parser.parse_args()
    written = seed_from_json(args.seed_from_json, force=args.force)
    print("seeded" if written else "already configured")
