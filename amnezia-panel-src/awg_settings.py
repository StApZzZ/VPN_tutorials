from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import config


class AwgSettingsError(RuntimeError):
    """Base error for AmneziaWG settings."""


class AwgSettingsNotConfigured(AwgSettingsError):
    """Raised when the shared AWG settings file is missing."""


class AwgSettingsValidationError(AwgSettingsError):
    """Raised when the shared AWG settings file is invalid."""


INTERFACE_INT_KEYS = ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4")
INTERFACE_TEXT_KEYS = ("I1", "I2", "I3", "I4", "I5")


def settings_path() -> Path:
    return Path(config.AWG_SETTINGS_PATH)


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


def load_settings() -> dict[str, Any]:
    path = settings_path()
    if not path.exists():
        raise AwgSettingsNotConfigured(f"AWG settings file is missing: {path}")

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise AwgSettingsValidationError(f"Cannot read AWG settings file: {path}") from exc

    if not isinstance(payload, dict):
        raise AwgSettingsValidationError("AWG settings file must be a JSON object")

    endpoint_host = str(payload.get("endpoint_host") or "").strip()
    if not endpoint_host:
        raise AwgSettingsValidationError("endpoint_host is required")

    endpoint_port = payload.get("endpoint_port")
    if not isinstance(endpoint_port, int) or endpoint_port < 1 or endpoint_port > 65535:
        raise AwgSettingsValidationError("endpoint_port must be an integer between 1 and 65535")

    dns_servers = str(payload.get("dns_servers") or config.DNS_SERVERS).strip()
    if not dns_servers:
        raise AwgSettingsValidationError("dns_servers must not be empty")

    result: dict[str, Any] = {
        "endpoint_host": endpoint_host,
        "endpoint_port": endpoint_port,
        "dns_servers": dns_servers,
        "persistent_keepalive": payload.get("persistent_keepalive", 25),
    }
    result["persistent_keepalive"] = _validate_non_negative_int(
        "persistent_keepalive",
        result["persistent_keepalive"],
    )

    for key in INTERFACE_INT_KEYS:
        result[key] = _validate_non_negative_int(key, payload.get(key, 0))
    for key in INTERFACE_TEXT_KEYS:
        result[key] = _validate_optional_text(key, payload.get(key, ""))

    return result
