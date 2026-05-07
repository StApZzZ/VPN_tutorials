import json
import os
import re
import tempfile
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlencode
from uuid import uuid4

import config
from models import XrayClientProfile, XrayClientSettingsStatus, XrayClientShare

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9_.@+-]+$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


class XrayClientError(RuntimeError):
    pass


class XrayClientValidationError(XrayClientError):
    pass


class XrayClientNotFound(XrayClientError):
    pass


class XrayClientConflict(XrayClientError):
    pass


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_write(path: str, content: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=target.parent, prefix=".tmp_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(tmp_path, path)
    except Exception:
        os.unlink(tmp_path)
        raise


def _slug(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value.strip().lower())
    normalized = normalized.strip("-._")
    return normalized or "client"


def _normalize_name(value: str) -> str:
    normalized = (value or "").strip()
    if not normalized:
        raise XrayClientValidationError("Client name is required")
    if len(normalized) > 80:
        raise XrayClientValidationError("Client name is too long")
    return normalized


def _normalize_email(value: str | None, name: str) -> str:
    normalized = (value or "").strip() or f"{_slug(name)}@panel"
    if len(normalized) > 120:
        raise XrayClientValidationError("Client email is too long")
    if not _EMAIL_RE.fullmatch(normalized):
        raise XrayClientValidationError("Client email contains unsupported characters")
    return normalized


def _is_placeholder(value: str | None) -> bool:
    normalized = (value or "").strip()
    if not normalized:
        return True
    lowered = normalized.lower()
    return (
        "replace" in lowered
        or "placeholder" in lowered
        or "new_server_ip" in lowered
    )


def get_settings_status() -> XrayClientSettingsStatus:
    errors: list[str] = []
    warnings: list[str] = []

    if _is_placeholder(config.XRAY_CLIENT_INBOUND_TAG):
        errors.append("XRAY_CLIENT_INBOUND_TAG is not configured")

    if _is_placeholder(config.XRAY_CLIENT_SERVER):
        errors.append("XRAY_CLIENT_SERVER is not configured")

    if config.XRAY_CLIENT_PORT < 1 or config.XRAY_CLIENT_PORT > 65535:
        errors.append("XRAY_CLIENT_PORT must be between 1 and 65535")

    if config.XRAY_CLIENT_LOCAL_SOCKS_PORT < 1 or config.XRAY_CLIENT_LOCAL_SOCKS_PORT > 65535:
        errors.append("XRAY_CLIENT_LOCAL_SOCKS_PORT must be between 1 and 65535")

    if config.XRAY_CLIENT_LOCAL_HTTP_PORT < 1 or config.XRAY_CLIENT_LOCAL_HTTP_PORT > 65535:
        errors.append("XRAY_CLIENT_LOCAL_HTTP_PORT must be between 1 and 65535")

    if config.XRAY_CLIENT_LOCAL_SOCKS_PORT == config.XRAY_CLIENT_LOCAL_HTTP_PORT:
        errors.append("XRAY_CLIENT_LOCAL_SOCKS_PORT and XRAY_CLIENT_LOCAL_HTTP_PORT must be different")

    if config.XRAY_CLIENT_NETWORK != "tcp":
        warnings.append("Only tcp VLESS/REALITY links are covered by the current panel templates")

    if config.XRAY_CLIENT_SECURITY != "reality":
        warnings.append("Current target architecture expects VLESS/REALITY for client ingress")

    if config.XRAY_CLIENT_SECURITY == "reality":
        if _is_placeholder(config.XRAY_CLIENT_REALITY_SERVER_NAME):
            errors.append("XRAY_CLIENT_REALITY_SERVER_NAME is not configured")
        if _is_placeholder(config.XRAY_CLIENT_REALITY_PUBLIC_KEY):
            errors.append("XRAY_CLIENT_REALITY_PUBLIC_KEY is not configured")
        if _is_placeholder(config.XRAY_CLIENT_REALITY_SHORT_ID):
            errors.append("XRAY_CLIENT_REALITY_SHORT_ID is not configured")
        elif not _HEX_RE.fullmatch(config.XRAY_CLIENT_REALITY_SHORT_ID):
            errors.append("XRAY_CLIENT_REALITY_SHORT_ID must be a hex string")
        elif len(config.XRAY_CLIENT_REALITY_SHORT_ID) > 16:
            errors.append("XRAY_CLIENT_REALITY_SHORT_ID must be at most 16 hex chars")
        elif len(config.XRAY_CLIENT_REALITY_SHORT_ID) % 2:
            warnings.append("XRAY_CLIENT_REALITY_SHORT_ID usually uses an even number of hex chars")

    ready = not errors
    return XrayClientSettingsStatus(
        status="ok" if ready else "needs_configuration",
        ready=ready,
        errors=errors,
        warnings=warnings,
        inbound_tag=config.XRAY_CLIENT_INBOUND_TAG,
        server=config.XRAY_CLIENT_SERVER,
        port=config.XRAY_CLIENT_PORT,
        network=config.XRAY_CLIENT_NETWORK,
        security=config.XRAY_CLIENT_SECURITY,
        local_socks_port=config.XRAY_CLIENT_LOCAL_SOCKS_PORT,
        local_http_port=config.XRAY_CLIENT_LOCAL_HTTP_PORT,
        reality_server_name=config.XRAY_CLIENT_REALITY_SERVER_NAME,
        reality_public_key_configured=not _is_placeholder(config.XRAY_CLIENT_REALITY_PUBLIC_KEY),
        reality_short_id_configured=not _is_placeholder(config.XRAY_CLIENT_REALITY_SHORT_ID),
        fingerprint=config.XRAY_CLIENT_FINGERPRINT,
        flow=config.XRAY_CLIENT_FLOW,
    )


def _load_clients() -> list[XrayClientProfile]:
    path = Path(config.XRAY_CLIENTS_PATH)
    if not path.exists():
        return []

    try:
        with path.open(encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception as exc:
        raise XrayClientError(f"Cannot read Xray clients store: {path}") from exc

    if not isinstance(payload, list):
        raise XrayClientError("Xray clients store must be a JSON array")

    try:
        clients = [XrayClientProfile(**item) for item in payload]
    except Exception as exc:
        raise XrayClientError("Xray clients store contains invalid entries") from exc

    return _sort_clients(clients)


def _save_clients(clients: list[XrayClientProfile]) -> None:
    payload = [client.model_dump(mode="json") for client in _sort_clients(clients)]
    _atomic_write(
        config.XRAY_CLIENTS_PATH,
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
    )


def _sort_clients(clients: list[XrayClientProfile]) -> list[XrayClientProfile]:
    return sorted(clients, key=lambda item: (item.created_at, item.id))


def _find_client(clients: list[XrayClientProfile], client_id: str) -> XrayClientProfile:
    for client in clients:
        if client.id == client_id:
            return client
    raise XrayClientNotFound("Xray client not found")


def _ensure_unique_email(
    clients: list[XrayClientProfile],
    email: str,
    exclude_id: str | None = None,
) -> None:
    for client in clients:
        if exclude_id and client.id == exclude_id:
            continue
        if client.email.lower() == email.lower():
            raise XrayClientConflict("Xray client with the same email already exists")


def list_clients() -> list[XrayClientProfile]:
    return _load_clients()


def snapshot_clients() -> list[XrayClientProfile]:
    return [client.model_copy(deep=True) for client in _load_clients()]


def restore_clients(clients: list[XrayClientProfile]) -> None:
    _save_clients([client.model_copy(deep=True) for client in clients])


def create_client(name: str, email: str | None = None) -> XrayClientProfile:
    clients = _load_clients()
    normalized_name = _normalize_name(name)
    normalized_email = _normalize_email(email, normalized_name)
    _ensure_unique_email(clients, normalized_email)

    now = _now_iso()
    client = XrayClientProfile(
        id=str(uuid4()),
        name=normalized_name,
        email=normalized_email,
        enabled=True,
        created_at=now,
        updated_at=now,
    )
    clients.append(client)
    _save_clients(clients)
    return client


def update_client(client_id: str, name: str, email: str | None = None) -> XrayClientProfile:
    clients = _load_clients()
    current = _find_client(clients, client_id)
    normalized_name = _normalize_name(name)
    normalized_email = _normalize_email(email, normalized_name)
    _ensure_unique_email(clients, normalized_email, exclude_id=client_id)

    updated = current.model_copy(
        update={
            "name": normalized_name,
            "email": normalized_email,
            "updated_at": _now_iso(),
        }
    )
    _save_clients([updated if client.id == client_id else client for client in clients])
    return updated


def toggle_client(client_id: str) -> XrayClientProfile:
    clients = _load_clients()
    current = _find_client(clients, client_id)
    updated = current.model_copy(
        update={
            "enabled": not current.enabled,
            "updated_at": _now_iso(),
        }
    )
    _save_clients([updated if client.id == client_id else client for client in clients])
    return updated


def delete_client(client_id: str) -> None:
    clients = _load_clients()
    _find_client(clients, client_id)
    _save_clients([client for client in clients if client.id != client_id])


def get_client(client_id: str) -> XrayClientProfile:
    return _find_client(_load_clients(), client_id)


def _xray_user(client: XrayClientProfile) -> dict:
    user = {
        "id": client.id,
        "email": client.email,
    }
    if config.XRAY_CLIENT_FLOW.strip():
        user["flow"] = config.XRAY_CLIENT_FLOW.strip()
    return user


def render_inbound_clients() -> list[dict]:
    return [_xray_user(client) for client in list_clients() if client.enabled]


def inject_clients_into_config(base_config: dict) -> dict:
    rendered = deepcopy(base_config)
    inbound_tag = config.XRAY_CLIENT_INBOUND_TAG

    for inbound in rendered.get("inbounds", []):
        if inbound.get("tag") != inbound_tag:
            continue
        inbound.setdefault("settings", {})["clients"] = render_inbound_clients()
        return rendered

    raise XrayClientValidationError(f"Xray inbound not found: {inbound_tag}")


def render_share_link(client: XrayClientProfile) -> str:
    params = {
        "encryption": "none",
        "type": config.XRAY_CLIENT_NETWORK,
        "security": config.XRAY_CLIENT_SECURITY,
    }

    if config.XRAY_CLIENT_SECURITY == "reality":
        params.update(
            {
                "sni": config.XRAY_CLIENT_REALITY_SERVER_NAME,
                "fp": config.XRAY_CLIENT_FINGERPRINT,
            }
        )
        if config.XRAY_CLIENT_REALITY_PUBLIC_KEY.strip():
            params["pbk"] = config.XRAY_CLIENT_REALITY_PUBLIC_KEY.strip()
        if config.XRAY_CLIENT_REALITY_SHORT_ID.strip():
            params["sid"] = config.XRAY_CLIENT_REALITY_SHORT_ID.strip()

    if config.XRAY_CLIENT_FLOW.strip():
        params["flow"] = config.XRAY_CLIENT_FLOW.strip()

    query = urlencode(params)
    remark = quote(client.name, safe="")
    return (
        f"vless://{client.id}@{config.XRAY_CLIENT_SERVER}:{config.XRAY_CLIENT_PORT}"
        f"?{query}#{remark}"
    )


def render_outbound_config(client: XrayClientProfile) -> dict:
    user = {
        "id": client.id,
        "encryption": "none",
    }
    if config.XRAY_CLIENT_FLOW.strip():
        user["flow"] = config.XRAY_CLIENT_FLOW.strip()

    stream_settings = {
        "network": config.XRAY_CLIENT_NETWORK,
        "security": config.XRAY_CLIENT_SECURITY,
    }
    if config.XRAY_CLIENT_SECURITY == "reality":
        stream_settings["realitySettings"] = {
            "serverName": config.XRAY_CLIENT_REALITY_SERVER_NAME,
            "fingerprint": config.XRAY_CLIENT_FINGERPRINT,
            "password": config.XRAY_CLIENT_REALITY_PUBLIC_KEY,
            "shortId": config.XRAY_CLIENT_REALITY_SHORT_ID,
        }

    return {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": config.XRAY_CLIENT_SERVER,
                    "port": config.XRAY_CLIENT_PORT,
                    "users": [user],
                }
            ]
        },
        "streamSettings": stream_settings,
    }


def render_client_config(client: XrayClientProfile) -> dict:
    return {
        "remarks": client.name,
        "log": {
            "loglevel": "warning",
        },
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": config.XRAY_CLIENT_LOCAL_SOCKS_PORT,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True,
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                },
            },
            {
                "tag": "http-in",
                "listen": "127.0.0.1",
                "port": config.XRAY_CLIENT_LOCAL_HTTP_PORT,
                "protocol": "http",
                "settings": {},
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"],
                },
            },
        ],
        "outbounds": [
            render_outbound_config(client),
            {
                "tag": "direct",
                "protocol": "freedom",
            },
            {
                "tag": "block",
                "protocol": "blackhole",
            },
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field",
                    "ip": ["geoip:private"],
                    "outboundTag": "direct",
                },
                {
                    "type": "field",
                    "network": "tcp,udp",
                    "outboundTag": "proxy",
                },
            ],
        },
    }


def get_share(client_id: str) -> XrayClientShare:
    client = get_client(client_id)
    settings = get_settings_status()
    return XrayClientShare(
        id=client.id,
        name=client.name,
        email=client.email,
        enabled=client.enabled,
        share_link=render_share_link(client),
        outbound_config=render_outbound_config(client),
        client_config=render_client_config(client),
        settings_ready=settings.ready,
        settings_errors=settings.errors,
        settings_warnings=settings.warnings,
    )
