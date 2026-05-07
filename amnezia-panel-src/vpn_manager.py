"""
VPN Manager — работа с native WireGuard на хосте без Docker.
Источник правды:
- /etc/wireguard/wg0.conf
- clientsTable
- wg show wg0 dump
"""

import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import awg_settings as awg
import config
from models import PeerInfo, PeerStatus, Protocol, Stats

logger = logging.getLogger(__name__)


def _run(cmd: list[str], input_text: Optional[str] = None) -> str:
    result = subprocess.run(
        cmd,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        message = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"{' '.join(cmd)} failed: {message}")
    return result.stdout


def _backup() -> None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = Path(config.BACKUP_DIR) / ts
    backup_dir.mkdir(parents=True, exist_ok=True)

    for src in [
        config.WG_CONFIG_PATH,
        config.WG_CLIENTS_TABLE,
        config.CLIENT_PRIVATE_KEYS_PATH,
    ]:
        path = Path(src)
        if path.exists():
            shutil.copy2(path, backup_dir / path.name)

    logger.info("Backup created: %s", backup_dir)


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


def _read_table() -> list[dict]:
    path = Path(config.WG_CLIENTS_TABLE)
    if not path.exists():
        return []

    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception as exc:
        logger.warning("Cannot read clientsTable %s: %s", path, exc)
        return []

    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "clients" in data and isinstance(data["clients"], list):
        return data["clients"]
    return []


def _write_table(clients: list[dict]) -> None:
    _atomic_write(
        config.WG_CLIENTS_TABLE,
        json.dumps(clients, ensure_ascii=False, indent=2),
    )


def _find_client(clients: list[dict], pubkey: str) -> Optional[dict]:
    for client in clients:
        if client.get("clientId") == pubkey:
            return client
    return None


def _load_private_keys() -> dict[str, str]:
    path = Path(config.CLIENT_PRIVATE_KEYS_PATH)
    if not path.exists():
        return {}

    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict):
            return data
    except Exception as exc:
        logger.warning("Cannot read private keys store %s: %s", path, exc)
    return {}


def _store_private_key(pubkey: str, privkey: str) -> None:
    data = _load_private_keys()
    data[pubkey] = privkey
    _atomic_write(config.CLIENT_PRIVATE_KEYS_PATH, json.dumps(data, indent=2))


def _remove_private_key(pubkey: str) -> None:
    data = _load_private_keys()
    if pubkey in data:
        data.pop(pubkey, None)
        _atomic_write(config.CLIENT_PRIVATE_KEYS_PATH, json.dumps(data, indent=2))


def _normalize_line(line: str) -> str:
    return re.sub(r"^#\s*", "", line.strip())


def _is_peer_start(line: str) -> bool:
    return _normalize_line(line) == "[Peer]"


def _split_config(content: str) -> tuple[str, list[str]]:
    header_lines: list[str] = []
    peer_blocks: list[str] = []
    current_block: Optional[list[str]] = None

    for line in content.splitlines(keepends=True):
        if _is_peer_start(line):
            if current_block is not None:
                peer_blocks.append("".join(current_block))
            current_block = [line]
            continue

        if current_block is None:
            header_lines.append(line)
        else:
            current_block.append(line)

    if current_block is not None:
        peer_blocks.append("".join(current_block))

    header = "".join(header_lines).rstrip() + "\n"
    return header, peer_blocks


def _read_config_blocks() -> tuple[str, list[str]]:
    path = Path(config.WG_CONFIG_PATH)
    if not path.exists():
        raise RuntimeError(f"WireGuard config not found: {path}")
    with path.open(encoding="utf-8") as handle:
        return _split_config(handle.read())


def _write_config_blocks(header: str, blocks: list[str]) -> None:
    cleaned_blocks = [block.strip("\n") for block in blocks if block.strip()]
    content = header.rstrip() + "\n"
    if cleaned_blocks:
        content += "\n\n" + "\n\n".join(cleaned_blocks) + "\n"
    _atomic_write(config.WG_CONFIG_PATH, content)


def _block_matches_pubkey(block: str, pubkey: str) -> bool:
    for line in block.splitlines():
        normalized = _normalize_line(line)
        if normalized.startswith("PublicKey ="):
            return normalized.split("=", 1)[1].strip() == pubkey
    return False


def _parse_peer_block(block: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in block.splitlines():
        normalized = _normalize_line(line)
        if "=" not in normalized:
            continue
        key, value = normalized.split("=", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def _comment_block(block: str) -> str:
    lines = []
    for line in block.splitlines():
        if not line.strip():
            lines.append("")
        elif line.lstrip().startswith("#"):
            lines.append(line)
        else:
            lines.append(f"# {line}")
    return "\n".join(lines) + "\n"


def _uncomment_block(block: str) -> str:
    lines = [re.sub(r"^#\s?", "", line) for line in block.splitlines()]
    return "\n".join(lines) + "\n"


def _get_peer_block(pubkey: str) -> Optional[str]:
    _, blocks = _read_config_blocks()
    for block in blocks:
        if _block_matches_pubkey(block, pubkey):
            return block
    return None


def _peer_block(pubkey: str, psk: str, ip: str) -> str:
    return (
        "[Peer]\n"
        f"PublicKey = {pubkey}\n"
        f"PresharedKey = {psk}\n"
        f"AllowedIPs = {ip}/32\n"
    )


def _parse_wg_dump(raw: str) -> dict[str, dict]:
    peers: dict[str, dict] = {}
    lines = raw.strip().splitlines()
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        pubkey = parts[0]
        peers[pubkey] = {
            "public_key": pubkey,
            "preshared_key": parts[1],
            "endpoint": parts[2],
            "allowed_ips": parts[3],
            "latest_handshake": int(parts[4]),
            "transfer_rx": int(parts[5]),
            "transfer_tx": int(parts[6]),
            "keepalive": parts[7],
        }
    return peers


def _get_live_peers() -> dict[str, dict]:
    try:
        raw = _run(["wg", "show", config.WG_INTERFACE, "dump"])
        return _parse_wg_dump(raw)
    except Exception as exc:
        logger.warning("Cannot get live peers from %s: %s", config.WG_INTERFACE, exc)
        return {}


def _handshake_status(ts: int) -> tuple[PeerStatus, Optional[int]]:
    if ts == 0:
        return PeerStatus.NEVER, None
    delta = int(time.time()) - ts
    if delta < 180:
        return PeerStatus.ONLINE, delta
    return PeerStatus.INACTIVE, delta


def _fmt_handshake(seconds_ago: Optional[int]) -> str:
    if seconds_ago is None:
        return "никогда"
    if seconds_ago < 60:
        return f"~{seconds_ago} сек"
    if seconds_ago < 3600:
        return f"~{seconds_ago // 60} мин"
    if seconds_ago < 86400:
        return f"~{seconds_ago // 3600} ч"
    return f"{seconds_ago // 86400} дн"


def _block_ip(block: Optional[str]) -> str:
    if not block:
        return ""
    allowed_ips = _parse_peer_block(block).get("AllowedIPs", "")
    return allowed_ips.split("/", 1)[0] if allowed_ips else ""


def get_all_peers() -> list[PeerInfo]:
    clients = _read_table()
    live = _get_live_peers()
    if not Path(config.WG_CONFIG_PATH).exists():
        if clients or live:
            logger.warning(
                "WireGuard config %s is missing; returning an empty peer list until WireGuard is configured.",
                config.WG_CONFIG_PATH,
            )
        return []

    _, blocks = _read_config_blocks()
    block_map = {
        _parse_peer_block(block).get("PublicKey", ""): block
        for block in blocks
        if _parse_peer_block(block).get("PublicKey")
    }

    result: list[PeerInfo] = []

    for client in clients:
        pubkey = client.get("clientId", "")
        block = block_map.get(pubkey)
        live_data = live.get(pubkey, {})

        ts = live_data.get("latest_handshake", 0)
        status, delta = _handshake_status(ts)
        allowed_ips = live_data.get("allowed_ips") or _parse_peer_block(block or "").get(
            "AllowedIPs",
            "",
        )
        vpn_ip = allowed_ips.split("/", 1)[0] if allowed_ips else ""

        result.append(
            PeerInfo(
                public_key=pubkey,
                protocol=Protocol.WG,
                name=client.get("clientName", "Unknown"),
                vpn_ip=vpn_ip,
                status=status,
                last_handshake=_fmt_handshake(delta),
                last_handshake_seconds=delta,
                transfer_rx=live_data.get("transfer_rx", 0),
                transfer_tx=live_data.get("transfer_tx", 0),
                created_at=client.get("creationDate", ""),
                deactivated=client.get("userData", {}).get("deactivated", False),
            )
        )

    known_keys = {client.get("clientId") for client in clients}
    for pubkey, live_data in live.items():
        if pubkey in known_keys:
            continue
        ts = live_data.get("latest_handshake", 0)
        status, delta = _handshake_status(ts)
        result.append(
            PeerInfo(
                public_key=pubkey,
                protocol=Protocol.WG,
                name="[Unknown]",
                vpn_ip=live_data.get("allowed_ips", "").split("/", 1)[0],
                status=status,
                last_handshake=_fmt_handshake(delta),
                last_handshake_seconds=delta,
                transfer_rx=live_data.get("transfer_rx", 0),
                transfer_tx=live_data.get("transfer_tx", 0),
                created_at=None,
                deactivated=False,
            )
        )

    return result


def get_stats() -> Stats:
    peers = get_all_peers()
    return Stats(
        total_online=sum(1 for peer in peers if peer.status == PeerStatus.ONLINE),
        total_peers=len(peers),
        never_connected=sum(1 for peer in peers if peer.status == PeerStatus.NEVER),
        inactive=sum(1 for peer in peers if peer.status == PeerStatus.INACTIVE),
        total_rx_bytes=sum(peer.transfer_rx for peer in peers),
        total_tx_bytes=sum(peer.transfer_tx for peer in peers),
    )


def _reserved_ips() -> set[ipaddress.IPv4Address]:
    _, blocks = _read_config_blocks()
    reserved = {ipaddress.ip_address(config.WG_SERVER_IP)}

    for block in blocks:
        allowed_ips = _parse_peer_block(block).get("AllowedIPs", "")
        if not allowed_ips:
            continue
        first_cidr = allowed_ips.split(",", 1)[0].strip()
        try:
            reserved.add(ipaddress.ip_interface(first_cidr).ip)
        except ValueError:
            logger.warning("Skipping invalid AllowedIPs entry: %s", allowed_ips)

    return reserved


def _next_ip() -> str:
    network = ipaddress.ip_network(config.WG_NETWORK, strict=False)
    reserved = _reserved_ips()
    for candidate in network.hosts():
        if candidate not in reserved:
            return str(candidate)
    raise RuntimeError(f"IP pool exhausted in {config.WG_NETWORK}")


def _keygen() -> tuple[str, str]:
    privkey = _run(["wg", "genkey"]).strip()
    pubkey = _run(["wg", "pubkey"], input_text=f"{privkey}\n").strip()
    return privkey, pubkey


def _gen_psk() -> str:
    return _run(["wg", "genpsk"]).strip()


def _read_server_pubkey() -> str:
    pubkey_path = Path(config.WG_PUBLIC_KEY_PATH)
    if pubkey_path.exists():
        return pubkey_path.read_text(encoding="utf-8").strip()
    return _run(["wg", "show", config.WG_INTERFACE, "public-key"]).strip()


def _wg_set_peer(pubkey: str, psk: str, ip: str) -> None:
    _run(
        [
            "wg",
            "set",
            config.WG_INTERFACE,
            "peer",
            pubkey,
            "preshared-key",
            "/dev/stdin",
            "allowed-ips",
            f"{ip}/32",
        ],
        input_text=f"{psk}\n",
    )


def _build_peer_conf(
    private_key: str,
    psk: str,
    ip: str,
    endpoint_host: str,
    endpoint_port: int,
    dns_servers: str,
    keepalive: int,
    interface_lines: list[str] | None = None,
) -> str:
    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {ip}/32",
        f"DNS = {dns_servers}",
    ]
    if interface_lines:
        lines.extend(interface_lines)
    lines.extend(
        [
            "",
            "[Peer]",
            f"PublicKey = {_read_server_pubkey()}",
            f"PresharedKey = {psk}",
            f"Endpoint = {endpoint_host}:{endpoint_port}",
            "AllowedIPs = 0.0.0.0/0",
            f"PersistentKeepalive = {keepalive}",
        ]
    )
    return "\n".join(lines) + "\n"


def _build_client_conf(private_key: str, psk: str, ip: str) -> str:
    return _build_peer_conf(
        private_key=private_key,
        psk=psk,
        ip=ip,
        endpoint_host=config.WG_ENDPOINT_HOST,
        endpoint_port=config.WG_PORT,
        dns_servers=config.DNS_SERVERS,
        keepalive=25,
    )


def _build_awg_client_conf(private_key: str, psk: str, ip: str) -> str:
    settings = awg.load_settings()
    interface_lines: list[str] = []
    for key in (*awg.INTERFACE_INT_KEYS, *awg.INTERFACE_TEXT_KEYS):
        value = settings.get(key, "")
        if isinstance(value, int):
            interface_lines.append(f"{key} = {value}")
        elif isinstance(value, str) and value:
            interface_lines.append(f"{key} = {value}")
    return _build_peer_conf(
        private_key=private_key,
        psk=psk,
        ip=ip,
        endpoint_host=settings["endpoint_host"],
        endpoint_port=settings["endpoint_port"],
        dns_servers=settings["dns_servers"],
        keepalive=settings["persistent_keepalive"],
        interface_lines=interface_lines,
    )


def create_peer(name: str) -> dict:
    _backup()

    privkey, pubkey = _keygen()
    psk = _gen_psk()
    ip = _next_ip()

    header, blocks = _read_config_blocks()
    blocks.append(_peer_block(pubkey, psk, ip))
    _write_config_blocks(header, blocks)

    _wg_set_peer(pubkey, psk, ip)

    clients = _read_table()
    clients.append(
        {
            "clientId": pubkey,
            "clientName": name,
            "creationDate": datetime.now(timezone.utc).isoformat(),
            "userData": {"deactivated": False},
        }
    )
    _write_table(clients)
    _store_private_key(pubkey, privkey)

    logger.info("Created peer %s (%s)", name, pubkey[:16])
    return {
        "public_key": pubkey,
        "private_key": privkey,
        "psk": psk,
        "ip": ip,
        "protocol": Protocol.WG.value,
        "name": name,
        "client_conf": _build_client_conf(privkey, psk, ip),
    }


def get_client_conf(pubkey: str, protocol: Protocol = Protocol.WG) -> Optional[str]:
    privkey = _load_private_keys().get(pubkey)
    if not privkey:
        return None

    live = _get_live_peers().get(pubkey, {})
    block = _get_peer_block(pubkey)
    block_data = _parse_peer_block(block or "")
    psk = live.get("preshared_key") or block_data.get("PresharedKey", "")
    allowed_ips = live.get("allowed_ips") or block_data.get("AllowedIPs", "")
    ip = allowed_ips.split("/", 1)[0] if allowed_ips else ""
    if not psk or not ip:
        return None

    if protocol == Protocol.WG:
        return _build_client_conf(privkey, psk, ip)
    if protocol == Protocol.AMNEZIAWG:
        return _build_awg_client_conf(privkey, psk, ip)
    raise ValueError(f"Unsupported peer config protocol: {protocol.value}")


def deactivate_peer(pubkey: str) -> None:
    _backup()

    try:
        _run(["wg", "set", config.WG_INTERFACE, "peer", pubkey, "remove"])
    except Exception as exc:
        logger.warning("Live peer removal failed for %s: %s", pubkey[:16], exc)

    header, blocks = _read_config_blocks()
    updated_blocks = []
    for block in blocks:
        if _block_matches_pubkey(block, pubkey):
            updated_blocks.append(_comment_block(block))
        else:
            updated_blocks.append(block)
    _write_config_blocks(header, updated_blocks)

    clients = _read_table()
    client = _find_client(clients, pubkey)
    if client is not None:
        client.setdefault("userData", {})
        client["userData"]["deactivated"] = True
        _write_table(clients)

    logger.info("Deactivated peer %s", pubkey[:16])


def activate_peer(pubkey: str) -> None:
    _backup()

    header, blocks = _read_config_blocks()
    updated_blocks = []
    psk = ""
    ip = ""
    found = False

    for block in blocks:
        if _block_matches_pubkey(block, pubkey):
            block = _uncomment_block(block)
            parsed = _parse_peer_block(block)
            psk = parsed.get("PresharedKey", "")
            allowed_ips = parsed.get("AllowedIPs", "")
            ip = allowed_ips.split("/", 1)[0] if allowed_ips else ""
            found = True
        updated_blocks.append(block)

    if not found:
        raise RuntimeError(f"Peer {pubkey} not found in {config.WG_CONFIG_PATH}")

    _write_config_blocks(header, updated_blocks)
    if psk and ip:
        _wg_set_peer(pubkey, psk, ip)

    clients = _read_table()
    client = _find_client(clients, pubkey)
    if client is not None:
        client.setdefault("userData", {})
        client["userData"]["deactivated"] = False
        _write_table(clients)

    logger.info("Activated peer %s", pubkey[:16])


def delete_peer(pubkey: str) -> None:
    _backup()

    try:
        _run(["wg", "set", config.WG_INTERFACE, "peer", pubkey, "remove"])
    except Exception as exc:
        logger.warning("Live peer removal failed for %s: %s", pubkey[:16], exc)

    header, blocks = _read_config_blocks()
    filtered_blocks = [block for block in blocks if not _block_matches_pubkey(block, pubkey)]
    _write_config_blocks(header, filtered_blocks)

    clients = [client for client in _read_table() if client.get("clientId") != pubkey]
    _write_table(clients)
    _remove_private_key(pubkey)

    logger.info("Deleted peer %s", pubkey[:16])


def rename_peer(pubkey: str, new_name: str) -> None:
    clients = _read_table()
    client = _find_client(clients, pubkey)
    if client is None:
        raise RuntimeError(f"Peer {pubkey} not found in clientsTable")
    client["clientName"] = new_name
    _write_table(clients)
    logger.info("Renamed peer %s to %s", pubkey[:16], new_name)


def health_check() -> dict:
    checks: dict[str, str] = {}

    try:
        _run(["wg", "--version"])
        checks["wg_binary"] = "ok"
    except Exception as exc:
        checks["wg_binary"] = f"error: {exc}"

    checks["wg_config"] = (
        "ok" if Path(config.WG_CONFIG_PATH).exists() else f"missing: {config.WG_CONFIG_PATH}"
    )

    try:
        _run(["wg", "show", config.WG_INTERFACE])
        checks["wg_interface"] = "ok"
    except Exception as exc:
        checks["wg_interface"] = f"error: {exc}"

    checks["clients_table"] = (
        "ok"
        if Path(config.WG_CLIENTS_TABLE).exists()
        else f"missing: {config.WG_CLIENTS_TABLE} (will be created on first peer)"
    )
    checks["private_keys_store"] = (
        "ok"
        if Path(config.CLIENT_PRIVATE_KEYS_PATH).exists()
        else f"missing: {config.CLIENT_PRIVATE_KEYS_PATH} (will be created on first peer)"
    )

    essential = []
    status = "ok" if all(checks[key] == "ok" for key in essential) else "degraded"
    return {"status": status, "checks": checks}
