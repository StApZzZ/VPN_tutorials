"""REALITY key consistency check.

Detects a stale REALITY public key: the Xray server was rebuilt or rotated to a
new key pair while the panel kept handing out the old public key
(``XRAY_CLIENT_REALITY_PUBLIC_KEY``), so every client failed the REALITY
handshake and was silently bounced to the decoy site. A short ID missing from
the server's ``shortIds`` or a server name missing from its ``serverNames``
fails the same way.

The check derives the public key from the server's REALITY *private* key and
compares it with the public key the panel embeds into client links. The panel
runs it in the Xray doctor and at startup; ``derive`` and ``compare`` do the
same from a shell.

Pure-Python derivation (via ``cryptography``) is byte-for-byte compatible with
``xray x25519`` (both use Curve25519 + base64 RawURLEncoding); pinned by
``tests/test_reality_keycheck.py``.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

DEFAULT_XRAY_CONFIG = "/etc/xray/config.json"
DEFAULT_INBOUND_TAG = "vless-in"


def _b64url_decode(value: str) -> bytes:
    """Decode base64 (url-safe or standard, with or without padding)."""
    s = value.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def _b64url_nopad(data: bytes) -> str:
    """Encode bytes as base64url without padding (xray's RawURLEncoding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def derive_public_key(private_key: str) -> str:
    """Derive the REALITY public key from a base64(url) X25519 private key.

    Output matches ``xray x25519 -i <private_key>`` exactly.
    """
    raw = _b64url_decode(private_key)
    if len(raw) != 32:
        raise ValueError(f"X25519 private key must be 32 bytes, got {len(raw)}")
    priv = X25519PrivateKey.from_private_bytes(raw)
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _b64url_nopad(pub)


def reality_settings(cfg: dict, inbound_tag: str = "", port: int = 0) -> dict:
    """realitySettings of the client inbound: by tag, else by port, else the
    first inbound that has a private key. (Behind the shared TCP 443 the inbound
    listens on a loopback port, so the tag is the reliable handle.)"""
    inbounds = [i for i in cfg.get("inbounds", []) if isinstance(i, dict)]
    candidates = (
        [i for i in inbounds if inbound_tag and i.get("tag") == inbound_tag]
        or [i for i in inbounds if port and i.get("port") == port]
        or inbounds
    )
    for inbound in candidates:
        reality = (inbound.get("streamSettings") or {}).get("realitySettings") or {}
        if reality.get("privateKey"):
            return reality
    raise ValueError("no REALITY privateKey in the Xray config")


def read_server_private_key(xray_config_path: str, port: int = 0, inbound_tag: str = "") -> str:
    """Extract the REALITY private key from an Xray server config.json."""
    with open(xray_config_path, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    return reality_settings(cfg, inbound_tag, port)["privateKey"]


def read_panel_reality_params(env_path: str) -> dict[str, str]:
    """Read the public REALITY params the panel embeds into client links."""
    keys = {
        "XRAY_CLIENT_REALITY_PUBLIC_KEY": "public_key",
        "XRAY_CLIENT_REALITY_SHORT_ID": "short_id",
        "XRAY_CLIENT_REALITY_SERVER_NAME": "server_name",
        "XRAY_CLIENT_SERVER": "server",
    }
    out: dict[str, str] = {}
    with open(env_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, _, value = line.partition("=")
            name = name.strip()
            if name in keys:
                out[keys[name]] = value.strip().strip('"').strip("'")
    return out


@dataclass
class CheckResult:
    ok: bool
    expected_public_key: str  # derived from the server's private key (source of truth)
    panel_public_key: str  # what the panel currently distributes
    detail: str

    def render(self) -> str:
        status = "OK" if self.ok else "MISMATCH"
        return (
            f"[{status}] REALITY public key\n"
            f"  server (derived): {self.expected_public_key}\n"
            f"  panel  (.env)   : {self.panel_public_key or '<empty>'}\n"
            f"  {self.detail}"
        )


_STALE_KEY = (
    "panel distributes a STALE/WRONG key -> clients fail the REALITY handshake and "
    "are bounced to the decoy site. Set XRAY_CLIENT_REALITY_PUBLIC_KEY to the derived "
    "value and restart the panel, then re-issue client links."
)


def compare(server_private_key: str, panel_public_key: str) -> CheckResult:
    expected = derive_public_key(server_private_key)
    panel = (panel_public_key or "").strip()
    ok = bool(panel) and panel == expected
    if not panel:
        detail = "panel public key is empty/unconfigured"
    elif ok:
        detail = "panel distributes the key matching the live server"
    else:
        detail = _STALE_KEY
    return CheckResult(ok=ok, expected_public_key=expected, panel_public_key=panel, detail=detail)


def check_server_config(
    cfg: dict,
    public_key: str,
    short_id: str | None = None,
    server_name: str = "",
    inbound_tag: str = "",
    port: int = 0,
) -> CheckResult:
    """Everything a client link carries against the live server config: the
    public key, the short ID (must be in shortIds) and the server name (must be
    in serverNames). None / "" skips the short ID / server name."""
    reality = reality_settings(cfg, inbound_tag, port)
    result = compare(reality["privateKey"], public_key)
    problems = [] if result.ok else [result.detail]
    short_ids = [str(value) for value in reality.get("shortIds") or []]
    if short_id is not None and short_ids and short_id.strip() not in short_ids:
        problems.append(f"short ID {short_id.strip() or '<empty>'!r} is not in the server's shortIds")
    names = [str(value) for value in reality.get("serverNames") or []]
    if server_name and names and server_name.strip() not in names:
        problems.append(f"server name {server_name.strip()!r} is not in the server's serverNames")
    if not problems:
        return result
    return CheckResult(
        ok=False,
        expected_public_key=result.expected_public_key,
        panel_public_key=result.panel_public_key,
        detail="; ".join(problems),
    )


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="REALITY key consistency check")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_derive = sub.add_parser("derive", help="print the public key of the server's REALITY private key")
    p_derive.add_argument("--xray-config", default=DEFAULT_XRAY_CONFIG)
    p_derive.add_argument("--inbound-tag", default=DEFAULT_INBOUND_TAG)
    p_derive.add_argument("--port", type=int, default=0)

    p_cmp = sub.add_parser("compare", help="compare the server's REALITY settings with the panel .env")
    g = p_cmp.add_mutually_exclusive_group(required=True)
    g.add_argument("--server-public-key", help="public key derived elsewhere (checks the key only)")
    g.add_argument("--xray-config", help="the server's config.json (checks key, short ID and server name)")
    p_cmp.add_argument("--env", default="/opt/vpn-panel/.env", help="panel .env path")
    p_cmp.add_argument("--inbound-tag", default=DEFAULT_INBOUND_TAG)
    p_cmp.add_argument("--port", type=int, default=0)

    args = parser.parse_args(argv)

    try:
        if args.cmd == "derive":
            priv = read_server_private_key(args.xray_config, args.port, args.inbound_tag)
            print(derive_public_key(priv))
            return 0

        params = read_panel_reality_params(args.env)
        if args.server_public_key:
            expected = args.server_public_key.strip()
            panel = params.get("public_key", "")
            result = CheckResult(
                ok=bool(panel) and panel == expected,
                expected_public_key=expected,
                panel_public_key=panel,
                detail=(
                    "panel distributes the key matching the live server"
                    if panel and panel == expected
                    else "panel public key is empty/unconfigured"
                    if not panel
                    else _STALE_KEY
                ),
            )
        else:
            with open(args.xray_config, "r", encoding="utf-8") as fh:
                cfg = json.load(fh)
            result = check_server_config(
                cfg,
                params.get("public_key", ""),
                short_id=params.get("short_id"),
                server_name=params.get("server_name", ""),
                inbound_tag=args.inbound_tag,
                port=args.port,
            )
        print(result.render())
        return 0 if result.ok else 2
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"[ERROR] reality key check failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(_main())
