"""Access-profile network policy.

An access profile decides, for every device of its members:

* client side - WireGuard/AmneziaWG configs get AllowedIPs (split tunnel: the
  allowed subnets only; full tunnel: everything), the profile's DNS servers and
  search domains; the VLESS JSON config gets the same split as routing rules;
* server side - an nftables table ``inet corpvpn_policy`` on the forward hook
  (WireGuard/AmneziaWG clients, matched by tunnel address) and per-user Xray
  routing rules (VLESS clients, matched by client e-mail).

Server side, first match wins, for a device whose owner has profile P:

    destination always denied (metadata, loopback, ...)       -> dropped, whatever P says
    destination in P's allowed subnets (+ its DNS resolvers)  -> allowed
    destination in a client pool (client isolation on)        -> dropped
    destination in CORP_CIDRS (every other corporate range)   -> dropped
    anything else                                             -> allowed (full) / dropped (split)

Tunnel addresses without an active device (a peer made on the low-level pages,
a stale address) get the default profile. A profile that lists a client pool in
its allowed subnets is how remote-support staff reach employees' devices.

The nft table only ever drops. Accepting is left to whatever else filters
forwarded traffic (base firewall, Docker), so the table coexists with them. It
is replaced atomically on each load and never touches other tables (no
``flush ruleset``).
"""
from __future__ import annotations

import copy
import ipaddress
import json
import logging
import os
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from typing import Any

import config
import vpn_manager as vm
import xray_clients as xc
from auth import store

logger = logging.getLogger(__name__)

TABLE = "corpvpn_policy"
MODES = ("off", "enforce")
PEER_PROTOCOLS = ("wg", "awg")
FULL_TUNNEL_ALLOWED_IPS = "0.0.0.0/0"

# Never reachable from a tunnel, whatever the profile allows. The site link and
# NETWORK_POLICY_DENY_CIDRS are added from the configuration.
ALWAYS_DENIED = (
    "0.0.0.0/8",            # "this network"
    "127.0.0.0/8",          # loopback
    "169.254.0.0/16",       # link-local, cloud metadata (169.254.169.254)
    "100.100.100.200/32",   # cloud metadata outside link-local
    "224.0.0.0/4",          # multicast
    "240.0.0.0/4",          # reserved, broadcast
)
# Xray dials out from the gateway itself: its own IPv6 loopback and link-local
# are reachable that way too.
_XRAY_DENIED_V6 = ("::1/128", "fe80::/10")

_state: dict[str, Any] = {
    "applied_nft": None,   # text last loaded into the kernel
    "applied_at": "",
    "loaded": None,        # table present in the kernel at the last check (None: unknown)
    "xray_rules": None,    # JSON of the rules Xray was last applied with
    "error": "",
    "checked_at": "",
}


class NetworkPolicyError(RuntimeError):
    pass


@dataclass
class Group:
    profile: dict[str, Any]
    addresses: list[str] = field(default_factory=list)   # tunnel IPv4 addresses (wg0 + awg0 mirror)
    emails: list[str] = field(default_factory=list)      # VLESS client e-mails
    devices: int = 0


# ------------------------------------------------------------------ inputs
def mode() -> str:
    value = (getattr(config, "NETWORK_POLICY_MODE", "off") or "off").strip().lower()
    if value not in MODES:
        raise NetworkPolicyError("NETWORK_POLICY_MODE must be off or enforce")
    return value


def _networks(values, what: str) -> list[str]:
    out: list[str] = []
    for raw in values or ():
        raw = str(raw).strip()
        if not raw:
            continue
        try:
            out.append(str(ipaddress.ip_network(raw, strict=False)))
        except ValueError as exc:
            raise NetworkPolicyError(f"invalid {what}: {raw}") from exc
    return _collapse(out)


def _collapse(cidrs: list[str]) -> list[str]:
    nets = [ipaddress.ip_network(c, strict=False) for c in cidrs]
    v4 = ipaddress.collapse_addresses(n for n in nets if n.version == 4)
    v6 = ipaddress.collapse_addresses(n for n in nets if n.version == 6)
    return [str(n) for n in v4] + [str(n) for n in v6]


def corp_cidrs() -> list[str]:
    return _networks(getattr(config, "CORP_CIDRS", ()), "CORP_CIDRS entry")


def denied_cidrs() -> list[str]:
    """Destinations no client may reach (IPv4 and IPv6), checked first."""
    extra = [config.SITE_LINK_NETWORK] if config.SITE_LINK_NETWORK else []
    configured = _networks([*extra, *config.NETWORK_POLICY_DENY_CIDRS], "NETWORK_POLICY_DENY_CIDRS entry")
    return _collapse([*ALWAYS_DENIED, *configured])


def client_pools() -> list[str]:
    """The client pools while client isolation is on, else []."""
    if not config.NETWORK_POLICY_CLIENT_ISOLATION:
        return []
    return _networks([config.WG_NETWORK, config.AWG_NETWORK], "client pool")


def _gateway_addresses() -> list[str]:
    """The gateway's own tunnel addresses (host routes)."""
    out = []
    for raw in (config.WG_SERVER_IP, config.AWG_SERVER_IP):
        try:
            out.append(f"{ipaddress.ip_address(raw)}/32")
        except ValueError:
            continue
    return out


def _resolvers(profile: dict[str, Any]) -> list[str]:
    """DNS servers the profile's clients query: the profile's own, else the
    gateway-wide DNS_SERVERS every config carries by default."""
    configured = profile.get("dns_servers") or [s for s in config.DNS_SERVERS.split(",") if s.strip()]
    out = []
    for server in configured:
        try:
            out.append(str(ipaddress.ip_address(str(server).strip())))
        except ValueError:
            continue  # a hostname: nothing to route
    return out


def resolver_cidrs(profile: dict[str, Any]) -> list[str]:
    return [f"{server}/{ipaddress.ip_address(server).max_prefixlen}" for server in _resolvers(profile)]


def effective_allowed(profile: dict[str, Any]) -> list[str]:
    """Allowed subnets plus the DNS resolvers the profile's clients use (host
    routes): a resolver outside the allowed subnets, e.g. a corporate DNS inside
    CORP_CIDRS on a full tunnel, must still be reachable through the tunnel."""
    hosts = []
    for server in _resolvers(profile):
        addr = ipaddress.ip_address(server)
        hosts.append(f"{addr}/{addr.max_prefixlen}")
    return _collapse(list(profile.get("allowed_cidrs") or []) + hosts)


def _v4(cidrs: list[str]) -> list[str]:
    return [c for c in cidrs if ipaddress.ip_network(c).version == 4]


def collect() -> tuple[list[Group], dict[str, Any]]:
    """Active devices grouped by their owner's access profile."""
    default = store.default_profile()
    profiles = {p["id"]: p for p in store.list_profiles()}
    users = {u["id"]: u for u in store.list_users()}
    # Suspended VLESS clients stay in the per-user rules (they are disabled in
    # the inbound anyway): suspending / resuming then does not change the Xray
    # rules, so it costs one Xray apply, not two.
    live = [d for d in store.list_devices() if d["status"] == "active" or d["protocol"] not in PEER_PROTOCOLS]
    peers: dict[str, str] = {}
    if any(d["protocol"] in PEER_PROTOCOLS for d in live):
        try:
            peers = {p.public_key: p.vpn_ip for p in vm.get_all_peers()}
        except Exception:
            logger.exception("network policy: cannot list WireGuard peers")
    emails: dict[str, str] = {}
    if any(d["protocol"] not in PEER_PROTOCOLS for d in live):
        try:
            emails = {c.id: c.email for c in xc.list_clients()}
        except Exception:
            logger.exception("network policy: cannot list VLESS clients")

    groups: dict[str, Group] = {}
    for device in live:
        owner = users.get(device["user_id"])
        profile = profiles.get((owner or {}).get("access_profile_id", "")) or default
        group = groups.setdefault(profile["id"], Group(profile=profile))
        group.devices += device["status"] == "active"
        if device["protocol"] in PEER_PROTOCOLS:
            ip = (peers.get(device["ref"]) or "").split("/")[0].strip()
            if ip:
                group.addresses.append(ip)
                mirror = vm.awg_address(ip)
                if mirror:
                    group.addresses.append(mirror)
        else:
            email = emails.get(device["ref"])
            if email:
                group.emails.append(email)
    ordered = sorted(groups.values(), key=lambda g: (g.profile["name"].lower(), g.profile["id"]))
    for group in ordered:
        group.addresses = sorted(set(group.addresses), key=ipaddress.ip_address)
        group.emails = sorted(set(group.emails))
    return ordered, default


def _restrictive(groups: list[Group], default: dict[str, Any], corp: list[str]) -> bool:
    """Whether any rule can drop traffic at all."""
    return bool(corp) or default["tunnel_mode"] == "split" or any(
        g.profile["tunnel_mode"] == "split" for g in groups
    )


# ----------------------------------------------------------- client configs
def client_allowed_ips(profile: dict[str, Any]) -> list[str]:
    # v2 has no IPv6 tunnel: capture all client IPv6 traffic and drop it at the
    # IPv4-only gateway, including when IPv4 internet traffic stays local.
    if profile.get("tunnel_mode") == "split":
        return _v4(effective_allowed(profile)) + ["::/0"]
    return [FULL_TUNNEL_ALLOWED_IPS, "::/0"]


def client_conf(conf: str, profile: dict[str, Any]) -> str:
    """Rewrite AllowedIPs / DNS of a WireGuard or AmneziaWG client config."""
    allowed = ", ".join(client_allowed_ips(profile))
    search = [d for d in profile.get("search_domains") or [] if d]
    servers = list(profile.get("dns_servers") or [])
    out: list[str] = []
    section = ""
    dns_done = False
    address_at = -1
    for line in conf.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped.lower()
        key = stripped.split("=", 1)[0].strip().lower() if "=" in stripped else ""
        if section == "[interface]" and key == "address":
            address_at = len(out)
        if section == "[interface]" and key == "dns":
            current = [v.strip() for v in stripped.split("=", 1)[1].split(",") if v.strip()]
            values = _dns_values(servers or current, search)
            if values:
                out.append(f"DNS = {', '.join(values)}")
            dns_done = True
            continue
        if section == "[peer]" and key == "allowedips":
            out.append(f"AllowedIPs = {allowed}")
            continue
        out.append(line)
    if not dns_done and (servers or search):
        values = _dns_values(servers, search)
        if values and address_at >= 0:
            out.insert(address_at + 1, f"DNS = {', '.join(values)}")
    text = "\n".join(out)
    return text + "\n" if conf.endswith("\n") else text


def _dns_values(servers: list[str], search: list[str]) -> list[str]:
    values: list[str] = []
    for value in [*servers, *search]:
        if value not in values:
            values.append(value)
    return values


def vless_client_config(base: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    """Xray client JSON with the profile's split applied (the vless:// link
    cannot carry routing rules)."""
    cfg = copy.deepcopy(base)
    allowed = effective_allowed(profile)
    domains = [f"domain:{d}" for d in profile.get("search_domains") or [] if d]
    rules: list[dict[str, Any]] = [{"type": "field", "ip": ["::/0"], "outboundTag": "block"}]
    if not any(o.get("tag") == "block" for o in cfg.get("outbounds", [])):
        cfg.setdefault("outbounds", []).append({"tag": "block", "protocol": "blackhole"})
    if allowed:
        rules.append({"type": "field", "ip": allowed, "outboundTag": "proxy"})
    if domains:
        rules.append({"type": "field", "domain": domains, "outboundTag": "proxy"})
    if profile.get("tunnel_mode") == "split":
        rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "direct"})
    else:
        rules.append({"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"})
        rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "proxy"})
    cfg["routing"] = {"domainStrategy": "IPIfNonMatch", "rules": rules}
    servers = list(profile.get("dns_servers") or [])
    if servers:
        dns_servers: list[Any] = []
        for server in servers:
            entry: dict[str, Any] = {"address": server}
            if domains:
                entry["domains"] = domains
            dns_servers.append(entry)
        if domains:
            dns_servers.append("localhost")
        cfg["dns"] = {"servers": dns_servers}
    return cfg


# ------------------------------------------------------------- nftables
_COMMENT_SAFE = re.compile(r"[^\w .,:;()«»/+-]", re.UNICODE)


def _comment(text: str) -> str:
    return _COMMENT_SAFE.sub("?", " ".join(str(text).split()))[:80]


def _set(name: str, kind: str, elements: list[str], interval: bool) -> list[str]:
    lines = [f"    set {name} {{", f"        type {kind}"]
    if interval:
        lines += ["        flags interval", "        auto-merge"]
    if elements:
        lines.append("        elements = { " + ", ".join(elements) + " }")
    lines.append("    }")
    return lines


def _ifaces() -> list[str]:
    names = []
    for name in (config.WG_INTERFACE, getattr(config, "AWG_INTERFACE", "")):
        name = (name or "").strip()
        if name and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name) and name not in names:
            names.append(name)
    return names


def render_nft(groups: list[Group], default: dict[str, Any], corp: list[str]) -> str:
    ifaces = _ifaces()
    iif = "{ " + ", ".join(f'"{i}"' for i in ifaces) + " }"
    corp4 = _v4(corp)
    pools = client_pools()
    isolate = ["ip daddr @client_pools counter drop"] if pools else []
    body: list[str] = []
    rules: list[str] = [
        "        type filter hook forward priority filter - 5; policy accept;",
        "        # Only traffic entering from the VPN tunnels is judged here.",
        f"        iifname != {iif} accept",
        "        # The tunnels carry IPv4 only.",
        "        meta nfproto ipv6 counter drop",
        "        # Never reachable, whatever the profile: metadata, loopback, site link, ...",
        "        ip daddr @always_denied counter drop",
    ]
    body += _set("always_denied", "ipv4_addr", _v4(denied_cidrs()), True)
    body += _set("corp_v4", "ipv4_addr", corp4, True)
    if pools:
        body += _set("client_pools", "ipv4_addr", pools, True)
    for index, group in enumerate(groups, start=1):
        profile = group.profile
        clients, allowed = f"p{index}_clients", f"p{index}_allowed"
        body += _set(clients, "ipv4_addr", group.addresses, False)
        body += _set(allowed, "ipv4_addr", _v4(profile.get("allowed_cidrs") or []), True)
        dns = f"p{index}_dns"
        body += _set(dns, "ipv4_addr", _v4(resolver_cidrs(profile)), True)
        protocols = profile.get("protocols", ["wg", "awg", "vless"])
        for protocol, iface in (("wg", config.WG_INTERFACE), ("awg", config.AWG_INTERFACE)):
            if protocol not in protocols and iface in ifaces:
                rules.append(f'        ip saddr @{clients} iifname "{iface}" counter drop')
        split = profile["tunnel_mode"] == "split"
        rules += [
            f"        # profile {_comment(profile['name'])} ({profile['tunnel_mode']} tunnel, {group.devices} devices)",
            f"        ip saddr @{clients} ip daddr @{allowed} accept",
            f"        ip saddr @{clients} ip daddr @{dns} meta l4proto {{ tcp, udp }} th dport 53 accept",
            *(f"        ip saddr @{clients} {rule}" for rule in isolate),
            f"        ip saddr @{clients} ip daddr @corp_v4 counter drop",
            f"        ip saddr @{clients} " + ("counter drop" if split else "accept"),
        ]
    body += _set("default_allowed", "ipv4_addr", _v4(default.get("allowed_cidrs") or []), True)
    body += _set("default_dns", "ipv4_addr", _v4(resolver_cidrs(default)), True)
    for protocol, iface in (("wg", config.WG_INTERFACE), ("awg", config.AWG_INTERFACE)):
        if protocol not in default.get("protocols", ["wg", "awg", "vless"]) and iface in ifaces:
            rules.append(f'        iifname "{iface}" counter drop')
    rules += [
        f"        # tunnel addresses without an active device: default profile {_comment(default['name'])}",
        "        ip daddr @default_allowed accept",
        "        ip daddr @default_dns meta l4proto { tcp, udp } th dport 53 accept",
        *(f"        {rule}" for rule in isolate),
        "        ip daddr @corp_v4 counter drop",
    ]
    if default["tunnel_mode"] == "split":
        rules.append("        counter drop")
    lines = [
        "#!/usr/sbin/nft -f",
        "# Generated by the CorpVPN (network_policy.py) from the access profiles.",
        "# Rewritten on every change; edit the profiles, not this file.",
        f"table inet {TABLE}",
        f"delete table inet {TABLE}",
        f"table inet {TABLE} {{",
        *body,
        "",
        "    chain forward {",
        *rules,
        "    }",
        "}",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- Xray
def xray_guard_rules() -> list[dict[str, Any]]:
    """The FIRST Xray routing rule. Xray dials out from the gateway itself, so
    without it a VLESS user reaches the gateway's loopback services (the panel
    trusts forwarded client addresses from loopback), its tunnel addresses and
    the cloud metadata service, and no profile can allow them back. Built from
    the configuration only, so it holds even when the device store is down.
    The gateway's public address stays reachable: employees open the portal
    through the tunnel."""
    ips = _collapse([*denied_cidrs(), *_XRAY_DENIED_V6, *_gateway_addresses()])
    return [{"type": "field", "ip": ips, "outboundTag": "block"}]


def xray_rules(groups: list[Group], default: dict[str, Any], corp: list[str]) -> list[dict[str, Any]]:
    """Per-user Xray rules for VLESS users; they go after the guard rule and
    before geoip:private."""
    pools = client_pools()
    restrictive = _restrictive(groups, default, corp)
    protocol_blocks = [{"type": "field", "user": list(group.emails), "network": "tcp,udp", "outboundTag": "block"}
                       for group in groups if group.emails and "vless" not in group.profile.get("protocols", ["wg", "awg", "vless"])]
    if not (restrictive or pools or protocol_blocks):
        return []
    rules: list[dict[str, Any]] = protocol_blocks
    for group in groups:
        allowed = list(group.profile.get("allowed_cidrs") or [])
        if group.emails and allowed:
            rules.append({"type": "field", "user": list(group.emails), "ip": allowed, "outboundTag": "direct"})
        if group.emails and resolver_cidrs(group.profile):
            rules.append({"type": "field", "user": list(group.emails), "ip": resolver_cidrs(group.profile), "port": "53", "network": "tcp,udp", "outboundTag": "direct"})
    if pools:
        # After the allowed subnets: a profile that lists a pool opts in.
        rules.append({"type": "field", "ip": pools, "outboundTag": "block"})
    if not restrictive:
        return rules
    for group in groups:
        if not group.emails:
            continue
        if corp:
            rules.append({"type": "field", "user": list(group.emails), "ip": list(corp), "outboundTag": "block"})
        if group.profile["tunnel_mode"] == "split":
            rules.append({"type": "field", "user": list(group.emails), "network": "tcp,udp", "outboundTag": "block"})
    if corp:
        # Safety net for a client without a device row (never matched above).
        default_allowed = list(default.get("allowed_cidrs") or [])
        if default_allowed:
            rules.append({"type": "field", "ip": default_allowed, "outboundTag": "direct"})
        if resolver_cidrs(default):
            rules.append({"type": "field", "ip": resolver_cidrs(default), "port": "53", "network": "tcp,udp", "outboundTag": "direct"})
        rules.append({"type": "field", "ip": list(corp), "outboundTag": "block"})
    return rules


def xray_policy_rules() -> list[dict[str, Any]]:
    """Rules for routing_overrides.get_preview (reads the current state)."""
    try:
        groups, default = collect()
        return xray_rules(groups, default, corp_cidrs())
    except Exception:
        logger.exception("network policy: cannot render Xray rules")
        raise


# ---------------------------------------------------------------- apply
def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=True, check=False, timeout=30)


def _load_nft(text: str) -> None:
    path = config.NFT_POLICY_PATH
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".new"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(tmp, 0o644)
    cmd = shlex.split(config.NFT_COMMAND)
    try:
        # Dry run first: a broken file never reaches the kernel.
        for args in (["-c", "-f", tmp], ["-f", tmp]):
            result = _run(cmd + args)
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "").strip()
                raise NetworkPolicyError(f"nft {' '.join(args[:-1])} failed: {detail[:500]}")
    except (OSError, subprocess.SubprocessError) as exc:
        os.remove(tmp)
        raise NetworkPolicyError(f"cannot run {config.NFT_COMMAND}: {exc}") from exc
    except NetworkPolicyError:
        os.remove(tmp)
        raise
    # Keep the loaded file where the boot-time loader includes it.
    os.replace(tmp, path)


def _table_loaded() -> bool | None:
    """Whether the table is in the kernel; None when nft cannot tell. A stock
    /etc/nftables.conf starts with `flush ruleset`, and `nft flush ruleset` by
    hand does the same: without this check the panel would never notice."""
    try:
        result = _run(shlex.split(config.NFT_COMMAND) + ["-t", "list", "table", "inet", TABLE])
    except (OSError, subprocess.SubprocessError):
        return None
    return result.returncode == 0


def _xray_ready() -> bool:
    return bool(config.XRAY_RELOAD_COMMAND) and os.path.exists(config.XRAY_BASE_CONFIG_PATH)


def render() -> dict[str, Any]:
    groups, default = collect()
    corp = corp_cidrs()
    return {
        "groups": groups,
        "default": default,
        "corp": corp,
        "nft": render_nft(groups, default, corp),
        "xray_rules": xray_rules(groups, default, corp),
    }


def refresh(reason: str = "", force: bool = False) -> dict[str, Any]:
    """Bring the kernel table and Xray in line with the current profiles and
    devices. Cheap when nothing changed; safe to call after every mutation."""
    import devices  # the lock lives with the other backend mutations
    import xray_manager as xm

    with devices.backend_lock():
        _state["checked_at"] = store.iso(store.now())
        try:
            current_mode = mode()
            rendered = render()
            if current_mode == "enforce":
                why = reason
                reload = force or rendered["nft"] != _state["applied_nft"]
                if not reload:
                    _state["loaded"] = _table_loaded()
                    if _state["loaded"] is False:
                        logger.warning("network policy: table inet %s is gone from the kernel; reloading", TABLE)
                        reload, why = True, "table missing"
                if reload:
                    _load_nft(rendered["nft"])
                    _state["applied_nft"] = rendered["nft"]
                    _state["applied_at"] = _state["checked_at"]
                    _state["loaded"] = True
                    store.audit("network.policy.apply", actor="system",
                                details={"reason": why, "profiles": len(rendered["groups"])})
            rules_json = json.dumps(rendered["xray_rules"], sort_keys=True)
            if _xray_ready() and (force or rules_json != _state["xray_rules"] or not xm.live_clients_in_sync()):
                xm.apply_xray()
            _state["xray_rules"] = rules_json
            _state["error"] = ""
        except Exception as exc:
            _state["error"] = str(exc)
            logger.exception("network policy refresh failed (%s)", reason or "periodic")
            if force:
                raise
    return status()


def policy_state() -> dict[str, Any]:
    """The last refresh's outcome without touching the stores (for /metrics)."""
    return {
        "mode": getattr(config, "NETWORK_POLICY_MODE", "off"),
        "loaded": _state["loaded"],
        "applied_at": _state["applied_at"],
        "checked_at": _state["checked_at"],
        "error": _state["error"],
    }


def safe_refresh(reason: str) -> None:
    """For mutation hooks: a policy failure is logged, never fatal to the caller."""
    try:
        refresh(reason)
    except Exception:
        logger.exception("network policy refresh failed (%s)", reason)


def status() -> dict[str, Any]:
    info: dict[str, Any] = {
        "mode": getattr(config, "NETWORK_POLICY_MODE", "off"),
        "path": config.NFT_POLICY_PATH,
        "applied_at": _state["applied_at"],
        "checked_at": _state["checked_at"],
        "loaded": _state["loaded"],
        "error": _state["error"],
        "client_isolation": bool(config.NETWORK_POLICY_CLIENT_ISOLATION),
        "always_denied": [],
        "corp_cidrs": [],
        "profiles": [],
    }
    try:
        groups, default = collect()
        info["always_denied"] = denied_cidrs()
        info["corp_cidrs"] = corp_cidrs()
        info["profiles"] = [
            {
                "id": g.profile["id"],
                "name": g.profile["name"],
                "tunnel_mode": g.profile["tunnel_mode"],
                "allowed": effective_allowed(g.profile),
                "devices": g.devices,
                "addresses": len(g.addresses),
                "vless_users": len(g.emails),
            }
            for g in groups
        ]
        info["default_profile"] = default["name"]
    except Exception as exc:
        info["error"] = info["error"] or str(exc)
    return info
