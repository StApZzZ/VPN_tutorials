"""Address-plan helpers for the CorpVPN playbooks (Ansible filters, stdlib only).

quickstart.sh imports this module directly to check quickstart.env with the same
rules the preflight role applies, so an invalid plan is refused before anything
touches a server, and again for runs that bypass quickstart.

Pools are any IPv4 network from /16 to /29. The AmneziaWG pool mirrors the
WireGuard pool by host offset (the device at wg_net + n gets awg_net + n on
awg0), so both pools must have the same size.
"""
from __future__ import annotations

import ipaddress

POOL_PREFIX_MIN = 16
POOL_PREFIX_MAX = 29


def _network(value, what: str, version: int | None = 4) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    text = str(value).strip()
    if "/" not in text:
        raise ValueError(f"{what}: {text!r} needs a prefix length (e.g. {text}/32 for a single host)")
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValueError(f"{what}: {text!r} is not a network in CIDR notation") from None
    if version and net.version != version:
        raise ValueError(f"{what}: {text!r} is not an IPv{version} network")
    if ipaddress.ip_interface(text).ip != net.network_address:
        raise ValueError(f"{what}: {text!r} has host bits set (did you mean {net}?)")
    return net


def host(network, index=1) -> str:
    """The index-th address of a network: host('10.66.0.0/22') -> '10.66.0.1'."""
    net = ipaddress.ip_network(str(network).strip(), strict=True)
    index = int(index)
    if not 0 < index < net.num_addresses - 1:
        raise ValueError(f"{network} has no host number {index}")
    return str(net.network_address + index)


def host_cidr(network, index=1) -> str:
    """host() with the network's prefix: '10.99.0.0/30', 2 -> '10.99.0.2/30'."""
    net = ipaddress.ip_network(str(network).strip(), strict=True)
    return f"{host(network, index)}/{net.prefixlen}"


def prefixlen(network) -> int:
    return ipaddress.ip_network(str(network).strip(), strict=False).prefixlen


def prefix3(network) -> str:
    """First three octets of the pool's first /24, e.g. '10.66.0.'.

    Only for panels that still map wg0 to awg0 addresses by a text prefix; the
    offset mapping (mirror) is exact for every pool size.
    """
    net = ipaddress.ip_network(str(network).strip(), strict=False)
    return str(net.network_address).rsplit(".", 1)[0] + "."


def mirror(address, wg_network, awg_network) -> str:
    """AmneziaWG address of a WireGuard pool address (same host offset)."""
    ip = ipaddress.ip_address(str(address).split("/")[0].strip())
    wg = ipaddress.ip_network(str(wg_network).strip(), strict=False)
    awg = ipaddress.ip_network(str(awg_network).strip(), strict=False)
    if ip not in wg:
        raise ValueError(f"{ip} is not in {wg}")
    return str(awg.network_address + (int(ip) - int(wg.network_address)))


def containing(cidrs, addresses) -> list[str]:
    """The CIDRs that contain at least one of the addresses."""
    ips = []
    for value in addresses or []:
        try:
            ips.append(ipaddress.ip_address(str(value).split("/")[0].strip()))
        except ValueError:
            continue
    out = []
    for cidr in cidrs or []:
        net = ipaddress.ip_network(str(cidr).strip(), strict=False)
        if any(ip.version == net.version and ip in net for ip in ips):
            out.append(str(cidr).strip())
    return out


def _list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    return [str(v).strip() for v in value if str(v).strip()]


def plan_errors(settings: dict) -> list[str]:
    """Every problem with an address plan; an empty list means it is usable.

    settings: wg_network, awg_network, awg_enabled, wg_server_ip (optional),
    corp_cidrs, dns_servers, split, link_network, trusted_proxy_cidrs,
    local_allowed_cidrs, forward_deny_cidrs (lists or comma-separated text).
    """
    errors: list[str] = []
    pools: dict[str, ipaddress.IPv4Network] = {}

    def pool(key: str, label: str):
        try:
            net = _network(settings.get(key, ""), label)
        except ValueError as exc:
            errors.append(str(exc))
            return None
        if not POOL_PREFIX_MIN <= net.prefixlen <= POOL_PREFIX_MAX:
            errors.append(f"{label}: {net} must be between /{POOL_PREFIX_MIN} and /{POOL_PREFIX_MAX}")
            return None
        pools[label] = net
        return net

    wg = pool("wg_network", "WireGuard pool")
    awg = pool("awg_network", "AmneziaWG pool") if settings.get("awg_enabled", True) else None
    if wg and awg:
        if wg.prefixlen != awg.prefixlen:
            errors.append(f"the AmneziaWG pool {awg} must be the same size as the WireGuard pool {wg} "
                          "(awg0 mirrors wg0 addresses by host offset)")
        if wg.overlaps(awg):
            errors.append(f"the WireGuard pool {wg} and the AmneziaWG pool {awg} overlap")

    server_ip = str(settings.get("wg_server_ip") or "").strip()
    if wg and server_ip:
        try:
            ip = ipaddress.ip_address(server_ip)
            if ip not in wg or ip in (wg.network_address, wg.broadcast_address):
                errors.append(f"the gateway address {ip} must be a host address of the WireGuard pool {wg}")
        except ValueError:
            errors.append(f"the gateway address {server_ip!r} is not an IPv4 address")

    link = None
    if settings.get("split"):
        try:
            link = _network(settings.get("link_network", ""), "site link network")
            if link.prefixlen > 30:
                errors.append(f"site link network: {link} needs at least two host addresses (/30 or larger)")
            for label, net in pools.items():
                if link.overlaps(net):
                    errors.append(f"the site link network {link} overlaps the {label} {net}")
        except ValueError as exc:
            errors.append(str(exc))

    for raw in _list(settings.get("corp_cidrs")):
        try:
            net = _network(raw, "corporate range")
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if net.prefixlen == 0:
            errors.append(f"corporate range: {net} would route everything; list the corporate networks instead")
            continue
        for label, pool_net in pools.items():
            if net.overlaps(pool_net):
                errors.append(f"corporate range {net} overlaps the {label} {pool_net}")
        if link and net.overlaps(link):
            errors.append(f"corporate range {net} overlaps the site link network {link}")

    for raw in _list(settings.get("dns_servers")):
        try:
            if ipaddress.ip_address(raw).version != 4:
                raise ValueError
        except ValueError:
            errors.append(f"DNS server {raw!r} is not an IPv4 address (VPN clients need resolver addresses, not names)")

    for key, label in (("trusted_proxy_cidrs", "trusted proxy range"),
                       ("local_allowed_cidrs", "break-glass sign-in range"),
                       ("forward_deny_cidrs", "forward deny range")):
        for raw in _list(settings.get(key)):
            try:
                _network(raw, label, version=None)
            except ValueError as exc:
                errors.append(str(exc))
    return errors


class FilterModule:
    def filters(self):
        return {
            "corpvpn_host": host,
            "corpvpn_host_cidr": host_cidr,
            "corpvpn_prefixlen": prefixlen,
            "corpvpn_prefix3": prefix3,
            "corpvpn_mirror": mirror,
            "corpvpn_containing": containing,
            "corpvpn_plan_errors": plan_errors,
        }
