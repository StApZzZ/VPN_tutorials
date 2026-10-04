"""vpn_manager: wg0.conf handling, address pools, backups and health."""
import json
import subprocess
from pathlib import Path

import pytest

import config
import vpn_manager as vm

SERVER_HEADER = """[Interface]
Address = 10.66.0.1/22
ListenPort = 51820
PrivateKey = c2VydmVy
"""


class FakeWgTool:
    """Stands in for vm._run: key generation works, the interface is absent."""

    def __init__(self, fail_show=True):
        self.calls = []
        self.fail_show = fail_show
        self.n = 0

    def __call__(self, cmd, input_text=None):
        self.calls.append(cmd)
        if cmd[:2] == ["wg", "genkey"]:
            self.n += 1
            return f"priv{self.n}\n"
        if cmd[:2] == ["wg", "pubkey"]:
            return f"pub-{input_text.strip()}=\n"
        if cmd[:2] == ["wg", "genpsk"]:
            return "psk\n"
        if "show" in cmd and self.fail_show:
            raise RuntimeError("Unable to access interface: No such device")
        return ""


@pytest.fixture
def wg_files(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "WG_CONFIG_PATH", str(tmp_path / "wg0.conf"))
    monkeypatch.setattr(config, "WG_CLIENTS_TABLE", str(tmp_path / "clientsTable"))
    monkeypatch.setattr(config, "CLIENT_PRIVATE_KEYS_PATH", str(tmp_path / "keys.json"))
    monkeypatch.setattr(config, "WG_PUBLIC_KEY_PATH", str(tmp_path / "wg0_public.key"))
    monkeypatch.setattr(config, "BACKUP_DIR", str(tmp_path / "backups"))
    monkeypatch.setattr(config, "WG_NETWORK", "10.66.0.0/22")
    monkeypatch.setattr(config, "WG_SERVER_IP", "10.66.0.1")
    monkeypatch.setattr(config, "AWG_NETWORK", "10.66.4.0/22")
    monkeypatch.setattr(config, "AWG_SERVER_IP", "10.66.4.1")
    (tmp_path / "wg0_public.key").write_text("c2VydmVyLXB1Yg==\n", encoding="utf-8")
    tool = FakeWgTool()
    monkeypatch.setattr(vm, "_run", tool)
    return tmp_path, tool


def _conf(tmp_path) -> str:
    return (tmp_path / "wg0.conf").read_text(encoding="utf-8")


# ------------------------------------------------------------- wg0.conf blocks
def test_compact_and_lowercase_blocks_are_suspended_and_deleted(wg_files):
    tmp_path, tool = wg_files
    (tmp_path / "wg0.conf").write_text(
        SERVER_HEADER
        + "\n[Peer]\nPublicKey=AAA=\nPresharedKey=psk1\nAllowedIPs=10.66.0.2/32\n"
        + "\n[peer]\npublickey = BBB=\npresharedkey = psk2\nallowedips = 10.66.0.3/32\n",
        encoding="utf-8",
    )
    vm.deactivate_peer("AAA=")
    text = _conf(tmp_path)
    assert "#corpvpn-off# PublicKey=AAA=" in text
    assert "\nPublicKey=AAA=" not in text                      # no longer active
    assert ["wg", "set", "wg0", "peer", "AAA=", "remove"] in tool.calls

    vm.delete_peer("BBB=")
    assert "BBB=" not in _conf(tmp_path)
    assert {p.public_key for p in vm.get_all_peers()} == set()  # clientsTable is empty
    assert vm._reserved_ips() == {vm.ipaddress.ip_address("10.66.0.1"), vm.ipaddress.ip_address("10.66.0.2")}


def test_resume_restores_config_lines_and_keeps_comments(wg_files):
    tmp_path, _ = wg_files
    original = (
        SERVER_HEADER
        + "\n[Peer]\n# Ivan's laptop\nPublicKey = AAA=\nPresharedKey = psk1\nAllowedIPs = 10.66.0.2/32\n"
        + "# printer in room 4\n"
    )
    (tmp_path / "wg0.conf").write_text(original, encoding="utf-8")
    vm.deactivate_peer("AAA=")
    vm.deactivate_peer("AAA=")                                  # idempotent
    vm.activate_peer("AAA=")
    lines = _conf(tmp_path).splitlines()
    assert "# Ivan's laptop" in lines and "# printer in room 4" in lines
    assert "Ivan's laptop" not in lines                         # a bare line breaks wg-quick
    assert "PublicKey = AAA=" in lines and "AllowedIPs = 10.66.0.2/32" in lines
    assert not any(line.startswith("#corpvpn-off#") for line in lines)


def test_blocks_suspended_by_older_panels_resume_without_touching_comments(wg_files):
    tmp_path, _ = wg_files
    (tmp_path / "wg0.conf").write_text(
        SERVER_HEADER
        + "\n# [Peer]\n# Ivan's laptop\n# PublicKey = CCC=\n# PresharedKey = psk3\n# AllowedIPs = 10.66.0.4/32\n",
        encoding="utf-8",
    )
    assert vm._reserved_ips() >= {vm.ipaddress.ip_address("10.66.0.4")}   # suspended keeps its address
    vm.activate_peer("CCC=")
    lines = _conf(tmp_path).splitlines()
    assert "[Peer]" in lines and "PublicKey = CCC=" in lines and "AllowedIPs = 10.66.0.4/32" in lines
    assert "# Ivan's laptop" in lines


def test_client_conf_reads_compact_blocks(wg_files):
    tmp_path, _ = wg_files
    (tmp_path / "wg0.conf").write_text(
        SERVER_HEADER + "\n[Peer]\nPublicKey=AAA=\nPresharedKey=psk1\nAllowedIPs=10.66.1.7/32\n",
        encoding="utf-8",
    )
    (tmp_path / "keys.json").write_text(json.dumps({"AAA=": "cHJpdg=="}), encoding="utf-8")
    conf = vm.get_client_conf("AAA=")
    assert "Address = 10.66.1.7/32" in conf and "PresharedKey = psk1" in conf


# ------------------------------------------------------------- address pools
def test_awg_addresses_follow_the_host_offset(wg_files, monkeypatch):
    assert vm.awg_address("10.66.0.7") == "10.66.4.7"
    assert vm.awg_address("10.66.3.254") == "10.66.7.254"     # past the first /24
    assert vm.awg_address("10.66.8.1") is None                  # outside the pool
    monkeypatch.setattr(config, "AWG_SERVER_PUBLIC_KEY", "")
    assert vm.awg_client_address("10.66.0.7") == "10.66.0.7"    # AWG as a wg0 alias
    monkeypatch.setattr(config, "AWG_SERVER_PUBLIC_KEY", "YXdnMA==")
    assert vm.awg_client_address("10.66.0.7") == "10.66.4.7"
    assert vm.awg_client_address("192.0.2.9") == "192.0.2.9"    # adopted from elsewhere


def test_existing_24_installs_keep_their_last_octet_mapping(wg_files, monkeypatch):
    monkeypatch.setattr(config, "WG_NETWORK", "10.67.0.0/24")
    monkeypatch.setattr(config, "AWG_NETWORK", config._next_pool("10.67.0.0/24"))
    assert config.AWG_NETWORK == "10.67.1.0/24"
    assert vm.awg_address("10.67.0.77") == "10.67.1.77"


def test_allocation_uses_the_whole_pool_and_skips_system_addresses(wg_files, monkeypatch):
    used = {vm.ipaddress.ip_address(f"10.66.0.{i}") for i in range(2, 256)}
    monkeypatch.setattr(vm, "_peer_addresses", lambda: used)
    assert vm._next_ip() == "10.66.1.0"                         # a host address of a /22
    monkeypatch.setattr(vm, "_peer_addresses", lambda: set())
    monkeypatch.setattr(config, "AWG_SERVER_IP", "10.66.4.2")
    assert vm._next_ip() == "10.66.0.3"                         # .2 mirrors awg0's own address


def test_create_peer_allocates_from_the_pool(wg_files):
    tmp_path, _ = wg_files
    (tmp_path / "wg0.conf").write_text(SERVER_HEADER, encoding="utf-8")
    first = vm.create_peer("laptop")
    second = vm.create_peer("phone")
    assert (first["ip"], second["ip"]) == ("10.66.0.2", "10.66.0.3")
    peers = {p.name: p for p in vm.get_all_peers()}
    assert peers["phone"].vpn_ip == "10.66.0.3"
    assert peers["phone"].last_handshake is None and peers["phone"].status == "never"


def test_pool_usage(wg_files, monkeypatch):
    monkeypatch.setattr(vm, "_peer_addresses", lambda: {vm.ipaddress.ip_address("10.66.0.2"),
                                                        vm.ipaddress.ip_address("192.0.2.1")})
    usage = vm.pool_usage()
    assert usage == {"network": "10.66.0.0/22", "awg_network": "10.66.4.0/22",
                     "size": 1021, "used": 1, "free": 1020}


@pytest.mark.parametrize("wg, awg, wg_ip, awg_ip, message", [
    ("10.66.0.0/22", "10.66.4.0/24", "10.66.0.1", "10.66.4.1", "same size"),
    ("10.66.0.0/22", "10.66.2.0/22", "10.66.0.1", "10.66.2.1", "must not overlap"),
    ("10.66.0.0/15", "10.68.0.0/15", "10.66.0.1", "10.68.0.1", "/16 to /30"),
    ("10.66.0.0/22", "10.66.4.0/22", "10.66.9.1", "10.66.4.1", "WG_SERVER_IP"),
    ("10.66.0.0/22", "10.66.4.0/22", "10.66.0.1", "10.66.4.0", "AWG_SERVER_IP"),
    ("not-a-net", "10.66.4.0/22", "10.66.0.1", "10.66.4.1", "WG_NETWORK"),
])
def test_pool_validation(monkeypatch, wg, awg, wg_ip, awg_ip, message):
    for name, value in (("WG_NETWORK", wg), ("AWG_NETWORK", awg), ("WG_SERVER_IP", wg_ip), ("AWG_SERVER_IP", awg_ip)):
        monkeypatch.setattr(config, name, value)
    with pytest.raises(RuntimeError, match=message):
        config.validate_network_config()


def test_default_pools_and_overlap_warnings(monkeypatch):
    assert config._next_pool("10.66.0.0/22") == "10.66.4.0/22"
    assert config._pool_host("10.66.0.0/22", 1) == "10.66.0.1"
    monkeypatch.setattr(config, "WG_NETWORK", "10.66.0.0/22")
    monkeypatch.setattr(config, "AWG_NETWORK", "10.66.4.0/22")
    monkeypatch.setattr(config, "SITE_LINK_NETWORK", "10.99.0.0/30")
    monkeypatch.setattr(config, "CORP_CIDRS", ("10.0.0.0/8", "10.66.2.0/24"))
    warnings = config.network_config_warnings()
    assert len(warnings) == 1 and "10.66.2.0/24" in warnings[0]   # a supernet is fine


# ------------------------------------------------------------- commands, backups
def test_hung_wg_command_becomes_an_error(monkeypatch):
    def hang(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

    monkeypatch.setattr(vm.subprocess, "run", hang)
    with pytest.raises(RuntimeError, match="timed out"):
        vm._run(["wg", "show", "wg0", "dump"])


def test_per_change_snapshots_are_pruned(wg_files, monkeypatch):
    tmp_path, _ = wg_files
    (tmp_path / "wg0.conf").write_text(SERVER_HEADER, encoding="utf-8")
    backups = tmp_path / "backups"
    (backups / "xray").mkdir(parents=True)
    (backups / "20250101_000000").mkdir()                       # older panel's naming
    (backups / "vpn-panel-20260101.tar.gz").write_bytes(b"daily")
    monkeypatch.setattr(config, "BACKUP_KEEP", 2)
    for _ in range(3):
        vm._backup()
    snapshots = sorted(p.name for p in backups.iterdir() if vm._SNAPSHOT_RE.fullmatch(p.name))
    assert len(snapshots) == 2 and "20250101_000000" not in snapshots
    assert (backups / "xray").is_dir() and (backups / "vpn-panel-20260101.tar.gz").exists()
    assert (backups / snapshots[-1] / "wg0.conf").exists()


def test_last_handshake_is_neutral_data():
    assert vm._fmt_handshake(0) is None
    assert vm._fmt_handshake(1767225600) == "2026-01-01T00:00:00Z"


# ------------------------------------------------------------------- health
def _health_tool(broken=()):
    def run(cmd, input_text=None):
        if any(name in cmd for name in broken):
            raise RuntimeError(f"{cmd[-1]} is down")
        return "ok\n"
    return run


def test_health_is_degraded_when_a_served_tunnel_is_down(wg_files, monkeypatch):
    monkeypatch.setattr(config, "ENABLED_PROTOCOLS", ("wg", "awg", "vless"))
    monkeypatch.setattr(config, "AWG_SERVER_PUBLIC_KEY", "")
    monkeypatch.setattr(vm, "_run", _health_tool())
    assert vm.health_check()["status"] == "ok"
    monkeypatch.setattr(vm, "_run", _health_tool(broken=("wg0",)))
    result = vm.health_check()
    assert result["status"] == "degraded" and "down" in result["checks"]["wg_interface"]

    monkeypatch.setattr(config, "AWG_SERVER_PUBLIC_KEY", "YXdnMA==")
    monkeypatch.setattr(vm, "_run", _health_tool(broken=("awg0",)))
    assert vm.health_check()["status"] == "degraded"
    monkeypatch.setattr(config, "ENABLED_PROTOCOLS", ("wg", "vless"))
    assert vm.health_check()["status"] == "ok"                  # AWG not served here


def test_vless_only_gateway_is_healthy_without_wireguard(wg_files, monkeypatch):
    monkeypatch.setattr(config, "ENABLED_PROTOCOLS", ("vless",))
    monkeypatch.setattr(vm, "_run", _health_tool(broken=("wg0", "--version")))
    assert vm.health_check()["status"] == "ok"


def test_get_all_peers_returns_empty_when_wg_config_is_missing(wg_files):
    tmp_path, _ = wg_files
    Path(config.WG_CLIENTS_TABLE).write_text(
        json.dumps([{"clientId": "peer-1", "clientName": "Alice", "creationDate": "2026-05-05T00:00:00+00:00",
                     "userData": {"deactivated": False}}]),
        encoding="utf-8",
    )
    assert vm.get_all_peers() == []
    stats = vm.get_stats()
    assert (stats.total_peers, stats.total_online, stats.never_connected, stats.inactive) == (0, 0, 0, 0)


@pytest.mark.parametrize("action", ["deactivate_peer", "delete_peer"])
def test_revocation_removes_awg_live_and_persisted_peers_before_return(wg_files, monkeypatch, action):
    tmp_path, tool = wg_files
    awg_conf = tmp_path / "awg0.conf"
    text = SERVER_HEADER + "\n[Peer]\nPublicKey=AAA=\nAllowedIPs=10.66.4.2/32\n" + "\n[Peer]\nPublicKey=BBB=\nAllowedIPs=10.66.4.3/32\n"
    (tmp_path / "wg0.conf").write_text(text)
    awg_conf.write_text(text)
    monkeypatch.setattr(config, "AWG_CONFIG_PATH", str(awg_conf))
    monkeypatch.setattr(config, "AWG_SERVER_PUBLIC_KEY", "separate-awg-key")
    monkeypatch.setattr(vm, "_awg_interface_live", lambda: True)
    getattr(vm, action)("AAA=")
    assert "AAA=" not in awg_conf.read_text() and "BBB=" in awg_conf.read_text()
    assert ["awg", "set", config.AWG_INTERFACE, "peer", "AAA=", "remove"] in tool.calls
    assert awg_conf.stat().st_mode & 0o777 == 0o600


def test_failed_awg_removal_is_reported(wg_files, monkeypatch):
    tmp_path, tool = wg_files
    monkeypatch.setattr(config, "AWG_CONFIG_PATH", str(tmp_path / "awg0.conf"))
    monkeypatch.setattr(config, "AWG_SERVER_PUBLIC_KEY", "separate-awg-key")
    monkeypatch.setattr(vm, "_awg_interface_live", lambda: True)
    (tmp_path / "wg0.conf").write_text(SERVER_HEADER)
    def fail(cmd, input_text=None):
        if cmd[:2] == ["awg", "set"]:
            raise RuntimeError("AWG removal failed")
        return tool(cmd, input_text)
    monkeypatch.setattr(vm, "_run", fail)
    with pytest.raises(RuntimeError, match="AWG removal failed"):
        vm.deactivate_peer("AAA=")
