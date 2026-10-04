"""Render the Ansible templates that carry logic with plain Jinja2
and check the output: the AmneziaWG peer mirror, NAT table, AWG interface block,
obfuscation generator, Xray seed config and the site link."""
import json
import re
import runpy
import subprocess
import sys
from pathlib import Path

import jinja2
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLES = ROOT / "deploy" / "ansible" / "roles"


def render(rel: str, **variables) -> str:
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(ROLES)), undefined=jinja2.StrictUndefined,
                             keep_trailing_newline=True, trim_blocks=True)  # Ansible's default
    env.filters["to_json"] = json.dumps
    env.tests["search"] = lambda value, pattern: re.search(pattern, str(value)) is not None
    env.tests["match"] = lambda value, pattern: re.match(pattern, str(value)) is not None
    return env.get_template(rel).render(ansible_managed="managed", **variables)


# ----------------------------------------------------------- AWG peer mirror
WG0 = """[Interface]
PrivateKey = c2VydmVy
Address = 10.66.0.1/24
ListenPort = 51820

[Peer]
PublicKey = AAAA
PresharedKey = PSK-A
AllowedIPs = 10.66.0.2/32

# [Peer]
# PublicKey = BBBB
# PresharedKey = PSK-B
# AllowedIPs = 10.66.0.3/32

[Peer]
PublicKey = CCCC
AllowedIPs = 10.66.0.4/32, 192.0.2.0/24
"""


@pytest.fixture
def peer_sync(tmp_path):
    conf_dir = tmp_path / "awg"
    conf_dir.mkdir()
    wg_dir = tmp_path / "wg"
    wg_dir.mkdir()
    source = render("awg_server/templates/awg-peer-sync.py.j2", awg_server_iface="awg0",
                    awg_server_wg_iface="wg0", awg_server_conf_dir=str(conf_dir).replace("\\", "/"),
                    awg_server_wg_network="10.66.0.0/24", awg_server_network="10.66.4.0/24")
    source = source.replace('"/etc/wireguard/wg0.conf"', repr(str(wg_dir / "wg0.conf")))
    script = tmp_path / "awg-peer-sync"
    script.write_text(source, encoding="utf-8")
    (conf_dir / "awg0_priv").write_text("QVdHLXByaXZhdGU=\n")
    (conf_dir / "awg0.iface").write_text("# managed\n[Interface]\nAddress = 10.66.4.1/24\nListenPort = 51821\nJc = 4\n")
    (wg_dir / "wg0.conf").write_text(WG0)
    return script, conf_dir / "awg0.conf"


def test_peer_mirror_skips_disabled_peers_and_rewrites_subnet(peer_sync):
    script, conf = peer_sync
    result = subprocess.run([sys.executable, str(script), "--no-apply"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    text = conf.read_text()
    assert "[Interface]\nPrivateKey = QVdHLXByaXZhdGU=\nAddress = 10.66.4.1/24" in text  # gitleaks:allow -- synthetic test fixture
    assert "PublicKey = AAAA\nPresharedKey = PSK-A\nAllowedIPs = 10.66.4.2/32" in text
    # The previous implementation script turned a commented-out (suspended) peer into an empty
    # [Peer] section, which made `awg syncconf` fail for everyone.
    assert "BBBB" not in text
    assert text.count("[Peer]") == 2
    assert "AllowedIPs = 10.66.4.4/32, 192.0.2.0/24" in text


def test_peer_mirror_is_idempotent(peer_sync):
    script, conf = peer_sync
    for _ in range(2):
        subprocess.run([sys.executable, str(script), "--no-apply"], check=True)
    first = conf.read_text()
    subprocess.run([sys.executable, str(script), "--no-apply"], check=True)
    assert conf.read_text() == first


# -------------------------------------------------------------- AWG server
def test_obfuscation_generator_respects_amneziawg_constraints(tmp_path, monkeypatch):
    target = tmp_path / "obfuscation.json"
    for _ in range(25):
        if target.exists():
            target.unlink()
        monkeypatch.setattr(sys, "argv", ["awg-gen-obfuscation", str(target)])
        with pytest.raises(SystemExit) as done:
            runpy.run_path(str(ROLES / "awg_server" / "files" / "awg-gen-obfuscation"), run_name="__main__")
        assert done.value.code == 0
        params = json.loads(target.read_text())
        assert 3 <= params["Jc"] <= 8 and params["Jmin"] < params["Jmax"] <= 1280
        assert params["S1"] + 56 != params["S2"] and max(params["S1"], params["S2"]) <= 1132
        headers = [params[f"H{i}"] for i in range(1, 5)]
        assert len(set(headers)) == 4 and min(headers) > 4


def test_obfuscation_generator_never_overwrites(tmp_path, monkeypatch):
    target = tmp_path / "obfuscation.json"
    target.write_text('{"Jc": 1}')
    monkeypatch.setattr(sys, "argv", ["awg-gen-obfuscation", str(target)])
    with pytest.raises(SystemExit):
        runpy.run_path(str(ROLES / "awg_server" / "files" / "awg-gen-obfuscation"), run_name="__main__")
    assert target.read_text() == '{"Jc": 1}'


def test_awg_interface_block_carries_every_obfuscation_param():
    params = {"Jc": 4, "Jmin": 40, "Jmax": 700, "S1": 20, "S2": 90, "H1": 11, "H2": 22, "H3": 33, "H4": 44}
    text = render("awg_server/templates/awg0.iface.j2", awg_server_iface="awg0", awg_server_wg_iface="wg0",
                  awg_server_address="10.66.4.1/24", awg_server_port=51821, awg_server_mtu=1420,
                  awg_server_obfuscation_effective=params)
    for key, value in params.items():
        assert f"\n{key} = {value}\n" in text
    assert "PrivateKey" not in text  # injected by awg-peer-sync from the key file


# ------------------------------------------------------------- WG server NAT
def test_nat_table_masquerades_clients_but_not_into_tunnels():
    text = render("wg_server/templates/corpvpn-nat.nft.j2",
                  wg_server_nat_exclude_ifaces=["wg0", "awg0", "wg-site"],
                  wg_server_client_nets=["10.66.0.0/24", "10.66.4.0/24"])
    assert "table inet corpvpn_nat\ndelete table inet corpvpn_nat\n" in text
    assert "flush ruleset" not in text
    assert ('ip saddr { 10.66.0.0/24, 10.66.4.0/24 } oifname != { "wg0", "awg0", "wg-site" } counter masquerade'
            in text)
    assert 'iifname { "wg0", "awg0", "wg-site" } tcp flags syn tcp option maxseg size set rt mtu' in text


# ------------------------------------------------------------- Xray seed
@pytest.mark.parametrize("egress", [False, True])
def test_xray_seed_config_is_valid_json_without_previous_implementation_leftovers(egress):
    cfg = json.loads(render("xray/templates/xray_base_config.json.j2",
        vpn_panel_xray_client_inbound_tag="vless-in", vpn_panel_xray_listen="127.0.0.1",
        vpn_panel_xray_port=8443, vpn_panel_xray_reality_dest="www.cloudflare.com:443",
        vpn_panel_xray_client_reality_server_name="www.cloudflare.com",
        vpn_panel_xray_direct_domain_strategy="UseIPv4",
        vpn_panel_xray_egress_outbounds=[{"tag":"to-egress","protocol":"freedom"}] if egress else []))
    assert [i["tag"] for i in cfg["inbounds"]] == ["vless-in"]
    inbound = cfg["inbounds"][0]
    assert inbound["listen"] == "127.0.0.1" and inbound["port"] == 8443
    assert inbound["streamSettings"]["sockopt"]["acceptProxyProtocol"] is True
    assert inbound["settings"]["clients"] == []
    assert inbound["streamSettings"]["realitySettings"]["privateKey"] == ""
    tags = [o["tag"] for o in cfg["outbounds"]]
    assert tags[:2] == ["direct", "block"] and ("to-egress" in tags) == egress
    assert "geoip:example" not in json.dumps(cfg)


# -------------------------------------------------------------- site link
SITE = {
    "site_link_iface": "wg-site", "site_link_port": 51830, "site_link_mtu": 1380, "site_link_keepalive": 25,
    "site_link_gateway_address": "10.99.0.1/30", "site_link_connector_address": "10.99.0.2/30",
    "site_link_corp_cidrs": ["10.0.0.0/8", "fd00::/8"], "site_link_client_nets": ["10.66.0.0/24", "10.66.4.0/24"],
    "site_link_gateway_endpoint": "", "site_link_lan_iface": "", "site_link_gateway_host": "gw",
    "site_link_connector_host": "conn", "ansible_default_ipv4": {"interface": "ens18"},
    "hostvars": {"gw": {"site_link_pubkey": {"stdout": "GWPUB="}, "ansible_host": "203.0.113.10"},
                 "conn": {"site_link_pubkey": {"stdout": "CONNPUB="}, "ansible_host": "10.1.1.5"}},
}


def test_site_link_configs_route_corporate_ranges_and_dial_out_from_the_connector():
    gateway = render("site_connector/templates/wg-site.conf.j2", site_link_side="gateway", **SITE)
    assert "ListenPort = 51830" in gateway and "Endpoint" not in gateway
    assert "AllowedIPs = 10.99.0.2/32, 10.0.0.0/8, fd00::/8" in gateway
    assert "PrivateKey" not in gateway.split("PostUp", 1)[0]  # key loaded from file
    connector = render("site_connector/templates/wg-site.conf.j2", site_link_side="connector", **SITE)
    assert "Endpoint = 203.0.113.10:51830" in connector and "PersistentKeepalive = 25" in connector
    assert "AllowedIPs = 10.99.0.1/32, 10.66.0.0/24, 10.66.4.0/24" in connector
    nft = render("site_connector/templates/site-link.nft.j2", site_link_side="connector", **SITE)
    assert "elements = { 10.0.0.0/8 }" in nft
    assert 'iifname "wg-site" ip daddr != @corp_v4 counter drop' in nft
    assert 'oifname "ens18" counter masquerade' in nft


# ------------------------------------------------------------- playbook
def test_site_playbook_installs_tunnels_before_the_panel():
    play = yaml.safe_load((ROOT / "deploy/ansible/site.yml").read_text())[0]
    roles = [r["role"] if isinstance(r,dict) else r for r in play["roles"]]
    assert roles == ["preflight", "common", "network_policy", "wg_server", "awg_server", "xray", "app", "nginx", "backup", "healthcheck", "smoke"]
    assert not play.get("vars")  # inventory must override role defaults


def test_connector_docker_pairs_use_the_configured_lan_and_default_fallback():
    tasks = yaml.safe_load((ROOT / "deploy/ansible/roles/site_connector/tasks/main.yml").read_text())
    task = next(item for item in tasks if item["name"] == "Site link | Docker integration on the connector")
    expression = task["vars"]["corpvpn_docker_user_pairs"]
    environment = jinja2.Environment(undefined=jinja2.StrictUndefined)
    for lan, expected in [("cvoffice0", "cvoffice0"), ("", "eth0")]:
        result = environment.from_string(expression).render(site_link_iface="wg-site", site_link_lan_iface=lan, ansible_default_ipv4={"interface": "eth0"})
        assert result == str([["wg-site", expected]])


def test_peer_mirror_takes_lock_before_reading_source(peer_sync):
    fcntl = pytest.importorskip("fcntl")
    script, conf = peer_sync
    source = script.read_text().replace("fcntl.flock(fd, fcntl.LOCK_EX)",
        "print('LOCK_WAIT', flush=True); fcntl.flock(fd, fcntl.LOCK_EX)")
    script.write_text(source)
    lock = conf.parent / ".corpvpn-peer-sync.lock"
    with lock.open("w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        child = subprocess.Popen([sys.executable, str(script), "--no-apply"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            assert child.stdout.readline().strip() == "LOCK_WAIT"
            assert child.poll() is None
            wg = script.parent / "wg/wg0.conf"
            wg.write_text(WG0.replace("PublicKey = AAAA", "PublicKey = REMOVED").replace(
                "[Peer]\nPublicKey = REMOVED\nPresharedKey = PSK-A\nAllowedIPs = 10.66.0.2/32",
                "# [Peer]\n# PublicKey = REMOVED\n# PresharedKey = PSK-A\n# AllowedIPs = 10.66.0.2/32"))
            fcntl.flock(held, fcntl.LOCK_UN)
            _, error = child.communicate(timeout=10)
            assert child.returncode == 0, error
            assert "REMOVED" not in conf.read_text()
            assert "CCCC" in conf.read_text()
        finally:
            if child.poll() is None:
                child.kill(); child.wait()
