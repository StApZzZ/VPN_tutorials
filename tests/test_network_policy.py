"""Access-profile network policy: client configs, nftables table, per-user Xray
rules, reload behaviour, portal and admin API."""
import json
import threading
import types
from pathlib import Path
from unittest import mock

import pytest

import config
import devices
import network_policy as np
import routing_overrides as ro
import xray_clients as xc
from auth import store
from device_support import admin_session, login_as, make_user

WG_CONF = """[Interface]
PrivateKey = cHJpdmF0ZQ==
Address = 10.66.0.5/32
DNS = 1.1.1.1, 1.0.0.1
Jc = 4

[Peer]
PublicKey = c2VydmVy
PresharedKey = cHNr
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""


def profile(**over):
    base = {"id": "p", "name": "Dev", "tunnel_mode": "full", "allowed_cidrs": [], "dns_servers": [],
            "search_domains": [], "protocols": ["wg", "awg", "vless"], "max_devices": 3, "device_ttl_days": 0}
    return {**base, **over}


@pytest.fixture(autouse=True)
def _policy_env(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "NETWORK_POLICY_MODE", "off")
    monkeypatch.setattr(config, "CORP_CIDRS", ())
    monkeypatch.setattr(config, "WG_NETWORK", "10.66.0.0/22")
    monkeypatch.setattr(config, "AWG_NETWORK", "10.66.4.0/22")
    monkeypatch.setattr(config, "WG_SERVER_IP", "10.66.0.1")
    monkeypatch.setattr(config, "AWG_SERVER_IP", "10.66.4.1")
    monkeypatch.setattr(config, "NETWORK_POLICY_CLIENT_ISOLATION", True)
    monkeypatch.setattr(config, "NETWORK_POLICY_DENY_CIDRS", ())
    monkeypatch.setattr(config, "SITE_LINK_NETWORK", "10.99.0.0/30")
    monkeypatch.setattr(config, "DNS_SERVERS", "1.1.1.1,1.0.0.1")
    monkeypatch.setattr(config, "NFT_POLICY_PATH", str(tmp_path / "nft" / "50-corpvpn-policy.nft"))
    monkeypatch.setattr(config, "XRAY_RELOAD_COMMAND", "")
    monkeypatch.setattr(np, "_state", {"applied_nft": None, "applied_at": "", "loaded": None, "xray_rules": None,
                                       "error": "", "checked_at": ""})


@pytest.fixture
def nft(monkeypatch):
    calls = []

    def fake_run(cmd):
        calls.append(cmd)
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(np, "_run", fake_run)
    monkeypatch.setattr(config, "NETWORK_POLICY_MODE", "enforce")
    return calls


def split_profile(name="Разработчики", cidrs=("10.20.0.0/16",), dns=("10.20.0.53",), search=("corp.example",)):
    return store.create_profile({"name": name, "tunnel_mode": "split", "allowed_cidrs": list(cidrs),
                                 "dns_servers": list(dns), "search_domains": list(search),
                                 "protocols": ["wg", "awg", "vless"], "max_devices": 3})


# ----------------------------------------------------------- client configs
def test_full_tunnel_config_keeps_catch_all_and_sets_profile_dns():
    out = np.client_conf(WG_CONF, profile(dns_servers=["10.0.0.53"], search_domains=["corp.example"]))
    assert "AllowedIPs = 0.0.0.0/0, ::/0\n" in out
    assert "DNS = 10.0.0.53, corp.example\n" in out
    assert "Jc = 4" in out and out.endswith("\n")


def test_split_tunnel_config_routes_allowed_subnets_and_dns_only():
    out = np.client_conf(WG_CONF, profile(tunnel_mode="split", allowed_cidrs=["10.20.0.0/16", "10.20.5.0/24"],
                                          dns_servers=["192.168.1.53"]))
    assert "AllowedIPs = 10.20.0.0/16, 192.168.1.53/32, ::/0\n" in out  # collapsed; resolver reachable
    assert "DNS = 192.168.1.53\n" in out
    assert "0.0.0.0/0" not in out


def test_search_domains_extend_the_existing_dns_when_profile_has_no_servers():
    out = np.client_conf(WG_CONF, profile(search_domains=["corp.example", "lab.corp.example"]))
    assert "DNS = 1.1.1.1, 1.0.0.1, corp.example, lab.corp.example\n" in out


def test_dns_line_is_added_when_the_config_has_none():
    conf = WG_CONF.replace("DNS = 1.1.1.1, 1.0.0.1\n", "")
    out = np.client_conf(conf, profile(dns_servers=["10.0.0.53"]))
    assert out.index("Address = 10.66.0.5/32\nDNS = 10.0.0.53\n") > 0


def test_vless_json_split_and_full():
    base = {"outbounds": [{"tag": "proxy"}, {"tag": "direct"}], "routing": {}}
    split = np.vless_client_config(base, profile(tunnel_mode="split", allowed_cidrs=["10.20.0.0/16"],
                                                 dns_servers=["10.20.0.53", "192.168.1.53"],
                                                 search_domains=["corp.example"]))
    rules = split["routing"]["rules"]
    assert rules[1] == {"type": "field", "ip": ["10.20.0.0/16", "192.168.1.53/32"], "outboundTag": "proxy"}
    assert rules[2] == {"type": "field", "domain": ["domain:corp.example"], "outboundTag": "proxy"}
    assert rules[-1]["outboundTag"] == "direct"
    assert split["dns"]["servers"][0] == {"address": "10.20.0.53", "domains": ["domain:corp.example"]}
    assert split["dns"]["servers"][-1] == "localhost"
    full = np.vless_client_config(base, profile(allowed_cidrs=["10.20.0.0/16"]))
    # Corporate ranges are private: they must win over geoip:private -> direct.
    assert [r["outboundTag"] for r in full["routing"]["rules"]] == ["block", "proxy", "direct", "proxy"]
    assert base["routing"] == {}  # input untouched


# ----------------------------------------------------------------- nftables
def test_nft_rendering_per_profile_and_default():
    groups = [
        np.Group(profile=profile(id="a", name="Dev «core»\n# injected", tunnel_mode="split",
                                 allowed_cidrs=["10.20.0.0/16", "fd00::/8"], dns_servers=["10.20.0.53"]),
                 addresses=["10.66.0.2", "10.66.4.2"], devices=1),
        np.Group(profile=profile(id="b", name="Office", allowed_cidrs=["10.30.0.0/16"]), addresses=[], devices=0),
    ]
    text = np.render_nft(groups, profile(id="d", name="Default"), ["10.0.0.0/8", "192.168.0.0/16", "fd00::/8"])
    assert text.startswith("#!/usr/sbin/nft -f\n")
    assert "table inet corpvpn_policy\ndelete table inet corpvpn_policy\ntable inet corpvpn_policy {" in text
    assert "flush ruleset" not in text
    assert "elements = { 10.0.0.0/8, 192.168.0.0/16 }" in text          # IPv6 left out
    assert "elements = { 10.66.0.2, 10.66.4.2 }" in text
    assert "elements = { 10.20.0.0/16 }" in text                         # DNS inside the subnet
    assert 'iifname != { "wg0", "awg0" } accept' in text
    assert "ip saddr @p1_clients ip daddr @p1_allowed accept" in text
    assert "ip saddr @p1_clients counter drop" in text                   # split
    assert "ip saddr @p2_clients accept" in text                         # full
    assert "set p2_clients {\n        type ipv4_addr\n    }" in text     # empty set: no elements clause
    assert "# injected" not in text and "\n# " not in text.split("{", 1)[1]
    assert text.rstrip().endswith("ip daddr @corp_v4 counter drop\n    }\n}")


def test_split_default_profile_drops_unknown_tunnel_addresses():
    text = np.render_nft([], profile(tunnel_mode="split", allowed_cidrs=["10.1.0.0/16"]), [])
    assert text.rstrip().endswith("        counter drop\n    }\n}")


def test_always_denied_destinations_come_before_any_profile(monkeypatch):
    monkeypatch.setattr(config, "NETWORK_POLICY_DENY_CIDRS", ("172.31.0.0/16",))
    wide_open = np.Group(profile=profile(id="a", allowed_cidrs=["0.0.0.0/0"]), addresses=["10.66.0.2"], devices=1)
    text = np.render_nft([wide_open], profile(id="d"), [])
    rules = text.split("chain forward {", 1)[1]
    assert rules.index("ip daddr @always_denied counter drop") < rules.index("@p1_allowed accept")
    denied = text.split("set always_denied {", 1)[1].split("}", 1)[0]
    for cidr in ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "100.100.100.200", "10.99.0.0/30",
                 "172.31.0.0/16", "224.0.0.0/3"):
        assert cidr in denied, cidr
    monkeypatch.setattr(config, "NETWORK_POLICY_DENY_CIDRS", ("nonsense",))
    with pytest.raises(np.NetworkPolicyError, match="NETWORK_POLICY_DENY_CIDRS"):
        np.denied_cidrs()


def test_clients_are_isolated_unless_their_profile_allows_a_pool(monkeypatch):
    groups = [
        np.Group(profile=profile(id="a", name="Staff"), addresses=["10.66.0.2"], devices=1),
        np.Group(profile=profile(id="b", name="Helpdesk", allowed_cidrs=["10.66.0.0/22", "10.66.4.0/22"]),
                 addresses=["10.66.0.3"], devices=1),
    ]
    text = np.render_nft(groups, profile(id="d"), [])
    assert "set client_pools {\n        type ipv4_addr\n        flags interval\n        auto-merge\n" \
           "        elements = { 10.66.0.0/21 }" in text             # the two adjacent pools
    rules = text.split("chain forward {", 1)[1]
    # Helpdesk's allowed set (the pools) is accepted before the isolation drop.
    assert rules.index("ip saddr @p2_clients ip daddr @p2_allowed accept") < \
        rules.index("ip saddr @p2_clients ip daddr @client_pools counter drop")
    assert "ip saddr @p1_clients ip daddr @client_pools counter drop" in rules
    assert rules.index("ip daddr @default_allowed accept") < rules.index("        ip daddr @client_pools counter drop")
    monkeypatch.setattr(config, "NETWORK_POLICY_CLIENT_ISOLATION", False)
    assert "client_pools" not in np.render_nft(groups, profile(id="d"), [])


def test_corporate_dns_stays_reachable_for_profiles_without_their_own(monkeypatch):
    monkeypatch.setattr(config, "DNS_SERVERS", "10.0.0.53")
    full, split = profile(), profile(tunnel_mode="split", allowed_cidrs=["10.20.0.0/16"])
    text = np.render_nft([], full, ["10.0.0.0/8"])
    assert "set default_dns {\n        type ipv4_addr\n        flags interval\n        auto-merge\n" \
           "        elements = { 10.0.0.53/32 }" in text              # accepted before corp_v4 drops it
    conf = np.client_conf(WG_CONF.replace("DNS = 1.1.1.1, 1.0.0.1", "DNS = 10.0.0.53"), split)
    assert "AllowedIPs = 10.0.0.53/32, 10.20.0.0/16, ::/0\n" in conf     # queries go through the tunnel


# --------------------------------------------------------------------- Xray
def test_xray_guard_is_the_first_rule_and_blocks_the_gateway_itself(wg, xray, monkeypatch):
    monkeypatch.setattr(config, "NETWORK_POLICY_DENY_CIDRS", ("172.31.0.0/16",))
    guard = np.xray_guard_rules()
    assert guard == [{"type": "field", "outboundTag": "block", "ip": guard[0]["ip"]}]
    for cidr in ("127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8", "10.66.0.1/32", "10.66.4.1/32", "10.99.0.0/30",
                 "172.31.0.0/16", "::1/128", "fe80::/10"):
        assert cidr in guard[0]["ip"], cidr
    # First even before a profile that allows everything.
    everything = store.create_profile({"name": "Everything", "tunnel_mode": "split", "allowed_cidrs": ["0.0.0.0/0"]})
    devices.create(make_user("root-ish", profile_id=everything["id"]), "Phone", "vless", actor="test")
    rules = ro.get_preview().rendered_routing["rules"]
    assert rules[0] == guard[0]
    assert ro.get_preview().routing_order[0].startswith("always denied")


def test_vless_isolation_follows_the_allowed_subnets():
    staff = np.Group(profile=profile(id="a", allowed_cidrs=["10.20.0.0/16"]), emails=["a@corpvpn"])
    helpdesk = np.Group(profile=profile(id="b", allowed_cidrs=["10.66.0.0/22"]), emails=["h@corpvpn"])
    rules = np.xray_rules([staff, helpdesk], profile(), [])
    pools = {"type": "field", "ip": ["10.66.0.0/21"], "outboundTag": "block"}
    assert rules[-1] == pools
    helpdesk_allowed = {"type": "field", "user": ["h@corpvpn"], "ip": ["10.66.0.0/22"],
                        "outboundTag": "direct"}
    assert rules.index(helpdesk_allowed) < rules.index(pools)


def test_xray_rules_only_when_something_can_be_dropped(monkeypatch):
    monkeypatch.setattr(config, "NETWORK_POLICY_CLIENT_ISOLATION", False)
    monkeypatch.setattr(config, "DNS_SERVERS", "")
    groups = [np.Group(profile=profile(allowed_cidrs=["10.20.0.0/16"]), emails=["a@corpvpn"])]
    assert np.xray_rules(groups, profile(), []) == []
    rules = np.xray_rules(groups, profile(), ["10.0.0.0/8"])
    assert rules == [
        {"type": "field", "user": ["a@corpvpn"], "ip": ["10.20.0.0/16"], "outboundTag": "direct"},
        {"type": "field", "user": ["a@corpvpn"], "ip": ["10.0.0.0/8"], "outboundTag": "block"},
        {"type": "field", "ip": ["10.0.0.0/8"], "outboundTag": "block"},
    ]
    split = [np.Group(profile=profile(tunnel_mode="split", allowed_cidrs=["10.20.0.0/16"]), emails=["b@corpvpn"])]
    assert np.xray_rules(split, profile(), [])[-1] == {
        "type": "field", "user": ["b@corpvpn"], "network": "tcp,udp", "outboundTag": "block"}


def test_preview_puts_profile_rules_before_geoip_private(wg, xray, monkeypatch):
    monkeypatch.setattr(config, "CORP_CIDRS", ("10.0.0.0/8",))
    dev = split_profile()
    user = make_user("olga", profile_id=dev["id"])
    device = devices.create(user, "Ноутбук", "vless", actor="test")
    email = xc.get_client(device["ref"]).email
    rules = ro.get_preview().rendered_routing["rules"]
    first_private = next(i for i, r in enumerate(rules) if r.get("ip") == ["geoip:private"])
    policy = rules[1:first_private]                                 # after the guard rule
    assert {"type": "field", "user": [email], "ip": ["10.20.0.0/16"], "outboundTag": "direct"} in policy
    assert {"type": "field", "user": [email], "network": "tcp,udp", "outboundTag": "block"} in policy
    assert policy[-1] == {"type": "field", "ip": ["10.0.0.0/8"], "outboundTag": "block"}
    assert ro.get_preview().routing_order[1].startswith("access profiles, client isolation")


def test_vless_create_applies_xray_once_and_cleans_up_on_failure(wg, xray):
    user = make_user("pavel")
    devices.create(user, "Phone", "vless", actor="test")
    assert xray.call_count == 1
    xray.side_effect = RuntimeError("xray down")
    with pytest.raises(RuntimeError):
        devices.create(user, "Tablet", "vless", actor="test")
    assert [d["name"] for d in store.list_devices(user_id=user["id"])] == ["Phone"]
    assert len(xc.list_clients()) == 1


def test_refresh_reapplies_xray_when_live_clients_drifted(wg, xray, monkeypatch, tmp_path):
    base = tmp_path / "config.json"
    base.write_text(json.dumps({"inbounds": [{"tag": config.XRAY_CLIENT_INBOUND_TAG, "settings": {"clients": []}}]}),
                    encoding="utf-8")
    monkeypatch.setattr(config, "XRAY_BASE_CONFIG_PATH", str(base))
    monkeypatch.setattr(config, "XRAY_RELOAD_COMMAND", "systemctl restart xray")
    np.refresh("startup")
    xray.reset_mock()
    np.refresh("periodic")
    assert xray.call_count == 0                                     # nothing changed, nothing drifted
    # A client enabled by another process (the directory-sync timer) or an apply
    # that failed half-way: the live config no longer matches the store.
    xc.create_client(name="changed elsewhere")
    np.refresh("periodic")
    assert xray.call_count == 1


# -------------------------------------------------------------------- apply
def test_refresh_loads_checked_file_once_and_reloads_on_change(wg, nft):
    dev = split_profile()
    user = make_user("anna", profile_id=dev["id"])

    def loads():
        return [c[1:3] for c in nft if "-f" in c]

    devices.create(user, "Laptop", "wg", actor="test")          # hook -> first load
    assert loads() == [["-c", "-f"], ["-f", config.NFT_POLICY_PATH + ".new"]]
    text = Path(config.NFT_POLICY_PATH).read_text(encoding="utf-8")
    assert "elements = { 10.66.0.2, 10.66.4.2 }" in text           # wg0 + awg0 mirror
    np.refresh("periodic")
    assert len(loads()) == 2                                        # unchanged -> no reload...
    assert ["nft", "-t", "list", "table", "inet", "corpvpn_policy"] in nft   # ...but the kernel is checked
    devices.create(user, "Desktop", "wg", actor="test")
    assert len(loads()) == 4
    assert "10.66.0.3" in Path(config.NFT_POLICY_PATH).read_text(encoding="utf-8")
    assert any(e["action"] == "network.policy.apply" for e in store.list_audit())


def test_a_table_flushed_from_the_kernel_is_loaded_again(wg, nft, monkeypatch):
    np.refresh("startup")
    assert np.status()["loaded"] is True
    calls = []

    def flushed(cmd):
        calls.append(cmd)
        return types.SimpleNamespace(returncode=1 if "list" in cmd else 0, stdout="", stderr="No such file")

    monkeypatch.setattr(np, "_run", flushed)
    np.refresh("periodic")
    assert [c[1] for c in calls] == ["-t", "-c", "-f"]              # checked, then dry run and load
    assert np.status()["loaded"] is True
    reasons = [e["details"].get("reason") for e in store.list_audit() if e["action"] == "network.policy.apply"]
    assert "table missing" in reasons


def test_failed_check_keeps_previous_file_and_reports(wg, nft, monkeypatch):
    np.refresh("first")
    good = Path(config.NFT_POLICY_PATH).read_text(encoding="utf-8")
    monkeypatch.setattr(np, "_run", lambda cmd: types.SimpleNamespace(returncode=1, stdout="", stderr="syntax error"))
    store.create_profile({"name": "Split", "tunnel_mode": "split", "allowed_cidrs": ["10.9.0.0/16"],
                          "protocols": ["wg"], "max_devices": 1})
    user = make_user("boris", profile_id=store.list_profiles()[-1]["id"])
    devices.create(user, "Laptop", "wg", actor="test")             # hook logs, never raises
    assert "syntax error" in np.status()["error"]
    assert Path(config.NFT_POLICY_PATH).read_text(encoding="utf-8") == good
    with pytest.raises(np.NetworkPolicyError):
        np.refresh("manual", force=True)


def test_mode_off_loads_nothing(wg, monkeypatch):
    calls = []
    monkeypatch.setattr(np, "_run", lambda cmd: calls.append(cmd))
    np.refresh("periodic")
    assert calls == []


def test_backend_lock_is_reentrant_and_exclusive():
    order = []
    with devices.backend_lock():
        with devices.backend_lock():
            order.append("nested")

        def contender():
            with devices.backend_lock():
                order.append("other")

        other = threading.Thread(target=contender)
        other.start()
        other.join(0.2)
        assert other.is_alive()                                     # blocked while we hold it
        order.append("release")
    other.join(2)
    assert not other.is_alive()
    assert order == ["nested", "release", "other"]


# --------------------------------------------------------------- portal/API
def test_portal_config_follows_the_profile_and_vless_json(client, wg, xray, monkeypatch):
    fake_art = types.SimpleNamespace(client_conf=WG_CONF)
    monkeypatch.setattr(devices.pa, "resolve_peer_artifact", lambda ref, protocol=None: fake_art)
    dev = split_profile()
    user = make_user("ivan", profile_id=dev["id"])
    h = login_as(client, user)
    peer = client.post("/api/me/devices", json={"name": "Laptop", "protocol": "wg"}, headers=h).json()
    conf = client.get(f"/api/me/devices/{peer['id']}/config").text
    assert "AllowedIPs = 10.20.0.0/16, ::/0\n" in conf
    assert "DNS = 10.20.0.53, corp.example\n" in conf
    vless = client.post("/api/me/devices", json={"name": "Phone", "protocol": "vless"}, headers=h).json()
    resp = client.get(f"/api/me/devices/{vless['id']}/config?variant=json")
    assert resp.status_code == 200 and resp.headers["content-type"].startswith("application/json")
    assert json.loads(resp.text)["routing"]["rules"][-1]["outboundTag"] == "direct"
    assert client.get(f"/api/me/devices/{vless['id']}/qr?variant=json").status_code == 400
    assert client.get(f"/api/me/devices/{vless['id']}/config?variant=zip").status_code == 400


def test_policy_api_is_admin_only_and_applies(client, wg, nft):
    login_as(client, make_user("eve", role="operator"))
    assert client.get("/api/network/policy").status_code == 403
    client.cookies.clear()
    ah = admin_session(client)
    info = client.get("/api/network/policy").json()
    assert info["mode"] == "enforce" and "table inet corpvpn_policy" in info["nft"]
    applied = client.post("/api/network/policy/apply", headers=ah)
    assert applied.status_code == 200, applied.text
    assert any(e["action"] == "network.policy.apply" and e["actor"] != "system" for e in store.list_audit())


def test_gateway_protocols_limit_what_employees_are_offered(client, wg, monkeypatch):
    monkeypatch.setattr(config, "ENABLED_PROTOCOLS", ("wg", "awg"))
    h = login_as(client, make_user("lena"))
    assert client.get("/api/me/devices").json()["profile"]["protocols"] == ["wg", "awg"]
    refused = client.post("/api/me/devices", json={"name": "Phone", "protocol": "vless"}, headers=h)
    assert refused.status_code == 400 and "not enabled on this gateway" in refused.json()["detail"]


def test_profile_change_refreshes_policy(client, wg, nft):
    ah = admin_session(client)
    before = len(nft)
    created = client.post("/api/profiles", json={"name": "Contractors", "tunnel_mode": "split",
                                                 "allowed_cidrs": ["10.50.0.0/24"], "protocols": ["wg"],
                                                 "max_devices": 1}, headers=ah)
    assert created.status_code == 201, created.text
    user = make_user("kate", profile_id=created.json()["id"])
    with mock.patch.object(np, "safe_refresh", wraps=np.safe_refresh) as spy:
        devices.create(user, "Laptop", "wg", actor="test")
        spy.assert_called_once_with("device.create")
    assert len(nft) > before


def test_client_ipv6_is_captured_and_blocked_in_every_profile():
    for mode in ("full", "split"):
        current = profile(tunnel_mode=mode, allowed_cidrs=["10.20.0.0/16"])
        assert "::/0" in np.client_allowed_ips(current)
        cfg = np.vless_client_config({"outbounds": [{"tag": "proxy"}, {"tag": "direct"}]}, current)
        assert cfg["routing"]["rules"][0] == {"type": "field", "ip": ["::/0"], "outboundTag": "block"}
        assert {"tag": "block", "protocol": "blackhole"} in cfg["outbounds"]


def test_profile_protocol_limits_apply_to_existing_credentials(monkeypatch):
    current = profile(protocols=["awg"])
    group = np.Group(profile=current, addresses=["10.66.0.2", "10.66.4.2"], emails=["device@corpvpn"])
    text = np.render_nft([group], profile(), [])
    assert 'ip saddr @p1_clients iifname "wg0" counter drop' in text
    assert text.index('iifname "wg0" counter drop') < text.index('ip saddr @p1_clients ip daddr @p1_allowed accept')
    assert "ct state established,related accept" not in text
    assert np.xray_rules([group], profile(), [])[0] == {"type": "field", "user": ["device@corpvpn"], "network": "tcp,udp", "outboundTag": "block"}


@pytest.mark.parametrize("port, expected", [(53, "direct"), (443, "block"), (853, "block"), (80, "block")])
def test_split_dns_exception_does_not_open_resolver_services(port, expected):
    import ipaddress
    group = np.Group(profile=profile(tunnel_mode="split", allowed_cidrs=["172.30.0.0/24"]), emails=["test@corpvpn"], addresses=["10.66.0.2"])
    rules = np.xray_rules([group], profile(), ["172.30.0.0/24"])
    def first_match():
        for rule in rules:
            if rule.get("user") and "test@corpvpn" not in rule["user"]:continue
            if rule.get("ip") and not any(ipaddress.ip_address("1.1.1.1") in ipaddress.ip_network(net) for net in rule["ip"]):continue
            if rule.get("port") and str(port) != rule["port"]:continue
            return rule["outboundTag"]
    assert first_match() == expected
    text = np.render_nft([group], profile(), ["172.30.0.0/24"])
    allowed_set = text.split("set p1_allowed {",1)[1].split("}",1)[0]
    assert "1.1.1.1" not in allowed_set
    assert "ip saddr @p1_clients ip daddr @p1_dns meta l4proto { tcp, udp } th dport 53 accept" in text
