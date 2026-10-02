"""xray_manager apply safety: time limits, apply backups, file ownership, the
blackhole outbound and the REALITY check in the doctor."""
import json
import os
import subprocess
import types

import pytest

import config
import xray_clients as xc
import xray_manager as xm

# Throwaway pair from `xray x25519` (same vector as test_reality_keycheck).
PRIV = "QbRGc6jSp-hznXk4il9PYIc-Hacei4BjRYHRj6hRCCc"
PUB = "p-qt05yyhTjrGZXdHAjKgBS37JROhRD_aNdg6ZUZ2lE"
OK = types.SimpleNamespace(returncode=0, stdout="ok\n", stderr="")


@pytest.fixture
def xray_env(tmp_path, monkeypatch):
    base = tmp_path / "config.json"
    base.write_text(json.dumps({
        "inbounds": [{
            "tag": config.XRAY_CLIENT_INBOUND_TAG, "protocol": "vless", "listen": "127.0.0.1", "port": 8443,
            "settings": {"clients": []}, "sniffing": {"enabled": True},
            "streamSettings": {"sockopt": {"acceptProxyProtocol": True}, "realitySettings": {
                "privateKey": PRIV, "shortIds": ["abcd1234"], "serverNames": ["www.example.com"]}},
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }), encoding="utf-8")
    for name, value in (
        ("XRAY_BASE_CONFIG_PATH", str(base)),
        ("XRAY_MERGED_CONFIG_EXPORT_PATH", str(tmp_path / "config.generated.json")),
        ("XRAY_ROUTING_EXPORT_PATH", str(tmp_path / "routing.generated.json")),
        ("XRAY_ACTION_STATE_PATH", str(tmp_path / "state.json")),
        ("XRAY_APPLY_BACKUP_DIR", str(tmp_path / "backups")),
        ("XRAY_VALIDATE_COMMAND", "xray run -test -config {config_path}"),
        ("XRAY_RELOAD_COMMAND", "systemctl restart xray"),
        ("XRAY_PUSH_COMMAND", ""),
        ("XRAY_CLIENT_SERVER", "vpn.example.com"),
        ("XRAY_CLIENT_SECURITY", "reality"),
        ("XRAY_CLIENT_REALITY_PUBLIC_KEY", PUB),
        ("XRAY_CLIENT_REALITY_SHORT_ID", "abcd1234"),
        ("XRAY_CLIENT_REALITY_SERVER_NAME", "www.example.com"),
    ):
        monkeypatch.setattr(config, name, value)
    return base


def test_a_hung_reload_restores_the_live_config(xray_env, monkeypatch):
    before = xray_env.read_text(encoding="utf-8")
    xc.create_client(name="Kate")

    def run(cmd, **kwargs):
        if "restart" in cmd:
            raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])
        return OK

    monkeypatch.setattr(xm.subprocess, "run", run)
    with pytest.raises(xm.XrayCommandError, match="timed out"):
        xm.apply_xray()
    assert xray_env.read_text(encoding="utf-8") == before


def test_every_command_runs_with_a_time_limit(xray_env, monkeypatch):
    seen = []
    monkeypatch.setattr(config, "XRAY_PUSH_COMMAND", "rsync {merged_config_path} edge:/etc/xray/config.json")
    monkeypatch.setattr(config, "XRAY_COMMAND_TIMEOUT_SECONDS", 7)
    monkeypatch.setattr(xm.subprocess, "run", lambda cmd, **kwargs: seen.append(kwargs["timeout"]) or OK)
    xc.create_client(name="Kate")
    xm.apply_xray()
    assert seen == [7, 7, 7]                                        # push, validate, reload


def test_apply_backups_are_pruned(xray_env, monkeypatch):
    monkeypatch.setattr(config, "BACKUP_KEEP", 2)
    monkeypatch.setattr(xm.subprocess, "run", lambda cmd, **kwargs: OK)
    for index in range(4):
        xc.create_client(name=f"Device {index}")                    # a real change each time
        xm.apply_xray()
    kept = sorted(os.listdir(config.XRAY_APPLY_BACKUP_DIR))
    assert len(kept) == 2 and all(name.startswith("config.json.") for name in kept)


def test_promotion_keeps_mode_and_owner_of_the_live_config(xray_env, monkeypatch):
    os.chmod(xray_env, 0o640)
    owner = os.stat(xray_env)
    chowned = []
    monkeypatch.setattr(xm.os, "chown", lambda path, uid, gid: chowned.append((uid, gid)))
    monkeypatch.setattr(xm.subprocess, "run", lambda cmd, **kwargs: OK)
    xc.create_client(name="Kate")
    xm.apply_xray()
    assert os.stat(xray_env).st_mode & 0o777 == 0o640
    assert chowned == [(owner.st_uid, owner.st_gid)]
    live = json.loads(xray_env.read_text(encoding="utf-8"))
    inbound = live["inbounds"][0]                                   # listen / port / sockopt survive
    assert (inbound["listen"], inbound["port"]) == ("127.0.0.1", 8443)
    assert inbound["streamSettings"]["sockopt"] == {"acceptProxyProtocol": True}


def test_block_outbound_is_added_once(xray_env):
    assert [o["tag"] for o in xm.build_merged_config()["outbounds"]] == ["direct", "block"]
    cfg = json.loads(xray_env.read_text(encoding="utf-8"))
    cfg["outbounds"].append({"tag": "block", "protocol": "blackhole"})
    xray_env.write_text(json.dumps(cfg), encoding="utf-8")
    assert [o["tag"] for o in xm.build_merged_config()["outbounds"]] == ["direct", "block"]


def test_doctor_compares_the_links_with_the_live_reality_settings(xray_env, monkeypatch):
    checks = {c.id: c for c in xm.get_doctor_status().checks}
    assert checks["reality_keys"].status == "ok"
    monkeypatch.setattr(config, "XRAY_CLIENT_REALITY_SHORT_ID", "deadbeef")
    checks = {c.id: c for c in xm.get_doctor_status().checks}
    assert checks["reality_keys"].status == "error" and "shortIds" in checks["reality_keys"].detail
    assert xm.check_reality_keys().ok is False
    monkeypatch.setattr(config, "XRAY_CLIENT_SECURITY", "none")
    assert xm.check_reality_keys() is None


def test_client_json_carries_the_key_under_both_names(xray_env):
    client = xc.create_client(name="Kate")
    reality = xc.render_outbound_config(client)["streamSettings"]["realitySettings"]
    assert reality["publicKey"] == reality["password"] == PUB
