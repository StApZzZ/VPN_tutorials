"""Shared pytest setup.

Every test gets its own copies of every panel store (identity, VLESS, routing,
AWG, config links), so state never leaks between tests and nothing is ever
written to /etc/vpn-panel. Tests that set their own paths still win.
"""
import sys
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parents[1] / "panel"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import config  # noqa: E402
import db  # noqa: E402
from auth import oidc, store  # noqa: E402
from auth.deps import limiter  # noqa: E402


@pytest.fixture
def wg(monkeypatch):
    """vpn_manager peer operations replaced by an in-memory FakeWG."""
    import types

    import devices
    import main
    from device_support import FakeWG

    fake = FakeWG()
    for name in ("create_peer", "activate_peer", "deactivate_peer", "delete_peer", "get_all_peers"):
        monkeypatch.setattr(devices.vm, name, getattr(fake, name))
    monkeypatch.setattr(main.vm, "get_all_peers", fake.get_all_peers)
    fake_art = types.SimpleNamespace(client_conf="[Interface]\nPrivateKey = x\n")
    monkeypatch.setattr(devices.pa, "resolve_peer_artifact", lambda ref, protocol=None: fake_art)
    return fake


@pytest.fixture
def xray(monkeypatch):
    """VLESS configured for share links; Xray apply is a Mock."""
    from unittest import mock

    import devices

    monkeypatch.setattr(config, "XRAY_CLIENT_SERVER", "vpn.example.com")
    monkeypatch.setattr(config, "XRAY_CLIENT_REALITY_PUBLIC_KEY", "pubkey")
    monkeypatch.setattr(config, "XRAY_CLIENT_REALITY_SHORT_ID", "abcd1234")
    apply = mock.Mock()
    monkeypatch.setattr(devices.xm, "apply_xray", apply)
    return apply


@pytest.fixture
def client(monkeypatch, wg):
    """TestClient with the break-glass admin enabled and SSO off."""
    from fastapi.testclient import TestClient

    import main
    from device_support import break_glass_config

    break_glass_config(monkeypatch)
    return TestClient(main.app)


@pytest.fixture(autouse=True)
def _isolated_identity_db(tmp_path, monkeypatch):
    for name in ("CORPVPN_DB_PATH", "VLESS_DB_PATH", "ROUTING_DB_PATH", "AWG_DB_PATH", "CONFIG_LINKS_DB_PATH"):
        monkeypatch.setattr(config, name, str(tmp_path / f"{name.lower()}.db"))
    for name in ("WG_CONFIG_PATH", "WG_CLIENTS_TABLE", "CLIENT_PRIVATE_KEYS_PATH", "WG_PUBLIC_KEY_PATH"):
        monkeypatch.setattr(config, name, str(tmp_path / name.lower()))
    monkeypatch.setattr(config, "LOCAL_DATA_KEY_PATH", str(tmp_path / "local-data.key"))
    monkeypatch.setattr(config, "PANEL_DATA_KEY", "")
    monkeypatch.setattr(config, "NETWORK_POLICY_MODE", "off")
    store.reset_schema_cache()
    limiter.reset()
    oidc.clear_cache()
    yield
    db.dispose_all_engines()
    store.reset_schema_cache()
