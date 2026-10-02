"""Tests for vpn_manager.get_vpn_status — wg0/awg0 interface + client link state."""

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "panel"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import config  # noqa: E402
import vpn_manager as vm  # noqa: E402

NOW = int(time.time())

PEER_ONLINE = "pk-online"
PEER_STALE = "pk-stale"
PEER_UNKNOWN = "pk-unknown"


def _dump(port: int, peers: list[tuple[str, int, int, int]], address: str = "10.66.0.5/32") -> str:
    lines = [f"srv-priv\tsrv-pub\t{port}\toff"]
    for pubkey, handshake, rx, tx in peers:
        lines.append(
            f"{pubkey}\tpsk\t203.0.113.9:5555\t{address}\t{handshake}\t{rx}\t{tx}\t25"
        )
    return "\n".join(lines) + "\n"


class GetVpnStatusTests(unittest.TestCase):
    def setUp(self):
        table = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        json.dump(
            [
                {
                    "clientId": PEER_ONLINE,
                    "clientName": "kate",
                    "creationDate": "2026-01-01T00:00:00+00:00",
                    "userData": {"deactivated": False},
                },
                {
                    "clientId": PEER_STALE,
                    "clientName": "bob",
                    "creationDate": "2026-01-02T00:00:00+00:00",
                    "userData": {"deactivated": True},
                },
            ],
            table,
        )
        table.close()
        self.addCleanup(Path(table.name).unlink)
        patcher = mock.patch.object(config, "WG_CLIENTS_TABLE", table.name)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _run_side_effect(self, wg_dump, awg_dump=None, awg_tool_missing=False):
        def fake_run(cmd, input_text=None):
            tool, _, iface, _ = cmd
            if tool == "awg" and awg_tool_missing:
                raise RuntimeError("awg: command not found")
            if iface == config.WG_INTERFACE:
                if wg_dump is None:
                    raise RuntimeError("no such device")
                return wg_dump
            if iface == config.AWG_INTERFACE:
                if awg_dump is None:
                    raise RuntimeError("no such device")
                return awg_dump
            raise AssertionError(f"unexpected command {cmd}")

        return fake_run

    def test_both_interfaces_up_and_client_links(self):
        wg_dump = _dump(51820, [(PEER_ONLINE, NOW - 30, 100, 200), (PEER_STALE, 0, 0, 0)])
        awg_dump = _dump(51821, [(PEER_ONLINE, NOW - 4000, 5, 7)], address="10.66.4.5/32")
        with mock.patch.object(config, "AWG_SERVER_PUBLIC_KEY", "srv-pub"), mock.patch.object(
            vm, "_run", side_effect=self._run_side_effect(wg_dump, awg_dump)
        ):
            status = vm.get_vpn_status()

        wg_iface, awg_iface = status.interfaces
        self.assertEqual(wg_iface.name, config.WG_INTERFACE)
        self.assertTrue(wg_iface.up)
        self.assertEqual(wg_iface.listen_port, 51820)
        self.assertEqual(wg_iface.peers_total, 2)
        self.assertEqual(wg_iface.peers_online, 1)
        self.assertEqual(wg_iface.peers_never, 1)
        self.assertEqual(wg_iface.transfer_rx, 100)
        self.assertEqual(wg_iface.transfer_tx, 200)

        self.assertEqual(awg_iface.name, config.AWG_INTERFACE)
        self.assertTrue(awg_iface.configured)
        self.assertTrue(awg_iface.up)
        self.assertEqual(awg_iface.peers_online, 0)
        self.assertEqual(awg_iface.peers_inactive, 1)

        by_key = {client.public_key: client for client in status.clients}
        kate = by_key[PEER_ONLINE]
        self.assertEqual(kate.name, "kate")
        self.assertEqual(kate.wg.status, "online")
        self.assertEqual(kate.awg.status, "inactive")
        self.assertEqual(kate.awg.vpn_ip, "10.66.4.5")
        # Neutral data for the UI to render in the viewer's language.
        self.assertRegex(kate.wg.last_handshake, r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        bob = by_key[PEER_STALE]
        self.assertTrue(bob.deactivated)
        self.assertEqual(bob.wg.status, "never")
        self.assertIsNone(bob.wg.last_handshake)
        self.assertIsNone(bob.awg)

    def test_awg_tool_missing_falls_back_to_wg(self):
        wg_dump = _dump(51820, [(PEER_ONLINE, NOW - 10, 1, 1)])
        awg_dump = _dump(51821, [(PEER_ONLINE, NOW - 10, 1, 1)], address="10.66.4.5/32")
        with mock.patch.object(
            vm, "_run", side_effect=self._run_side_effect(wg_dump, awg_dump, awg_tool_missing=True)
        ):
            status = vm.get_vpn_status()
        self.assertTrue(status.interfaces[1].up)
        self.assertEqual(status.interfaces[1].peers_online, 1)

    def test_missing_awg_interface_reports_down_without_breaking(self):
        wg_dump = _dump(51820, [(PEER_ONLINE, NOW - 10, 1, 1)])
        with mock.patch.object(config, "AWG_SERVER_PUBLIC_KEY", ""), mock.patch.object(
            vm, "_run", side_effect=self._run_side_effect(wg_dump, awg_dump=None)
        ):
            status = vm.get_vpn_status()
        awg_iface = status.interfaces[1]
        self.assertFalse(awg_iface.up)
        self.assertFalse(awg_iface.configured)
        self.assertIn("no such device", awg_iface.error)
        self.assertIsNone(status.clients[0].awg)
        self.assertEqual(status.clients[0].wg.status, "online")

    def test_unknown_live_peer_is_listed(self):
        wg_dump = _dump(
            51820,
            [(PEER_ONLINE, NOW - 10, 1, 1), (PEER_UNKNOWN, NOW - 20, 2, 2)],
        )
        with mock.patch.object(
            vm, "_run", side_effect=self._run_side_effect(wg_dump, awg_dump=None)
        ):
            status = vm.get_vpn_status()
        unknown = [c for c in status.clients if c.public_key == PEER_UNKNOWN]
        self.assertEqual(len(unknown), 1)
        self.assertEqual(unknown[0].name, "[Unknown]")
        self.assertEqual(unknown[0].wg.status, "online")


if __name__ == "__main__":
    unittest.main()
