import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "amnezia-panel-src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

if "dotenv" not in sys.modules:
    dotenv_stub = types.ModuleType("dotenv")
    dotenv_stub.load_dotenv = lambda *args, **kwargs: None
    sys.modules["dotenv"] = dotenv_stub

try:
    import config
    import vpn_manager as vm

    SERVICE_DEPS_AVAILABLE = True
except ModuleNotFoundError:
    config = None
    vm = None
    SERVICE_DEPS_AVAILABLE = False


@unittest.skipUnless(SERVICE_DEPS_AVAILABLE, "panel dependencies are not installed")
class VpnManagerWireGuardOptionalTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.original_wg_config_path = config.WG_CONFIG_PATH
        self.original_wg_clients_table = config.WG_CLIENTS_TABLE
        self.original_client_private_keys_path = config.CLIENT_PRIVATE_KEYS_PATH
        self.original_wg_interface = config.WG_INTERFACE

        config.WG_CONFIG_PATH = str(Path(self.tmpdir.name) / "missing-wg0.conf")
        config.WG_CLIENTS_TABLE = str(Path(self.tmpdir.name) / "clientsTable")
        config.CLIENT_PRIVATE_KEYS_PATH = str(Path(self.tmpdir.name) / "clientsPrivateKeys.json")
        config.WG_INTERFACE = "wg0"

    def tearDown(self):
        config.WG_CONFIG_PATH = self.original_wg_config_path
        config.WG_CLIENTS_TABLE = self.original_wg_clients_table
        config.CLIENT_PRIVATE_KEYS_PATH = self.original_client_private_keys_path
        config.WG_INTERFACE = self.original_wg_interface
        self.tmpdir.cleanup()

    def test_get_all_peers_returns_empty_when_wg_config_is_missing(self):
        Path(config.WG_CLIENTS_TABLE).write_text(
            json.dumps(
                [
                    {
                        "clientId": "peer-1",
                        "clientName": "Alice",
                        "creationDate": "2026-05-05T00:00:00+00:00",
                        "userData": {"deactivated": False},
                    }
                ]
            ),
            encoding="utf-8",
        )

        with patch.object(vm, "_get_live_peers", return_value={}):
            self.assertEqual(vm.get_all_peers(), [])
            stats = vm.get_stats()

        self.assertEqual(stats.total_peers, 0)
        self.assertEqual(stats.total_online, 0)
        self.assertEqual(stats.never_connected, 0)
        self.assertEqual(stats.inactive, 0)


if __name__ == "__main__":
    unittest.main()
