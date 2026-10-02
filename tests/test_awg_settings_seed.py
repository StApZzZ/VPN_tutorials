"""awg_settings.seed_from_json — first-install seeding of awg.db from Ansible's JSON."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "panel"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import awg_settings  # noqa: E402
import config  # noqa: E402
import db  # noqa: E402


def _payload(**overrides):
    base = {
        "endpoint_host": "vpn.example.com",
        "endpoint_port": "51821",
        "dns_servers": "10.0.0.53",
        "persistent_keepalive": 25,
        "Jc": 4, "Jmin": 40, "Jmax": 70,
        "S1": 50, "S2": 50, "S3": 0, "S4": 0,
        "H1": 1, "H2": 2, "H3": 3, "H4": 4,
        "I1": "", "I2": "", "I3": "", "I4": "", "I5": "",
    }
    base.update(overrides)
    return base


class SeedFromJsonTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.original_db = config.AWG_DB_PATH
        config.AWG_DB_PATH = str(Path(self.tmp.name) / "awg.db")
        self.json_path = Path(self.tmp.name) / "awg_settings.json"

    def tearDown(self):
        config.AWG_DB_PATH = self.original_db
        db.dispose_all_engines()
        self.tmp.cleanup()

    def _write(self, **overrides):
        self.json_path.write_text(json.dumps(_payload(**overrides)), encoding="utf-8")

    def test_seeds_empty_store_and_coerces_ints(self):
        self._write()
        self.assertFalse(awg_settings.is_configured())
        self.assertTrue(awg_settings.seed_from_json(str(self.json_path)))
        loaded = awg_settings.load_settings()
        self.assertEqual(loaded["endpoint_host"], "vpn.example.com")
        self.assertEqual(loaded["endpoint_port"], 51821)
        self.assertEqual(loaded["Jc"], 4)

    def test_never_overwrites_live_settings_without_force(self):
        self._write()
        awg_settings.seed_from_json(str(self.json_path))
        # A later deploy renders different obfuscation params: they must NOT land,
        # distributed clients depend on the live ones.
        self._write(Jc=9, endpoint_host="other.example.com")
        self.assertFalse(awg_settings.seed_from_json(str(self.json_path)))
        self.assertEqual(awg_settings.load_settings()["Jc"], 4)
        self.assertTrue(awg_settings.seed_from_json(str(self.json_path), force=True))
        self.assertEqual(awg_settings.load_settings()["Jc"], 9)

    def test_rejects_missing_endpoint(self):
        self._write(endpoint_host="")
        with self.assertRaises(awg_settings.AwgSettingsValidationError):
            awg_settings.seed_from_json(str(self.json_path))
        self.assertFalse(awg_settings.is_configured())


if __name__ == "__main__":
    unittest.main()
