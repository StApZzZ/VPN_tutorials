"""Tests for xray_manager._inject_stats_into_config — Xray stats/metrics injection."""

import sys
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "panel"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import config  # noqa: E402
import xray_manager as xm  # noqa: E402


class InjectStatsTests(unittest.TestCase):
    def test_disabled_is_noop(self):
        cfg = {"inbounds": []}
        with mock.patch.object(config, "XRAY_STATS_ENABLED", False), mock.patch.object(
            config, "XRAY_STATS_METRICS_LISTEN", "10.98.0.3:11111"
        ):
            xm._inject_stats_into_config(cfg)
        self.assertNotIn("stats", cfg)
        self.assertNotIn("metrics", cfg)

    def test_enabled_without_listen_is_noop(self):
        cfg = {"inbounds": []}
        with mock.patch.object(config, "XRAY_STATS_ENABLED", True), mock.patch.object(
            config, "XRAY_STATS_METRICS_LISTEN", ""
        ):
            xm._inject_stats_into_config(cfg)
        self.assertNotIn("metrics", cfg)

    def test_enabled_injects_stats_metrics_policy(self):
        cfg = {"inbounds": []}
        with mock.patch.object(config, "XRAY_STATS_ENABLED", True), mock.patch.object(
            config, "XRAY_STATS_METRICS_LISTEN", "10.98.0.3:11111"
        ):
            xm._inject_stats_into_config(cfg)
        self.assertEqual(cfg["stats"], {})
        self.assertEqual(cfg["metrics"], {"tag": "metrics", "listen": "10.98.0.3:11111"})
        level0 = cfg["policy"]["levels"]["0"]
        self.assertTrue(level0["statsUserUplink"])
        self.assertTrue(level0["statsUserDownlink"])
        self.assertTrue(cfg["policy"]["system"]["statsInboundUplink"])
        self.assertTrue(cfg["policy"]["system"]["statsInboundDownlink"])

    def test_preserves_existing_policy_levels(self):
        cfg = {"policy": {"levels": {"0": {"handshake": 4}}}}
        with mock.patch.object(config, "XRAY_STATS_ENABLED", True), mock.patch.object(
            config, "XRAY_STATS_METRICS_LISTEN", "10.98.0.3:11111"
        ):
            xm._inject_stats_into_config(cfg)
        # Existing tuning kept; stats flags added alongside it.
        self.assertEqual(cfg["policy"]["levels"]["0"]["handshake"], 4)
        self.assertTrue(cfg["policy"]["levels"]["0"]["statsUserUplink"])


if __name__ == "__main__":
    unittest.main()
