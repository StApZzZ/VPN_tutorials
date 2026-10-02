"""Tests for protocol_stats — the panel's live VLESS /metrics collector."""

import sys
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "panel"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import config  # noqa: E402
import protocol_stats as ps  # noqa: E402


class FakeClock:
    def __init__(self, t: float = 0.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def _samples(collector) -> dict:
    """name -> {label-tuple: value} across everything a collector yields."""
    out: dict = {}
    for family in collector.collect():
        for sample in family.samples:
            key = tuple(sorted(sample.labels.items()))
            out.setdefault(sample.name, {})[key] = sample.value
    return out


class ParseXrayExpvarTests(unittest.TestCase):
    def test_nested_stats(self):
        payload = {
            "stats": {
                "user": {
                    "alice@x": {"uplink": 100, "downlink": 200},
                    "bob@x": {"uplink": 5, "downlink": 0},
                },
                "inbound": {"vless-in": {"uplink": 1000, "downlink": 2000}},
            }
        }
        snap = ps.parse_xray_expvar(payload)
        self.assertEqual(snap.users["alice@x"], (100, 200))
        self.assertEqual(snap.users["bob@x"], (5, 0))
        self.assertEqual(snap.inbounds["vless-in"], (1000, 2000))

    def test_missing_directions_coerce_to_zero(self):
        snap = ps.parse_xray_expvar({"stats": {"user": {"c@x": {"uplink": 7}}}})
        self.assertEqual(snap.users["c@x"], (7, 0))

    def test_garbage_inputs(self):
        self.assertEqual(ps.parse_xray_expvar(None).users, {})
        self.assertEqual(ps.parse_xray_expvar({"stats": "nope"}).users, {})
        self.assertEqual(ps.parse_xray_expvar({}).inbounds, {})


class ActivityOnlineTrackerTests(unittest.TestCase):
    def test_activity_marks_online_within_window(self):
        tracker = ps.ActivityOnlineTracker(window_seconds=100)
        # First observation establishes a baseline; nobody is online yet.
        self.assertEqual(tracker.update({"a": 10}, now=0), set())
        # Total rose -> active now.
        self.assertEqual(tracker.update({"a": 25}, now=10), {"a"})
        # No change, still inside the 100s window -> stays online.
        self.assertEqual(tracker.update({"a": 25}, now=90), {"a"})
        # Window elapsed with no new activity -> drops offline.
        self.assertEqual(tracker.update({"a": 25}, now=200), set())

    def test_counter_reset_is_not_activity(self):
        tracker = ps.ActivityOnlineTracker(window_seconds=100)
        tracker.update({"a": 500}, now=0)
        # Xray restarted -> counter dropped; must NOT be read as activity.
        self.assertEqual(tracker.update({"a": 3}, now=5), set())
        # A genuine post-reset increase re-arms it.
        self.assertEqual(tracker.update({"a": 40}, now=6), {"a"})

    def test_vanished_key_ages_out(self):
        tracker = ps.ActivityOnlineTracker(window_seconds=50)
        tracker.update({"a": 1}, now=0)
        tracker.update({"a": 5}, now=1)  # a online
        tracker.update({}, now=100)  # a gone from previous implementation and stale
        self.assertNotIn("a", tracker._last_active)


class ResolveLabelsTests(unittest.TestCase):
    def test_unique_name_used(self):
        labels = ps.resolve_labels(["e1", "e2"], {"e1": "alice", "e2": "bob"})
        self.assertEqual(labels, {"e1": "alice", "e2": "bob"})

    def test_duplicate_name_falls_back_to_key(self):
        labels = ps.resolve_labels(["e1", "e2"], {"e1": "dup", "e2": "dup"})
        self.assertEqual(labels, {"e1": "e1", "e2": "e2"})

    def test_missing_name_falls_back_to_key(self):
        self.assertEqual(ps.resolve_labels(["e1"], {}), {"e1": "e1"})


class VlessStatsCollectorTests(unittest.TestCase):
    def setUp(self):
        self.names = mock.patch.object(
            ps, "_client_name_maps", return_value=({"a@x": "alice", "b@x": "bob"}, {})
        )
        self.count = mock.patch.object(ps, "_configured_client_count", return_value=5)
        # Per-client series are gated by METRICS_PEER_DETAIL. These tests are about
        # the traffic/online/caching mechanics, so detail is switched on here;
        # the gate itself is covered by test_per_client_series_need_peer_detail.
        self.opt_in = mock.patch.object(config, "METRICS_PEER_DETAIL", True)
        self.names.start()
        self.count.start()
        self.opt_in.start()
        self.addCleanup(self.names.stop)
        self.addCleanup(self.count.stop)
        self.addCleanup(self.opt_in.stop)

    def test_emits_traffic_and_online(self):
        box = {
            "v": {
                "stats": {
                    "user": {"a@x": {"uplink": 100, "downlink": 200}, "b@x": {"uplink": 0, "downlink": 0}},
                    "inbound": {"vless-in": {"uplink": 1000, "downlink": 2000}},
                }
            }
        }
        clock = FakeClock(1000.0)
        col = ps.VlessStatsCollector(
            fetcher=lambda: box["v"], clock=clock, online_window_seconds=120, min_refresh_seconds=10
        )

        first = _samples(col)
        self.assertEqual(first["vless_stats_up"][()], 1.0)
        self.assertEqual(first["vless_clients_configured"][()], 5.0)
        self.assertEqual(first["vless_clients_online"][()], 0.0)  # no baseline yet
        self.assertEqual(first["vless_client_uplink_bytes_total"][(("client", "alice"),)], 100.0)
        self.assertEqual(first["vless_client_downlink_bytes_total"][(("client", "alice"),)], 200.0)
        self.assertEqual(first["vless_inbound_uplink_bytes_total"][(("inbound", "vless-in"),)], 1000.0)

        # A later scrape past the refresh window with more bytes -> alice online.
        box["v"]["stats"]["user"]["a@x"] = {"uplink": 100, "downlink": 500}
        clock.t = 1015.0
        second = _samples(col)
        self.assertEqual(second["vless_clients_online"][()], 1.0)
        self.assertEqual(second["vless_client_online"][(("client", "alice"),)], 1.0)
        self.assertEqual(second["vless_client_online"][(("client", "bob"),)], 0.0)
        self.assertEqual(second["vless_client_downlink_bytes_total"][(("client", "alice"),)], 500.0)

    def test_cache_skips_refetch_within_window(self):
        box = {"v": {"stats": {"user": {"a@x": {"uplink": 1, "downlink": 1}}}}}
        clock = FakeClock(100.0)
        col = ps.VlessStatsCollector(fetcher=lambda: box["v"], clock=clock, min_refresh_seconds=10)
        _samples(col)
        # Change previous implementation but advance the clock less than the min refresh interval.
        box["v"] = {"stats": {"user": {"a@x": {"uplink": 999, "downlink": 999}}}}
        clock.t = 105.0
        cached = _samples(col)
        self.assertEqual(cached["vless_client_uplink_bytes_total"][(("client", "alice"),)], 1.0)

    def test_fetch_failure_sets_down_and_skips_clients(self):
        def boom():
            raise RuntimeError("mesh unreachable")

        col = ps.VlessStatsCollector(fetcher=boom, clock=FakeClock(0.0), min_refresh_seconds=10)
        s = _samples(col)
        self.assertEqual(s["vless_stats_up"][()], 0.0)
        self.assertNotIn("vless_client_uplink_bytes_total", s)

    def test_per_client_series_need_peer_detail(self):
        payload = {"stats": {"user": {"a@x": {"uplink": 1, "downlink": 2}}, "inbound": {}}}
        with mock.patch.object(config, "METRICS_PEER_DETAIL", False):
            col = ps.VlessStatsCollector(fetcher=lambda: payload, clock=FakeClock(0.0))
            s = _samples(col)
        self.assertEqual(s["vless_stats_up"][()], 1.0)
        # Families are still declared, but carry no per-client samples.
        self.assertEqual(s.get("vless_client_uplink_bytes_total", {}), {})
        self.assertEqual(s.get("vless_client_online", {}), {})


if __name__ == "__main__":
    unittest.main()
