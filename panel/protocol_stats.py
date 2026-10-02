"""Live VLESS client/traffic metrics for the panel's /metrics endpoint.

The panel is the single Prometheus scrape target for the fleet, so — exactly like
the wg/awg ``VpnStatusCollector`` — this module re-exports live protocol stats it
pulls on each scrape:

  * VLESS: Xray's expvar endpoint (``metrics.listen`` -> ``/debug/vars``) exposes
    cumulative per-user and per-inbound uplink/downlink counters. Xray has no live
    session list, so a client is treated as "online" while it moves traffic within
    a sliding window (``XRAY_STATS_ONLINE_WINDOW_SECONDS``).

The endpoint lives on a private address; the panel polls it there.
Everything degrades safely: a fetch/parse failure yields ``*_stats_up 0`` and skips
the per-client series for that scrape rather than breaking the whole /metrics page.

The collectors are only registered when their URL is configured (see
``register_protocol_stats_collectors``), so deployments without the endpoints emit
nothing and are unaffected.
"""
from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional

from prometheus_client.core import GaugeMetricFamily

import config

logger = logging.getLogger("protocol-stats")

# Minimum seconds between previous implementation polls. collect() runs on every scrape (~15s);
# this caps the poll rate so several near-simultaneous scrapes don't stampede the
# edge endpoints while still refreshing well inside the online window.
_MIN_REFRESH_SECONDS = 10.0

JsonFetcher = Callable[[], object]
Clock = Callable[[], float]


# --------------------------------------------------------------------------- #
# HTTP helpers                                                                 #
# --------------------------------------------------------------------------- #
def http_get_json(url: str, timeout: float, headers: Optional[dict] = None) -> object:
    """GET ``url`` and parse the body as JSON. Raises on any transport/parse error."""
    request = urllib.request.Request(url, headers=headers or {}, method="GET")
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (mesh-only URL)
        charset = response.headers.get_content_charset() or "utf-8"
        return json.loads(response.read().decode(charset))


# --------------------------------------------------------------------------- #
# Parsing                                                                      #
# --------------------------------------------------------------------------- #
@dataclass
class XraySnapshot:
    # email/tag -> (uplink_bytes, downlink_bytes), cumulative since Xray start.
    users: dict[str, tuple[int, int]] = field(default_factory=dict)
    inbounds: dict[str, tuple[int, int]] = field(default_factory=dict)


def _coerce_int(value: object) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def parse_xray_expvar(payload: object) -> XraySnapshot:
    """Extract per-user and per-inbound uplink/downlink from Xray's /debug/vars.

    Xray publishes ``stats`` as a nested object (counter names split on ``>>>``):
    ``{"user": {"<email>": {"uplink": N, "downlink": N}}, "inbound": {...}}``.
    """
    snapshot = XraySnapshot()
    if not isinstance(payload, dict):
        return snapshot
    stats = payload.get("stats")
    if not isinstance(stats, dict):
        return snapshot

    def _collect(section: object) -> dict[str, tuple[int, int]]:
        out: dict[str, tuple[int, int]] = {}
        if not isinstance(section, dict):
            return out
        for key, directions in section.items():
            if not isinstance(directions, dict):
                continue
            out[str(key)] = (
                _coerce_int(directions.get("uplink")),
                _coerce_int(directions.get("downlink")),
            )
        return out

    snapshot.users = _collect(stats.get("user"))
    snapshot.inbounds = _collect(stats.get("inbound"))
    return snapshot


# --------------------------------------------------------------------------- #
# Online-by-activity tracker (VLESS has no live session list)                  #
# --------------------------------------------------------------------------- #
class ActivityOnlineTracker:
    """Marks a key online while its cumulative total keeps rising within a window.

    Fed the per-key cumulative byte total on every poll. A key is "online" if its
    total increased at some point within the last ``window`` seconds. A counter
    reset (total drops, e.g. Xray restart) is absorbed without a false activity
    mark; the next genuine increase re-arms it.
    """

    def __init__(self, window_seconds: float) -> None:
        self.window_seconds = window_seconds
        self._totals: dict[str, int] = {}
        self._last_active: dict[str, float] = {}

    def update(self, totals: dict[str, int], now: float) -> set[str]:
        online: set[str] = set()
        for key, total in totals.items():
            previous = self._totals.get(key)
            if previous is not None and total > previous:
                self._last_active[key] = now
            self._totals[key] = total
            last = self._last_active.get(key)
            if last is not None and (now - last) <= self.window_seconds:
                online.add(key)

        # Forget keys that vanished from previous implementation (deleted clients) once they age
        # out of the window, so the maps don't grow without bound.
        stale = [
            key
            for key, last in self._last_active.items()
            if key not in totals and (now - last) > self.window_seconds
        ]
        for key in stale:
            self._last_active.pop(key, None)
            self._totals.pop(key, None)
        return online


# --------------------------------------------------------------------------- #
# Label resolution (raw stats key -> human client name, kept unique)           #
# --------------------------------------------------------------------------- #
def resolve_labels(keys, key_to_name: dict[str, str]) -> dict[str, str]:
    """Map each raw stats key to a display label.

    Uses the client's name when it resolves 1:1 (so a name shared by two clients,
    or a missing name, falls back to the raw key) — the label therefore stays
    unique per client and rate() series never silently merge.
    """
    name_counts: dict[str, int] = {}
    for key in keys:
        name = key_to_name.get(key)
        if name:
            name_counts[name] = name_counts.get(name, 0) + 1
    labels: dict[str, str] = {}
    for key in keys:
        name = key_to_name.get(key)
        labels[key] = name if name and name_counts.get(name) == 1 else key
    return labels


def _client_name_maps() -> tuple[dict[str, str], dict[str, str]]:
    """(email -> name, id -> name) for enabled+disabled VLESS clients, or empty on error."""
    email_to_name: dict[str, str] = {}
    id_to_name: dict[str, str] = {}
    try:
        import xray_clients as xc

        for client in xc.list_clients():
            if client.email:
                email_to_name[client.email] = client.name
            if client.id:
                id_to_name[client.id] = client.name
    except Exception:  # pragma: no cover - store errors must never break a scrape
        logger.exception("Could not load VLESS client names for stats labels")
    return email_to_name, id_to_name


def _configured_client_count() -> int:
    try:
        import xray_clients as xc

        return sum(1 for client in xc.list_clients() if client.enabled)
    except Exception:  # pragma: no cover
        logger.exception("Could not count VLESS clients")
        return 0


# --------------------------------------------------------------------------- #
# Collectors                                                                   #
# --------------------------------------------------------------------------- #
class VlessStatsCollector:
    """Exports live VLESS (Xray) client + inbound traffic on every /metrics scrape."""

    def __init__(
        self,
        fetcher: Optional[JsonFetcher] = None,
        clock: Clock = time.monotonic,
        online_window_seconds: Optional[float] = None,
        min_refresh_seconds: float = _MIN_REFRESH_SECONDS,
    ) -> None:
        self._fetcher = fetcher or self._default_fetcher
        self._clock = clock
        self._min_refresh = min_refresh_seconds
        self._tracker = ActivityOnlineTracker(
            online_window_seconds
            if online_window_seconds is not None
            else config.XRAY_STATS_ONLINE_WINDOW_SECONDS
        )
        self._lock = threading.Lock()
        self._fetched_at: Optional[float] = None
        self._up = False
        self._snapshot = XraySnapshot()
        self._online: set[str] = set()

    def _default_fetcher(self) -> object:
        return http_get_json(config.XRAY_STATS_URL, config.XRAY_STATS_TIMEOUT)

    def _refresh(self, now: float) -> None:
        try:
            snapshot = parse_xray_expvar(self._fetcher())
            self._up = True
            self._snapshot = snapshot
        except Exception:
            logger.warning("VLESS stats collection failed", exc_info=True)
            self._up = False
            self._snapshot = XraySnapshot()
        # Advance the online window even on failure (nothing new => nobody re-armed).
        totals = {
            email: up + down for email, (up, down) in self._snapshot.users.items()
        }
        self._online = self._tracker.update(totals, now)
        self._fetched_at = now

    def _maybe_refresh(self) -> None:
        with self._lock:
            now = self._clock()
            if self._fetched_at is None or (now - self._fetched_at) >= self._min_refresh:
                self._refresh(now)

    def collect(self):
        self._maybe_refresh()

        up = GaugeMetricFamily(
            "vless_stats_up",
            "Whether the last VLESS (Xray) stats scrape succeeded (1) or failed (0).",
        )
        up.add_metric([], 1.0 if self._up else 0.0)
        yield up

        configured = GaugeMetricFamily(
            "vless_clients_configured",
            "Number of enabled VLESS clients in the panel store.",
        )
        configured.add_metric([], float(_configured_client_count()))
        yield configured

        online_count = GaugeMetricFamily(
            "vless_clients_online",
            "VLESS clients that moved traffic within the online window.",
        )
        online_count.add_metric([], float(len(self._online)))
        yield online_count

        email_to_name, _ = _client_name_maps()
        labels = resolve_labels(self._snapshot.users.keys(), email_to_name)

        user_uplink = GaugeMetricFamily(
            "vless_client_uplink_bytes_total",
            "Cumulative bytes uploaded by a VLESS client since Xray start.",
            labels=("client",),
        )
        user_downlink = GaugeMetricFamily(
            "vless_client_downlink_bytes_total",
            "Cumulative bytes downloaded by a VLESS client since Xray start.",
            labels=("client",),
        )
        client_online = GaugeMetricFamily(
            "vless_client_online",
            "Whether a VLESS client moved traffic within the online window (1) or not (0).",
            labels=("client",),
        )
        # Per-user VLESS series follow the same METRICS_PEER_DETAIL switch as the
        # wg/awg peer traffic series. Aggregates above are unaffected.
        for email, (uplink, downlink) in self._snapshot.users.items():
            if not config.METRICS_PEER_DETAIL:
                break
            label = labels.get(email, email)
            user_uplink.add_metric([label], float(uplink))
            user_downlink.add_metric([label], float(downlink))
            client_online.add_metric([label], 1.0 if email in self._online else 0.0)
        yield user_uplink
        yield user_downlink
        yield client_online

        inbound_uplink = GaugeMetricFamily(
            "vless_inbound_uplink_bytes_total",
            "Cumulative uplink bytes per Xray inbound since Xray start.",
            labels=("inbound",),
        )
        inbound_downlink = GaugeMetricFamily(
            "vless_inbound_downlink_bytes_total",
            "Cumulative downlink bytes per Xray inbound since Xray start.",
            labels=("inbound",),
        )
        for tag, (uplink, downlink) in self._snapshot.inbounds.items():
            inbound_uplink.add_metric([tag], float(uplink))
            inbound_downlink.add_metric([tag], float(downlink))
        yield inbound_uplink
        yield inbound_downlink


def register_protocol_stats_collectors(registry) -> list:
    """Register the VLESS collector when it is configured. Returns the registered list.

    Only collectors whose previous implementation URL is set are registered, so a deployment that
    hasn't enabled a protocol's stats endpoint emits none of its metrics.
    """
    registered: list = []
    if config.XRAY_STATS_URL:
        collector = VlessStatsCollector()
        registry.register(collector)
        registered.append(collector)
        logger.info("VLESS stats collector registered (%s)", config.XRAY_STATS_URL)
    return registered
