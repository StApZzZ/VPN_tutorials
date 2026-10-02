"""
CorpVPN — FastAPI app for WireGuard / AmneziaWG / VLESS on the gateway.
Port: PANEL_PORT (default 8080), bind host: PANEL_HOST (loopback behind nginx).
Auth: see auth/ — server-side sessions (local break-glass, OIDC, LDAP) with
roles from directory groups; Bearer/Basic break-glass token for automation.

Handlers that touch wg, nft, Xray, the directory or the backend lock are plain
`def`: FastAPI runs them in its thread pool, so one slow call never stalls the
event loop (and with it every other request).
"""

import asyncio
import base64
import hashlib
import io
import json
import logging
import platform
import threading
import time
import zipfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Callable
from typing import Optional
from urllib.parse import quote

import qrcode
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    Counter,
    Histogram,
    generate_latest,
)
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily

import client_artifacts as ca
from auth import routes as auth_routes
from auth import local_routes
from auth import store as auth_store
from auth.deps import Principal, current_principal, require_admin
from auth.deps import require_operator as require_auth
import config
import i18n
import config_links as cl
import devices
import devices_routes
import network_policy
import peer_artifacts as pa
import protocol_stats as ps
import routing_overrides as ro
import vpn_manager as vm
import xray_clients as xc
import xray_manager as xm
from models import (
    ConfigLinkCreated,
    ConfigLinkRecord,
    CreateConfigLinkRequest,
    CreatePeerRequest,
    CreateRoutingOverrideRequest,
    CreateXrayClientRequest,
    Protocol,
    UpdatePeerRequest,
    UpdateRoutingOverrideRequest,
    UpdateXrayClientRequest,
)

try:  # a scrape-only API token when the auth package offers one
    from auth.deps import require_metrics
except ImportError:  # pragma: no cover - older auth package: admins only
    require_metrics = require_admin

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
VERSION = "2.0.0"


@asynccontextmanager
async def lifespan(_: FastAPI):
    config.validate_runtime_config()
    config.validate_network_config()
    for warning in config.network_config_warnings():
        logger.warning("network settings: %s", warning)
    seeded = auth_store.seed_policies_from_config()
    if seeded:
        logger.info("seeded %d group policies from AUTH_*_GROUPS", seeded)
    try:
        adopted = await asyncio.to_thread(devices.adopt_unmanaged)
        if adopted:
            logger.info("adopted %d existing peers / VLESS clients as unassigned devices", adopted)
    except Exception:
        logger.exception("device adoption at startup failed")
    # Load the access-profile policy before serving (nftables.service may have
    # flushed the ruleset at boot; the unit starts after it).
    await asyncio.to_thread(network_policy.safe_refresh, "startup")
    reality = await asyncio.to_thread(xm.check_reality_keys)
    if reality is not None and not reality.ok:
        logger.warning("VLESS links do not match the live Xray server: %s", reality.detail)
    cleanup_task = asyncio.create_task(_config_link_cleanup_loop())
    try:
        yield
    finally:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("config link cleanup task shutdown failed")


async def _config_link_cleanup_loop() -> None:
    """Housekeeping: purge expired one-shot config links, suspend expired
    devices, keep the network policy in line (profile changes at sign-in, peers
    made on the low-level pages, a table flushed from the kernel)."""
    interval = max(15, min(config.CONFIG_LINK_CLEANUP_INTERVAL_SECONDS, config.NETWORK_POLICY_REFRESH_SECONDS))
    while True:
        try:
            await asyncio.to_thread(cl.purge_expired)
        except Exception:
            logger.exception("config link cleanup failed")
        try:
            await asyncio.to_thread(devices.enforce_expiry)
        except Exception:
            logger.exception("device expiry enforcement failed")
        await asyncio.to_thread(auth_store.prune_audit)
        await asyncio.to_thread(network_policy.safe_refresh, "periodic")
        await asyncio.sleep(interval)


# The interactive API docs map every route for anyone who can reach the panel.
_API_DOCS = {} if config.API_DOCS_ENABLED else {"docs_url": None, "redoc_url": None, "openapi_url": None}
app = FastAPI(title="CorpVPN", version=VERSION, lifespan=lifespan, **_API_DOCS)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# --- static asset cache-busting ---------------------------------------------
# Templates reference assets as /static/app.js?v={{ asset_version('app.js') }}
# so that a deploy changes the URL itself. StaticFiles sends ETag +
# Last-Modified but no Cache-Control, so browsers fall back to *heuristic*
# freshness and can reuse a cached app.js for a long time without ever
# revalidating — that is why a freshly deployed UI kept not showing up. nginx
# now also sends `Cache-Control: no-cache` (roles/nginx/templates/
# vpn-panel.conf.j2), but headers only affect responses the browser actually
# asks for; copies already frozen in a cache are only evicted by a new URL.
# Both halves are needed.
#
# Keyed on (mtime_ns, size) instead of hashed once at import: the panel is
# restarted on deploy, so import-time would be enough in production, but
# `uvicorn --reload` (README, Local development) only re-imports on .py
# changes — editing app.js alone would keep serving the stale hash. The
# stat() per call is microseconds; the sha256 only re-runs when the file
# actually changed.
_ASSET_VERSION_FALLBACK = "0"
_asset_version_cache: dict[str, tuple[tuple[int, int], str]] = {}
_asset_version_unreadable: set[str] = set()


def asset_version(filename: str) -> str:
    """Short content hash of ``static/<filename>``, for cache-busting URLs.

    Exposed to Jinja as the global ``asset_version``; used as
    ``/static/app.js?v={{ asset_version('app.js') }}``.

    Never raises: a missing or unreadable file degrades to a constant (logged
    once per file) so a template render can't 500 over a query parameter.
    """
    path = BASE_DIR / "static" / filename
    try:
        stat = path.stat()
        key = (stat.st_mtime_ns, stat.st_size)
        cached = _asset_version_cache.get(filename)
        if cached is not None and cached[0] == key:
            return cached[1]
        digest = hashlib.sha256(path.read_bytes()).hexdigest()[:10]
    except OSError:
        if filename not in _asset_version_unreadable:
            _asset_version_unreadable.add(filename)
            logger.warning(
                "static asset %s is missing or unreadable; serving it without a "
                "cache-busting version",
                filename,
            )
        return _ASSET_VERSION_FALLBACK
    # Plain dict assignment, no lock: sync endpoints run in a threadpool, so two
    # threads can race here — but they compute the same digest for the same key
    # and dict get/set are atomic under the GIL, so the race is benign.
    _asset_version_cache[filename] = (key, digest)
    _asset_version_unreadable.discard(filename)
    return digest


templates.env.globals["asset_version"] = asset_version
templates.env.globals["_"] = i18n.translate
templates.env.globals["language"] = i18n.language
app.include_router(auth_routes.build_router(templates))
app.include_router(local_routes.build_router(templates))
app.include_router(devices_routes.build_router())

HTTP_REQUESTS_TOTAL = Counter(
    "vpn_panel_http_requests_total",
    "Total HTTP requests handled by the CorpVPN.",
    ("method", "path", "status_code"),
)
HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "vpn_panel_http_request_duration_seconds",
    "HTTP request duration for the CorpVPN.",
    ("method", "path"),
)


class VpnStatusCollector:
    """Exports live wg0/awg0 state on every /metrics scrape.

    Collection shells out to `wg`/`awg show <iface> dump` (a few ms); the
    Prometheus scrape interval is 15s, so the cost is negligible. Failures
    are logged and skipped so a broken interface never breaks the scrape.
    """

    def __init__(self) -> None:
        # Endpoint state for the opt-in change counters, keyed by (interface,
        # public_key). In-process only: counters reset when the panel restarts,
        # so dashboards use increase()/rate() instead of absolute thresholds.
        self._endpoints: dict[tuple[str, str], str] = {}
        self._endpoint_changes: dict[tuple[str, str], int] = {}
        self._endpoint_change_events: dict[tuple[str, str, str], int] = {}

    @staticmethod
    def _endpoint_parts(endpoint: str) -> Optional[tuple[str, str]]:
        """Return (IP, port) for wg/awg endpoint text without retaining either.

        WireGuard prints IPv4 as ``203.0.113.4:51820`` and IPv6 as
        ``[2001:db8::1]:51820``. Malformed/non-IP values are left unclassified
        rather than guessed; the overall endpoint-change counter still records
        those transitions.
        """
        host, separator, port = endpoint.rpartition(":")
        if not separator or not host or not port.isdigit():
            return None
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        if not host:
            return None
        try:
            host = str(ip_address(host))
        except ValueError:
            return None
        return host, port

    def collect(self):
        try:
            vpn_status = vm.get_vpn_status()
        except Exception:
            logger.exception("VPN status metrics collection failed")
            return

        # `configured` lets alerts skip interfaces the panel does not expect
        # (e.g. awg0 on a deployment without AWG_SERVER_PUBLIC_KEY).
        iface_up = GaugeMetricFamily(
            "vpn_interface_up",
            "Whether the VPN interface is readable (1) or down/unreadable (0).",
            labels=("interface", "protocol", "configured"),
        )
        iface_peers = GaugeMetricFamily(
            "vpn_interface_peers",
            "Number of peers on the VPN interface by handshake state.",
            labels=("interface", "protocol", "state"),
        )
        iface_transfer = GaugeMetricFamily(
            "vpn_interface_transfer_bytes_total",
            "Cumulative bytes transferred on the VPN interface since it came up.",
            labels=("interface", "protocol", "direction"),
        )
        peer_handshake = GaugeMetricFamily(
            "vpn_peer_last_handshake_seconds",
            "Seconds since the peer's last handshake (absent if never connected).",
            labels=("interface", "peer", "public_key"),
        )
        peer_online = GaugeMetricFamily(
            "vpn_peer_online",
            "Whether the peer handshaked within the online window (1) or not (0).",
            labels=("interface", "peer", "public_key"),
        )
        # --- Opt-in only, below this line -----------------------------------
        # Traffic volumes and endpoint changes are personal data, so they are exported
        # only when the operator enables METRICS_PEER_DETAIL (default off).
        # The two series above stay unconditional (online state and handshake
        # age are what connection alerts are built on).
        peer_transfer = GaugeMetricFamily(
            "vpn_peer_transfer_bytes_total",
            "Cumulative bytes transferred by an opted-in peer since the interface came up.",
            labels=("interface", "peer", "public_key", "direction"),
        )
        # The endpoint address itself is deliberately NOT a label: that would
        # put client IPs in Prometheus and create unbounded cardinality.
        peer_endpoint_changes = CounterMetricFamily(
            "vpn_peer_endpoint_changes_total",
            "Times an opted-in peer's endpoint changed since the panel started.",
            labels=("interface", "peer", "public_key"),
        )
        peer_endpoint_change_events = CounterMetricFamily(
            "vpn_peer_endpoint_change_events_total",
            "Endpoint changes by type for an opted-in peer since the panel started.",
            labels=("interface", "peer", "public_key", "change_type"),
        )

        for iface in vpn_status.interfaces:
            labels = (iface.name, iface.protocol.value)
            iface_up.add_metric(
                (*labels, "true" if iface.configured else "false"),
                1.0 if iface.up else 0.0,
            )
            for state, count in (
                ("online", iface.peers_online),
                ("inactive", iface.peers_inactive),
                ("never", iface.peers_never),
            ):
                iface_peers.add_metric((*labels, state), count)
            iface_transfer.add_metric((*labels, "rx"), iface.transfer_rx)
            iface_transfer.add_metric((*labels, "tx"), iface.transfer_tx)

        # Per-peer detail is a deployment-wide switch. Off => aggregates and
        # online/handshake only.
        detail = config.METRICS_PEER_DETAIL

        for client in vpn_status.clients:
            # Short pubkey keeps label sets unique when client names collide.
            key = client.public_key[:12]
            for link in (client.wg, client.awg):
                if link is None:
                    continue
                labels = (link.interface, client.name, key)
                peer_online.add_metric(labels, 1.0 if link.status == "online" else 0.0)
                if link.last_handshake_seconds is not None:
                    peer_handshake.add_metric(labels, link.last_handshake_seconds)

                if not detail:
                    continue
                peer_transfer.add_metric((*labels, "rx"), link.transfer_rx)
                peer_transfer.add_metric((*labels, "tx"), link.transfer_tx)
                # Count transitions, not the addresses themselves. A same-IP
                # port change is NAT/CGNAT rebinding, not proof of a network
                # switch. An IP change is roaming, but still cannot by itself
                # prove Wi-Fi<->cellular without ISP/ASN data. The first sighting
                # is not a change, so a stationary peer stays at zero.
                seen_key = (link.interface, client.public_key)
                if link.endpoint:
                    previous = self._endpoints.get(seen_key)
                    if previous is not None and previous != link.endpoint:
                        self._endpoint_changes[seen_key] = (
                            self._endpoint_changes.get(seen_key, 0) + 1
                        )
                        previous_parts = self._endpoint_parts(previous)
                        current_parts = self._endpoint_parts(link.endpoint)
                        if previous_parts is None or current_parts is None:
                            change_type = "unknown"
                        elif previous_parts[0] != current_parts[0]:
                            change_type = "ip"
                        else:
                            change_type = "port"
                        event_key = (*seen_key, change_type)
                        self._endpoint_change_events[event_key] = (
                            self._endpoint_change_events.get(event_key, 0) + 1
                        )
                    self._endpoints[seen_key] = link.endpoint
                peer_endpoint_changes.add_metric(
                    labels, float(self._endpoint_changes.get(seen_key, 0))
                )
                for change_type in ("ip", "port", "unknown"):
                    peer_endpoint_change_events.add_metric(
                        (*labels, change_type),
                        float(
                            self._endpoint_change_events.get(
                                (*seen_key, change_type), 0
                            )
                        ),
                    )

        yield iface_up
        yield iface_peers
        yield iface_transfer
        yield peer_handshake
        yield peer_online
        yield peer_transfer
        yield peer_endpoint_changes
        yield peer_endpoint_change_events


def _timestamp(value: str) -> Optional[float]:
    try:
        moment = auth_store.parse_iso(value)
    except ValueError:
        return None
    return moment.timestamp() if moment else None


class GatewayCollector:
    """CorpVPN state for alerting: build, devices, the address pool, the
    network policy and the directory-sync timer. A family whose source fails is
    skipped; the scrape never breaks."""

    # The directory-sync lookup scans the audit log: at most once a minute.
    _SYNC_CACHE_SECONDS = 60.0

    def __init__(self) -> None:
        self._sync: tuple[float, Optional[dict]] = (0.0, None)

    def _directory_sync(self) -> Optional[dict]:
        """Latest 'directory.sync' audit events: when the timer last ran and
        last ran without errors (None until the first recorded run)."""
        fetched_at, cached = self._sync
        now = time.monotonic()
        if fetched_at and now - fetched_at < self._SYNC_CACHE_SECONDS:
            return cached
        runs = [e for e in auth_store.list_audit(limit=50, action_prefix="directory.sync")
                if e["action"] == "directory.sync"]
        result = None
        if runs:
            success = next((e for e in runs if not e["details"].get("errors")), None)
            result = {"last_run": runs[0]["ts"], "last_success": success["ts"] if success else ""}
        self._sync = (now, result)
        return result

    def collect(self):
        build = GaugeMetricFamily("corpvpn_build_info", "CorpVPN build.", labels=("version", "python"))
        build.add_metric((VERSION, platform.python_version()), 1.0)
        yield build

        try:
            counts: dict[tuple[str, str], int] = {}
            for device in auth_store.list_devices(include_revoked=True):
                key = (device["status"], device["protocol"])
                counts[key] = counts.get(key, 0) + 1
            family = GaugeMetricFamily(
                "corpvpn_devices", "Devices by status and protocol.", labels=("status", "protocol")
            )
            for status in auth_store.DEVICE_STATUSES:
                for protocol in auth_store.DEVICE_PROTOCOLS:
                    family.add_metric((status, protocol), float(counts.get((status, protocol), 0)))
            yield family
        except Exception:
            logger.exception("device metrics collection failed")

        try:
            usage = vm.pool_usage()
            size = GaugeMetricFamily(
                "corpvpn_ip_pool_size", "Client addresses in the wg0 pool (awg0 mirrors it).", labels=("pool",)
            )
            free = GaugeMetricFamily("corpvpn_ip_pool_free", "Client addresses not handed out yet.", labels=("pool",))
            size.add_metric((usage["network"],), float(usage["size"]))
            free.add_metric((usage["network"],), float(usage["free"]))
            yield size
            yield free
        except Exception:
            logger.exception("address pool metrics collection failed")

        policy = network_policy.policy_state()
        enforced = GaugeMetricFamily(
            "corpvpn_network_policy_enforced",
            "1 when NETWORK_POLICY_MODE is enforce and the table was in the kernel at the last check.",
        )
        enforced.add_metric([], 1.0 if policy["mode"] == "enforce" and policy["loaded"] and not policy["error"] else 0.0)
        yield enforced
        failed = GaugeMetricFamily("corpvpn_network_policy_error", "1 when the last policy refresh failed.")
        failed.add_metric([], 1.0 if policy["error"] else 0.0)
        yield failed
        applied = _timestamp(policy["applied_at"])
        if applied is not None:
            last = GaugeMetricFamily(
                "corpvpn_network_policy_last_apply_timestamp_seconds",
                "When the panel last loaded the policy table into the kernel.",
            )
            last.add_metric([], applied)
            yield last

        try:
            sync = self._directory_sync()
        except Exception:
            logger.exception("directory sync metrics collection failed")
            sync = None
        if sync is not None:
            for name, key, text in (
                ("corpvpn_directory_sync_last_run_timestamp_seconds", "last_run",
                 "When the directory-sync timer last ran."),
                ("corpvpn_directory_sync_last_success_timestamp_seconds", "last_success",
                 "When the directory-sync timer last ran without errors (0: not among the last 50 runs)."),
            ):
                family = GaugeMetricFamily(name, text)
                family.add_metric([], _timestamp(sync[key]) or 0.0)
                yield family


REGISTRY.register(VpnStatusCollector())
REGISTRY.register(GatewayCollector())

# Live VLESS (Xray) client/traffic stats, re-exported on /metrics.
# The collector registers only when its stats URL is configured, so
# deployments without that endpoint emit nothing extra.
ps.register_protocol_stats_collectors(REGISTRY)

_METRIC_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})


def _metrics_path(request: Request) -> str:
    """The route template, never the raw URL: every unmatched URL an anonymous
    client makes up would otherwise become a new series (memory growth)."""
    route = request.scope.get("route")
    route_path = getattr(route, "path", None)
    if route_path:
        return route_path
    return "/static" if request.url.path.startswith("/static/") else "unmatched"


def _metrics_method(request: Request) -> str:
    return request.method if request.method in _METRIC_METHODS else "OTHER"


@app.middleware("http")
async def record_http_metrics(request: Request, call_next: Callable):
    start = time.perf_counter()
    status_code = "500"
    try:
        response = await call_next(request)
        status_code = str(response.status_code)
        return response
    finally:
        path, method = _metrics_path(request), _metrics_method(request)
        HTTP_REQUESTS_TOTAL.labels(method, path, status_code).inc()
        HTTP_REQUEST_DURATION_SECONDS.labels(method, path).observe(
            time.perf_counter() - start
        )
        await asyncio.to_thread(_audit_api_call, request, status_code)


# Routers that write their own, richer audit events.
_SELF_AUDITED = ("/api/auth/", "/api/me/", "/api/devices", "/api/profiles")


def _audit_api_call(request: Request, status_code: str) -> None:
    """Every state-changing API call is audited: who, what, from where, result."""
    if request.method in ("GET", "HEAD", "OPTIONS") or not request.url.path.startswith("/api/"):
        return
    if request.url.path.startswith(_SELF_AUDITED):
        return
    principal = getattr(request.state, "principal", None)
    if principal is None:
        return
    try:
        auth_store.audit(
            f"api.{request.method.lower()}",
            actor=f"{principal.provider}:{principal.username}",
            target=_metrics_path(request),
            details={"status": int(status_code), "resource_hash": hashlib.sha256(request.url.path.encode()).hexdigest()},
            ip=_ip(request),
        )
    except Exception:
        logger.exception("audit write failed for %s %s", request.method, _metrics_path(request))


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _actor(principal: Principal) -> str:
    return f"{principal.provider}:{principal.username}"


def _peer_by_id(pubkey: str):
    for peer in vm.get_all_peers():
        if peer.public_key == pubkey:
            return peer
    return None


def _safe_download_name(value: str) -> str:
    """Sanitised download stem — may still contain non-ASCII letters.

    `str.isalnum()` is true for Cyrillic, which is deliberate: employees are
    often named in Cyrillic and the operator wants to see the real name. Use it for the RFC 5987 `filename*` parameter and for names
    inside archives — never for a bare `filename=` header (see below).
    """
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in value.strip())
    return safe.strip("-_") or "client"


# Transliteration only for the ASCII `filename=` fallback. The real name always
# goes into `filename*` (see _attachment_headers), so any sensible scheme works
# here; what matters is that two different Cyrillic names do not collapse into
# one "client.conf" for clients that ignore filename*.
_CYRILLIC_TRANSLIT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
    "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "kh", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "shch",
    "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
}


def _ascii_download_name(value: str) -> str:
    """ASCII-only variant of `_safe_download_name` for the `filename=` fallback."""
    chars: list[str] = []
    for ch in value.strip():
        if (ch.isascii() and ch.isalnum()) or ch in "-_":
            chars.append(ch)
            continue
        lowered = ch.lower()
        mapped = _CYRILLIC_TRANSLIT.get(lowered)
        if mapped is None:
            chars.append("-")
        elif ch == lowered:
            chars.append(mapped)
        else:
            chars.append(mapped.title())
    return "".join(chars).strip("-_") or "client"


# Responses that carry a private key, a VLESS client id or a whole Xray config
# must not linger in browser or proxy caches.
_NO_STORE = {"Cache-Control": "no-store"}


def _attachment_headers(stem: str, suffix: str) -> dict[str, str]:
    """Content-Disposition per RFC 6266/5987, plus no-store (every download
    here carries credentials).

    Starlette encodes header values as latin-1, so a raw Cyrillic filename
    raises UnicodeEncodeError *inside* the handler — which the download routes
    used to turn into an opaque HTTP 500. That hit exactly the peers this UI
    exists for, so always emit both parameters:
      * `filename="..."`  — ASCII-only, safe for latin-1 and for old clients;
      * `filename*=UTF-8''...` — percent-encoded real name, preferred by every
        current browser (RFC 6266 §4.3: `filename*` wins when both are sent).
    `suffix` carries the extension and any protocol marker, e.g. "-awg.conf".
    """
    ascii_filename = f"{_ascii_download_name(stem)}{suffix}"
    utf8_filename = quote(f"{_safe_download_name(stem)}{suffix}", safe="")
    return {
        "Content-Disposition": (
            f'attachment; filename="{ascii_filename}"; filename*=UTF-8\'\'{utf8_filename}'
        ),
        **_NO_STORE,
    }


def _qr_png(payload: str) -> StreamingResponse:
    img = qrcode.make(payload)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png", headers=dict(_NO_STORE))


def _raise_mapped_http_error(
    exc: Exception, mapping: tuple[tuple[type, int], ...]
) -> None:
    """Re-raise a domain exception as an HTTPException via an ordered isinstance map.

    The first matching (exc_type, status) wins, so list subclasses before their
    bases. Anything unmatched becomes a 500. Centralises the identical
    map-and-raise pattern the per-domain helpers below used to repeat.
    """
    for exc_type, status_code in mapping:
        if isinstance(exc, exc_type):
            raise HTTPException(status_code=status_code, detail=str(exc)) from exc
    raise HTTPException(status_code=500, detail=str(exc)) from exc


def _raise_override_http_error(exc: Exception) -> None:
    _raise_mapped_http_error(exc, (
        (ro.RoutingOverrideConflict, 409),
        (ro.RoutingOverrideNotFound, 404),
        (ro.RoutingOverrideValidationError, 400),
    ))


def _log_override_error(action: str, exc: Exception) -> None:
    if isinstance(
        exc,
        (
            ro.RoutingOverrideConflict,
            ro.RoutingOverrideNotFound,
            ro.RoutingOverrideValidationError,
        ),
    ):
        logger.info("%s rejected: %s", action, exc)
        return
    logger.exception("%s failed", action)


def _raise_xray_http_error(exc: Exception) -> None:
    # XrayCommandError / XrayManagerError and anything unmatched fall through to 500.
    _raise_mapped_http_error(exc, (
        (xm.XrayNotConfiguredError, 409),
    ))


def _raise_xray_client_http_error(exc: Exception) -> None:
    # The XrayClientError base and anything unmatched fall through to 500.
    _raise_mapped_http_error(exc, (
        (xc.XrayClientConflict, 409),
        (xc.XrayClientNotFound, 404),
        (xc.XrayClientValidationError, 400),
    ))


def _raise_peer_artifact_http_error(exc: Exception) -> None:
    # The PeerArtifactError base and anything unmatched fall through to 500.
    _raise_mapped_http_error(exc, (
        (pa.PeerArtifactNotFound, 404),
        (pa.PeerArtifactValidationError, 400),
    ))


def _mutate_xray_clients_locked(action: str, mutation: Callable[[], object]) -> object:
    # backend_lock: the device layer and the sync timer change the same client list.
    with devices.backend_lock():
        snapshot = xc.snapshot_clients()
        try:
            result = mutation()
            xm.apply_xray()
            return result
        except Exception:
            try:
                xc.restore_clients(snapshot)
            except Exception:
                logger.exception("%s rollback failed", action)
            logger.exception("%s failed", action)
            raise


def _adopt_new_credentials() -> None:
    """A peer or VLESS client made on a low-level page becomes an unassigned
    device right away, so its later changes go through the device layer."""
    try:
        devices.adopt_unmanaged()
    except Exception:
        logger.exception("adopting new credentials failed")


def _device_usable(device: dict) -> bool:
    owner = auth_store.get_user(device["user_id"])
    return device["status"] == "active" and owner is not None and owner["status"] == "active"


# --- Low-level WireGuard peers ------------------------------------------------
# Operators may list peers and toggle the ones that belong to a device (the
# device layer then checks the owner, the expiry and the lock). Everything that
# mints or hands out a credential, or touches a peer with no device, is admin.


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, _=Depends(require_auth)):
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "principal": current_principal(request),
            "peers": [peer.model_dump() for peer in vm.get_all_peers()],
            "stats": vm.get_stats().model_dump(),
        },
    )


@app.get("/api/peers")
def api_list_peers(_=Depends(require_auth)):
    return [peer.model_dump() for peer in vm.get_all_peers()]


@app.post("/api/peers", status_code=201)
def api_create_peer(req: CreatePeerRequest, _=Depends(require_admin)):
    try:
        with devices.backend_lock():
            created = vm.create_peer(req.name)
    except Exception as exc:
        logger.exception("create_peer failed")
        raise HTTPException(500, str(exc))
    _adopt_new_credentials()
    return JSONResponse(created, status_code=201, headers=dict(_NO_STORE))


@app.put("/api/peers/{pubkey:path}")
def api_update_peer(pubkey: str, req: UpdatePeerRequest, _=Depends(require_auth)):
    if not _peer_by_id(pubkey):
        raise HTTPException(404, "Peer not found")
    with devices.backend_lock():
        vm.rename_peer(pubkey, req.name)
    return {"status": "ok"}


def _set_peer_active(pubkey: str, active: bool, principal: Principal, request: Request) -> dict:
    if not _peer_by_id(pubkey):
        raise HTTPException(404, "Peer not found")
    device = devices.find_by_ref(pubkey)
    if device is not None:
        try:
            devices.set_active(device["id"], active, actor=_actor(principal), ip=_ip(request))
        except devices.DeviceError as exc:
            raise HTTPException(400, str(exc)) from exc
    elif principal.has("admin"):
        with devices.backend_lock():
            (vm.activate_peer if active else vm.deactivate_peer)(pubkey)
    else:
        raise HTTPException(403, "requires role admin: the peer belongs to no device")
    return {"status": "activated" if active else "deactivated"}


@app.post("/api/peers/{pubkey:path}/deactivate")
def api_deactivate(pubkey: str, request: Request, principal: Principal = Depends(require_auth)):
    return _set_peer_active(pubkey, False, principal, request)


@app.post("/api/peers/{pubkey:path}/activate")
def api_activate(pubkey: str, request: Request, principal: Principal = Depends(require_auth)):
    return _set_peer_active(pubkey, True, principal, request)


@app.delete("/api/peers/{pubkey:path}")
def api_delete(pubkey: str, request: Request, principal: Principal = Depends(require_auth)):
    if not _peer_by_id(pubkey):
        raise HTTPException(404, "Peer not found")
    device = devices.find_by_ref(pubkey)
    if device is not None:
        devices.revoke(device["id"], actor=_actor(principal), ip=_ip(request))
        return {"status": "deleted"}
    if not principal.has("admin"):
        raise HTTPException(403, "requires role admin: the peer belongs to no device")
    with devices.backend_lock():
        vm.delete_peer(pubkey)
    devices.mark_backend_deleted(pubkey, actor=_actor(principal))
    return {"status": "deleted"}


def _peer_client_conf(pubkey: str, protocol: Optional[Protocol]):
    """The peer's config the way its device's access profile shapes it
    (AllowedIPs, DNS), exactly as the employee portal hands it out."""
    artifact = pa.resolve_peer_artifact(pubkey, protocol=protocol)
    device = devices.find_by_ref(pubkey)
    profile = devices.device_profile(device) if device else auth_store.default_profile()
    return artifact, network_policy.client_conf(artifact.client_conf, profile)


@app.get("/api/peers/{pubkey:path}/config")
def api_get_config(
    pubkey: str,
    protocol: Protocol | None = None,
    _=Depends(require_admin),
):
    try:
        artifact, client_conf = _peer_client_conf(pubkey, protocol)
        # WireGuard and AmneziaWG are two different configs of one peer: without
        # distinct names the second download lands as "<name> (1).conf". Both keep
        # the .conf extension, the only one wg-quick and AmneziaVPN import.
        suffix = "-awg.conf" if artifact.protocol == Protocol.AMNEZIAWG else ".conf"
        return Response(
            content=client_conf,
            media_type="text/plain",
            headers=_attachment_headers(artifact.peer.name or pubkey[:8], suffix),
        )
    except Exception as exc:
        logger.exception("peer_config failed")
        _raise_peer_artifact_http_error(exc)


@app.get("/api/peers/{pubkey:path}/artifacts")
def api_get_peer_artifacts(pubkey: str, _=Depends(require_admin)):
    try:
        return pa.describe_peer_artifacts(pubkey).model_dump()
    except Exception as exc:
        logger.exception("peer_artifacts failed")
        _raise_peer_artifact_http_error(exc)


@app.get("/api/peers/{pubkey:path}/qr")
def api_get_qr(
    pubkey: str,
    protocol: Protocol | None = None,
    _=Depends(require_admin),
):
    try:
        _, client_conf = _peer_client_conf(pubkey, protocol)
    except Exception as exc:
        logger.exception("peer_qr failed")
        _raise_peer_artifact_http_error(exc)
    return _qr_png(client_conf)


@app.get("/api/peers/{pubkey:path}")
def api_get_peer(pubkey: str, _=Depends(require_auth)):
    peer = _peer_by_id(pubkey)
    if not peer:
        raise HTTPException(404, "Peer not found")
    return peer.model_dump()


@app.get("/api/stats")
def api_stats(_=Depends(require_auth)):
    return vm.get_stats().model_dump()


@app.get("/api/vpn/status")
def api_vpn_status(_=Depends(require_auth)):
    return vm.get_vpn_status().model_dump()


@app.get("/api/network/pools")
def api_network_pools(_=Depends(require_auth)):
    """Client address pools: size, used and free addresses."""
    return vm.pool_usage()


@app.get("/api/routing/overrides")
def api_list_routing_overrides(_=Depends(require_admin)):
    try:
        return [override.model_dump() for override in ro.list_overrides()]
    except Exception as exc:
        _log_override_error("list_routing_overrides", exc)
        _raise_override_http_error(exc)


@app.post("/api/routing/overrides", status_code=201)
def api_create_routing_override(req: CreateRoutingOverrideRequest, _=Depends(require_admin)):
    try:
        override = ro.create_override(
            match_type=req.match_type,
            value=req.value,
            route=req.route,
            comment=req.comment,
        )
        return override.model_dump()
    except Exception as exc:
        _log_override_error("create_routing_override", exc)
        _raise_override_http_error(exc)


@app.put("/api/routing/overrides/{override_id}")
def api_update_routing_override(
    override_id: str,
    req: UpdateRoutingOverrideRequest,
    _=Depends(require_admin),
):
    try:
        override = ro.update_override(
            override_id=override_id,
            match_type=req.match_type,
            value=req.value,
            route=req.route,
            comment=req.comment,
        )
        return override.model_dump()
    except Exception as exc:
        _log_override_error("update_routing_override", exc)
        _raise_override_http_error(exc)


@app.post("/api/routing/overrides/{override_id}/toggle")
def api_toggle_routing_override(override_id: str, _=Depends(require_admin)):
    try:
        override = ro.toggle_override(override_id)
        return override.model_dump()
    except Exception as exc:
        _log_override_error("toggle_routing_override", exc)
        _raise_override_http_error(exc)


@app.delete("/api/routing/overrides/{override_id}")
def api_delete_routing_override(override_id: str, _=Depends(require_admin)):
    try:
        ro.delete_override(override_id)
        return {"status": "deleted"}
    except Exception as exc:
        _log_override_error("delete_routing_override", exc)
        _raise_override_http_error(exc)


@app.get("/api/routing/preview")
def api_routing_preview(_=Depends(require_admin)):
    try:
        return ro.get_preview().model_dump()
    except Exception as exc:
        _log_override_error("routing_preview", exc)
        _raise_override_http_error(exc)


@app.get("/api/routing/check")
def api_routing_check(host: str, _=Depends(require_admin)):
    try:
        return ro.check_domain(host).model_dump()
    except Exception as exc:
        _log_override_error("routing_check", exc)
        _raise_override_http_error(exc)


# --- Low-level VLESS clients --------------------------------------------------
# A client id is the VLESS credential: only admins see or hand one out.


@app.get("/api/xray/clients")
def api_list_xray_clients(principal: Principal = Depends(require_auth)):
    try:
        clients = [client.model_dump() for client in xc.list_clients()]
    except Exception as exc:
        logger.exception("list_xray_clients failed")
        _raise_xray_client_http_error(exc)
    _adopt_new_credentials()
    for client in clients:
        device = devices.find_by_ref(client["id"])
        client["id"] = device["id"] if device else ""
    return clients


def _xray_management_record(record: dict) -> dict:
    device = devices.find_by_ref(record["id"])
    return {**record, "id": device["id"] if device else ""}


def _xray_reference(value: str) -> str:
    """Management handles never reveal the VLESS UUID; old UUID inputs still work."""
    device = auth_store.get_device(value)
    return device["ref"] if device and device["protocol"] == "vless" else value


@app.get("/api/xray/settings")
def api_xray_client_settings(_=Depends(require_auth)):
    try:
        return xc.get_settings_status().model_dump()
    except Exception as exc:
        logger.exception("xray_client_settings failed")
        _raise_xray_client_http_error(exc)


@app.get("/api/xray/doctor")
def api_xray_doctor(_=Depends(require_auth)):
    try:
        return xm.get_doctor_status().model_dump()
    except Exception as exc:
        logger.exception("xray_doctor failed")
        _raise_xray_http_error(exc)


@app.post("/api/xray/clients", status_code=201)
def api_create_xray_client(req: CreateXrayClientRequest, _=Depends(require_admin)):
    try:
        client = _mutate_xray_clients_locked(
            "create_xray_client",
            lambda: xc.create_client(name=req.name, email=req.email),
        )
    except Exception as exc:
        logger.exception("create_xray_client failed")
        _raise_xray_client_http_error(exc)
    _adopt_new_credentials()
    return JSONResponse(client.model_dump(), status_code=201, headers=dict(_NO_STORE))


@app.put("/api/xray/clients/{client_id}")
def api_update_xray_client(
    client_id: str,
    req: UpdateXrayClientRequest,
    _=Depends(require_admin),
):
    client_id = _xray_reference(client_id)
    try:
        client = _mutate_xray_clients_locked(
            "update_xray_client",
            lambda: xc.update_client(client_id=client_id, name=req.name, email=req.email),
        )
        return _xray_management_record(client.model_dump())
    except Exception as exc:
        logger.exception("update_xray_client failed")
        _raise_xray_client_http_error(exc)


@app.post("/api/xray/clients/{client_id}/toggle")
def api_toggle_xray_client(client_id: str, request: Request, principal: Principal = Depends(require_auth)):
    client_id = _xray_reference(client_id)
    try:
        device = devices.find_by_ref(client_id)
        if device is not None:
            enabled = xc.get_client(client_id).enabled
            devices.set_active(device["id"], not enabled, actor=_actor(principal), ip=_ip(request))
            client = xc.get_client(client_id)
        elif principal.has("admin"):
            client = _mutate_xray_clients_locked("toggle_xray_client", lambda: xc.toggle_client(client_id))
        else:
            raise HTTPException(403, "requires role admin: the client belongs to no device")
    except HTTPException:
        raise
    except devices.DeviceError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        logger.exception("toggle_xray_client failed")
        _raise_xray_client_http_error(exc)
    result = client.model_dump()
    return _xray_management_record(result)


@app.delete("/api/xray/clients/{client_id}")
def api_delete_xray_client(client_id: str, request: Request, principal: Principal = Depends(require_auth)):
    client_id = _xray_reference(client_id)
    try:
        device = devices.find_by_ref(client_id)
        if device is not None:
            devices.revoke(device["id"], actor=_actor(principal), ip=_ip(request))
            return {"status": "deleted"}
        if not principal.has("admin"):
            raise HTTPException(403, "requires role admin: the client belongs to no device")
        _mutate_xray_clients_locked("delete_xray_client", lambda: xc.delete_client(client_id))
        devices.mark_backend_deleted(client_id, actor=_actor(principal))
        return {"status": "deleted"}
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("delete_xray_client failed")
        _raise_xray_client_http_error(exc)


@app.get("/api/xray/clients/{client_id}/share")
def api_xray_client_share(
    client_id: str,
    response: Response,
    protocol: Protocol | None = None,
    _=Depends(require_admin),
):
    client_id = _xray_reference(client_id)
    try:
        share = ca.resolve_client_artifact(client_id, protocol=protocol).share.model_dump()
    except Exception as exc:
        logger.exception("xray_client_share failed")
        _raise_xray_client_http_error(exc)
    response.headers.update(_NO_STORE)
    return share


@app.get("/api/xray/clients/{client_id}/config")
def api_xray_client_config(
    client_id: str,
    protocol: Protocol | None = None,
    _=Depends(require_admin),
):
    client_id = _xray_reference(client_id)
    try:
        artifact = ca.resolve_client_artifact(client_id, protocol=protocol)
        share = artifact.share
        content = json.dumps(share.client_config, ensure_ascii=False, indent=2) + "\n"
        suffix = (
            ".xray-client.json"
            if artifact.protocol == Protocol.VLESS
            else f".{artifact.protocol.value}-client.json"
        )
        return Response(
            content=content,
            media_type="application/json",
            headers=_attachment_headers(share.name, suffix),
        )
    except Exception as exc:
        logger.exception("xray_client_config failed")
        _raise_xray_client_http_error(exc)


@app.get("/api/xray/clients/{client_id}/bundle")
def api_xray_client_bundle(client_id: str, _=Depends(require_admin)):
    client_id = _xray_reference(client_id)
    try:
        artifact = ca.resolve_client_artifact(client_id)
        share = artifact.share
        device = devices.find_by_ref(client_id)
        if device is not None and not _device_usable(device):
            raise HTTPException(403, "device_unavailable")
        profile = devices.device_profile(device) if device else auth_store.default_profile()
        content = network_policy.vless_client_config(share.client_config, profile)
    except HTTPException:
        raise
    except Exception as exc:
        _raise_xray_client_http_error(exc)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("vless-link.txt", share.share_link + "\n")
        archive.writestr(_safe_download_name(share.name) + ".xray-client.json", json.dumps(content, indent=2))
        archive.writestr("README.txt", "CorpVPN: import the JSON configuration or VLESS link in your VPN client. Keep this archive private.\n")
    return Response(output.getvalue(), media_type="application/zip", headers=_attachment_headers(share.name, ".zip"))


@app.get("/api/xray/clients/{client_id}/artifacts")
def api_xray_client_artifacts(client_id: str, _=Depends(require_admin)):
    client_id = _xray_reference(client_id)
    try:
        return ca.describe_client_artifacts(client_id).model_dump()
    except Exception as exc:
        logger.exception("xray_client_artifacts failed")
        _raise_xray_client_http_error(exc)


@app.get("/api/xray/clients/{client_id}/qr")
def api_xray_client_qr(
    client_id: str,
    protocol: Protocol | None = None,
    _=Depends(require_admin),
):
    client_id = _xray_reference(client_id)
    try:
        share = ca.resolve_client_artifact(client_id, protocol=protocol).share
    except Exception as exc:
        logger.exception("xray_client_qr failed")
        _raise_xray_client_http_error(exc)
    return _qr_png(share.share_link)


# --- One-shot AmneziaWG config links (<CONFIG_LINK_PUBLIC_BASE_URL>/awg/<code>) ---
# An admin mints a single-use link for an EXISTING peer and hands it to the
# employee; the /awg/* routes never create or rotate a key, they only read
# (see config_links.py). GET is idempotent and POST consumes: chat apps fetch a
# link preview with GET, so a consuming GET would burn the link unseen.

# The code is a bearer secret in the URL and the page carries a private key:
# nothing may cache it or leak the URL through Referer.
_LINK_PAGE_HEADERS = {"Cache-Control": "no-store", "Referrer-Policy": "strict-origin"}


def _png_data_uri(payload: str) -> str:
    """Inline QR so the page pulls in no external resource (and no second request)."""
    img = qrcode.make(payload)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


def _config_link_expiry_text(link: dict) -> str:
    raw = str(link.get("expires_at") or "")
    try:
        moment = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return raw
    return moment.astimezone(timezone.utc).strftime("%d.%m.%Y %H:%M") + " UTC"


def _link_page(request: Request, context: dict, status_code: int = 200, template: str = "awg_link_landing.html"):
    return templates.TemplateResponse(
        request, template, context, status_code=status_code, headers=dict(_LINK_PAGE_HEADERS)
    )


def _config_link_page(request: Request, link: dict | None, code: str):
    """Landing page for a link that cannot be claimed right now, or None if it can.

    Unknown, expired and revoked codes deliberately render the SAME generic page:
    the response must not tell a scanner whether a code ever existed. The real
    reason is logged server-side instead.
    """
    if link is None or link["state"] in (cl.STATE_EXPIRED, cl.STATUS_REVOKED):
        reason = "unknown" if link is None else link["state"]
        logger.info("config link %s… rejected: %s", code[:6], reason)
        return _link_page(request, {"state": "invalid"}, status_code=404)
    if link["state"] == cl.STATUS_CONSUMED:
        return _link_page(request, {"state": "consumed", "label": link.get("label") or ""}, status_code=410)
    return None


@app.get("/awg/{code}", response_class=HTMLResponse)
def awg_config_link_landing(code: str, request: Request):
    normalized = cl.normalize_code(code)
    link = cl.get_link(normalized)
    page = _config_link_page(request, link, normalized)
    if page is not None:
        return page
    return _link_page(
        request,
        {
            "state": "active",
            "code": normalized,
            "label": link.get("label") or "",
            "expires_text": _config_link_expiry_text(link),
        },
    )


@app.post("/awg/{code}/claim", response_class=HTMLResponse)
def awg_config_link_claim(code: str, request: Request):
    normalized = cl.normalize_code(code)
    link = cl.get_link(normalized)
    page = _config_link_page(request, link, normalized)
    if page is not None:
        return page

    # The link serves the peer the way its device serves it in the portal: only
    # while the device and its owner are active, and shaped by the owner's access
    # profile. A peer without a device (made on a low-level page, not adopted
    # yet) gets the default profile.
    peer = link["peer_public_key"]
    device = devices.find_by_ref(peer)
    if device is not None and not _device_usable(device):
        logger.info("config link %s… rejected: device or owner not active", normalized[:6])
        return _link_page(request, {"state": "invalid"}, status_code=404)
    profile = devices.device_profile(device) if device is not None else auth_store.default_profile()

    # Order matters: render the config FIRST, consume only once we hold it.
    # get_client_conf is a pure read (private key + live peer state), so doing it
    # before the conditional UPDATE has no side effect worth undoing — whereas
    # consuming first and failing to build would cost the user their single use,
    # and "restore it afterwards" is itself a write that can fail. The UPDATE
    # below still decides exactly-once delivery, so a link built here but lost in
    # the race is simply discarded, never served.
    try:
        client_conf = vm.get_client_conf(peer, protocol=Protocol.AMNEZIAWG)
        if client_conf:
            client_conf = network_policy.client_conf(client_conf, profile)
    except Exception:
        logger.exception("config link %s… config build failed", normalized[:6])
        client_conf = None
    if not client_conf:
        logger.warning("config link %s… has no usable peer %s…", normalized[:6], str(peer)[:8])
        return _link_page(request, {"state": "unavailable", "code": normalized}, status_code=503)

    try:
        link = cl.consume_link(normalized)
    except cl.ConfigLinkAlreadyUsed:
        return _link_page(request, {"state": "consumed", "label": link.get("label") or ""}, status_code=410)
    except cl.ConfigLinkError as exc:
        logger.info("config link %s… claim rejected: %s", normalized[:6], exc)
        return _link_page(request, {"state": "invalid"}, status_code=404)

    # ASCII (transliterated) on purpose: unlike the panel's own downloads there is
    # no Content-Disposition here to carry a filename* — the name lives in a
    # `download=` attribute, and a Cyrillic one is where mobile download managers
    # like to drop the extension. AmneziaVPN needs the ".conf" to survive.
    file_name = f"{_ascii_download_name(link.get('label') or 'vpn')}-awg.conf"
    conf_b64 = base64.b64encode(client_conf.encode("utf-8")).decode("ascii")
    return _link_page(
        request,
        {
            "label": link.get("label") or "",
            "client_conf": client_conf,
            "file_name": file_name,
            "download_uri": f"data:application/octet-stream;base64,{conf_b64}",
            "qr_uri": _png_data_uri(client_conf),
        },
        template="awg_link_config.html",
    )


@app.post("/api/config-links", status_code=201, response_model=ConfigLinkCreated)
def api_create_config_link(req: CreateConfigLinkRequest, _=Depends(require_admin)):
    device = devices.find_by_ref(req.peer_public_key.strip())
    if device is not None and not _device_usable(device):
        raise HTTPException(status_code=400, detail="the device or its owner is not active")
    try:
        link = cl.create_link(
            peer_public_key=req.peer_public_key,
            user_id=req.user_id,
            label=req.label,
            ttl_days=req.ttl_days,
        )
    except cl.ConfigLinkError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "code": link["code"],
        "url": f"{config.CONFIG_LINK_PUBLIC_BASE_URL}/awg/{link['code']}",
        "expires_at": link["expires_at"],
    }


@app.get("/api/config-links", response_model=list[ConfigLinkRecord])
def api_list_config_links(
    status: Optional[str] = None,
    user_id: Optional[str] = None,
    _=Depends(require_admin),
):
    try:
        return [cl.management_record(row) for row in cl.list_links(status=status, user_id=user_id)]
    except Exception as exc:
        logger.exception("list_config_links failed")
        raise HTTPException(500, str(exc)) from exc


@app.delete("/api/config-links/{code}", response_model=ConfigLinkRecord)
def api_revoke_config_link(code: str, _=Depends(require_admin)):
    try:
        return cl.management_record(cl.revoke_link(cl.resolve_handle(code)))
    except cl.ConfigLinkNotFound:
        raise HTTPException(status_code=404, detail="config link not found")
    except cl.ConfigLinkError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# --- Xray routing actions (admin) ---------------------------------------------
# Export, validate, reload and apply write the same files the device layer's
# applies do: they run under the backend lock.


@app.get("/api/routing/runtime")
def api_routing_runtime(_=Depends(require_admin)):
    try:
        return xm.get_runtime_status().model_dump()
    except Exception as exc:
        logger.exception("routing_runtime failed")
        _raise_xray_http_error(exc)


@app.get("/api/routing/merged-config")
def api_routing_merged_config(_=Depends(require_admin)):
    try:
        content = xm.render_merged_config_json()
        return Response(
            content=content,
            media_type="application/json",
            headers=_attachment_headers("xray-merged-config", ".json"),
        )
    except Exception as exc:
        logger.exception("routing_merged_config failed")
        _raise_xray_http_error(exc)


@app.get("/api/routing/exported-routing")
def api_routing_exported_routing(_=Depends(require_admin)):
    try:
        content = xm.read_exported_routing_json()
        return Response(
            content=content,
            media_type="application/json",
            headers=_attachment_headers("routing", ".generated.json"),
        )
    except Exception as exc:
        logger.exception("routing_exported_routing failed")
        _raise_xray_http_error(exc)


@app.get("/api/routing/exported-merged-config")
def api_routing_exported_merged_config(_=Depends(require_admin)):
    try:
        content = xm.read_exported_merged_config_json()
        return Response(
            content=content,
            media_type="application/json",
            headers=_attachment_headers("config", ".generated.json"),
        )
    except Exception as exc:
        logger.exception("routing_exported_merged_config failed")
        _raise_xray_http_error(exc)


def _locked_xray_action(action: str, fn: Callable[[], object]) -> dict:
    try:
        with devices.backend_lock():
            return fn().model_dump()
    except Exception as exc:
        logger.exception("%s failed", action)
        _raise_xray_http_error(exc)


@app.post("/api/routing/export")
def api_routing_export(_=Depends(require_admin)):
    return _locked_xray_action("routing_export", xm.export_routing)


@app.post("/api/routing/validate")
def api_routing_validate(_=Depends(require_admin)):
    return _locked_xray_action("routing_validate", xm.validate_routing)


@app.post("/api/routing/reload")
def api_routing_reload(_=Depends(require_admin)):
    return _locked_xray_action("routing_reload", xm.reload_xray)


@app.post("/api/routing/apply")
def api_routing_apply(_=Depends(require_admin)):
    return _locked_xray_action("routing_apply", xm.apply_xray)


# --- Health and metrics ---------------------------------------------------------
_HEALTH_CACHE_SECONDS = 5.0
_health_cache: dict = {"at": 0.0, "result": None}
_health_lock = threading.Lock()


def _gateway_health() -> dict:
    """vm.health_check() at most once per few seconds: /health is public, and
    every check runs `wg` subprocesses."""
    with _health_lock:
        now = time.monotonic()
        if _health_cache["result"] is None or now - _health_cache["at"] >= _HEALTH_CACHE_SECONDS:
            _health_cache["result"] = vm.health_check()
            _health_cache["at"] = now
        return _health_cache["result"]


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin"
    if not request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store"
    if request.query_params.get("lang") in ("en", "ru"):
        response.set_cookie("corpvpn-language", request.query_params["lang"], httponly=True, samesite="lax", secure=request.url.scheme == "https")
    return response


@app.get("/health")
def health():
    """Public liveness for load balancers and uptime monitors: the status only,
    503 while a tunnel this gateway serves is down. Details: /api/health."""
    status = _gateway_health()["status"]
    return JSONResponse({"status": status}, status_code=200 if status == "ok" else 503)


@app.get("/api/health")
def api_health(_=Depends(require_admin)):
    return {**_gateway_health(), "network_policy": network_policy.policy_state()}


@app.get("/metrics")
def metrics(_=Depends(require_metrics)):
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.PANEL_HOST, port=config.PANEL_PORT)
