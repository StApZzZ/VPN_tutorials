import hashlib
import json
import os
import re
import shutil
import shlex
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import config
import reality_keycheck
import routing_overrides as ro
import vpn_manager as vm
import xray_clients as xc
from models import (
    RoutingApplyResult,
    RoutingExportResult,
    RoutingLastAction,
    RoutingReloadResult,
    RoutingRuntimeStatus,
    RoutingValidationResult,
    XrayDoctorCheck,
    XrayDoctorStatus,
)


class XrayManagerError(RuntimeError):
    pass


class XrayNotConfiguredError(XrayManagerError):
    pass


class XrayCommandError(XrayManagerError):
    pass


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_command(command: list[str], action: str) -> subprocess.CompletedProcess:
    """Run a configured push / validate / reload command with a time limit: it
    runs under the backend lock that every device change needs."""
    timeout = config.XRAY_COMMAND_TIMEOUT_SECONDS
    try:
        return subprocess.run(command, text=True, capture_output=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise XrayCommandError(f"{action} timed out after {timeout}s") from exc
    except OSError as exc:
        raise XrayCommandError(f"{action} could not run: {exc}") from exc


def _atomic_write(path: str, content: str) -> int:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    encoded = content.encode("utf-8")
    fd, tmp_path = tempfile.mkstemp(dir=target.parent, prefix=".tmp_")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
        os.replace(tmp_path, path)
    except Exception:
        os.unlink(tmp_path)
        raise
    return len(encoded)


def _atomic_copy(source: Path, target: Path) -> int:
    """Replace `target` keeping its mode, owner and group: the live config holds
    the REALITY private key and every client id, and may be tightened to
    0640 root:<xray group> so that only the Xray service can read it."""
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = source.read_bytes()
    current = target.stat() if target.exists() else None
    mode = current.st_mode & 0o777 if current else 0o644
    fd, tmp_path = tempfile.mkstemp(dir=target.parent, prefix=".tmp_")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
        os.chmod(tmp_path, mode)
        if current is not None and hasattr(os, "chown"):
            try:
                os.chown(tmp_path, current.st_uid, current.st_gid)
            except PermissionError:
                pass  # not root (development): the file stays ours
        os.replace(tmp_path, target)
    except Exception:
        os.unlink(tmp_path)
        raise
    return len(payload)


def _json_payload(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def _sha256_text(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str | None:
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    return (
        "replace" in lowered
        or "placeholder" in lowered
        or "new_server_ip" in lowered
    )


def _collect_placeholder_paths(payload, prefix: str = "$") -> list[str]:
    if isinstance(payload, dict):
        paths: list[str] = []
        for key, value in payload.items():
            paths.extend(_collect_placeholder_paths(value, f"{prefix}.{key}"))
        return paths
    if isinstance(payload, list):
        paths = []
        for index, value in enumerate(payload):
            paths.extend(_collect_placeholder_paths(value, f"{prefix}[{index}]"))
        return paths
    if isinstance(payload, str) and _looks_like_placeholder(payload):
        return [prefix]
    return []


def _find_tagged(items: list[dict], tag: str) -> dict | None:
    for item in items:
        if isinstance(item, dict) and item.get("tag") == tag:
            return item
    return None


def _live_client_ids(client_inbound: dict | None) -> set[str]:
    if not client_inbound:
        return set()
    users = client_inbound.get("settings", {}).get("clients", [])
    if not isinstance(users, list):
        return set()
    return {user.get("id") for user in users if isinstance(user, dict) and user.get("id")}


def _format_command(template: str, **kwargs) -> list[str]:
    if not template.strip():
        raise XrayNotConfiguredError("Requested Xray action is not configured")
    return shlex.split(template.format_map(kwargs), posix=os.name != "nt")


def _load_action_state() -> tuple[RoutingLastAction | None, str]:
    state_path = Path(config.XRAY_ACTION_STATE_PATH)
    if not state_path.exists():
        return None, ""

    try:
        with state_path.open(encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception as exc:
        return None, f"Cannot read Xray action state: {state_path} ({exc})"

    try:
        return RoutingLastAction(**payload), ""
    except Exception as exc:
        return None, f"Xray action state is invalid: {state_path} ({exc})"


def _save_action_state(
    action: str,
    status: str,
    detail: str = "",
    command: list[str] | None = None,
    export_path: str | None = None,
    merged_config_path: str | None = None,
    live_config_path: str | None = None,
    backup_path: str | None = None,
) -> RoutingLastAction:
    payload = RoutingLastAction(
        action=action,
        status=status,
        updated_at=_now_iso(),
        detail=detail,
        command=command or [],
        export_path=export_path,
        merged_config_path=merged_config_path,
        live_config_path=live_config_path,
        backup_path=backup_path,
    )
    _atomic_write(
        config.XRAY_ACTION_STATE_PATH,
        json.dumps(payload.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n",
    )
    return payload


def _load_base_config() -> dict:
    base_path = Path(config.XRAY_BASE_CONFIG_PATH)
    if not config.XRAY_BASE_CONFIG_PATH.strip():
        raise XrayNotConfiguredError("XRAY_BASE_CONFIG_PATH is not configured")
    if not base_path.exists():
        raise XrayNotConfiguredError(f"Xray base config not found: {base_path}")

    try:
        with base_path.open(encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception as exc:
        raise XrayManagerError(f"Cannot read Xray base config: {base_path}") from exc

    if not isinstance(payload, dict):
        raise XrayManagerError("Xray base config must be a JSON object")

    return payload


def _sync_observatory(base_config: dict, rendered_routing: dict) -> None:
    """Keep observatory's subjectSelector in lockstep with the balancer selector.

    The leastPing balancer can only fail over to an egress the observatory
    actually probes; if subjectSelector omits an egress, the balancer has no
    health data for it. Deriving the observatory from the rendered balancers
    makes the panel the single source of truth and prevents the selector vs.
    observatory drift that previously left the second egress unprobed (and so
    excluded from failover). Only touches observatory when a balancer is
    present; otherwise the base config's observatory is left untouched.
    """
    subject_tags: list[str] = []
    seen: set[str] = set()
    for balancer in rendered_routing.get("balancers") or []:
        for tag in balancer.get("selector", []):
            if tag and tag not in seen:
                seen.add(tag)
                subject_tags.append(tag)
    if not subject_tags:
        return
    base_config["observatory"] = {
        "subjectSelector": subject_tags,
        "probeURL": config.XRAY_EGRESS_PROBE_URL,
        "probeInterval": config.XRAY_EGRESS_PROBE_INTERVAL,
        "enableConcurrency": True,
    }


def _inject_stats_into_config(base_config: dict) -> None:
    """Enable Xray stats + an expvar metrics endpoint for the panel to scrape.

    Adds ``stats``/``policy`` counters and a ``metrics.listen`` endpoint so the
    panel's /metrics collector can read live per-user/per-inbound VLESS traffic.
    Gated by ``XRAY_STATS_ENABLED`` and only when XRAY_STATS_METRICS_LISTEN is
    set, so a half-configured deployment can never bind the endpoint (loopback or
    an internal address, never public; the Xray guard rule keeps VLESS users off
    both). Because this runs inside the merged-config build, the endpoint
    survives every apply and the result is still validated by ``xray -test``
    before it goes live.
    """
    if not config.XRAY_STATS_ENABLED:
        return
    listen = config.XRAY_STATS_METRICS_LISTEN.strip()
    if not listen:
        return
    base_config["stats"] = {}
    base_config["metrics"] = {"tag": "metrics", "listen": listen}
    policy = base_config.setdefault("policy", {})
    level0 = policy.setdefault("levels", {}).setdefault("0", {})
    level0["statsUserUplink"] = True
    level0["statsUserDownlink"] = True
    system = policy.setdefault("system", {})
    system["statsInboundUplink"] = True
    system["statsInboundDownlink"] = True


def _ensure_block_outbound(base_config: dict, rendered_routing: dict) -> None:
    """Rules that send traffic to "block" need a blackhole outbound with that
    tag: Xray hands a rule with an unknown tag to the DEFAULT outbound, so the
    guard and every access-profile limit would silently let traffic through."""
    if not any(rule.get("outboundTag") == "block" for rule in rendered_routing.get("rules") or []):
        return
    outbounds = base_config.setdefault("outbounds", [])
    if _find_tagged(outbounds, "block") is None:
        outbounds.append({"tag": "block", "protocol": "blackhole"})


def _build_merged_config_from_rendered(rendered_routing: dict) -> dict:
    base_config = _load_base_config()
    base_config["routing"] = rendered_routing
    _ensure_block_outbound(base_config, rendered_routing)
    _sync_observatory(base_config, rendered_routing)
    _inject_stats_into_config(base_config)
    try:
        return xc.inject_clients_into_config(base_config)
    except xc.XrayClientError as exc:
        raise XrayManagerError(str(exc)) from exc


def _render_merged_config_payload(rendered_routing: dict) -> str:
    return _json_payload(_build_merged_config_from_rendered(rendered_routing))


def _backup_live_config() -> str:
    live_path = Path(config.XRAY_BASE_CONFIG_PATH)
    if not live_path.exists():
        raise XrayNotConfiguredError(f"Xray live config not found: {live_path}")

    backup_dir = Path(config.XRAY_APPLY_BACKUP_DIR)
    backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup_path = backup_dir / f"{live_path.name}.{timestamp}.bak"
    shutil.copy2(live_path, backup_path)
    vm.prune_backups(str(backup_dir), re.compile(re.escape(live_path.name) + r"\.\d{8}T\d{6,12}Z\.bak"))
    return str(backup_path)


def _promote_merged_config_to_live() -> int:
    merged_path = Path(config.XRAY_MERGED_CONFIG_EXPORT_PATH)
    if not merged_path.exists():
        raise XrayNotConfiguredError(f"Exported merged config file not found: {merged_path}")
    return _atomic_copy(merged_path, Path(config.XRAY_BASE_CONFIG_PATH))


def _restore_live_config(backup_path: str) -> None:
    _atomic_copy(Path(backup_path), Path(config.XRAY_BASE_CONFIG_PATH))


def _normalized_json_file(path: str) -> str | None:
    """Canonical JSON text of a file, or None if missing/unparsable."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.dumps(json.loads(p.read_text(encoding="utf-8")), sort_keys=True)
    except Exception:
        return None


def live_clients_in_sync() -> bool:
    """Whether the live config serves exactly the enabled VLESS clients. False
    after an apply that failed or ran in another process (the directory-sync
    timer); the periodic policy refresh then applies again. True when there is
    nothing to compare yet."""
    try:
        live = _load_base_config()
    except XrayManagerError:
        return True
    inbound = _find_tagged(live.get("inbounds", []), config.XRAY_CLIENT_INBOUND_TAG)
    if inbound is None:
        return True
    return _live_client_ids(inbound) == {client.id for client in xc.list_clients() if client.enabled}


def _merged_matches_live() -> bool:
    """True when the freshly-exported merged config equals the live config.

    Used to skip the Xray restart on a no-op apply — restarting drops every
    active client session, so we must not do it when nothing actually changed.
    """
    merged = _normalized_json_file(config.XRAY_MERGED_CONFIG_EXPORT_PATH)
    live = _normalized_json_file(config.XRAY_BASE_CONFIG_PATH)
    return merged is not None and merged == live


def _export_artifacts(require_base_config: bool = False) -> RoutingExportResult:
    preview = ro.get_preview()
    routing_payload = _json_payload(preview.rendered_routing)
    routing_sha256 = _sha256_text(routing_payload)
    bytes_written = _atomic_write(config.XRAY_ROUTING_EXPORT_PATH, routing_payload)

    merged_payload = None
    merged_path: str | None = None
    merged_bytes_written = 0
    merged_config_sha256: str | None = None
    detail = "Routing fragment exported"

    try_write_merged = require_base_config or Path(config.XRAY_BASE_CONFIG_PATH).exists()
    if try_write_merged:
        try:
            merged_payload = _render_merged_config_payload(preview.rendered_routing)
        except XrayManagerError:
            if require_base_config:
                raise
            merged_payload = None
            detail = "Routing fragment exported; merged config skipped because base config is invalid"

    if merged_payload is not None:
        merged_path = config.XRAY_MERGED_CONFIG_EXPORT_PATH
        merged_config_sha256 = _sha256_text(merged_payload)
        merged_bytes_written = _atomic_write(merged_path, merged_payload)
        detail = "Routing fragment and merged config exported"
    elif not require_base_config and not Path(config.XRAY_BASE_CONFIG_PATH).exists():
        detail = "Routing fragment exported; merged config skipped because base config is not available"

    return RoutingExportResult(
        status="ok",
        export_path=config.XRAY_ROUTING_EXPORT_PATH,
        merged_config_path=merged_path,
        bytes_written=bytes_written,
        merged_bytes_written=merged_bytes_written,
        manual_overrides_enabled=preview.manual_overrides_enabled,
        routing_sha256=routing_sha256,
        merged_config_sha256=merged_config_sha256,
        rendered_routing=preview.rendered_routing,
        detail=detail,
    )


def get_runtime_status() -> RoutingRuntimeStatus:
    export_path = Path(config.XRAY_ROUTING_EXPORT_PATH)
    merged_path = Path(config.XRAY_MERGED_CONFIG_EXPORT_PATH)
    base_path = Path(config.XRAY_BASE_CONFIG_PATH)
    state_path = Path(config.XRAY_ACTION_STATE_PATH)

    preview = ro.get_preview()
    current_routing_payload = _json_payload(preview.rendered_routing)
    current_routing_sha256 = _sha256_text(current_routing_payload)
    exported_routing_sha256 = _sha256_file(export_path)

    current_merged_config_sha256 = None
    exported_merged_config_sha256 = _sha256_file(merged_path)
    merged_config_export_in_sync = None
    base_config_error = ""
    if base_path.exists():
        try:
            current_merged_payload = _render_merged_config_payload(preview.rendered_routing)
            current_merged_config_sha256 = _sha256_text(current_merged_payload)
            merged_config_export_in_sync = (
                exported_merged_config_sha256 == current_merged_config_sha256
                if exported_merged_config_sha256 is not None
                else False
            )
        except XrayManagerError as exc:
            base_config_error = str(exc)

    last_action, action_state_error = _load_action_state()
    xray_clients = xc.list_clients()

    return RoutingRuntimeStatus(
        export_path=str(export_path),
        merged_config_path=str(merged_path),
        base_config_path=str(base_path),
        action_state_path=str(state_path),
        apply_backup_dir=config.XRAY_APPLY_BACKUP_DIR,
        export_exists=export_path.exists(),
        merged_config_exists=merged_path.exists(),
        base_config_exists=base_path.exists(),
        action_state_exists=state_path.exists(),
        validate_command_configured=bool(config.XRAY_VALIDATE_COMMAND.strip()),
        reload_command_configured=bool(config.XRAY_RELOAD_COMMAND.strip()),
        xray_clients_total=len(xray_clients),
        xray_clients_enabled=sum(1 for client in xray_clients if client.enabled),
        current_routing_sha256=current_routing_sha256,
        exported_routing_sha256=exported_routing_sha256,
        routing_export_in_sync=exported_routing_sha256 == current_routing_sha256,
        current_merged_config_sha256=current_merged_config_sha256,
        exported_merged_config_sha256=exported_merged_config_sha256,
        merged_config_export_in_sync=merged_config_export_in_sync,
        last_action=last_action,
        action_state_error=action_state_error,
        base_config_error=base_config_error,
    )


def check_reality_keys(base_config: dict | None = None) -> reality_keycheck.CheckResult | None:
    """What every client link carries (public key, short ID, server name)
    against the live server config. None when there is nothing to compare:
    VLESS without REALITY, or no live config or private key yet."""
    if config.XRAY_CLIENT_SECURITY != "reality":
        return None
    try:
        cfg = base_config if base_config is not None else _load_base_config()
        return reality_keycheck.check_server_config(
            cfg,
            config.XRAY_CLIENT_REALITY_PUBLIC_KEY,
            short_id=config.XRAY_CLIENT_REALITY_SHORT_ID,
            server_name=config.XRAY_CLIENT_REALITY_SERVER_NAME,
            inbound_tag=config.XRAY_CLIENT_INBOUND_TAG,
        )
    except (XrayManagerError, ValueError):
        return None


def _doctor_check(check_id: str, label: str, ok: bool, detail: str, warn: bool = False) -> XrayDoctorCheck:
    if ok:
        status = "ok"
    elif warn:
        status = "warn"
    else:
        status = "error"
    return XrayDoctorCheck(id=check_id, label=label, status=status, detail=detail)


def get_doctor_status() -> XrayDoctorStatus:
    settings = xc.get_settings_status()
    runtime = get_runtime_status()
    base_config = None
    base_config_load_error = ""
    if runtime.base_config_exists:
        try:
            base_config = _load_base_config()
        except Exception as exc:
            base_config_load_error = str(exc)

    client_inbound = None
    egress_outbound = None
    block_outbound = None
    egress_outbound_tag = config.XRAY_EGRESS_OUTBOUND_TAG
    placeholder_paths: list[str] = []
    if base_config is not None:
        client_inbound = _find_tagged(base_config.get("inbounds", []), config.XRAY_CLIENT_INBOUND_TAG)
        egress_outbound = _find_tagged(base_config.get("outbounds", []), egress_outbound_tag)
        block_outbound = _find_tagged(base_config.get("outbounds", []), "block")
        placeholder_paths = _collect_placeholder_paths(base_config)

    reality = check_reality_keys(base_config) if base_config is not None else None
    enabled_clients = [client for client in xc.list_clients() if client.enabled]
    enabled_client_ids = {client.id for client in enabled_clients}
    live_client_ids = _live_client_ids(client_inbound)
    missing_live_clients = [
        client.name for client in enabled_clients if client.id not in live_client_ids
    ]
    extra_live_client_count = len(live_client_ids - enabled_client_ids)
    live_clients_synced = (
        client_inbound is not None
        and not missing_live_clients
        and extra_live_client_count == 0
    )
    live_clients_detail = (
        f"{len(live_client_ids)} live / {len(enabled_clients)} enabled"
        if live_clients_synced
        else (
            f"Missing live clients: {', '.join(missing_live_clients[:8])}; "
            f"extra live clients: {extra_live_client_count}"
            if client_inbound is not None
            else f"Missing VLESS inbound tag {config.XRAY_CLIENT_INBOUND_TAG}"
        )
    )

    checks = [
        _doctor_check(
            "client_settings",
            "VLESS share settings",
            settings.ready,
            "VLESS links and JSON configs have complete connection parameters"
            if settings.ready
            else "; ".join(settings.errors),
        ),
        _doctor_check(
            "enabled_client",
            "Enabled VLESS client",
            runtime.xray_clients_enabled > 0,
            f"{runtime.xray_clients_enabled} enabled / {runtime.xray_clients_total} total",
        ),
        _doctor_check(
            "live_clients_sync",
            "Live VLESS clients match panel store",
            live_clients_synced,
            live_clients_detail,
        ),
        _doctor_check(
            "base_config_exists",
            "Xray base config",
            runtime.base_config_exists,
            runtime.base_config_path if runtime.base_config_exists else f"Missing: {runtime.base_config_path}",
        ),
        _doctor_check(
            "base_config_mergeable",
            "Base config can receive panel clients and routing",
            runtime.base_config_exists and not runtime.base_config_error,
            runtime.base_config_error or "Base config can be merged with generated routing",
        ),
        _doctor_check(
            "base_config_placeholders",
            "Base config placeholders",
            runtime.base_config_exists and base_config is not None and not placeholder_paths,
            "No placeholder values found in base config"
            if runtime.base_config_exists and base_config is not None and not placeholder_paths
            else (
                f"Found placeholders at: {', '.join(placeholder_paths[:6])}"
                if placeholder_paths
                else base_config_load_error or "Base config is missing"
            ),
        ),
        _doctor_check(
            "client_inbound",
            "Client VLESS inbound",
            client_inbound is not None and client_inbound.get("protocol") == "vless",
            f"Inbound tag {config.XRAY_CLIENT_INBOUND_TAG} exists and uses VLESS"
            if client_inbound is not None and client_inbound.get("protocol") == "vless"
            else f"Missing VLESS inbound tag {config.XRAY_CLIENT_INBOUND_TAG}",
        ),
        _doctor_check(
            "reality_keys",
            "REALITY settings match the live server",
            reality is not None and reality.ok,
            reality.detail
            if reality is not None
            else "Nothing to compare yet: no REALITY private key in the live config",
            warn=reality is None,
        ),
        _doctor_check(
            "client_inbound_sniffing",
            "Client inbound sniffing",
            bool(client_inbound and client_inbound.get("sniffing", {}).get("enabled")),
            "Sniffing is enabled for domain-aware routing"
            if client_inbound and client_inbound.get("sniffing", {}).get("enabled")
            else "Enable sniffing on the client inbound so domain overrides can match TLS/HTTP targets",
        ),
        _doctor_check(
            "egress_outbound",
            "Egress outbound",
            egress_outbound is not None,
            f"Outbound tag {egress_outbound_tag} exists"
            if egress_outbound is not None
            else f"Missing outbound tag {egress_outbound_tag}; egress/default traffic will have nowhere to go",
        ),
        _doctor_check(
            "block_outbound",
            "Block outbound",
            block_outbound is not None,
            "Outbound tag block exists"
            if block_outbound is not None
            else "Missing outbound tag block in the base config; the panel adds a blackhole outbound "
            "with that tag to every config it applies",
            warn=True,
        ),
        _doctor_check(
            "validate_command",
            "Validate command",
            runtime.validate_command_configured,
            "XRAY_VALIDATE_COMMAND is configured"
            if runtime.validate_command_configured
            else "XRAY_VALIDATE_COMMAND is empty",
        ),
        _doctor_check(
            "reload_command",
            "Reload command",
            runtime.reload_command_configured,
            "XRAY_RELOAD_COMMAND is configured"
            if runtime.reload_command_configured
            else "XRAY_RELOAD_COMMAND is empty",
        ),
        _doctor_check(
            "routing_export_sync",
            "Routing export sync",
            runtime.routing_export_in_sync,
            "Exported routing matches current preview"
            if runtime.routing_export_in_sync
            else "Click Export or Apply before relying on exported routing",
            warn=True,
        ),
        _doctor_check(
            "merged_config_sync",
            "Merged config sync",
            runtime.merged_config_export_in_sync is True,
            "Exported merged config matches current preview"
            if runtime.merged_config_export_in_sync is True
            else "Merged config is missing, stale, or unavailable until base config is valid",
            warn=True,
        ),
    ]

    ready = all(check.status != "error" for check in checks)
    return XrayDoctorStatus(
        status="ready" if ready else "needs_attention",
        ready=ready,
        checks=checks,
        settings=settings,
        runtime=runtime,
    )


def export_routing(require_base_config: bool = False) -> RoutingExportResult:
    try:
        exported = _export_artifacts(require_base_config=require_base_config)
        _save_action_state(
            action="export",
            status="ok",
            detail=exported.detail,
            export_path=exported.export_path,
            merged_config_path=exported.merged_config_path,
        )
        return exported
    except Exception as exc:
        _save_action_state(
            action="export",
            status="error",
            detail=str(exc),
            export_path=config.XRAY_ROUTING_EXPORT_PATH,
            merged_config_path=config.XRAY_MERGED_CONFIG_EXPORT_PATH,
        )
        raise


def build_merged_config() -> dict:
    preview = ro.get_preview()
    return _build_merged_config_from_rendered(preview.rendered_routing)


def render_merged_config_json() -> str:
    preview = ro.get_preview()
    return _render_merged_config_payload(preview.rendered_routing)


def read_exported_routing_json() -> str:
    export_path = Path(config.XRAY_ROUTING_EXPORT_PATH)
    if not export_path.exists():
        raise XrayNotConfiguredError(f"Exported routing file not found: {export_path}")
    return export_path.read_text(encoding="utf-8")


def read_exported_merged_config_json() -> str:
    merged_path = Path(config.XRAY_MERGED_CONFIG_EXPORT_PATH)
    if not merged_path.exists():
        raise XrayNotConfiguredError(f"Exported merged config file not found: {merged_path}")
    return merged_path.read_text(encoding="utf-8")


def validate_routing() -> RoutingValidationResult:
    command: list[str] = []
    try:
        exported = export_routing(require_base_config=True)

        if config.XRAY_PUSH_COMMAND.strip():
            push_cmd = _format_command(
                config.XRAY_PUSH_COMMAND,
                config_path=config.XRAY_MERGED_CONFIG_EXPORT_PATH,
                merged_config_path=config.XRAY_MERGED_CONFIG_EXPORT_PATH,
                export_path=config.XRAY_ROUTING_EXPORT_PATH,
                base_config_path=config.XRAY_BASE_CONFIG_PATH,
            )
            push_result = _run_command(push_cmd, "Xray config push")
            if push_result.returncode != 0:
                raise XrayCommandError(
                    (push_result.stderr or push_result.stdout or "Xray config push failed").strip()
                )

        command = _format_command(
            config.XRAY_VALIDATE_COMMAND,
            config_path=config.XRAY_MERGED_CONFIG_EXPORT_PATH,
            merged_config_path=config.XRAY_MERGED_CONFIG_EXPORT_PATH,
            export_path=config.XRAY_ROUTING_EXPORT_PATH,
            base_config_path=config.XRAY_BASE_CONFIG_PATH,
        )
        result = _run_command(command, "Xray validation")
        if result.returncode != 0:
            raise XrayCommandError(
                (result.stderr or result.stdout or "Xray validation failed").strip()
            )

        validation = RoutingValidationResult(
            status="ok",
            command=command,
            export_path=exported.export_path,
            merged_config_path=config.XRAY_MERGED_CONFIG_EXPORT_PATH,
            base_config_path=config.XRAY_BASE_CONFIG_PATH,
            stdout=result.stdout.strip(),
            stderr=result.stderr.strip(),
        )
        _save_action_state(
            action="validate",
            status="ok",
            detail="Xray validation completed",
            command=command,
            export_path=validation.export_path,
            merged_config_path=validation.merged_config_path,
        )
        return validation
    except Exception as exc:
        _save_action_state(
            action="validate",
            status="error",
            detail=str(exc),
            command=command,
            export_path=config.XRAY_ROUTING_EXPORT_PATH,
            merged_config_path=config.XRAY_MERGED_CONFIG_EXPORT_PATH,
        )
        raise


def reload_xray() -> RoutingReloadResult:
    command: list[str] = []
    try:
        validation = validate_routing()
        command = _format_command(
            config.XRAY_RELOAD_COMMAND,
            config_path=config.XRAY_MERGED_CONFIG_EXPORT_PATH,
            merged_config_path=config.XRAY_MERGED_CONFIG_EXPORT_PATH,
            export_path=config.XRAY_ROUTING_EXPORT_PATH,
            base_config_path=config.XRAY_BASE_CONFIG_PATH,
        )
        result = _run_command(command, "Xray reload")
        if result.returncode != 0:
            raise XrayCommandError((result.stderr or result.stdout or "Xray reload failed").strip())

        reloaded = RoutingReloadResult(
            status="ok",
            command=command,
            stdout=result.stdout.strip(),
            stderr=result.stderr.strip(),
            merged_config_path=config.XRAY_MERGED_CONFIG_EXPORT_PATH,
            validation=validation,
        )
        _save_action_state(
            action="reload",
            status="ok",
            detail="Xray reload completed",
            command=command,
            export_path=config.XRAY_ROUTING_EXPORT_PATH,
            merged_config_path=config.XRAY_MERGED_CONFIG_EXPORT_PATH,
        )
        return reloaded
    except Exception as exc:
        _save_action_state(
            action="reload",
            status="error",
            detail=str(exc),
            command=command,
            export_path=config.XRAY_ROUTING_EXPORT_PATH,
            merged_config_path=config.XRAY_MERGED_CONFIG_EXPORT_PATH,
        )
        raise


def apply_xray() -> RoutingApplyResult:
    command: list[str] = []
    backup_path = ""
    try:
        validation = validate_routing()

        # Idempotency guard: if the merged config is identical to what's already
        # live, restarting Xray would drop every active session for nothing.
        if _merged_matches_live():
            unchanged = RoutingApplyResult(
                status="unchanged",
                command=[],
                stdout="merged config identical to live; Xray restart skipped",
                live_config_path=config.XRAY_BASE_CONFIG_PATH,
                merged_config_path=config.XRAY_MERGED_CONFIG_EXPORT_PATH,
                backup_path="",
                validation=validation,
                reloaded=False,
            )
            _save_action_state(
                action="apply",
                status="ok",
                detail="No changes; Xray restart skipped (sessions preserved)",
                command=[],
                export_path=config.XRAY_ROUTING_EXPORT_PATH,
                merged_config_path=config.XRAY_MERGED_CONFIG_EXPORT_PATH,
                live_config_path=config.XRAY_BASE_CONFIG_PATH,
            )
            return unchanged

        command = _format_command(
            config.XRAY_RELOAD_COMMAND,
            config_path=config.XRAY_BASE_CONFIG_PATH,
            merged_config_path=config.XRAY_MERGED_CONFIG_EXPORT_PATH,
            export_path=config.XRAY_ROUTING_EXPORT_PATH,
            base_config_path=config.XRAY_BASE_CONFIG_PATH,
        )
        backup_path = _backup_live_config()
        _promote_merged_config_to_live()

        try:
            result = _run_command(command, "Xray reload")
        except XrayCommandError:
            _restore_live_config(backup_path)
            raise
        if result.returncode != 0:
            _restore_live_config(backup_path)
            raise XrayCommandError(
                (
                    result.stderr
                    or result.stdout
                    or "Xray reload failed after applying generated config"
                ).strip()
                + "; live config restored from backup"
            )

        applied = RoutingApplyResult(
            status="ok",
            command=command,
            stdout=result.stdout.strip(),
            stderr=result.stderr.strip(),
            live_config_path=config.XRAY_BASE_CONFIG_PATH,
            merged_config_path=config.XRAY_MERGED_CONFIG_EXPORT_PATH,
            backup_path=backup_path,
            validation=validation,
        )
        _save_action_state(
            action="apply",
            status="ok",
            detail="Generated Xray config applied and service reloaded",
            command=command,
            export_path=config.XRAY_ROUTING_EXPORT_PATH,
            merged_config_path=config.XRAY_MERGED_CONFIG_EXPORT_PATH,
            live_config_path=config.XRAY_BASE_CONFIG_PATH,
            backup_path=backup_path,
        )
        return applied
    except Exception as exc:
        _save_action_state(
            action="apply",
            status="error",
            detail=str(exc),
            command=command,
            export_path=config.XRAY_ROUTING_EXPORT_PATH,
            merged_config_path=config.XRAY_MERGED_CONFIG_EXPORT_PATH,
            live_config_path=config.XRAY_BASE_CONFIG_PATH,
            backup_path=backup_path or None,
        )
        raise
