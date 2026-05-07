import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import config
from models import (
    RoutingDomainCheck,
    RoutingMatchType,
    RoutingOverride,
    RoutingPreview,
    RoutingPreviewRule,
    RoutingRoute,
)

_HOST_LABEL_RE = re.compile(r"^[a-z0-9-]+$")
_ROUTE_PRIORITY = {
    RoutingRoute.RU: 0,
    RoutingRoute.NON_RU: 1,
}
_MATCH_PRIORITY = {
    RoutingMatchType.EXACT: 0,
    RoutingMatchType.SUFFIX: 1,
}
_DEFAULT_RU_ZONE_RULES = (
    ("ru", "domain:ru"),
    ("xn--p1ai", "domain:xn--p1ai"),
)


class RoutingOverrideError(RuntimeError):
    pass


class RoutingOverrideValidationError(RoutingOverrideError):
    pass


class RoutingOverrideNotFound(RoutingOverrideError):
    pass


class RoutingOverrideConflict(RoutingOverrideError):
    pass


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_write(path: str, content: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=target.parent, prefix=".tmp_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(tmp_path, path)
    except Exception:
        os.unlink(tmp_path)
        raise


def normalize_domain(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        raise RoutingOverrideValidationError("Domain value is required")

    if re.search(r"\s", raw):
        raise RoutingOverrideValidationError("Domain must not contain spaces")

    normalized_input = raw.lower().rstrip(".")
    if not normalized_input:
        raise RoutingOverrideValidationError("Domain value is required")

    invalid_tokens = ("://", "/", "\\", ":")
    if any(token in normalized_input for token in invalid_tokens):
        raise RoutingOverrideValidationError("Use a hostname only, without scheme, path, or port")

    try:
        normalized = normalized_input.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise RoutingOverrideValidationError("Domain contains unsupported characters") from exc

    if len(normalized) > 253:
        raise RoutingOverrideValidationError("Domain is too long")

    labels = normalized.split(".")
    for label in labels:
        if not label:
            raise RoutingOverrideValidationError("Domain contains an empty label")
        if len(label) > 63:
            raise RoutingOverrideValidationError("Domain label is too long")
        if label.startswith("-") or label.endswith("-"):
            raise RoutingOverrideValidationError("Domain label must not start or end with '-'")
        if not _HOST_LABEL_RE.fullmatch(label):
            raise RoutingOverrideValidationError("Domain contains unsupported characters")

    return normalized


def matches_override(hostname: str, override: RoutingOverride) -> bool:
    normalized_host = normalize_domain(hostname)
    target = override.normalized_value
    if override.match_type == RoutingMatchType.EXACT:
        return normalized_host == target
    return normalized_host == target or normalized_host.endswith(f".{target}")


def _default_ru_zone_match(normalized_host: str) -> str | None:
    for suffix, rendered_match in _DEFAULT_RU_ZONE_RULES:
        if normalized_host == suffix or normalized_host.endswith(f".{suffix}"):
            return rendered_match
    return None


def _load_overrides() -> list[RoutingOverride]:
    path = Path(config.ROUTING_OVERRIDES_PATH)
    if not path.exists():
        return []

    try:
        with path.open(encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception as exc:
        raise RoutingOverrideError(f"Cannot read routing overrides store: {path}") from exc

    if not isinstance(payload, list):
        raise RoutingOverrideError("Routing overrides store must be a JSON array")

    try:
        overrides = [RoutingOverride(**item) for item in payload]
    except Exception as exc:
        raise RoutingOverrideError("Routing overrides store contains invalid entries") from exc

    return _sort_overrides(overrides)


def _save_overrides(overrides: list[RoutingOverride]) -> None:
    payload = [override.model_dump(mode="json") for override in _sort_overrides(overrides)]
    _atomic_write(
        config.ROUTING_OVERRIDES_PATH,
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
    )


def _sort_overrides(overrides: list[RoutingOverride]) -> list[RoutingOverride]:
    return sorted(overrides, key=lambda item: (item.created_at, item.id))


def _sort_for_routing(overrides: list[RoutingOverride]) -> list[RoutingOverride]:
    return sorted(
        overrides,
        key=lambda item: (
            _ROUTE_PRIORITY[item.route],
            _MATCH_PRIORITY[item.match_type],
            item.created_at,
            item.id,
        ),
    )


def _find_override(overrides: list[RoutingOverride], override_id: str) -> RoutingOverride:
    for override in overrides:
        if override.id == override_id:
            return override
    raise RoutingOverrideNotFound("Routing override not found")


def _ensure_unique(
    overrides: list[RoutingOverride],
    match_type: RoutingMatchType,
    normalized_value: str,
    exclude_id: str | None = None,
) -> None:
    for override in overrides:
        if exclude_id and override.id == exclude_id:
            continue
        if override.match_type == match_type and override.normalized_value == normalized_value:
            raise RoutingOverrideConflict(
                "Routing override with the same match type and domain already exists",
            )


def list_overrides() -> list[RoutingOverride]:
    return _load_overrides()


def create_override(
    match_type: RoutingMatchType,
    value: str,
    route: RoutingRoute,
    comment: str = "",
    enabled: bool = True,
) -> RoutingOverride:
    overrides = _load_overrides()
    normalized_value = normalize_domain(value)
    _ensure_unique(overrides, match_type, normalized_value)

    now = _now_iso()
    override = RoutingOverride(
        id=uuid4().hex[:8],
        match_type=match_type,
        value=(value or "").strip().rstrip("."),
        normalized_value=normalized_value,
        route=route,
        comment=(comment or "").strip(),
        enabled=enabled,
        created_at=now,
        updated_at=now,
    )
    overrides.append(override)
    _save_overrides(overrides)
    return override


def update_override(
    override_id: str,
    match_type: RoutingMatchType,
    value: str,
    route: RoutingRoute,
    comment: str = "",
) -> RoutingOverride:
    overrides = _load_overrides()
    current = _find_override(overrides, override_id)

    normalized_value = normalize_domain(value)
    _ensure_unique(overrides, match_type, normalized_value, exclude_id=override_id)

    updated = current.model_copy(
        update={
            "match_type": match_type,
            "value": (value or "").strip().rstrip("."),
            "normalized_value": normalized_value,
            "route": route,
            "comment": (comment or "").strip(),
            "updated_at": _now_iso(),
        }
    )

    stored = [updated if override.id == override_id else override for override in overrides]
    _save_overrides(stored)
    return updated


def toggle_override(override_id: str) -> RoutingOverride:
    overrides = _load_overrides()
    current = _find_override(overrides, override_id)
    updated = current.model_copy(
        update={
            "enabled": not current.enabled,
            "updated_at": _now_iso(),
        }
    )

    stored = [updated if override.id == override_id else override for override in overrides]
    _save_overrides(stored)
    return updated


def delete_override(override_id: str) -> None:
    overrides = _load_overrides()
    _find_override(overrides, override_id)
    filtered = [override for override in overrides if override.id != override_id]
    _save_overrides(filtered)


def get_preview() -> RoutingPreview:
    enabled = _sort_for_routing([override for override in list_overrides() if override.enabled])

    manual_rules: list[RoutingPreviewRule] = []
    xray_rules: list[dict] = [
        {
            "type": "field",
            "ip": ["geoip:private"],
            "outboundTag": "direct",
        }
    ]
    for index, override in enumerate(enabled, start=1):
        outbound = "direct" if override.route == RoutingRoute.RU else "to-egress"
        rendered_match = (
            f"full:{override.normalized_value}"
            if override.match_type == RoutingMatchType.EXACT
            else f"domain:{override.normalized_value}"
        )
        xray_rule = {
            "type": "field",
            "domain": [rendered_match],
            "outboundTag": outbound,
        }
        xray_rules.append(xray_rule)
        manual_rules.append(
            RoutingPreviewRule(
                priority=index,
                route=override.route,
                outbound=outbound,
                match_type=override.match_type,
                value=override.value,
                normalized_value=override.normalized_value,
                rendered_match=rendered_match,
                rendered_rule=f"{rendered_match} -> {outbound}",
                xray_rule=xray_rule,
            )
        )

    for _, rendered_match in _DEFAULT_RU_ZONE_RULES:
        xray_rules.append(
            {
                "type": "field",
                "domain": [rendered_match],
                "outboundTag": "direct",
            }
        )

    xray_rules.extend(
        [
            {
                "type": "field",
                "ip": ["geoip:ru"],
                "outboundTag": "direct",
            },
            {
                "type": "field",
                "network": "tcp,udp",
                "outboundTag": "to-egress",
            },
        ]
    )

    return RoutingPreview(
        routing_order=[
            "geoip:private -> direct",
            "manual:ru overrides -> direct",
            "manual:non_ru overrides -> to-egress",
            "builtin:.ru/.xn--p1ai -> direct",
            "geoip:ru -> direct",
            "default -> to-egress",
        ],
        manual_rules=manual_rules,
        manual_overrides_enabled=len(manual_rules),
        rendered_routing={
            "domainStrategy": "IPIfNonMatch",
            "rules": xray_rules,
        },
        status="ok",
    )


def check_domain(hostname: str) -> RoutingDomainCheck:
    normalized = normalize_domain(hostname)
    enabled = _sort_for_routing([override for override in list_overrides() if override.enabled])

    for override in enabled:
        if not matches_override(normalized, override):
            continue

        outbound = "direct" if override.route == RoutingRoute.RU else "to-egress"
        rendered_match = (
            f"full:{override.normalized_value}"
            if override.match_type == RoutingMatchType.EXACT
            else f"domain:{override.normalized_value}"
        )
        return RoutingDomainCheck(
            input_value=(hostname or "").strip(),
            normalized_value=normalized,
            matched=True,
            source="manual_override",
            override_id=override.id,
            match_type=override.match_type,
            route=override.route,
            outbound=outbound,
            rendered_rule=f"{rendered_match} -> {outbound}",
            detail="Matched an enabled manual override before geoip fallback",
        )

    default_match = _default_ru_zone_match(normalized)
    if default_match:
        return RoutingDomainCheck(
            input_value=(hostname or "").strip(),
            normalized_value=normalized,
            matched=True,
            source="builtin_ru_zone",
            match_type=RoutingMatchType.SUFFIX,
            route=RoutingRoute.RU,
            outbound="direct",
            rendered_rule=f"{default_match} -> direct",
            detail="Matched the built-in .ru/.xn--p1ai rule before geoip fallback",
        )

    return RoutingDomainCheck(
        input_value=(hostname or "").strip(),
        normalized_value=normalized,
        matched=False,
        source="fallback",
        outbound="builtin .ru/.xn--p1ai -> direct, geoip:ru -> direct, otherwise default -> to-egress",
        rendered_rule="no manual override",
        detail="No enabled manual override or built-in RU zone matched; Xray will continue to geoip:ru and then default routing",
    )
