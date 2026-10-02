import re
from ipaddress import ip_network
from datetime import datetime, timezone
from uuid import uuid4

import config
import db
from models import (
    RoutingDomainCheck,
    RoutingMatchType,
    RoutingOverride,
    RoutingPreview,
    RoutingPreviewRule,
    RoutingRoute,
)
from sqlalchemy import text

_DDL = """
CREATE TABLE IF NOT EXISTS routing_rules (
    id               TEXT PRIMARY KEY,
    match_type       TEXT NOT NULL,
    value            TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    route            TEXT NOT NULL,
    comment          TEXT NOT NULL DEFAULT '',
    enabled          INTEGER NOT NULL DEFAULT 1,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    UNIQUE (match_type, normalized_value)
)
"""
def _engine():
    # Resolved per call so config.ROUTING_DB_PATH can be repointed (tests).
    return db.get_engine(config.ROUTING_DB_PATH, _DDL)

_HOST_LABEL_RE = re.compile(r"^[a-z0-9-]+$")
_ROUTE_PRIORITY = {
    RoutingRoute.BLOCK: 0,
    RoutingRoute.DIRECT: 1,
    RoutingRoute.EGRESS: 2,
}
_MATCH_PRIORITY = {
    RoutingMatchType.EXACT: 0,
    RoutingMatchType.SUFFIX: 1,
}


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


def _configured_direct_ip_rules() -> list[str]:
    direct_ips: list[str] = []
    seen: set[str] = set()
    for raw_value in getattr(config, "XRAY_DIRECT_IP_RULES", ()):
        value = (raw_value or "").strip()
        if not value:
            continue
        try:
            normalized = str(ip_network(value, strict=False))
        except ValueError as exc:
            raise RoutingOverrideValidationError(
                f"Invalid XRAY_DIRECT_IP_RULES entry: {value}"
            ) from exc
        if normalized not in seen:
            seen.add(normalized)
            direct_ips.append(normalized)
    return direct_ips


def _egress_target() -> tuple[str, str]:
    balancer = getattr(config, "XRAY_EGRESS_BALANCER_TAG", "").strip()
    if balancer:
        return "balancerTag", balancer
    outbound = getattr(config, "XRAY_EGRESS_OUTBOUND_TAG", "direct").strip() or "direct"
    return "outboundTag", outbound


def _egress_outbound_tags() -> list[str]:
    """Outbound tags the egress balancer fans traffic over (leastPing).

    More than one tag lets the balancer fail over when an exit degrades; with a
    single tag an observatory probe flap drops all egress traffic. Falls back to
    XRAY_EGRESS_OUTBOUND_TAG.
    """
    tags: list[str] = []
    seen: set[str] = set()
    for raw in getattr(config, "XRAY_EGRESS_OUTBOUND_TAGS", ()):
        value = (raw or "").strip()
        if value and value not in seen:
            seen.add(value)
            tags.append(value)
    if not tags:
        tags = [getattr(config, "XRAY_EGRESS_OUTBOUND_TAG", "direct").strip() or "direct"]
    return tags


def _load_overrides() -> list[RoutingOverride]:
    with _engine().connect() as conn:
        rows = conn.execute(
            text(
                "SELECT id, match_type, value, normalized_value, route, comment, enabled, "
                "created_at, updated_at FROM routing_rules"
            )
        ).mappings().all()
    overrides = [
        RoutingOverride(
            id=row["id"],
            match_type=RoutingMatchType(row["match_type"]),
            value=row["value"],
            normalized_value=row["normalized_value"],
            route=RoutingRoute(row["route"]),
            comment=row["comment"] or "",
            enabled=bool(row["enabled"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
        for row in rows
    ]
    return _sort_overrides(overrides)


def _save_overrides(overrides: list[RoutingOverride]) -> None:
    sorted_overrides = _sort_overrides(overrides)
    with _engine().begin() as conn:
        existing_ids = {
            row[0] for row in conn.execute(text("SELECT id FROM routing_rules")).fetchall()
        }
        new_ids = {o.id for o in sorted_overrides}
        for rule_id in existing_ids - new_ids:
            conn.execute(text("DELETE FROM routing_rules WHERE id = :id"), {"id": rule_id})
        for override in sorted_overrides:
            conn.execute(
                text(
                    "INSERT INTO routing_rules "
                    "(id, match_type, value, normalized_value, route, comment, enabled, created_at, updated_at) "
                    "VALUES (:id, :match_type, :value, :normalized_value, :route, :comment, :enabled, :created_at, :updated_at) "
                    "ON CONFLICT(id) DO UPDATE SET "
                    "match_type=:match_type, value=:value, normalized_value=:normalized_value, "
                    "route=:route, comment=:comment, enabled=:enabled, updated_at=:updated_at"
                ),
                {
                    "id": override.id,
                    "match_type": override.match_type.value,
                    "value": override.value,
                    "normalized_value": override.normalized_value,
                    "route": override.route.value,
                    "comment": override.comment,
                    "enabled": int(override.enabled),
                    "created_at": override.created_at,
                    "updated_at": override.updated_at,
                },
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


def _target(route: RoutingRoute) -> tuple[str, str]:
    """(Xray rule key, value) for a route."""
    if route == RoutingRoute.BLOCK:
        return "outboundTag", "block"
    if route == RoutingRoute.DIRECT:
        return "outboundTag", "direct"
    return _egress_target()


def _default_route() -> RoutingRoute:
    return RoutingRoute.DIRECT if getattr(config, "XRAY_DEFAULT_ROUTE", "egress") == "direct" else RoutingRoute.EGRESS


def _rendered_match(override: RoutingOverride) -> str:
    if override.match_type == RoutingMatchType.EXACT:
        return f"full:{override.normalized_value}"
    return f"domain:{override.normalized_value}"


def _guard_rules() -> list[dict]:
    """Destinations no VLESS user may reach (network_policy). Built from the
    configuration alone; an invalid NETWORK_POLICY_DENY_CIDRS fails the render,
    so Xray keeps its previous config rather than losing the guard."""
    import network_policy

    return network_policy.xray_guard_rules()


def _policy_rules() -> list[dict]:
    """Per-user rules from access profiles (network_policy); never fatal here."""
    try:
        import network_policy

        return network_policy.xray_policy_rules()
    except Exception:  # the policy module logs its own errors
        return []


def get_preview() -> RoutingPreview:
    enabled = _sort_for_routing([override for override in list_overrides() if override.enabled])
    egress_key, egress_value = _egress_target()
    default_key, default_value = _target(_default_route())

    manual_rules: list[RoutingPreviewRule] = []
    # The guard comes first and no rule can override it. Access-profile rules
    # follow: corporate subnets are private addresses, so geoip:private -> direct
    # would otherwise let every VLESS user reach them.
    policy_rules = _policy_rules()
    xray_rules: list[dict] = [*_guard_rules(), *policy_rules]
    xray_rules.append(
        {
            "type": "field",
            "ip": ["geoip:private"],
            "outboundTag": "direct",
        }
    )
    direct_ip_rules = _configured_direct_ip_rules()
    if direct_ip_rules:
        xray_rules.append(
            {
                "type": "field",
                "ip": direct_ip_rules,
                "outboundTag": "direct",
            }
        )
    for index, override in enumerate(enabled, start=1):
        target_key, outbound = _target(override.route)
        rendered_match = _rendered_match(override)
        xray_rule = {
            "type": "field",
            "domain": [rendered_match],
            target_key: outbound,
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

    xray_rules.append(
        {
            "type": "field",
            "network": "tcp,udp",
            default_key: default_value,
        }
    )

    rendered_routing = {
        "domainStrategy": "IPIfNonMatch",
        "rules": xray_rules,
    }
    if egress_key == "balancerTag":
        rendered_routing["balancers"] = [
            {
                "tag": egress_value,
                "selector": _egress_outbound_tags(),
                "strategy": {"type": "leastPing"},
            }
        ]

    order = ["always denied (metadata, loopback, gateway, site link) -> block"]
    if policy_rules:
        order.append(f"access profiles, client isolation ({len(policy_rules)} rules) -> direct / block")
    order.extend(
        [
            "geoip:private -> direct",
            "configured direct IP rules -> direct",
            "manual:block rules -> block",
            "manual:direct rules -> direct",
            f"manual:egress rules -> {egress_value}",
            f"default -> {default_value}",
        ]
    )
    return RoutingPreview(
        routing_order=order,
        manual_rules=manual_rules,
        manual_overrides_enabled=len(manual_rules),
        rendered_routing=rendered_routing,
        status="ok",
    )


def check_domain(hostname: str) -> RoutingDomainCheck:
    normalized = normalize_domain(hostname)
    enabled = _sort_for_routing([override for override in list_overrides() if override.enabled])

    for override in enabled:
        if not matches_override(normalized, override):
            continue

        outbound = _target(override.route)[1]
        rendered_match = _rendered_match(override)
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
            detail="Matched an enabled domain rule",
        )

    default = _default_route()
    outbound = _target(default)[1]
    return RoutingDomainCheck(
        input_value=(hostname or "").strip(),
        normalized_value=normalized,
        matched=False,
        source="fallback",
        route=default,
        outbound=outbound,
        rendered_rule=f"default -> {outbound}",
        detail="No enabled domain rule matched; the default route applies "
        "(private and corporate addresses follow the access-profile rules first)",
    )
