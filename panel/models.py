from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Protocol(str, Enum):
    WG = "wg"
    AMNEZIAWG = "amneziawg"
    VLESS = "vless"


class RoutingRoute(str, Enum):
    """Where traffic matching a domain rule leaves the gateway (Xray/VLESS).

    direct  - straight from the gateway (the kernel routes corporate subnets
              through the site connector, everything else to the internet)
    egress  - through the configured egress outbound / balancer
    block   - dropped
    """

    DIRECT = "direct"
    EGRESS = "egress"
    BLOCK = "block"


class RoutingMatchType(str, Enum):
    EXACT = "exact"
    SUFFIX = "suffix"


class PeerStatus(str, Enum):
    ONLINE = "online"
    INACTIVE = "inactive"
    NEVER = "never"


class PeerInfo(BaseModel):
    public_key: str
    protocol: Protocol = Protocol.WG
    name: str
    vpn_ip: str
    # The address the peer's AmneziaWG config carries (the awg0 mirror of vpn_ip).
    awg_ip: str = ""
    status: PeerStatus
    # Last handshake as ISO-8601 UTC ("2026-10-01T12:00:00Z"); None = never.
    last_handshake: Optional[str] = None
    last_handshake_seconds: Optional[int] = None
    transfer_rx: int = 0
    transfer_tx: int = 0
    created_at: Optional[str] = None
    deactivated: bool = False


class CreatePeerRequest(BaseModel):
    name: str


class UpdatePeerRequest(BaseModel):
    name: str


class RoutingOverride(BaseModel):
    id: str
    match_type: RoutingMatchType
    value: str
    normalized_value: str
    route: RoutingRoute
    comment: str = ""
    enabled: bool = True
    created_at: str
    updated_at: str


class CreateRoutingOverrideRequest(BaseModel):
    match_type: RoutingMatchType
    value: str
    route: RoutingRoute
    comment: str = ""


class UpdateRoutingOverrideRequest(BaseModel):
    match_type: RoutingMatchType
    value: str
    route: RoutingRoute
    comment: str = ""


class RoutingPreviewRule(BaseModel):
    priority: int
    route: RoutingRoute
    outbound: str
    match_type: RoutingMatchType
    value: str
    normalized_value: str
    rendered_match: str
    rendered_rule: str
    xray_rule: dict


class RoutingDomainCheck(BaseModel):
    input_value: str
    normalized_value: str
    matched: bool
    source: str
    outbound: str
    rendered_rule: str
    detail: str
    override_id: Optional[str] = None
    match_type: Optional[RoutingMatchType] = None
    route: Optional[RoutingRoute] = None


class RoutingPreview(BaseModel):
    routing_order: list[str]
    manual_rules: list[RoutingPreviewRule]
    manual_overrides_enabled: int
    rendered_routing: dict
    status: str = "ok"


class RoutingLastAction(BaseModel):
    action: str
    status: str
    updated_at: str
    detail: str = ""
    command: list[str] = Field(default_factory=list)
    export_path: Optional[str] = None
    merged_config_path: Optional[str] = None
    live_config_path: Optional[str] = None
    backup_path: Optional[str] = None


class RoutingRuntimeStatus(BaseModel):
    export_path: str
    merged_config_path: str
    base_config_path: str
    action_state_path: str
    apply_backup_dir: str
    export_exists: bool
    merged_config_exists: bool
    base_config_exists: bool
    action_state_exists: bool
    validate_command_configured: bool
    reload_command_configured: bool
    xray_clients_total: int = 0
    xray_clients_enabled: int = 0
    current_routing_sha256: str
    exported_routing_sha256: Optional[str] = None
    routing_export_in_sync: bool
    current_merged_config_sha256: Optional[str] = None
    exported_merged_config_sha256: Optional[str] = None
    merged_config_export_in_sync: Optional[bool] = None
    last_action: Optional[RoutingLastAction] = None
    action_state_error: str = ""
    base_config_error: str = ""


class RoutingExportResult(BaseModel):
    status: str = "ok"
    export_path: str
    merged_config_path: Optional[str] = None
    bytes_written: int
    merged_bytes_written: int = 0
    manual_overrides_enabled: int
    routing_sha256: str
    merged_config_sha256: Optional[str] = None
    rendered_routing: dict
    detail: str = ""


class RoutingValidationResult(BaseModel):
    status: str = "ok"
    command: list[str]
    export_path: str
    merged_config_path: str
    base_config_path: str
    stdout: str = ""
    stderr: str = ""


class RoutingReloadResult(BaseModel):
    status: str = "ok"
    command: list[str]
    stdout: str = ""
    stderr: str = ""
    merged_config_path: str
    validation: RoutingValidationResult


class RoutingApplyResult(BaseModel):
    status: str = "ok"
    command: list[str]
    stdout: str = ""
    stderr: str = ""
    live_config_path: str
    merged_config_path: str
    backup_path: str
    validation: RoutingValidationResult
    # False when the merged config was byte-identical to live and the restart
    # was skipped (no client sessions dropped).
    reloaded: bool = True


class XrayClientProfile(BaseModel):
    id: str
    name: str
    email: str
    enabled: bool = True
    created_at: str
    updated_at: str


class CreateXrayClientRequest(BaseModel):
    name: str
    email: Optional[str] = None


class UpdateXrayClientRequest(BaseModel):
    name: str
    email: Optional[str] = None


class CreateConfigLinkRequest(BaseModel):
    peer_public_key: str = Field(min_length=1)
    user_id: Optional[str] = Field(default=None, max_length=64)
    label: str = Field(default="", max_length=120)
    ttl_days: Optional[int] = Field(default=None, gt=0, le=30)


class ConfigLinkCreated(BaseModel):
    code: str
    url: str
    expires_at: str


class ConfigLinkRecord(BaseModel):
    code: str
    peer_public_key: str
    user_id: Optional[str] = None
    protocol: str
    label: str = ""
    status: str
    # Computed, not stored: "expired" for a link still marked active past its TTL.
    state: str
    created_at: str
    expires_at: str
    consumed_at: str = ""


class XrayClientShare(BaseModel):
    id: str
    name: str
    email: str
    enabled: bool
    share_link: str
    outbound_config: dict
    client_config: dict
    settings_ready: bool = True
    settings_errors: list[str] = Field(default_factory=list)
    settings_warnings: list[str] = Field(default_factory=list)


class ClientArtifactProtocolOption(BaseModel):
    protocol: Protocol
    label: str
    share_endpoint: str
    config_endpoint: str
    qr_endpoint: str
    bundle_endpoint: str


class ClientArtifactCatalog(BaseModel):
    client_id: str
    client_name: str
    default_protocol: Protocol
    available_protocols: list[ClientArtifactProtocolOption]


class PeerArtifactProtocolOption(BaseModel):
    protocol: Protocol
    label: str
    config_endpoint: str
    qr_endpoint: Optional[str] = None


class PeerArtifactCatalog(BaseModel):
    peer_public_key: str
    peer_name: str
    default_protocol: Protocol
    available_protocols: list[PeerArtifactProtocolOption]


class XrayClientSettingsStatus(BaseModel):
    status: str
    ready: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    inbound_tag: str
    server: str
    port: int
    network: str
    security: str
    local_socks_port: int
    local_http_port: int
    reality_server_name: str = ""
    reality_public_key_configured: bool = False
    reality_short_id_configured: bool = False
    fingerprint: str = ""
    flow: str = ""


class XrayDoctorCheck(BaseModel):
    id: str
    label: str
    status: str
    detail: str = ""


class XrayDoctorStatus(BaseModel):
    status: str
    ready: bool
    checks: list[XrayDoctorCheck]
    settings: XrayClientSettingsStatus
    runtime: RoutingRuntimeStatus


class Stats(BaseModel):
    total_online: int
    total_peers: int
    never_connected: int
    inactive: int
    total_rx_bytes: int
    total_tx_bytes: int


class VpnInterfaceStatus(BaseModel):
    name: str
    protocol: Protocol
    configured: bool = True
    up: bool = False
    listen_port: Optional[int] = None
    peers_total: int = 0
    peers_online: int = 0
    peers_inactive: int = 0
    peers_never: int = 0
    transfer_rx: int = 0
    transfer_tx: int = 0
    error: str = ""


class VpnPeerLinkStatus(BaseModel):
    interface: str
    status: PeerStatus
    # ISO-8601 UTC, None = never (see PeerInfo).
    last_handshake: Optional[str] = None
    last_handshake_seconds: Optional[int] = None
    transfer_rx: int = 0
    transfer_tx: int = 0
    vpn_ip: str = ""
    endpoint: str = ""


class VpnClientStatus(BaseModel):
    name: str
    public_key: str
    deactivated: bool = False
    created_at: Optional[str] = None
    # Per-interface link state; None = the peer is not present on that interface.
    wg: Optional[VpnPeerLinkStatus] = None
    awg: Optional[VpnPeerLinkStatus] = None


class VpnStatus(BaseModel):
    interfaces: list[VpnInterfaceStatus]
    clients: list[VpnClientStatus]
    generated_at: str
