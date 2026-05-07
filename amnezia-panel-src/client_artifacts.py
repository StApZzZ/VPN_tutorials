from __future__ import annotations

from dataclasses import dataclass

from models import ClientArtifactCatalog, ClientArtifactProtocolOption, Protocol, XrayClientProfile, XrayClientShare
import xray_clients as xc


@dataclass(frozen=True)
class ResolvedClientArtifact:
    protocol: Protocol
    client: XrayClientProfile
    share: XrayClientShare


def default_protocol() -> Protocol:
    return Protocol.VLESS


def supported_protocols() -> list[Protocol]:
    return [Protocol.VLESS]


def _normalize_protocol(protocol: Protocol | None) -> Protocol:
    return protocol or default_protocol()


def _ensure_supported_protocol(protocol: Protocol) -> None:
    if protocol not in supported_protocols():
        raise xc.XrayClientValidationError(
            f"Client artifacts for protocol '{protocol.value}' are not implemented yet"
        )


def describe_client_artifacts(client_id: str) -> ClientArtifactCatalog:
    client = xc.get_client(client_id)
    available_protocols = [
        ClientArtifactProtocolOption(
            protocol=Protocol.VLESS,
            label="VLESS/Xray",
            share_endpoint=f"/api/xray/clients/{client.id}/share?protocol=vless",
            config_endpoint=f"/api/xray/clients/{client.id}/config?protocol=vless",
            qr_endpoint=f"/api/xray/clients/{client.id}/qr?protocol=vless",
            bundle_endpoint=f"/api/xray/clients/{client.id}/bundle?protocol=vless",
        )
    ]
    return ClientArtifactCatalog(
        client_id=client.id,
        client_name=client.name,
        default_protocol=default_protocol(),
        available_protocols=available_protocols,
    )


def resolve_client_artifact(
    client_id: str,
    protocol: Protocol | None = None,
) -> ResolvedClientArtifact:
    normalized_protocol = _normalize_protocol(protocol)
    _ensure_supported_protocol(normalized_protocol)
    client = xc.get_client(client_id)
    if normalized_protocol == Protocol.VLESS:
        return ResolvedClientArtifact(
            protocol=normalized_protocol,
            client=client,
            share=xc.get_share(client_id),
        )
    raise xc.XrayClientValidationError(
        f"Client artifacts for protocol '{normalized_protocol.value}' are not implemented yet"
    )
