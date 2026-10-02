from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote

from models import PeerArtifactCatalog, PeerArtifactProtocolOption, PeerInfo, Protocol
import vpn_manager as vm


class PeerArtifactError(Exception):
    """Base error for peer artifact delivery."""


class PeerArtifactNotFound(PeerArtifactError):
    """Peer or its config artifact could not be resolved."""


class PeerArtifactValidationError(PeerArtifactError):
    """Requested peer artifact protocol is unsupported."""


@dataclass(frozen=True)
class ResolvedPeerArtifact:
    protocol: Protocol
    peer: PeerInfo
    client_conf: str


def default_protocol() -> Protocol:
    return Protocol.WG


def supported_protocols() -> list[Protocol]:
    return [Protocol.WG, Protocol.AMNEZIAWG]


def _normalize_protocol(protocol: Protocol | None) -> Protocol:
    return protocol or default_protocol()


def _ensure_supported_protocol(protocol: Protocol) -> None:
    if protocol not in supported_protocols():
        raise PeerArtifactValidationError(
            f"Peer artifacts for protocol '{protocol.value}' are not implemented yet"
        )


def _get_peer(pubkey: str) -> PeerInfo:
    for peer in vm.get_all_peers():
        if peer.public_key == pubkey:
            return peer
    raise PeerArtifactNotFound("Peer not found")


def _peer_endpoint(pubkey: str, artifact_type: str, protocol: str | None = None) -> str:
    encoded_pubkey = quote(pubkey, safe="")
    endpoint = f"/api/peers/{encoded_pubkey}/{artifact_type}"
    if protocol:
        endpoint = f"{endpoint}?protocol={quote(protocol, safe='')}"
    return endpoint


def describe_peer_artifacts(pubkey: str) -> PeerArtifactCatalog:
    peer = _get_peer(pubkey)
    available_protocols = [
        PeerArtifactProtocolOption(
            protocol=Protocol.WG,
            label="WireGuard",
            config_endpoint=_peer_endpoint(peer.public_key, "config", protocol="wg"),
            qr_endpoint=_peer_endpoint(peer.public_key, "qr", protocol="wg"),
        ),
        PeerArtifactProtocolOption(
            protocol=Protocol.AMNEZIAWG,
            label="AmneziaWG",
            config_endpoint=_peer_endpoint(peer.public_key, "config", protocol="amneziawg"),
            qr_endpoint=_peer_endpoint(peer.public_key, "qr", protocol="amneziawg"),
        ),
    ]
    return PeerArtifactCatalog(
        peer_public_key=peer.public_key,
        peer_name=peer.name,
        default_protocol=default_protocol(),
        available_protocols=available_protocols,
    )


def resolve_peer_artifact(
    pubkey: str,
    protocol: Protocol | None = None,
) -> ResolvedPeerArtifact:
    normalized_protocol = _normalize_protocol(protocol)
    _ensure_supported_protocol(normalized_protocol)
    peer = _get_peer(pubkey)
    if normalized_protocol in {Protocol.WG, Protocol.AMNEZIAWG}:
        try:
            client_conf = vm.get_client_conf(pubkey, protocol=normalized_protocol)
        except Exception as exc:
            raise PeerArtifactValidationError(str(exc)) from exc
        if not client_conf:
            raise PeerArtifactNotFound("Config not available (private key not stored)")
        return ResolvedPeerArtifact(
            protocol=normalized_protocol,
            peer=peer,
            client_conf=client_conf,
        )
    raise PeerArtifactValidationError(
        f"Peer artifacts for protocol '{normalized_protocol.value}' are not implemented yet"
    )
