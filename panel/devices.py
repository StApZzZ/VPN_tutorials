"""Employee devices on top of the existing VPN backends.

A device belongs to one user and is backed by exactly one VPN credential:
  * wg / awg -> a WireGuard peer on wg0 (awg0 mirrors it); `ref` = public key.
               The protocol only selects which config is handed out.
  * vless    -> an Xray VLESS client; `ref` = client id.

Lifecycle: active -> suspended (user disabled, expired, or by an operator) ->
active again, or -> revoked (backend credential deleted; the row stays for audit).

The panel process and the directory-sync timer both mutate wg0.conf and the Xray
client list, so every backend change runs under `backend_lock()` (a thread lock
plus an flock on a lock file next to the identity database).

Every Xray apply restarts Xray and drops every VLESS session, so bulk changes
(offboarding, expiry, a directory-sync run) go through `batch()`: one apply and
one policy refresh at the end instead of one per device.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
import threading
import uuid
from datetime import timedelta
from typing import Any, Iterator, Optional

import config
import config_links as cl
import peer_artifacts as pa
import client_artifacts as ca
import vpn_manager as vm
import xray_clients as xc
import xray_manager as xm
from auth import store
from models import Protocol

logger = logging.getLogger(__name__)

UNASSIGNED_EXTERNAL_ID = "_unassigned"
UNASSIGNED_DISPLAY_NAME = "Unassigned"
REASON_USER_DISABLED = "user_disabled"
REASON_EXPIRED = "expired"
REASON_MANUAL = "manual"
PEER_PROTOCOLS = ("wg", "awg")
# xray_clients accepts client names up to this length.
_BACKEND_NAME_MAX = 80

try:  # POSIX servers; Windows dev boxes fall back to the thread lock only
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

_thread_lock = threading.RLock()
_held = threading.local()
_batch = threading.local()


class DeviceError(ValueError):
    """Request cannot be fulfilled (validation, limits, backend not configured)."""


class DeviceNotFound(LookupError):
    pass


def _lock_path() -> str:
    db_path = str(config.CORPVPN_DB_PATH)
    base = os.path.dirname(db_path) if "://" not in db_path else tempfile.gettempdir()
    return os.path.join(base or tempfile.gettempdir(), ".corpvpn-backend.lock")


@contextlib.contextmanager
def backend_lock() -> Iterator[None]:
    """Reentrant within a thread (a second flock on a new descriptor would block
    the same process). Never hold it on the event-loop thread across an await:
    run locked work in a worker thread."""
    if getattr(_held, "depth", 0):
        _held.depth += 1
        try:
            yield
        finally:
            _held.depth -= 1
        return
    with _thread_lock:
        _held.depth = 1
        try:
            if fcntl is None:
                yield
                return
            os.makedirs(os.path.dirname(_lock_path()), exist_ok=True)
            with open(_lock_path(), "a") as handle:
                fcntl.flock(handle, fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(handle, fcntl.LOCK_UN)
        finally:
            _held.depth = 0


def _batching() -> bool:
    return getattr(_batch, "depth", 0) > 0


@contextlib.contextmanager
def batch(reason: str) -> Iterator[None]:
    """Defer Xray applies and policy refreshes to the end of the block (one of
    each), e.g. `with devices.batch("directory sync"): ...`. Reentrant within a
    thread. Inside, VLESS changes land in the client store without an apply; a
    failed final apply is logged, and the periodic policy refresh applies again
    because the live clients no longer match the store."""
    depth = getattr(_batch, "depth", 0)
    if depth == 0:
        _batch.xray, _batch.policy = False, False
    _batch.depth = depth + 1
    try:
        yield
    finally:
        _batch.depth = depth
        if depth == 0:
            xray, policy = _batch.xray, _batch.policy
            _batch.xray, _batch.policy = False, False
            if xray:
                try:
                    with backend_lock():
                        xm.apply_xray()
                except Exception:
                    logger.exception("Xray apply after %s failed; the periodic refresh retries", reason)
            if policy or xray:
                _policy_changed(reason)


def _policy_changed(reason: str) -> None:
    """Devices changed: bring the network policy (nft, Xray rules) along."""
    if _batching():
        _batch.policy = True
        return
    import network_policy

    network_policy.safe_refresh(reason)


def _xray_mutation(fn):
    """Mutate the VLESS client list and apply Xray atomically (rollback on
    failure). Inside batch() only the store changes; the apply comes at the end."""
    if _batching():
        result = fn()
        _batch.xray = True
        return result
    snapshot = xc.snapshot_clients()
    try:
        result = fn()
        xm.apply_xray()
        return result
    except Exception:
        try:
            xc.restore_clients(snapshot)
        except Exception:
            logger.exception("VLESS client rollback failed")
        raise


# ------------------------------------------------------------------- profiles
def profile_for(user: dict[str, Any]) -> dict[str, Any]:
    return store.get_profile(user.get("access_profile_id", "")) or store.default_profile()


def offered_protocols(profile: dict[str, Any]) -> list[str]:
    """Protocols the profile allows AND this gateway serves."""
    enabled = set(getattr(config, "ENABLED_PROTOCOLS", store.DEVICE_PROTOCOLS))
    return [p for p in profile["protocols"] if p in enabled]


def _clean_name(name: str) -> str:
    name = " ".join((name or "").split())
    if not name:
        raise DeviceError("device name is required")
    if len(name) > 40:
        raise DeviceError("device name is too long (40 characters max)")
    return name


def _get(device_id: str) -> dict[str, Any]:
    device = store.get_device(device_id)
    if device is None:
        raise DeviceNotFound(device_id)
    return device


def owned_device(device_id: str, user_id: str) -> dict[str, Any]:
    device = store.get_device(device_id)
    if device is None or device["user_id"] != user_id or device["status"] == "revoked":
        raise DeviceNotFound(device_id)
    return device


# -------------------------------------------------------------------- create
def _backend_name(username: str, name: str) -> str:
    """'<username> · <device>' within the backend's length limit: a long UPN
    is shortened, the device name is kept."""
    full = f"{username} · {name}"
    if len(full) <= _BACKEND_NAME_MAX:
        return full
    room = max(_BACKEND_NAME_MAX - len(name) - len(" · ") - 1, 1)
    return f"{username[:room]}… · {name}"


def _check_allowed(user: dict[str, Any], protocol: str, profile: dict[str, Any], exclude: str = "") -> None:
    """The owner may hold one more device of this protocol under `profile`."""
    if user["status"] != "active":
        raise DeviceError("the user is disabled")
    if protocol not in profile["protocols"]:
        raise DeviceError(f"protocol {protocol} is not allowed by the access profile '{profile['name']}'")
    live = [d for d in store.list_devices(user_id=user["id"]) if d["id"] != exclude]
    if len(live) >= profile["max_devices"]:
        raise DeviceError(f"device limit reached ({profile['max_devices']}); revoke an old device first")


def create(user: dict[str, Any], name: str, protocol: str, actor: str, ip: str = "") -> dict[str, Any]:
    if user["status"] != "active":
        raise DeviceError("the user is disabled")
    protocol = (protocol or "").strip().lower()
    if protocol not in store.DEVICE_PROTOCOLS:
        raise DeviceError("protocol must be one of: " + ", ".join(store.DEVICE_PROTOCOLS))
    if protocol not in getattr(config, "ENABLED_PROTOCOLS", store.DEVICE_PROTOCOLS):
        raise DeviceError(f"protocol {protocol} is not enabled on this gateway")
    _check_allowed(user, protocol, profile_for(user))
    name = _clean_name(name)
    device_id = uuid.uuid4().hex

    with backend_lock():
        # Again under the lock, with the owner read afresh: parallel requests
        # must not all pass the limit, and a user disabled a moment ago must not
        # get a new device.
        user = store.get_user(user["id"]) or user
        profile = profile_for(user)
        _check_allowed(user, protocol, profile)
        backend_name = _backend_name(user["username"], name)
        expires_at = ""
        if profile["device_ttl_days"] > 0:
            expires_at = store.iso(store.now() + timedelta(days=profile["device_ttl_days"]))
        values = {
            "id": device_id,
            "user_id": user["id"],
            "name": name,
            "protocol": protocol,
            "status": "active",
            "created_by": actor,
            "expires_at": expires_at,
        }
        if protocol in PEER_PROTOCOLS:
            device = store.insert_device({**values, "ref": vm.create_peer(backend_name)["public_key"]})
        else:
            if not xc.get_settings_status().ready:
                raise DeviceError("VLESS is not configured on this gateway")

            def _create_vless():
                # The device row exists before Xray is applied, so the owner's
                # access-profile rules are part of that one apply.
                client = xc.create_client(name=backend_name, email=f"dev-{device_id[:12]}@corpvpn")
                return store.insert_device({**values, "ref": client.id})

            try:
                device = _xray_mutation(_create_vless)
            except Exception:
                store.delete_device(device_id)
                raise
    _policy_changed("device.create")
    store.audit(
        "device.create", actor=actor, target=device_id, ip=ip,
        details={"user": user["username"], "name": name, "protocol": protocol, "expires_at": expires_at},
    )
    return device


# ------------------------------------------------------------------ status
def _backend_active(device: dict[str, Any]) -> Optional[bool]:
    """Whether the device's credential is live right now (None: it is gone)."""
    if device["protocol"] in PEER_PROTOCOLS:
        for peer in vm.get_all_peers():
            if peer.public_key == device["ref"]:
                return not peer.deactivated
        return None
    try:
        return xc.get_client(device["ref"]).enabled
    except xc.XrayClientNotFound:
        return None


def _revoke_links(device: dict[str, Any]) -> None:
    if device["protocol"] not in PEER_PROTOCOLS:
        return
    try:
        revoked = cl.revoke_links_for_peer(device["ref"])
    except Exception:
        logger.exception("could not revoke the config links of device %s", device["id"])
        return
    if revoked:
        logger.info("revoked %d open config link(s) of device %s", revoked, device["id"])


def _backend_set_active(device: dict[str, Any], active: bool) -> None:
    if device["protocol"] in PEER_PROTOCOLS:
        try:
            (vm.activate_peer if active else vm.deactivate_peer)(device["ref"])
        except Exception:
            logger.exception("peer %s… state change failed", device["ref"][:10])
            raise
        return
    try:
        client = xc.get_client(device["ref"])
    except xc.XrayClientNotFound:
        logger.warning("VLESS client %s is gone; only the device row changes", device["ref"])
        return
    if client.enabled != active:
        _xray_mutation(lambda: xc.toggle_client(device["ref"]))


def set_active(device_id: str, active: bool, *, actor: str, reason: str = REASON_MANUAL, ip: str = "") -> dict[str, Any]:
    target = "active" if active else "suspended"
    with backend_lock():
        # Row and owner are read under the lock: a concurrent disable of the owner
        # must not be overtaken by a resume that saw the old status.
        device = _get(device_id)
        if device["status"] == "revoked":
            raise DeviceError("the device is revoked")
        if active:
            owner = store.get_user(device["user_id"])
            if owner is None or owner["status"] != "active":
                raise DeviceError("the owner is disabled")
            if device["expires_at"] and store.parse_iso(device["expires_at"]) <= store.now():
                raise DeviceError("the device has expired; issue a new one")
        changed = device["status"] != target
        if changed:
            _backend_set_active(device, active)
        elif _backend_active(device) not in (active, None):
            # The row already says so but the credential disagrees (changed on a
            # low-level page or by hand): bring the backend in line.
            logger.warning("device %s: backend state differed from the row; fixing", device_id)
            _backend_set_active(device, active)
        if changed:
            store.update_device(device_id, status=target, suspend_reason="" if active else reason)
    if not active:
        _revoke_links(device)
    if changed:
        store.audit(
            "device.resume" if active else "device.suspend", actor=actor, target=device_id, ip=ip,
            details={"name": device["name"], "reason": reason},
        )
        _policy_changed("device.resume" if active else "device.suspend")
    return _get(device_id)


def revoke(device_id: str, *, actor: str, ip: str = "") -> dict[str, Any]:
    with backend_lock():
        device = _get(device_id)
        if device["status"] == "revoked":
            return device
        if device["protocol"] in PEER_PROTOCOLS:
            if any(p.public_key == device["ref"] for p in vm.get_all_peers()):
                vm.delete_peer(device["ref"])
        else:
            try:
                xc.get_client(device["ref"])
            except xc.XrayClientNotFound:
                pass
            else:
                _xray_mutation(lambda: xc.delete_client(device["ref"]))
        store.update_device(device_id, status="revoked", suspend_reason="")
    _revoke_links(device)
    store.audit("device.revoke", actor=actor, target=device_id, ip=ip, details={"name": device["name"]})
    _policy_changed("device.revoke")
    return _get(device_id)


def assign(device_id: str, user_id: str, *, actor: str, actor_role: str = "admin", ip: str = "") -> dict[str, Any]:
    """Give a device to another user. The new owner's profile must allow the
    protocol and have room. Below admin, only devices nobody owns yet may be
    handed out, and only to users: a device carries its owner's network access,
    so moving one is a way to widen someone's reach."""
    with backend_lock():
        device = _get(device_id)
        if device["status"] == "revoked":
            raise DeviceError("the device is revoked")
        user = store.get_user(user_id)
        if user is None:
            raise DeviceError("unknown user")
        previous = store.get_user(device["user_id"])
        if store.ROLE_RANK.get(actor_role, 0) < store.ROLE_RANK["admin"]:
            if previous is not None and previous["external_id"] != UNASSIGNED_EXTERNAL_ID:
                raise DeviceError("operators can only assign devices that have no owner yet")
            if store.ROLE_RANK.get(user["role"], 0) >= store.ROLE_RANK.get(actor_role, 0):
                raise DeviceError("operators can only assign devices to users")
        profile = profile_for(user)
        _check_allowed(user, device["protocol"], profile, exclude=device_id)
        store.update_device(device_id, user_id=user_id)
    previous_profile = profile_for(previous) if previous else None
    details = {"name": device["name"], "user": user["username"], "previous_user": (previous or {}).get("username", "")}
    if previous_profile is None or previous_profile["id"] != profile["id"]:
        details.update(profile=profile["name"], previous_profile=(previous_profile or {}).get("name", ""))
    store.audit("device.assign", actor=actor, target=device_id, ip=ip, details=details)
    _policy_changed("device.assign")
    return _get(device_id)


# ------------------------------------------------------------ lifecycle hooks
def suspend_user_devices(user_id: str, *, actor: str) -> int:
    count = 0
    with batch("user devices suspended"):
        for device in store.list_devices(user_id=user_id):
            if device["status"] == "active":
                try:
                    set_active(device["id"], False, actor=actor, reason=REASON_USER_DISABLED)
                    count += 1
                except Exception:
                    logger.exception("could not suspend device %s", device["id"])
    return count


def resume_user_devices(user_id: str, *, actor: str) -> int:
    """Only devices suspended BECAUSE the user was disabled come back."""
    count = 0
    with batch("user devices resumed"):
        for device in store.list_devices(user_id=user_id):
            if device["status"] == "suspended" and device["suspend_reason"] == REASON_USER_DISABLED:
                try:
                    set_active(device["id"], True, actor=actor, reason=REASON_USER_DISABLED)
                    count += 1
                except DeviceError:
                    pass  # expired meanwhile: stays suspended
                except Exception:
                    logger.exception("could not resume device %s", device["id"])
    return count


def enforce_expiry(actor: str = "system") -> int:
    count = 0
    moment = store.now()
    with batch("device expiry"):
        for device in store.list_devices():
            expires = store.parse_iso(device["expires_at"]) if device["expires_at"] else None
            if device["status"] == "active" and expires is not None and expires <= moment:
                try:
                    set_active(device["id"], False, actor=actor, reason=REASON_EXPIRED)
                    count += 1
                except Exception:
                    logger.exception("could not expire device %s", device["id"])
    return count


def mark_backend_deleted(ref: str, *, actor: str) -> int:
    """A peer / VLESS client was deleted outside the device API (legacy pages)."""
    count = 0
    for device in store.list_devices():
        if device["ref"] == ref:
            store.update_device(device["id"], status="revoked", suspend_reason="")
            store.audit("device.revoke", actor=actor, target=device["id"],
                        details={"name": device["name"], "via": "backend delete"})
            count += 1
    return count


# --------------------------------------------------------------- adoption
def unassigned_user() -> dict[str, Any]:
    """The placeholder owner of adopted devices (the UI shows owner.unassigned)."""
    existing = store.find_user("local", UNASSIGNED_EXTERNAL_ID)
    if existing and existing["display_name"] == UNASSIGNED_DISPLAY_NAME:
        return existing
    try:
        # Also renames the placeholder of databases that stored a localized name.
        return store.upsert_user(
            provider="local", external_id=UNASSIGNED_EXTERNAL_ID, username="unassigned",
            email="", display_name=UNASSIGNED_DISPLAY_NAME, role="user", groups=[], login=False,
        )
    except Exception:
        # The other process (directory sync, a second request) created it first.
        existing = store.find_user("local", UNASSIGNED_EXTERNAL_ID)
        if existing is None:
            raise
        return existing


def adopt_unmanaged(actor: str = "system") -> int:
    """Give every existing peer / VLESS client without a device row an owner-less
    device, so pre-v2 credentials can be assigned to employees in the panel.
    Serialized with every other backend change: two concurrent runs used to
    adopt the same credential twice."""
    with backend_lock():
        known = {d["ref"] for d in store.list_devices(include_revoked=True) if d["status"] != "revoked"}
        owner = None
        adopted = 0
        try:
            peers = vm.get_all_peers()
        except Exception:
            logger.exception("cannot list peers for adoption")
            peers = []
        try:
            clients = xc.list_clients()
        except Exception:
            logger.exception("cannot list VLESS clients for adoption")
            clients = []
        candidates = [(p.public_key, p.name, "wg", not p.deactivated) for p in peers]
        candidates += [(c.id, c.name, "vless", c.enabled) for c in clients]
        for ref, name, protocol, enabled in candidates:
            if ref in known:
                continue
            owner = owner or unassigned_user()
            store.insert_device({
                "user_id": owner["id"], "name": (name or ref[:12])[:40], "protocol": protocol, "ref": ref,
                "status": "active" if enabled else "suspended",
                "suspend_reason": "" if enabled else REASON_MANUAL, "created_by": "adopted",
            })
            known.add(ref)
            adopted += 1
    if adopted:
        store.audit("device.adopt", actor=actor, details={"count": adopted})
        _policy_changed("device.adopt")
    return adopted


# --------------------------------------------------------------- artifacts
def device_profile(device: dict[str, Any]) -> dict[str, Any]:
    owner = store.get_user(device["user_id"])
    return profile_for(owner) if owner else store.default_profile()


def find_by_ref(ref: str) -> Optional[dict[str, Any]]:
    """The live (not revoked) device backed by a peer public key / client id."""
    for device in store.list_devices():
        if device["ref"] == ref:
            return device
    return None


def public_view(device: dict[str, Any]) -> dict[str, Any]:
    """A device row for API responses: a WireGuard ref is a public key, but a
    VLESS ref is the client id, i.e. the credential itself."""
    if device["protocol"] in PEER_PROTOCOLS:
        return dict(device)
    return {**device, "ref": ""}


def artifact(device: dict[str, Any], variant: Optional[str] = None) -> dict[str, Any]:
    """Config for a device: {kind, filename, content, qr, mime}. WireGuard /
    AmneziaWG configs and the VLESS JSON follow the owner's access profile."""
    import network_policy

    if device["status"] != "active":
        raise DeviceError("the device is not active")
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in device["name"]).strip("-") or "device"
    profile = device_profile(device)
    if device["protocol"] in PEER_PROTOCOLS:
        variant = (variant or device["protocol"]).lower()
        if variant not in PEER_PROTOCOLS:
            raise DeviceError("variant must be wg or awg")
        protocol = Protocol.AMNEZIAWG if variant == "awg" else Protocol.WG
        try:
            conf = pa.resolve_peer_artifact(device["ref"], protocol=protocol).client_conf
        except (pa.PeerArtifactNotFound, pa.PeerArtifactValidationError) as exc:
            raise DeviceError(str(exc)) from exc
        conf = network_policy.client_conf(conf, profile)
        suffix = "-awg.conf" if variant == "awg" else ".conf"
        return {"kind": variant, "filename": f"{safe}{suffix}", "content": conf, "qr": conf, "mime": "text/plain"}
    variant = (variant or "link").lower()
    if variant not in ("link", "json"):
        raise DeviceError("variant must be link or json")
    if variant == "json":
        try:
            base = xc.render_client_config(xc.get_client(device["ref"]))
        except xc.XrayClientError as exc:
            raise DeviceError(str(exc)) from exc
        content = json.dumps(network_policy.vless_client_config(base, profile), ensure_ascii=False, indent=2) + "\n"
        return {"kind": "vless-json", "filename": f"{safe}-xray.json", "content": content, "qr": None,
                "mime": "application/json"}
    try:
        share = ca.resolve_client_artifact(device["ref"]).share
    except xc.XrayClientError as exc:
        raise DeviceError(str(exc)) from exc
    return {
        "kind": "vless", "filename": f"{safe}.txt", "content": share.share_link + "\n",
        "qr": share.share_link, "mime": "text/plain", "share_link": share.share_link,
    }


# ------------------------------------------------------------------ views
def describe(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add owner and live state (handshake / enabled) for the UI."""
    try:
        peers = {p.public_key: p for p in vm.get_all_peers()}
    except Exception:
        peers = {}
    users = {u["id"]: u for u in store.list_users()}
    out = []
    for device in devices:
        item = dict(device)
        owner = users.get(device["user_id"])
        item["owner"] = {
            "id": device["user_id"],
            "username": owner["username"] if owner else "?",
            "display_name": (owner["display_name"] or owner["username"]) if owner else "?",
            "unassigned": bool(owner and owner["external_id"] == UNASSIGNED_EXTERNAL_ID),
        }
        peer = peers.get(device["ref"]) if device["protocol"] in PEER_PROTOCOLS else None
        item["online"] = bool(peer and peer.status == "online")
        item["last_handshake"] = peer.last_handshake if peer else None
        out.append(public_view(item))
    return out
