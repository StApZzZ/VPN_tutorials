"""HTTP API for devices and access profiles.

  /api/me/devices*   the employee portal: own devices only (role user and up)
  /api/devices*      operators: every device, issue for a user, suspend/resume/revoke
  /api/profiles*     admins: access profiles (limits, TTL, protocols, tunnel settings)
"""
from __future__ import annotations

import asyncio
import io
from typing import Optional
from urllib.parse import quote

import qrcode
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

import devices
import network_policy
import xray_clients as xc
from auth import sessions, store
from auth.deps import Principal, require_admin, require_operator, require_user


class DeviceRequest(BaseModel):
    name: str = Field(min_length=1, max_length=40)
    protocol: str


class IssueRequest(DeviceRequest):
    user_id: str


class AssignRequest(BaseModel):
    user_id: str


class ProfileRequest(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    description: str = ""
    tunnel_mode: str = "full"
    allowed_cidrs: list[str] = []
    dns_servers: list[str] = []
    search_domains: list[str] = []
    protocols: list[str] = ["wg", "awg", "vless"]
    max_devices: int = Field(default=3, ge=1, le=100)
    device_ttl_days: int = Field(default=0, ge=0, le=3650)


def _actor(p: Principal) -> str:
    return f"{p.provider}:{p.username}"


def _ip(request: Request) -> str:
    return sessions.client_ip(request)


def _raise(exc: Exception) -> None:
    if isinstance(exc, devices.DeviceNotFound):
        raise HTTPException(404, "device not found") from exc
    if isinstance(exc, (devices.DeviceError, store.StoreError, xc.XrayClientValidationError, xc.XrayClientConflict)):
        raise HTTPException(400, str(exc)) from exc
    raise exc


def _file(art: dict) -> Response:
    # Headers are latin-1: an ASCII fallback in filename=, the real (often Cyrillic)
    # name in filename*= (RFC 6266 / 5987), which every current browser prefers.
    name = art["filename"]
    stem, dot, ext = name.rpartition(".")
    cleaned = "".join(ch if ch.isascii() and (ch.isalnum() or ch in "-_") else "-" for ch in stem).strip("-")
    if cleaned != stem:  # lost characters: keep the fallback recognisable
        cleaned = "device" + (f"-{cleaned}" if cleaned else "")
    ascii_name = f"{cleaned}{dot}{ext}"
    return Response(
        content=art["content"],
        media_type=art["mime"],
        headers={
            "Content-Disposition": f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(name, safe='')}",
            "Cache-Control": "no-store",
        },
    )


def _qr(art: dict) -> StreamingResponse:
    if not art.get("qr"):
        raise HTTPException(400, "this config has no QR code; download the file")
    img = qrcode.make(art["qr"])
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png", headers={"Cache-Control": "no-store"})


def _session_user(principal: Principal) -> dict:
    user = store.get_user(principal.user_id) if principal.user_id else None
    if user is None:
        raise HTTPException(403, "devices belong to directory users; API tokens have none")
    return user


def build_router() -> APIRouter:
    router = APIRouter()

    # ------------------------------------------------------------ employee portal
    @router.get("/api/me/devices")
    async def my_devices(principal: Principal = Depends(require_user)):
        user = _session_user(principal)
        profile = devices.profile_for(user)
        items = await asyncio.to_thread(devices.describe, store.list_devices(user_id=user["id"]))
        for item in items:
            item.pop("ref", None)
            item.pop("created_by", None)
        return {
            "devices": items,
            "profile": {
                **{k: profile[k] for k in ("name", "description", "max_devices", "device_ttl_days", "tunnel_mode")},
                "protocols": devices.offered_protocols(profile),
            },
        }

    @router.post("/api/me/devices", status_code=201)
    async def my_device_create(req: DeviceRequest, request: Request, principal: Principal = Depends(require_user)):
        user = _session_user(principal)
        try:
            device = await asyncio.to_thread(devices.create, user, req.name, req.protocol, _actor(principal), _ip(request))
        except Exception as exc:
            _raise(exc)
        return {k: v for k, v in device.items() if k not in ("ref", "created_by")}

    @router.delete("/api/me/devices/{device_id}")
    async def my_device_revoke(device_id: str, request: Request, principal: Principal = Depends(require_user)):
        user = _session_user(principal)
        try:
            devices.owned_device(device_id, user["id"])
            await asyncio.to_thread(devices.revoke, device_id, actor=_actor(principal), ip=_ip(request))
        except Exception as exc:
            _raise(exc)
        return {"status": "revoked"}

    def _my_artifact(device_id: str, principal: Principal, variant: Optional[str]) -> dict:
        user = _session_user(principal)
        device = devices.owned_device(device_id, user["id"])
        art = devices.artifact(device, variant)
        store.audit("device.download", actor=_actor(principal), target=device_id,
                    details={"name": device["name"], "kind": art["kind"]})
        return art

    @router.get("/api/me/devices/{device_id}/config")
    async def my_device_config(device_id: str, variant: Optional[str] = None, principal: Principal = Depends(require_user)):
        try:
            return _file(await asyncio.to_thread(_my_artifact, device_id, principal, variant))
        except Exception as exc:
            _raise(exc)

    @router.get("/api/me/devices/{device_id}/qr")
    async def my_device_qr(device_id: str, variant: Optional[str] = None, principal: Principal = Depends(require_user)):
        try:
            return _qr(await asyncio.to_thread(_my_artifact, device_id, principal, variant))
        except Exception as exc:
            _raise(exc)

    # -------------------------------------------------------------- operators
    @router.get("/api/devices")
    async def all_devices(user_id: Optional[str] = None, include_revoked: bool = False,
                          _: Principal = Depends(require_operator)):
        await asyncio.to_thread(devices.adopt_unmanaged)
        rows = store.list_devices(user_id=user_id, include_revoked=include_revoked)
        return await asyncio.to_thread(devices.describe, rows)

    @router.get("/api/users/brief")
    async def users_brief(_: Principal = Depends(require_operator)):
        return [
            {"id": u["id"], "username": u["username"], "display_name": u["display_name"] or u["username"],
             "status": u["status"], "provider": u["provider"]}
            for u in store.list_users()
        ]

    # Responses below never carry a VLESS client id: it is the credential, and
    # operators get no private material (employees download configs in /me).
    @router.post("/api/devices", status_code=201)
    async def issue_device(req: IssueRequest, request: Request, principal: Principal = Depends(require_operator)):
        user = store.get_user(req.user_id)
        if user is None:
            raise HTTPException(404, "user not found")
        try:
            device = await asyncio.to_thread(devices.create, user, req.name, req.protocol, _actor(principal), _ip(request))
        except Exception as exc:
            _raise(exc)
        return devices.public_view(device)

    @router.post("/api/devices/{device_id}/suspend")
    async def suspend_device(device_id: str, request: Request, principal: Principal = Depends(require_operator)):
        try:
            device = await asyncio.to_thread(devices.set_active, device_id, False, actor=_actor(principal), ip=_ip(request))
        except Exception as exc:
            _raise(exc)
        return devices.public_view(device)

    @router.post("/api/devices/{device_id}/resume")
    async def resume_device(device_id: str, request: Request, principal: Principal = Depends(require_operator)):
        try:
            device = await asyncio.to_thread(devices.set_active, device_id, True, actor=_actor(principal), ip=_ip(request))
        except Exception as exc:
            _raise(exc)
        return devices.public_view(device)

    @router.delete("/api/devices/{device_id}")
    async def revoke_device(device_id: str, request: Request, principal: Principal = Depends(require_operator)):
        try:
            device = await asyncio.to_thread(devices.revoke, device_id, actor=_actor(principal), ip=_ip(request))
        except Exception as exc:
            _raise(exc)
        return devices.public_view(device)

    @router.post("/api/devices/{device_id}/assign")
    async def assign_device(device_id: str, req: AssignRequest, request: Request,
                            principal: Principal = Depends(require_operator)):
        try:
            device = await asyncio.to_thread(
                devices.assign, device_id, req.user_id,
                actor=_actor(principal), actor_role=principal.role, ip=_ip(request),
            )
        except Exception as exc:
            _raise(exc)
        return devices.public_view(device)

    @router.post("/api/devices/adopt")
    async def adopt_devices(principal: Principal = Depends(require_operator)):
        return {"adopted": await asyncio.to_thread(devices.adopt_unmanaged, _actor(principal))}

    # -------------------------------------------------------------- profiles
    @router.get("/api/profiles")
    async def profiles(_: Principal = Depends(require_operator)):
        return store.list_profiles()

    @router.post("/api/profiles", status_code=201)
    async def profile_create(req: ProfileRequest, request: Request, principal: Principal = Depends(require_admin)):
        try:
            created = store.create_profile(req.model_dump())
        except store.StoreError as exc:
            raise HTTPException(400, str(exc)) from exc
        store.audit("profile.create", actor=_actor(principal), target=created["id"], details=created, ip=_ip(request))
        await asyncio.to_thread(network_policy.safe_refresh, "profile.create")
        return created

    @router.put("/api/profiles/{profile_id}")
    async def profile_update(profile_id: str, req: ProfileRequest, request: Request,
                             principal: Principal = Depends(require_admin)):
        try:
            updated = store.update_profile(profile_id, req.model_dump())
        except store.StoreError as exc:
            raise HTTPException(400, str(exc)) from exc
        if updated is None:
            raise HTTPException(404, "profile not found")
        store.audit("profile.update", actor=_actor(principal), target=profile_id, details=updated, ip=_ip(request))
        await asyncio.to_thread(network_policy.safe_refresh, "profile.update")
        return updated

    @router.post("/api/profiles/{profile_id}/default")
    async def profile_default(profile_id: str, request: Request, principal: Principal = Depends(require_admin)):
        try:
            store.set_default_profile(profile_id)
        except store.StoreError as exc:
            raise HTTPException(404, str(exc)) from exc
        store.audit("profile.default", actor=_actor(principal), target=profile_id, ip=_ip(request))
        await asyncio.to_thread(network_policy.safe_refresh, "profile.default")
        return store.get_profile(profile_id)

    @router.delete("/api/profiles/{profile_id}")
    async def profile_delete(profile_id: str, request: Request, principal: Principal = Depends(require_admin)):
        try:
            deleted = store.delete_profile(profile_id)
        except store.StoreError as exc:
            raise HTTPException(400, str(exc)) from exc
        if not deleted:
            raise HTTPException(404, "profile not found")
        store.audit("profile.delete", actor=_actor(principal), target=profile_id, ip=_ip(request))
        await asyncio.to_thread(network_policy.safe_refresh, "profile.delete")
        return {"status": "deleted"}

    # ---------------------------------------------------------- network policy
    @router.get("/api/network/policy")
    async def policy_status(_: Principal = Depends(require_admin)):
        info = await asyncio.to_thread(network_policy.status)
        try:
            info["nft"] = (await asyncio.to_thread(network_policy.render))["nft"]
        except Exception as exc:  # shown in the UI next to the error
            info["nft"] = ""
            info["error"] = info["error"] or str(exc)
        return info

    @router.post("/api/network/policy/apply")
    async def policy_apply(request: Request, principal: Principal = Depends(require_admin)):
        try:
            info = await asyncio.to_thread(network_policy.refresh, "manual", True)
        except Exception as exc:
            store.audit("network.policy.apply_failed", actor=_actor(principal), details={"error": str(exc)},
                        ip=_ip(request))
            raise HTTPException(502, f"policy not applied: {exc}") from exc
        store.audit("network.policy.apply", actor=_actor(principal), details={"reason": "manual"}, ip=_ip(request))
        return info

    return router
