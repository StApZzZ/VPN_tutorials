"""Local account management and employee enrolment routes."""
import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

import config
import network_policy
from auth import local_accounts as local, sessions, store
from auth.deps import Principal, require_admin, require_user


class LocalUserRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    role: str = "user"
    access_profile_id: str = ""
    display_name: str = Field(default="", max_length=128)


class LocalUserUpdate(BaseModel):
    role: str = "user"
    access_profile_id: str = ""
    display_name: str = Field(default="", max_length=128)


class TotpRequest(BaseModel):
    code: str = Field(min_length=6, max_length=32)


def build_router(templates):
    router = APIRouter()
    slots = asyncio.Semaphore(2)

    def enabled():
        if not config.LOCAL_ACCOUNTS_ENABLED:
            raise HTTPException(404, "local_accounts_disabled")

    def event(action, request, principal, user_id):
        store.audit(action, actor=principal.username, target=user_id, ip=sessions.client_ip(request))

    def fail(exc):
        raise HTTPException(400, str(exc)) from exc

    @router.get("/api/auth/local-users")
    def list_users(_=Depends(require_admin)):
        enabled()
        return local.users()

    @router.post("/api/auth/local-users", status_code=201)
    def create_user(body: LocalUserRequest, request: Request, principal: Principal = Depends(require_admin)):
        enabled()
        try:
            user = local.create(body.username, body.role, body.access_profile_id, body.display_name)
        except store.StoreError as exc:
            fail(exc)
        event("user.create", request, principal, user["id"])
        return user

    @router.put("/api/auth/local-users/{user_id}")
    def update_user(user_id: str, body: LocalUserUpdate, request: Request, principal: Principal = Depends(require_admin)):
        enabled()
        try:
            user = local.update(user_id, body.role, body.access_profile_id, body.display_name)
        except store.StoreError as exc:
            fail(exc)
        event("user.update", request, principal, user_id)
        network_policy.safe_refresh("local_user.update")
        return user

    @router.post("/api/auth/local-users/{user_id}/invite")
    @router.post("/api/auth/local-users/{user_id}/reset")
    def invite_user(user_id: str, request: Request, principal: Principal = Depends(require_admin)):
        enabled()
        try:
            token = local.invite(user_id)
        except store.StoreError as exc:
            fail(exc)
        event("password.reset" if request.url.path.endswith("/reset") else "user.invite", request, principal, user_id)
        return {"invite_url": config.PANEL_PUBLIC_URL + "/invite/" + token, "expires_in": 72 * 3600}

    @router.get("/invite/{token}")
    def invite_page(token: str, request: Request):
        enabled()
        try:
            user = local.invitation(token)
            factor = local.begin_totp(user["id"])
        except store.StoreError as exc:
            raise HTTPException(400, str(exc)) from exc
        return templates.TemplateResponse(request, "invite.html", {"request": request, "user": user,
            "factor": factor, "token": token, "required": local.required(user), "error": "", "codes": None})

    @router.post("/invite/{token}")
    async def accept_invite(token: str, request: Request):
        enabled()
        from auth.routes import _same_origin
        if not _same_origin(request):
            raise HTTPException(403, "origin")
        form = await request.form(max_fields=8, max_files=0, max_part_size=1024)
        ip = sessions.client_ip(request)
        from auth.deps import limiter
        if limiter.blocked(ip):
            raise HTTPException(429, "locked")
        try:
            async with slots:
                user, codes = await asyncio.to_thread(local.accept_invite, token, str(form.get("password", "")), str(form.get("otp", "")))
        except store.StoreError as exc:
            limiter.failed(ip)
            raise HTTPException(400, str(exc)) from exc
        store.audit("password.set", actor="local:" + user["username"], target=user["id"], ip=ip)
        return templates.TemplateResponse(request, "invite.html", {"request": request, "user": user, "codes": codes})

    @router.post("/api/me/totp/start")
    def start_totp(request: Request, principal: Principal = Depends(require_user)):
        enabled()
        try:
            value = local.begin_totp(principal.user_id)
        except store.StoreError as exc:
            fail(exc)
        event("totp.start", request, principal, principal.user_id)
        return value

    @router.post("/api/me/totp/confirm")
    def confirm_totp(body: TotpRequest, request: Request, principal: Principal = Depends(require_user)):
        enabled()
        try:
            codes = local.finish_totp(principal.user_id, body.code)
        except store.StoreError as exc:
            fail(exc)
        event("totp.enrol", request, principal, principal.user_id)
        return {"recovery_codes": codes}

    return router
