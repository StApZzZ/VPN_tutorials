"""HTTP routes for sign-in / sign-out and the admin 'Access' API.

Work that can wait on a directory, an IdP, nft or Xray (sign-ins, provider
tests, directory sync, disabling users) runs in worker threads: the panel is a
single event loop, and one slow LDAP bind must not stall every other request.
"""
from __future__ import annotations

import asyncio
import logging
import secrets
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

import config
import devices
import directory_sync
from auth import ldap_auth, oidc, sessions, store, tokens, local_accounts
from auth.deps import Principal, current_principal, limiter, require_admin, require_auditor, require_user
from auth.identity import (
    PASSWORD_MAX,
    REASON_ADMIN,
    USERNAME_MAX,
    AccessDenied,
    AuthFailed,
    DirectoryUnavailable,
    GroupsUnknown,
    MfaRequired,
    admit,
    attestation_due,
    is_break_glass,
    is_break_glass_user,
    local_admin_user,
    secure_equals,
)

logger = logging.getLogger(__name__)

LOGIN_ERRORS = {
    "failed": "Invalid username, password or authenticator code.",
    "denied": "Access denied. Contact your IT administrator.",
    "locked": "Too many failed attempts. Try again later.",
    "sso": "SSO sign-in failed.",
    "mfa": "Your identity provider must verify multi-factor authentication.",
    "groups_claim": "Your identity provider did not supply VPN group membership.",
    "origin": "Request rejected. Open the sign-in page again.",
    "unavailable": "Directory temporarily unavailable.",
}


class PolicyRequest(BaseModel):
    provider: str = "any"
    group_name: str = Field(min_length=1)
    role: str
    priority: int = Field(default=100, ge=0)
    access_profile_id: str = ""


class TokenRequest(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    role: str = "operator"
    ttl_days: int = Field(default=0, ge=0, le=3650)


def _home_for(role: str) -> str:
    return "/me" if role == "user" else "/"


def _same_origin(request: Request) -> bool:
    origin = request.headers.get("origin") or request.headers.get("referer") or ""
    if not origin:
        return True  # non-browser client; the session cookie is not involved yet
    return urlparse(origin).netloc == request.headers.get("host", "")


def _login_error(code: str) -> RedirectResponse:
    return RedirectResponse(f"/login?error={code}", status_code=302)


@dataclass
class _Outcome:
    """Result of a sign-in step run in a worker thread: a login error code, or a
    user with a fresh session."""

    error: str = ""
    user: Optional[dict] = None
    session: str = ""


def _signed_in(user: dict, request: Request) -> _Outcome:
    raw, _ = sessions.create(user, request)
    return _Outcome(user=user, session=raw)


def _finish(outcome: _Outcome, request: Request) -> RedirectResponse:
    if outcome.error:
        return _login_error(outcome.error)
    response = RedirectResponse(_home_for(outcome.user["role"]), status_code=302)
    sessions.set_cookie(response, outcome.session, request)
    return response


# Sign-ins may wait on a directory or an IdP (seconds when one is slow). They run
# in worker threads, and at most this many at once: a flood against a slow
# directory then queues here instead of taking every thread the panel has.
_SIGN_IN_SLOTS = 8


def _password_sign_in(request: Request, username: str, password: str, otp: str = "") -> _Outcome:
    """Break-glass, then LDAP. Blocking: runs in a worker thread."""
    ip = sessions.client_ip(request)
    if len(username) > USERNAME_MAX or len(password) > PASSWORD_MAX:
        limiter.failed(ip)
        store.audit("auth.failed", actor=username[:USERNAME_MAX], details={"reason": "input too long"}, ip=ip)
        return _Outcome(error="failed")
    # The break-glass name has no directory account behind it: only the IP
    # budget applies, so nobody can lock the emergency login on purpose.
    account = "" if username.casefold() == config.PANEL_USERNAME.casefold() else username
    if limiter.blocked(ip, account):
        if limiter.first_notice(ip, account):
            store.audit("auth.locked", actor=username, ip=ip)
        return _Outcome(error="locked")

    if is_break_glass(username, password, ip):
        user = local_admin_user()
        store.audit("auth.login", actor=f"local:{username}", target=user["id"], details={"role": "admin"}, ip=ip)
        return _signed_in(user, request)

    if config.LOCAL_ACCOUNTS_ENABLED and account:
        user = local_accounts.authenticate(username, password, otp)
        if user is not None:
            limiter.reset(ip, account)
            store.audit("auth.login", actor="local:" + username, target=user["id"], ip=ip)
            return _signed_in(user, request)
        if store.find_user("local", "u:" + username.casefold()):
            limiter.failed(ip, account)
            store.audit("auth.failed", actor="local:" + username, ip=ip)
            return _Outcome(error="failed")

    if ldap_auth.enabled() and account:
        try:
            identity = ldap_auth.authenticate(username, password)
            user = admit(identity, ip)
        except AccessDenied:
            return _Outcome(error="denied")
        except DirectoryUnavailable as exc:
            # Not the user's fault: nothing is counted against their budget.
            logger.warning("LDAP sign-in for %r impossible: %s", username, exc)
            store.audit("auth.error", actor=f"ldap:{username}", details={"reason": str(exc)}, ip=ip)
            return _Outcome(error="unavailable")
        except AuthFailed as exc:
            logger.info("LDAP sign-in failed for %r: %s", username, exc)
            limiter.failed(ip, account)
            store.audit("auth.failed", actor=f"ldap:{username}", details={"reason": str(exc)}, ip=ip)
            return _Outcome(error="failed")
        limiter.reset(ip, account)
        return _signed_in(user, request)

    limiter.failed(ip, account)
    store.audit("auth.failed", actor=username, details={"reason": "no matching provider or bad credentials"}, ip=ip)
    return _Outcome(error="failed")


def _oidc_sign_in(request: Request, params: dict[str, str], binding: str) -> _Outcome:
    """Code exchange, token checks and admit(). Blocking: runs in a worker thread."""
    ip = sessions.client_ip(request)
    try:
        identity = oidc.callback(params, binding)
        user = admit(identity, ip)
    except AccessDenied:
        return _Outcome(error="denied")
    except MfaRequired:
        return _Outcome(error="mfa")
    except GroupsUnknown:
        return _Outcome(error="groups_claim")
    except AuthFailed as exc:
        logger.warning("OIDC callback rejected: %s", exc)
        store.audit("auth.failed", actor="oidc", details={"reason": str(exc)}, ip=ip)
        return _Outcome(error="sso")
    return _signed_in(user, request)


def build_router(templates: Jinja2Templates) -> APIRouter:
    router = APIRouter()
    sign_in_slots = asyncio.Semaphore(_SIGN_IN_SLOTS)

    # ------------------------------------------------------------- sign-in pages
    @router.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request, error: Optional[str] = None):
        principal = current_principal(request)
        if principal is not None and principal.via == "session":
            return RedirectResponse(_home_for(principal.role), status_code=302)
        return templates.TemplateResponse(
            request, "login.html",
            {
                "request": request,
                "error": LOGIN_ERRORS.get(error or ""),
                "oidc_enabled": oidc.enabled(),
                "oidc_label": config.OIDC_BUTTON_LABEL,
                "password_enabled": config.AUTH_LOCAL_ENABLED or config.LOCAL_ACCOUNTS_ENABLED or ldap_auth.enabled(),
                "ldap_enabled": ldap_auth.enabled(),
            },
        )

    @router.post("/login")
    async def login(request: Request):
        if not _same_origin(request):
            return _login_error("origin")
        form = await request.form(max_fields=8, max_files=0, max_part_size=1024)
        username = str(form.get("username", "")).strip()
        password = str(form.get("password", "") or form.get("token", ""))
        async with sign_in_slots:
            outcome = await asyncio.to_thread(_password_sign_in, request, username, password, str(form.get("otp", "")))
        return _finish(outcome, request)

    @router.get("/auth/oidc/start")
    async def oidc_start(request: Request):
        if not oidc.enabled():
            raise HTTPException(404, "OIDC is not configured")
        binding = secrets.token_urlsafe(32)
        try:
            url = await asyncio.to_thread(oidc.start_url, binding, sessions.client_ip(request))
        except AuthFailed as exc:
            logger.warning("OIDC start failed: %s", exc)
            return _login_error("sso")
        response = RedirectResponse(url, status_code=302)
        # Lax: the callback is a top-level navigation coming back from the IdP.
        sessions.set_flow_cookie(response, request, sessions.OIDC_COOKIE, binding, max_age=600)
        return response

    @router.get("/auth/oidc/callback")
    async def oidc_callback(request: Request):
        if not oidc.enabled():
            raise HTTPException(404, "OIDC is not configured")
        binding = sessions.read_cookie(request, sessions.OIDC_COOKIE)
        async with sign_in_slots:
            outcome = await asyncio.to_thread(_oidc_sign_in, request, dict(request.query_params), binding)
        response = _finish(outcome, request)
        sessions.clear_flow_cookie(response, request, sessions.OIDC_COOKIE)
        return response

    @router.post("/logout")
    async def logout(request: Request):
        form = await request.form(max_fields=8, max_files=0, max_part_size=1024)
        principal = current_principal(request)
        raw = sessions.read_cookie(request)
        if principal is not None and principal.via == "session":
            if not secure_equals(str(form.get("csrf_token", "")), principal.csrf):
                raise HTTPException(403, "CSRF token missing or invalid")
            sessions.revoke(raw)
            store.audit("auth.logout", actor=f"{principal.provider}:{principal.username}", target=principal.user_id,
                        ip=sessions.client_ip(request))
        target = "/login"
        if principal is not None and principal.provider == "oidc":
            base = config.PANEL_PUBLIC_URL or str(request.base_url).rstrip("/")
            target = await asyncio.to_thread(oidc.end_session_url, f"{base}/login") or "/login"
        response = RedirectResponse(target, status_code=302)
        sessions.clear_cookie(response, request)
        return response

    @router.get("/logout")
    async def logout_get():
        # Logout changes state, so it is POST-only; old bookmarks land here.
        return RedirectResponse("/", status_code=302)

    @router.get("/me", response_class=HTMLResponse)
    async def me_page(request: Request, principal: Principal = Depends(require_user)):
        user = store.get_user(principal.user_id) if principal.user_id else None
        return templates.TemplateResponse(
            request, "me.html",
            {"request": request, "principal": principal, "user": user},
        )

    @router.get("/api/auth/me")
    async def api_me(principal: Principal = Depends(require_user)):
        user = store.get_user(principal.user_id) if principal.user_id else None
        due = attestation_due(user) if user else None
        return {
            "username": principal.username,
            "display_name": principal.display_name,
            "role": principal.role,
            "provider": principal.provider,
            "via": principal.via,
            # OIDC attestation: sign in again before due_at or lose VPN access
            "attestation": {"due_at": store.iso(due), "days_left": max(0, (due - store.now()).days)} if due else None,
        }

    # ------------------------------------------------------------ admin: access
    def _actor(principal: Principal) -> str:
        return f"{principal.provider}:{principal.username}"

    @router.get("/api/auth/providers")
    async def api_providers(_: Principal = Depends(require_admin)):
        return {
            "local": {
                "enabled": config.AUTH_LOCAL_ENABLED,
                "api_token": config.AUTH_API_TOKEN_ENABLED,
                "allowed_cidrs": list(config.AUTH_LOCAL_ALLOWED_CIDRS),
            },
            "oidc": {
                "enabled": oidc.enabled(),
                "discovery_url": config.OIDC_DISCOVERY_URL,
                "client_id": config.OIDC_CLIENT_ID,
                "redirect_url": config.OIDC_REDIRECT_URL,
                "groups_claims": config.OIDC_GROUPS_CLAIMS,
            },
            "ldap": {
                "enabled": ldap_auth.enabled(),
                "url": config.LDAP_URL,
                "user_base_dn": config.LDAP_USER_BASE_DN,
                "group_search": bool(config.LDAP_GROUP_SEARCH_FILTER),
            },
            "default_role": config.AUTH_DEFAULT_ROLE or None,
            "attestation_days": config.AUTH_ATTESTATION_DAYS,
        }

    def _test_providers() -> dict:
        result = {}
        if oidc.enabled():
            try:
                doc = oidc.discovery(force=True)
                result["oidc"] = {"ok": True, "code": "ok", "detail": f"issuer {doc['issuer']}"}
            except Exception as exc:  # network errors surface as-is
                result["oidc"] = {"ok": False, "code": "unreachable", "detail": str(exc)}
        if ldap_auth.enabled():
            try:
                result["ldap"] = ldap_auth.test_connection()
            except Exception as exc:
                result["ldap"] = {"ok": False, "code": "error", "detail": str(exc)}
        return result

    @router.post("/api/auth/providers/test")
    async def api_providers_test(_: Principal = Depends(require_admin)):
        return await asyncio.to_thread(_test_providers)

    @router.get("/api/auth/users")
    async def api_users(_: Principal = Depends(require_admin)):
        counts = store.count_sessions_by_user()
        users = store.list_users()
        for user in users:
            user["sessions"] = counts.get(user["id"], 0)
            due = attestation_due(user)
            user["attestation_due_at"] = store.iso(due) if due else ""
        return users

    def _user_or_404(user_id: str) -> dict:
        user = store.get_user(user_id)
        if user is None:
            raise HTTPException(404, "user not found")
        return user

    @router.post("/api/auth/users/{user_id}/disable")
    async def api_user_disable(user_id: str, request: Request, principal: Principal = Depends(require_admin)):
        user = _user_or_404(user_id)
        if user["id"] == principal.user_id:
            raise HTTPException(400, "cannot_disable_self")
        if is_break_glass_user(user):
            # AUTH_LOCAL_ENABLED / PANEL_SECRET_TOKEN control this account.
            raise HTTPException(400, "break_glass_managed_by_config")
        # Sticky: the user's next SSO / LDAP sign-in does not undo it (source admin).
        store.set_user_status(user_id, "disabled", REASON_ADMIN, source="admin")
        revoked = store.delete_user_sessions(user_id)
        # Suspending takes the backend lock and reloads nft / Xray: a worker thread.
        suspended = await asyncio.to_thread(devices.suspend_user_devices, user_id, actor=_actor(principal))
        store.audit("user.disable", actor=_actor(principal), target=user_id,
                    details={"username": user["username"], "sessions_revoked": revoked,
                             "devices_suspended": suspended}, ip=sessions.client_ip(request))
        return store.get_user(user_id)

    @router.post("/api/auth/users/{user_id}/enable")
    async def api_user_enable(user_id: str, request: Request, principal: Principal = Depends(require_admin)):
        user = _user_or_404(user_id)
        store.set_user_status(user_id, "active")
        resumed = await asyncio.to_thread(devices.resume_user_devices, user_id, actor=_actor(principal))
        store.audit("user.enable", actor=_actor(principal), target=user_id,
                    details={"username": user["username"], "devices_resumed": resumed}, ip=sessions.client_ip(request))
        return store.get_user(user_id)

    @router.post("/api/auth/users/{user_id}/revoke-sessions")
    async def api_user_revoke(user_id: str, request: Request, principal: Principal = Depends(require_admin)):
        user = _user_or_404(user_id)
        revoked = store.delete_user_sessions(user_id)
        store.audit("user.revoke_sessions", actor=_actor(principal), target=user_id,
                    details={"username": user["username"], "sessions_revoked": revoked}, ip=sessions.client_ip(request))
        return {"revoked": revoked}

    @router.get("/api/auth/policies")
    async def api_policies(_: Principal = Depends(require_admin)):
        return store.list_policies()

    @router.post("/api/auth/policies", status_code=201)
    async def api_policy_create(req: PolicyRequest, request: Request, principal: Principal = Depends(require_admin)):
        try:
            created = store.create_policy(req.provider, req.group_name, req.role, req.priority,
                                          req.access_profile_id)
        except store.StoreError as exc:
            raise HTTPException(400, str(exc)) from exc
        store.audit("policy.create", actor=_actor(principal), target=created["id"], details=created,
                    ip=sessions.client_ip(request))
        return created

    @router.put("/api/auth/policies/{policy_id}")
    async def api_policy_update(policy_id: str, req: PolicyRequest, request: Request,
                                principal: Principal = Depends(require_admin)):
        try:
            updated = store.update_policy(policy_id, req.provider, req.group_name, req.role, req.priority,
                                          req.access_profile_id)
        except store.StoreError as exc:
            raise HTTPException(400, str(exc)) from exc
        if updated is None:
            raise HTTPException(404, "policy not found")
        store.audit("policy.update", actor=_actor(principal), target=policy_id, details=updated,
                    ip=sessions.client_ip(request))
        return updated

    @router.delete("/api/auth/policies/{policy_id}")
    async def api_policy_delete(policy_id: str, request: Request, principal: Principal = Depends(require_admin)):
        existing = store.get_policy(policy_id)
        if existing is None or not store.delete_policy(policy_id):
            raise HTTPException(404, "policy not found")
        store.audit("policy.delete", actor=_actor(principal), target=policy_id, details=existing,
                    ip=sessions.client_ip(request))
        return {"status": "deleted"}

    @router.get("/api/auth/audit")
    async def api_audit(limit: int = 200, action: str = "", _: Principal = Depends(require_auditor)):
        return store.list_audit(limit=limit, action_prefix=action)

    @router.get("/api/auth/audit/export")
    def api_audit_export(limit: int = 1000, from_ts: str = "", to_ts: str = "", cursor: str = "", _: Principal = Depends(require_auditor)):
        """JSON Lines for a SIEM or an archive (newest first, up to 1000 events)."""
        import json as _json

        try:
            items, next_cursor = store.audit_page(limit, from_ts, to_ts, cursor)
        except (ValueError, TypeError, KeyError) as exc:
            raise HTTPException(422, "invalid_audit_range_or_cursor") from exc
        lines = "".join(_json.dumps(item, ensure_ascii=False) + "\n" for item in items)
        stamp = store.iso(store.now()).replace(":", "")
        return Response(
            content=lines,
            media_type="application/x-ndjson",
            headers={"Content-Disposition": f'attachment; filename="corpvpn-audit-{stamp}.jsonl"', "X-Next-Cursor": next_cursor, "Cache-Control": "no-store"},
        )

    # --------------------------------------------------------------- API tokens
    @router.get("/api/auth/tokens")
    async def api_tokens(_: Principal = Depends(require_admin)):
        return store.list_api_tokens()

    @router.post("/api/auth/tokens", status_code=201)
    async def api_token_create(req: TokenRequest, request: Request, principal: Principal = Depends(require_admin)):
        try:
            raw, row = tokens.create(req.name, req.role, _actor(principal), req.ttl_days)
        except store.StoreError as exc:
            raise HTTPException(400, str(exc)) from exc
        store.audit("token.create", actor=_actor(principal), target=row["id"],
                    details={"name": row["name"], "role": row["role"], "expires_at": row["expires_at"]},
                    ip=sessions.client_ip(request))
        return {**row, "token": raw}

    @router.delete("/api/auth/tokens/{token_id}")
    async def api_token_revoke(token_id: str, request: Request, principal: Principal = Depends(require_admin)):
        row = store.get_api_token(token_id)
        if row is None or not store.revoke_api_token(token_id):
            raise HTTPException(404, "token not found or already revoked")
        store.audit("token.revoke", actor=_actor(principal), target=token_id, details={"name": row["name"]},
                    ip=sessions.client_ip(request))
        return {"status": "revoked"}

    @router.post("/api/auth/sync")
    async def api_sync(request: Request, principal: Principal = Depends(require_admin)):
        summary = await asyncio.to_thread(directory_sync.run)
        store.audit("directory.sync", actor=_actor(principal), details={
            "checked": summary["checked"], "updated": summary["updated"],
            "disabled": len(summary["disabled"]), "enabled": len(summary["enabled"]),
            "missing": len(summary["missing"]), "errors": summary["errors"],
        }, ip=sessions.client_ip(request))
        return summary

    return router
