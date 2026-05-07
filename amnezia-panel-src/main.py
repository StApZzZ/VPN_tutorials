"""
VPN Panel — FastAPI веб-приложение для native WireGuard на хосте.
Порт: PANEL_PORT (по умолчанию 8080), bind host: PANEL_HOST.
Авторизация: Bearer Token, Basic Auth (password = token) или cookie-сессия.
"""

import asyncio
import io
import json
import logging
import secrets
import zipfile
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from typing import Optional

import httpx
import qrcode
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import client_artifacts as ca
import config
import peer_artifacts as pa
import routing_overrides as ro
import telegram_access as ta
import telegram_command_docs as tcd
import vpn_manager as vm
import xray_clients as xc
import xray_manager as xm
from models import (
    CreatePeerRequest,
    CreateRoutingOverrideRequest,
    CreateXrayClientRequest,
    GrantTelegramUserRequest,
    Protocol,
    ReplySupportTicketRequest,
    UpdatePeerRequest,
    UpdateRoutingOverrideRequest,
    UpdateTelegramBillingSettingsRequest,
    UpdateTelegramCommandDocsRequest,
    UpdateTelegramUserDiscountRequest,
    UpdateTelegramUserExpiryRequest,
    UpdateXrayClientRequest,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(_: FastAPI):
    config.validate_runtime_config()
    yield


app = FastAPI(title="VPN Panel", version="2.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

security = HTTPBasic(auto_error=False)
_xray_client_apply_lock = asyncio.Lock()


def _check_token(token: str) -> bool:
    return secrets.compare_digest(token.strip(), config.PANEL_SECRET_TOKEN.strip())


def require_auth(
    request: Request,
    credentials: Optional[HTTPBasicCredentials] = Depends(security),
):
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer ") and _check_token(auth_header[7:]):
        return True

    if credentials and _check_token(credentials.password):
        return True

    session_token = request.cookies.get("session_token", "")
    if session_token and _check_token(session_token):
        return True

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Basic"},
    )


def _peer_by_id(pubkey: str):
    for peer in vm.get_all_peers():
        if peer.public_key == pubkey:
            return peer
    return None


def _safe_download_name(value: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in value.strip())
    return safe.strip("-_") or "client"


def _message_chunks(text: str, limit: int = 3900) -> list[str]:
    if len(text) <= limit:
        return [text]

    chunks: list[str] = []
    current = ""
    for line in text.splitlines(keepends=True):
        if len(line) > limit:
            if current:
                chunks.append(current)
                current = ""
            chunks.extend(line[index : index + limit] for index in range(0, len(line), limit))
            continue
        if len(current) + len(line) > limit:
            if current:
                chunks.append(current)
            current = line
        else:
            current += line
    if current:
        chunks.append(current)
    return chunks or [text[:limit]]


def _manual_check_text() -> str:
    candidates = [
        BASE_DIR.parent / "manual-check-windows.md",
        BASE_DIR / "manual-check-windows.md",
        BASE_DIR / "deploy" / "manual-check-windows.md",
    ]
    for path in candidates:
        if path.exists():
            return path.read_text(encoding="utf-8")

    return """# Проверка VPN вручную на Windows

1. Используйте vless-link.txt, QR из панели или *.xray-client.json.
2. Перед smoke проверьте Xray doctor в панели: красных ошибок быть не должно.
3. На Windows выполните:
   - ipconfig /all
   - curl.exe --connect-timeout 10 https://api.ipify.org
   - curl.exe -x socks5h://127.0.0.1:10808 --connect-timeout 10 https://api.ipify.org
4. Для VLESS/Xray ping 10.8.2.1 не является обязательной проверкой.
5. Верните вывод команд и кратко опишите, что открылось, что не открылось, работает ли локальная сеть.
"""


def _raise_override_http_error(exc: Exception) -> None:
    if isinstance(exc, ro.RoutingOverrideConflict):
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if isinstance(exc, ro.RoutingOverrideNotFound):
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if isinstance(exc, ro.RoutingOverrideValidationError):
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    raise HTTPException(status_code=500, detail=str(exc)) from exc


def _log_override_error(action: str, exc: Exception) -> None:
    if isinstance(
        exc,
        (
            ro.RoutingOverrideConflict,
            ro.RoutingOverrideNotFound,
            ro.RoutingOverrideValidationError,
        ),
    ):
        logger.info("%s rejected: %s", action, exc)
        return
    logger.exception("%s failed", action)


def _raise_xray_http_error(exc: Exception) -> None:
    if isinstance(exc, xm.XrayNotConfiguredError):
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if isinstance(exc, xm.XrayCommandError):
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    if isinstance(exc, xm.XrayManagerError):
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    raise HTTPException(status_code=500, detail=str(exc)) from exc


def _raise_xray_client_http_error(exc: Exception) -> None:
    if isinstance(exc, xc.XrayClientConflict):
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if isinstance(exc, xc.XrayClientNotFound):
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if isinstance(exc, xc.XrayClientValidationError):
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if isinstance(exc, xc.XrayClientError):
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    raise HTTPException(status_code=500, detail=str(exc)) from exc


def _raise_peer_artifact_http_error(exc: Exception) -> None:
    if isinstance(exc, pa.PeerArtifactNotFound):
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if isinstance(exc, pa.PeerArtifactValidationError):
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if isinstance(exc, pa.PeerArtifactError):
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    raise HTTPException(status_code=500, detail=str(exc)) from exc


async def _mutate_xray_clients_with_apply(action: str, mutation: Callable[[], object]) -> object:
    async with _xray_client_apply_lock:
        snapshot = xc.snapshot_clients()
        try:
            result = mutation()
            await asyncio.to_thread(xm.apply_xray)
            return result
        except Exception:
            try:
                xc.restore_clients(snapshot)
            except Exception:
                logger.exception("%s rollback failed", action)
            logger.exception("%s failed", action)
            raise


def _telegram_access_store() -> ta.TelegramAccessStore:
    admin_ids = ta.parse_id_set(config.TELEGRAM_ADMIN_USER_IDS.strip() or config.TELEGRAM_ALLOWED_CHAT_IDS)
    return ta.TelegramAccessStore(
        path=config.TELEGRAM_ACCESS_PATH,
        admin_user_ids=admin_ids,
    )


def _telegram_command_docs_store() -> tcd.TelegramCommandDocsStore:
    return tcd.TelegramCommandDocsStore(path=config.TELEGRAM_COMMAND_DOCS_PATH)


def _parse_moscow_expiry_date(value: str) -> datetime:
    try:
        year, month, day = [int(part) for part in value.strip().split("-")]
        moscow = timezone(timedelta(hours=3))
        return datetime(year, month, day, 23, 59, 59, tzinfo=moscow).astimezone(timezone.utc)
    except Exception as exc:
        raise HTTPException(400, "Use YYYY-MM-DD date") from exc


async def _ensure_telegram_user_client_enabled(
    access: ta.TelegramAccessStore,
    user_id: int,
) -> xc.XrayClientProfile:
    client_id = access.client_for_user(user_id)
    if client_id:
        try:
            client = xc.get_client(client_id)
        except xc.XrayClientNotFound:
            client = None
        if client is not None:
            desired_name = access.desired_client_name_for_user(
                user_id,
                existing_name=client.name,
                default_name=f"Telegram {user_id}",
            )
            if client.name != desired_name:
                client = await _mutate_xray_clients_with_apply(
                    "telegram_billing_rename_xray_client",
                    lambda: xc.update_client(client.id, name=desired_name, email=client.email),
                )
            if client.enabled:
                return client
            return await _mutate_xray_clients_with_apply(
                "telegram_billing_enable_xray_client",
                lambda: xc.toggle_client(client.id),
            )

    client = await _mutate_xray_clients_with_apply(
        "telegram_billing_create_xray_client",
        lambda: xc.create_client(
            name=access.desired_client_name_for_user(
                user_id,
                default_name=f"Telegram {user_id}",
            ),
            email=None,
        ),
    )
    access.bind_client(user_id, client.id, invited_by=None)
    return client


async def _disable_telegram_user_client(access: ta.TelegramAccessStore, user_id: int) -> None:
    client_id = access.client_for_user(user_id)
    if not client_id:
        return
    try:
        client = xc.get_client(client_id)
    except xc.XrayClientNotFound:
        return
    if client.enabled:
        await _mutate_xray_clients_with_apply(
            "telegram_billing_disable_xray_client",
            lambda: xc.toggle_client(client.id),
        )


async def _ensure_telegram_user_peer_enabled(
    access: ta.TelegramAccessStore,
    user_id: int,
) -> dict:
    desired_name = access.desired_client_name_for_user(
        user_id,
        default_name=f"Telegram {user_id}",
    )
    peer_public_key = access.peer_for_user(user_id)
    if peer_public_key:
        peer = _peer_by_id(peer_public_key)
        if peer is not None:
            if peer.name != desired_name:
                await asyncio.to_thread(vm.rename_peer, peer_public_key, desired_name)
                peer = _peer_by_id(peer_public_key)
            if peer is not None and peer.deactivated:
                await asyncio.to_thread(vm.activate_peer, peer_public_key)
                peer = _peer_by_id(peer_public_key)
            if peer is not None:
                return peer.model_dump()

    created = await asyncio.to_thread(vm.create_peer, desired_name)
    access.bind_peer(user_id, created["public_key"], invited_by=None)
    return dict(created)


async def _disable_telegram_user_peer(access: ta.TelegramAccessStore, user_id: int) -> None:
    peer_public_key = access.peer_for_user(user_id)
    if not peer_public_key:
        return
    peer = _peer_by_id(peer_public_key)
    if peer is None or peer.deactivated:
        return
    await asyncio.to_thread(vm.deactivate_peer, peer_public_key)


async def _send_telegram_bot_message(chat_id: int, text: str) -> None:
    token = config.TELEGRAM_BOT_TOKEN.strip()
    if not token:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is not configured")

    proxy_url = config.TELEGRAM_PROXY_URL.strip() or None
    async with httpx.AsyncClient(
        base_url=f"https://api.telegram.org/bot{token}",
        timeout=config.TELEGRAM_REQUEST_TIMEOUT,
        proxy=proxy_url,
        trust_env=False,
    ) as client:
        for chunk in _message_chunks(text):
            response = await client.post(
                "/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": chunk,
                    "disable_web_page_preview": True,
                },
            )
            if response.status_code >= 400:
                raise RuntimeError(f"Telegram API {response.status_code}: {response.text}")
            payload = response.json()
            if not payload.get("ok", False):
                raise RuntimeError(f"Telegram API error: {payload}")


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, _=Depends(require_auth)):
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "peers": vm.get_all_peers(),
            "stats": vm.get_stats(),
        },
    )


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
async def login(request: Request):
    form = await request.form()
    token = form.get("token", "")
    if _check_token(token):
        response = Response(status_code=302, headers={"Location": "/"})
        response.set_cookie("session_token", token, httponly=True, samesite="strict")
        return response

    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": "Неверный токен"},
        status_code=401,
    )


@app.get("/logout")
async def logout():
    response = Response(status_code=302, headers={"Location": "/login"})
    response.delete_cookie("session_token")
    return response


@app.get("/api/peers")
async def api_list_peers(_=Depends(require_auth)):
    return [peer.model_dump() for peer in vm.get_all_peers()]


@app.post("/api/peers", status_code=201)
async def api_create_peer(req: CreatePeerRequest, _=Depends(require_auth)):
    try:
        return vm.create_peer(req.name)
    except Exception as exc:
        logger.exception("create_peer failed")
        raise HTTPException(500, str(exc))


@app.put("/api/peers/{pubkey:path}")
async def api_update_peer(pubkey: str, req: UpdatePeerRequest, _=Depends(require_auth)):
    if not _peer_by_id(pubkey):
        raise HTTPException(404, "Peer not found")
    vm.rename_peer(pubkey, req.name)
    return {"status": "ok"}


@app.post("/api/peers/{pubkey:path}/deactivate")
async def api_deactivate(pubkey: str, _=Depends(require_auth)):
    if not _peer_by_id(pubkey):
        raise HTTPException(404, "Peer not found")
    vm.deactivate_peer(pubkey)
    return {"status": "deactivated"}


@app.post("/api/peers/{pubkey:path}/activate")
async def api_activate(pubkey: str, _=Depends(require_auth)):
    if not _peer_by_id(pubkey):
        raise HTTPException(404, "Peer not found")
    vm.activate_peer(pubkey)
    return {"status": "activated"}


@app.delete("/api/peers/{pubkey:path}")
async def api_delete(pubkey: str, _=Depends(require_auth)):
    if not _peer_by_id(pubkey):
        raise HTTPException(404, "Peer not found")
    vm.delete_peer(pubkey)
    return {"status": "deleted"}


@app.get("/api/peers/{pubkey:path}/config")
async def api_get_config(
    pubkey: str,
    protocol: Protocol | None = None,
    _=Depends(require_auth),
):
    try:
        artifact = pa.resolve_peer_artifact(pubkey, protocol=protocol)
        safe_name = _safe_download_name(artifact.peer.name or pubkey[:8])
        return Response(
            content=artifact.client_conf,
            media_type="text/plain",
            headers={"Content-Disposition": f'attachment; filename="{safe_name}.conf"'},
        )
    except Exception as exc:
        logger.exception("peer_config failed")
        _raise_peer_artifact_http_error(exc)


@app.get("/api/peers/{pubkey:path}/artifacts")
async def api_get_peer_artifacts(pubkey: str, _=Depends(require_auth)):
    try:
        return pa.describe_peer_artifacts(pubkey).model_dump()
    except Exception as exc:
        logger.exception("peer_artifacts failed")
        _raise_peer_artifact_http_error(exc)


@app.get("/api/peers/{pubkey:path}/qr")
async def api_get_qr(
    pubkey: str,
    protocol: Protocol | None = None,
    _=Depends(require_auth),
):
    try:
        artifact = pa.resolve_peer_artifact(pubkey, protocol=protocol)
    except Exception as exc:
        logger.exception("peer_qr failed")
        _raise_peer_artifact_http_error(exc)

    img = qrcode.make(artifact.client_conf)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


@app.get("/api/peers/{pubkey:path}")
async def api_get_peer(pubkey: str, _=Depends(require_auth)):
    peer = _peer_by_id(pubkey)
    if not peer:
        raise HTTPException(404, "Peer not found")
    return peer.model_dump()


@app.get("/api/stats")
async def api_stats(_=Depends(require_auth)):
    return vm.get_stats().model_dump()


@app.get("/api/telegram/billing/summary")
async def api_telegram_billing_summary(_=Depends(require_auth)):
    try:
        return _telegram_access_store().billing_summary()
    except Exception as exc:
        logger.exception("telegram_billing_summary failed")
        raise HTTPException(500, str(exc)) from exc


@app.put("/api/telegram/billing/settings")
async def api_update_telegram_billing_settings(
    req: UpdateTelegramBillingSettingsRequest,
    _=Depends(require_auth),
):
    try:
        access = _telegram_access_store()
        if (
            req.subscription_price_stars is None
            and req.subscription_max_12m_discount_percent is None
            and req.trial_period_days is None
        ):
            raise HTTPException(
                400,
                "subscription_price_stars, subscription_max_12m_discount_percent or trial_period_days is required",
            )
        if req.subscription_price_stars is not None:
            access.set_subscription_price_stars(req.subscription_price_stars)
        if req.subscription_max_12m_discount_percent is not None:
            access.set_subscription_max_12m_discount_percent(
                req.subscription_max_12m_discount_percent
            )
        if req.trial_period_days is not None:
            access.set_trial_period_days(req.trial_period_days)
        return access.billing_summary()
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("update_telegram_billing_settings failed")
        raise HTTPException(500, str(exc)) from exc


@app.get("/api/telegram/users")
async def api_telegram_users(_=Depends(require_auth)):
    try:
        return _telegram_access_store().public_user_records()
    except Exception as exc:
        logger.exception("telegram_users failed")
        raise HTTPException(500, str(exc)) from exc


@app.get("/api/telegram/payments")
async def api_telegram_payments(_=Depends(require_auth)):
    try:
        return _telegram_access_store().list_payments()
    except Exception as exc:
        logger.exception("telegram_payments failed")
        raise HTTPException(500, str(exc)) from exc


@app.get("/api/telegram/invites")
async def api_telegram_invites(_=Depends(require_auth)):
    try:
        return _telegram_access_store().public_invite_records()
    except Exception as exc:
        logger.exception("telegram_invites failed")
        raise HTTPException(500, str(exc)) from exc


@app.get("/api/telegram/leads")
async def api_telegram_leads(_=Depends(require_auth)):
    try:
        return _telegram_access_store().public_lead_records()
    except Exception as exc:
        logger.exception("telegram_leads failed")
        raise HTTPException(500, str(exc)) from exc


@app.get("/api/telegram/support/summary")
async def api_telegram_support_summary(_=Depends(require_auth)):
    try:
        return _telegram_access_store().support_summary()
    except Exception as exc:
        logger.exception("telegram_support_summary failed")
        raise HTTPException(500, str(exc)) from exc


@app.get("/api/telegram/support/tickets")
async def api_telegram_support_tickets(status: str | None = None, _=Depends(require_auth)):
    try:
        normalized_status = status.strip().lower() if isinstance(status, str) else None
        if normalized_status not in {None, ta.SUPPORT_TICKET_STATUS_OPEN, ta.SUPPORT_TICKET_STATUS_ARCHIVED}:
            raise HTTPException(400, "support status must be open or archived")
        return _telegram_access_store().public_support_ticket_records(normalized_status)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("telegram_support_tickets failed")
        raise HTTPException(500, str(exc)) from exc


@app.get("/api/telegram/support/tickets/{ticket_id}")
async def api_telegram_support_ticket(ticket_id: str, _=Depends(require_auth)):
    try:
        return _telegram_access_store().public_support_ticket_detail(ticket_id)
    except Exception as exc:
        logger.exception("telegram_support_ticket failed")
        raise HTTPException(404, str(exc)) from exc


@app.post("/api/telegram/support/tickets/{ticket_id}/mark-read")
async def api_telegram_support_ticket_mark_read(ticket_id: str, _=Depends(require_auth)):
    try:
        access = _telegram_access_store()
        access.mark_support_ticket_read(ticket_id)
        return access.public_support_ticket_detail(ticket_id)
    except Exception as exc:
        logger.exception("telegram_support_ticket_mark_read failed")
        raise HTTPException(404, str(exc)) from exc


@app.post("/api/telegram/support/tickets/{ticket_id}/reply")
async def api_telegram_support_ticket_reply(
    ticket_id: str,
    req: ReplySupportTicketRequest,
    _=Depends(require_auth),
):
    try:
        access = _telegram_access_store()
        ticket = access.public_support_ticket_detail(ticket_id)
        if ticket.get("status") != ta.SUPPORT_TICKET_STATUS_OPEN:
            raise HTTPException(409, "Support ticket is archived")
        user_id = ticket.get("user_id")
        if not isinstance(user_id, int) or user_id <= 0:
            raise HTTPException(400, "Support ticket user is invalid")
        await _send_telegram_bot_message(
            user_id,
            f"Support reply for {ticket_id}:\n\n{req.message.strip()}",
        )
        access.create_or_append_support_ticket(user_id, req.message, author="admin")
        return access.public_support_ticket_detail(ticket_id)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("telegram_support_ticket_reply failed")
        raise HTTPException(500, str(exc)) from exc


@app.post("/api/telegram/support/tickets/{ticket_id}/archive")
async def api_telegram_support_ticket_archive(ticket_id: str, _=Depends(require_auth)):
    try:
        access = _telegram_access_store()
        archived = access.archive_support_ticket(ticket_id)
        user_id = archived.get("user_id")
        if isinstance(user_id, int) and user_id > 0:
            user_lang = access.preferred_language_for_user(user_id)
            archive_message = (
                f"Заявка {ticket_id} переведена в архив. Если помощь понадобится снова, отправьте /support."
                if user_lang == "ru"
                else f"Support ticket {ticket_id} has been archived. Send /support if you need more help."
            )
            await _send_telegram_bot_message(
                user_id,
                archive_message,
            )
        return access.public_support_ticket_detail(ticket_id)
    except Exception as exc:
        logger.exception("telegram_support_ticket_archive failed")
        raise HTTPException(404, str(exc)) from exc


@app.get("/api/telegram/command-docs")
async def api_telegram_command_docs(_=Depends(require_auth)):
    try:
        return _telegram_command_docs_store().describe()
    except Exception as exc:
        logger.exception("telegram_command_docs failed")
        raise HTTPException(500, str(exc)) from exc


@app.put("/api/telegram/command-docs")
async def api_update_telegram_command_docs(
    req: UpdateTelegramCommandDocsRequest,
    _=Depends(require_auth),
):
    try:
        return _telegram_command_docs_store().update_raw_config(req.raw_config)
    except tcd.TelegramCommandDocsError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        logger.exception("update_telegram_command_docs failed")
        raise HTTPException(500, str(exc)) from exc


@app.post("/api/telegram/command-docs/reset")
async def api_reset_telegram_command_docs(_=Depends(require_auth)):
    try:
        return _telegram_command_docs_store().reset_to_defaults()
    except Exception as exc:
        logger.exception("reset_telegram_command_docs failed")
        raise HTTPException(500, str(exc)) from exc


@app.post("/api/telegram/users/{user_id}/grant")
async def api_grant_telegram_user(
    user_id: int,
    req: GrantTelegramUserRequest,
    _=Depends(require_auth),
):
    if user_id <= 0:
        raise HTTPException(400, "Telegram user id must be positive")
    try:
        access = _telegram_access_store()
        client = await _ensure_telegram_user_client_enabled(access, user_id)
        peer = await _ensure_telegram_user_peer_enabled(access, user_id)
        access.grant_subscription(user_id, days=req.days)
        return {
            "user": access.public_user_record(user_id),
            "client": client.model_dump(),
            "peer": peer,
        }
    except Exception as exc:
        logger.exception("grant_telegram_user failed")
        _raise_xray_client_http_error(exc)


@app.post("/api/telegram/users/{user_id}/revoke")
async def api_revoke_telegram_user(user_id: int, _=Depends(require_auth)):
    if user_id <= 0:
        raise HTTPException(400, "Telegram user id must be positive")
    try:
        access = _telegram_access_store()
        await _disable_telegram_user_client(access, user_id)
        await _disable_telegram_user_peer(access, user_id)
        access.revoke_subscription(user_id)
        return {"user": access.public_user_record(user_id)}
    except Exception as exc:
        logger.exception("revoke_telegram_user failed")
        _raise_xray_client_http_error(exc)


@app.put("/api/telegram/users/{user_id}/discount")
async def api_update_telegram_user_discount(
    user_id: int,
    req: UpdateTelegramUserDiscountRequest,
    _=Depends(require_auth),
):
    if user_id <= 0:
        raise HTTPException(400, "Telegram user id must be positive")
    try:
        access = _telegram_access_store()
        if req.clear:
            access.clear_discount_percent(user_id)
        elif req.discount_percent is not None:
            access.set_discount_percent(user_id, req.discount_percent)
        else:
            raise HTTPException(400, "discount_percent or clear=true is required")
        return {"user": access.public_user_record(user_id)}
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("update_telegram_user_discount failed")
        raise HTTPException(500, str(exc)) from exc


@app.put("/api/telegram/users/{user_id}/expires")
async def api_update_telegram_user_expires(
    user_id: int,
    req: UpdateTelegramUserExpiryRequest,
    _=Depends(require_auth),
):
    if user_id <= 0:
        raise HTTPException(400, "Telegram user id must be positive")
    try:
        access = _telegram_access_store()
        expires_at = _parse_moscow_expiry_date(req.expires_at)
        access.set_subscription_expires_at(user_id, expires_at)
        if access.is_subscription_active(user_id):
            await _ensure_telegram_user_client_enabled(access, user_id)
            await _ensure_telegram_user_peer_enabled(access, user_id)
        else:
            await _disable_telegram_user_client(access, user_id)
            await _disable_telegram_user_peer(access, user_id)
        return {"user": access.public_user_record(user_id)}
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("update_telegram_user_expires failed")
        _raise_xray_client_http_error(exc)


@app.get("/api/routing/overrides")
async def api_list_routing_overrides(_=Depends(require_auth)):
    try:
        return [override.model_dump() for override in ro.list_overrides()]
    except Exception as exc:
        _log_override_error("list_routing_overrides", exc)
        _raise_override_http_error(exc)


@app.post("/api/routing/overrides", status_code=201)
async def api_create_routing_override(req: CreateRoutingOverrideRequest, _=Depends(require_auth)):
    try:
        override = ro.create_override(
            match_type=req.match_type,
            value=req.value,
            route=req.route,
            comment=req.comment,
        )
        return override.model_dump()
    except Exception as exc:
        _log_override_error("create_routing_override", exc)
        _raise_override_http_error(exc)


@app.put("/api/routing/overrides/{override_id}")
async def api_update_routing_override(
    override_id: str,
    req: UpdateRoutingOverrideRequest,
    _=Depends(require_auth),
):
    try:
        override = ro.update_override(
            override_id=override_id,
            match_type=req.match_type,
            value=req.value,
            route=req.route,
            comment=req.comment,
        )
        return override.model_dump()
    except Exception as exc:
        _log_override_error("update_routing_override", exc)
        _raise_override_http_error(exc)


@app.post("/api/routing/overrides/{override_id}/toggle")
async def api_toggle_routing_override(override_id: str, _=Depends(require_auth)):
    try:
        override = ro.toggle_override(override_id)
        return override.model_dump()
    except Exception as exc:
        _log_override_error("toggle_routing_override", exc)
        _raise_override_http_error(exc)


@app.delete("/api/routing/overrides/{override_id}")
async def api_delete_routing_override(override_id: str, _=Depends(require_auth)):
    try:
        ro.delete_override(override_id)
        return {"status": "deleted"}
    except Exception as exc:
        _log_override_error("delete_routing_override", exc)
        _raise_override_http_error(exc)


@app.get("/api/routing/preview")
async def api_routing_preview(_=Depends(require_auth)):
    try:
        return ro.get_preview().model_dump()
    except Exception as exc:
        _log_override_error("routing_preview", exc)
        _raise_override_http_error(exc)


@app.get("/api/routing/check")
async def api_routing_check(host: str, _=Depends(require_auth)):
    try:
        return ro.check_domain(host).model_dump()
    except Exception as exc:
        _log_override_error("routing_check", exc)
        _raise_override_http_error(exc)


@app.get("/api/xray/clients")
async def api_list_xray_clients(_=Depends(require_auth)):
    try:
        return [client.model_dump() for client in xc.list_clients()]
    except Exception as exc:
        logger.exception("list_xray_clients failed")
        _raise_xray_client_http_error(exc)


@app.get("/api/xray/settings")
async def api_xray_client_settings(_=Depends(require_auth)):
    try:
        return xc.get_settings_status().model_dump()
    except Exception as exc:
        logger.exception("xray_client_settings failed")
        _raise_xray_client_http_error(exc)


@app.get("/api/xray/doctor")
async def api_xray_doctor(_=Depends(require_auth)):
    try:
        return xm.get_doctor_status().model_dump()
    except Exception as exc:
        logger.exception("xray_doctor failed")
        _raise_xray_http_error(exc)


@app.post("/api/xray/clients", status_code=201)
async def api_create_xray_client(req: CreateXrayClientRequest, _=Depends(require_auth)):
    try:
        client = await _mutate_xray_clients_with_apply(
            "create_xray_client",
            lambda: xc.create_client(name=req.name, email=req.email),
        )
        return client.model_dump()
    except Exception as exc:
        logger.exception("create_xray_client failed")
        _raise_xray_client_http_error(exc)


@app.put("/api/xray/clients/{client_id}")
async def api_update_xray_client(
    client_id: str,
    req: UpdateXrayClientRequest,
    _=Depends(require_auth),
):
    try:
        client = await _mutate_xray_clients_with_apply(
            "update_xray_client",
            lambda: xc.update_client(client_id=client_id, name=req.name, email=req.email),
        )
        return client.model_dump()
    except Exception as exc:
        logger.exception("update_xray_client failed")
        _raise_xray_client_http_error(exc)


@app.post("/api/xray/clients/{client_id}/toggle")
async def api_toggle_xray_client(client_id: str, _=Depends(require_auth)):
    try:
        client = await _mutate_xray_clients_with_apply(
            "toggle_xray_client",
            lambda: xc.toggle_client(client_id),
        )
        return client.model_dump()
    except Exception as exc:
        logger.exception("toggle_xray_client failed")
        _raise_xray_client_http_error(exc)


@app.delete("/api/xray/clients/{client_id}")
async def api_delete_xray_client(client_id: str, _=Depends(require_auth)):
    try:
        await _mutate_xray_clients_with_apply(
            "delete_xray_client",
            lambda: xc.delete_client(client_id),
        )
        return {"status": "deleted"}
    except Exception as exc:
        logger.exception("delete_xray_client failed")
        _raise_xray_client_http_error(exc)


@app.get("/api/xray/clients/{client_id}/share")
async def api_xray_client_share(
    client_id: str,
    protocol: Protocol | None = None,
    _=Depends(require_auth),
):
    try:
        return ca.resolve_client_artifact(client_id, protocol=protocol).share.model_dump()
    except Exception as exc:
        logger.exception("xray_client_share failed")
        _raise_xray_client_http_error(exc)


@app.get("/api/xray/clients/{client_id}/config")
async def api_xray_client_config(
    client_id: str,
    protocol: Protocol | None = None,
    _=Depends(require_auth),
):
    try:
        artifact = ca.resolve_client_artifact(client_id, protocol=protocol)
        share = artifact.share
        content = json.dumps(share.client_config, ensure_ascii=False, indent=2) + "\n"
        safe_name = _safe_download_name(share.name)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{safe_name}.xray-client.json"'},
        )
    except Exception as exc:
        logger.exception("xray_client_config failed")
        _raise_xray_client_http_error(exc)


@app.get("/api/xray/clients/{client_id}/artifacts")
async def api_xray_client_artifacts(client_id: str, _=Depends(require_auth)):
    try:
        return ca.describe_client_artifacts(client_id).model_dump()
    except Exception as exc:
        logger.exception("xray_client_artifacts failed")
        _raise_xray_client_http_error(exc)


@app.get("/api/xray/clients/{client_id}/qr")
async def api_xray_client_qr(
    client_id: str,
    protocol: Protocol | None = None,
    _=Depends(require_auth),
):
    try:
        artifact = ca.resolve_client_artifact(client_id, protocol=protocol)
        share = artifact.share
    except Exception as exc:
        logger.exception("xray_client_qr failed")
        _raise_xray_client_http_error(exc)

    img = qrcode.make(share.share_link)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


@app.get("/api/xray/clients/{client_id}/bundle")
async def api_xray_client_bundle(
    client_id: str,
    protocol: Protocol | None = None,
    _=Depends(require_auth),
):
    try:
        artifact = ca.resolve_client_artifact(client_id, protocol=protocol)
        share = artifact.share
        safe_name = _safe_download_name(share.name)
        doctor = xm.get_doctor_status()
        preview = ro.get_preview()

        bundle = io.BytesIO()
        with zipfile.ZipFile(bundle, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("vless-link.txt", share.share_link + "\n")
            archive.writestr(
                f"{safe_name}.xray-client.json",
                json.dumps(share.client_config, ensure_ascii=False, indent=2) + "\n",
            )
            archive.writestr(
                "xray-share.json",
                json.dumps(share.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n",
            )
            archive.writestr(
                "xray-doctor.json",
                json.dumps(doctor.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n",
            )
            archive.writestr(
                "routing-preview.json",
                json.dumps(preview.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n",
            )
            archive.writestr("manual-check-windows.md", _manual_check_text())
            archive.writestr(
                "README.txt",
                (
                    "VLESS/Xray smoke bundle\n\n"
                    "1. First check xray-doctor.json or the Xray doctor block in the panel.\n"
                    "2. Import vless-link.txt, QR from the panel, or the *.xray-client.json file.\n"
                    "3. Follow manual-check-windows.md and return the requested command output.\n"
                    "4. This bundle is read-only evidence; it does not apply or reload Xray.\n"
                ),
            )

        bundle.seek(0)
        return StreamingResponse(
            bundle,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{safe_name}.xray-smoke-bundle.zip"'},
        )
    except Exception as exc:
        logger.exception("xray_client_bundle failed")
        _raise_xray_client_http_error(exc)


@app.get("/api/routing/runtime")
async def api_routing_runtime(_=Depends(require_auth)):
    try:
        return xm.get_runtime_status().model_dump()
    except Exception as exc:
        logger.exception("routing_runtime failed")
        _raise_xray_http_error(exc)


@app.get("/api/routing/merged-config")
async def api_routing_merged_config(_=Depends(require_auth)):
    try:
        content = xm.render_merged_config_json()
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="xray-merged-config.json"'},
        )
    except Exception as exc:
        logger.exception("routing_merged_config failed")
        _raise_xray_http_error(exc)


@app.get("/api/routing/exported-routing")
async def api_routing_exported_routing(_=Depends(require_auth)):
    try:
        content = xm.read_exported_routing_json()
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="routing.generated.json"'},
        )
    except Exception as exc:
        logger.exception("routing_exported_routing failed")
        _raise_xray_http_error(exc)


@app.get("/api/routing/exported-merged-config")
async def api_routing_exported_merged_config(_=Depends(require_auth)):
    try:
        content = xm.read_exported_merged_config_json()
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="config.generated.json"'},
        )
    except Exception as exc:
        logger.exception("routing_exported_merged_config failed")
        _raise_xray_http_error(exc)


@app.post("/api/routing/export")
async def api_routing_export(_=Depends(require_auth)):
    try:
        return xm.export_routing().model_dump()
    except Exception as exc:
        logger.exception("routing_export failed")
        _raise_xray_http_error(exc)


@app.post("/api/routing/validate")
async def api_routing_validate(_=Depends(require_auth)):
    try:
        return xm.validate_routing().model_dump()
    except Exception as exc:
        logger.exception("routing_validate failed")
        _raise_xray_http_error(exc)


@app.post("/api/routing/reload")
async def api_routing_reload(_=Depends(require_auth)):
    try:
        return xm.reload_xray().model_dump()
    except Exception as exc:
        logger.exception("routing_reload failed")
        _raise_xray_http_error(exc)


@app.post("/api/routing/apply")
async def api_routing_apply(_=Depends(require_auth)):
    try:
        return xm.apply_xray().model_dump()
    except Exception as exc:
        logger.exception("routing_apply failed")
        _raise_xray_http_error(exc)


@app.get("/health")
async def health():
    return vm.health_check()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.PANEL_HOST, port=config.PANEL_PORT)
