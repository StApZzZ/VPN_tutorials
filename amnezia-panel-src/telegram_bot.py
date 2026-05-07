"""
Telegram bot for the VPN panel.

The bot is intentionally a separate long-running process. It talks to the
panel through the same REST API as external clients and keeps Telegram secrets
in environment variables only.
"""

import asyncio
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

import httpx

import config
import telegram_access as ta
import telegram_command_docs as tdocs

logger = logging.getLogger(__name__)

COMMAND_RE = re.compile(r"^/(?P<command>[a-zA-Z0-9_]+)(?:@[a-zA-Z0-9_]+)?(?:\s+(?P<args>.*))?$")
TELEGRAM_USERNAME_RE = re.compile(r"^@?[A-Za-z][A-Za-z0-9_]{4,31}$")
PHONE_HINT_RE = re.compile(r"^\+?[0-9][0-9 ()-]{5,24}$")
INVITE_CLAIM_CALLBACK_RE = re.compile(r"^invite_claim:(?P<action>approve|reject):(?P<claim_id>[0-9a-f]{32})$")
LANGUAGE_CALLBACK_RE = re.compile(r"^language:set:(?P<language>ru|en)$")
PAY_MONTHS_CALLBACK_RE = re.compile(r"^pay:months:(?P<user_id>\d+):(?P<months>1|3|6|12)$")
MENU_OPEN_CALLBACK_RE = re.compile(r"^menu:open:(?P<screen_id>[a-z0-9_.-]+)$")
MENU_TAP_CALLBACK_RE = re.compile(r"^menu:tap:(?P<screen_id>[a-z0-9_.-]+):(?P<item_id>[a-z0-9_.-]+)$")


USER_TEXTS = {
    "en": {
        "access_denied": "Access denied.",
        "bonus_spent": "Bonus spent: {stars} Stars.",
        "bonus_subscription": "Bonus balance covers the full subscription price.",
        "bundle_caption": "Xray smoke bundle: {name}",
        "config_not_assigned": "Config is not assigned yet.",
        "discount_subscription": "Discount covers the full subscription price.",
        "help_hint": "Use /help to see available commands.",
        "invite_accepted": "Invite accepted.\nTrial active until: {expires_at}\nUse /link to get your config.\nUse /help to see available commands.",
        "invite_already_active": "Invite already activated.\nAccess active until: {expires_at}\nUse /link to get your config.\nUse /help to see available commands.",
        "invite_activated_creator": "Invite activated.\nInvite ID: {invite_id}\nActivated by: {user_label}\nTrial active until: {expires_at}",
        "invite_created": "Pending invite created.\nInvite ID: {invite_id}\nTarget hint: {target}\nTrial days: {trial_days}\n\nSend this link to the user:\n{link}",
        "invite_created_username_hint": "\nSet TELEGRAM_BOT_USERNAME to generate clickable t.me invite links.",
        "invite_unavailable": "Invite is not available.",
        "invite_usage": "Usage: /invite <@username or +phone or telegram-user-id>\nFor example: /invite @pupkin or /invite 1111111",
        "invoice_created": "Invoice created.",
        "invoice_description": "VPN access for {months} month(s) ({days} days)",
        "invoice_label": "{months} month(s) VPN access",
        "invoice_label_bonus": "{months} month(s) VPN access ({stars} Stars bonus used)",
        "invoice_title": "VPN subscription",
        "language_prompt": "Choose the language you prefer for bot messages.\n\nВыберите язык, на котором вам удобнее читать сообщения бота.",
        "language_set": "Language set to English.",
        "language_usage": "Choose a language:",
        "menu_choose_action": "Choose an action:",
        "menu_helper_example": "Example:",
        "menu_helper_prompt": "Send this command manually with arguments.",
        "menu_helper_usage": "Usage:",
        "menu_root_prompt": "Use the buttons below to open available sections.",
        "pay_choose_duration": "Choose subscription period:",
        "pay_again": "Please send /pay again.",
        "payment_access_denied": "Access denied.",
        "payment_amount_changed": "Payment amount has changed. Please send /pay again.",
        "payment_already_processed": "Payment was already processed.",
        "payment_belongs_other": "Payment request belongs to another user.",
        "payment_order_not_found": "Payment received, but order was not found.",
        "payment_received": "Payment received.",
        "payment_request_not_active": "Payment request is no longer active. Please send /pay again.",
        "payment_request_not_found": "Payment request was not found. Please send /pay again.",
        "payment_validation_failed": "Payment received, but order validation failed.",
        "private_chat": "Use private chat with the bot to receive configs.",
        "qr_caption": "VLESS QR: {name}",
        "referral_bonus_credited": "Referral bonus has been credited to your inviter.",
        "share_link": (
            "VLESS link for {name}.\n"
            "The next message will contain the raw link for quick copy.\n"
            "If copying is inconvenient, use /qr and scan the code in the Amnezia app."
        ),
        "subscription_active_until": "Subscription active until: {expires_at}",
        "subscription_expired": "Subscription expired. VPN config has been deactivated. Use /pay to renew.",
        "subscription_expires_days": "Subscription expires in {days} days. Use /pay to renew.",
        "subscription_expires_one_day": "Subscription expires in 1 day. Use /pay to renew.",
        "subscription_expires_today": "Subscription expires today. Use /pay to renew.",
        "subscription_inactive": "Subscription is not active. Use /pay to activate VPN access.",
        "unsupported_payment_currency": "Unsupported payment currency.",
        "usage_bundle": "Usage: /bundle <client-id>",
        "usage_command": "Usage: /{command}",
        "usage_link": "Usage: /link <client-id>",
        "usage_qr": "Usage: /qr <client-id>",
        "user_bot_error": "Bot error: {error}",
        "user_panel_error": "Panel API error: {error}",
        "use_link": "Use /link to get your config.",
        "support_closed": "Support ticket {ticket_id} has been archived. Send /support if you need more help.",
        "support_compose_prompt": (
            "Write one text message with your question for support.\n"
            "If you already have an open ticket, the message will be added there. Otherwise a new ticket will be created."
        ),
        "support_created": "Support ticket {ticket_id} created. We will reply here.",
        "support_followup": "Message added to support ticket {ticket_id}. We will reply here.",
        "wg_caption": "WireGuard config: {name}",
        "wg_share_link": (
            "WireGuard config for {name}.\n"
            "VLESS stays the default option. If you need faster alternatives, use /wg or /awg."
        ),
        "awg_caption": "AmneziaWG config: {name}",
        "awg_share_link": (
            "AmneziaWG config for {name}.\n"
            "VLESS stays the default option. AmneziaWG is usually faster than VLESS and more private than plain WG."
        ),
    },
    "ru": {
        "access_denied": "Доступ запрещён.",
        "bonus_spent": "Списано бонусов: {stars} Stars.",
        "bonus_subscription": "Бонусный баланс полностью покрывает стоимость подписки.",
        "bundle_caption": "Архив настройки Xray: {name}",
        "config_not_assigned": "Конфиг ещё не назначен.",
        "discount_subscription": "Скидка полностью покрывает стоимость подписки.",
        "help_hint": "Используйте /help, чтобы посмотреть доступные команды.",
        "invite_accepted": "Приглашение принято.\nПробный период активен до: {expires_at}\nИспользуйте /link, чтобы получить конфиг.\nИспользуйте /help, чтобы посмотреть доступные команды.",
        "invite_already_active": "Приглашение уже активировано.\nДоступ активен до: {expires_at}\nИспользуйте /link, чтобы получить конфиг.\nИспользуйте /help, чтобы посмотреть доступные команды.",
        "invite_activated_creator": "Приглашение активировано.\nID приглашения: {invite_id}\nАктивировал: {user_label}\nПробный период до: {expires_at}",
        "invite_created": "Приглашение создано и ожидает активации.\nID приглашения: {invite_id}\nЦель: {target}\nПробный период: {trial_days} дн.\n\nОтправьте эту ссылку пользователю:\n{link}",
        "invite_created_username_hint": "\nЗадайте TELEGRAM_BOT_USERNAME, чтобы бот создавал кликабельные ссылки t.me.",
        "invite_unavailable": "Приглашение недоступно.",
        "invite_usage": "Использование: /invite <@username or +phone or telegram-user-id>\nНапример: /invite @pupkin или /invite 1111111",
        "invoice_created": "Счёт создан.",
        "invoice_description": "VPN-доступ на {months} мес. ({days} дн.)",
        "invoice_label": "VPN-доступ на {months} мес.",
        "invoice_label_bonus": "VPN-доступ на {months} мес. (использовано бонусов: {stars} Stars)",
        "invoice_title": "VPN-подписка",
        "language_prompt": "Выберите язык, на котором вам удобнее читать сообщения бота.\n\nChoose the language you prefer for bot messages.",
        "language_set": "Язык переключён на русский.",
        "language_usage": "Выберите язык:",
        "menu_choose_action": "Выберите действие:",
        "menu_helper_example": "Пример:",
        "menu_helper_prompt": "Введите эту команду вручную с аргументами.",
        "menu_helper_usage": "Использование:",
        "menu_root_prompt": "Используйте кнопки ниже, чтобы открыть доступные разделы.",
        "pay_choose_duration": "Выберите срок подписки:",
        "pay_again": "Отправьте /pay ещё раз.",
        "payment_access_denied": "Доступ запрещён.",
        "payment_amount_changed": "Сумма платежа изменилась. Отправьте /pay ещё раз.",
        "payment_already_processed": "Этот платёж уже обработан.",
        "payment_belongs_other": "Этот платёж относится к другому пользователю.",
        "payment_order_not_found": "Платёж получен, но заказ не найден.",
        "payment_received": "Платёж получен.",
        "payment_request_not_active": "Этот платёж больше не активен. Отправьте /pay ещё раз.",
        "payment_request_not_found": "Платёж не найден. Отправьте /pay ещё раз.",
        "payment_validation_failed": "Платёж получен, но проверка заказа не прошла.",
        "private_chat": "Напишите боту в личные сообщения, чтобы получить конфиг.",
        "qr_caption": "QR-код VLESS: {name}",
        "referral_bonus_credited": "Бонус за приглашение начислен тому, кто вас пригласил.",
        "share_link": (
            "VLESS-ссылка для {name}.\n"
            "Следующим сообщением бот отправит чистую ссылку для быстрого копирования.\n"
            "Если копировать неудобно, используйте /qr и отсканируйте код в приложении Amnezia."
        ),
        "subscription_active_until": "Подписка активна до: {expires_at}",
        "subscription_expired": "Подписка истекла. VPN-конфиг отключён. Используйте /pay для продления.",
        "subscription_expires_days": "Подписка истекает через {days} дн. Используйте /pay для продления.",
        "subscription_expires_one_day": "Подписка истекает через 1 день. Используйте /pay для продления.",
        "subscription_expires_today": "Подписка истекает сегодня. Используйте /pay для продления.",
        "subscription_inactive": "Подписка не активна. Используйте /pay, чтобы включить VPN-доступ.",
        "unsupported_payment_currency": "Валюта платежа не поддерживается.",
        "usage_bundle": "Использование: /bundle <client-id>",
        "usage_command": "Использование: /{command}",
        "usage_link": "Использование: /link <client-id>",
        "usage_qr": "Использование: /qr <client-id>",
        "user_bot_error": "Ошибка бота: {error}",
        "user_panel_error": "Ошибка Panel API: {error}",
        "use_link": "Используйте /link, чтобы получить конфиг.",
        "support_closed": "Заявка {ticket_id} переведена в архив. Если помощь понадобится снова, отправьте /support.",
        "support_compose_prompt": (
            "Напишите одним следующим сообщением ваш вопрос для поддержки.\n"
            "Если у вас уже есть открытая заявка, сообщение попадёт в неё. Иначе бот создаст новую."
        ),
        "support_created": "Заявка {ticket_id} создана. Ответ придёт сюда в этот чат.",
        "support_followup": "Сообщение добавлено в заявку {ticket_id}. Ответ придёт сюда в этот чат.",
        "wg_caption": "Конфиг WireGuard: {name}",
        "wg_share_link": (
            "Конфиг WireGuard для {name}.\n"
            "По умолчанию мы всё равно рекомендуем VLESS. Если нужен более быстрый вариант, можно использовать /wg или /awg."
        ),
        "awg_caption": "Конфиг AmneziaWG: {name}",
        "awg_share_link": (
            "Конфиг AmneziaWG для {name}.\n"
            "По умолчанию мы всё равно рекомендуем VLESS. AmneziaWG обычно быстрее VLESS и приватнее обычного WG."
        ),
    },
}


class BotConfigError(RuntimeError):
    pass


class PanelApiError(RuntimeError):
    pass


def parse_allowed_chat_ids(raw_value: str) -> set[int]:
    try:
        return ta.parse_id_set(raw_value)
    except ValueError as exc:
        raise BotConfigError(str(exc)) from exc


def _filename_from_content_disposition(header_value: str, fallback: str) -> str:
    if not header_value:
        return fallback

    match = re.search(r'filename="?(?P<name>[^";]+)"?', header_value)
    if not match:
        return fallback

    name = match.group("name").strip()
    return name or fallback


def _safe_name(value: str, fallback: str = "client") -> str:
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in value.strip())
    return safe.strip("-_.") or fallback


@dataclass
class Download:
    filename: str
    content: bytes
    content_type: str


class PanelClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        http: httpx.AsyncClient | None = None,
        timeout: float = 20.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self._owns_http = http is None
        self.http = http or httpx.AsyncClient(base_url=self.base_url, timeout=timeout)

    async def aclose(self) -> None:
        if self._owns_http:
            await self.http.aclose()

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        response = await self.http.request(method, path, headers=self._headers(), **kwargs)
        if response.status_code >= 400:
            detail = response.text
            try:
                payload = response.json()
                detail = str(payload.get("detail", payload))
            except ValueError:
                pass
            raise PanelApiError(f"Panel API {response.status_code}: {detail}")
        return response

    async def list_clients(self) -> list[dict[str, Any]]:
        response = await self._request("GET", "/api/xray/clients")
        payload = response.json()
        if not isinstance(payload, list):
            raise PanelApiError("Panel API returned an invalid clients list")
        return payload

    async def create_client(self, name: str) -> dict[str, Any]:
        response = await self._request(
            "POST",
            "/api/xray/clients",
            json={"name": name, "email": None},
        )
        return response.json()

    async def update_client(
        self,
        client_id: str,
        name: str,
        email: str | None = None,
    ) -> dict[str, Any]:
        response = await self._request(
            "PUT",
            f"/api/xray/clients/{client_id}",
            json={"name": name, "email": email},
        )
        return response.json()

    async def get_share(self, client_id: str) -> dict[str, Any]:
        response = await self._request("GET", f"/api/xray/clients/{client_id}/share")
        return response.json()

    async def get_qr(self, client_id: str, client_name: str = "client") -> Download:
        response = await self._request("GET", f"/api/xray/clients/{client_id}/qr")
        filename = f"{_safe_name(client_name)}.png"
        return Download(
            filename=filename,
            content=response.content,
            content_type=response.headers.get("content-type", "image/png"),
        )

    async def get_bundle(self, client_id: str, client_name: str = "client") -> Download:
        response = await self._request("GET", f"/api/xray/clients/{client_id}/bundle")
        fallback = f"{_safe_name(client_name)}.xray-smoke-bundle.zip"
        filename = _filename_from_content_disposition(
            response.headers.get("content-disposition", ""),
            fallback,
        )
        return Download(
            filename=filename,
            content=response.content,
            content_type=response.headers.get("content-type", "application/zip"),
        )

    async def delete_client(self, client_id: str) -> None:
        await self._request("DELETE", f"/api/xray/clients/{client_id}")

    async def get_client(self, client_id: str) -> dict[str, Any]:
        for client in await self.list_clients():
            if client.get("id") == client_id:
                return client
        raise PanelApiError("Xray client not found")

    async def set_client_enabled(self, client_id: str, enabled: bool) -> dict[str, Any]:
        client = await self.get_client(client_id)
        if bool(client.get("enabled")) == enabled:
            return client

        response = await self._request("POST", f"/api/xray/clients/{client_id}/toggle")
        return response.json()

    async def doctor(self) -> dict[str, Any]:
        response = await self._request("GET", "/api/xray/doctor")
        return response.json()

    async def create_peer(self, name: str) -> dict[str, Any]:
        response = await self._request("POST", "/api/peers", json={"name": name})
        return response.json()

    async def list_peers(self) -> list[dict[str, Any]]:
        response = await self._request("GET", "/api/peers")
        payload = response.json()
        if not isinstance(payload, list):
            raise PanelApiError("Panel API returned an invalid peers list")
        return payload

    async def get_peer(self, public_key: str) -> dict[str, Any]:
        for peer in await self.list_peers():
            if peer.get("public_key") == public_key:
                return peer
        raise PanelApiError("WireGuard peer not found")

    def _peer_path(self, public_key: str, suffix: str = "") -> str:
        encoded_public_key = quote(public_key, safe="")
        return f"/api/peers/{encoded_public_key}{suffix}"

    async def update_peer(self, public_key: str, name: str) -> dict[str, Any]:
        response = await self._request(
            "PUT",
            self._peer_path(public_key),
            json={"name": name},
        )
        return response.json()

    async def set_peer_enabled(self, public_key: str, enabled: bool) -> dict[str, Any]:
        peer = await self.get_peer(public_key)
        is_deactivated = bool(peer.get("deactivated"))
        if enabled and not is_deactivated:
            return peer
        if (not enabled) and is_deactivated:
            return peer

        action = "activate" if enabled else "deactivate"
        response = await self._request("POST", self._peer_path(public_key, f"/{action}"))
        return response.json()

    async def get_peer_config(self, public_key: str, protocol: str = "wg") -> Download:
        response = await self._request(
            "GET",
            self._peer_path(public_key, "/config"),
            params={"protocol": protocol},
        )
        fallback_suffix = "conf" if protocol in {"wg", "amneziawg"} else "txt"
        fallback = f"{_safe_name(public_key, fallback='peer')}.{fallback_suffix}"
        filename = _filename_from_content_disposition(
            response.headers.get("content-disposition", ""),
            fallback,
        )
        return Download(
            filename=filename,
            content=response.content,
            content_type=response.headers.get("content-type", "text/plain; charset=utf-8"),
        )

    async def get_peer_qr(self, public_key: str, protocol: str = "wg", peer_name: str = "peer") -> Download:
        response = await self._request(
            "GET",
            self._peer_path(public_key, "/qr"),
            params={"protocol": protocol},
        )
        filename = f"{_safe_name(peer_name, fallback='peer')}-{protocol}.png"
        return Download(
            filename=filename,
            content=response.content,
            content_type=response.headers.get("content-type", "image/png"),
        )


class TelegramClient:
    def __init__(
        self,
        token: str,
        http: httpx.AsyncClient | None = None,
        timeout: float = 20.0,
        proxy_url: str | None = None,
    ):
        self.token = token
        self._owns_http = http is None
        self.http = http or httpx.AsyncClient(
            base_url=f"https://api.telegram.org/bot{token}",
            timeout=timeout,
            proxy=proxy_url,
            trust_env=False,
        )

    async def aclose(self) -> None:
        if self._owns_http:
            await self.http.aclose()

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        response = await self.http.request(method, path, **kwargs)
        if response.status_code >= 400:
            raise RuntimeError(f"Telegram API {response.status_code}: {response.text}")
        payload = response.json()
        if not payload.get("ok", False):
            raise RuntimeError(f"Telegram API error: {payload}")
        return payload

    async def get_updates(self, offset: int | None, timeout: int) -> list[dict[str, Any]]:
        payload = await self._request(
            "GET",
            "/getUpdates",
            params={
                "timeout": timeout,
                "offset": offset,
                "allowed_updates": '["message","callback_query","pre_checkout_query"]',
            },
        )
        result = payload.get("result", [])
        if not isinstance(result, list):
            raise RuntimeError("Telegram API returned invalid updates")
        return result

    async def get_chat(self, chat_id: int) -> dict[str, Any]:
        payload = await self._request(
            "GET",
            "/getChat",
            params={"chat_id": chat_id},
        )
        result = payload.get("result", {})
        if not isinstance(result, dict):
            raise RuntimeError("Telegram API returned invalid chat")
        return result

    async def send_message(
        self,
        chat_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> None:
        for chunk in _message_chunks(text):
            payload = {
                "chat_id": chat_id,
                "text": chunk,
                "disable_web_page_preview": True,
            }
            if reply_markup is not None:
                payload["reply_markup"] = reply_markup
            await self._request("POST", "/sendMessage", json=payload)

    async def send_photo(self, chat_id: int, photo: Download, caption: str = "") -> None:
        await self._request(
            "POST",
            "/sendPhoto",
            data={"chat_id": str(chat_id), "caption": caption},
            files={"photo": (photo.filename, photo.content, photo.content_type)},
        )

    async def send_document(self, chat_id: int, document: Download, caption: str = "") -> None:
        await self._request(
            "POST",
            "/sendDocument",
            data={"chat_id": str(chat_id), "caption": caption},
            files={"document": (document.filename, document.content, document.content_type)},
        )

    async def send_invoice(
        self,
        chat_id: int,
        title: str,
        description: str,
        payload: str,
        amount_stars: int,
        label: str,
    ) -> None:
        await self._request(
            "POST",
            "/sendInvoice",
            json={
                "chat_id": chat_id,
                "title": title,
                "description": description,
                "payload": payload,
                "currency": ta.PAYMENT_CURRENCY,
                "prices": [{"label": label, "amount": amount_stars}],
            },
        )

    async def answer_pre_checkout_query(
        self,
        pre_checkout_query_id: str,
        ok: bool,
        error_message: str = "",
    ) -> None:
        payload: dict[str, Any] = {
            "pre_checkout_query_id": pre_checkout_query_id,
            "ok": ok,
        }
        if not ok:
            payload["error_message"] = error_message or "Payment cannot be processed."
        await self._request("POST", "/answerPreCheckoutQuery", json=payload)

    async def answer_callback_query(
        self,
        callback_query_id: str,
        text: str = "",
        show_alert: bool = False,
    ) -> None:
        payload: dict[str, Any] = {
            "callback_query_id": callback_query_id,
            "show_alert": show_alert,
        }
        if text:
            payload["text"] = text
        await self._request("POST", "/answerCallbackQuery", json=payload)


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
        if current and len(current) + len(line) > limit:
            chunks.append(current)
            current = ""
        current += line
    if current:
        chunks.append(current)
    return chunks


def _parse_user_id(value: str) -> int | None:
    try:
        user_id = int(value.strip())
    except ValueError:
        return None
    if user_id <= 0:
        return None
    return user_id


def _start_token_from_text(text: str) -> str:
    match = COMMAND_RE.match(text.strip())
    if not match or match.group("command").lower() != "start":
        return ""
    return (match.group("args") or "").strip()


def _parse_user_id_and_text(value: str) -> tuple[int, str] | None:
    parts = value.split(maxsplit=1)
    if len(parts) != 2:
        return None

    user_id = _parse_user_id(parts[0])
    text = parts[1].strip()
    if user_id is None or not text:
        return None
    return user_id, text


def _parse_ticket_id(value: str) -> str:
    ticket_id = (value or "").strip().upper()
    if not re.fullmatch(r"T\d{6}", ticket_id):
        return ""
    return ticket_id


def _parse_ticket_reply_args(value: str) -> tuple[str, str] | None:
    parts = (value or "").strip().split(maxsplit=1)
    if len(parts) != 2:
        return None
    ticket_id = _parse_ticket_id(parts[0])
    message = parts[1].strip()
    if not ticket_id or not message:
        return None
    return ticket_id, message


def _parse_invite_target(value: str) -> dict[str, Any] | None:
    target = value.strip()
    if not target:
        return None

    user_id = _parse_user_id(target)
    if user_id is not None:
        return {"target_user_id": user_id}

    if TELEGRAM_USERNAME_RE.fullmatch(target):
        username = target if target.startswith("@") else f"@{target}"
        return {"target_username_hint": username.lower()}

    if PHONE_HINT_RE.fullmatch(target):
        phone = re.sub(r"[\s()-]+", "", target)
        if not phone.startswith("+"):
            phone = f"+{phone}"
        return {"target_phone_hint": phone}

    return None


def _profile_username(profile: dict[str, Any]) -> str:
    username = str(profile.get("username") or "").strip().lstrip("@")
    if not username:
        return ""
    return f"@{username.lower()}"


def _telegram_language_code(profile: dict[str, Any] | None) -> str:
    if not isinstance(profile, dict):
        return ""
    return str(profile.get("language_code") or "").strip().lower()


def _t(language: str, key: str, **kwargs: Any) -> str:
    lang = ta.normalize_user_language(language) or ta.DEFAULT_USER_LANGUAGE
    template = USER_TEXTS.get(lang, USER_TEXTS[ta.DEFAULT_USER_LANGUAGE]).get(key)
    if template is None:
        template = USER_TEXTS[ta.DEFAULT_USER_LANGUAGE][key]
    return template.format(**kwargs)


def _language_reply_markup() -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [
                {"text": "Русский", "callback_data": "language:set:ru"},
                {"text": "English", "callback_data": "language:set:en"},
            ]
        ]
    }


def _pay_months_reply_markup(user_id: int) -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [
                {"text": "1 month", "callback_data": f"pay:months:{user_id}:1"},
                {"text": "3 months", "callback_data": f"pay:months:{user_id}:3"},
            ],
            [
                {"text": "6 months", "callback_data": f"pay:months:{user_id}:6"},
                {"text": "12 months", "callback_data": f"pay:months:{user_id}:12"},
            ],
        ]
    }


def _menu_open_callback(screen_id: str) -> str:
    return f"menu:open:{screen_id}"


def _menu_tap_callback(screen_id: str, item_id: str) -> str:
    return f"menu:tap:{screen_id}:{item_id}"


def _chunked_labels(labels: list[str], width: int = 2) -> list[list[str]]:
    rows: list[list[str]] = []
    for index in range(0, len(labels), width):
        rows.append(labels[index : index + width])
    return rows


def _root_menu_reply_markup(items: list[tdocs.MenuItem]) -> dict[str, Any]:
    labels = [item.label for item in items]
    return {
        "keyboard": [[{"text": label} for label in row] for row in _chunked_labels(labels)],
        "resize_keyboard": True,
    }


def _inline_menu_reply_markup(screen_id: str, items: list[tdocs.MenuItem]) -> dict[str, Any]:
    rows: list[list[dict[str, str]]] = []
    regular_items = [item for item in items if item.action.kind != "back"]
    back_items = [item for item in items if item.action.kind == "back"]
    for row_items in _chunked_labels([item.item_id for item in regular_items]):
        row: list[dict[str, str]] = []
        for item_id in row_items:
            item = next(item for item in regular_items if item.item_id == item_id)
            callback_data = (
                _menu_open_callback(item.action.target)
                if item.action.kind == "submenu"
                else _menu_tap_callback(screen_id, item.item_id)
            )
            row.append({"text": item.label, "callback_data": callback_data})
        rows.append(row)
    for item in back_items:
        rows.append([{"text": item.label, "callback_data": _menu_open_callback(item.action.target)}])
    return {"inline_keyboard": rows}


def _menu_helper_example(command_text: str) -> str:
    parts = command_text.strip().split()
    if not parts:
        return command_text.strip()
    example = [parts[0]]
    for part in parts[1:]:
        if part.startswith("<") and part.endswith(">"):
            example.append("...")
            continue
        if part.startswith("[") and part.endswith("]"):
            example.append("...")
            continue
        example.append(part)
    return " ".join(example)


def _invite_target_label(invite: dict[str, Any]) -> str:
    return str(
        invite.get("target_username_hint")
        or invite.get("target_phone_hint")
        or invite.get("target_user_id")
        or "unknown"
    )


def parse_notify_days(raw_value: str) -> set[int]:
    values = [item.strip() for item in re.split(r"[,\s]+", raw_value or "") if item.strip()]
    days: set[int] = set()
    for value in values:
        try:
            day = int(value)
        except ValueError as exc:
            raise BotConfigError(f"Invalid subscription notify day: {value}") from exc
        if day < 0:
            raise BotConfigError(f"Invalid subscription notify day: {value}")
        days.add(day)
    return days or {3, 1, 0}


def _parse_positive_int(value: str) -> int | None:
    try:
        parsed = int(value.strip())
    except ValueError:
        return None
    if parsed <= 0:
        return None
    return parsed


def _parse_non_negative_int(value: str) -> int | None:
    try:
        parsed = int(value.strip())
    except ValueError:
        return None
    if parsed < 0:
        return None
    return parsed


def _parse_moscow_expiry_date(value: str) -> datetime | None:
    match = re.fullmatch(r"\d{4}-\d{2}-\d{2}", value.strip())
    if not match:
        return None
    try:
        year, month, day = [int(part) for part in value.split("-")]
        moscow = timezone(timedelta(hours=3))
        local_expiry = datetime(year, month, day, 23, 59, 59, tzinfo=moscow)
    except ValueError:
        return None
    return local_expiry.astimezone(timezone.utc)


def _format_months_label(months: int, lang: str) -> str:
    if lang == "ru":
        if months % 10 == 1 and months % 100 != 11:
            suffix = "месяц"
        elif months % 10 in {2, 3, 4} and months % 100 not in {12, 13, 14}:
            suffix = "месяца"
        else:
            suffix = "месяцев"
        return f"{months} {suffix}"
    return f"{months} month" if months == 1 else f"{months} months"


def _format_pay_quote_lines(quote: dict[str, int], lang: str) -> list[str]:
    months = int(quote.get("months") or 1)
    period_days = int(quote.get("period_days") or 0)
    amount_stars = int(quote.get("amount_stars") or 0)
    base_amount_stars = int(quote.get("base_amount_stars") or 0)
    bonus_spent_stars = int(quote.get("bonus_spent_stars") or 0)
    total_discount_percent = int(quote.get("total_discount_percent") or 0)
    package_discount_percent = int(quote.get("package_discount_percent") or 0)
    if lang == "ru":
        line = f"- {_format_months_label(months, lang)} / {period_days} дн.: {amount_stars} Stars"
        details: list[str] = []
        if total_discount_percent > 0:
            details.append(f"скидка {total_discount_percent}%")
        if bonus_spent_stars > 0:
            details.append(f"-{bonus_spent_stars} bonus")
        if details:
            line = f"{line} ({', '.join(details)})"
        extra = f"  До бонусов: {base_amount_stars} Stars."
        if package_discount_percent > 0:
            extra += f" Пакетная скидка: {package_discount_percent}%."
        return [line, extra]
    line = f"- {_format_months_label(months, lang)} / {period_days} days: {amount_stars} Stars"
    details: list[str] = []
    if total_discount_percent > 0:
        details.append(f"{total_discount_percent}% discount")
    if bonus_spent_stars > 0:
        details.append(f"-{bonus_spent_stars} bonus")
    if details:
        line = f"{line} ({', '.join(details)})"
    extra = f"  Before bonus: {base_amount_stars} Stars."
    if package_discount_percent > 0:
        extra += f" Package discount: {package_discount_percent}%."
    return [line, extra]


def _format_pay_selection_message(
    quotes: list[dict[str, int]],
    lang: str,
    max_12m_discount_percent: int,
) -> str:
    lines = [_t(lang, "pay_choose_duration")]
    if lang == "ru":
        lines.append(
            f"Цена за 1 месяц: {quotes[0]['monthly_price_stars']} Stars / {quotes[0]['period_days']} дн."
        )
        if max_12m_discount_percent > 0:
            lines.append(f"Макс. пакетная скидка на 12 месяцев: {max_12m_discount_percent}%.")
        bonus_balance = int(quotes[0].get("bonus_balance_stars") or 0)
        if bonus_balance > 0:
            lines.append(f"Бонусный баланс: {bonus_balance} Stars.")
    else:
        lines.append(
            f"Monthly base price: {quotes[0]['monthly_price_stars']} Stars / {quotes[0]['period_days']} days."
        )
        if max_12m_discount_percent > 0:
            lines.append(f"Max 12-month package discount: {max_12m_discount_percent}%.")
        bonus_balance = int(quotes[0].get("bonus_balance_stars") or 0)
        if bonus_balance > 0:
            lines.append(f"Bonus balance: {bonus_balance} Stars.")
    for quote in quotes:
        lines.extend(_format_pay_quote_lines(quote, lang))
    if lang == "ru":
        lines.append("Нажмите кнопку ниже, чтобы выставить счёт или сразу активировать пакет.")
    else:
        lines.append("Tap a button below to create an invoice or activate the package immediately.")
    return "\n".join(lines)


class TelegramVpnBot:
    def __init__(
        self,
        panel: PanelClient,
        telegram: TelegramClient,
        access: ta.TelegramAccessStore,
        command_docs: tdocs.TelegramCommandDocsStore | None = None,
        subscription_check_interval_seconds: int = 300,
        subscription_notify_days: set[int] | None = None,
        bot_username: str = "",
    ):
        self.panel = panel
        self.telegram = telegram
        self.access = access
        self.command_docs = command_docs or tdocs.TelegramCommandDocsStore(
            path=config.TELEGRAM_COMMAND_DOCS_PATH
        )
        self.subscription_check_interval_seconds = max(30, subscription_check_interval_seconds)
        self.subscription_notify_days = subscription_notify_days or {3, 1, 0}
        self.bot_username = bot_username.strip().lstrip("@")
        self._telegram_send_message = telegram.send_message
        self.telegram.send_message = self._send_message_proxy

    async def _send_message_proxy(
        self,
        chat_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> None:
        markup = reply_markup
        if markup is None:
            markup = self._default_root_reply_markup(chat_id)
        await self._telegram_send_message(chat_id, text, reply_markup=markup)

    def _default_root_reply_markup(self, chat_id: int) -> dict[str, Any] | None:
        if not isinstance(chat_id, int) or chat_id <= 0:
            return None
        if not self.access.is_known_user(chat_id):
            return None
        parsed = self.command_docs.load_effective()
        return _root_menu_reply_markup(
            parsed.root_menu_items(
                is_admin=self.access.is_admin(chat_id),
                lang=self._user_lang(chat_id),
            )
        )

    def _is_regular_user(self, user_id: int) -> bool:
        return self.access.is_known_user(user_id) and not self.access.is_admin(user_id)

    def _user_lang(self, user_id: int, from_user: dict[str, Any] | None = None) -> str:
        if self.access.is_admin(user_id):
            return ta.DEFAULT_USER_LANGUAGE
        return self.access.preferred_language_for_user(
            user_id,
            telegram_language_code=_telegram_language_code(from_user),
        )

    async def _ensure_user_language(
        self,
        chat_id: int,
        user_id: int,
        from_user: dict[str, Any] | None = None,
        send_prompt: bool = True,
    ) -> str:
        if not self._is_regular_user(user_id):
            return ta.DEFAULT_USER_LANGUAGE

        telegram_language_code = _telegram_language_code(from_user)
        record = self.access.user_record(user_id) or {}
        language = self.access.preferred_language_for_user(
            user_id,
            telegram_language_code=telegram_language_code,
        )
        was_prompted = bool(record.get("language_prompted_at"))
        needs_profile_update = (
            not record.get("preferred_language")
            or (telegram_language_code and record.get("telegram_language_code") != telegram_language_code)
            or not was_prompted
        )
        if needs_profile_update:
            self.access.update_user_language(
                user_id,
                preferred_language=language,
                telegram_language_code=telegram_language_code,
                mark_prompted=send_prompt and not was_prompted,
            )
        if send_prompt and not was_prompted:
            await self.telegram.send_message(
                chat_id,
                _t(language, "language_prompt"),
                reply_markup=_language_reply_markup(),
            )
        return language

    def _menu_screen_title(
        self,
        parsed: tdocs.ParsedTelegramCommandDocs,
        screen_id: str,
        is_admin: bool,
        lang: str,
    ) -> str:
        if screen_id == tdocs.SCREEN_USER_ROOT:
            return "Main menu" if lang != "ru" else "Главное меню"
        if screen_id.startswith("user."):
            for item in parsed.root_menu_items(is_admin=is_admin, lang=lang):
                if item.action.kind == "submenu" and item.action.target == screen_id:
                    return item.label
        if screen_id == tdocs.SCREEN_ADMIN_ROOT:
            for item in parsed.root_menu_items(is_admin=True, lang=lang):
                if item.action.kind == "submenu" and item.action.target == screen_id:
                    return item.label
            return "Admin"
        for item in parsed.menu_screen_items(tdocs.SCREEN_ADMIN_ROOT, "en"):
            if item.action.kind == "submenu" and item.action.target == screen_id:
                return item.label
        return screen_id

    async def _open_menu_screen(
        self,
        chat_id: int,
        user_id: int,
        screen_id: str,
        lang: str,
        callback_id: str = "",
    ) -> None:
        if screen_id.startswith("admin.") and not self.access.is_admin(user_id):
            if callback_id:
                await self.telegram.answer_callback_query(
                    callback_id,
                    text=_t(lang, "access_denied"),
                    show_alert=True,
                )
            return

        if callback_id:
            await self.telegram.answer_callback_query(callback_id)

        if screen_id == tdocs.SCREEN_USER_ROOT:
            await self.telegram.send_message(chat_id, _t(lang, "menu_root_prompt"))
            return

        parsed = self.command_docs.load_effective()
        title = self._menu_screen_title(
            parsed,
            screen_id=screen_id,
            is_admin=self.access.is_admin(user_id),
            lang=lang,
        )
        await self.telegram.send_message(
            chat_id,
            f"{title}\n\n{_t(lang, 'menu_choose_action')}",
            reply_markup=_inline_menu_reply_markup(
                screen_id,
                parsed.menu_screen_items(screen_id, lang),
            ),
        )

    async def _show_menu_helper(
        self,
        chat_id: int,
        user_id: int,
        command_name: str,
        lang: str,
    ) -> None:
        entry = self.command_docs.load_effective().lookup_help_entry(
            command_name,
            is_admin=self.access.is_admin(user_id),
            lang=lang,
        )
        if entry is None:
            await self.telegram.send_message(chat_id, _t(lang, "access_denied"))
            return
        lines = [
            entry.command,
            entry.description,
            "",
            _t(lang, "menu_helper_usage"),
            entry.command,
        ]
        example = _menu_helper_example(entry.command)
        if example and example != entry.command:
            lines.extend(["", _t(lang, "menu_helper_example"), example])
        lines.extend(["", _t(lang, "menu_helper_prompt")])
        await self.telegram.send_message(chat_id, "\n".join(lines))

    async def _execute_menu_command(
        self,
        chat_id: int,
        user_id: int,
        chat_type: str,
        command_text: str,
        lang: str,
        from_user: dict[str, Any] | None = None,
    ) -> None:
        await self._dispatch(
            chat_id,
            user_id,
            chat_type,
            command_text,
            from_user=from_user,
            lang=lang,
        )

    async def _handle_menu_item_action(
        self,
        chat_id: int,
        user_id: int,
        chat_type: str,
        item: tdocs.MenuItem,
        lang: str,
        from_user: dict[str, Any] | None = None,
        callback_id: str = "",
    ) -> None:
        if item.action.kind in {"submenu", "back"}:
            await self._open_menu_screen(
                chat_id,
                user_id,
                screen_id=item.action.target,
                lang=lang,
                callback_id=callback_id,
            )
            return
        if callback_id:
            await self.telegram.answer_callback_query(callback_id)
        if item.action.kind == "helper":
            await self._show_menu_helper(chat_id, user_id, item.action.command, lang)
            return
        await self._execute_menu_command(
            chat_id,
            user_id,
            chat_type,
            f"/{item.action.command}",
            lang=lang,
            from_user=from_user,
        )

    async def run_polling(self, poll_timeout: int) -> None:
        offset: int | None = None
        maintenance_task = asyncio.create_task(self.run_subscription_maintenance())
        try:
            while True:
                try:
                    updates = await self.telegram.get_updates(offset=offset, timeout=poll_timeout)
                except Exception as exc:
                    logger.warning("Telegram polling failed: %r", exc, exc_info=True)
                    await asyncio.sleep(5)
                    continue

                for update in updates:
                    update_id = update.get("update_id")
                    if isinstance(update_id, int):
                        offset = update_id + 1
                    await self.handle_update(update)
        finally:
            maintenance_task.cancel()

    async def handle_update(self, update: dict[str, Any]) -> None:
        pre_checkout_query = update.get("pre_checkout_query")
        if isinstance(pre_checkout_query, dict):
            await self._handle_pre_checkout_query(pre_checkout_query)
            return

        callback_query = update.get("callback_query")
        if isinstance(callback_query, dict):
            await self._handle_callback_query(callback_query)
            return

        message = update.get("message") or {}
        chat = message.get("chat") or {}
        chat_id = chat.get("id")
        if not isinstance(chat_id, int):
            return

        from_user = message.get("from") or {}
        user_id = from_user.get("id")
        if not isinstance(user_id, int):
            logger.warning("Rejected Telegram message without from.id in chat_id=%s", chat_id)
            return

        text = (message.get("text") or "").strip()
        chat_type = str(chat.get("type") or "private")

        if not self.access.is_known_user(user_id):
            token = _start_token_from_text(text) if text else ""
            if token:
                try:
                    await self._accept_invite(
                        chat_id,
                        user_id,
                        chat_type,
                        token,
                        from_user,
                        respond_to_user=False,
                    )
                except Exception as exc:
                    logger.warning("Silent invite flow failed for user_id=%s: %s", user_id, exc)
            return

        await self._refresh_known_user_profile(user_id, from_user)

        successful_payment = message.get("successful_payment")
        command_match = COMMAND_RE.match(text) if text else None
        skip_language_prompt = (
            command_match is not None and command_match.group("command").lower() == "language"
        )
        lang = await self._ensure_user_language(
            chat_id,
            user_id,
            from_user,
            send_prompt=chat_type == "private" and not skip_language_prompt,
        )
        if isinstance(successful_payment, dict):
            try:
                await self._handle_successful_payment(chat_id, user_id, successful_payment, lang)
            except PanelApiError as exc:
                logger.warning("Panel API payment fulfilment failed: %s", exc)
                if self.access.is_admin(user_id):
                    await self.telegram.send_message(chat_id, f"Panel API error: {exc}")
                else:
                    await self.telegram.send_message(chat_id, _t(lang, "user_panel_error", error=exc))
            except Exception as exc:
                logger.exception("Telegram payment fulfilment failed")
                if self.access.is_admin(user_id):
                    await self.telegram.send_message(chat_id, f"Bot error: {exc}")
                else:
                    await self.telegram.send_message(chat_id, _t(lang, "user_bot_error", error=exc))
            return

        if not text:
            return

        if (
            self._is_regular_user(user_id)
            and chat_type == "private"
            and self.access.support_compose_started_at_for_user(user_id)
            and command_match is None
        ):
            await self._capture_support_message(chat_id, user_id, text, lang)
            return

        try:
            await self._dispatch(chat_id, user_id, chat_type, text, from_user, lang)
        except PanelApiError as exc:
            logger.warning("Panel API command failed: %s", exc)
            if self.access.is_admin(user_id):
                await self.telegram.send_message(chat_id, f"Panel API error: {exc}")
            else:
                await self.telegram.send_message(chat_id, _t(lang, "user_panel_error", error=exc))
        except Exception as exc:
            logger.exception("Telegram command failed")
            if self.access.is_admin(user_id):
                await self.telegram.send_message(chat_id, f"Bot error: {exc}")
            else:
                await self.telegram.send_message(chat_id, _t(lang, "user_bot_error", error=exc))

    async def _dispatch(
        self,
        chat_id: int,
        user_id: int,
        chat_type: str,
        text: str,
        from_user: dict[str, Any] | None = None,
        lang: str = ta.DEFAULT_USER_LANGUAGE,
    ) -> None:
        parsed = self.command_docs.load_effective()
        match = COMMAND_RE.match(text)
        if not match:
            root_item = parsed.root_menu_item_for_label(
                text,
                is_admin=self.access.is_admin(user_id),
                lang=lang,
            )
            if root_item is not None:
                await self._handle_menu_item_action(
                    chat_id,
                    user_id,
                    chat_type,
                    root_item,
                    lang=lang,
                    from_user=from_user,
                )
                return
            await self.telegram.send_message(chat_id, self._help_text(user_id, lang))
            return

        command = match.group("command").lower()
        args = (match.group("args") or "").strip()

        if command == "start":
            if args:
                await self._accept_invite(chat_id, user_id, chat_type, args, from_user or {}, lang=lang)
                return
            await self.telegram.send_message(chat_id, self._help_text(user_id, lang))
        elif command == "help":
            await self.telegram.send_message(chat_id, self._help_text(user_id, lang))
        elif command == "invite":
            await self._invite_user(chat_id, user_id, args, lang)
        elif command == "language":
            await self._language(chat_id, user_id, args, from_user or {}, lang)
        elif command in {"status", "pay", "apps", "install", "instruction"}:
            await self._dispatch_common(chat_id, user_id, chat_type, command, args, lang)
        elif self.access.is_admin(user_id):
            await self._dispatch_admin(chat_id, user_id, chat_type, command, args)
        else:
            await self._dispatch_user(chat_id, user_id, chat_type, command, args, lang)

    async def _dispatch_common(
        self,
        chat_id: int,
        user_id: int,
        chat_type: str,
        command: str,
        args: str,
        lang: str,
    ) -> None:
        if args:
            lang = ta.DEFAULT_USER_LANGUAGE if self.access.is_admin(user_id) else lang
            await self.telegram.send_message(chat_id, _t(lang, "usage_command", command=command))
            return
        lang = ta.DEFAULT_USER_LANGUAGE if self.access.is_admin(user_id) else lang
        if command == "status":
            await self._status(chat_id, user_id, lang)
        elif command == "pay":
            if not await self._ensure_private(chat_id, chat_type, lang):
                return
            await self._pay(chat_id, user_id, lang)
        elif command == "apps":
            await self.telegram.send_message(
                chat_id,
                self.command_docs.load_effective().render_apps(lang),
            )
        elif command == "install":
            await self.telegram.send_message(
                chat_id,
                self.command_docs.load_effective().render_install(lang),
            )
        elif command == "instruction":
            await self.telegram.send_message(
                chat_id,
                self.command_docs.load_effective().render_instruction(lang),
            )

    async def _dispatch_admin(
        self,
        chat_id: int,
        user_id: int,
        chat_type: str,
        command: str,
        args: str,
    ) -> None:
        if command in {"new", "create"}:
            if not await self._ensure_private(chat_id, chat_type):
                return
            await self._create_client(chat_id, args)
        elif command == "clients":
            await self._list_clients(chat_id)
        elif command == "link":
            if not await self._ensure_private(chat_id, chat_type):
                return
            await self._send_link(chat_id, args)
        elif command == "qr":
            if not await self._ensure_private(chat_id, chat_type):
                return
            await self._send_qr(chat_id, args)
        elif command == "bundle":
            if not await self._ensure_private(chat_id, chat_type):
                return
            await self._send_bundle(chat_id, args)
        elif command == "disable":
            await self._set_enabled(chat_id, args, enabled=False)
        elif command == "enable":
            await self._set_enabled(chat_id, args, enabled=True)
        elif command == "delete":
            await self._delete_client(chat_id, args)
        elif command == "doctor":
            await self._doctor(chat_id)
        elif command == "bind":
            await self._bind_client(chat_id, user_id, args)
        elif command == "newfor":
            if not await self._ensure_private(chat_id, chat_type):
                return
            await self._create_client_for_user(chat_id, user_id, args)
        elif command == "price":
            await self._price(chat_id, args)
        elif command == "discount":
            await self._discount(chat_id, args)
        elif command == "expires":
            await self._expires(chat_id, args)
        elif command == "grant":
            await self._grant(chat_id, args)
        elif command == "revoke":
            await self._revoke(chat_id, args)
        elif command == "invites":
            await self._list_invites(chat_id)
        elif command == "leads":
            await self._list_leads(chat_id)
        elif command == "trial":
            await self._trial(chat_id, args)
        elif command == "bonus":
            await self._bonus(chat_id, args)
        elif command == "broadcastactive":
            await self._broadcast(chat_id, args, audience="active")
        elif command == "broadcastdeactivated":
            await self._broadcast(chat_id, args, audience="deactivated")
        elif command == "broadcastall":
            await self._broadcast(chat_id, args, audience="all")
        elif command == "cancelinvite":
            await self._cancel_invite(chat_id, args)
        elif command == "tickets":
            await self._tickets(chat_id)
        elif command == "ticket":
            await self._ticket(chat_id, args)
        elif command == "replyticket":
            await self._replyticket(chat_id, args)
        elif command == "archiveticket":
            await self._archiveticket(chat_id, args)
        else:
            await self.telegram.send_message(chat_id, self._help_text(user_id, ta.DEFAULT_USER_LANGUAGE))

    async def _dispatch_user(
        self,
        chat_id: int,
        user_id: int,
        chat_type: str,
        command: str,
        args: str,
        lang: str,
    ) -> None:
        if command not in {"link", "qr", "bundle", "wg", "awg", "support"}:
            await self.telegram.send_message(chat_id, _t(lang, "access_denied"))
            return
        if not await self._ensure_private(chat_id, chat_type, lang):
            return

        if command == "support":
            await self._support(chat_id, user_id, args, lang)
            return

        if args:
            await self.telegram.send_message(chat_id, _t(lang, "access_denied"))
            return

        if not self.access.is_subscription_active(user_id):
            await self.telegram.send_message(
                chat_id,
                _t(lang, "subscription_inactive"),
            )
            return

        if command in {"link", "qr", "bundle"}:
            client = await self._ensure_user_client_enabled(user_id)
            client_id = str(client.get("id") or "").strip()
            if command == "link":
                await self._send_link(chat_id, client_id, lang, include_help_hint=True)
            elif command == "qr":
                await self._send_qr(chat_id, client_id, lang)
            elif command == "bundle":
                await self._send_bundle(chat_id, client_id, lang)
        elif command == "wg":
            await self._send_user_peer_config(chat_id, user_id, lang, protocol="wg")
        elif command == "awg":
            await self._send_user_peer_config(chat_id, user_id, lang, protocol="amneziawg")

    def _help_text(self, user_id: int, lang: str = ta.DEFAULT_USER_LANGUAGE) -> str:
        return self.command_docs.load_effective().render_help(
            is_admin=self.access.is_admin(user_id),
            lang=lang,
        )

    async def _ensure_private(
        self,
        chat_id: int,
        chat_type: str,
        lang: str = ta.DEFAULT_USER_LANGUAGE,
    ) -> bool:
        if chat_type == "private":
            return True
        await self.telegram.send_message(chat_id, _t(lang, "private_chat"))
        return False

    async def _invite_user(self, chat_id: int, invited_by: int, args: str, lang: str) -> None:
        target = _parse_invite_target(args)
        if target is None:
            message = (
                "Usage: /invite <@username or +phone or telegram-user-id>\nFor example: /invite @pupkin or /invite 1111111"
                if self.access.is_admin(invited_by)
                else _t(lang, "invite_usage")
            )
            await self.telegram.send_message(chat_id, message)
            return

        invite = self.access.create_invite(created_by=invited_by, **target)
        await self.telegram.send_message(
            chat_id,
            _format_created_invite(
                invite,
                self._invite_link(invite["token"]),
                ta.DEFAULT_USER_LANGUAGE if self.access.is_admin(invited_by) else lang,
            ),
        )

    async def _language(
        self,
        chat_id: int,
        user_id: int,
        args: str,
        from_user: dict[str, Any],
        lang: str,
    ) -> None:
        if self.access.is_admin(user_id):
            await self.telegram.send_message(chat_id, "Language selection is only used for regular users.")
            return
        requested = ta.normalize_user_language(args)
        if requested:
            self.access.update_user_language(
                user_id,
                preferred_language=requested,
                telegram_language_code=_telegram_language_code(from_user),
                mark_prompted=True,
            )
            await self.telegram.send_message(chat_id, _t(requested, "language_set"))
            return
        self.access.update_user_language(
            user_id,
            preferred_language=lang,
            telegram_language_code=_telegram_language_code(from_user),
            mark_prompted=True,
        )
        await self.telegram.send_message(
            chat_id,
            _t(lang, "language_usage"),
            reply_markup=_language_reply_markup(),
        )

    async def _accept_invite(
        self,
        chat_id: int,
        user_id: int,
        chat_type: str,
        token: str,
        from_user: dict[str, Any],
        respond_to_user: bool = True,
        lang: str | None = None,
    ) -> None:
        if chat_type != "private":
            if respond_to_user:
                await self._ensure_private(chat_id, chat_type, lang or self._user_lang(user_id, from_user))
            return

        invite = self.access.invite_for_token(token)
        if not invite:
            if respond_to_user and self.access.is_known_user(user_id):
                await self.telegram.send_message(
                    chat_id,
                    _t(lang or self._user_lang(user_id, from_user), "invite_unavailable"),
                )
            return

        invite_valid, invite_reason = self.access.validate_invite(invite)
        opener_valid, opener_reason = self._validate_invite_claim(invite, user_id, from_user)
        if self.access.is_admin(user_id):
            reason = opener_reason if invite_valid else invite_reason
            await self.telegram.send_message(
                chat_id,
                _format_invite_admin_check(
                    invite=invite,
                    valid=invite_valid and opener_valid,
                    reason=reason,
                ),
            )
            return

        if self._invite_is_already_accepted_by_user(invite, user_id):
            lang = await self._ensure_user_language(chat_id, user_id, from_user)
            record = self.access.user_record(user_id) or {}
            await self.telegram.send_message(
                chat_id,
                _t(
                    lang,
                    "invite_already_active",
                    expires_at=self._access_expires_at(record),
                ),
            )
            return

        if not invite_valid:
            if respond_to_user and self.access.is_known_user(user_id):
                await self.telegram.send_message(
                    chat_id,
                    _t(lang or self._user_lang(user_id, from_user), "invite_unavailable"),
                )
            return

        if not opener_valid:
            claim = self.access.create_invite_claim(
                invite_id=str(invite.get("id") or ""),
                claimant_tg_id=user_id,
                claimant_username=_profile_username(from_user),
            )
            await self._notify_admins(
                _format_invite_claim(
                    invite=invite,
                    claim=claim,
                    reason=opener_reason,
                ),
                reply_markup=_invite_claim_reply_markup(str(claim.get("id") or "")),
            )
            return

        result = await self._provision_invite_access(
            invite=invite,
            token=token,
            user_id=user_id,
            from_user=from_user,
        )
        lang = await self._ensure_user_language(chat_id, user_id, from_user)
        user = result["user"]
        await self.telegram.send_message(
            chat_id,
            _t(
                lang,
                "invite_accepted",
                expires_at=user.get("trial_expires_at", ""),
            ),
        )
        await self._notify_invite_creator_activated(
            invite=invite,
            activated_user_id=user_id,
            activated_username=_profile_username(from_user),
            expires_at=self._access_expires_at(user),
        )

    async def _provision_invite_access(
        self,
        invite: dict[str, Any],
        token: str,
        user_id: int,
        from_user: dict[str, Any] | None = None,
        claim_id: str | None = None,
        approved_by: int | None = None,
    ) -> dict[str, Any]:
        if from_user:
            self.access.update_user_profile(
                user_id,
                from_user,
                invited_by=invite.get("created_by") if isinstance(invite.get("created_by"), int) else None,
            )
        client_id = await self._client_id_for_invite_user(user_id)
        result = self.access.accept_invite(
            token=token,
            user_id=user_id,
            claim_id=claim_id,
            approved_by=approved_by,
        )
        self.access.bind_client(
            user_id,
            client_id,
            invited_by=invite.get("created_by") if isinstance(invite.get("created_by"), int) else None,
        )
        return result

    async def _client_id_for_invite_user(self, user_id: int) -> str:
        client_id = self.access.client_for_user(user_id)
        if client_id:
            try:
                client = await self.panel.get_client(client_id)
            except PanelApiError:
                pass
            else:
                await self._sync_client_name_if_needed(user_id, client)
                await self.panel.set_client_enabled(client_id, enabled=True)
                return client_id

        client = await self.panel.create_client(name=self._desired_client_name(user_id))
        return str(client["id"])

    async def _handle_callback_query(self, query: dict[str, Any]) -> None:
        from_user = query.get("from") or {}
        user_id = from_user.get("id")
        if isinstance(user_id, int) and self.access.is_known_user(user_id):
            await self._refresh_known_user_profile(user_id, from_user)
        data = str(query.get("data") or "")
        menu_open_match = MENU_OPEN_CALLBACK_RE.fullmatch(data)
        if menu_open_match:
            if isinstance(user_id, int) and self.access.is_known_user(user_id):
                message = query.get("message") or {}
                chat = message.get("chat") or {}
                chat_id = chat.get("id") if isinstance(chat, dict) else None
                if not isinstance(chat_id, int):
                    chat_id = user_id
                await self._open_menu_screen(
                    chat_id,
                    user_id,
                    screen_id=menu_open_match.group("screen_id"),
                    lang=self._user_lang(user_id, from_user),
                    callback_id=str(query.get("id") or ""),
                )
            return
        menu_tap_match = MENU_TAP_CALLBACK_RE.fullmatch(data)
        if menu_tap_match:
            if isinstance(user_id, int) and self.access.is_known_user(user_id):
                message = query.get("message") or {}
                chat = message.get("chat") or {}
                chat_id = chat.get("id") if isinstance(chat, dict) else None
                if not isinstance(chat_id, int):
                    chat_id = user_id
                lang = self._user_lang(user_id, from_user)
                parsed = self.command_docs.load_effective()
                item = parsed.menu_item_by_id(
                    menu_tap_match.group("screen_id"),
                    menu_tap_match.group("item_id"),
                    lang,
                )
                callback_id = str(query.get("id") or "")
                if item is None:
                    if callback_id:
                        await self.telegram.answer_callback_query(
                            callback_id,
                            text="Unsupported action.",
                            show_alert=True,
                        )
                    return
                await self._handle_menu_item_action(
                    chat_id,
                    user_id,
                    "private",
                    item,
                    lang=lang,
                    from_user=from_user,
                    callback_id=callback_id,
                )
            return
        language_match = LANGUAGE_CALLBACK_RE.fullmatch(data)
        if language_match:
            if isinstance(user_id, int):
                await self._handle_language_callback(query, user_id, language_match.group("language"))
            return
        pay_match = PAY_MONTHS_CALLBACK_RE.fullmatch(data)
        if pay_match:
            if isinstance(user_id, int):
                await self._handle_pay_months_callback(
                    query,
                    user_id=user_id,
                    target_user_id=int(pay_match.group("user_id")),
                    months=int(pay_match.group("months")),
                )
            return

        if not isinstance(user_id, int) or not self.access.is_admin(user_id):
            return

        callback_id = str(query.get("id") or "")
        match = INVITE_CLAIM_CALLBACK_RE.fullmatch(data)
        if not match:
            if callback_id:
                await self.telegram.answer_callback_query(callback_id, text="Unsupported action.")
            return

        message = query.get("message") or {}
        chat = message.get("chat") or {}
        chat_id = chat.get("id") if isinstance(chat, dict) else None
        if not isinstance(chat_id, int):
            chat_id = user_id

        action = match.group("action")
        claim_id = match.group("claim_id")
        try:
            if action == "approve":
                await self._approve_invite_claim(chat_id, user_id, claim_id)
                if callback_id:
                    await self.telegram.answer_callback_query(callback_id, text="Invite claim approved.")
            else:
                claim = self.access.reject_invite_claim(claim_id, decided_by=user_id)
                await self.telegram.send_message(chat_id, _format_invite_claim_decision(claim, "rejected"))
                if callback_id:
                    await self.telegram.answer_callback_query(callback_id, text="Invite claim rejected.")
        except PanelApiError as exc:
            logger.warning("Panel API invite claim callback failed: %s", exc)
            if callback_id:
                await self.telegram.answer_callback_query(callback_id, text="Panel API error.", show_alert=True)
            await self.telegram.send_message(chat_id, f"Panel API error: {exc}")
        except Exception as exc:
            logger.warning("Invite claim callback failed: %s", exc)
            if callback_id:
                await self.telegram.answer_callback_query(callback_id, text="Invite claim error.", show_alert=True)
            await self.telegram.send_message(chat_id, f"Invite claim error: {exc}")

    async def _approve_invite_claim(self, chat_id: int, admin_user_id: int, claim_id: str) -> None:
        claim = self.access.invite_claim_for_id(claim_id)
        if not claim:
            raise ValueError("Invite claim was not found")
        if claim.get("status") != ta.INVITE_CLAIM_STATUS_PENDING:
            raise ValueError("Invite claim is not pending")

        invite_id = str(claim.get("invite_id") or "")
        invite = self.access.invite_for_id(invite_id)
        if not invite:
            raise ValueError("Invite was not found")
        valid, reason = self.access.validate_invite(invite)
        if not valid:
            raise ValueError(reason)

        claimant_tg_id = claim.get("claimant_tg_id")
        if not isinstance(claimant_tg_id, int) or claimant_tg_id <= 0:
            raise ValueError("Invite claim has no Telegram user id")
        token = str(invite.get("token") or "")
        if not token:
            raise ValueError("Invite token is missing")

        result = await self._provision_invite_access(
            invite=invite,
            token=token,
            user_id=claimant_tg_id,
            claim_id=claim_id,
            approved_by=admin_user_id,
        )
        claimant_lang = self.access.preferred_language_for_user(claimant_tg_id)
        await self.telegram.send_message(
            claimant_tg_id,
            _t(
                claimant_lang,
                "invite_accepted",
                expires_at=self._access_expires_at(result["user"]),
            ),
        )
        await self._notify_invite_creator_activated(
            invite=invite,
            activated_user_id=claimant_tg_id,
            activated_username=str(claim.get("claimant_username") or "").strip(),
            expires_at=self._access_expires_at(result["user"]),
        )
        approved = self.access.invite_claim_for_id(claim_id) or claim
        await self.telegram.send_message(chat_id, _format_invite_claim_decision(approved, "approved"))

    async def _handle_language_callback(
        self,
        query: dict[str, Any],
        user_id: int,
        language: str,
    ) -> None:
        if not self._is_regular_user(user_id):
            return

        callback_id = str(query.get("id") or "")
        message = query.get("message") or {}
        chat = message.get("chat") or {}
        chat_id = chat.get("id") if isinstance(chat, dict) else None
        if not isinstance(chat_id, int):
            chat_id = user_id

        from_user = query.get("from") or {}
        self.access.update_user_language(
            user_id,
            preferred_language=language,
            telegram_language_code=_telegram_language_code(from_user),
            mark_prompted=True,
        )
        confirmation = _t(language, "language_set")
        if callback_id:
            await self.telegram.answer_callback_query(callback_id, text=confirmation)
        await self.telegram.send_message(chat_id, confirmation)

    async def _handle_pay_months_callback(
        self,
        query: dict[str, Any],
        user_id: int,
        target_user_id: int,
        months: int,
    ) -> None:
        callback_id = str(query.get("id") or "")
        message = query.get("message") or {}
        chat = message.get("chat") or {}
        chat_id = chat.get("id") if isinstance(chat, dict) else None
        if not isinstance(chat_id, int):
            chat_id = user_id

        lang = self._user_lang(user_id, query.get("from") or {})
        if user_id != target_user_id or not self.access.is_known_user(user_id):
            if callback_id:
                await self.telegram.answer_callback_query(
                    callback_id,
                    text=_t(lang, "payment_access_denied"),
                    show_alert=True,
                )
            return

        quote = self.access.payment_quote_for_user(user_id, months=months)
        if quote["amount_stars"] == 0:
            if quote["bonus_spent_stars"] > 0:
                self.access.spend_bonus(user_id, int(quote["bonus_spent_stars"]))
            subscription = await self._activate_paid_access(
                user_id,
                days=int(quote["period_days"]),
            )
            lines = self._payment_success_lines(
                lang=lang,
                expires_at=str(subscription.get("subscription_expires_at", "")),
                bonus_spent_stars=int(quote["bonus_spent_stars"]),
                referral_bonus=False,
                discount_only=quote["base_amount_stars"] == 0,
                activated_without_invoice=True,
            )
            if callback_id:
                await self.telegram.answer_callback_query(
                    callback_id,
                    text=_t(
                        lang,
                        "subscription_active_until",
                        expires_at=subscription.get("subscription_expires_at", ""),
                    ),
                )
            await self.telegram.send_message(chat_id, "\n".join(lines))
            return

        payment = self.access.create_payment(
            user_id,
            amount_stars=int(quote["amount_stars"]),
            base_amount_stars=int(quote["base_amount_stars"]),
            bonus_spent_stars=int(quote["bonus_spent_stars"]),
            months=int(quote["months"]),
            period_days=int(quote["period_days"]),
            personal_discount_percent=int(quote["personal_discount_percent"]),
            package_discount_percent=int(quote["package_discount_percent"]),
            total_discount_percent=int(quote["total_discount_percent"]),
        )
        label = _t(
            lang,
            "invoice_label",
            months=quote["months"],
            days=quote["period_days"],
        )
        if quote["bonus_spent_stars"]:
            label = _t(
                lang,
                "invoice_label_bonus",
                months=quote["months"],
                days=quote["period_days"],
                stars=quote["bonus_spent_stars"],
            )
        await self.telegram.send_invoice(
            chat_id=chat_id,
            title=_t(lang, "invoice_title"),
            description=_t(
                lang,
                "invoice_description",
                months=quote["months"],
                days=quote["period_days"],
            ),
            payload=payment["payload"],
            amount_stars=int(quote["amount_stars"]),
            label=label,
        )
        if callback_id:
            await self.telegram.answer_callback_query(callback_id, text=_t(lang, "invoice_created"))

    def _validate_invite_claim(
        self,
        invite: dict[str, Any],
        user_id: int,
        from_user: dict[str, Any],
    ) -> tuple[bool, str]:
        if invite.get("status") != ta.INVITE_STATUS_PENDING:
            return False, f"invite status is {invite.get('status', 'unknown')}"

        target_user_id = invite.get("target_user_id")
        if isinstance(target_user_id, int) and target_user_id > 0:
            if target_user_id == user_id:
                return True, "telegram user id matches"
            return False, f"expected user id {target_user_id}, got {user_id}"

        target_username = str(invite.get("target_username_hint") or "").strip().lower()
        if target_username:
            opener_username = _profile_username(from_user)
            if opener_username and opener_username == target_username:
                return True, f"username matches {target_username}"
            return False, f"expected username {target_username}, got {opener_username or 'no username'}"

        target_phone = str(invite.get("target_phone_hint") or "").strip()
        if target_phone:
            return False, f"phone-only invite {target_phone} cannot be auto-verified by /start"

        return False, "invite has no verifiable target"

    def _invite_is_already_accepted_by_user(self, invite: dict[str, Any], user_id: int) -> bool:
        return (
            invite.get("status") == ta.INVITE_STATUS_ACCEPTED
            and invite.get("target_user_id") == user_id
        )

    def _access_expires_at(self, record: dict[str, Any]) -> str:
        return str(
            record.get("trial_expires_at")
            or record.get("subscription_expires_at")
            or "-"
        )

    async def _notify_invite_creator_activated(
        self,
        invite: dict[str, Any],
        activated_user_id: int,
        activated_username: str,
        expires_at: str,
    ) -> None:
        creator_id = invite.get("created_by")
        if not isinstance(creator_id, int) or creator_id <= 0 or creator_id == activated_user_id:
            return

        lang = (
            ta.DEFAULT_USER_LANGUAGE
            if self.access.is_admin(creator_id)
            else self.access.preferred_language_for_user(creator_id)
        )
        user_label = str(activated_user_id)
        username = activated_username.strip()
        if username:
            user_label = f"{user_label} ({username})"

        try:
            await self.telegram.send_message(
                creator_id,
                _t(
                    lang,
                    "invite_activated_creator",
                    invite_id=invite.get("id", ""),
                    user_label=user_label,
                    expires_at=expires_at,
                ),
            )
        except Exception as exc:
            logger.warning("Failed to notify invite creator user_id=%s: %s", creator_id, exc)

    async def _notify_admins(
        self,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> None:
        for admin_user_id in sorted(self.access.admin_user_ids):
            try:
                await self.telegram.send_message(admin_user_id, text, reply_markup=reply_markup)
            except Exception as exc:
                logger.warning("Failed to notify admin user_id=%s: %s", admin_user_id, exc)

    async def _notify_admins_support_event(self, ticket: dict[str, Any]) -> None:
        summary = self.access.support_summary()
        await self._notify_admins(
            _format_support_admin_notification(
                ticket=ticket,
                summary=summary,
                user_label=self.access.display_name_for_user(int(ticket.get("user_id") or 0)),
            )
        )

    def _invite_link(self, token: str) -> str:
        if self.bot_username:
            return f"https://t.me/{self.bot_username}?start={token}"
        return f"/start {token}"

    async def _capture_support_message(
        self,
        chat_id: int,
        user_id: int,
        text: str,
        lang: str,
    ) -> None:
        ticket = self.access.create_or_append_support_ticket(user_id, text, author="user")
        self.access.clear_support_compose_started(user_id)
        await self.telegram.send_message(
            chat_id,
            _t(
                lang,
                "support_created" if ticket.get("is_new_ticket") else "support_followup",
                ticket_id=ticket.get("ticket_id", ""),
            ),
        )
        await self._notify_admins_support_event(ticket)

    async def _support(self, chat_id: int, user_id: int, args: str, lang: str) -> None:
        message = args.strip()
        if message:
            await self._capture_support_message(chat_id, user_id, message, lang)
            return

        open_ticket_id = ""
        for ticket in self.access.public_support_ticket_records(status=ta.SUPPORT_TICKET_STATUS_OPEN):
            if ticket.get("user_id") == user_id:
                open_ticket_id = str(ticket.get("ticket_id") or "")
                break
        self.access.set_support_compose_started(user_id)
        placeholder = open_ticket_id or ("a new ticket" if lang != "ru" else "новую заявку")
        await self.telegram.send_message(
            chat_id,
            _t(lang, "support_compose_prompt", ticket_id=placeholder),
        )

    async def _ensure_user_peer_enabled(self, user_id: int) -> dict[str, Any]:
        desired_name = self.access.desired_client_name_for_user(
            user_id,
            default_name=f"Telegram {user_id}",
        )
        public_key = self.access.peer_for_user(user_id)
        if public_key:
            try:
                peer = await self.panel.get_peer(public_key)
                if str(peer.get("name") or "") != desired_name:
                    peer = await self.panel.update_peer(public_key, desired_name)
                if bool(peer.get("deactivated")):
                    peer = await self.panel.set_peer_enabled(public_key, enabled=True)
                return peer
            except PanelApiError:
                logger.warning("Bound peer %s for user_id=%s was not found, creating a new one", public_key, user_id)

        created = await self.panel.create_peer(desired_name)
        public_key = str(created.get("public_key") or "").strip()
        if not public_key:
            raise PanelApiError("Panel API did not return peer public key")
        self.access.bind_peer(user_id, public_key)
        return created

    async def _send_user_peer_config(
        self,
        chat_id: int,
        user_id: int,
        lang: str,
        protocol: str,
    ) -> None:
        peer = await self._ensure_user_peer_enabled(user_id)
        public_key = str(peer.get("public_key") or "").strip()
        peer_name = str(peer.get("name") or self.access.desired_client_name_for_user(user_id) or user_id)
        if protocol == "wg":
            await self.telegram.send_message(
                chat_id,
                _t(lang, "wg_share_link", name=peer_name),
            )
            conf = await self.panel.get_peer_config(public_key, protocol="wg")
            await self.telegram.send_document(
                chat_id,
                conf,
                caption=_t(lang, "wg_caption", name=peer_name),
            )
            qr = await self.panel.get_peer_qr(public_key, protocol="wg", peer_name=peer_name)
            await self.telegram.send_photo(
                chat_id,
                qr,
                caption=_t(lang, "wg_caption", name=peer_name),
            )
            return

        await self.telegram.send_message(
            chat_id,
            _t(lang, "awg_share_link", name=peer_name),
        )
        conf = await self.panel.get_peer_config(public_key, protocol="amneziawg")
        await self.telegram.send_document(
            chat_id,
            conf,
            caption=_t(lang, "awg_caption", name=peer_name),
        )

    async def _tickets(self, chat_id: int) -> None:
        summary = self.access.support_summary(latest_limit=10)
        open_tickets = self.access.public_support_ticket_records(status=ta.SUPPORT_TICKET_STATUS_OPEN)[:5]
        await self.telegram.send_message(chat_id, _format_support_summary(summary, open_tickets))

    async def _ticket(self, chat_id: int, args: str) -> None:
        ticket_id = _parse_ticket_id(args)
        if not ticket_id:
            await self.telegram.send_message(chat_id, "Usage: /ticket <ticket-id>")
            return
        ticket = self.access.public_support_ticket_detail(ticket_id)
        if ticket.get("status") == ta.SUPPORT_TICKET_STATUS_OPEN:
            self.access.mark_support_ticket_read(ticket_id)
            ticket = self.access.public_support_ticket_detail(ticket_id)
        for chunk in _message_chunks(_format_support_ticket_detail(ticket)):
            await self.telegram.send_message(chat_id, chunk)

    async def _replyticket(self, chat_id: int, args: str) -> None:
        parsed = _parse_ticket_reply_args(args)
        if parsed is None:
            await self.telegram.send_message(chat_id, "Usage: /replyticket <ticket-id> <message>")
            return
        ticket_id, message = parsed
        ticket = self.access.public_support_ticket_detail(ticket_id)
        if ticket.get("status") != ta.SUPPORT_TICKET_STATUS_OPEN:
            await self.telegram.send_message(chat_id, f"Ticket {ticket_id} is archived.")
            return
        user_id = int(ticket.get("user_id") or 0)
        if user_id <= 0:
            raise ValueError("Support ticket user is invalid")
        await self.telegram.send_message(user_id, f"Support reply for {ticket_id}:\n\n{message}")
        self.access.create_or_append_support_ticket(user_id, message, author="admin")
        await self.telegram.send_message(chat_id, f"Reply sent to {ticket_id}.")

    async def _archiveticket(self, chat_id: int, args: str) -> None:
        ticket_id = _parse_ticket_id(args)
        if not ticket_id:
            await self.telegram.send_message(chat_id, "Usage: /archiveticket <ticket-id>")
            return
        ticket = self.access.public_support_ticket_detail(ticket_id)
        self.access.archive_support_ticket(ticket_id)
        user_id = int(ticket.get("user_id") or 0)
        if user_id > 0:
            try:
                user_lang = self.access.preferred_language_for_user(user_id)
                await self.telegram.send_message(
                    user_id,
                    _t(user_lang, "support_closed", ticket_id=ticket_id),
                )
            except Exception as exc:
                logger.warning("Failed to notify user_id=%s about archived support ticket %s: %s", user_id, ticket_id, exc)
        await self.telegram.send_message(chat_id, f"Ticket {ticket_id} archived.")

    def _record_unknown_lead(
        self,
        user_id: int,
        chat_id: int,
        chat_type: str,
        from_user: dict[str, Any],
        message: dict[str, Any],
        text: str,
    ) -> None:
        contact = message.get("contact") or {}
        phone_number = ""
        if isinstance(contact, dict) and contact.get("user_id") == user_id:
            phone_number = str(contact.get("phone_number") or "")
        self.access.record_lead(
            user_id=user_id,
            chat_id=chat_id,
            chat_type=chat_type,
            profile=from_user,
            message_text=text,
            phone_number=phone_number,
        )

    async def _create_client(self, chat_id: int, name: str) -> None:
        if not name:
            await self.telegram.send_message(chat_id, "Usage: /new <client name>")
            return

        client = await self.panel.create_client(name=name)
        share = await self.panel.get_share(client["id"])
        await self.telegram.send_message(chat_id, _format_created_client(client, share))

    async def _create_client_for_user(self, chat_id: int, admin_user_id: int, args: str) -> None:
        parsed = _parse_user_id_and_text(args)
        if parsed is None:
            await self.telegram.send_message(chat_id, "Usage: /newfor <telegram-user-id> <client name>")
            return

        user_id, name = parsed
        existing_client_id = self.access.client_for_user(user_id)
        client: dict[str, Any] | None = None
        reused_existing = False

        if existing_client_id:
            try:
                existing_client = await self.panel.get_client(existing_client_id)
            except PanelApiError:
                existing_client = None
            else:
                # Make repeated /newfor with the same target idempotent. This matters when
                # the client was created successfully but the bot failed while sending the
                # confirmation message and Telegram redelivered the same admin command.
                if str(existing_client.get("name", "")).strip() == name:
                    client = existing_client
                    reused_existing = True
                    await self.panel.set_client_enabled(existing_client_id, enabled=True)

        if client is None:
            client = await self.panel.create_client(name=name)
            self.access.bind_client(user_id, client["id"], invited_by=admin_user_id)

        subscription = self.access.grant_subscription(user_id)
        share = await self.panel.get_share(client["id"])
        prefix = "Client already existed and remains bound to this Telegram user." if reused_existing else ""
        await self.telegram.send_message(
            chat_id,
            "\n".join(
                [
                    line
                    for line in [
                        prefix,
                        _format_created_client(client, share),
                        "",
                        f"Bound to Telegram user: {user_id}",
                        f"Subscription expires at: {subscription.get('subscription_expires_at', '')}",
                    ]
                    if line
                ]
            ),
        )

    async def _list_clients(self, chat_id: int) -> None:
        clients = await self.panel.list_clients()
        if not clients:
            await self.telegram.send_message(chat_id, "No VLESS clients yet.")
            return
        await self.telegram.send_message(chat_id, _format_clients(clients))

    async def _send_link(
        self,
        chat_id: int,
        client_id: str,
        lang: str = ta.DEFAULT_USER_LANGUAGE,
        include_help_hint: bool = False,
    ) -> None:
        if not client_id:
            await self.telegram.send_message(chat_id, _t(lang, "usage_link"))
            return

        share = await self.panel.get_share(client_id)
        text = _format_share_link(share, lang)
        if include_help_hint:
            text = f"{text}\n\n{_t(lang, 'help_hint')}"
        await self.telegram.send_message(chat_id, text)
        raw_share_link = str(share.get("share_link", "")).strip()
        if raw_share_link:
            await self.telegram.send_message(chat_id, raw_share_link)

    async def _send_qr(
        self,
        chat_id: int,
        client_id: str,
        lang: str = ta.DEFAULT_USER_LANGUAGE,
    ) -> None:
        if not client_id:
            await self.telegram.send_message(chat_id, _t(lang, "usage_qr"))
            return

        client = await self.panel.get_client(client_id)
        qr = await self.panel.get_qr(client_id, client_name=client.get("name", "client"))
        await self.telegram.send_photo(
            chat_id,
            qr,
            caption=_t(lang, "qr_caption", name=client.get("name", client_id)),
        )

    async def _send_bundle(
        self,
        chat_id: int,
        client_id: str,
        lang: str = ta.DEFAULT_USER_LANGUAGE,
    ) -> None:
        if not client_id:
            await self.telegram.send_message(chat_id, _t(lang, "usage_bundle"))
            return

        client = await self.panel.get_client(client_id)
        bundle = await self.panel.get_bundle(client_id, client_name=client.get("name", "client"))
        await self.telegram.send_document(
            chat_id,
            bundle,
            caption=_t(lang, "bundle_caption", name=client.get("name", client_id)),
        )

    async def _set_enabled(self, chat_id: int, client_id: str, enabled: bool) -> None:
        if not client_id:
            command = "enable" if enabled else "disable"
            await self.telegram.send_message(chat_id, f"Usage: /{command} <client-id>")
            return

        client = await self.panel.set_client_enabled(client_id, enabled=enabled)
        state = "enabled" if client.get("enabled") else "disabled"
        await self.telegram.send_message(
            chat_id,
            f"Client {client.get('name', client_id)} is {state} and applied.",
        )

    async def _delete_client(self, chat_id: int, client_id: str) -> None:
        if not client_id:
            await self.telegram.send_message(chat_id, "Usage: /delete <client-id>")
            return

        await self.panel.delete_client(client_id)
        await self.telegram.send_message(chat_id, f"Client deleted and applied: {client_id}")

    async def _doctor(self, chat_id: int) -> None:
        doctor = await self.panel.doctor()
        await self.telegram.send_message(chat_id, _format_doctor(doctor))

    async def _status(self, chat_id: int, user_id: int, lang: str = ta.DEFAULT_USER_LANGUAGE) -> None:
        record = self.access.user_record(user_id) or {}
        await self.telegram.send_message(
            chat_id,
            _format_subscription_status(
                user_id=user_id,
                record=record,
                is_admin=self.access.is_admin(user_id),
                is_active=self.access.is_subscription_active(user_id),
                price_stars=self.access.price_for_user(user_id),
                base_price_stars=self.access.subscription_price_stars(),
                discount_percent=self.access.discount_for_user(user_id),
                period_days=self.access.subscription_period_days(),
                max_12m_discount_percent=self.access.subscription_max_12m_discount_percent(),
                lang=lang,
            ),
        )

    async def _pay(self, chat_id: int, user_id: int, lang: str = ta.DEFAULT_USER_LANGUAGE) -> None:
        quotes = [
            self.access.payment_quote_for_user(user_id, months=months)
            for months in ta.ALLOWED_PAYMENT_MONTHS
        ]
        await self.telegram.send_message(
            chat_id,
            _format_pay_selection_message(
                quotes=quotes,
                lang=lang,
                max_12m_discount_percent=self.access.subscription_max_12m_discount_percent(),
            ),
            reply_markup=_pay_months_reply_markup(user_id),
        )

    async def _handle_pre_checkout_query(self, query: dict[str, Any]) -> None:
        query_id = str(query.get("id") or "")
        if not query_id:
            return

        from_user = query.get("from") or {}
        user_id = from_user.get("id")
        payment_payload = str(query.get("invoice_payload") or "")
        payment = self.access.payment_for_payload(payment_payload)
        lang = self._user_lang(user_id, from_user) if isinstance(user_id, int) else ta.DEFAULT_USER_LANGUAGE

        error = ""
        if not isinstance(user_id, int) or not self.access.is_known_user(user_id):
            error = _t(lang, "payment_access_denied")
        elif not payment:
            error = _t(lang, "payment_request_not_found")
        elif payment.get("status") != "pending":
            error = _t(lang, "payment_request_not_active")
        elif payment.get("user_id") != user_id:
            error = _t(lang, "payment_belongs_other")
        elif query.get("currency") != ta.PAYMENT_CURRENCY:
            error = _t(lang, "unsupported_payment_currency")
        elif query.get("total_amount") != payment.get("amount_stars"):
            error = _t(lang, "payment_amount_changed")

        if error:
            await self.telegram.answer_pre_checkout_query(query_id, ok=False, error_message=error)
            return

        await self.telegram.answer_pre_checkout_query(query_id, ok=True)

    async def _handle_successful_payment(
        self,
        chat_id: int,
        user_id: int,
        successful_payment: dict[str, Any],
        lang: str = ta.DEFAULT_USER_LANGUAGE,
    ) -> None:
        payment_payload = str(successful_payment.get("invoice_payload") or "")
        payment = self.access.payment_for_payload(payment_payload)
        if not payment:
            await self.telegram.send_message(chat_id, _t(lang, "payment_order_not_found"))
            return
        if payment.get("status") == "completed":
            await self.telegram.send_message(chat_id, _t(lang, "payment_already_processed"))
            return
        if (
            payment.get("user_id") != user_id
            or successful_payment.get("currency") != ta.PAYMENT_CURRENCY
            or successful_payment.get("total_amount") != payment.get("amount_stars")
        ):
            await self.telegram.send_message(chat_id, _t(lang, "payment_validation_failed"))
            return

        self.access.complete_payment(
            payment_payload,
            telegram_payment_charge_id=str(successful_payment.get("telegram_payment_charge_id") or ""),
        )
        referral_bonus = self.access.award_referral_bonus_for_payment(payment_payload)
        subscription = await self._activate_paid_access(
            user_id,
            days=int(payment.get("period_days") or self.access.subscription_period_days()),
        )
        lines = self._payment_success_lines(
            lang=lang,
            expires_at=str(subscription.get("subscription_expires_at", "")),
            bonus_spent_stars=int(payment.get("bonus_spent_stars") or 0),
            referral_bonus=bool(referral_bonus),
            discount_only=False,
            activated_without_invoice=False,
        )
        await self.telegram.send_message(
            chat_id,
            "\n".join(lines),
        )

    async def _activate_paid_access(self, user_id: int, days: int | None = None) -> dict[str, Any]:
        await self._ensure_user_client_enabled(user_id, invited_by=user_id)
        return self.access.grant_subscription(user_id, days=days)

    async def _refresh_known_user_profile(
        self,
        user_id: int,
        from_user: dict[str, Any] | None,
    ) -> None:
        if not self._is_regular_user(user_id):
            return
        previous_display_name = self.access.display_name_for_user(user_id)
        updated = self.access.update_user_profile(user_id, from_user)
        client_id = str(updated.get("client_id") or "").strip()
        current_display_name = str(updated.get("display_name") or "").strip()
        if not client_id or not current_display_name or current_display_name == previous_display_name:
            return
        try:
            client = await self.panel.get_client(client_id)
        except PanelApiError:
            return
        await self._sync_client_name_if_needed(user_id, client)

    def _desired_client_name(self, user_id: int, existing_name: str = "") -> str:
        return self.access.desired_client_name_for_user(
            user_id,
            existing_name=existing_name,
            default_name=f"Telegram {user_id}",
        )

    async def _sync_client_name_if_needed(
        self,
        user_id: int,
        client: dict[str, Any],
    ) -> dict[str, Any]:
        client_id = str(client.get("id") or "")
        current_name = str(client.get("name") or "")
        desired_name = self._desired_client_name(user_id, existing_name=current_name)
        if not client_id or desired_name == current_name:
            return client
        return await self.panel.update_client(
            client_id,
            desired_name,
            email=client.get("email"),
        )

    async def _ensure_user_client_enabled(
        self,
        user_id: int,
        invited_by: int | None = None,
    ) -> dict[str, Any]:
        client_id = self.access.client_for_user(user_id)
        if client_id:
            try:
                client = await self.panel.get_client(client_id)
            except PanelApiError:
                client = await self.panel.create_client(name=self._desired_client_name(user_id))
                self.access.bind_client(user_id, client["id"], invited_by=invited_by)
            else:
                client = await self._sync_client_name_if_needed(user_id, client)
                client = await self.panel.set_client_enabled(client_id, enabled=True)
        else:
            client = await self.panel.create_client(name=self._desired_client_name(user_id))
            self.access.bind_client(user_id, client["id"], invited_by=invited_by)
        return client

    async def _price(self, chat_id: int, args: str) -> None:
        if not args:
            await self.telegram.send_message(
                chat_id,
                (
                    f"Monthly subscription price: {self.access.subscription_price_stars()} Stars "
                    f"for {self.access.subscription_period_days()} days.\n"
                    f"Max 12-month package discount: {self.access.subscription_max_12m_discount_percent()}%."
                ),
            )
            return

        price = _parse_non_negative_int(args)
        if price is None:
            await self.telegram.send_message(chat_id, "Usage: /price <stars>")
            return
        self.access.set_subscription_price_stars(price)
        await self.telegram.send_message(chat_id, f"Subscription price set to {price} Stars.")

    async def _discount(self, chat_id: int, args: str) -> None:
        parts = args.split(maxsplit=1)
        if len(parts) != 2:
            await self.telegram.send_message(chat_id, "Usage: /discount <telegram-user-id> <percent|clear>")
            return

        user_id = _parse_user_id(parts[0])
        if user_id is None:
            await self.telegram.send_message(chat_id, "Usage: /discount <telegram-user-id> <percent|clear>")
            return

        if parts[1].strip().lower() == "clear":
            self.access.clear_discount_percent(user_id)
            await self.telegram.send_message(chat_id, f"Discount cleared for user {user_id}.")
            return

        percent = _parse_non_negative_int(parts[1])
        if percent is None or percent > 100:
            await self.telegram.send_message(chat_id, "Discount percent must be 0..100.")
            return

        self.access.set_discount_percent(user_id, percent)
        await self.telegram.send_message(chat_id, f"Discount for user {user_id} set to {percent}%.")

    async def _expires(self, chat_id: int, args: str) -> None:
        parsed = _parse_user_id_and_text(args)
        if parsed is None:
            await self.telegram.send_message(chat_id, "Usage: /expires <telegram-user-id> <YYYY-MM-DD>")
            return

        user_id, raw_date = parsed
        expires_at = _parse_moscow_expiry_date(raw_date)
        if expires_at is None:
            await self.telegram.send_message(chat_id, "Usage: /expires <telegram-user-id> <YYYY-MM-DD>")
            return

        record = self.access.set_subscription_expires_at(user_id, expires_at)
        if self.access.is_subscription_active(user_id) and self.access.client_for_user(user_id):
            await self.panel.set_client_enabled(self.access.client_for_user(user_id) or "", enabled=True)
        await self.telegram.send_message(
            chat_id,
            f"Subscription for user {user_id} expires at: {record.get('subscription_expires_at', '')}",
        )

    async def _grant(self, chat_id: int, args: str) -> None:
        parts = args.split(maxsplit=1)
        if not parts or not parts[0]:
            await self.telegram.send_message(chat_id, "Usage: /grant <telegram-user-id> [days]")
            return

        user_id = _parse_user_id(parts[0])
        days = self.access.subscription_period_days()
        if user_id is None:
            await self.telegram.send_message(chat_id, "Usage: /grant <telegram-user-id> [days]")
            return
        if len(parts) == 2:
            parsed_days = _parse_positive_int(parts[1])
            if parsed_days is None:
                await self.telegram.send_message(chat_id, "Usage: /grant <telegram-user-id> [days]")
                return
            days = parsed_days

        subscription = await self._activate_paid_access(user_id, days=days)
        await self.telegram.send_message(
            chat_id,
            f"Granted user {user_id} paid access until {subscription.get('subscription_expires_at', '')}.",
        )

    async def _revoke(self, chat_id: int, args: str) -> None:
        user_id = _parse_user_id(args)
        if user_id is None:
            await self.telegram.send_message(chat_id, "Usage: /revoke <telegram-user-id>")
            return

        client_id = self.access.client_for_user(user_id)
        if client_id:
            await self.panel.set_client_enabled(client_id, enabled=False)
        self.access.revoke_subscription(user_id)
        await self.telegram.send_message(chat_id, f"User {user_id} subscription revoked.")

    async def _list_invites(self, chat_id: int) -> None:
        invites = self.access.public_invite_records()
        await self.telegram.send_message(chat_id, _format_invites(invites))

    async def _list_leads(self, chat_id: int) -> None:
        leads = self.access.public_lead_records()
        await self.telegram.send_message(chat_id, _format_leads(leads))

    async def _trial(self, chat_id: int, args: str) -> None:
        if not args:
            await self.telegram.send_message(
                chat_id,
                f"Trial period: {self.access.trial_period_days()} days.",
            )
            return
        days = _parse_positive_int(args)
        if days is None:
            await self.telegram.send_message(chat_id, "Usage: /trial <days>")
            return
        self.access.set_trial_period_days(days)
        await self.telegram.send_message(chat_id, f"Trial period set to {days} days.")

    async def _bonus(self, chat_id: int, args: str) -> None:
        user_id = _parse_user_id(args)
        if user_id is None:
            await self.telegram.send_message(chat_id, "Usage: /bonus <telegram-user-id>")
            return
        ledger = self.access.public_bonus_ledger_records(user_id=user_id, limit=5)
        await self.telegram.send_message(
            chat_id,
            _format_bonus(user_id, self.access.bonus_balance_for_user(user_id), ledger),
        )

    async def _broadcast(self, chat_id: int, args: str, audience: str) -> None:
        message = args.strip()
        if not message:
            await self.telegram.send_message(chat_id, f"Usage: /broadcast{audience} <message>")
            return

        recipient_ids = self._broadcast_recipient_ids(audience)
        delivered = 0
        failed: list[int] = []
        for recipient_id in recipient_ids:
            try:
                await self.telegram.send_message(recipient_id, message)
                delivered += 1
            except Exception as exc:
                failed.append(recipient_id)
                logger.warning(
                    "Broadcast delivery failed audience=%s user_id=%s: %s",
                    audience,
                    recipient_id,
                    exc,
                )

        summary_lines = [
            f"Broadcast audience: {audience}",
            f"Selected recipients: {len(recipient_ids)}",
            f"Delivered: {delivered}",
            f"Failed: {len(failed)}",
        ]
        if failed:
            summary_lines.append(
                "Failed user ids: " + ", ".join(str(user_id) for user_id in failed[:20])
            )
        await self.telegram.send_message(chat_id, "\n".join(summary_lines))

    def _broadcast_recipient_ids(self, audience: str) -> list[int]:
        recipient_ids: list[int] = []
        for user_id in sorted(self.access.all_user_records()):
            if self.access.is_admin(user_id):
                continue
            is_active = self.access.is_subscription_active(user_id)
            if audience == "active" and not is_active:
                continue
            if audience == "deactivated" and is_active:
                continue
            recipient_ids.append(user_id)
        return recipient_ids

    async def _cancel_invite(self, chat_id: int, args: str) -> None:
        invite_id = args.strip()
        if not invite_id:
            await self.telegram.send_message(chat_id, "Usage: /cancelinvite <invite-id>")
            return
        invite = self.access.cancel_invite(invite_id)
        await self.telegram.send_message(chat_id, f"Invite cancelled: {invite.get('id', invite_id)}")

    async def run_subscription_maintenance(self) -> None:
        while True:
            try:
                await self.run_subscription_maintenance_once()
            except Exception as exc:
                logger.exception("Telegram subscription maintenance failed: %s", exc)
            await asyncio.sleep(self.subscription_check_interval_seconds)

    async def run_subscription_maintenance_once(self, now: datetime | None = None) -> None:
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        for user_id, record in self.access.all_user_records().items():
            try:
                if record.get("account_type") != "paid":
                    continue
                expires_at = ta.parse_timestamp(record.get("subscription_expires_at"))
                if expires_at is None:
                    continue
                if expires_at <= now:
                    await self._deactivate_expired_user(user_id)
                    continue
                await self._maybe_send_expiry_notification(user_id, record, expires_at, now)
            except Exception as exc:
                logger.warning("Subscription maintenance failed for user_id=%s: %s", user_id, exc)

    async def _deactivate_expired_user(self, user_id: int) -> None:
        client_id = self.access.client_for_user(user_id)
        if client_id:
            await self.panel.set_client_enabled(client_id, enabled=False)
        self.access.revoke_subscription(user_id)
        try:
            lang = self.access.preferred_language_for_user(user_id)
            await self.telegram.send_message(
                user_id,
                _t(lang, "subscription_expired"),
            )
        except Exception as exc:
            logger.warning("Failed to send expiry message to user_id=%s: %s", user_id, exc)

    async def _maybe_send_expiry_notification(
        self,
        user_id: int,
        record: dict[str, Any],
        expires_at: datetime,
        now: datetime,
    ) -> None:
        days_left = max(0, (expires_at.date() - now.date()).days)
        if days_left not in self.subscription_notify_days:
            return

        notification_key = f"{expires_at.date().isoformat()}:{days_left}"
        sent = record.get("last_expiry_notifications")
        if not isinstance(sent, list):
            sent = []
        if notification_key in sent:
            return

        lang = self.access.preferred_language_for_user(user_id)
        if days_left == 0:
            message = _t(lang, "subscription_expires_today")
        elif days_left == 1:
            message = _t(lang, "subscription_expires_one_day")
        else:
            message = _t(lang, "subscription_expires_days", days=days_left)

        await self.telegram.send_message(user_id, message)
        self.access.mark_expiry_notification_sent(user_id, notification_key)

    async def _bind_client(self, chat_id: int, admin_user_id: int, args: str) -> None:
        parsed = _parse_user_id_and_text(args)
        if parsed is None:
            await self.telegram.send_message(chat_id, "Usage: /bind <telegram-user-id> <client-id>")
            return

        user_id, client_id = parsed
        await self.panel.get_client(client_id)
        self.access.bind_client(user_id, client_id, invited_by=admin_user_id)
        await self.telegram.send_message(chat_id, f"User {user_id} bound to client {client_id}.")

    def _payment_success_lines(
        self,
        lang: str,
        expires_at: str,
        bonus_spent_stars: int,
        referral_bonus: bool,
        discount_only: bool,
        activated_without_invoice: bool,
    ) -> list[str]:
        lines = []
        if activated_without_invoice and bonus_spent_stars > 0:
            lines.append(_t(lang, "bonus_subscription"))
        elif discount_only:
            lines.append(_t(lang, "discount_subscription"))
        else:
            lines.append(_t(lang, "payment_received"))
        if bonus_spent_stars > 0:
            lines.append(_t(lang, "bonus_spent", stars=bonus_spent_stars))
        lines.append(_t(lang, "subscription_active_until", expires_at=expires_at))
        if referral_bonus:
            lines.append(_t(lang, "referral_bonus_credited"))
        lines.append(_t(lang, "use_link"))
        return lines

def _format_created_client(client: dict[str, Any], share: dict[str, Any]) -> str:
    lines = [
        "Created and applied VLESS client:",
        f"Name: {client.get('name', '')}",
        f"ID: {client.get('id', '')}",
        f"Email: {client.get('email', '')}",
        f"Enabled: {client.get('enabled', False)}",
        "",
        str(share.get("share_link", "")),
    ]
    warnings = share.get("settings_warnings") or []
    errors = share.get("settings_errors") or []
    if warnings:
        lines.extend(["", "Warnings:", *[f"- {item}" for item in warnings]])
    if errors:
        lines.extend(["", "Settings errors:", *[f"- {item}" for item in errors]])
    return "\n".join(lines)


def _format_clients(clients: list[dict[str, Any]]) -> str:
    lines = ["VLESS clients:"]
    for client in clients:
        state = "enabled" if client.get("enabled") else "disabled"
        lines.append(
            f"- {client.get('name', '')} | {state} | {client.get('email', '')} | {client.get('id', '')}"
        )
    return "\n".join(lines)


def _format_created_invite(
    invite: dict[str, Any],
    link: str,
    lang: str = ta.DEFAULT_USER_LANGUAGE,
) -> str:
    target = (
        invite.get("target_username_hint")
        or invite.get("target_phone_hint")
        or invite.get("target_user_id")
        or "unknown target"
    )
    text = _t(
        lang,
        "invite_created",
        invite_id=invite.get("id", ""),
        target=target,
        trial_days=invite.get("trial_days", ""),
        link=link,
    )
    if link.startswith("/start "):
        text += _t(lang, "invite_created_username_hint")
    return text


def _format_invites(invites: list[dict[str, Any]]) -> str:
    if not invites:
        return "No invites yet."
    lines = ["Invites:"]
    for invite in invites[:30]:
        target = (
            invite.get("target_username_hint")
            or invite.get("target_phone_hint")
            or invite.get("target_user_id")
            or "unknown"
        )
        lines.append(
            " | ".join(
                [
                    f"- {invite.get('id', '')}",
                    str(invite.get("status", "")),
                    f"target {target}",
                    f"by {invite.get('created_by', '')}",
                    f"trial {invite.get('trial_days', '')}d",
                    f"accepted {invite.get('accepted_at') or '-'}",
                ]
            )
        )
    return "\n".join(lines)


def _format_invite_admin_check(invite: dict[str, Any], valid: bool, reason: str) -> str:
    lines = [
        "Invite check only. No changes applied.",
        f"Invite ID: {invite.get('id', '')}",
        f"Status: {invite.get('status', '')}",
        f"Target: {_invite_target_label(invite)}",
        f"Created by: {invite.get('created_by', '')}",
        f"Trial days: {invite.get('trial_days', '')}",
        f"Accepted at: {invite.get('accepted_at') or '-'}",
        f"Current opener would match: {valid}",
        f"Reason: {reason}",
    ]
    return "\n".join(lines)


def _invite_claim_reply_markup(claim_id: str) -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [
                {
                    "text": "Approve",
                    "callback_data": f"invite_claim:approve:{claim_id}",
                },
                {
                    "text": "Reject",
                    "callback_data": f"invite_claim:reject:{claim_id}",
                },
            ]
        ]
    }


def _format_invite_claim(
    invite: dict[str, Any],
    claim: dict[str, Any],
    reason: str,
) -> str:
    return "\n".join(
        [
            "Invite claim requires review.",
            f"Claim ID: {claim.get('id', '')}",
            f"Invite ID: {invite.get('id', '')}",
            f"Status: {invite.get('status', '')}",
            f"Expected target: {_invite_target_label(invite)}",
            f"Created by: {invite.get('created_by', '')}",
            f"Claimant user id: {claim.get('claimant_tg_id', '')}",
            f"Claimant username: {claim.get('claimant_username') or '-'}",
            f"Reason: {reason}",
        ]
    )


def _format_invite_claim_decision(claim: dict[str, Any], decision: str) -> str:
    return "\n".join(
        [
            f"Invite claim {decision}.",
            f"Claim ID: {claim.get('id', '')}",
            f"Invite ID: {claim.get('invite_id', '')}",
            f"Claimant user id: {claim.get('claimant_tg_id', '')}",
            f"Claimant username: {claim.get('claimant_username') or '-'}",
            f"Status: {claim.get('status', '')}",
        ]
    )


def _format_leads(leads: list[dict[str, Any]]) -> str:
    if not leads:
        return "No uninvited leads yet."
    lines = ["Uninvited leads:"]
    for lead in leads[:30]:
        name = " ".join(
            item
            for item in [
                str(lead.get("first_name") or ""),
                str(lead.get("last_name") or ""),
            ]
            if item
        )
        username = lead.get("username") or "-"
        username_text = f"@{username}" if username != "-" else "-"
        phone = lead.get("phone_number") or "-"
        lines.append(
            f"- {lead.get('telegram_user_id')} | {username_text} | {name or '-'} | phone {phone} | messages {lead.get('message_count', 0)}"
        )
    return "\n".join(lines)


def _format_bonus(user_id: int, balance: int, ledger: list[dict[str, Any]]) -> str:
    lines = [
        f"Referral bonus for user {user_id}: {balance} Stars.",
    ]
    if ledger:
        lines.append("Recent ledger:")
        for entry in ledger:
            sign = "+" if int(entry.get("amount_stars") or 0) >= 0 else ""
            lines.append(
                f"- {entry.get('kind', '')}: {sign}{entry.get('amount_stars', 0)} Stars, balance {entry.get('balance_after_stars', 0)}"
            )
    return "\n".join(lines)


def _support_user_label(ticket: dict[str, Any], fallback_user_id: int = 0) -> str:
    display_name = str(ticket.get("display_name") or "").strip()
    if display_name:
        return display_name
    username = str(ticket.get("username") or "").strip().lstrip("@")
    if username:
        return f"@{username}"
    first_name = str(ticket.get("first_name") or "").strip()
    last_name = str(ticket.get("last_name") or "").strip()
    full_name = " ".join(part for part in [first_name, last_name] if part)
    if full_name:
        return full_name
    user_id = int(ticket.get("user_id") or fallback_user_id or 0)
    return str(user_id or "unknown")


def _format_support_admin_notification(
    ticket: dict[str, Any],
    summary: dict[str, Any],
    user_label: str = "",
) -> str:
    ticket_id = str(ticket.get("ticket_id") or "")
    user_id = int(ticket.get("user_id") or 0)
    counts = summary.get("counts") or {}
    label = user_label or _support_user_label(ticket, user_id)
    event = "New support ticket" if ticket.get("is_new_ticket") else "Support follow-up"
    return "\n".join(
        [
            f"{event}: {ticket_id}",
            f"User: {label} ({user_id})",
            f"Excerpt: {ticket.get('last_message_excerpt') or '-'}",
            f"Open tickets: {int(counts.get('open_tickets') or 0)}",
            f"Unread user messages: {int(counts.get('unread_user_messages') or 0)}",
            f"Reply: /replyticket {ticket_id} <message>",
            f"Archive: /archiveticket {ticket_id}",
        ]
    )


def _format_support_summary(summary: dict[str, Any], open_tickets: list[dict[str, Any]]) -> str:
    counts = summary.get("counts") or {}
    lines = [
        "Support queue:",
        f"Open tickets: {int(counts.get('open_tickets') or 0)}",
        f"Archived tickets: {int(counts.get('archived_tickets') or 0)}",
        f"Unread user messages: {int(counts.get('unread_user_messages') or 0)}",
        f"New tickets: {int(counts.get('new_tickets') or 0)}",
    ]
    if open_tickets:
        lines.append("")
        lines.append("Latest open tickets:")
        for ticket in open_tickets:
            lines.append(
                f"- {ticket.get('ticket_id')} | {_support_user_label(ticket)} | unread {int(ticket.get('unread_user_messages') or 0)} | {ticket.get('last_message_excerpt') or '-'}"
            )
    return "\n".join(lines)


def _format_support_ticket_detail(ticket: dict[str, Any], max_messages: int = 12) -> str:
    ticket_id = str(ticket.get("ticket_id") or "")
    user_id = int(ticket.get("user_id") or 0)
    lines = [
        f"Support ticket: {ticket_id}",
        f"Status: {ticket.get('status') or 'unknown'}",
        f"User: {_support_user_label(ticket, user_id)} ({user_id})",
        f"Created: {ticket.get('created_at') or '-'}",
        f"Updated: {ticket.get('updated_at') or '-'}",
        f"Messages: {int(ticket.get('message_count') or 0)}",
        "",
        "Thread:",
    ]
    messages = ticket.get("messages")
    if not isinstance(messages, list) or not messages:
        lines.append("- no messages")
        return "\n".join(lines)
    for message in messages[-max_messages:]:
        if not isinstance(message, dict):
            continue
        author = "Admin" if message.get("author") == "admin" else "User"
        lines.append(
            f"- [{message.get('created_at') or '-'}] {author}: {message.get('text') or ''}"
        )
    return "\n".join(lines)


def _format_share_link(share: dict[str, Any], lang: str = ta.DEFAULT_USER_LANGUAGE) -> str:
    return _t(
        lang,
        "share_link",
        name=share.get("name", ""),
        share_link=str(share.get("share_link", "")),
    )


def _format_subscription_status(
    user_id: int,
    record: dict[str, Any],
    is_admin: bool,
    is_active: bool,
    price_stars: int,
    base_price_stars: int,
    discount_percent: int,
    period_days: int,
    max_12m_discount_percent: int,
    lang: str = ta.DEFAULT_USER_LANGUAGE,
) -> str:
    account_type = record.get("account_type") or ("admin" if is_admin else "free")
    if lang == "ru" and not is_admin:
        role = "пользователь"
        account = {"free": "бесплатный", "paid": "оплачен"}.get(str(account_type), str(account_type))
        active = "да" if is_active else "нет"
        lines = [
            f"Telegram user: {user_id}",
            f"Роль: {role}",
            f"Аккаунт: {account}",
            f"Подписка активна: {active}",
        ]
        expires_at = record.get("subscription_expires_at")
        if expires_at:
            lines.append(f"Истекает: {expires_at}")
        client_id = record.get("client_id")
        if client_id:
            lines.append(f"Client ID: {client_id}")
        trial_expires_at = record.get("trial_expires_at")
        if trial_expires_at:
            lines.append(f"Пробный период до: {trial_expires_at}")
        bonus_balance = record.get("bonus_balance_stars")
        if isinstance(bonus_balance, int) and bonus_balance > 0:
            lines.append(f"Бонусный баланс: {bonus_balance} Stars")
        lines.extend(
            [
                f"Цена за 1 месяц: {base_price_stars} Stars / {period_days} дн.",
                f"Персональная скидка: {discount_percent}%",
                f"Макс. пакетная скидка 12 мес.: {max_12m_discount_percent}%",
                f"Ваша цена за 1 месяц: {price_stars} Stars",
            ]
        )
        if not is_active:
            lines.append("Используйте /pay, чтобы включить VPN-доступ.")
        return "\n".join(lines)

    lines = [
        f"Telegram user: {user_id}",
        f"Role: {'admin' if is_admin else 'user'}",
        f"Account: {account_type}",
        f"Subscription active: {is_active}",
    ]
    expires_at = record.get("subscription_expires_at")
    if expires_at:
        lines.append(f"Expires at: {expires_at}")
    client_id = record.get("client_id")
    if client_id:
        lines.append(f"Client ID: {client_id}")
    trial_expires_at = record.get("trial_expires_at")
    if trial_expires_at:
        lines.append(f"Trial expires at: {trial_expires_at}")
    bonus_balance = record.get("bonus_balance_stars")
    if isinstance(bonus_balance, int) and bonus_balance > 0:
        lines.append(f"Bonus balance: {bonus_balance} Stars")
    lines.extend(
        [
            f"Monthly base price: {base_price_stars} Stars / {period_days} days",
            f"Personal discount: {discount_percent}%",
            f"Max 12-month package discount: {max_12m_discount_percent}%",
            f"Your 1-month price: {price_stars} Stars",
        ]
    )
    if not is_active and not is_admin:
        lines.append("Use /pay to activate VPN access.")
    return "\n".join(lines)


def _format_doctor(doctor: dict[str, Any]) -> str:
    lines = [
        f"Xray doctor: {doctor.get('status', 'unknown')}",
        f"Ready: {doctor.get('ready', False)}",
    ]

    checks = doctor.get("checks") or []
    not_ok = [check for check in checks if check.get("status") != "ok"]
    if not_ok:
        lines.append("")
        lines.append("Attention:")
        for check in not_ok:
            detail = check.get("detail") or check.get("label") or check.get("id")
            lines.append(f"- {check.get('id', 'check')}: {check.get('status', '')} - {detail}")
    return "\n".join(lines)


def build_bot_from_env() -> TelegramVpnBot:
    token = config.TELEGRAM_BOT_TOKEN.strip()
    if not token:
        raise BotConfigError("TELEGRAM_BOT_TOKEN is required")

    admin_user_ids = parse_allowed_chat_ids(
        config.TELEGRAM_ADMIN_USER_IDS.strip() or config.TELEGRAM_ALLOWED_CHAT_IDS
    )
    if not admin_user_ids:
        raise BotConfigError("TELEGRAM_ADMIN_USER_IDS or TELEGRAM_ALLOWED_CHAT_IDS is required")

    panel_token = config.TELEGRAM_PANEL_TOKEN.strip()
    if not panel_token or panel_token == "changeme":
        raise BotConfigError("TELEGRAM_PANEL_TOKEN or PANEL_SECRET_TOKEN is required")

    panel = PanelClient(
        base_url=config.TELEGRAM_PANEL_BASE_URL,
        token=panel_token,
        timeout=config.TELEGRAM_REQUEST_TIMEOUT,
    )
    telegram = TelegramClient(
        token=token,
        timeout=config.TELEGRAM_REQUEST_TIMEOUT,
        proxy_url=config.TELEGRAM_PROXY_URL.strip() or None,
    )
    access = ta.TelegramAccessStore(
        path=config.TELEGRAM_ACCESS_PATH,
        admin_user_ids=admin_user_ids,
    )
    return TelegramVpnBot(
        panel=panel,
        telegram=telegram,
        access=access,
        command_docs=tdocs.TelegramCommandDocsStore(config.TELEGRAM_COMMAND_DOCS_PATH),
        subscription_check_interval_seconds=config.TELEGRAM_SUBSCRIPTION_CHECK_INTERVAL_SECONDS,
        subscription_notify_days=parse_notify_days(config.TELEGRAM_SUBSCRIPTION_NOTIFY_DAYS),
        bot_username=config.TELEGRAM_BOT_USERNAME,
    )


async def amain() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    bot = build_bot_from_env()
    logger.info("Starting Telegram VPN bot")
    try:
        await bot.run_polling(poll_timeout=config.TELEGRAM_POLL_TIMEOUT)
    finally:
        await bot.panel.aclose()
        await bot.telegram.aclose()


if __name__ == "__main__":
    asyncio.run(amain())
