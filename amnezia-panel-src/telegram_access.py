"""
Access store and policy helpers for the Telegram bot.

The bot uses Telegram user IDs as identity. Chat IDs are intentionally not
used for authorization because group chats can contain many users.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

DEFAULT_SUBSCRIPTION_PRICE_STARS = 100
DEFAULT_SUBSCRIPTION_PERIOD_DAYS = 30
DEFAULT_SUBSCRIPTION_MAX_12M_DISCOUNT_PERCENT = 0
DEFAULT_TRIAL_PERIOD_DAYS = 7
DEFAULT_INVITE_TTL_DAYS = 7
DEFAULT_INVITE_MAX_USES = 1
DEFAULT_REFERRAL_BONUS_PERCENT = 10
PAYMENT_CURRENCY = "XTR"
ALLOWED_PAYMENT_MONTHS = (1, 3, 6, 12)
INVITE_STATUS_PENDING = "pending"
INVITE_STATUS_ACCEPTED = "accepted"
INVITE_STATUS_CANCELLED = "cancelled"
INVITE_CLAIM_STATUS_PENDING = "pending"
INVITE_CLAIM_STATUS_APPROVED = "approved"
INVITE_CLAIM_STATUS_REJECTED = "rejected"
SUPPORT_TICKET_STATUS_OPEN = "open"
SUPPORT_TICKET_STATUS_ARCHIVED = "archived"
DEFAULT_USER_LANGUAGE = "en"
SUPPORTED_USER_LANGUAGES = {"ru", "en"}


def parse_id_set(raw_value: str) -> set[int]:
    values = [item.strip() for item in re.split(r"[,\s]+", raw_value or "") if item.strip()]
    ids: set[int] = set()
    for value in values:
        try:
            ids.add(int(value))
        except ValueError as exc:
            raise ValueError(f"Invalid Telegram user id: {value}") from exc
    return ids


def normalize_user_language(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    language = value.strip().lower()
    if language in SUPPORTED_USER_LANGUAGES:
        return language
    return ""


def default_user_language_for_telegram_code(value: Any) -> str:
    if isinstance(value, str) and value.strip().lower().startswith("ru"):
        return "ru"
    return DEFAULT_USER_LANGUAGE


def _normalize_profile_text(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.strip().split())


def normalize_telegram_username(value: Any) -> str:
    username = _normalize_profile_text(value).lstrip("@").lower()
    return username


def telegram_display_name(
    username: Any = "",
    first_name: Any = "",
    last_name: Any = "",
) -> str:
    normalized_username = normalize_telegram_username(username)
    if normalized_username:
        return f"@{normalized_username}"

    parts = [
        _normalize_profile_text(first_name),
        _normalize_profile_text(last_name),
    ]
    return " ".join(part for part in parts if part).strip()


def normalize_telegram_profile(profile: Any) -> dict[str, str]:
    if not isinstance(profile, dict):
        return {
            "username": "",
            "first_name": "",
            "last_name": "",
            "display_name": "",
        }

    normalized = {
        "username": normalize_telegram_username(profile.get("username")),
        "first_name": _normalize_profile_text(profile.get("first_name")),
        "last_name": _normalize_profile_text(profile.get("last_name")),
    }
    normalized["display_name"] = telegram_display_name(
        username=normalized["username"],
        first_name=normalized["first_name"],
        last_name=normalized["last_name"],
    )
    return normalized


def _timestamp() -> str:
    return format_timestamp(datetime.now(timezone.utc))


def format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        normalized = value.strip().replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _clamp_percent(value: int) -> int:
    return max(0, min(100, value))


def _round_half_up_div(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        raise ValueError("denominator must be positive")
    return (numerator + (denominator // 2)) // denominator


def _normalize_payment_months(value: int) -> int:
    if value not in ALLOWED_PAYMENT_MONTHS:
        raise ValueError(f"months must be one of {ALLOWED_PAYMENT_MONTHS}")
    return value


def _payment_sort_key(record: dict[str, Any]) -> str:
    updated_at = record.get("updated_at")
    created_at = record.get("created_at")
    if isinstance(updated_at, str) and updated_at:
        return updated_at
    if isinstance(created_at, str) and created_at:
        return created_at
    return ""


def _record_sort_key(record: dict[str, Any]) -> str:
    updated_at = record.get("updated_at")
    created_at = record.get("created_at")
    if isinstance(updated_at, str) and updated_at:
        return updated_at
    if isinstance(created_at, str) and created_at:
        return created_at
    return ""


def _support_message_excerpt(value: Any, limit: int = 120) -> str:
    if not isinstance(value, str):
        return ""
    normalized = " ".join(value.strip().split())
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 1].rstrip() + "…"


def _redact_charge_id(value: Any) -> tuple[bool, str]:
    if not isinstance(value, str) or not value:
        return False, ""
    if len(value) <= 12:
        return True, value
    return True, f"{value[:8]}...{value[-4:]}"


class TelegramAccessStore:
    def __init__(self, path: str | Path, admin_user_ids: set[int]):
        self.path = Path(path)
        self.admin_user_ids = set(admin_user_ids)

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return self._normalize_payload({})

        with self.path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)

        if not isinstance(payload, dict):
            raise ValueError(f"Telegram access store must be a JSON object: {self.path}")

        return self._normalize_payload(payload)

    def save(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp_name = ""
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=str(self.path.parent),
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                tmp_name = handle.name
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
            os.replace(tmp_name, self.path)
        finally:
            if tmp_name and os.path.exists(tmp_name):
                os.unlink(tmp_name)

    def is_admin(self, user_id: int) -> bool:
        return user_id in self.admin_user_ids

    def is_known_user(self, user_id: int) -> bool:
        if self.is_admin(user_id):
            return True
        return str(user_id) in self.load().get("users", {})

    def preferred_language_for_user(
        self,
        user_id: int,
        telegram_language_code: str = "",
    ) -> str:
        record = self.user_record(user_id) or {}
        preferred = normalize_user_language(record.get("preferred_language"))
        if preferred:
            return preferred
        stored_code = record.get("telegram_language_code")
        return default_user_language_for_telegram_code(telegram_language_code or stored_code)

    def language_prompted_for_user(self, user_id: int) -> bool:
        record = self.user_record(user_id) or {}
        return bool(record.get("language_prompted_at"))

    def update_user_language(
        self,
        user_id: int,
        preferred_language: str | None = None,
        telegram_language_code: str | None = None,
        mark_prompted: bool = False,
    ) -> dict[str, Any]:
        normalized_language = None
        if preferred_language is not None:
            normalized_language = normalize_user_language(preferred_language)
            if not normalized_language:
                raise ValueError("preferred_language must be ru or en")
        prompted_at = _timestamp() if mark_prompted else None
        return self._update_user(
            user_id,
            preferred_language=normalized_language,
            telegram_language_code=telegram_language_code,
            language_prompted_at=prompted_at,
        )

    def update_user_profile(
        self,
        user_id: int,
        profile: dict[str, Any] | None = None,
        invited_by: int | None = None,
    ) -> dict[str, Any]:
        normalized = normalize_telegram_profile(profile)
        return self._update_user(
            user_id,
            invited_by=invited_by,
            username=normalized["username"],
            first_name=normalized["first_name"],
            last_name=normalized["last_name"],
            display_name=normalized["display_name"],
        )

    def display_name_for_user(self, user_id: int) -> str:
        record = self.user_record(user_id) or {}
        display_name = _normalize_profile_text(record.get("display_name"))
        if display_name:
            return display_name
        return telegram_display_name(
            username=record.get("username", ""),
            first_name=record.get("first_name", ""),
            last_name=record.get("last_name", ""),
        )

    def desired_client_name_for_user(
        self,
        user_id: int,
        existing_name: str = "",
        default_name: str = "",
    ) -> str:
        display_name = self.display_name_for_user(user_id)
        if display_name:
            return display_name
        fallback_name = _normalize_profile_text(existing_name)
        if fallback_name:
            return fallback_name
        default_value = _normalize_profile_text(default_name)
        if default_value:
            return default_value
        return f"Telegram {user_id}"

    def invite_user(self, user_id: int, invited_by: int) -> dict[str, Any]:
        return self._update_user(user_id, invited_by=invited_by, client_id=None)

    def bind_client(self, user_id: int, client_id: str, invited_by: int | None = None) -> dict[str, Any]:
        client_id = client_id.strip()
        if not client_id:
            raise ValueError("client_id is required")
        return self._update_user(user_id, invited_by=invited_by, client_id=client_id)

    def bind_peer(self, user_id: int, peer_public_key: str, invited_by: int | None = None) -> dict[str, Any]:
        peer_public_key = peer_public_key.strip()
        if not peer_public_key:
            raise ValueError("peer_public_key is required")
        return self._update_user(
            user_id,
            invited_by=invited_by,
            peer_public_key=peer_public_key,
        )

    def client_for_user(self, user_id: int) -> str | None:
        record = self.user_record(user_id)
        if not isinstance(record, dict):
            return None
        client_id = record.get("client_id")
        if isinstance(client_id, str) and client_id.strip():
            return client_id.strip()
        return None

    def peer_for_user(self, user_id: int) -> str | None:
        record = self.user_record(user_id)
        if not isinstance(record, dict):
            return None
        peer_public_key = record.get("peer_public_key")
        if isinstance(peer_public_key, str) and peer_public_key.strip():
            return peer_public_key.strip()
        return None

    def user_record(self, user_id: int) -> dict[str, Any] | None:
        record = self.load().get("users", {}).get(str(user_id))
        if not isinstance(record, dict):
            return None
        return dict(record)

    def all_user_records(self) -> dict[int, dict[str, Any]]:
        records: dict[int, dict[str, Any]] = {}
        for raw_user_id, record in self.load().get("users", {}).items():
            if not isinstance(record, dict):
                continue
            try:
                user_id = int(raw_user_id)
            except ValueError:
                continue
            records[user_id] = dict(record)
        return records

    def subscription_price_stars(self) -> int:
        value = self.load().get("settings", {}).get("subscription_price_stars")
        if isinstance(value, int) and value >= 0:
            return value
        return DEFAULT_SUBSCRIPTION_PRICE_STARS

    def subscription_period_days(self) -> int:
        value = self.load().get("settings", {}).get("subscription_period_days")
        if isinstance(value, int) and value > 0:
            return value
        return DEFAULT_SUBSCRIPTION_PERIOD_DAYS

    def subscription_max_12m_discount_percent(self) -> int:
        value = self.load().get("settings", {}).get("subscription_max_12m_discount_percent")
        if isinstance(value, int):
            return _clamp_percent(value)
        return DEFAULT_SUBSCRIPTION_MAX_12M_DISCOUNT_PERCENT

    def trial_period_days(self) -> int:
        value = self.load().get("settings", {}).get("trial_period_days")
        if isinstance(value, int) and value > 0:
            return value
        return DEFAULT_TRIAL_PERIOD_DAYS

    def invite_ttl_days(self) -> int:
        value = self.load().get("settings", {}).get("invite_ttl_days")
        if isinstance(value, int) and value > 0:
            return value
        return DEFAULT_INVITE_TTL_DAYS

    def referral_bonus_percent(self) -> int:
        value = self.load().get("settings", {}).get("referral_bonus_percent")
        if isinstance(value, int):
            return _clamp_percent(value)
        return DEFAULT_REFERRAL_BONUS_PERCENT

    def set_subscription_price_stars(self, price: int) -> int:
        if price < 0:
            raise ValueError("subscription price must be non-negative")
        payload = self.load()
        payload.setdefault("settings", {})["subscription_price_stars"] = price
        self.save(payload)
        return price

    def set_subscription_max_12m_discount_percent(self, percent: int) -> int:
        payload = self.load()
        normalized = _clamp_percent(percent)
        payload.setdefault("settings", {})["subscription_max_12m_discount_percent"] = normalized
        self.save(payload)
        return normalized

    def set_trial_period_days(self, days: int) -> int:
        if days <= 0:
            raise ValueError("trial days must be positive")
        payload = self.load()
        payload.setdefault("settings", {})["trial_period_days"] = days
        self.save(payload)
        return days

    def discount_for_user(self, user_id: int) -> int:
        record = self.user_record(user_id)
        if not record:
            return 0
        value = record.get("discount_percent")
        if isinstance(value, int):
            return _clamp_percent(value)
        return 0

    def set_discount_percent(self, user_id: int, percent: int) -> dict[str, Any]:
        return self._update_user(user_id, discount_percent=_clamp_percent(percent))

    def clear_discount_percent(self, user_id: int) -> dict[str, Any]:
        return self._update_user(user_id, discount_percent=0)

    def price_for_user(self, user_id: int) -> int:
        return int(self.payment_quote_for_user(user_id, months=1)["base_amount_stars"])

    def package_discount_percent_for_months(self, months: int) -> int:
        normalized_months = _normalize_payment_months(months)
        if normalized_months == 1:
            return 0
        max_discount = self.subscription_max_12m_discount_percent()
        if max_discount <= 0:
            return 0
        return _clamp_percent(_round_half_up_div(max_discount * normalized_months, 12))

    def payment_quote_for_user(self, user_id: int, months: int) -> dict[str, int]:
        normalized_months = _normalize_payment_months(months)
        monthly_price = self.subscription_price_stars()
        personal_discount_percent = self.discount_for_user(user_id)
        package_discount_percent = self.package_discount_percent_for_months(normalized_months)
        total_discount_percent = _clamp_percent(
            personal_discount_percent + package_discount_percent
        )
        period_days = self.subscription_period_days() * normalized_months
        base_amount_stars = (
            monthly_price * normalized_months * (100 - total_discount_percent) // 100
        )
        bonus_balance_stars = self.bonus_balance_for_user(user_id)
        bonus_spent_stars = min(base_amount_stars, bonus_balance_stars)
        amount_stars = base_amount_stars - bonus_spent_stars
        return {
            "months": normalized_months,
            "monthly_price_stars": monthly_price,
            "period_days": period_days,
            "personal_discount_percent": personal_discount_percent,
            "package_discount_percent": package_discount_percent,
            "total_discount_percent": total_discount_percent,
            "base_amount_stars": base_amount_stars,
            "bonus_balance_stars": bonus_balance_stars,
            "bonus_spent_stars": bonus_spent_stars,
            "amount_stars": amount_stars,
        }

    def bonus_balance_for_user(self, user_id: int) -> int:
        record = self.user_record(user_id)
        if not record:
            return 0
        value = record.get("bonus_balance_stars")
        if isinstance(value, int) and value > 0:
            return value
        return 0

    def is_subscription_active(self, user_id: int, now: datetime | None = None) -> bool:
        record = self.user_record(user_id)
        if not record or record.get("account_type") != "paid":
            return False
        expires_at = parse_timestamp(record.get("subscription_expires_at"))
        if expires_at is None:
            return False
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        return expires_at > now

    def set_subscription_expires_at(self, user_id: int, expires_at: datetime) -> dict[str, Any]:
        return self._update_user(
            user_id,
            account_type="paid",
            subscription_expires_at=format_timestamp(expires_at),
            deactivated_at="",
            last_expiry_notifications=[],
        )

    def start_trial(
        self,
        user_id: int,
        invite_id: str,
        invited_by: int,
        days: int | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        days = days or self.trial_period_days()
        if days <= 0:
            raise ValueError("trial days must be positive")
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        expires_at = now + timedelta(days=days)
        return self._update_user(
            user_id,
            invited_by=invited_by,
            account_type="paid",
            subscription_expires_at=format_timestamp(expires_at),
            trial_started_at=format_timestamp(now),
            trial_expires_at=format_timestamp(expires_at),
            trial_invite_id=invite_id,
            deactivated_at="",
            last_expiry_notifications=[],
        )

    def is_trial_active(self, user_id: int, now: datetime | None = None) -> bool:
        record = self.user_record(user_id)
        if not record or not record.get("trial_invite_id"):
            return False
        expires_at = parse_timestamp(record.get("trial_expires_at"))
        if expires_at is None:
            return False
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        return expires_at > now

    def grant_subscription(
        self,
        user_id: int,
        days: int | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        days = days or self.subscription_period_days()
        if days <= 0:
            raise ValueError("subscription days must be positive")
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        current = None
        record = self.user_record(user_id)
        if record:
            current = parse_timestamp(record.get("subscription_expires_at"))
        base = current if current and current > now else now
        return self.set_subscription_expires_at(user_id, base + timedelta(days=days))

    def revoke_subscription(self, user_id: int) -> dict[str, Any]:
        return self._update_user(
            user_id,
            account_type="free",
            subscription_expires_at="",
            deactivated_at=_timestamp(),
            last_expiry_notifications=[],
        )

    def mark_deactivated(self, user_id: int) -> dict[str, Any]:
        return self._update_user(user_id, deactivated_at=_timestamp())

    def create_payment(
        self,
        user_id: int,
        amount_stars: int,
        base_amount_stars: int | None = None,
        bonus_spent_stars: int = 0,
        months: int = 1,
        period_days: int | None = None,
        personal_discount_percent: int = 0,
        package_discount_percent: int = 0,
        total_discount_percent: int | None = None,
    ) -> dict[str, Any]:
        normalized_months = _normalize_payment_months(months)
        if amount_stars < 0:
            raise ValueError("payment amount must be non-negative")
        if bonus_spent_stars < 0:
            raise ValueError("bonus spent must be non-negative")
        if period_days is None:
            period_days = self.subscription_period_days() * normalized_months
        if period_days <= 0:
            raise ValueError("payment period_days must be positive")
        normalized_personal_discount = _clamp_percent(personal_discount_percent)
        normalized_package_discount = _clamp_percent(package_discount_percent)
        normalized_total_discount = _clamp_percent(
            (
                normalized_personal_discount + normalized_package_discount
                if total_discount_percent is None
                else total_discount_percent
            )
        )
        payload = self.load()
        payments = payload.setdefault("payments", {})
        now = _timestamp()
        for record in payments.values():
            if not isinstance(record, dict):
                continue
            if record.get("user_id") == user_id and record.get("status") == "pending":
                record["status"] = "cancelled"
                record["updated_at"] = now
        payment_payload = f"sub:{user_id}:{uuid.uuid4().hex}"
        record = {
            "status": "pending",
            "user_id": user_id,
            "amount_stars": amount_stars,
            "base_amount_stars": amount_stars if base_amount_stars is None else base_amount_stars,
            "bonus_spent_stars": bonus_spent_stars,
            "months": normalized_months,
            "personal_discount_percent": normalized_personal_discount,
            "package_discount_percent": normalized_package_discount,
            "total_discount_percent": normalized_total_discount,
            "currency": PAYMENT_CURRENCY,
            "period_days": period_days,
            "created_at": now,
            "updated_at": now,
        }
        payments[payment_payload] = record
        self.save(payload)
        return {"payload": payment_payload, **record}

    def payment_for_payload(self, payment_payload: str) -> dict[str, Any] | None:
        record = self.load().get("payments", {}).get(payment_payload)
        if not isinstance(record, dict):
            return None
        return {"payload": payment_payload, **dict(record)}

    def complete_payment(
        self,
        payment_payload: str,
        telegram_payment_charge_id: str,
    ) -> dict[str, Any] | None:
        payload = self.load()
        payments = payload.setdefault("payments", {})
        record = payments.get(payment_payload)
        if not isinstance(record, dict):
            return None
        record = dict(record)
        record["status"] = "completed"
        record["telegram_payment_charge_id"] = telegram_payment_charge_id
        record["updated_at"] = _timestamp()
        payments[payment_payload] = record
        bonus_spent = record.get("bonus_spent_stars")
        user_id = record.get("user_id")
        if isinstance(user_id, int) and isinstance(bonus_spent, int) and bonus_spent > 0:
            self._append_bonus_ledger_entry(
                payload=payload,
                user_id=user_id,
                amount_stars=-bonus_spent,
                kind="spend",
                source_payment_payload=payment_payload,
                related_user_id=user_id,
            )
        self.save(payload)
        return {"payload": payment_payload, **record}

    def spend_bonus(
        self,
        user_id: int,
        amount_stars: int,
        source_payment_payload: str = "",
    ) -> dict[str, Any] | None:
        if amount_stars <= 0:
            return None
        payload = self.load()
        return self._append_bonus_ledger_entry(
            payload=payload,
            user_id=user_id,
            amount_stars=-amount_stars,
            kind="spend",
            source_payment_payload=source_payment_payload,
            related_user_id=user_id,
            save=True,
        )

    def award_referral_bonus_for_payment(
        self,
        payment_payload: str,
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        payload = self.load()
        payments = payload.setdefault("payments", {})
        payment = payments.get(payment_payload)
        if not isinstance(payment, dict) or payment.get("status") != "completed":
            return None
        if payment.get("referral_bonus_ledger_id"):
            return None

        user_id = payment.get("user_id")
        amount_stars = payment.get("amount_stars")
        if not isinstance(user_id, int) or not isinstance(amount_stars, int) or amount_stars <= 0:
            return None

        users = payload.setdefault("users", {})
        user_record = users.get(str(user_id))
        if not isinstance(user_record, dict):
            return None

        trial_invite_id = user_record.get("trial_invite_id")
        trial_expires_at = parse_timestamp(user_record.get("trial_expires_at"))
        if not isinstance(trial_invite_id, str) or not trial_invite_id or trial_expires_at is None:
            return None
        if trial_expires_at <= now:
            return None

        invites = payload.setdefault("invites", {})
        invite = invites.get(trial_invite_id)
        if not isinstance(invite, dict):
            return None
        if invite.get("bonus_awarded_payment_payload"):
            return None

        referrer_id = invite.get("created_by")
        if not isinstance(referrer_id, int) or referrer_id <= 0 or referrer_id == user_id:
            return None

        bonus = amount_stars * self.referral_bonus_percent() // 100
        if bonus <= 0:
            return None

        entry = self._append_bonus_ledger_entry(
            payload=payload,
            user_id=referrer_id,
            amount_stars=bonus,
            kind="referral_bonus",
            source_payment_payload=payment_payload,
            related_user_id=user_id,
        )
        payment["referral_bonus_ledger_id"] = entry["id"]
        payment["referral_bonus_stars"] = bonus
        invite["bonus_awarded_at"] = format_timestamp(now)
        invite["bonus_awarded_payment_payload"] = payment_payload
        invite["updated_at"] = format_timestamp(now)
        self.save(payload)
        return entry

    def list_payments(self, limit: int | None = None) -> list[dict[str, Any]]:
        payments: list[dict[str, Any]] = []
        for payment_payload, record in self.load().get("payments", {}).items():
            if not isinstance(record, dict):
                continue
            payments.append(self.public_payment_record(payment_payload, record))
        payments.sort(key=_payment_sort_key, reverse=True)
        if limit is not None:
            return payments[: max(0, limit)]
        return payments

    def last_completed_payment_for_user(self, user_id: int) -> dict[str, Any] | None:
        for payment in self.list_payments():
            if payment.get("user_id") == user_id and payment.get("status") == "completed":
                return payment
        return None

    def public_payment_record(
        self,
        payment_payload: str,
        record: dict[str, Any],
    ) -> dict[str, Any]:
        charge_present, charge_short = _redact_charge_id(record.get("telegram_payment_charge_id"))
        return {
            "payload": payment_payload,
            "status": record.get("status", ""),
            "user_id": record.get("user_id"),
            "amount_stars": record.get("amount_stars", 0),
            "base_amount_stars": record.get("base_amount_stars", record.get("amount_stars", 0)),
            "bonus_spent_stars": record.get("bonus_spent_stars", 0),
            "months": record.get("months", 1),
            "personal_discount_percent": record.get("personal_discount_percent", 0),
            "package_discount_percent": record.get("package_discount_percent", 0),
            "total_discount_percent": record.get("total_discount_percent", 0),
            "referral_bonus_stars": record.get("referral_bonus_stars", 0),
            "currency": record.get("currency", PAYMENT_CURRENCY),
            "period_days": record.get("period_days", self.subscription_period_days()),
            "created_at": record.get("created_at", ""),
            "updated_at": record.get("updated_at", ""),
            "telegram_payment_charge_id_present": charge_present,
            "telegram_payment_charge_id_short": charge_short,
        }

    def public_user_record(self, user_id: int, now: datetime | None = None) -> dict[str, Any] | None:
        record = self.user_record(user_id)
        if record is None:
            return None
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        account_type = record.get("account_type", "free")
        expires_at = parse_timestamp(record.get("subscription_expires_at"))
        subscription_active = account_type == "paid" and expires_at is not None and expires_at > now
        subscription_expired = account_type == "paid" and not subscription_active
        trial_expires_at = parse_timestamp(record.get("trial_expires_at"))
        trial_active = (
            bool(record.get("trial_invite_id"))
            and trial_expires_at is not None
            and trial_expires_at > now
        )
        return {
            "telegram_user_id": user_id,
            "invited_by": record.get("invited_by"),
            "client_id": record.get("client_id", ""),
            "peer_public_key": record.get("peer_public_key", ""),
            "username": record.get("username", ""),
            "first_name": record.get("first_name", ""),
            "last_name": record.get("last_name", ""),
            "display_name": self.display_name_for_user(user_id),
            "account_type": account_type,
            "subscription_active": subscription_active,
            "subscription_expired": subscription_expired,
            "subscription_expires_at": record.get("subscription_expires_at", ""),
            "trial_active": trial_active,
            "trial_started_at": record.get("trial_started_at", ""),
            "trial_expires_at": record.get("trial_expires_at", ""),
            "trial_invite_id": record.get("trial_invite_id", ""),
            "discount_percent": self.discount_for_user(user_id),
            "bonus_balance_stars": self.bonus_balance_for_user(user_id),
            "preferred_language": record.get("preferred_language", ""),
            "telegram_language_code": record.get("telegram_language_code", ""),
            "language_prompted_at": record.get("language_prompted_at", ""),
            "support_compose_started_at": record.get("support_compose_started_at", ""),
            "deactivated_at": record.get("deactivated_at", ""),
            "created_at": record.get("created_at", ""),
            "updated_at": record.get("updated_at", ""),
            "last_expiry_notifications": record.get("last_expiry_notifications", []),
            "last_completed_payment": self.last_completed_payment_for_user(user_id),
        }

    def public_user_records(self, now: datetime | None = None) -> list[dict[str, Any]]:
        users = []
        for user_id in sorted(self.all_user_records()):
            record = self.public_user_record(user_id, now=now)
            if record is not None:
                users.append(record)
        return users

    def billing_summary(self, recent_payment_limit: int = 5) -> dict[str, Any]:
        users = self.public_user_records()
        total = len(users)
        active_paid = sum(1 for user in users if user.get("subscription_active"))
        expired = sum(1 for user in users if user.get("subscription_expired"))
        free = sum(1 for user in users if user.get("account_type") != "paid")
        payments = self.list_payments()
        completed_payments = sum(1 for payment in payments if payment.get("status") == "completed")
        invites = self.public_invite_records()
        claims = self.public_invite_claim_records()
        leads = self.public_lead_records()
        pending_invites = sum(1 for invite in invites if invite.get("status") == INVITE_STATUS_PENDING)
        pending_claims = sum(
            1 for claim in claims if claim.get("status") == INVITE_CLAIM_STATUS_PENDING
        )
        bonus_total = sum(
            int(user.get("bonus_balance_stars") or 0)
            for user in users
            if isinstance(user.get("bonus_balance_stars"), int)
        )
        return {
            "settings": {
                "subscription_price_stars": self.subscription_price_stars(),
                "subscription_period_days": self.subscription_period_days(),
                "subscription_max_12m_discount_percent": self.subscription_max_12m_discount_percent(),
                "trial_period_days": self.trial_period_days(),
                "invite_ttl_days": self.invite_ttl_days(),
                "referral_bonus_percent": self.referral_bonus_percent(),
            },
            "counts": {
                "total_users": total,
                "active_paid": active_paid,
                "expired_paid": expired,
                "free_users": free,
                "pending_invites": pending_invites,
                "pending_invite_claims": pending_claims,
                "uninvited_leads": len(leads),
                "bonus_balance_stars": bonus_total,
                "completed_payments": completed_payments,
                "payments_total": len(payments),
            },
            "recent_payments": payments[:recent_payment_limit],
        }

    def create_invite(
        self,
        created_by: int,
        target_username_hint: str = "",
        target_phone_hint: str = "",
        target_user_id: int | None = None,
        trial_days: int | None = None,
        max_uses: int = DEFAULT_INVITE_MAX_USES,
    ) -> dict[str, Any]:
        if created_by <= 0:
            raise ValueError("created_by must be positive")
        if target_user_id is not None and target_user_id <= 0:
            raise ValueError("target_user_id must be positive")
        trial_days = trial_days or self.trial_period_days()
        if trial_days <= 0:
            raise ValueError("trial days must be positive")
        if max_uses <= 0:
            raise ValueError("max_uses must be positive")

        payload = self.load()
        invites = payload.setdefault("invites", {})
        invite_id = uuid.uuid4().hex
        token = f"inv_{secrets.token_urlsafe(24)}"
        now_dt = datetime.now(timezone.utc)
        now = format_timestamp(now_dt)
        expires_at = format_timestamp(now_dt + timedelta(days=self.invite_ttl_days()))
        record = {
            "id": invite_id,
            "status": INVITE_STATUS_PENDING,
            "created_by": created_by,
            "target_username_hint": target_username_hint,
            "target_phone_hint": target_phone_hint,
            "target_user_id": target_user_id,
            "token": token,
            "trial_days": trial_days,
            "expires_at": expires_at,
            "max_uses": max_uses,
            "used_count": 0,
            "accepted_at": "",
            "accepted_by": None,
            "revoked_at": "",
            "bonus_awarded_at": "",
            "bonus_awarded_payment_payload": "",
            "created_at": now,
            "updated_at": now,
        }
        invites[invite_id] = record
        self.save(payload)
        return dict(record)

    def invite_for_token(self, token: str) -> dict[str, Any] | None:
        token = token.strip()
        if not token:
            return None
        for invite in self.load().get("invites", {}).values():
            if isinstance(invite, dict) and invite.get("token") == token:
                return dict(invite)
        return None

    def invite_for_id(self, invite_id: str) -> dict[str, Any] | None:
        invite = self.load().get("invites", {}).get(invite_id)
        if not isinstance(invite, dict):
            return None
        return dict(invite)

    def validate_invite(self, invite: dict[str, Any], now: datetime | None = None) -> tuple[bool, str]:
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        status = str(invite.get("status") or "")
        if status == INVITE_STATUS_CANCELLED or invite.get("revoked_at"):
            return False, "invite is revoked"

        expires_at = parse_timestamp(invite.get("expires_at"))
        if expires_at is None:
            return False, "invite has no expiry"
        if expires_at <= now:
            return False, "invite is expired"

        max_uses = invite.get("max_uses")
        if not isinstance(max_uses, int) or max_uses <= 0:
            max_uses = DEFAULT_INVITE_MAX_USES
        used_count = invite.get("used_count")
        if not isinstance(used_count, int) or used_count < 0:
            used_count = 0
        if status == INVITE_STATUS_ACCEPTED or used_count >= max_uses:
            return False, "invite is already used"

        if status != INVITE_STATUS_PENDING:
            return False, f"invite status is {status or 'unknown'}"

        return True, "invite is valid"

    def create_invite_claim(
        self,
        invite_id: str,
        claimant_tg_id: int,
        claimant_username: str = "",
    ) -> dict[str, Any]:
        if claimant_tg_id <= 0:
            raise ValueError("Telegram user id must be positive")
        payload = self.load()
        invites = payload.setdefault("invites", {})
        invite = invites.get(invite_id)
        if not isinstance(invite, dict):
            raise ValueError("Invite was not found")

        claims = payload.setdefault("invite_claims", {})
        now = _timestamp()
        for claim_id, record in claims.items():
            if not isinstance(record, dict):
                continue
            if (
                record.get("invite_id") == invite_id
                and record.get("claimant_tg_id") == claimant_tg_id
                and record.get("status") == INVITE_CLAIM_STATUS_PENDING
            ):
                record = dict(record)
                record["claimant_username"] = claimant_username
                record["updated_at"] = now
                claims[claim_id] = record
                self.save(payload)
                return dict(record)

        claim_id = uuid.uuid4().hex
        record = {
            "id": claim_id,
            "invite_id": invite_id,
            "claimant_tg_id": claimant_tg_id,
            "claimant_username": claimant_username,
            "created_at": now,
            "updated_at": now,
            "status": INVITE_CLAIM_STATUS_PENDING,
            "decided_at": "",
            "decided_by": None,
        }
        claims[claim_id] = record
        self.save(payload)
        return dict(record)

    def invite_claim_for_id(self, claim_id: str) -> dict[str, Any] | None:
        claim = self.load().get("invite_claims", {}).get(claim_id)
        if not isinstance(claim, dict):
            return None
        return dict(claim)

    def reject_invite_claim(
        self,
        claim_id: str,
        decided_by: int | None = None,
    ) -> dict[str, Any]:
        payload = self.load()
        claims = payload.setdefault("invite_claims", {})
        claim = claims.get(claim_id)
        if not isinstance(claim, dict):
            raise ValueError("Invite claim was not found")
        if claim.get("status") != INVITE_CLAIM_STATUS_PENDING:
            raise ValueError("Invite claim is not pending")
        now = _timestamp()
        claim = dict(claim)
        claim["status"] = INVITE_CLAIM_STATUS_REJECTED
        claim["decided_at"] = now
        claim["decided_by"] = decided_by
        claim["updated_at"] = now
        claims[claim_id] = claim
        self.save(payload)
        return dict(claim)

    def accept_invite(
        self,
        token: str,
        user_id: int,
        now: datetime | None = None,
        claim_id: str | None = None,
        approved_by: int | None = None,
    ) -> dict[str, Any]:
        if user_id <= 0:
            raise ValueError("Telegram user id must be positive")
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        payload = self.load()
        invites = payload.setdefault("invites", {})
        invite_id = ""
        invite: dict[str, Any] | None = None
        for raw_invite_id, record in invites.items():
            if isinstance(record, dict) and record.get("token") == token:
                invite_id = str(raw_invite_id)
                invite = dict(record)
                break
        if invite is None:
            raise ValueError("Invite was not found")
        valid, reason = self.validate_invite(invite, now=now)
        if not valid:
            raise ValueError(reason)

        target_user_id = invite.get("target_user_id")
        if (
            isinstance(target_user_id, int)
            and target_user_id > 0
            and target_user_id != user_id
            and not claim_id
        ):
            raise ValueError("Invite belongs to another Telegram user")
        target_phone = str(invite.get("target_phone_hint") or "").strip()
        target_username = str(invite.get("target_username_hint") or "").strip()
        if target_phone and not target_username and not isinstance(target_user_id, int) and not claim_id:
            raise ValueError("Phone invite requires admin approval")

        accepted_at = format_timestamp(now)
        used_count = invite.get("used_count")
        if not isinstance(used_count, int) or used_count < 0:
            used_count = 0
        invite["status"] = INVITE_STATUS_ACCEPTED
        invite["target_user_id"] = user_id
        invite["used_count"] = used_count + 1
        invite["accepted_at"] = accepted_at
        invite["accepted_by"] = user_id
        invite["updated_at"] = accepted_at
        invites[invite_id] = invite

        if claim_id:
            claims = payload.setdefault("invite_claims", {})
            claim = claims.get(claim_id)
            if not isinstance(claim, dict):
                raise ValueError("Invite claim was not found")
            if claim.get("status") != INVITE_CLAIM_STATUS_PENDING:
                raise ValueError("Invite claim is not pending")
            if claim.get("invite_id") != invite_id or claim.get("claimant_tg_id") != user_id:
                raise ValueError("Invite claim does not match invite opener")
            claim = dict(claim)
            claim["status"] = INVITE_CLAIM_STATUS_APPROVED
            claim["decided_at"] = accepted_at
            claim["decided_by"] = approved_by
            claim["updated_at"] = accepted_at
            claims[claim_id] = claim

        payload.setdefault("leads", {}).pop(str(user_id), None)
        self.save(payload)

        return {
            "invite": dict(invite),
            "user": self.start_trial(
                user_id=user_id,
                invite_id=invite_id,
                invited_by=int(invite["created_by"]),
                days=int(invite.get("trial_days") or self.trial_period_days()),
                now=now,
            ),
        }

    def cancel_invite(self, invite_id: str) -> dict[str, Any]:
        payload = self.load()
        invites = payload.setdefault("invites", {})
        record = invites.get(invite_id)
        if not isinstance(record, dict):
            raise ValueError("Invite was not found")
        if record.get("status") != INVITE_STATUS_PENDING:
            raise ValueError("Only pending invites can be cancelled")
        now = _timestamp()
        record = dict(record)
        record["status"] = INVITE_STATUS_CANCELLED
        record["revoked_at"] = now
        record["updated_at"] = now
        invites[invite_id] = record
        self.save(payload)
        return dict(record)

    def public_invite_records(self, include_non_pending: bool = True) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for invite_id, record in self.load().get("invites", {}).items():
            if not isinstance(record, dict):
                continue
            if not include_non_pending and record.get("status") != INVITE_STATUS_PENDING:
                continue
            public = dict(record)
            public["id"] = str(record.get("id") or invite_id)
            public.pop("token", None)
            public["token_present"] = bool(record.get("token"))
            records.append(public)
        records.sort(key=_record_sort_key, reverse=True)
        return records

    def public_invite_claim_records(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for claim_id, record in self.load().get("invite_claims", {}).items():
            if not isinstance(record, dict):
                continue
            public = dict(record)
            public["id"] = str(record.get("id") or claim_id)
            records.append(public)
        records.sort(key=_record_sort_key, reverse=True)
        return records

    def record_lead(
        self,
        user_id: int,
        chat_id: int,
        chat_type: str,
        profile: dict[str, Any] | None = None,
        message_text: str = "",
        phone_number: str = "",
    ) -> dict[str, Any]:
        if user_id <= 0:
            raise ValueError("Telegram user id must be positive")
        payload = self.load()
        leads = payload.setdefault("leads", {})
        now = _timestamp()
        key = str(user_id)
        existing = leads.get(key)
        record = dict(existing) if isinstance(existing, dict) else {
            "telegram_user_id": user_id,
            "first_seen_at": now,
            "message_count": 0,
        }
        profile = profile or {}
        record.update(
            {
                "telegram_user_id": user_id,
                "chat_id": chat_id,
                "chat_type": chat_type,
                "username": profile.get("username", record.get("username", "")) or "",
                "first_name": profile.get("first_name", record.get("first_name", "")) or "",
                "last_name": profile.get("last_name", record.get("last_name", "")) or "",
                "language_code": profile.get("language_code", record.get("language_code", "")) or "",
                "phone_number": phone_number or record.get("phone_number", ""),
                "last_message_text": message_text[:200],
                "last_seen_at": now,
                "updated_at": now,
                "message_count": int(record.get("message_count") or 0) + 1,
            }
        )
        leads[key] = record
        self.save(payload)
        return dict(record)

    def public_lead_records(self) -> list[dict[str, Any]]:
        payload = self.load()
        users = payload.get("users", {})
        records: list[dict[str, Any]] = []
        for raw_user_id, record in payload.get("leads", {}).items():
            if raw_user_id in users or not isinstance(record, dict):
                continue
            public = dict(record)
            public.pop("last_message_text", None)
            records.append(public)
        records.sort(key=_record_sort_key, reverse=True)
        return records

    def support_compose_started_at_for_user(self, user_id: int) -> str:
        record = self.user_record(user_id) or {}
        return str(record.get("support_compose_started_at") or "")

    def set_support_compose_started(self, user_id: int) -> dict[str, Any]:
        return self._update_user(user_id, support_compose_started_at=_timestamp())

    def clear_support_compose_started(self, user_id: int) -> dict[str, Any]:
        return self._update_user(user_id, support_compose_started_at="")

    def support_ticket_for_id(self, ticket_id: str) -> dict[str, Any] | None:
        record = self.load().get("support_tickets", {}).get(ticket_id)
        if not isinstance(record, dict):
            return None
        public = dict(record)
        public["ticket_id"] = str(record.get("ticket_id") or ticket_id)
        return public

    def _latest_open_ticket_for_user(self, payload: dict[str, Any], user_id: int) -> tuple[str, dict[str, Any]] | None:
        tickets = payload.setdefault("support_tickets", {})
        matches: list[tuple[str, dict[str, Any]]] = []
        for raw_ticket_id, record in tickets.items():
            if not isinstance(record, dict):
                continue
            if record.get("user_id") != user_id:
                continue
            if record.get("status") != SUPPORT_TICKET_STATUS_OPEN:
                continue
            ticket_id = str(record.get("ticket_id") or raw_ticket_id)
            matches.append((ticket_id, dict(record)))
        matches.sort(key=lambda item: _record_sort_key(item[1]), reverse=True)
        return matches[0] if matches else None

    def _support_ticket_snapshot(self, user_id: int, record: dict[str, Any]) -> dict[str, Any]:
        return {
            "display_name": self.display_name_for_user(user_id),
            "username": str(record.get("username") or ""),
            "first_name": str(record.get("first_name") or ""),
            "last_name": str(record.get("last_name") or ""),
            "preferred_language": str(record.get("preferred_language") or ""),
        }

    def create_or_append_support_ticket(
        self,
        user_id: int,
        message_text: str,
        author: str = "user",
    ) -> dict[str, Any]:
        if user_id <= 0:
            raise ValueError("Telegram user id must be positive")
        text = " ".join((message_text or "").strip().split())
        if not text:
            raise ValueError("Support message must not be empty")
        if author not in {"user", "admin"}:
            raise ValueError("author must be user or admin")

        payload = self.load()
        users = payload.setdefault("users", {})
        user_record = users.get(str(user_id))
        if not isinstance(user_record, dict):
            user_record = self._new_user_record(invited_by=None)
            users[str(user_id)] = user_record

        now = _timestamp()
        existing = self._latest_open_ticket_for_user(payload, user_id)
        if existing is None:
            payload["support_ticket_seq"] = int(payload.get("support_ticket_seq") or 0) + 1
            sequence = payload["support_ticket_seq"]
            ticket_id = f"T{sequence:06d}"
            ticket = {
                "ticket_id": ticket_id,
                "user_id": user_id,
                "status": SUPPORT_TICKET_STATUS_OPEN,
                "created_at": now,
                "updated_at": now,
                "unread_user_messages": 0,
                "unread_total_messages": 0,
                "message_count": 0,
                "last_author": "",
                "last_message_at": "",
                "last_message_excerpt": "",
                "messages": [],
                **self._support_ticket_snapshot(user_id, user_record),
            }
            is_new_ticket = True
        else:
            ticket_id, ticket = existing
            ticket = dict(ticket)
            ticket.update(self._support_ticket_snapshot(user_id, user_record))
            is_new_ticket = False

        messages = ticket.get("messages")
        if not isinstance(messages, list):
            messages = []
        messages = [*messages, {"author": author, "text": text, "created_at": now}]
        ticket["messages"] = messages
        ticket["message_count"] = len(messages)
        ticket["updated_at"] = now
        ticket["last_author"] = author
        ticket["last_message_at"] = now
        ticket["last_message_excerpt"] = _support_message_excerpt(text)
        if author == "user":
            ticket["unread_user_messages"] = int(ticket.get("unread_user_messages") or 0) + 1
            ticket["unread_total_messages"] = int(ticket.get("unread_total_messages") or 0) + 1
        else:
            ticket["unread_user_messages"] = 0
            ticket["unread_total_messages"] = 0
        payload.setdefault("support_tickets", {})[ticket_id] = ticket
        self.save(payload)
        result = dict(ticket)
        result["ticket_id"] = ticket_id
        result["is_new_ticket"] = is_new_ticket
        return result

    def mark_support_ticket_read(self, ticket_id: str) -> dict[str, Any]:
        payload = self.load()
        tickets = payload.setdefault("support_tickets", {})
        record = tickets.get(ticket_id)
        if not isinstance(record, dict):
            raise ValueError("Support ticket was not found")
        updated = dict(record)
        updated["unread_user_messages"] = 0
        updated["unread_total_messages"] = 0
        updated["updated_at"] = _timestamp()
        tickets[ticket_id] = updated
        self.save(payload)
        updated["ticket_id"] = ticket_id
        return updated

    def archive_support_ticket(self, ticket_id: str) -> dict[str, Any]:
        payload = self.load()
        tickets = payload.setdefault("support_tickets", {})
        record = tickets.get(ticket_id)
        if not isinstance(record, dict):
            raise ValueError("Support ticket was not found")
        updated = dict(record)
        updated["status"] = SUPPORT_TICKET_STATUS_ARCHIVED
        updated["unread_user_messages"] = 0
        updated["unread_total_messages"] = 0
        updated["updated_at"] = _timestamp()
        tickets[ticket_id] = updated
        self.save(payload)
        updated["ticket_id"] = ticket_id
        return updated

    def public_support_ticket_records(self, status: str | None = None) -> list[dict[str, Any]]:
        if status is not None and status not in {SUPPORT_TICKET_STATUS_OPEN, SUPPORT_TICKET_STATUS_ARCHIVED}:
            raise ValueError("support status must be open or archived")
        records: list[dict[str, Any]] = []
        for raw_ticket_id, record in self.load().get("support_tickets", {}).items():
            if not isinstance(record, dict):
                continue
            if status is not None and record.get("status") != status:
                continue
            public = dict(record)
            public["ticket_id"] = str(record.get("ticket_id") or raw_ticket_id)
            public.pop("messages", None)
            records.append(public)
        records.sort(key=_record_sort_key, reverse=True)
        return records

    def public_support_ticket_detail(self, ticket_id: str) -> dict[str, Any]:
        record = self.support_ticket_for_id(ticket_id)
        if record is None:
            raise ValueError("Support ticket was not found")
        record.setdefault("messages", [])
        return record

    def support_summary(self, latest_limit: int = 5) -> dict[str, Any]:
        tickets = self.public_support_ticket_records()
        open_tickets = [ticket for ticket in tickets if ticket.get("status") == SUPPORT_TICKET_STATUS_OPEN]
        archived_tickets = [
            ticket for ticket in tickets if ticket.get("status") == SUPPORT_TICKET_STATUS_ARCHIVED
        ]
        unread_user_messages = sum(int(ticket.get("unread_user_messages") or 0) for ticket in open_tickets)
        new_tickets = sum(
            1
            for ticket in open_tickets
            if int(ticket.get("message_count") or 0) == 1
            and int(ticket.get("unread_user_messages") or 0) > 0
        )
        return {
            "counts": {
                "open_tickets": len(open_tickets),
                "archived_tickets": len(archived_tickets),
                "unread_user_messages": unread_user_messages,
                "new_tickets": new_tickets,
            },
            "latest_open_ticket_ids": [ticket.get("ticket_id", "") for ticket in open_tickets[:latest_limit]],
        }

    def public_bonus_ledger_records(
        self,
        user_id: int | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for ledger_id, record in self.load().get("bonus_ledger", {}).items():
            if not isinstance(record, dict):
                continue
            if user_id is not None and record.get("user_id") != user_id:
                continue
            public = dict(record)
            public["id"] = str(record.get("id") or ledger_id)
            records.append(public)
        records.sort(key=_record_sort_key, reverse=True)
        if limit is not None:
            return records[: max(0, limit)]
        return records

    def mark_expiry_notification_sent(self, user_id: int, notification_key: str) -> dict[str, Any]:
        record = self.user_record(user_id) or {}
        sent = record.get("last_expiry_notifications")
        if not isinstance(sent, list):
            sent = []
        if notification_key not in sent:
            sent = [*sent, notification_key]
        return self._update_user(user_id, last_expiry_notifications=sent)

    def _update_user(
        self,
        user_id: int,
        invited_by: int | None = None,
        client_id: str | None = None,
        peer_public_key: str | None = None,
        account_type: str | None = None,
        subscription_expires_at: str | None = None,
        discount_percent: int | None = None,
        trial_started_at: str | None = None,
        trial_expires_at: str | None = None,
        trial_invite_id: str | None = None,
        bonus_balance_stars: int | None = None,
        preferred_language: str | None = None,
        telegram_language_code: str | None = None,
        username: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
        display_name: str | None = None,
        language_prompted_at: str | None = None,
        support_compose_started_at: str | None = None,
        deactivated_at: str | None = None,
        last_expiry_notifications: list[str] | None = None,
    ) -> dict[str, Any]:
        if user_id <= 0:
            raise ValueError("Telegram user id must be positive")

        payload = self.load()
        users = payload.setdefault("users", {})
        now = _timestamp()
        key = str(user_id)
        record = users.get(key)
        if not isinstance(record, dict):
            record = {
                "invited_by": invited_by,
                "client_id": "",
                "peer_public_key": "",
                "account_type": "free",
                "subscription_expires_at": "",
                "discount_percent": 0,
                "trial_started_at": "",
                "trial_expires_at": "",
                "trial_invite_id": "",
                "bonus_balance_stars": 0,
                "preferred_language": "",
                "telegram_language_code": "",
                "username": "",
                "first_name": "",
                "last_name": "",
                "display_name": "",
                "language_prompted_at": "",
                "support_compose_started_at": "",
                "deactivated_at": "",
                "last_expiry_notifications": [],
                "created_at": now,
                "updated_at": now,
            }
        else:
            record = dict(record)
            record.setdefault("created_at", now)
            if record.get("invited_by") is None and invited_by is not None:
                record["invited_by"] = invited_by
            record.setdefault("client_id", "")
            record.setdefault("peer_public_key", "")
            record.setdefault("account_type", "free")
            record.setdefault("subscription_expires_at", "")
            record.setdefault("discount_percent", 0)
            record.setdefault("trial_started_at", "")
            record.setdefault("trial_expires_at", "")
            record.setdefault("trial_invite_id", "")
            record.setdefault("bonus_balance_stars", 0)
            record.setdefault("preferred_language", "")
            record.setdefault("telegram_language_code", "")
            record.setdefault("username", "")
            record.setdefault("first_name", "")
            record.setdefault("last_name", "")
            record.setdefault("display_name", "")
            record.setdefault("language_prompted_at", "")
            record.setdefault("support_compose_started_at", "")
            record.setdefault("deactivated_at", "")
            record.setdefault("last_expiry_notifications", [])
            record["updated_at"] = now

        if client_id is not None:
            record["client_id"] = client_id
            record["updated_at"] = now
        if peer_public_key is not None:
            record["peer_public_key"] = peer_public_key.strip()
            record["updated_at"] = now
        if account_type is not None:
            if account_type not in {"free", "paid"}:
                raise ValueError("account_type must be free or paid")
            record["account_type"] = account_type
            record["updated_at"] = now
        if subscription_expires_at is not None:
            record["subscription_expires_at"] = subscription_expires_at
            record["updated_at"] = now
        if discount_percent is not None:
            record["discount_percent"] = _clamp_percent(discount_percent)
            record["updated_at"] = now
        if trial_started_at is not None:
            record["trial_started_at"] = trial_started_at
            record["updated_at"] = now
        if trial_expires_at is not None:
            record["trial_expires_at"] = trial_expires_at
            record["updated_at"] = now
        if trial_invite_id is not None:
            record["trial_invite_id"] = trial_invite_id
            record["updated_at"] = now
        if bonus_balance_stars is not None:
            record["bonus_balance_stars"] = max(0, bonus_balance_stars)
            record["updated_at"] = now
        if preferred_language is not None:
            language = normalize_user_language(preferred_language)
            if not language:
                raise ValueError("preferred_language must be ru or en")
            record["preferred_language"] = language
            record["updated_at"] = now
        if telegram_language_code is not None:
            record["telegram_language_code"] = telegram_language_code.strip().lower()
            record["updated_at"] = now
        if username is not None:
            record["username"] = normalize_telegram_username(username)
            record["updated_at"] = now
        if first_name is not None:
            record["first_name"] = _normalize_profile_text(first_name)
            record["updated_at"] = now
        if last_name is not None:
            record["last_name"] = _normalize_profile_text(last_name)
            record["updated_at"] = now
        if display_name is not None:
            record["display_name"] = _normalize_profile_text(display_name)
            record["updated_at"] = now
        if language_prompted_at is not None:
            record["language_prompted_at"] = language_prompted_at
            record["updated_at"] = now
        if support_compose_started_at is not None:
            record["support_compose_started_at"] = support_compose_started_at
            record["updated_at"] = now
        if deactivated_at is not None:
            record["deactivated_at"] = deactivated_at
            record["updated_at"] = now
        if last_expiry_notifications is not None:
            record["last_expiry_notifications"] = list(last_expiry_notifications)
            record["updated_at"] = now

        users[key] = record
        self.save(payload)
        return dict(record)

    def _normalize_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        users = payload.get("users")
        if users is None:
            payload["users"] = {}
        elif not isinstance(users, dict):
            raise ValueError(f"Telegram access users must be a JSON object: {self.path}")

        settings = payload.get("settings")
        if settings is None:
            settings = {}
            payload["settings"] = settings
        elif not isinstance(settings, dict):
            raise ValueError(f"Telegram access settings must be a JSON object: {self.path}")
        settings.setdefault("subscription_price_stars", DEFAULT_SUBSCRIPTION_PRICE_STARS)
        settings.setdefault("subscription_period_days", DEFAULT_SUBSCRIPTION_PERIOD_DAYS)
        settings.setdefault(
            "subscription_max_12m_discount_percent",
            DEFAULT_SUBSCRIPTION_MAX_12M_DISCOUNT_PERCENT,
        )
        settings.setdefault("trial_period_days", DEFAULT_TRIAL_PERIOD_DAYS)
        settings.setdefault("invite_ttl_days", DEFAULT_INVITE_TTL_DAYS)
        settings.setdefault("referral_bonus_percent", DEFAULT_REFERRAL_BONUS_PERCENT)
        if not isinstance(settings.get("subscription_max_12m_discount_percent"), int):
            settings["subscription_max_12m_discount_percent"] = (
                DEFAULT_SUBSCRIPTION_MAX_12M_DISCOUNT_PERCENT
            )
        settings["subscription_max_12m_discount_percent"] = _clamp_percent(
            settings["subscription_max_12m_discount_percent"]
        )
        if not isinstance(settings.get("invite_ttl_days"), int) or settings["invite_ttl_days"] <= 0:
            settings["invite_ttl_days"] = DEFAULT_INVITE_TTL_DAYS

        payments = payload.get("payments")
        if payments is None:
            payload["payments"] = {}
        elif not isinstance(payments, dict):
            raise ValueError(f"Telegram access payments must be a JSON object: {self.path}")

        invites = payload.get("invites")
        if invites is None:
            payload["invites"] = {}
        elif not isinstance(invites, dict):
            raise ValueError(f"Telegram access invites must be a JSON object: {self.path}")

        invite_claims = payload.get("invite_claims")
        if invite_claims is None:
            payload["invite_claims"] = {}
        elif not isinstance(invite_claims, dict):
            raise ValueError(f"Telegram access invite claims must be a JSON object: {self.path}")

        leads = payload.get("leads")
        if leads is None:
            payload["leads"] = {}
        elif not isinstance(leads, dict):
            raise ValueError(f"Telegram access leads must be a JSON object: {self.path}")

        support_tickets = payload.get("support_tickets")
        if support_tickets is None:
            payload["support_tickets"] = {}
        elif not isinstance(support_tickets, dict):
            raise ValueError(f"Telegram access support_tickets must be a JSON object: {self.path}")

        support_ticket_seq = payload.get("support_ticket_seq")
        if support_ticket_seq is None:
            payload["support_ticket_seq"] = 0
        elif not isinstance(support_ticket_seq, int) or support_ticket_seq < 0:
            raise ValueError(f"Telegram access support_ticket_seq must be a non-negative integer: {self.path}")

        bonus_ledger = payload.get("bonus_ledger")
        if bonus_ledger is None:
            payload["bonus_ledger"] = {}
        elif not isinstance(bonus_ledger, dict):
            raise ValueError(f"Telegram access bonus ledger must be a JSON object: {self.path}")

        now = datetime.now(timezone.utc)
        for invite_id, record in payload["invites"].items():
            if not isinstance(record, dict):
                continue
            record.setdefault("id", str(invite_id))
            record.setdefault("status", INVITE_STATUS_PENDING)
            record.setdefault("target_username_hint", "")
            record.setdefault("target_phone_hint", "")
            record.setdefault("target_user_id", None)
            record.setdefault("trial_days", settings["trial_period_days"])
            record.setdefault("max_uses", DEFAULT_INVITE_MAX_USES)
            if not isinstance(record.get("used_count"), int):
                record["used_count"] = 1 if record.get("status") == INVITE_STATUS_ACCEPTED else 0
            created_at = parse_timestamp(record.get("created_at")) or now
            record.setdefault("created_at", format_timestamp(created_at))
            record.setdefault("updated_at", record.get("created_at", format_timestamp(created_at)))
            if parse_timestamp(record.get("expires_at")) is None:
                record["expires_at"] = format_timestamp(
                    created_at + timedelta(days=int(settings["invite_ttl_days"]))
                )
            record.setdefault("accepted_at", "")
            record.setdefault("accepted_by", record.get("target_user_id"))
            record.setdefault("revoked_at", "")

        for claim_id, record in payload["invite_claims"].items():
            if not isinstance(record, dict):
                continue
            record.setdefault("id", str(claim_id))
            record.setdefault("invite_id", "")
            record.setdefault("claimant_tg_id", None)
            record.setdefault("claimant_username", "")
            record.setdefault("status", INVITE_CLAIM_STATUS_PENDING)
            record.setdefault("created_at", _timestamp())
            record.setdefault("updated_at", record.get("created_at", ""))
            record.setdefault("decided_at", "")
            record.setdefault("decided_by", None)

        for raw_ticket_id, record in payload["support_tickets"].items():
            if not isinstance(record, dict):
                continue
            record["ticket_id"] = str(record.get("ticket_id") or raw_ticket_id)
            record.setdefault("user_id", None)
            record.setdefault("status", SUPPORT_TICKET_STATUS_OPEN)
            if record["status"] not in {SUPPORT_TICKET_STATUS_OPEN, SUPPORT_TICKET_STATUS_ARCHIVED}:
                record["status"] = SUPPORT_TICKET_STATUS_OPEN
            record.setdefault("display_name", "")
            record.setdefault("username", "")
            record.setdefault("first_name", "")
            record.setdefault("last_name", "")
            record.setdefault("preferred_language", "")
            record.setdefault("created_at", _timestamp())
            record.setdefault("updated_at", record.get("created_at", ""))
            record.setdefault("unread_user_messages", 0)
            record.setdefault("unread_total_messages", 0)
            record.setdefault("message_count", 0)
            record.setdefault("last_author", "")
            record.setdefault("last_message_at", "")
            record.setdefault("last_message_excerpt", "")
            messages = record.get("messages")
            if not isinstance(messages, list):
                messages = []
            normalized_messages: list[dict[str, Any]] = []
            for item in messages:
                if not isinstance(item, dict):
                    continue
                author = str(item.get("author") or "")
                if author not in {"user", "admin"}:
                    continue
                normalized_messages.append(
                    {
                        "author": author,
                        "text": str(item.get("text") or ""),
                        "created_at": str(item.get("created_at") or _timestamp()),
                    }
                )
            record["messages"] = normalized_messages
            record["message_count"] = int(record.get("message_count") or len(normalized_messages))

        for record in payload["users"].values():
            if not isinstance(record, dict):
                continue
            record.setdefault("client_id", "")
            record.setdefault("peer_public_key", "")
            record.setdefault("account_type", "free")
            record.setdefault("subscription_expires_at", "")
            record.setdefault("discount_percent", 0)
            record.setdefault("trial_started_at", "")
            record.setdefault("trial_expires_at", "")
            record.setdefault("trial_invite_id", "")
            record.setdefault("bonus_balance_stars", 0)
            record.setdefault("preferred_language", "")
            if normalize_user_language(record.get("preferred_language")) != record.get("preferred_language"):
                record["preferred_language"] = normalize_user_language(record.get("preferred_language"))
            record.setdefault("telegram_language_code", "")
            record.setdefault("username", "")
            record["username"] = normalize_telegram_username(record.get("username", ""))
            record.setdefault("first_name", "")
            record["first_name"] = _normalize_profile_text(record.get("first_name", ""))
            record.setdefault("last_name", "")
            record["last_name"] = _normalize_profile_text(record.get("last_name", ""))
            record.setdefault("display_name", "")
            record["display_name"] = telegram_display_name(
                username=record.get("username", ""),
                first_name=record.get("first_name", ""),
                last_name=record.get("last_name", ""),
            ) or _normalize_profile_text(record.get("display_name", ""))
            record.setdefault("language_prompted_at", "")
            record.setdefault("support_compose_started_at", "")
            record.setdefault("deactivated_at", "")
            record.setdefault("last_expiry_notifications", [])

        return payload

    def _append_bonus_ledger_entry(
        self,
        payload: dict[str, Any],
        user_id: int,
        amount_stars: int,
        kind: str,
        source_payment_payload: str = "",
        related_user_id: int | None = None,
        save: bool = False,
    ) -> dict[str, Any]:
        users = payload.setdefault("users", {})
        key = str(user_id)
        user_record = users.get(key)
        if not isinstance(user_record, dict):
            user_record = self._new_user_record(invited_by=None)
        else:
            user_record = dict(user_record)
        current_balance = user_record.get("bonus_balance_stars")
        if not isinstance(current_balance, int):
            current_balance = 0
        new_balance = max(0, current_balance + amount_stars)
        now = _timestamp()
        user_record["bonus_balance_stars"] = new_balance
        user_record["updated_at"] = now
        users[key] = user_record

        ledger = payload.setdefault("bonus_ledger", {})
        ledger_id = uuid.uuid4().hex
        entry = {
            "id": ledger_id,
            "user_id": user_id,
            "amount_stars": amount_stars,
            "balance_after_stars": new_balance,
            "kind": kind,
            "source_payment_payload": source_payment_payload,
            "related_user_id": related_user_id,
            "created_at": now,
            "updated_at": now,
        }
        ledger[ledger_id] = entry
        if save:
            self.save(payload)
        return dict(entry)

    def _new_user_record(self, invited_by: int | None) -> dict[str, Any]:
        now = _timestamp()
        return {
            "invited_by": invited_by,
            "client_id": "",
            "peer_public_key": "",
            "account_type": "free",
            "subscription_expires_at": "",
            "discount_percent": 0,
            "trial_started_at": "",
            "trial_expires_at": "",
            "trial_invite_id": "",
            "bonus_balance_stars": 0,
            "preferred_language": "",
            "telegram_language_code": "",
            "username": "",
            "first_name": "",
            "last_name": "",
            "display_name": "",
            "language_prompted_at": "",
            "support_compose_started_at": "",
            "deactivated_at": "",
            "last_expiry_notifications": [],
            "created_at": now,
            "updated_at": now,
        }
