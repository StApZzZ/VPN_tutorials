from __future__ import annotations

import asyncio
import json
from typing import Any

import config
import telegram_access as ta
import telegram_bot as tb
import xray_clients as xc
import xray_manager as xm


def _telegram_access_store() -> ta.TelegramAccessStore:
    admin_ids = ta.parse_id_set(
        config.TELEGRAM_ADMIN_USER_IDS.strip() or config.TELEGRAM_ALLOWED_CHAT_IDS
    )
    return ta.TelegramAccessStore(
        path=config.TELEGRAM_ACCESS_PATH,
        admin_user_ids=admin_ids,
    )


async def backfill_telegram_client_names(
    telegram: tb.TelegramClient,
    access: ta.TelegramAccessStore,
) -> dict[str, Any]:
    clients = {client.id: client for client in xc.list_clients()}
    snapshot = xc.snapshot_clients()
    report: dict[str, Any] = {
        "total_users": 0,
        "bound_users": 0,
        "renamed": 0,
        "unchanged": 0,
        "skipped_unbound": 0,
        "skipped_missing_client": 0,
        "skipped_missing_profile_name": 0,
        "skipped_profile_lookup": 0,
        "applied": False,
        "renamed_clients": [],
        "profile_errors": [],
    }
    changed = False

    for user_id in sorted(access.all_user_records()):
        report["total_users"] += 1
        record = access.user_record(user_id) or {}
        client_id = str(record.get("client_id") or "").strip()
        if not client_id:
            report["skipped_unbound"] += 1
            continue

        report["bound_users"] += 1
        client = clients.get(client_id)
        if client is None:
            report["skipped_missing_client"] += 1
            continue

        try:
            profile = await telegram.get_chat(user_id)
        except Exception as exc:
            report["skipped_profile_lookup"] += 1
            report["profile_errors"].append(
                {
                    "telegram_user_id": user_id,
                    "client_id": client_id,
                    "error": str(exc),
                }
            )
            continue

        updated = access.update_user_profile(user_id, profile)
        display_name = str(updated.get("display_name") or "").strip()
        if not display_name:
            report["skipped_missing_profile_name"] += 1
            continue

        desired_name = access.desired_client_name_for_user(
            user_id,
            existing_name=client.name,
            default_name=f"Telegram {user_id}",
        )
        if desired_name == client.name:
            report["unchanged"] += 1
            continue

        old_name = client.name
        client = xc.update_client(client_id, name=desired_name, email=client.email)
        clients[client_id] = client
        changed = True
        report["renamed"] += 1
        report["renamed_clients"].append(
            {
                "telegram_user_id": user_id,
                "client_id": client_id,
                "old_name": old_name,
                "new_name": desired_name,
            }
        )

    if changed:
        try:
            xm.apply_xray()
        except Exception:
            xc.restore_clients(snapshot)
            raise
        report["applied"] = True

    return report


async def _main() -> int:
    if not config.TELEGRAM_BOT_TOKEN.strip():
        raise RuntimeError("TELEGRAM_BOT_TOKEN must be configured")

    telegram = tb.TelegramClient(
        token=config.TELEGRAM_BOT_TOKEN,
        timeout=config.TELEGRAM_REQUEST_TIMEOUT,
        proxy_url=config.TELEGRAM_PROXY_URL or None,
    )
    try:
        report = await backfill_telegram_client_names(
            telegram=telegram,
            access=_telegram_access_store(),
        )
    finally:
        await telegram.aclose()

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
