# Agent Guide: `amnezia-panel-src/`

This file describes the application directory for LLMs working on the panel codebase.

## What Lives Here

The core application: a FastAPI web panel and a standalone Telegram bot, sharing a common configuration and data layer.

## File Responsibilities

| File | Responsibility |
|------|---------------|
| `main.py` | FastAPI application: web UI, authentication, all HTTP API endpoints |
| `config.py` | Env-backed configuration via `python-dotenv`. Never hardcode live secrets in defaults. |
| `models.py` | Pydantic data models: `Protocol` enum (`vless`, `wg`, `amneziawg`), client/peer shapes |
| `telegram_bot.py` | Telegram bot: polling loop, update dispatch, all command and callback handlers |
| `telegram_access.py` | JSON store for users, payments, invites, invite claims, support tickets, billing settings |
| `telegram_command_docs.py` | Unified DSL for `/help`, `/apps`, `/install`, `/instruction`, and role-based menu. Persisted on disk; falls back to bundled defaults if no file exists. |
| `vpn_manager.py` | WireGuard peer management: read `wg show`, add/remove peers, sync client table |
| `xray_manager.py` | Xray config lifecycle: export routing fragment, merge with base config, validate, reload |
| `xray_clients.py` | VLESS client record CRUD on top of `xray_clients.json` |
| `client_artifacts.py` | Generate VLESS share artifacts: `vless://` URI, QR code, full Xray client JSON bundle |
| `peer_artifacts.py` | Generate WireGuard / AmneziaWG `.conf` and QR artifacts for a peer |
| `awg_settings.py` | Load/save AmneziaWG obfuscation parameters from a dedicated JSON file |
| `routing_overrides.py` | CRUD for per-destination routing rules: `direct`, `relay`, `block` |
| `telegram_name_backfill.py` | One-shot utility to backfill display names in the access store |
| `static/app.js` | Dashboard frontend (vanilla JS; run `node --check static/app.js` to verify syntax) |
| `templates/` | Jinja2 templates: `login.html`, `dashboard.html` |
| `.env.example` | Configuration template. Copy to `.env` and fill in values. Never commit `.env`. |
| `requirements.txt` | Python dependencies |
| `deploy/` | Static server config examples: nginx, systemd units, Xray base configs |

## Data Flow Between Modules

```
Panel HTTP request
  main.py
  ├── xray_clients.py   → xray_clients.json
  ├── xray_manager.py   → Xray base config, generated routing/merged configs
  ├── routing_overrides.py → routing_overrides.json
  └── vpn_manager.py    → wg0.conf, clientsTable

Telegram update
  telegram_bot.py
  ├── telegram_access.py → telegram_access.json (users, payments, invites, tickets)
  ├── telegram_command_docs.py → telegram_command_docs.conf (menu/help DSL)
  ├── client_artifacts.py → vless:// link, QR, JSON bundle
  └── peer_artifacts.py  → .conf file, QR for WireGuard / AmneziaWG
      └── awg_settings.py → awg_settings.json
```

## Telegram Bot Behavior Invariants

- Unknown Telegram users are silently ignored outside the invite flow.
- All authorization is keyed on `from.id`, never `chat_id`.
- Secret user replies (`vless://`, QR codes, bundles) are sent only in private chat.
- `/link` sends two messages: an explanatory text, then a standalone raw `vless://` for easy copy. Do not merge into one message.
- Invite claims, leads, and accepted invites are separate entities in `telegram_access.py`.
- Persisted command docs (`telegram_command_docs.conf`) are never silently overwritten by code changes; only an explicit reset or dashboard save replaces them.
- Subscription state changes (grant, renew, revoke) must propagate to the bound WireGuard/AmneziaWG peer if one exists.
- Root reply keyboard is shown to known users in private chat. Admins see an extra `Admin` button. Do not break existing `pay:months:*`, `language:set:*`, and invite claim callbacks when editing menu logic.

## Localization

- User language is detected from Telegram `language_code`: `ru*` → `ru`, everything else → `en`.
- On first interaction, authorized non-admin users see a bilingual language selection prompt.
- `/language` allows language change at any time.
- All user-facing strings must have both `ru` and `en` variants. Admin/panel-internal strings can be English-only.

## Billing (Telegram Stars)

The billing system is optional and only active when a bot token and admin IDs are configured.

- `/pay` shows package presets: 1 / 3 / 6 / 12 months.
- Package discounts are computed against `subscription_max_12m_discount_percent`.
- Personal and package discounts stack, capped at 100%.
- If the final amount is 0 after discounts/bonuses, access is activated without issuing an invoice.
- Payment records include `months`, `period_days`, and personal/package/total discount fields.
- Billing UI in the dashboard must stay compatible with these fields.

## Quick Verification

```bash
# From repo root:
python -m unittest discover tests

# Syntax-only check (faster):
cd amnezia-panel-src
python3 -m py_compile config.py main.py telegram_access.py telegram_bot.py \
    telegram_command_docs.py awg_settings.py peer_artifacts.py vpn_manager.py
node --check static/app.js
```

## What to Check After Changes

| Change area | Minimum verification |
|-------------|---------------------|
| Bot / access / docs | `python -m unittest tests.test_telegram_bot` |
| Routing / Xray | `python -m unittest tests.test_routing_overrides` |
| Billing | package discounts 1/3/6/12, stacking, zero-amount activation, payment record fields |
| Menu / docs | default/fallback parsing, root keyboard user/admin visibility, `menu:open:*` and `menu:tap:*` callbacks |
| Shared imports or panel endpoints | panel health endpoint + related API calls |
