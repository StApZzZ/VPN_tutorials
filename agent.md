# Agent Guide: VPN Panel Project

This file describes the repository structure and architecture for LLMs working on this project.

## What This Project Is

A self-hosted management panel for multi-protocol VPN infrastructure. It combines:

- A **FastAPI web panel** for managing VLESS/Xray clients, WireGuard/AmneziaWG peers, and dynamic per-destination routing rules.
- An **optional Telegram bot** for user onboarding, invite flow, subscription management, and Telegram Stars billing.
- An **Ansible-based deployment layer** for automated server provisioning.

Supported protocols: VLESS/Xray (with REALITY transport), WireGuard (raw), AmneziaWG (obfuscated WireGuard).

## Directory Map

```
my-vpn/
├── amnezia-panel-src/   # Core application (FastAPI + Telegram bot)
├── deploy/              # Deployment automation (Ansible + entry scripts)
├── tests/               # Python test suite
├── LICENSE              # MIT License
├── NOTICE               # Third-party attributions
├── README.md            # Public project documentation
└── release-notes-v1.0.0.md
```

## Module Overview

### `amnezia-panel-src/`

The main application. See [amnezia-panel-src/agent.md](amnezia-panel-src/agent.md) for details.

Key files:
- `main.py` — FastAPI app: web UI, auth, all HTTP API endpoints.
- `config.py` — Env-backed configuration. Never return live secrets in defaults.
- `models.py` — Pydantic data models (Protocol enum, client/peer shapes).
- `telegram_bot.py` — Telegram bot runtime: polling loop, command handlers, menus.
- `telegram_access.py` — JSON store for users, payments, invites, tickets, settings.
- `telegram_command_docs.py` — Unified DSL for `/help`, `/apps`, `/install`, `/instruction`, and role-based menu structure. Customisable via the dashboard; falls back to bundled defaults.
- `vpn_manager.py` — WireGuard peer management: add/remove peers, read `wg show`.
- `xray_manager.py` — Xray config management: export routing, validate, reload.
- `xray_clients.py` — VLESS client record management.
- `client_artifacts.py` — Generate VLESS share artifacts (link, QR, JSON bundle).
- `peer_artifacts.py` — Generate WireGuard / AmneziaWG `.conf` and QR artifacts.
- `awg_settings.py` — AmneziaWG obfuscation parameters (loaded from a JSON file).
- `routing_overrides.py` — Manage per-destination routing rules (direct / relay / block).
- `static/app.js` — Dashboard frontend (vanilla JS).
- `templates/` — Jinja2 templates: `login.html`, `dashboard.html`.
- `.env.example` — Configuration template; copy to `.env` and fill in values.
- `requirements.txt` — Python dependencies.
- `deploy/` — Static server config examples (nginx, systemd units, Xray base configs).

### `deploy/`

Deployment automation. See [deploy/agent.md](deploy/agent.md) for details.

- `run.sh` / `run.ps1` — Operator entry points for running Ansible from Linux/Windows.
- `ansible/site.yml` — Main playbook. Roles: `common`, `app`, `nginx`, `smoke`.
- `ansible/ansible.cfg` — Ansible settings.
- `ansible/inventory/hosts.yml.example` — Inventory template.
- `ansible/group_vars/all.yml.example` — Deploy variables template.
- `ansible/group_vars/all.secrets.yml.example` — Secrets template (copy to `all.secrets.yml`).
- `ansible/roles/app/templates/` — Jinja2 templates for `.env`, `awg_settings.json`, systemd units.

### `tests/`

Python `unittest` test suite. See [tests/agent.md](tests/agent.md) for details.

- `test_telegram_bot.py` — Comprehensive bot behavior coverage (invite flow, access policy, billing, menus, localization).
- `test_routing_overrides.py` — Routing API coverage.

## Data Flow

```
Client request
  → nginx (TLS termination)
  → FastAPI panel (main.py)
  → vpn_manager / xray_manager / xray_clients / routing_overrides
  → WireGuard / Xray on the same host

Telegram update
  → telegram_bot.py (polling)
  → telegram_access.py (JSON store for users/payments/invites)
  → panel API (via TELEGRAM_PANEL_BASE_URL) for VLESS client management
  → peer_artifacts / client_artifacts for config delivery
```

## Feature Toggles

All features are controlled via `.env` values and ansible deploy vars:

| Feature | Toggle | Default |
|---------|--------|---------|
| Web panel | `panel_enabled` | `true` |
| Telegram bot | `telegram_bot_enabled` | `false` |
| Nginx reverse proxy | `nginx_enabled` | `true` |
| Xray bootstrap | `xray_bootstrap_enabled` | `false` in the Ansible path; full bootstrap lives in `deploy/quickstart.sh` |
| WireGuard bootstrap | `wireguard_fallback_enabled` | `false` (future) |
| TLS issuance | `tls_issuance_enabled` | `false` (future) |

The Telegram bot (including billing and invite flow) is entirely optional.
The panel works standalone without any Telegram integration.

There are two deployment modes:
- `deploy/run.sh` / `deploy/run.ps1` / Ansible deploy the panel stack only and expect Xray to already exist.
- `deploy/quickstart.sh` / `deploy/quickstart.ps1` are the full bootstrap path for systemd-based Debian-like and Oracle/RHEL-like hosts, including Xray install and REALITY key generation.

## Protocols

- **VLESS/Xray with REALITY** — default user-facing protocol; provides TLS camouflage without a certificate.
- **WireGuard (raw)** — fastest, most recognizable by DPI; suitable for trusted networks.
- **AmneziaWG** — WireGuard fork with obfuscation headers; balances speed and fingerprint resistance.

Protocol selection per user is managed through the Telegram bot (`/wg`, `/awg`) or the web dashboard.

## Invariants — What Must Not Break

- Unknown Telegram users must be silently ignored outside the invite flow.
- All authorization uses `from.id`, never `chat_id`.
- Secret user replies (`vless://`, QR codes, bundles) only in private chat.
- User-facing text must have both `ru` and `en` variants.
- Existing user subscriptions and billing state must survive invite flow changes.
- Leads and accepted invites are separate entities; do not conflate them.
- Persisted command docs must not silently overwrite user customizations.
- `/link` sends two messages: explanatory text first, raw `vless://` second. Do not merge them.

## Running Tests

```bash
# From repo root, with .venv active:
python -m unittest discover tests

# Individual suites:
python -m unittest tests.test_telegram_bot
python -m unittest tests.test_routing_overrides
```

All tests must pass before any deployment. No mocking of the JSON store — tests use in-memory state.

## Local Development

```bash
cd amnezia-panel-src
cp .env.example .env         # fill in PANEL_SECRET_TOKEN at minimum
python3 -m uvicorn main:app --host 127.0.0.1 --port 8080

# In a second terminal, for the bot:
python3 telegram_bot.py
```

## Deployment

```bash
cp deploy/ansible/group_vars/all.secrets.yml.example \
   deploy/ansible/group_vars/all.secrets.yml
# fill in all.secrets.yml

./deploy/run.sh --host <server-ip> --ssh-key ~/.ssh/id_ed25519
```

The playbook provisions: app directory, virtualenv, `.env`, systemd units, nginx, post-deploy smoke checks.

## Security Notes

- Never commit `.env`, `deploy_key`, `all.secrets.yml`, or any client config to git.
- All secrets live in gitignored files only.
- Rotate all tokens before any public exposure of the server.
- The panel auth is token-based and intentionally minimal; expose only behind TLS.
