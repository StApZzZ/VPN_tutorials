# VPN Panel

Open-source educational management panel for self-hosted private network
infrastructure with dynamic per-destination routing.

Provides a web dashboard, HTTP API, and an optional Telegram bot for user management, access management and client configuration delivery for lawful private deployments.

## What's Inside

- FastAPI panel in `amnezia-panel-src/`
- Optional Telegram bot for invite flow, onboarding, and subscription management
- Role-based Telegram menu for user and admin scenarios
- Editable unified Telegram bot content (help, apps, install, menu) via the dashboard UI
- VLESS/Xray client management with REALITY transport
- WireGuard and AmneziaWG peer management
- Dynamic per-destination routing rules with live preview and export
- JSON-backed store for access control, billing state, and support tickets
- Ansible-based deployment automation in `deploy/ansible/`

## Capabilities

- Web dashboard for peer and client management
- Multi-protocol support: VLESS/Xray (REALITY transport), WireGuard, AmneziaWG
- Per-destination routing rules: direct, relay, or block — with live preview before applying
- Xray config export, validation, and reload via the dashboard
- Optional Telegram bot: invite flow, trial access, subscription management, support tickets
- Optional billing integration via Telegram Stars (for jurisdictions where this is a permitted business activity)
- Role-based Telegram menu: separate flows for users and administrators
- Smoke-friendly `/health` endpoint and systemd-compatible services

## Optional Features

The Telegram bot — including invite flow, subscription management, and Telegram Stars billing — is **fully optional**. The core panel (web UI, routing management, API) runs standalone without any Telegram integration.

To deploy without the bot, set `telegram_bot_enabled: false` in your Ansible vars (this is the default).

Billing via Telegram Stars is optional and intended only for lawful use cases
in jurisdictions where operating such services and accepting such payments is permitted.

## Secrets and Repository

Never commit to this repository:

- `.env` or any runtime secrets
- Telegram bot tokens, panel tokens, admin or chat IDs
- Client configs, smoke bundles, or WireGuard/VLESS artifacts
- Local notes and private runbook files

The root `.gitignore` excludes all sensitive and local artifacts. Rotate all tokens and keys before any public server exposure.

## Quick Local Start

1. Create a virtualenv.
2. Install dependencies from `amnezia-panel-src/requirements.txt`.
3. Copy `amnezia-panel-src/.env.example` to `amnezia-panel-src/.env`.
4. Fill in at least `PANEL_SECRET_TOKEN`.
5. Start the panel:

```bash
cd amnezia-panel-src
python3 -m uvicorn main:app --host 127.0.0.1 --port 8080
```

To also run the Telegram bot, fill in the Telegram-related variables and run:

```bash
cd amnezia-panel-src
python3 telegram_bot.py
```

## Configuration

The environment variable template is at [amnezia-panel-src/.env.example](amnezia-panel-src/.env.example).

Minimum required for a local run:

- `PANEL_SECRET_TOKEN`

Additionally required for the Telegram bot:

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_ADMIN_USER_IDS`
- `TELEGRAM_PANEL_TOKEN` (or reuse `PANEL_SECRET_TOKEN`)

All Xray, WireGuard, and path variables in the example config are intentionally templated. Set them for your infrastructure.

## Public Deployment (v1)

The repository includes two deployment paths:

Panel-only deploy via Ansible:
- [deploy/run.sh](deploy/run.sh)
- [deploy/run.ps1](deploy/run.ps1)
- [deploy/ansible/site.yml](deploy/ansible/site.yml)

Full bootstrap quickstart:
- [deploy/quickstart.sh](deploy/quickstart.sh)
- [deploy/quickstart.ps1](deploy/quickstart.ps1)

The Ansible path deploys the panel stack and expects Xray to already exist on the target host.
The quickstart path is the full bootstrap installer for systemd-based Debian-like and Oracle/RHEL-like hosts: it installs Xray, generates REALITY keys, writes Xray configs, deploys the panel, and starts services. When the Telegram bot is enabled in a two-server setup, quickstart probes Telegram reachability and pins the bot to Server B so the panel can stay on Server A.

Example:

```bash
cp deploy/ansible/group_vars/all.secrets.yml.example \
   deploy/ansible/group_vars/all.secrets.yml
./deploy/run.sh --host 203.0.113.10 --ssh-key ~/.ssh/id_ed25519
```

```powershell
Copy-Item deploy\ansible\group_vars\all.secrets.yml.example `
          deploy\ansible\group_vars\all.secrets.yml
.\deploy\run.ps1 -TargetHost 203.0.113.10 -SshKey $HOME\.ssh\id_ed25519
```

What v1 automates:

- Application directory and state files
- Python dependencies and virtualenv
- `.env` from template
- systemd units for the panel and the Telegram bot
- Nginx reverse proxy to `127.0.0.1:8080`
- Post-deploy smoke checks

What the Ansible path does not automate:

- Xray installation or bootstrap
- WireGuard installation or bootstrap
- TLS certificate issuance
- Full two-host provisioning (ingress + egress nodes)

Use `deploy/quickstart.sh` or `deploy/quickstart.ps1` when you want the repository to bootstrap Xray and the two-host ingress/egress layout from scratch.

After deployment, admins can edit `/help`, `/apps`, `/install`, and the Telegram menu structure through the dashboard. Changes are persisted in a DSL config file on the server.

### Deploy Options

| Toggle | Default | Depends on | V1 status | Notes |
|--------|---------|------------|-----------|-------|
| `panel_enabled` | `true` | — | supported | Base component; required for all other features. |
| `telegram_bot_enabled` | `false` | `panel_enabled=true` | supported | Requires bot token, admin IDs, and panel token. Bot-only install is not supported. |
| `nginx_enabled` | `true` | `panel_enabled=true` | supported | Disable only for localhost/private installs or when using an external reverse proxy. |
| `xray_bootstrap_enabled` | `false` | future | future | The Ansible path does not install or configure Xray from scratch; use `deploy/quickstart.sh` for full bootstrap. |
| `wireguard_fallback_enabled` | `false` | future | future | Legacy/backlog option, outside current public deploy. |
| `tls_issuance_enabled` | `false` | `nginx_enabled=true` + public DNS | future | Let's Encrypt automation is not part of v1. |

### Post-Deploy Smoke Checklist

1. Check panel service status: `systemctl status vpn-panel.service`
2. If the Telegram bot is enabled: `systemctl status vpn-panel-telegram-bot.service`
3. Verify the health endpoint locally on the server: `curl -s http://127.0.0.1:8080/health` (should return `{"status":"ok"}`)
4. If nginx is enabled: `systemctl status nginx`
5. Send `/start` or `/help` from an admin account in the Telegram bot to verify connectivity.

## Public Deploy Input Files

- [deploy/ansible/inventory/hosts.yml.example](deploy/ansible/inventory/hosts.yml.example)
- [deploy/ansible/group_vars/all.yml.example](deploy/ansible/group_vars/all.yml.example)
- [deploy/ansible/group_vars/all.secrets.yml.example](deploy/ansible/group_vars/all.secrets.yml.example)

Copy secrets to the local untracked file `deploy/ansible/group_vars/all.secrets.yml`.

## HTTP API

```
GET  /health
GET  /api/xray/doctor
GET  /api/xray/clients
POST /api/xray/clients
GET  /api/xray/clients/{id}/share
GET  /api/xray/clients/{id}/bundle

GET  /api/routing/overrides
POST /api/routing/overrides
PUT  /api/routing/overrides/{id}
POST /api/routing/overrides/{id}/toggle
DELETE /api/routing/overrides/{id}
GET  /api/routing/check?host=<domain>
GET  /api/routing/preview
GET  /api/routing/runtime
POST /api/routing/export
POST /api/routing/validate
POST /api/routing/apply

GET  /api/telegram/billing/summary
PUT  /api/telegram/billing/settings
GET  /api/telegram/users
GET  /api/telegram/payments
GET  /api/telegram/invites
GET  /api/telegram/leads
POST /api/telegram/users/{user_id}/grant
POST /api/telegram/users/{user_id}/revoke
PUT  /api/telegram/users/{user_id}/discount
PUT  /api/telegram/users/{user_id}/expires
```

## Third-Party Acknowledgements

This panel manages [WireGuard](https://www.wireguard.com/) and [AmneziaWG](https://github.com/amnezia-vpn/amnezia-client) infrastructure. AmneziaWG is developed by the AmneziaVPN project. This panel does not include or redistribute AmneziaVPN source code.

Xray-core is developed by the [XTLS project](https://github.com/XTLS/Xray-core). This panel manages Xray server configuration but does not bundle Xray.

WireGuard® is a registered trademark of Jason A. Donenfeld.

See [NOTICE](NOTICE) for full third-party attribution.

## Educational Purpose and Lawful Use

VPN Panel is an educational and self-hosted infrastructure management project.
It is intended for learning, research, and lawful administration of private
network infrastructure.

The project is not intended to bypass access restrictions, provide access to
resources restricted by applicable law, or operate public circumvention services.

The author does not operate a VPN service through this repository and does not
provide access to any third-party networks or restricted resources.

Each operator is solely responsible for deploying, configuring, and using this
software in compliance with the laws and regulations of their jurisdiction,
including rules related to VPN, proxy, tunneling, encryption, telecommunications,
data protection, payments, and user access control.

This repository does not provide legal advice.


## Security Notes

- Public exposure should only go behind TLS.
- Current panel authentication is token-based and intentionally minimal.
- Session hardening, CSRF protection, and stricter cookie policy are in the backlog.
- If real `.env` values or client configs were ever present in the working directory, treat all secrets in them as compromised and rotate before any public server exposure.

## License

## License

MIT License — see [LICENSE](LICENSE). The original copyright notice and license
text must be preserved in copies or substantial portions of the software.

See [NOTICE](NOTICE) for third-party acknowledgements.
