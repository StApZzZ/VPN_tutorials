# Agent Guide: `deploy/`

This file describes the deployment layer for LLMs working on provisioning and automation.

## What Lives Here

Deployment automation for the VPN Panel application: Ansible playbook, roles, config templates, and operator entry-point scripts.

## Directory Structure

```
deploy/
├── run.sh                          # Linux/macOS entry point
├── run.ps1                         # Windows (PowerShell) entry point
└── ansible/
    ├── site.yml                    # Main playbook
    ├── ansible.cfg                 # Ansible configuration
    ├── inventory/
    │   └── hosts.yml.example       # Inventory template
    ├── group_vars/
    │   ├── all.yml.example         # Deploy variables template
    │   └── all.secrets.yml.example # Secrets template → copy to all.secrets.yml
    └── roles/
        ├── common/tasks/main.yml   # OS-level setup: packages, dirs, firewall
        ├── app/
        │   ├── tasks/main.yml      # App install: virtualenv, pip, .env, units
        │   └── templates/          # Jinja2 templates rendered on deploy
        │       ├── env.j2                          → .env
        │       ├── awg_settings.json.j2            → awg_settings.json
        │       ├── vpn-panel.service.j2            → systemd unit
        │       └── vpn-panel-telegram-bot.service.j2 → systemd unit
        ├── nginx/tasks/main.yml    # Nginx install + reverse proxy config
        └── smoke/tasks/main.yml    # Post-deploy health checks
```

## Entry Points

`run.sh` and `run.ps1` are thin wrappers that:
1. Check that Ansible is available.
2. Resolve paths to inventory and secrets.
3. Call `ansible-playbook site.yml` with appropriate flags.

Pass `--host <ip>` and `--ssh-key <path>` to override inventory defaults.

## Playbook Roles

| Role | What it does |
|------|-------------|
| `common` | Install system packages (Python, nginx, etc.), create app directories, set file permissions |
| `app` | Deploy Python virtualenv, install `requirements.txt`, render `.env` from `env.j2`, install and enable systemd units |
| `nginx` | Install nginx config, enable the reverse proxy to `127.0.0.1:8080` |
| `smoke` | Verify systemd services are active, hit `/health`, optionally test bot connectivity |

## Feature Toggles (group_vars)

| Variable | Default | Effect |
|----------|---------|--------|
| `panel_enabled` | `true` | Deploy the web panel; required for all other features |
| `telegram_bot_enabled` | `false` | Deploy and enable the Telegram bot service; requires bot token and admin IDs |
| `nginx_enabled` | `true` | Deploy the nginx reverse proxy; disable only for private installs or external proxy |
| `xray_bootstrap_enabled` | `false` | Not in the Ansible path; `deploy/quickstart.sh` handles full Xray bootstrap outside the playbook |
| `wireguard_fallback_enabled` | `false` | Not in v1; future role placeholder |
| `tls_issuance_enabled` | `false` | Not in v1; Let's Encrypt automation is future work |

## Secret Files (gitignored, never commit)

| File | Purpose |
|------|---------|
| `ansible/group_vars/all.secrets.yml` | Live secrets: bot token, panel token, admin IDs |
| `ansible/group_vars/all.yml` | Runtime vars with real host values |
| `ansible/inventory/hosts.yml` | Real server addresses |

Always copy from the `.example` counterparts and fill in real values locally.

## Invariants

- Public deploy docs must never contain live secrets, real IPs, or local paths.
- `telegram_bot_enabled=true` without `panel_enabled=true` is unsupported.
- Xray and WireGuard bootstrap are not part of the Ansible playbook; use `deploy/quickstart.sh` for full bootstrap or pre-provision them manually before running `deploy/run.sh`.
- If billing or Telegram bot env model changes, verify that `env.j2` and `all.yml.example` stay consistent with the new variables.

## Validate Before Running

```bash
ansible-playbook --syntax-check deploy/ansible/site.yml
```
