# Quickstart — Full Cascade Installation

This guide walks you through a complete two-server VPN setup from scratch. You fill in one config file; the installer does everything else.

## Architecture

```
User's device
    │
    │  VLESS/REALITY (port 443)
    ▼
 Server A — ingress node
 • Runs the VPN Panel (web UI + API)
 • Runs Xray: accepts user connections
 • Routes "relay" traffic to Server B
    │
    │  VLESS/REALITY (port 443, internal uplink)
    ▼
 Server B — egress/relay node  [optional]
 • Runs Xray: receives traffic from A, exits to the internet
 • No panel, no extra software
```

Single-server mode (no Server B) is also supported — just leave `SERVER_B_IP` empty.

## What the installer does automatically

1. Verifies SSH connectivity to both servers.
2. Installs [Xray-core](https://github.com/XTLS/Xray-core) on both servers.
3. Generates REALITY keypairs on each server using `xray x25519`.
4. Generates a UUID for the internal A→B uplink connection.
5. Builds Xray configuration files for Server A (ingress) and Server B (egress).
6. Generates Ansible inventory, variables, and secrets files from the repository examples.
7. Deploys the VPN Panel to Server A via Ansible (Python environment, systemd units, nginx).
8. Uploads Xray configs to both servers and starts the Xray service.
9. Prints a summary with the panel URL and public keys.

## Prerequisites

| What | Details |
|------|---------|
| **Server A** | systemd-based Debian-like or Oracle/RHEL-like Linux, root SSH access, public IP, port 443 open |
| **Server B** | Same requirements; leave `SERVER_B_IP` empty to skip |
| **Domain** | Optional but recommended — point an A record to Server A |
| **SSH key** | An ED25519 or RSA key with access to both servers |
| **Telegram bot** | Optional — create via [@BotFather](https://t.me/BotFather) if you want the bot |
| **Installer machine** | Linux / macOS / WSL on Windows with: `bash`, `ssh`, `scp`, `ansible-playbook`, `curl`, `python3` |

The installer bootstraps the minimal server-side packages needed for Xray (`curl`, `ca-certificates`, `openssl`) before downloading and installing Xray itself.

Install Ansible if missing:
```bash
pip3 install --user ansible
```

## Step 1 — Clone and configure

```bash
git clone <repository-url>
cd my-vpn
cp deploy/quickstart.env.example deploy/quickstart.env
```

Open `deploy/quickstart.env` in any text editor and fill in the fields. The file is self-documented. Minimum required:

```bash
SERVER_A_IP=1.2.3.4            # your Server A public IP
SSH_KEY=~/.ssh/id_ed25519      # path to your SSH private key
PANEL_SECRET_TOKEN=...         # generate with: openssl rand -base64 32
```

For a two-server setup, also add:

```bash
SERVER_B_IP=5.6.7.8            # your Server B public IP
```

For Telegram bot (optional):

```bash
TELEGRAM_BOT_TOKEN=123456:ABC...
TELEGRAM_ADMIN_IDS=123456789   # your Telegram user ID (find it via @userinfobot)
TELEGRAM_BOT_USERNAME=my_vpn_bot
```

In a two-server installation, quickstart checks Telegram Bot API reachability and deploys the bot on Server B. If Server B cannot reach Telegram, the installer stops instead of silently falling back to Server A.

All other fields have safe defaults and can be left empty.

## Step 2 — Run the installer

**Linux / macOS / WSL:**
```bash
bash deploy/quickstart.sh
```

**Windows PowerShell** (uses WSL automatically if available):
```powershell
.\deploy\quickstart.ps1
```

The installer prints progress for each step and exits with an error message if anything fails.

Typical runtime: 3–5 minutes for a single-server setup, 5–8 minutes for two servers.

## Step 3 — First steps after installation

### Open the panel

Navigate to `http://<Server A IP or domain>/` in your browser. Enter your `PANEL_SECRET_TOKEN` as the password.

### Add the first VPN client

1. Go to **Xray / VLESS clients** in the dashboard.
2. Click **Add client** and give it a name.
3. Click **Share** to get the `vless://` link, QR code, or Xray client JSON.
4. Import the config into [AmneziaVPN](https://amnezia.org/downloads) or any Xray-compatible client.

### Set up routing rules (two-server only)

After adding clients:

1. Go to **Routing** in the dashboard.
2. Add overrides for destinations that should go through Server B (relay) vs. direct.
3. Click **Export**, then **Validate**, then **Apply + Reload**.

The panel handles all Xray config merging and reloading automatically.

### Invite users via Telegram bot (if configured)

1. Open Telegram and send `/start` to your bot from your admin account.
2. Use `/newfor <@username>` to generate an invite link for a new user.
3. The user follows the invite link, the bot guides them through setup.

## Troubleshooting

| Symptom | Check |
|---------|-------|
| SSH connection refused | Confirm the server is reachable on port 22; check firewall rules |
| Xray install fails | The server needs internet access; check DNS and outbound connectivity |
| Panel returns 502 Bad Gateway | `systemctl status vpn-panel.service` on Server A |
| Xray not starting | `journalctl -u xray -n 50` on the relevant server; check config with `xray run -test -config /etc/xray/config.json` |
| Bot not responding | `systemctl status vpn-panel-telegram-bot.service`; verify `TELEGRAM_BOT_TOKEN` in `/opt/vpn-panel/.env` |
| Client cannot connect | Check that Xray is running (`systemctl status xray`); verify port 443 is open; try re-importing the client config from the panel |

## Re-running the installer

The installer is idempotent for the panel-related Ansible steps (panel, nginx, systemd units). Re-running it will:
- Skip SSH key validation if keys are already set (if you pre-configure `SERVER_A_REALITY_*` in quickstart.env).
- Regenerate Xray keys if the `SERVER_*_REALITY_*` fields are left empty — this will break existing client configs.
- Overwrite generated Ansible files.

To update only the panel without touching Xray, use `deploy/run.sh` or `deploy/run.ps1` directly instead of quickstart.

## Generated files (gitignored)

The installer creates these files locally — they are gitignored and must not be committed:

| File | Contents |
|------|---------|
| `deploy/quickstart.env` | Your config with secrets |
| `deploy/ansible/inventory/hosts.yml` | Server address |
| `deploy/ansible/group_vars/all.yml` | Non-secret deploy variables |
| `deploy/ansible/group_vars/all.secrets.yml` | Tokens and credentials |

Back these up securely — you will need them to redeploy or update.
