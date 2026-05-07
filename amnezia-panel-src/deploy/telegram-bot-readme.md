# VPN Panel Telegram Bot

Standalone bot process for VLESS/Xray client operations, role-based access,
invite/onboarding, Telegram Stars payments and subscription maintenance.

## Required env

```text
TELEGRAM_BOT_TOKEN=<bot token from BotFather>
TELEGRAM_BOT_USERNAME=<bot username without @>
TELEGRAM_ALLOWED_CHAT_IDS=<legacy fallback admin user ids>
TELEGRAM_ADMIN_USER_IDS=<comma-separated admin Telegram user ids>
TELEGRAM_ACCESS_PATH=/etc/vpn-panel/telegram_access.json
TELEGRAM_COMMAND_DOCS_PATH=/etc/vpn-panel/telegram_command_docs.conf
TELEGRAM_PANEL_BASE_URL=http://127.0.0.1:8080
TELEGRAM_PANEL_TOKEN=<panel bearer token; may match PANEL_SECRET_TOKEN>
TELEGRAM_PROXY_URL=<optional HTTP proxy, for example http://127.0.0.1:18080>
TELEGRAM_SUBSCRIPTION_CHECK_INTERVAL_SECONDS=300
TELEGRAM_SUBSCRIPTION_NOTIFY_DAYS=3,1,0
```

If `TELEGRAM_ADMIN_USER_IDS` is empty, the bot treats
`TELEGRAM_ALLOWED_CHAT_IDS` as admin IDs for backward compatibility.
Authorization uses Telegram `from.id`, not chat IDs.

## Access store

Telegram subscription users are stored in:

```text
/etc/vpn-panel/telegram_access.json
```

The store contains users, invite claims, leads, bound Xray client IDs, trial
fields, `free`/`paid` status, expiry, per-user discounts, referral bonus
balances and payment records.

Bot command descriptions for `/help`, `/apps`, `/install` and the role-based
Telegram menu are stored together in `TELEGRAM_COMMAND_DOCS_PATH` and can be
edited through the web UI. Bundled defaults include official Amnezia
downloads, official mirror links, stable platform links for clients, official
install/import guides and the default user/admin menu structure. The panel also
exposes a reset action that overwrites the current file with those bundled
defaults.

## Commands

Admin commands:

```text
/clients
/new <name>
/newfor <telegram-user-id> <name>
/invite <@username|+phone|telegram-user-id>
/invites
/leads
/trial [days]
/bonus <telegram-user-id>
/cancelinvite <invite-id>
/bind <telegram-user-id> <client-id>
/link <client-id>
/qr <client-id>
/bundle <client-id>
/enable <client-id>
/disable <client-id>
/delete <client-id>
/doctor
/price [stars]
/discount <telegram-user-id> <percent|clear>
/expires <telegram-user-id> <YYYY-MM-DD>
/grant <telegram-user-id> [days]
/revoke <telegram-user-id>
/status
/apps
/install
```

User commands:

```text
/status
/pay
/link
/qr
/bundle
/apps
/install
/language
```

## Menu UX

- Known users in private chat receive a persistent root keyboard.
- Regular users see user-facing sections only.
- Admins see the same root keyboard plus `Admin`.
- Subsections open through inline buttons.
- Buttons for commands without args execute immediately.
- Buttons for commands with args show a helper card with usage and example
  instead of executing the command blindly.

Invite links use `https://t.me/<bot>?start=<token>` when
`TELEGRAM_BOT_USERNAME` is configured. Username and phone values remain hints;
reliable authorization is always bound to Telegram user ID.

Secrets such as `vless://` links, QR codes and bundles are returned only in
private chat and only for active paid/trial users.

## Telegram Stars payments

1. User runs `/pay`.
2. Bot shows package presets `1 / 3 / 6 / 12` months via callback buttons.
3. After package selection the bot creates a Telegram Stars invoice in `XTR`
   only for the remaining amount after package discount and bonus balance.
4. Bot validates `pre_checkout_query`.
5. On `successful_payment`, the bot records the payment, extends access and
   creates or enables the bound VLESS client.
6. If discounts and bonus reduce the amount to `0`, access is extended
   immediately without creating an invoice.
7. Optional referral bonus balance can be awarded to the inviter.

Official references:

- https://core.telegram.org/bots/payments-stars
- https://core.telegram.org/api/stars
- https://core.telegram.org/method/payments.getStarsRevenueWithdrawalUrl

## Panel integration

The bot talks to the panel through REST API only. Typical local panel URL:

```text
http://127.0.0.1:8080
```

Panel login and API auth use `PANEL_SECRET_TOKEN` or `TELEGRAM_PANEL_TOKEN`
from the deployment environment.

## systemd

```bash
cp /opt/vpn-panel/deploy/vpn-panel-telegram-bot.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vpn-panel-telegram-bot.service
journalctl -u vpn-panel-telegram-bot.service -f
```

## Suggested smoke

1. Admin sends `/doctor`.
2. Admin sends `/price`.
3. Invited user opens `/start <token>`.
4. User sends `/status`.
5. User sends `/pay` and confirms that Telegram invoice is created.
