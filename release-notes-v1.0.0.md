# Release v1.0.0 (Initial Public Release)

We are excited to announce the first public open-source release of the VPN Panel!

## Highlights

- **FastAPI Management Panel**: A lightweight, token-secured REST API and web dashboard for managing VPN client connectivity, subscriptions, and routing.
- **Xray / VLESS Integration**: First-class support for managing VLESS/Reality clients alongside dynamic Xray routing generation with a built-in proxy preview.
- **Telegram Bot Onboarding**: A comprehensive Telegram bot capable of:
  - Invite generation and strict token-based onboarding.
  - Multi-language support (RU / EN) with auto-detection.
  - Telegram Stars billing integration for managing paid subscriptions.
  - Delivery of secure artifact bundles, deep links (`vless://`), and QR codes.
- **Ansible Deployment Automation**: A hybrid v1 deployment playbook for deploying the panel and bot natively on Ubuntu with integrated systemd services and Nginx reverse proxy.
- **Configurable DSL**: A web UI editable DSL for configuring help texts, custom download links, and app mirrors within the bot.

## Deployment

Refer to our `README.md` for instructions on using the v1 Ansible automation script `deploy/run.sh` to install the service on a bare-metal Ubuntu host.

## Note on Legacy Transport

In this release, WireGuard has been transitioned to a fallback/diagnostic role. Xray/VLESS is the primary supported routing transport.