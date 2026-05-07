import os

from dotenv import load_dotenv

load_dotenv()

EXAMPLE_SERVER_PUBLIC_IP = "203.0.113.10"
EXAMPLE_SERVER_FALLBACK_IP = "198.51.100.20"
PLACEHOLDER_SECRETS = {
    "",
    "changeme",
    "replace_me",
    "replace-with-long-random-token",
    "your-panel-secret-token",
    "example-token",
}


def is_placeholder_secret(value: str) -> bool:
    return value.strip().lower() in PLACEHOLDER_SECRETS


def require_runtime_secret(value: str, env_name: str) -> str:
    secret = value.strip()
    if is_placeholder_secret(secret):
        raise RuntimeError(f"{env_name} must be set to a non-placeholder value")
    return secret


def validate_runtime_config() -> None:
    require_runtime_secret(PANEL_SECRET_TOKEN, "PANEL_SECRET_TOKEN")


PANEL_SECRET_TOKEN = os.getenv("PANEL_SECRET_TOKEN", "").strip()

SERVER_PUBLIC_IP = os.getenv("SERVER_PUBLIC_IP", EXAMPLE_SERVER_PUBLIC_IP)
SERVER_FALLBACK_IP = os.getenv("SERVER_FALLBACK_IP", EXAMPLE_SERVER_FALLBACK_IP)
SERVER_PUBLIC_HOST = os.getenv("SERVER_PUBLIC_HOST", SERVER_PUBLIC_IP).strip() or SERVER_PUBLIC_IP

WG_INTERFACE = os.getenv("WG_INTERFACE", "wg0")
WG_CONFIG_PATH = os.getenv("WG_CONFIG_PATH", "/etc/wireguard/wg0.conf")
WG_PUBLIC_KEY_PATH = os.getenv("WG_PUBLIC_KEY_PATH", "/etc/wireguard/wg0_public.key")
WG_CLIENTS_TABLE = os.getenv("WG_CLIENTS_TABLE", "/etc/wireguard/clientsTable")
CLIENT_PRIVATE_KEYS_PATH = os.getenv(
    "CLIENT_PRIVATE_KEYS_PATH",
    "/etc/wireguard/clientsPrivateKeys.json",
)
AWG_SETTINGS_PATH = os.getenv(
    "AWG_SETTINGS_PATH",
    "/etc/vpn-panel/awg_settings.json",
)

WG_PORT = int(os.getenv("WG_PORT", "34011"))
WG_ENDPOINT_HOST = os.getenv("WG_ENDPOINT_HOST", SERVER_PUBLIC_HOST).strip() or SERVER_PUBLIC_HOST
DNS_SERVERS = os.getenv("DNS_SERVERS", "1.1.1.1,1.0.0.1")

PANEL_HOST = os.getenv("PANEL_HOST", "127.0.0.1")
PANEL_PORT = int(os.getenv("PANEL_PORT", "8080"))

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_BOT_USERNAME = os.getenv("TELEGRAM_BOT_USERNAME", "")
TELEGRAM_ALLOWED_CHAT_IDS = os.getenv("TELEGRAM_ALLOWED_CHAT_IDS", "")
TELEGRAM_ADMIN_USER_IDS = os.getenv("TELEGRAM_ADMIN_USER_IDS", "")
TELEGRAM_ACCESS_PATH = os.getenv(
    "TELEGRAM_ACCESS_PATH",
    "/etc/vpn-panel/telegram_access.json",
)
TELEGRAM_COMMAND_DOCS_PATH = os.getenv(
    "TELEGRAM_COMMAND_DOCS_PATH",
    "/etc/vpn-panel/telegram_command_docs.conf",
)
TELEGRAM_PANEL_BASE_URL = os.getenv(
    "TELEGRAM_PANEL_BASE_URL",
    f"http://{PANEL_HOST}:{PANEL_PORT}",
) or f"http://{PANEL_HOST}:{PANEL_PORT}"
TELEGRAM_PANEL_TOKEN = (os.getenv("TELEGRAM_PANEL_TOKEN") or PANEL_SECRET_TOKEN).strip()
TELEGRAM_POLL_TIMEOUT = int(os.getenv("TELEGRAM_POLL_TIMEOUT", "30"))
TELEGRAM_REQUEST_TIMEOUT = float(os.getenv("TELEGRAM_REQUEST_TIMEOUT", "45"))
TELEGRAM_PROXY_URL = os.getenv("TELEGRAM_PROXY_URL", "")
TELEGRAM_SUBSCRIPTION_CHECK_INTERVAL_SECONDS = int(
    os.getenv("TELEGRAM_SUBSCRIPTION_CHECK_INTERVAL_SECONDS", "300")
)
TELEGRAM_SUBSCRIPTION_NOTIFY_DAYS = os.getenv("TELEGRAM_SUBSCRIPTION_NOTIFY_DAYS", "3,1,0")

BACKUP_DIR = os.getenv("BACKUP_DIR", "/var/backups/vpn-panel")
ROUTING_OVERRIDES_PATH = os.getenv(
    "ROUTING_OVERRIDES_PATH",
    "/etc/vpn-panel/routing_overrides.json",
)
XRAY_ROUTING_EXPORT_PATH = os.getenv(
    "XRAY_ROUTING_EXPORT_PATH",
    "/etc/xray/routing.generated.json",
)
XRAY_MERGED_CONFIG_EXPORT_PATH = os.getenv(
    "XRAY_MERGED_CONFIG_EXPORT_PATH",
    "/etc/xray/config.generated.json",
)
XRAY_BASE_CONFIG_PATH = os.getenv(
    "XRAY_BASE_CONFIG_PATH",
    "/etc/xray/config.json",
)
XRAY_ACTION_STATE_PATH = os.getenv(
    "XRAY_ACTION_STATE_PATH",
    "/etc/vpn-panel/xray_action_state.json",
)
XRAY_APPLY_BACKUP_DIR = os.getenv(
    "XRAY_APPLY_BACKUP_DIR",
    os.path.join(BACKUP_DIR, "xray"),
)
XRAY_VALIDATE_COMMAND = os.getenv("XRAY_VALIDATE_COMMAND", "")
XRAY_RELOAD_COMMAND = os.getenv("XRAY_RELOAD_COMMAND", "")

XRAY_CLIENTS_PATH = os.getenv(
    "XRAY_CLIENTS_PATH",
    "/etc/vpn-panel/xray_clients.json",
)
XRAY_CLIENT_INBOUND_TAG = os.getenv("XRAY_CLIENT_INBOUND_TAG", "vless-in")
XRAY_CLIENT_SERVER = os.getenv("XRAY_CLIENT_SERVER", SERVER_PUBLIC_HOST)
XRAY_CLIENT_PORT = int(os.getenv("XRAY_CLIENT_PORT", "443"))
XRAY_CLIENT_NETWORK = os.getenv("XRAY_CLIENT_NETWORK", "tcp")
XRAY_CLIENT_SECURITY = os.getenv("XRAY_CLIENT_SECURITY", "reality")
XRAY_CLIENT_LOCAL_SOCKS_PORT = int(os.getenv("XRAY_CLIENT_LOCAL_SOCKS_PORT", "10808"))
XRAY_CLIENT_LOCAL_HTTP_PORT = int(os.getenv("XRAY_CLIENT_LOCAL_HTTP_PORT", "10809"))
XRAY_CLIENT_REALITY_SERVER_NAME = os.getenv(
    "XRAY_CLIENT_REALITY_SERVER_NAME",
    "www.microsoft.com",
)
XRAY_CLIENT_REALITY_PUBLIC_KEY = os.getenv("XRAY_CLIENT_REALITY_PUBLIC_KEY", "")
XRAY_CLIENT_REALITY_SHORT_ID = os.getenv("XRAY_CLIENT_REALITY_SHORT_ID", "")
XRAY_CLIENT_FINGERPRINT = os.getenv("XRAY_CLIENT_FINGERPRINT", "chrome")
XRAY_CLIENT_FLOW = os.getenv("XRAY_CLIENT_FLOW", "")

WG_NETWORK = os.getenv("WG_NETWORK", "10.8.2.0/24")
WG_SERVER_IP = os.getenv("WG_SERVER_IP", "10.8.2.1")
