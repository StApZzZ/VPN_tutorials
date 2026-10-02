import ipaddress
import os

from dotenv import load_dotenv

load_dotenv()

# CorpVPN configuration. Everything is env-driven; deploy/ansible renders
# /opt/vpn-panel/.env from roles/app/templates/env.j2 and quickstart.sh fills the
# inputs. Built-in defaults are deliberately NEUTRAL: no deployment's addresses
# live in code. A value that must be set per deployment defaults to "" and the
# relevant settings-status / doctor check reports it as not configured.

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
    if AUTH_LOCAL_TOTP not in {"off", "admins", "all"}:
        raise RuntimeError("AUTH_LOCAL_TOTP must be off, admins or all")
    if PANEL_DATA_KEY:
        from cryptography.fernet import Fernet
        Fernet(PANEL_DATA_KEY.encode())
    if AUDIT_RETENTION_DAYS < 1:
        raise RuntimeError("AUDIT_RETENTION_DAYS must be positive")


def _flag(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes")


def _csv(value: str) -> tuple[str, ...]:
    return tuple(v.strip() for v in value.split(",") if v.strip())


# --- State ---------------------------------------------------------------------
# The panel's own databases and state files live here; every *_DB_PATH and state
# path below defaults to a file in this directory. Point it at a writable
# directory for local development (see .env.example).
STATE_DIR = os.getenv("CORPVPN_STATE_DIR", "").strip() or "/etc/vpn-panel"


def _state_path(name: str) -> str:
    return os.path.join(STATE_DIR, name)


# --- Panel ---------------------------------------------------------------------
# Break-glass local admin: emergency login and API automation next to SSO.
PANEL_SECRET_TOKEN = os.getenv("PANEL_SECRET_TOKEN", "").strip()
PANEL_USERNAME = os.getenv("PANEL_USERNAME", "admin").strip()
PANEL_HOST = os.getenv("PANEL_HOST", "127.0.0.1")
PANEL_PORT = int(os.getenv("PANEL_PORT", "8080"))
# Public HTTPS origin of the panel (e.g. https://vpn.example.com). Used to build
# absolute links handed to employees (one-shot config links). Empty => relative.
PANEL_PUBLIC_URL = os.getenv("PANEL_PUBLIC_URL", "").strip().rstrip("/")
# Interactive API documentation (/docs, /redoc, /openapi.json). Off: it maps the
# whole API for anyone who can reach the panel. Enable for development only.
API_DOCS_ENABLED = _flag("API_DOCS_ENABLED")

# --- Gateway addresses -----------------------------------------------------------
# Public address of the VPN gateway (server A). A hostname or an IP — whatever
# employees' clients should dial. In single-host mode WireGuard/AmneziaWG and Xray
# all terminate here; override WG_ENDPOINT_HOST / XRAY_CLIENT_SERVER only when the
# protocols terminate on different boxes.
SERVER_PUBLIC_IP = os.getenv("SERVER_PUBLIC_IP", "").strip()
SERVER_PUBLIC_HOST = os.getenv("SERVER_PUBLIC_HOST", "").strip() or SERVER_PUBLIC_IP
SERVER_FALLBACK_IP = os.getenv("SERVER_FALLBACK_IP", "").strip() or SERVER_PUBLIC_IP

# --- WireGuard (wg0) -------------------------------------------------------------
WG_INTERFACE = os.getenv("WG_INTERFACE", "wg0")
WG_CONFIG_PATH = os.getenv("WG_CONFIG_PATH", "/etc/wireguard/wg0.conf")
WG_PUBLIC_KEY_PATH = os.getenv("WG_PUBLIC_KEY_PATH", "/etc/wireguard/wg0_public.key")
WG_CLIENTS_TABLE = os.getenv("WG_CLIENTS_TABLE", "/etc/wireguard/clientsTable")
CLIENT_PRIVATE_KEYS_PATH = os.getenv(
    "CLIENT_PRIVATE_KEYS_PATH",
    "/etc/wireguard/clientsPrivateKeys.json",
)
WG_PORT = int(os.getenv("WG_PORT", "51820"))
WG_ENDPOINT_HOST = os.getenv("WG_ENDPOINT_HOST", "").strip() or SERVER_PUBLIC_HOST
# DNS handed to WG/AWG clients whose access profile names no resolver. For a
# corporate VPN this is normally the internal resolver (split-horizon names).
DNS_SERVERS = os.getenv("DNS_SERVERS", "1.1.1.1,1.0.0.1")


# --- Client address pools --------------------------------------------------------
# wg0 hands out client addresses from WG_NETWORK. AmneziaWG (awg0) mirrors every
# wg0 peer at the SAME host offset in AWG_NETWORK (10.66.0.7 -> 10.66.4.7), so the
# two pools must be the same size (/16 to /30) and must not overlap. Unset
# AWG_NETWORK is the block of the same size right after WG_NETWORK, which also
# keeps installs that predate the setting on their original pair. The server
# addresses default to the first host of each pool.
def _pool_host(network: str, index: int) -> str:
    try:
        return str(ipaddress.ip_network(network, strict=False)[index])
    except (ValueError, IndexError):
        return ""


def _next_pool(network: str) -> str:
    try:
        net = ipaddress.ip_network(network, strict=False)
        return str(ipaddress.ip_network((int(net.network_address) + net.num_addresses, net.prefixlen)))
    except ValueError:
        return ""


WG_NETWORK = os.getenv("WG_NETWORK", "").strip() or "10.66.0.0/22"
WG_SERVER_IP = os.getenv("WG_SERVER_IP", "").strip() or _pool_host(WG_NETWORK, 1)
AWG_NETWORK = os.getenv("AWG_NETWORK", "").strip() or _next_pool(WG_NETWORK)
AWG_SERVER_IP = os.getenv("AWG_SERVER_IP", "").strip() or _pool_host(AWG_NETWORK, 1)


def validate_network_config() -> None:
    """Refuse to start with pools the address mapping cannot serve."""
    pools = {}
    for name, value in (("WG_NETWORK", WG_NETWORK), ("AWG_NETWORK", AWG_NETWORK)):
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise RuntimeError(f"{name} is not a valid network: {value!r}") from exc
        if net.version != 4 or not 16 <= net.prefixlen <= 30:
            raise RuntimeError(f"{name} must be an IPv4 network from /16 to /30, got {value}")
        pools[name] = net
    wg, awg = pools["WG_NETWORK"], pools["AWG_NETWORK"]
    if wg.prefixlen != awg.prefixlen:
        raise RuntimeError("WG_NETWORK and AWG_NETWORK must be the same size: awg0 mirrors wg0 by host offset")
    if wg.overlaps(awg):
        raise RuntimeError("WG_NETWORK and AWG_NETWORK must not overlap")
    for name, value, net in (("WG_SERVER_IP", WG_SERVER_IP, wg), ("AWG_SERVER_IP", AWG_SERVER_IP, awg)):
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise RuntimeError(f"{name} is not a valid address: {value!r}") from exc
        if address not in net or address in (net.network_address, net.broadcast_address):
            raise RuntimeError(f"{name} {value} is not a host address of {net}")


def network_config_warnings() -> list[str]:
    """Settings that start fine but route wrongly (logged at startup)."""
    warnings = []
    try:
        pools = [ipaddress.ip_network(n, strict=False) for n in (WG_NETWORK, AWG_NETWORK)]
    except ValueError:
        return warnings
    for raw in (*CORP_CIDRS, SITE_LINK_NETWORK):
        try:
            other = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        for pool in pools:
            # A corporate supernet around a pool is fine (the pool route is more
            # specific); a range inside or across a pool steals client addresses.
            if other.version == 4 and other.overlaps(pool) and not pool.subnet_of(other):
                warnings.append(f"{other} overlaps the client pool {pool}; return traffic to those clients is misrouted")
    return warnings


# --- AmneziaWG (awg0) ------------------------------------------------------------
# AmneziaWG runs as a SEPARATE interface (awg0) with its own key and pool. When
# AWG_SERVER_PUBLIC_KEY is set, AWG client configs target awg0; empty => AWG falls
# back to a plain-WG alias of wg0.
AWG_SERVER_PUBLIC_KEY = os.getenv("AWG_SERVER_PUBLIC_KEY", "").strip()
AWG_INTERFACE = os.getenv("AWG_INTERFACE", "awg0")
# Protocols this gateway actually serves (the installer's PROTOCOLS). A profile
# may allow more; employees are only offered the intersection.
ENABLED_PROTOCOLS = tuple(
    p.strip().lower() for p in os.getenv("ENABLED_PROTOCOLS", "wg,awg,vless").split(",") if p.strip()
)
# Legacy JSON path; obfuscation params live in awg.db (AWG_DB_PATH). Kept only
# because tests and migrations still reference it.
AWG_SETTINGS_PATH = os.getenv("AWG_SETTINGS_PATH", _state_path("awg_settings.json"))

# --- Metrics ---------------------------------------------------------------------
# Per-peer traffic volumes and endpoint changes are personal data. Off by default:
# /metrics then carries aggregates plus per-peer online/handshake state only.
METRICS_PEER_DETAIL = _flag("METRICS_PEER_DETAIL")

# --- Backups -----------------------------------------------------------------------
# Every peer change snapshots wg0.conf, the client table and the key store into
# BACKUP_DIR/<timestamp>/, and every Xray apply keeps the previous config in
# XRAY_APPLY_BACKUP_DIR. Only the newest BACKUP_KEEP of each are kept (0 = all):
# the snapshots hold client private keys.
BACKUP_DIR = os.getenv("BACKUP_DIR", "/var/backups/vpn-panel")
BACKUP_KEEP = int(os.getenv("BACKUP_KEEP", "20"))

# --- Xray (VLESS / REALITY) ------------------------------------------------------
ROUTING_OVERRIDES_PATH = os.getenv("ROUTING_OVERRIDES_PATH", _state_path("routing_overrides.json"))
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
XRAY_ACTION_STATE_PATH = os.getenv("XRAY_ACTION_STATE_PATH", _state_path("xray_action_state.json"))
XRAY_APPLY_BACKUP_DIR = os.getenv(
    "XRAY_APPLY_BACKUP_DIR",
    os.path.join(BACKUP_DIR, "xray"),
)
XRAY_VALIDATE_COMMAND = os.getenv("XRAY_VALIDATE_COMMAND", "")
XRAY_RELOAD_COMMAND = os.getenv("XRAY_RELOAD_COMMAND", "")
XRAY_PUSH_COMMAND = os.getenv("XRAY_PUSH_COMMAND", "")
# Upper bound for each validate / reload / push command. They run under the lock
# every device change and the directory-sync timer need, so a hung push or a
# stuck restart must not hold it forever.
XRAY_COMMAND_TIMEOUT_SECONDS = int(os.getenv("XRAY_COMMAND_TIMEOUT_SECONDS", "60"))
XRAY_DIRECT_IP_RULES = _csv(os.getenv("XRAY_DIRECT_IP_RULES", ""))
# Xray routing targets (VLESS). Domain rules route to "direct" (the gateway's own
# routing: corporate subnets via the site connector, the rest to the internet),
# "egress" (the outbound or balancer below) or "block". Default egress =
# "direct", i.e. no separate exit.
XRAY_EGRESS_OUTBOUND_TAG = os.getenv("XRAY_EGRESS_OUTBOUND_TAG", "").strip() or "direct"
XRAY_EGRESS_BALANCER_TAG = os.getenv("XRAY_EGRESS_BALANCER_TAG", "").strip()
# Outbound tags the egress balancer fans traffic over (leastPing). More than one
# gives the balancer somewhere to fail over to; empty => [XRAY_EGRESS_OUTBOUND_TAG].
XRAY_EGRESS_OUTBOUND_TAGS = _csv(os.getenv("XRAY_EGRESS_OUTBOUND_TAGS", ""))
# Where traffic that matches no rule goes: "direct" or "egress".
XRAY_DEFAULT_ROUTE = (os.getenv("XRAY_DEFAULT_ROUTE", "egress").strip().lower() or "egress")
if XRAY_DEFAULT_ROUTE not in ("direct", "egress"):
    raise RuntimeError("XRAY_DEFAULT_ROUTE must be direct or egress")

# Access-profile network policy (network_policy.py).
#   enforce - the panel loads the nftables table inet corpvpn_policy at startup
#             and after every change, and restores it if it disappears
#   off     - nothing is loaded into the kernel; client configs still follow
#             the profiles (AllowedIPs, DNS). For development only.
NETWORK_POLICY_MODE = os.getenv("NETWORK_POLICY_MODE", "enforce").strip().lower() or "enforce"
# Every corporate range. A destination here that the device's profile does not
# allow is dropped even on a full tunnel.
CORP_CIDRS = _csv(os.getenv("CORP_CIDRS", ""))
# Destinations no VPN client may reach, checked before any access profile (WG,
# AWG and VLESS alike): cloud metadata, loopback, "this network", multicast,
# reserved space and the site-connector link are always in; add the gateway's
# management or VPC ranges here (comma-separated CIDRs).
NETWORK_POLICY_DENY_CIDRS = _csv(os.getenv("NETWORK_POLICY_DENY_CIDRS", ""))
# Devices cannot reach each other through the gateway. A profile whose allowed
# subnets include a client pool lets its members in (e.g. remote support).
NETWORK_POLICY_CLIENT_ISOLATION = _flag("NETWORK_POLICY_CLIENT_ISOLATION", "true")
# The /30 between the gateway and the site connector (split mode). Clients never
# need to reach the link addresses themselves. Empty = no site link.
SITE_LINK_NETWORK = os.getenv("SITE_LINK_NETWORK", "10.99.0.0/30").strip()
NFT_POLICY_PATH = os.getenv("NFT_POLICY_PATH", "/etc/nftables.d/50-corpvpn-policy.nft")
NFT_COMMAND = os.getenv("NFT_COMMAND", "nft")
# How often the housekeeping loop re-checks the policy: it reloads on change and
# when the table is missing from the kernel (e.g. after `nft flush ruleset`).
NETWORK_POLICY_REFRESH_SECONDS = int(os.getenv("NETWORK_POLICY_REFRESH_SECONDS", "60"))
# Observatory health-probe settings for the egress balancer, rendered into the
# merged Xray config whenever a balancer is used. The default probe target avoids
# Google's aggressive per-IP rate limiting (a 429 there could flap an egress down
# even while user traffic is fine).
XRAY_EGRESS_PROBE_URL = (
    os.getenv("XRAY_EGRESS_PROBE_URL", "https://cp.cloudflare.com/generate_204").strip()
    or "https://cp.cloudflare.com/generate_204"
)
XRAY_EGRESS_PROBE_INTERVAL = os.getenv("XRAY_EGRESS_PROBE_INTERVAL", "30s").strip() or "30s"

XRAY_CLIENTS_PATH = os.getenv("XRAY_CLIENTS_PATH", _state_path("xray_clients.json"))
XRAY_CLIENT_INBOUND_TAG = os.getenv("XRAY_CLIENT_INBOUND_TAG", "vless-in")
# Address written into every vless:// link. Defaults to the gateway address.
XRAY_CLIENT_SERVER = os.getenv("XRAY_CLIENT_SERVER", "").strip() or SERVER_PUBLIC_HOST
# The public port clients dial. With nginx sharing TCP 443 (SNI routing) the Xray
# inbound itself listens on loopback; clients still dial 443.
XRAY_CLIENT_PORT = int(os.getenv("XRAY_CLIENT_PORT", "443"))
XRAY_CLIENT_NETWORK = os.getenv("XRAY_CLIENT_NETWORK", "tcp")
XRAY_CLIENT_SECURITY = os.getenv("XRAY_CLIENT_SECURITY", "reality")
XRAY_CLIENT_LOCAL_SOCKS_PORT = int(os.getenv("XRAY_CLIENT_LOCAL_SOCKS_PORT", "10808"))
XRAY_CLIENT_LOCAL_HTTP_PORT = int(os.getenv("XRAY_CLIENT_LOCAL_HTTP_PORT", "10809"))
# The REALITY decoy (SNI and dest). It must complete a TLS 1.3 handshake quickly
# with a small certificate chain; www.microsoft.com no longer does.
XRAY_CLIENT_REALITY_SERVER_NAME = os.getenv(
    "XRAY_CLIENT_REALITY_SERVER_NAME",
    "www.cloudflare.com",
)
XRAY_CLIENT_REALITY_PUBLIC_KEY = os.getenv("XRAY_CLIENT_REALITY_PUBLIC_KEY", "")
XRAY_CLIENT_REALITY_SHORT_ID = os.getenv("XRAY_CLIENT_REALITY_SHORT_ID", "")
XRAY_CLIENT_FINGERPRINT = os.getenv("XRAY_CLIENT_FINGERPRINT", "chrome")
XRAY_CLIENT_FLOW = os.getenv("XRAY_CLIENT_FLOW", "")

# --- Live VLESS stats for /metrics ---
# The panel re-exports live VLESS client/traffic stats on /metrics (same pattern
# as the wg/awg VpnStatusCollector). When XRAY_STATS_ENABLED is set, the panel
# injects a stats/policy block plus an expvar `metrics.listen` endpoint into the
# Xray config it applies; XRAY_STATS_URL is where the panel then scrapes that
# endpoint over a private address. Empty URL => collector stays unregistered, so
# deployments without the endpoint emit nothing and are unaffected.
XRAY_STATS_ENABLED = os.getenv("XRAY_STATS_ENABLED", "false").strip().lower() in ("1", "true", "yes")
# host:port the pushed Xray config binds its expvar endpoint to. MUST be private
# (loopback or an internal IP, e.g. 127.0.0.1:11111) — never reachable publicly.
XRAY_STATS_METRICS_LISTEN = os.getenv("XRAY_STATS_METRICS_LISTEN", "").strip()
# URL the panel polls for Xray expvar; defaults to the listen addr's /debug/vars.
XRAY_STATS_URL = os.getenv("XRAY_STATS_URL", "").strip() or (
    f"http://{XRAY_STATS_METRICS_LISTEN}/debug/vars" if XRAY_STATS_METRICS_LISTEN else ""
)
XRAY_STATS_TIMEOUT = float(os.getenv("XRAY_STATS_TIMEOUT", "3"))
# Xray keeps no live session list, so a client counts as "online" while it moves
# traffic within this many seconds (activity is the only available liveness signal).
XRAY_STATS_ONLINE_WINDOW_SECONDS = float(os.getenv("XRAY_STATS_ONLINE_WINDOW_SECONDS", "120"))

# --- Stores ----------------------------------------------------------------------
# SQLite files in STATE_DIR are the supported setup. A value containing "://" is
# a SQLAlchemy URL (see db.py); PostgreSQL is EXPERIMENTAL: no driver ships in
# requirements.lock and the deploy does not render URLs.
VLESS_DB_PATH = os.getenv("VLESS_DB_PATH", _state_path("vless.db"))
ROUTING_DB_PATH = os.getenv("ROUTING_DB_PATH", _state_path("routing_rules.db"))
AWG_DB_PATH = os.getenv("AWG_DB_PATH", _state_path("awg.db"))
CONFIG_LINKS_DB_PATH = os.getenv("CONFIG_LINKS_DB_PATH", _state_path("config_links.db"))

# --- One-shot AmneziaWG config links (<base>/awg/<code>) -------------------------
# An admin mints a single-use link that serves an EXISTING peer's config (no key
# is ever regenerated — see config_links.py) and sends it to the employee.
CONFIG_LINK_TTL_DAYS = int(os.getenv("CONFIG_LINK_TTL_DAYS", "7"))
CONFIG_LINK_PUBLIC_BASE_URL = (
    os.getenv("CONFIG_LINK_PUBLIC_BASE_URL", "").strip().rstrip("/") or PANEL_PUBLIC_URL
)
CONFIG_LINK_CLEANUP_INTERVAL_SECONDS = int(
    os.getenv("CONFIG_LINK_CLEANUP_INTERVAL_SECONDS", "300")
)

# --- Corporate identity (Phase 3) ------------------------------------------------
# Users, sessions, group policies and the audit log live here (SQLite path or a
# SQLAlchemy URL, like the other stores).
CORPVPN_DB_PATH = os.getenv("CORPVPN_DB_PATH", "/etc/vpn-panel/corpvpn.db")

# Sessions: server-side, random id in an HttpOnly cookie; absolute and idle limits.
SESSION_TTL_HOURS = int(os.getenv("SESSION_TTL_HOURS", "12"))
SESSION_IDLE_MINUTES = int(os.getenv("SESSION_IDLE_MINUTES", "120"))

# Break-glass local admin: PANEL_USERNAME + PANEL_SECRET_TOKEN on the login form,
# and the token as Bearer/Basic for API automation. The break-glass sign-in and
# every API token (break-glass and named) work only from these networks when set
# (comma-separated CIDRs; empty = anywhere).
AUTH_LOCAL_ENABLED = _flag("AUTH_LOCAL_ENABLED", "true")
AUTH_API_TOKEN_ENABLED = _flag("AUTH_API_TOKEN_ENABLED", "true")
AUTH_LOCAL_ALLOWED_CIDRS = tuple(
    v.strip() for v in os.getenv("AUTH_LOCAL_ALLOWED_CIDRS", "").split(",") if v.strip()
)
# Role for a directory user matching no group policy: "" (deny, default) or user.
AUTH_DEFAULT_ROLE = os.getenv("AUTH_DEFAULT_ROLE", "").strip().lower()
# Seed group policies on first start (comma-separated). A DN, a Keycloak path
# (/corp/vpn-admins) or DOMAIN\name matches exactly that group; a bare name
# matches a group of that name anywhere. Afterwards policies are edited in the panel.
AUTH_ADMIN_GROUPS = os.getenv("AUTH_ADMIN_GROUPS", "").strip()
AUTH_OPERATOR_GROUPS = os.getenv("AUTH_OPERATOR_GROUPS", "").strip()
AUTH_USER_GROUPS = os.getenv("AUTH_USER_GROUPS", "").strip()
# Sign-in failure budgets per AUTH_FAILURE_WINDOW_SECONDS, checked before a
# password reaches the directory. AUTH_MAX_FAILURES counts per username across
# all source IPs: keep it BELOW the directory's lockout threshold (AD policies
# often lock at 5-10) and the panel can never lock an AD account. The
# break-glass username has no directory behind it and only has the IP budget.
# AUTH_MAX_FAILURES_PER_IP counts per client IP across usernames (password
# sprays, API-token guessing).
AUTH_MAX_FAILURES = int(os.getenv("AUTH_MAX_FAILURES", "5"))
AUTH_MAX_FAILURES_PER_IP = int(os.getenv("AUTH_MAX_FAILURES_PER_IP", "30"))
AUTH_FAILURE_WINDOW_SECONDS = int(os.getenv("AUTH_FAILURE_WINDOW_SECONDS", "900"))
# OIDC-only deployments cannot query the directory: a user who has not signed in
# for this many days is disabled by directory_sync until they sign in again.
# 0 = off. During the last AUTH_ATTESTATION_WARN_DAYS the sync audits
# directory.attestation_due once per user (route it from syslog to a
# notification) and the portal shows the days left.
AUTH_ATTESTATION_DAYS = int(os.getenv("AUTH_ATTESTATION_DAYS", "30"))
AUTH_ATTESTATION_WARN_DAYS = int(os.getenv("AUTH_ATTESTATION_WARN_DAYS", "7"))
# Roles that must sign in with a second factor. OIDC users prove it through
# OIDC_REQUIRED_ACR / OIDC_REQUIRED_AMR (nothing is checked while both are empty:
# then MFA is the IdP's business alone).
AUTH_MFA_REQUIRED_ROLES = tuple(
    v.strip().lower() for v in os.getenv("AUTH_MFA_REQUIRED_ROLES", "admin,operator").split(",") if v.strip()
)

# --- OIDC (Keycloak, ADFS 2016+, Entra ID, any OpenID Provider) ---------------------
OIDC_ALLOW_INSECURE_HTTP = _flag("OIDC_ALLOW_INSECURE_HTTP")
OIDC_ENABLED = _flag("OIDC_ENABLED")
# Issuer's discovery document, e.g.
#   https://sso.example.com/realms/corp/.well-known/openid-configuration  (Keycloak)
#   https://adfs.example.com/adfs/.well-known/openid-configuration        (ADFS)
OIDC_DISCOVERY_URL = os.getenv("OIDC_DISCOVERY_URL", "").strip()
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "").strip()
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET", "").strip()
# client_secret_basic (default) or client_secret_post.
OIDC_TOKEN_AUTH_METHOD = os.getenv("OIDC_TOKEN_AUTH_METHOD", "client_secret_basic").strip()
OIDC_SCOPES = os.getenv("OIDC_SCOPES", "openid profile email").strip()
# Default: <PANEL_PUBLIC_URL>/auth/oidc/callback — register exactly this in the IdP.
OIDC_REDIRECT_URL = (
    os.getenv("OIDC_REDIRECT_URL", "").strip()
    or (f"{PANEL_PUBLIC_URL}/auth/oidc/callback" if PANEL_PUBLIC_URL else "")
)
# First present claim wins (comma-separated).
OIDC_USERNAME_CLAIMS = os.getenv("OIDC_USERNAME_CLAIMS", "preferred_username,upn,email,sub").strip()
# Keycloak "groups", ADFS "group" / "role", Entra "groups" or "roles". When none
# of them arrives (Entra sends an overage marker instead of more than 200 groups;
# a claim mapper was removed) the sign-in is refused without touching the user,
# unless AUTH_DEFAULT_ROLE gives everyone a role anyway.
OIDC_GROUPS_CLAIMS = os.getenv("OIDC_GROUPS_CLAIMS", "groups,group,roles").strip()
# Proof of MFA for AUTH_MFA_REQUIRED_ROLES (comma-separated; any listed value
# satisfies it). acr: e.g. a Keycloak level of authentication; amr: e.g. "mfa"
# (Entra ID), "otp", "hwk", or ADFS "http://schemas.microsoft.com/claims/multipleauthn".
OIDC_REQUIRED_ACR = tuple(v.strip() for v in os.getenv("OIDC_REQUIRED_ACR", "").split(",") if v.strip())
OIDC_REQUIRED_AMR = tuple(v.strip() for v in os.getenv("OIDC_REQUIRED_AMR", "").split(",") if v.strip())
OIDC_BUTTON_LABEL = os.getenv("OIDC_BUTTON_LABEL", "Sign in with corporate SSO").strip()
# After logout, also end the IdP session (RP-initiated logout) when the provider
# publishes end_session_endpoint.
OIDC_LOGOUT_AT_IDP = _flag("OIDC_LOGOUT_AT_IDP", "true")
OIDC_HTTP_TIMEOUT = float(os.getenv("OIDC_HTTP_TIMEOUT", "10"))

# --- LDAP / Active Directory ---------------------------------------------------------
LDAP_ENABLED = _flag("LDAP_ENABLED")
# ldaps://dc1.corp.example.com:636 (or ldap:// with LDAP_START_TLS=true)
LDAP_URL = os.getenv("LDAP_URL", "").strip()
LDAP_START_TLS = _flag("LDAP_START_TLS")
# CA bundle for the directory's certificate; empty = system trust store.
LDAP_CA_FILE = os.getenv("LDAP_CA_FILE", "").strip()
# Strict X.509 checks of the directory's certificate (VERIFY_X509_STRICT, the
# default since Python 3.13 / Debian 13). false accepts certificates that break
# the stricter rules, e.g. Samba's self-generated one (no Authority Key Identifier).
LDAP_TLS_STRICT = _flag("LDAP_TLS_STRICT", "true")
# Read-only service account used to find users and for directory_sync.
LDAP_BIND_DN = os.getenv("LDAP_BIND_DN", "").strip()
LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD", "")
LDAP_USER_BASE_DN = os.getenv("LDAP_USER_BASE_DN", "").strip()
LDAP_USER_FILTER = os.getenv(
    "LDAP_USER_FILTER", "(&(objectClass=user)(sAMAccountName={username}))"
).strip()
LDAP_USERNAME_ATTR = os.getenv("LDAP_USERNAME_ATTR", "sAMAccountName").strip()
LDAP_EMAIL_ATTR = os.getenv("LDAP_EMAIL_ATTR", "mail").strip()
LDAP_DISPLAY_NAME_ATTR = os.getenv("LDAP_DISPLAY_NAME_ATTR", "displayName").strip()
LDAP_GROUP_ATTR = os.getenv("LDAP_GROUP_ATTR", "memberOf").strip()
# Extra group lookup, e.g. nested AD groups. {user_dn} is filter-escaped.
#   AD (nested):  (member:1.2.840.113556.1.4.1941:={user_dn})
#   OpenLDAP/IPA: (&(objectClass=groupOfNames)(member={user_dn}))
# Empty = only LDAP_GROUP_ATTR on the user entry.
LDAP_GROUP_BASE_DN = os.getenv("LDAP_GROUP_BASE_DN", "").strip() or LDAP_USER_BASE_DN
LDAP_GROUP_SEARCH_FILTER = os.getenv(
    "LDAP_GROUP_SEARCH_FILTER", "(member:1.2.840.113556.1.4.1941:={user_dn})"
).strip()
# "Account disabled" test for directories other than AD, evaluated on the user's
# own entry; a match means disabled. FreeIPA / 389-DS: (nsAccountLock=TRUE);
# OpenLDAP ppolicy: (pwdAccountLockedTime=*). AD's userAccountControl and
# accountExpires are always checked.
LDAP_DISABLED_FILTER = os.getenv("LDAP_DISABLED_FILTER", "").strip()
LDAP_TIMEOUT = int(os.getenv("LDAP_TIMEOUT", "10"))
# directory_sync circuit breaker: a run that would disable more LDAP users than
# this changes nothing and fails (directory.sync_aborted). "N" users or "N%" of
# the active LDAP users (at least 5); 0 = no limit.
DIRECTORY_SYNC_MAX_DISABLE = os.getenv("DIRECTORY_SYNC_MAX_DISABLE", "10%").strip() or "10%"

# --- Audit -------------------------------------------------------------------------
# Also send every audit event to syslog as one JSON line, for a SIEM:
# "/dev/log" (local rsyslog/journald) or "host:514" (UDP). Empty = database only.
AUDIT_SYSLOG_ADDRESS = os.getenv("AUDIT_SYSLOG_ADDRESS", "").strip()

# Local accounts (separate from the emergency break-glass identity).
LOCAL_ACCOUNTS_ENABLED = _flag("LOCAL_ACCOUNTS_ENABLED", "true")
AUTH_LOCAL_TOTP = os.getenv("AUTH_LOCAL_TOTP", "admins").strip()
PANEL_DATA_KEY = os.getenv("PANEL_DATA_KEY", "").strip()
LOCAL_DATA_KEY_PATH = os.getenv("LOCAL_DATA_KEY_PATH", "").strip() or _state_path("local-data.key")
AUDIT_RETENTION_DAYS = int(os.getenv("AUDIT_RETENTION_DAYS", "365"))
