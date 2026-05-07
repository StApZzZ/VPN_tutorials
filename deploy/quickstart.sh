#!/usr/bin/env bash
# deploy/quickstart.sh — Full cascade installation from a single config file.
# Reads deploy/quickstart.env and does everything: installs Xray on both servers,
# generates REALITY keys, builds all config files from repository examples,
# deploys the panel via Ansible, and places Xray configs on both nodes.
set -euo pipefail

# --- Paths ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
QS_ENV="${QS_ENV:-$SCRIPT_DIR/quickstart.env}"
ANSIBLE_DIR="$SCRIPT_DIR/ansible"
APP_SRC="$REPO_ROOT/amnezia-panel-src"
RUN_SH="${QS_RUN_SH:-$SCRIPT_DIR/run.sh}"
XRAY_INSTALL_URL="${XRAY_INSTALL_URL:-https://github.com/XTLS/Xray-install/raw/main/install-release.sh}"
XRAY_BIN_PATH="${XRAY_BIN_PATH:-/usr/local/bin/xray}"
XRAY_CONFIG_DIR="${XRAY_CONFIG_DIR:-/etc/xray}"
XRAY_CONFIG_PATH="${XRAY_CONFIG_PATH:-$XRAY_CONFIG_DIR/config.json}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# --- Terminal colors ---
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; NC='\033[0m'
info() { echo -e "${B}[•]${NC} $*"; }
ok()   { echo -e "${G}[✓]${NC} $*"; }
warn() { echo -e "${Y}[!]${NC} $*"; }
die()  { echo -e "${R}[✗]${NC} $*" >&2; exit 1; }
step() { echo; echo -e "${B}━━━ $* ${NC}"; }

# ================================================================
# Load and validate configuration
# ================================================================
[[ -f "$QS_ENV" ]] || die "Config not found: $QS_ENV
  Copy deploy/quickstart.env.example to deploy/quickstart.env and fill it in."

# shellcheck source=/dev/null
source "$QS_ENV"

[[ -n "${SERVER_A_IP:-}"        ]] || die "SERVER_A_IP is required"
[[ -n "${SSH_KEY:-}"            ]] || die "SSH_KEY is required"
[[ -n "${PANEL_SECRET_TOKEN:-}" ]] || die "PANEL_SECRET_TOKEN is required"
[[ "$PANEL_SECRET_TOKEN" != "replace-with-long-random-token" ]] \
    || die "PANEL_SECRET_TOKEN is still the placeholder — generate one with: openssl rand -base64 32"
[[ -f "${SSH_KEY}" ]] || die "SSH key not found: $SSH_KEY"

SSH_USER="${SSH_USER:-root}"
SERVER_A_DOMAIN="${SERVER_A_DOMAIN:-}"
SERVER_B_IP="${SERVER_B_IP:-}"
SERVER_B_DOMAIN="${SERVER_B_DOMAIN:-}"
SERVER_B_SSH_KEY="${SERVER_B_SSH_KEY:-$SSH_KEY}"
REALITY_SERVER_NAME="${REALITY_SERVER_NAME:-www.microsoft.com}"
TWO_SERVER=false
[[ -n "$SERVER_B_IP" ]] && TWO_SERVER=true

SERVER_A_HOST="${SERVER_A_DOMAIN:-$SERVER_A_IP}"
SERVER_B_HOST="${SERVER_B_DOMAIN:-${SERVER_B_IP:-}}"

TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_ADMIN_IDS="${TELEGRAM_ADMIN_IDS:-}"
TELEGRAM_BOT_USERNAME="${TELEGRAM_BOT_USERNAME:-}"
BOT_ENABLED=false
[[ -n "$TELEGRAM_BOT_TOKEN" ]] && BOT_ENABLED=true
BOT_HOST_ROLE="disabled"
BOT_HOST_IP=""
BOT_HOST_KEY=""
BOT_HOST_LABEL=""
BOT_PANEL_BASE_URL=""

if [[ -n "${SERVER_B_SSH_KEY}" && ! -f "${SERVER_B_SSH_KEY}" ]]; then
    die "SERVER_B_SSH_KEY not found: $SERVER_B_SSH_KEY"
fi

echo
echo -e "${G}VPN Panel — Quickstart Installer${NC}"
echo "  Server A (ingress/panel): $SERVER_A_IP${SERVER_A_DOMAIN:+ ($SERVER_A_DOMAIN)}"
$TWO_SERVER && echo "  Server B (egress/relay):  $SERVER_B_IP${SERVER_B_DOMAIN:+ ($SERVER_B_DOMAIN)}"
$BOT_ENABLED && echo "  Telegram bot:             @${TELEGRAM_BOT_USERNAME:-<configured>}"
echo

# ================================================================
# SSH helpers
# ================================================================
ssh_run() {
    local host=$1 key=$2; shift 2
    ssh -i "$key" -o StrictHostKeyChecking=no -o BatchMode=yes \
        -o ConnectTimeout=20 "$SSH_USER@$host" "$@"
}

scp_upload() {
    local src=$1 host=$2 key=$3 dst=$4
    scp -i "$key" -o StrictHostKeyChecking=no -q "$src" "$SSH_USER@$host:$dst"
}

check_ssh() {
    local host=$1 key=$2
    ssh_run "$host" "$key" 'echo ok' >/dev/null \
        || die "Cannot connect to $host with key $key (user: $SSH_USER)"
}

prepare_remote_host_for_xray() {
    local host=$1 key=$2 label=$3
    info "Bootstrapping Xray prerequisites on $label ..."
    if ! ssh_run "$host" "$key" bash -s <<'EOF'
set -euo pipefail

if ! command -v systemctl >/dev/null 2>&1 || \
   { [[ ! -d /run/systemd/system ]] && ! grep -qa systemd /proc/1/comm 2>/dev/null; }; then
    echo "error: quickstart supports only systemd-based hosts." >&2
    exit 1
fi

if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update >/dev/null
    apt-get install -y --no-install-recommends curl ca-certificates openssl unzip >/dev/null
elif command -v dnf >/dev/null 2>&1; then
    dnf -y install curl ca-certificates openssl unzip >/dev/null
elif command -v yum >/dev/null 2>&1; then
    yum -y install curl ca-certificates openssl unzip >/dev/null
else
    echo "error: supported package manager not found (expected apt-get, dnf, or yum)." >&2
    exit 1
fi

mkdir -p /etc/systemd/system/xray.service.d /etc/systemd/system/xray@.service.d
touch /etc/systemd/system/xray.service.d/10-donot_touch_multi_conf.conf
touch /etc/systemd/system/xray@.service.d/10-donot_touch_multi_conf.conf
EOF
    then
        die "Failed to install Xray prerequisites on $label"
    fi
}

install_xray_on() {
    local host=$1 key=$2 label=$3
    info "Installing Xray on $label ..."
    if ! ssh_run "$host" "$key" bash -s <<EOF
set -euo pipefail

tmp_installer=\$(mktemp)
cleanup() {
    rm -f "\$tmp_installer"
}
trap cleanup EXIT

curl -fsSL "$XRAY_INSTALL_URL" -o "\$tmp_installer"
TERM=dumb JSON_PATH="$XRAY_CONFIG_DIR" bash "\$tmp_installer" install

test -x "$XRAY_BIN_PATH"
systemctl daemon-reload
systemctl cat xray.service | grep -F "$XRAY_CONFIG_PATH" >/dev/null
EOF
    then
        die "Xray install failed on $label"
    fi
    ok "Xray installed on $label"
}

deploy_xray_config() {
    local src=$1 host=$2 key=$3 label=$4
    local tmp_remote=/tmp/xray-qs.json

    info "Uploading Xray config to $label ..."
    scp_upload "$src" "$host" "$key" "$tmp_remote"
    if ! ssh_run "$host" "$key" bash -s <<EOF
set -euo pipefail

tmp_config="$tmp_remote"
cleanup() {
    rm -f "\$tmp_config"
}
trap cleanup EXIT

test -x "$XRAY_BIN_PATH"
mkdir -p "$XRAY_CONFIG_DIR"
"$XRAY_BIN_PATH" run -test -config "\$tmp_config"
cp "\$tmp_config" "$XRAY_CONFIG_PATH"
systemctl enable xray --quiet
systemctl restart xray
sleep 1
systemctl is-active --quiet xray
EOF
    then
        die "Failed to validate or start Xray on $label"
    fi
}

# ================================================================
# STEP 1 — Verify SSH connectivity
# ================================================================
step "Step 1/8 — Checking SSH connectivity"
info "Testing SSH to Server A ($SERVER_A_IP) ..."
check_ssh "$SERVER_A_IP" "$SSH_KEY"
ok "Server A reachable"

if $TWO_SERVER; then
    info "Testing SSH to Server B ($SERVER_B_IP) ..."
    check_ssh "$SERVER_B_IP" "$SERVER_B_SSH_KEY"
    ok "Server B reachable"
fi

# ================================================================
# Telegram reachability helpers
# ================================================================
telegram_api_reachable_from() {
    local host=$1 key=$2
    ssh_run "$host" "$key" bash -s <<EOF
set -euo pipefail

command -v curl >/dev/null 2>&1 || exit 1
response=\$(curl -fsS --max-time 20 "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getMe")
grep -Eq '"ok"[[:space:]]*:[[:space:]]*true' <<<"\$response"
EOF
}

select_telegram_bot_host() {
    if ! $BOT_ENABLED; then
        return 0
    fi

    if $TWO_SERVER; then
        info "Checking Telegram Bot API reachability from Server B ($SERVER_B_IP) ..."
        if telegram_api_reachable_from "$SERVER_B_IP" "$SERVER_B_SSH_KEY"; then
            BOT_HOST_ROLE="server_b"
            BOT_HOST_IP="$SERVER_B_IP"
            BOT_HOST_KEY="$SERVER_B_SSH_KEY"
            BOT_HOST_LABEL="Server B ($SERVER_B_IP)"
            BOT_PANEL_BASE_URL="http://$SERVER_A_IP"
            ok "Telegram bot will run on $BOT_HOST_LABEL"
            return 0
        fi

        warn "Server B cannot reach the Telegram Bot API with the configured token."
        if telegram_api_reachable_from "$SERVER_A_IP" "$SSH_KEY"; then
            die "Telegram Bot API is reachable from Server A, but two-server quickstart pins the Telegram bot to Server B. Fix Telegram reachability on Server B and rerun quickstart."
        fi

        die "Telegram Bot API is unreachable from both servers. Quickstart cannot place the Telegram bot safely."
    fi

    info "Checking Telegram Bot API reachability from Server A ($SERVER_A_IP) ..."
    telegram_api_reachable_from "$SERVER_A_IP" "$SSH_KEY" \
        || die "Telegram Bot API is unreachable from Server A. Quickstart cannot enable the Telegram bot."

    BOT_HOST_ROLE="server_a"
    BOT_HOST_IP="$SERVER_A_IP"
    BOT_HOST_KEY="$SSH_KEY"
    BOT_HOST_LABEL="Server A ($SERVER_A_IP)"
    BOT_PANEL_BASE_URL="http://127.0.0.1:8080"
    ok "Telegram bot will run on $BOT_HOST_LABEL"
}

# ================================================================
# STEP 2 — Install Xray
# ================================================================
step "Step 2/8 — Installing Xray"

prepare_remote_host_for_xray "$SERVER_A_IP" "$SSH_KEY" "Server A ($SERVER_A_IP)"
install_xray_on "$SERVER_A_IP" "$SSH_KEY" "Server A ($SERVER_A_IP)"

if $TWO_SERVER; then
    prepare_remote_host_for_xray "$SERVER_B_IP" "$SERVER_B_SSH_KEY" "Server B ($SERVER_B_IP)"
    install_xray_on "$SERVER_B_IP" "$SERVER_B_SSH_KEY" "Server B ($SERVER_B_IP)"
fi

# ================================================================
# STEP 3 — Generate REALITY keys
# ================================================================
step "Step 3/8 — Generating REALITY keys"

parse_x25519_output() {
    local out=$1
    local line private="" public="" short=""

    while IFS= read -r line; do
        case "$line" in
            "Private key:"*|"PrivateKey:"*)
                private="${line#*: }"
                ;;
            "Public key:"*|"PublicKey:"*|"Password (PublicKey):"*)
                public="${line#*: }"
                ;;
            "Hash32:"*)
                ;;
            *)
                if [[ "$line" =~ ^[[:xdigit:]]{8}$ ]]; then
                    short="$line"
                fi
                ;;
        esac
    done <<< "$out"

    [[ -n "$private" ]] || die "REALITY key generation output did not include a private key."
    [[ -n "$public"  ]] || die "REALITY key generation output did not include a client-side REALITY key."
    [[ -n "$short"   ]] || die "REALITY key generation output did not include a generated short ID."

    echo "$private $public $short"
}

gen_keys_on() {
    local host=$1 key=$2
    local out
    out=$(ssh_run "$host" "$key" bash -s <<EOF
set -euo pipefail

command -v openssl >/dev/null 2>&1 || {
    echo "openssl is required for REALITY key generation." >&2
    exit 1
}
test -x "$XRAY_BIN_PATH" || {
    echo "Xray binary not found at $XRAY_BIN_PATH." >&2
    exit 1
}
"$XRAY_BIN_PATH" x25519
openssl rand -hex 4
EOF
)
    parse_x25519_output "$out" \
        || die "Key generation failed on $host (output: $out)"
}

if [[ -z "${SERVER_A_REALITY_PRIVATE_KEY:-}" ]]; then
    info "Generating REALITY keys on Server A ..."
    read -r SERVER_A_REALITY_PRIVATE_KEY SERVER_A_REALITY_PUBLIC_KEY SERVER_A_REALITY_SHORT_ID \
        < <(gen_keys_on "$SERVER_A_IP" "$SSH_KEY")
    ok "Server A keys generated (public: ${SERVER_A_REALITY_PUBLIC_KEY:0:20}...)"
else
    [[ -n "${SERVER_A_REALITY_PUBLIC_KEY:-}" && -n "${SERVER_A_REALITY_SHORT_ID:-}" ]] \
        || die "SERVER_A_REALITY_PUBLIC_KEY and SERVER_A_REALITY_SHORT_ID are required when providing SERVER_A_REALITY_PRIVATE_KEY"
    ok "Using pre-configured Server A REALITY keys"
fi

if $TWO_SERVER; then
    if [[ -z "${SERVER_B_REALITY_PRIVATE_KEY:-}" ]]; then
        info "Generating REALITY keys on Server B ..."
        read -r SERVER_B_REALITY_PRIVATE_KEY SERVER_B_REALITY_PUBLIC_KEY SERVER_B_REALITY_SHORT_ID \
            < <(gen_keys_on "$SERVER_B_IP" "$SERVER_B_SSH_KEY")
        ok "Server B keys generated (public: ${SERVER_B_REALITY_PUBLIC_KEY:0:20}...)"
    else
        [[ -n "${SERVER_B_REALITY_PUBLIC_KEY:-}" && -n "${SERVER_B_REALITY_SHORT_ID:-}" ]] \
            || die "SERVER_B_REALITY_PUBLIC_KEY and SERVER_B_REALITY_SHORT_ID are required when providing SERVER_B_REALITY_PRIVATE_KEY"
        ok "Using pre-configured Server B REALITY keys"
    fi
fi

# ================================================================
# STEP 4 — Generate UUID for A→B uplink (two-server only)
# ================================================================
step "Step 4/8 — Generating connection identifiers"

gen_uuid() {
    python3 -c "import uuid; print(uuid.uuid4())" 2>/dev/null \
        || cat /proc/sys/kernel/random/uuid 2>/dev/null \
        || uuidgen
}

UPLINK_UUID=$(gen_uuid)
ok "Uplink UUID: $UPLINK_UUID"

# ================================================================
# STEP 5 — Build Xray configs
# ================================================================
step "Step 5/8 — Building Xray configuration files"

# Helper: write Xray JSON to a file using printf (avoids heredoc quoting issues)
write_ingress_config() {
    local out=$1 relay_ip=$2 relay_pub=$3 relay_short=$4

    local outbounds_direct='"direct"'
    local outbounds_block='"block"'

    # Build outbounds JSON array
    local outbounds
    if [[ -n "$relay_ip" ]]; then
        outbounds=$(cat <<EOF
[
    {"tag": "direct", "protocol": "freedom"},
    {"tag": "block",  "protocol": "blackhole"},
    {
      "tag": "to-egress",
      "protocol": "vless",
      "settings": {
        "vnext": [{
          "address": "$relay_ip",
          "port": 443,
          "users": [{"id": "$UPLINK_UUID", "encryption": "none"}]
        }]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "serverName": "$REALITY_SERVER_NAME",
          "password": "$relay_pub",
          "shortId": "$relay_short",
          "fingerprint": "chrome"
        }
      }
    }
  ]
EOF
)
    else
        outbounds='[
    {"tag": "direct", "protocol": "freedom"},
    {"tag": "block",  "protocol": "blackhole"}
  ]'
    fi

    cat > "$out" <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "tag": "vless-in",
    "listen": "0.0.0.0",
    "port": 443,
    "protocol": "vless",
    "settings": {
      "clients": [],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "$REALITY_SERVER_NAME:443",
        "xver": 0,
        "serverNames": ["$REALITY_SERVER_NAME"],
        "privateKey": "$SERVER_A_REALITY_PRIVATE_KEY",
        "shortIds": ["$SERVER_A_REALITY_SHORT_ID"]
      }
    },
    "sniffing": {
      "enabled": true,
      "destOverride": ["http", "tls", "quic"],
      "routeOnly": true
    }
  }],
  "outbounds": $outbounds,
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": []
  }
}
EOF
}

write_egress_config() {
    local out=$1
    cat > "$out" <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "tag": "from-ingress",
    "listen": "0.0.0.0",
    "port": 443,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "$UPLINK_UUID", "email": "ingress-uplink"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "$REALITY_SERVER_NAME:443",
        "xver": 0,
        "serverNames": ["$REALITY_SERVER_NAME"],
        "privateKey": "$SERVER_B_REALITY_PRIVATE_KEY",
        "shortIds": ["$SERVER_B_REALITY_SHORT_ID"]
      }
    },
    "sniffing": {
      "enabled": true,
      "destOverride": ["http", "tls", "quic"],
      "routeOnly": true
    }
  }],
  "outbounds": [
    {"tag": "direct", "protocol": "freedom"},
    {"tag": "block",  "protocol": "blackhole"}
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": []
  }
}
EOF
}

INGRESS_CONFIG="$TMP_DIR/xray-ingress.json"
if $TWO_SERVER; then
    write_ingress_config "$INGRESS_CONFIG" \
        "$SERVER_B_IP" "$SERVER_B_REALITY_PUBLIC_KEY" "$SERVER_B_REALITY_SHORT_ID"
    ok "Ingress config built (with relay outbound → $SERVER_B_IP)"

    EGRESS_CONFIG="$TMP_DIR/xray-egress.json"
    write_egress_config "$EGRESS_CONFIG"
    ok "Egress config built"
else
    write_ingress_config "$INGRESS_CONFIG" "" "" ""
    ok "Ingress config built (single-server, no relay)"
fi

# ================================================================
# STEP 6 — Build Ansible config files
# ================================================================
step "Step 6/8 — Building Ansible configuration files"

select_telegram_bot_host

# inventory/hosts.yml
mkdir -p "$ANSIBLE_DIR/inventory"
cat > "$ANSIBLE_DIR/inventory/hosts.yml" <<EOF
all:
  hosts:
    server-a:
      ansible_host: $SERVER_A_IP
      ansible_user: $SSH_USER
      ansible_ssh_private_key_file: $SSH_KEY
EOF
$TWO_SERVER && cat >> "$ANSIBLE_DIR/inventory/hosts.yml" <<EOF
    server-b:
      ansible_host: $SERVER_B_IP
      ansible_user: $SSH_USER
      ansible_ssh_private_key_file: $SERVER_B_SSH_KEY
EOF
ok "inventory/hosts.yml written"

# group_vars/all.yml (panel host defaults)
mkdir -p "$ANSIBLE_DIR/group_vars"
{
    echo "# Generated by quickstart.sh"
    echo "vpn_panel_panel_enabled: true"
    echo "vpn_panel_nginx_enabled: true"
    echo "vpn_panel_server_name: \"$SERVER_A_HOST\""
    echo "vpn_panel_public_host: \"$SERVER_A_IP\""
    echo "vpn_panel_fallback_host: \"${SERVER_B_IP:-$SERVER_A_IP}\""
    echo "vpn_panel_wg_endpoint_host: \"$SERVER_A_HOST\""
    echo "vpn_panel_telegram_panel_base_url: \"http://127.0.0.1:8080\""
    echo "vpn_panel_xray_client_server: \"$SERVER_A_HOST\""
    echo "vpn_panel_xray_client_reality_server_name: \"$REALITY_SERVER_NAME\""
    echo "vpn_panel_xray_client_reality_public_key: \"$SERVER_A_REALITY_PUBLIC_KEY\""
    echo "vpn_panel_xray_client_reality_short_id: \"$SERVER_A_REALITY_SHORT_ID\""
    echo "vpn_panel_xray_validate_command: \"/usr/local/bin/xray run -test -config {config_path}\""
    echo "vpn_panel_xray_reload_command: \"/bin/systemctl restart xray\""
    if $BOT_ENABLED; then
        if [[ "$BOT_HOST_ROLE" == "server_a" ]]; then
            echo "vpn_panel_bot_enabled: true"
        else
            echo "vpn_panel_bot_enabled: false"
        fi
        [[ -n "$TELEGRAM_BOT_USERNAME" ]] && echo "vpn_panel_bot_username: \"$TELEGRAM_BOT_USERNAME\""
    fi
} > "$ANSIBLE_DIR/group_vars/all.yml"
ok "group_vars/all.yml written"

if $BOT_ENABLED && [[ "$BOT_HOST_ROLE" == "server_b" ]]; then
    {
        echo "# Generated by quickstart.sh for Telegram bot host"
        echo "vpn_panel_panel_enabled: false"
        echo "vpn_panel_nginx_enabled: false"
        echo "vpn_panel_bot_enabled: true"
        echo "vpn_panel_server_name: \"$SERVER_A_HOST\""
        echo "vpn_panel_public_host: \"$SERVER_A_IP\""
        echo "vpn_panel_fallback_host: \"${SERVER_B_IP:-$SERVER_A_IP}\""
        echo "vpn_panel_wg_endpoint_host: \"$SERVER_A_HOST\""
        echo "vpn_panel_telegram_panel_base_url: \"$BOT_PANEL_BASE_URL\""
        echo "vpn_panel_xray_client_server: \"$SERVER_A_HOST\""
        echo "vpn_panel_xray_client_reality_server_name: \"$REALITY_SERVER_NAME\""
        echo "vpn_panel_xray_client_reality_public_key: \"$SERVER_A_REALITY_PUBLIC_KEY\""
        echo "vpn_panel_xray_client_reality_short_id: \"$SERVER_A_REALITY_SHORT_ID\""
        echo "vpn_panel_xray_validate_command: \"/usr/local/bin/xray run -test -config {config_path}\""
        echo "vpn_panel_xray_reload_command: \"/bin/systemctl restart xray\""
        [[ -n "$TELEGRAM_BOT_USERNAME" ]] && echo "vpn_panel_bot_username: \"$TELEGRAM_BOT_USERNAME\""
    } > "$ANSIBLE_DIR/group_vars/bot-host.yml"
    ok "group_vars/bot-host.yml written"
fi

# group_vars/all.secrets.yml
{
    echo "# Generated by quickstart.sh — keep this file private"
    echo "panel_secret_token: \"$PANEL_SECRET_TOKEN\""
    if $BOT_ENABLED; then
        echo "telegram_bot_token: \"$TELEGRAM_BOT_TOKEN\""
        echo "telegram_panel_token: \"$PANEL_SECRET_TOKEN\""
        if [[ -n "$TELEGRAM_ADMIN_IDS" ]]; then
            echo "vpn_panel_admin_user_ids:"
            IFS=',' read -ra _ids <<< "$TELEGRAM_ADMIN_IDS"
            for _id in "${_ids[@]}"; do
                echo "  - ${_id// /}"
            done
        fi
    fi
} > "$ANSIBLE_DIR/group_vars/all.secrets.yml"
ok "group_vars/all.secrets.yml written"

# ================================================================
# STEP 7 — Deploy app services via Ansible
# ================================================================
step "Step 7/8 — Deploying application services"
"$RUN_SH" --host "$SERVER_A_IP" --ssh-key "$SSH_KEY" --ssh-user "$SSH_USER" \
    || die "Ansible deployment failed"
ok "Panel deployed on Server A"

if $BOT_ENABLED && [[ "$BOT_HOST_ROLE" == "server_b" ]]; then
    info "Deploying Telegram bot to $BOT_HOST_LABEL ..."
    "$RUN_SH" --host "$BOT_HOST_IP" --ssh-key "$BOT_HOST_KEY" --ssh-user "$SSH_USER" \
        --vars-file "$ANSIBLE_DIR/group_vars/bot-host.yml" \
        || die "Telegram bot deployment failed on $BOT_HOST_LABEL"
    ok "Telegram bot deployed on $BOT_HOST_LABEL"
fi

# ================================================================
# STEP 8 — Upload and start Xray configs
# ================================================================
step "Step 8/8 — Deploying Xray configs"

deploy_xray_config "$INGRESS_CONFIG" "$SERVER_A_IP" "$SSH_KEY" "Server A ($SERVER_A_IP)"
ok "Xray ingress running on Server A"

if $TWO_SERVER; then
    deploy_xray_config "$EGRESS_CONFIG" "$SERVER_B_IP" "$SERVER_B_SSH_KEY" "Server B ($SERVER_B_IP)"
    ok "Xray egress running on Server B"
fi

# ================================================================
# Summary
# ================================================================
echo
echo -e "${G}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${G}  Quickstart complete!${NC}"
echo -e "${G}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo
echo "  Panel:          http://$SERVER_A_HOST/"
echo "  Health check:   curl http://$SERVER_A_HOST/health"
echo
echo "  Server A public key:  $SERVER_A_REALITY_PUBLIC_KEY"
$TWO_SERVER && echo "  Server B public key:  $SERVER_B_REALITY_PUBLIC_KEY"
echo
echo "Next steps:"
echo "  1. Open the panel and click 'Add client' to create the first VLESS user."
if $TWO_SERVER; then
    echo "  2. In 'Routing', configure direct/relay rules as needed (the panel"
    echo "     already knows where Server B is — just add overrides per destination)."
fi
if $BOT_ENABLED; then
    echo "  3. In Telegram, send /start to @${TELEGRAM_BOT_USERNAME:-your_bot} from"
    echo "     your admin account, then use /newfor <username> to invite the first user."
else
    echo "  3. To add Telegram bot support later, fill in TELEGRAM_* fields and re-run."
fi
echo
echo "  Panel credentials: token is in deploy/ansible/group_vars/all.secrets.yml"
echo "  (this file is gitignored and should never be committed)"
echo
