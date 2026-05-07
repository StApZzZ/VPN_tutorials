#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT

pass() {
    printf 'PASS: %s\n' "$1"
}

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

assert_contains() {
    local file=$1 pattern=$2
    grep -F -- "$pattern" "$file" >/dev/null || fail "Expected '$pattern' in $file"
}

assert_not_contains() {
    local file=$1 pattern=$2
    if grep -F -- "$pattern" "$file" >/dev/null; then
        fail "Did not expect '$pattern' in $file"
    fi
}

assert_line_count() {
    local file=$1 expected=$2
    local actual
    actual=$(wc -l < "$file")
    [[ "$actual" == "$expected" ]] || fail "Expected $expected lines in $file, got $actual"
}

new_case_dir() {
    mktemp -d "$TMP_ROOT/case.XXXXXX"
}

write_mock_ssh() {
    local case_dir=$1
    cat > "$case_dir/bin/ssh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

STATE_DIR=${MOCK_STATE_DIR:?}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|-o)
            shift 2
            ;;
        *)
            break
            ;;
    esac
done

target=${1:?missing target}
shift
host=${target#*@}
command=${*:-}
stdin_payload=""
if [[ ! -t 0 ]]; then
    stdin_payload=$(cat)
fi

profile="$STATE_DIR/$host.profile"
[[ -f "$profile" ]] || {
    echo "missing host profile for $host" >&2
    exit 1
}
# shellcheck source=/dev/null
source "$profile"

log_file="$STATE_DIR/$host.log"
touch "$log_file"

if [[ "$command" == "echo ok" ]]; then
    exit 0
fi

    if [[ "$command" == "bash -s" ]]; then
        printf '%s\n' "$stdin_payload" >> "$log_file"

        if grep -Fq 'https://api.telegram.org/bot' <<<"$stdin_payload"; then
            case "${MOCK_TELEGRAM_API:-fail}" in
                ok)
                    printf '{"ok":true,"result":{"id":123,"is_bot":true}}\n'
                    exit 0
                    ;;
                *)
                    echo "telegram api unreachable" >&2
                    exit 1
                    ;;
            esac
        fi

        if grep -Fq "supported package manager not found" <<<"$stdin_payload"; then
            if [[ "${MOCK_SYSTEMD:-1}" != "1" ]]; then
                echo "error: quickstart supports only systemd-based hosts." >&2
                exit 1
        fi
        case "${MOCK_PKG_MANAGER:-}" in
            apt-get|dnf|yum)
                ;;
            *)
                echo "error: supported package manager not found (expected apt-get, dnf, or yum)." >&2
                exit 1
                ;;
        esac
        grep -F 'curl ca-certificates openssl unzip' <<<"$stdin_payload" >/dev/null || {
            echo "bootstrap script did not install unzip" >&2
            exit 1
        }
        grep -F '10-donot_touch_multi_conf.conf' <<<"$stdin_payload" >/dev/null || {
            echo "bootstrap script did not pre-create systemd drop-in files" >&2
            exit 1
        }
        printf 'bootstrap:%s\n' "${MOCK_PKG_MANAGER:-}" >> "$log_file"
        touch "$STATE_DIR/$host.openssl"
        touch "$STATE_DIR/$host.curl"
        touch "$STATE_DIR/$host.unzip"
        exit 0
    fi

    if grep -Fq 'TERM=dumb JSON_PATH="/etc/xray" bash "$tmp_installer" install' <<<"$stdin_payload"; then
        if [[ "${MOCK_DOWNLOAD_FAIL:-0}" == "1" ]]; then
            echo "curl: download failed" >&2
            exit 1
        fi
        printf 'install\n' >> "$log_file"
        printf '%s\n' "$stdin_payload" > "$STATE_DIR/$host.install-script"
        if [[ "${MOCK_INSTALL_MISSING_XRAY:-0}" != "1" ]]; then
            touch "$STATE_DIR/$host.xray"
        fi
        if [[ "${MOCK_WRONG_SERVICE_PATH:-0}" == "1" ]]; then
            printf '/usr/local/etc/xray/config.json\n' > "$STATE_DIR/$host.service-path"
        else
            printf '/etc/xray/config.json\n' > "$STATE_DIR/$host.service-path"
        fi
        [[ -f "$STATE_DIR/$host.xray" ]] || {
            echo "xray binary missing after install" >&2
            exit 1
        }
        grep -Fx '/etc/xray/config.json' "$STATE_DIR/$host.service-path" >/dev/null || {
            echo "service path mismatch" >&2
            exit 1
        }
        exit 0
    fi

    if grep -Fq 'run -test -config "$tmp_config"' <<<"$stdin_payload"; then
        [[ -f "$STATE_DIR/$host.upload" ]] || {
            echo "missing uploaded config for $host" >&2
            exit 1
        }
        if [[ "${MOCK_VALIDATE_FAIL:-0}" == "1" ]]; then
            echo "config validation failed" >&2
            exit 1
        fi
        printf 'validate-and-start\n' >> "$log_file"
        touch "$STATE_DIR/$host.xray-active"
        exit 0
    fi

    if grep -Fq 'x25519' <<<"$stdin_payload"; then
        [[ -f "$STATE_DIR/$host.xray" ]] || {
            echo "Xray binary not found at /usr/local/bin/xray." >&2
            exit 1
        }
        [[ -f "$STATE_DIR/$host.openssl" ]] || {
            echo "openssl is required for REALITY key generation." >&2
            exit 1
        }
        if [[ "${MOCK_X25519_FORMAT:-current}" == "legacy" ]]; then
            cat <<KEYS
Private key: PRIVATE-$host
Public key: PUBLIC-$host
abcd1234
KEYS
        else
            cat <<KEYS
PrivateKey: PRIVATE-$host
Password (PublicKey): PUBLIC-$host
Hash32: HASH-$host
abcd1234
KEYS
        fi
        exit 0
    fi

    echo "unexpected bash -s payload" >&2
    exit 1
fi

echo "unexpected ssh command: $command" >&2
exit 1
EOF
    chmod +x "$case_dir/bin/ssh"
}

write_mock_scp() {
    local case_dir=$1
    cat > "$case_dir/bin/scp" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

STATE_DIR=${MOCK_STATE_DIR:?}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|-o)
            shift 2
            ;;
        -q)
            shift
            ;;
        *)
            break
            ;;
    esac
done

src=${1:?missing src}
dst_spec=${2:?missing dst}
host=${dst_spec#*@}
host=${host%%:*}
cp "$src" "$STATE_DIR/$host.upload"
EOF
    chmod +x "$case_dir/bin/scp"
}

setup_case() {
    local case_dir=$1

    mkdir -p "$case_dir/bin" "$case_dir/deploy" "$case_dir/state" "$case_dir/.ssh"
    cp "$REPO_ROOT/deploy/quickstart.sh" "$case_dir/deploy/quickstart.sh"

    cat > "$case_dir/deploy/run.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${MOCK_STATE_DIR:?}/run.log"
EOF
    chmod +x "$case_dir/deploy/run.sh"

    cat > "$case_dir/deploy/quickstart.env" <<EOF
SERVER_A_IP=server-a
SSH_KEY=$case_dir/.ssh/id_ed25519
PANEL_SECRET_TOKEN=test-token
REALITY_SERVER_NAME=www.microsoft.com
EOF

    printf 'dummy-key\n' > "$case_dir/.ssh/id_ed25519"
    chmod 600 "$case_dir/.ssh/id_ed25519"

    write_mock_ssh "$case_dir"
    write_mock_scp "$case_dir"
}

enable_two_server_case() {
    local case_dir=$1
    cat >> "$case_dir/deploy/quickstart.env" <<'EOF'
SERVER_B_IP=server-b
EOF
}

enable_telegram_bot_case() {
    local case_dir=$1
    cat >> "$case_dir/deploy/quickstart.env" <<'EOF'
TELEGRAM_BOT_TOKEN=test-telegram-token
TELEGRAM_ADMIN_IDS=123456789
TELEGRAM_BOT_USERNAME=corpvpn_bot
EOF
}

run_case() {
    local case_dir=$1
    local output=$2
    (
        export MOCK_STATE_DIR="$case_dir/state"
        export PATH="$case_dir/bin:$PATH"
        cd "$case_dir"
        bash deploy/quickstart.sh
    ) >"$output" 2>&1
}

test_debian_bootstrap_success() {
    local case_dir output
    case_dir=$(new_case_dir)
    setup_case "$case_dir"
    cat > "$case_dir/state/server-a.profile" <<'EOF'
MOCK_SYSTEMD=1
MOCK_PKG_MANAGER=apt-get
EOF
    output="$case_dir/output.log"

    if ! run_case "$case_dir" "$output"; then
        cat "$output" >&2
        fail "Debian-like bootstrap case should succeed"
    fi

    assert_contains "$output" "Xray installed on Server A (server-a)"
    assert_contains "$case_dir/state/server-a.log" "bootstrap:apt-get"
    assert_contains "$case_dir/state/server-a.install-script" 'TERM=dumb JSON_PATH="/etc/xray" bash "$tmp_installer" install'
    pass "Debian-like bootstrap installs prerequisites and Xray"
}

test_oracle_bootstrap_success() {
    local case_dir output
    case_dir=$(new_case_dir)
    setup_case "$case_dir"
    cat > "$case_dir/state/server-a.profile" <<'EOF'
MOCK_SYSTEMD=1
MOCK_PKG_MANAGER=dnf
EOF
    output="$case_dir/output.log"

    if ! run_case "$case_dir" "$output"; then
        cat "$output" >&2
        fail "Oracle-like bootstrap case should succeed"
    fi

    assert_contains "$case_dir/state/server-a.log" "bootstrap:dnf"
    assert_contains "$output" "Quickstart complete!"
    pass "Oracle-like bootstrap supports dnf"
}

test_legacy_x25519_output_remains_compatible() {
    local case_dir output
    case_dir=$(new_case_dir)
    setup_case "$case_dir"
    enable_two_server_case "$case_dir"
    cat > "$case_dir/state/server-a.profile" <<'EOF'
MOCK_SYSTEMD=1
MOCK_PKG_MANAGER=apt-get
MOCK_X25519_FORMAT=legacy
EOF
    cat > "$case_dir/state/server-b.profile" <<'EOF'
MOCK_SYSTEMD=1
MOCK_PKG_MANAGER=apt-get
MOCK_X25519_FORMAT=legacy
EOF
    output="$case_dir/output.log"

    if ! run_case "$case_dir" "$output"; then
        cat "$output" >&2
        fail "Legacy x25519 output case should succeed"
    fi

    assert_contains "$case_dir/state/server-a.upload" '"password": "PUBLIC-server-b"'
    pass "Legacy x25519 output remains compatible"
}

test_two_server_ingress_config_uses_password_field() {
    local case_dir output
    case_dir=$(new_case_dir)
    setup_case "$case_dir"
    enable_two_server_case "$case_dir"
    cat > "$case_dir/state/server-a.profile" <<'EOF'
MOCK_SYSTEMD=1
MOCK_PKG_MANAGER=apt-get
EOF
    cat > "$case_dir/state/server-b.profile" <<'EOF'
MOCK_SYSTEMD=1
MOCK_PKG_MANAGER=apt-get
EOF
    output="$case_dir/output.log"

    if ! run_case "$case_dir" "$output"; then
        cat "$output" >&2
        fail "Two-server REALITY config case should succeed"
    fi

    assert_contains "$case_dir/state/server-a.upload" '"password": "PUBLIC-server-b"'
    assert_not_contains "$case_dir/state/server-a.upload" '"publicKey"'
    pass "Two-server ingress config uses REALITY password field"
}

test_two_server_selects_server_b_for_telegram_bot() {
    local case_dir output
    case_dir=$(new_case_dir)
    setup_case "$case_dir"
    enable_two_server_case "$case_dir"
    enable_telegram_bot_case "$case_dir"
    cat > "$case_dir/state/server-a.profile" <<'EOF'
MOCK_SYSTEMD=1
MOCK_PKG_MANAGER=apt-get
MOCK_TELEGRAM_API=fail
EOF
    cat > "$case_dir/state/server-b.profile" <<'EOF'
MOCK_SYSTEMD=1
MOCK_PKG_MANAGER=apt-get
MOCK_TELEGRAM_API=ok
EOF
    output="$case_dir/output.log"

    if ! run_case "$case_dir" "$output"; then
        cat "$output" >&2
        fail "Two-server Telegram placement case should succeed"
    fi

    assert_contains "$output" "Telegram bot will run on Server B (server-b)"
    assert_line_count "$case_dir/state/run.log" 2
    assert_contains "$case_dir/state/run.log" "--host server-a"
    assert_contains "$case_dir/state/run.log" "--host server-b"
    assert_contains "$case_dir/deploy/ansible/group_vars/all.yml" "vpn_panel_bot_enabled: false"
    assert_contains "$case_dir/deploy/ansible/group_vars/bot-host.yml" "vpn_panel_panel_enabled: false"
    assert_contains "$case_dir/deploy/ansible/group_vars/bot-host.yml" "vpn_panel_nginx_enabled: false"
    assert_contains "$case_dir/deploy/ansible/group_vars/bot-host.yml" 'vpn_panel_telegram_panel_base_url: "http://server-a"'
    pass "Two-server quickstart places Telegram bot on Server B and points it at Server A"
}

test_two_server_fails_when_only_server_a_reaches_telegram() {
    local case_dir output
    case_dir=$(new_case_dir)
    setup_case "$case_dir"
    enable_two_server_case "$case_dir"
    enable_telegram_bot_case "$case_dir"
    cat > "$case_dir/state/server-a.profile" <<'EOF'
MOCK_SYSTEMD=1
MOCK_PKG_MANAGER=apt-get
MOCK_TELEGRAM_API=ok
EOF
    cat > "$case_dir/state/server-b.profile" <<'EOF'
MOCK_SYSTEMD=1
MOCK_PKG_MANAGER=apt-get
MOCK_TELEGRAM_API=fail
EOF
    output="$case_dir/output.log"

    if run_case "$case_dir" "$output"; then
        fail "Quickstart should fail when Telegram is reachable only from Server A in a two-server deployment"
    fi

    assert_contains "$output" "two-server quickstart pins the Telegram bot to Server B"
    pass "Two-server quickstart refuses to place the Telegram bot on Server A"
}

test_unsupported_package_manager_fails() {
    local case_dir output
    case_dir=$(new_case_dir)
    setup_case "$case_dir"
    cat > "$case_dir/state/server-a.profile" <<'EOF'
MOCK_SYSTEMD=1
MOCK_PKG_MANAGER=
EOF
    output="$case_dir/output.log"

    if run_case "$case_dir" "$output"; then
        fail "Unsupported package manager case should fail"
    fi

    assert_contains "$output" "supported package manager not found"
    pass "Unsupported hosts fail with a clear package-manager error"
}

test_download_failure_does_not_report_success() {
    local case_dir output
    case_dir=$(new_case_dir)
    setup_case "$case_dir"
    cat > "$case_dir/state/server-a.profile" <<'EOF'
MOCK_SYSTEMD=1
MOCK_PKG_MANAGER=apt-get
MOCK_DOWNLOAD_FAIL=1
EOF
    output="$case_dir/output.log"

    if run_case "$case_dir" "$output"; then
        fail "Download failure case should fail"
    fi

    assert_contains "$output" "Xray install failed on Server A (server-a)"
    assert_not_contains "$output" "Xray installed on Server A (server-a)"
    pass "Installer download failures stop the script without a false success marker"
}

test_missing_binary_is_caught() {
    local case_dir output
    case_dir=$(new_case_dir)
    setup_case "$case_dir"
    cat > "$case_dir/state/server-a.profile" <<'EOF'
MOCK_SYSTEMD=1
MOCK_PKG_MANAGER=apt-get
MOCK_INSTALL_MISSING_XRAY=1
EOF
    output="$case_dir/output.log"

    if run_case "$case_dir" "$output"; then
        fail "Missing xray binary case should fail"
    fi

    assert_contains "$output" "Xray install failed on Server A (server-a)"
    pass "Post-install verification catches a missing xray binary"
}

test_wrong_service_path_is_caught() {
    local case_dir output
    case_dir=$(new_case_dir)
    setup_case "$case_dir"
    cat > "$case_dir/state/server-a.profile" <<'EOF'
MOCK_SYSTEMD=1
MOCK_PKG_MANAGER=apt-get
MOCK_WRONG_SERVICE_PATH=1
EOF
    output="$case_dir/output.log"

    if run_case "$case_dir" "$output"; then
        fail "Wrong service path case should fail"
    fi

    assert_contains "$output" "Xray install failed on Server A (server-a)"
    pass "Post-install verification catches a wrong systemd config path"
}

test_debian_bootstrap_success
test_oracle_bootstrap_success
test_legacy_x25519_output_remains_compatible
test_two_server_ingress_config_uses_password_field
test_two_server_selects_server_b_for_telegram_bot
test_two_server_fails_when_only_server_a_reaches_telegram
test_unsupported_package_manager_fails
test_download_failure_does_not_report_success
test_missing_binary_is_caught
test_wrong_service_path_is_caught
