#!/usr/bin/env bash
# CorpVPN acceptance kit: installs the product on fresh VMs with its own
# installer and checks it end to end through its public interfaces only -
# deploy/quickstart.sh, the panel's HTTP API and SSH to the VMs.
#
#   tools/acceptance/run.sh [-e FILE] [stage...]    default: every stage, in order
#   tools/acceptance/run.sh --list
#
# Settings come from tools/acceptance/acceptance.env (a copy of
# acceptance.env.example). Everything a run produces - the installer's copy of
# the source with its generated secrets, lab passwords, client configs, logs -
# stays in WORK_DIR (mode 700); secrets never reach the terminal. Exit code 0:
# every selected stage passed; 1: a stage failed or was skipped; 2: bad usage
# or settings. See README.md.
set -uo pipefail

KIT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "$KIT_DIR/../.." && pwd)
STAGES=(install rerun traffic oidc ldap policy)
declare -A STAGE_INFO=(
    [install]="quickstart.sh in single mode: panel, break-glass sign-in, services"
    [rerun]="quickstart.sh again with the same settings: no key, peer or token changes"
    [traffic]="WireGuard, AmneziaWG and VLESS clients reach the internet through the gateway"
    [oidc]="Keycloak sign-in: groups become roles, users without a VPN group are refused"
    [ldap]="Samba AD sign-in incl. a nested group; offboarding suspends and restores devices"
    [policy]="split mode via the connector: full, split and blocked access profiles"
)
REMOTE_DIR=/var/lib/corpvpn-acceptance
REMOTE_SCRIPTS=(gateway.sh vpn-client.sh office-lan.sh samba-ad-setup.sh keycloak-setup.sh)
DC_NAME=dc.corp.example
OFFICE_PORT=8080

declare -A RESULTS=() HOST_OS=()
SUMMARY=() DEVICES=() SECRET_VALUES=() MASTERS=() PROTO_LIST=() TLS_ARGS=() CURL_TLS=() SSH_OPTS=()
TOKEN="" GATEWAY_EGRESS="" CLIENT_READY="" LOG="" SUDO="" CTL_DIR="" REVISION=""
STAGE_FAILED=0 STAGE_NOTE="" STAGE_SKIPPED="" NEW_ID="" PEER_DEVICE="" VLESS_DEVICE=""

# ------------------------------------------------------------------- output
log() { if [[ -n $LOG ]]; then printf '%s\n' "$*" >> "$LOG"; fi; }
say() { printf '%s\n' "$*"; log "$*"; }
pass() { say "   ok    $*"; }
info() { say "   ..    $*"; }
fail() {
    say "   FAIL  $*"
    STAGE_FAILED=1
    [[ -n $STAGE_NOTE ]] || STAGE_NOTE=$*
    return 1
}
skip() { STAGE_SKIPPED=$*; }
duration() { printf '%dm%02ds' $(($1 / 60)) $(($1 % 60)); }

kv() {  # kv <key> <text>: the value of the first "key=value" line
    local line
    while IFS= read -r line; do
        if [[ $line == "$1="* ]]; then
            printf '%s\n' "${line#*=}"
            return 0
        fi
    done <<< "$2"
    return 1
}

has_proto() { [[ ",$PROTOCOLS," == *",$1,"* ]]; }

# ----------------------------------------------------------------- settings
office_addresses() {  # office_addresses <cidr>: "<network> <connector address/prefix> <office host>"
    python3 - "$1" <<'PY'
import ipaddress, sys

try:
    net = ipaddress.ip_network(sys.argv[1], strict=False)
except ValueError:
    sys.exit(1)
if net.version != 4 or net.prefixlen > 30:
    sys.exit(1)
print(f"{net} {net.network_address + 1}/{net.prefixlen} {net.network_address + 2}")
PY
}

load_settings() {  # load_settings <file>: acceptance.env, checked; derived paths and URLs
    local file=$1 errors=() error host proto office tls_mode
    if [[ ! -f $file ]]; then
        echo "settings not found: $file" >&2
        echo "  cp $KIT_DIR/acceptance.env.example $KIT_DIR/acceptance.env, then fill it in" >&2
        return 1
    fi
    # shellcheck source=/dev/null
    source "$file" || { echo "cannot read $file" >&2; return 1; }
    GATEWAY_HOST=${GATEWAY_HOST:-}
    CONNECTOR_HOST=${CONNECTOR_HOST:-}
    CLIENT_HOST=${CLIENT_HOST:-$CONNECTOR_HOST}
    SSH_KEY=${SSH_KEY:-}
    SSH_USER=${SSH_USER:-root}
    PROTOCOLS=${PROTOCOLS:-wg,awg,vless}
    PROTOCOLS=${PROTOCOLS// /}
    OFFICE_CIDR=${OFFICE_CIDR:-172.30.0.0/24}
    SOURCE_REF=${SOURCE_REF:-HEAD}
    KEYCLOAK_IMAGE=${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak@sha256:09a381c715ab0b111835b70f2905955274843a219c6f27efb348e4d9f4086858}
    KEYCLOAK_PORT=${KEYCLOAK_PORT:-8081}
    SAMBA_IMAGE=${SAMBA_IMAGE:-nowsci/samba-domain@sha256:953f973514f19f236b0eb838b0e8c98c274b44f70c2bf7f817a0aa931e8f3eb9}
    EGRESS_URL=${EGRESS_URL:-https://1.1.1.1/cdn-cgi/trace}

    [[ -n $GATEWAY_HOST ]] || errors+=("GATEWAY_HOST is required")
    for host in "$GATEWAY_HOST" "$CONNECTOR_HOST" "$CLIENT_HOST"; do
        [[ -z $host || $host =~ ^[A-Za-z0-9.-]+$ ]] || errors+=("not a host name or IPv4 address: $host")
    done
    [[ -z $CLIENT_HOST || $CLIENT_HOST != "$GATEWAY_HOST" ]] \
        || errors+=("CLIENT_HOST must be another VM than the gateway")
    [[ -n $SSH_KEY && -f $SSH_KEY ]] || errors+=("SSH_KEY must name your private key file (got: ${SSH_KEY:-nothing})")
    [[ $SSH_USER =~ ^[a-z_][a-z0-9_.-]*$ ]] || errors+=("SSH_USER is not a user name: $SSH_USER")
    IFS=, read -r -a PROTO_LIST <<< "$PROTOCOLS"
    ((${#PROTO_LIST[@]})) || errors+=("PROTOCOLS lists no protocol")
    for proto in "${PROTO_LIST[@]}"; do
        [[ $proto == wg || $proto == awg || $proto == vless ]] || errors+=("unknown protocol in PROTOCOLS: $proto")
    done
    if office=$(office_addresses "$OFFICE_CIDR" 2> /dev/null); then
        read -r OFFICE_CIDR OFFICE_LAN OFFICE_HOST <<< "$office"
    else
        errors+=("OFFICE_CIDR must be an IPv4 network of /30 or larger: $OFFICE_CIDR")
    fi
    [[ $KEYCLOAK_PORT =~ ^[0-9]+$ ]] || errors+=("KEYCLOAK_PORT is not a port number: $KEYCLOAK_PORT")
    [[ $EGRESS_URL =~ ^https?://[0-9.]+(:[0-9]+)?/ ]] \
        || errors+=("EGRESS_URL must name an IPv4 address: the client's test namespace has no DNS")
    [[ $SOURCE_REF =~ ^[A-Za-z0-9._/@^~-]+$ ]] || errors+=("SOURCE_REF is not a git revision: $SOURCE_REF")
    if ((${#errors[@]})); then
        for error in "${errors[@]}"; do echo "$file: $error" >&2; done
        return 1
    fi

    SSH_KEY=$(cd "$(dirname "$SSH_KEY")" && pwd)/$(basename "$SSH_KEY")
    WORK_DIR=${WORK_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/corpvpn-acceptance/$GATEWAY_HOST}
    # quickstart.sh runs in another directory and gets paths inside WORK_DIR
    [[ $WORK_DIR == /* ]] || WORK_DIR=$PWD/$WORK_DIR
    SRC_DIR=$WORK_DIR/src
    QS_FILE=$SRC_DIR/deploy/quickstart.env
    SECRETS_FILE=$SRC_DIR/deploy/ansible/group_vars/all.secrets.yml
    LOG_DIR=$WORK_DIR/logs
    CLIENT_DIR=$WORK_DIR/client
    PROFILE_BACKUP=$WORK_DIR/default-profile.json
    OFFICE_URL=http://$OFFICE_HOST:$OFFICE_PORT/
    # The panel certificate is trusted only when quickstart gets a real one.
    tls_mode=${QUICKSTART_TLS_MODE:-auto}
    if [[ $tls_mode == auto ]]; then
        tls_mode=selfsigned
        [[ -n ${QUICKSTART_PANEL_FQDN:-} && -n ${QUICKSTART_CERTBOT_EMAIL:-} ]] && tls_mode=letsencrypt
    fi
    if [[ $tls_mode == none ]]; then
        PANEL_URL=${PANEL_URL:-http://${QUICKSTART_PANEL_FQDN:-$GATEWAY_HOST}}
    else
        PANEL_URL=${PANEL_URL:-https://${QUICKSTART_PANEL_FQDN:-$GATEWAY_HOST}}
    fi
    PANEL_URL=${PANEL_URL%/}
    if [[ $tls_mode == selfsigned ]]; then TLS_ARGS=(--insecure); CURL_TLS=(-k); fi
}

# ---------------------------------------------------------------------- SSH
ssh_setup() {
    CTL_DIR=$(mktemp -d "${TMPDIR:-/tmp}/cvacc.XXXXXX")
    SSH_OPTS=(-i "$SSH_KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new
              -o ConnectTimeout=20 -o ServerAliveInterval=15 -o ServerAliveCountMax=4
              -o ControlPath="$CTL_DIR/%C")
    if [[ $SSH_USER == root ]]; then SUDO=""; else SUDO="sudo -n "; fi
}

ssh_to() {  # ssh_to <host> <remote command>: stdin is not passed on
    ssh -n "${SSH_OPTS[@]}" "$SSH_USER@$1" "$2"
}

ssh_in() {  # ssh_in <host> <remote command>: stdin goes to the command
    # shellcheck disable=SC2029  # the remote command is composed here, from checked words
    ssh "${SSH_OPTS[@]}" "$SSH_USER@$1" "$2"
}

safe_words() {  # safe_words <word>...: joined, if a remote shell takes them as they are
    local word
    for word in "$@"; do
        if [[ ! $word =~ ^[A-Za-z0-9_.,:/@%+=-]+$ ]]; then
            log "refusing to pass to a remote shell: $word"
            return 1
        fi
    done
    printf '%s' "$*"
}

connect() {  # connect <host>: one shared SSH connection, a root shell, the kit's helpers on the VM
    local host=$1 os
    [[ -n ${HOST_OS[$host]:-} ]] && return 0
    ssh "${SSH_OPTS[@]}" -o ControlMaster=yes -o ControlPersist=600 -f -N "$SSH_USER@$host" \
        < /dev/null > /dev/null 2>> "$LOG" && MASTERS+=("$host")
    if ! os=$(ssh_to "$host" "${SUDO}sh -c '. /etc/os-release && echo \"\$PRETTY_NAME\"'" 2>> "$LOG"); then
        fail "no root shell on $host over SSH as $SSH_USER (a re-created VM keeps its old host key: ssh-keygen -R $host)"
        return 1
    fi
    if ! (cd "$KIT_DIR" && COPYFILE_DISABLE=1 tar -cf - "${REMOTE_SCRIPTS[@]}") \
        | ssh_in "$host" "${SUDO}sh -c 'umask 077 && mkdir -p $REMOTE_DIR/bin $REMOTE_DIR/client && tar -C $REMOTE_DIR/bin -xf - --no-same-owner'" \
        >> "$LOG" 2>&1; then
        fail "cannot copy the kit's helpers to $host"
        return 1
    fi
    HOST_OS[$host]=${os:-unknown OS}
}

remote() {  # remote <host> [VAR=value...] <script> [args...]: one of the kit's helpers, as root
    local host=$1 envs=() prefix="" words
    shift
    while [[ ${1:-} == [A-Z]*=* ]]; do envs+=("$1"); shift; done
    if ((${#envs[@]})); then prefix="env $(safe_words "${envs[@]}") " || return 2; fi
    words=$(safe_words "$@") || return 2
    ssh_to "$host" "${SUDO}${prefix}bash $REMOTE_DIR/bin/$words"
}

put_file() {  # put_file <host> <local file> <name>: to REMOTE_DIR/client/<name>, mode 600
    safe_words "$3" > /dev/null || return 2
    ssh_in "$1" "${SUDO}sh -c 'umask 077 && cat > $REMOTE_DIR/client/$3'" < "$2"
}

cleanup() {
    local host
    for host in "${MASTERS[@]}"; do
        ssh "${SSH_OPTS[@]}" -O exit "$SSH_USER@$host" > /dev/null 2>&1
    done
    if [[ -n $CTL_DIR ]]; then rm -rf "$CTL_DIR"; fi
}

# ------------------------------------------------------ source and installer
export_source() {  # a clean copy of the revision under test in SRC_DIR
    local tmp rev label
    tmp=$(mktemp -d "$WORK_DIR/src.XXXXXX") || { fail "cannot create a directory in $WORK_DIR"; return 1; }
    if git -C "$REPO_DIR" rev-parse --git-dir > /dev/null 2>&1; then
        if [[ $SOURCE_REF == worktree ]]; then
            # Include untracked product files while excluding all gitignored secrets.
            label="$(git -C "$REPO_DIR" rev-parse --short HEAD)+worktree"
            python3 - "$REPO_DIR" "$tmp" <<'PYTREE'
import pathlib,subprocess,sys,tarfile
root=pathlib.Path(sys.argv[1])
paths=subprocess.check_output(["git","-C",str(root),"ls-files","--cached","--others","--exclude-standard","-z"]).decode().split("\0")
with tarfile.open(pathlib.Path(sys.argv[2])/".worktree.tar","w") as archive:
    for name in sorted(set(paths)):
        if name and (root/name).is_file():archive.add(root/name,arcname=name,recursive=False)
PYTREE
            tar -xf "$tmp/.worktree.tar" -C "$tmp" && rm "$tmp/.worktree.tar" || return 1
            rev=""
        elif ! label=$(git -C "$REPO_DIR" rev-parse --short --verify "$SOURCE_REF^{commit}" 2>> "$LOG"); then
            rm -rf "$tmp"
            fail "SOURCE_REF is no revision of $REPO_DIR: $SOURCE_REF"
            return 1
        else
            rev=$SOURCE_REF
        fi
        if [[ -n $rev ]] && ! git -C "$REPO_DIR" archive --format=tar "$rev" | tar -xf - -C "$tmp"; then
            rm -rf "$tmp"
            fail "git archive $rev failed"
            return 1
        fi
    else
        # A release tarball: copied, but never an operator's own installer files.
        if ! (cd "$REPO_DIR" && tar -cf - --exclude=.git --exclude=.venv --exclude=__pycache__ --exclude=.env \
                --exclude=./deploy/quickstart.env --exclude=./deploy/ansible/inventory/hosts.yml \
                --exclude=./deploy/ansible/group_vars/all.yml --exclude=./deploy/ansible/group_vars/all.secrets.yml .) \
                | tar -xf - -C "$tmp"; then
            rm -rf "$tmp"
            fail "cannot copy $REPO_DIR"
            return 1
        fi
        label="$(basename "$REPO_DIR") (not a git checkout)"
    fi
    # An operator's checkout keeps its gitignored secrets across updates; so
    # does the kit (the break-glass token lives there).
    if [[ -f $SECRETS_FILE ]]; then cp -p "$SECRETS_FILE" "$tmp/deploy/ansible/group_vars/"; fi
    rm -rf "$SRC_DIR"
    mv "$tmp" "$SRC_DIR"
    REVISION=$label
    printf '%s\n' "$label" > "$WORK_DIR/revision"
    info "revision under test: $label"
}

qs_set() {  # qs_set <KEY> <value>: one setting in the quickstart.env the kit writes
    local tmp
    tmp=$(mktemp "$QS_FILE.XXXXXX") || return 1
    if [[ -f $QS_FILE ]]; then grep -v "^$1=" "$QS_FILE" > "$tmp"; fi
    printf "%s='%s'\n" "$1" "${2//\'/\'\\\'\'}" >> "$tmp"
    mv "$tmp" "$QS_FILE"
}

qs_write_base() {  # single mode, local sign-in; QUICKSTART_<NAME> settings passed on as <NAME>
    local var
    rm -f "$QS_FILE"
    qs_set SERVER_A_IP "$GATEWAY_HOST"
    qs_set SSH_KEY "$SSH_KEY"
    qs_set SSH_USER "$SSH_USER"
    qs_set PROTOCOLS "$PROTOCOLS"
    qs_set CORP_CIDRS "$OFFICE_CIDR"
    qs_set SITE_LAN_INTERFACE cvoffice0
    qs_set AUTH_MODE local
    while read -r var; do
        [[ -n $var ]] && qs_set "${var#QUICKSTART_}" "${!var}"
    done < <(compgen -v QUICKSTART_)
}

add_secret() { [[ -z $1 ]] || SECRET_VALUES+=("$1"); }

load_token() {  # TOKEN: the break-glass token quickstart.sh keeps in group_vars/all.secrets.yml
    TOKEN=$(python3 - "$SECRETS_FILE" <<'PY'
import json, sys

try:
    content = open(sys.argv[1], encoding="utf-8").read()
    try:
        print(json.loads(content)["panel_secret_token"])
        sys.exit(0)
    except (ValueError, KeyError):
        pass
    lines = content.splitlines()
except OSError:
    lines = []
for line in lines:
    if line.startswith("panel_secret_token:"):
        value = line.split(":", 1)[1].strip()
        try:
            print(json.loads(value) if value.startswith('"') else value.strip("'"))
        except ValueError:
            print(value.strip('"'))
        break
PY
)
    add_secret "$TOKEN"
}

redact() {  # redact <file>...: mask every secret the kit has seen
    ((${#SECRET_VALUES[@]})) || return 0
    SECRETS_TEXT=$(printf '%s\n' "${SECRET_VALUES[@]}") python3 - "$@" <<'PY'
import os, sys

secrets = sorted({s for s in os.environ["SECRETS_TEXT"].splitlines() if len(s) >= 8}, key=len, reverse=True)
for path in sys.argv[1:]:
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    masked = text
    for secret in secrets:
        masked = masked.replace(secret, "***")
    if masked != text:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(masked)
PY
}

run_quickstart() {  # run_quickstart <label>: the product's installer with the kit's settings
    local label=$1 qlog=$LOG_DIR/$1-quickstart.log start=$SECONDS rc
    command -v ansible-playbook > /dev/null \
        || { fail "ansible-playbook is not installed on this machine (pip install ansible-core)"; return 1; }
    info "quickstart.sh ($label) ... log: $qlog"
    (cd "$SRC_DIR" && bash deploy/quickstart.sh) < /dev/null > "$qlog" 2>&1
    rc=$?
    load_token
    redact "$qlog"
    if ((rc != 0)); then
        fail "quickstart.sh ($label) exited with $rc after $(duration $((SECONDS - start)))"
        tail -n 8 "$qlog" | sed 's/^/          /' | tee -a "$LOG"
        return 1
    fi
    pass "quickstart.sh ($label) finished in $(duration $((SECONDS - start)))"
}

install_gateway() {  # a fresh copy of the source, the base settings, one installer run
    export_source || return 1
    qs_write_base
    run_quickstart install
}

# -------------------------------------------------------------- panel API
panel_health() {  # the HTTP status of the panel's /health
    curl -s "${CURL_TLS[@]}" -o /dev/null -w '%{http_code}' --max-time 20 "$PANEL_URL/health" 2>> "$LOG"
}

papi() {  # papi <command> [args...]: panel_api.py as the break-glass admin
    PANEL_TOKEN=$TOKEN python3 "$KIT_DIR/panel_api.py" --panel "$PANEL_URL" "${TLS_ARGS[@]}" "$@" 2>> "$LOG"
}

portal() {  # portal <user> <password> <command> [args...]: panel_api.py as an employee
    local user=$1 password=$2
    shift 2
    PASSWORD=$password python3 "$KIT_DIR/panel_api.py" --panel "$PANEL_URL" "${TLS_ARGS[@]}" --user "$user" "$@" \
        2>> "$LOG"
}

signs_in() {  # signs_in <user> <password> <expect>: login_e2e.py, its verdict in the log
    PASSWORD=$2 python3 "$KIT_DIR/login_e2e.py" --panel "$PANEL_URL" "${TLS_ARGS[@]}" --user "$1" --expect "$3" \
        >> "$LOG" 2>&1
}

new_device() {  # new_device <user> <password> <protocol>: NEW_ID; revoked at the end of the stage
    local out
    NEW_ID=""
    out=$(portal "$1" "$2" device-create --protocol "$3" --name "acc-$3-$(date +%H%M%S)") || return 1
    NEW_ID=$(kv id "$out") || return 1
    DEVICES+=("$NEW_ID")
}

revoke_devices() {
    local id
    for id in "${DEVICES[@]}"; do
        papi device-revoke --id "$id" >> "$LOG" || info "could not revoke device $id"
    done
    DEVICES=()
}

profile_use() {  # profile_use <full|split> [cidr]: the default access profile the checks run under
    local args=(profile-set --backup "$PROFILE_BACKUP" --mode "$1")
    [[ -z ${2:-} ]] || args+=(--cidr "$2")
    papi "${args[@]}" >> "$LOG" || { fail "cannot set the default access profile to $1 ${2:-}"; return 1; }
}

profile_restore() {  # the operator's own default profile back (saved by the first profile_use)
    papi profile-restore --backup "$PROFILE_BACKUP" >> "$LOG" \
        || info "could not restore the default access profile; its settings are in $PROFILE_BACKUP"
}

# ------------------------------------------------------------ shared checks
check_gateway() {  # the panel answers, both break-glass paths work, the units run
    local code out kind name value bad=()
    [[ -n $TOKEN ]] || { fail "no break-glass token in $SECRETS_FILE"; return 1; }
    code=$(panel_health)
    if [[ $code == 200 ]]; then pass "panel answers: $PANEL_URL/health"; else fail "$PANEL_URL/health answered ${code:-nothing}"; fi
    if [[ $(kv role "$(papi whoami)") == admin ]]; then
        pass "the API accepts the break-glass token"
    else
        fail "the API refuses the break-glass token"
    fi
    if signs_in admin "$TOKEN" admin; then
        pass "the break-glass admin signs in on the login form"
    else
        fail "break-glass sign-in on the login form failed"
    fi
    out=$(remote "$GATEWAY_HOST" gateway.sh services "$PROTOCOLS" 2>> "$LOG")
    log "$out"
    while read -r kind name value; do
        case $kind in
            UNIT) [[ $value == active ]] || bad+=("$name is ${value:-unknown}") ;;
            NFT) [[ $value == present ]] || bad+=("nft table inet $name is missing") ;;
            RESTARTS) [[ $value == 0 ]] || bad+=("$name restarted ${value:-?} times") ;;
        esac
    done <<< "$out"
    if [[ -z $out ]]; then
        fail "no service report from the gateway"
    elif ((${#bad[@]})); then
        fail "gateway: ${bad[*]}"
    else
        pass "running: $(awk '$1 == "UNIT" {printf "%s ", $2}' <<< "$out")and the policy table"
    fi
}

ensure_installed() {  # for a stage run on its own: install first, or repair a panel that does not answer
    connect "$GATEWAY_HOST" || return 1
    if [[ ! -f $QS_FILE ]]; then
        info "no install by the kit in $WORK_DIR yet: installing first"
        install_gateway || return 1
    fi
    load_token
    [[ -n $TOKEN && $(panel_health) == 200 ]] && return 0
    info "the panel does not answer: quickstart.sh again with the last settings"
    run_quickstart repair || return 1
    [[ $(panel_health) == 200 ]] || { fail "the panel still does not answer on $PANEL_URL/health"; return 1; }
}

gateway_egress() {  # GATEWAY_EGRESS: the gateway's address as the internet sees it
    [[ -n $GATEWAY_EGRESS ]] && return 0
    GATEWAY_EGRESS=$(kv EGRESS "$(remote "$GATEWAY_HOST" EGRESS_URL="$EGRESS_URL" vpn-client.sh egress 2>> "$LOG")")
    if [[ -z $GATEWAY_EGRESS || $GATEWAY_EGRESS == none ]]; then
        GATEWAY_EGRESS=""
        fail "the gateway cannot reach $EGRESS_URL"
        return 1
    fi
}

prepare_client() {  # the client VM gets wireguard-tools and the gateway's own client binaries
    local missing
    connect "$CLIENT_HOST" || return 1
    [[ -n $CLIENT_READY ]] && return 0
    remote "$CLIENT_HOST" vpn-client.sh prepare >> "$LOG" 2>&1 \
        || { fail "cannot install the client tools on $CLIENT_HOST"; return 1; }
    missing=$(remote "$CLIENT_HOST" vpn-client.sh missing "$PROTOCOLS" 2>> "$LOG")
    if [[ -n $missing ]]; then
        info "copying the gateway's client binaries to $CLIENT_HOST (${missing//$'\n'/ })"
        ssh_to "$GATEWAY_HOST" "${SUDO}bash $REMOTE_DIR/bin/gateway.sh pack-client-tools $PROTOCOLS" 2>> "$LOG" \
            | ssh_in "$CLIENT_HOST" "${SUDO}bash $REMOTE_DIR/bin/vpn-client.sh unpack" >> "$LOG" 2>&1
        missing=$(remote "$CLIENT_HOST" vpn-client.sh missing "$PROTOCOLS" 2>> "$LOG")
        if [[ -n $missing ]]; then
            fail "client tools unusable on $CLIENT_HOST: ${missing//$'\n'/ } (give it the gateway's OS image)"
            return 1
        fi
    fi
    CLIENT_READY=1
    pass "client VM ready: $CLIENT_HOST"
}

fetch_config() {  # fetch_config <user> <password> <device> <variant> <name>: download, put on the client VM
    local file=$CLIENT_DIR/$5
    portal "$1" "$2" device-config --id "$3" --variant "$4" --out "$file" > /dev/null || return 1
    put_file "$CLIENT_HOST" "$file" "$5" 2>> "$LOG"
}

client_run() {  # client_run <vpn-client.sh args...>: the facts a check prints, also logged
    local out
    out=$(remote "$CLIENT_HOST" EGRESS_URL="$EGRESS_URL" vpn-client.sh "$@" 2>> "$LOG")
    log "$out"
    printf '%s\n' "$out"
}

probe_status() {  # probe_status <url> <client output>: the HTTP status of that probe, or "none"
    local kind url status
    while read -r kind url status; do
        if [[ $kind == PROBE && $url == "$1" ]]; then
            printf '%s\n' "$status"
            return 0
        fi
    done <<< "$2"
    echo none
}

handshake_wait() {  # seconds to wait for a first handshake: awg0 learns peers from a 30 s timer
    if [[ $1 == awg ]]; then echo 120; else echo 30; fi
}

peer_state() {  # peer_state <interface> <public key>: yes|no|no-interface
    kv PEER "$(remote "$GATEWAY_HOST" gateway.sh peer "$1" "$2" 2>> "$LOG")"
}

wait_peer() {  # wait_peer <interface> <public key> <yes|no> <seconds>
    local deadline=$((SECONDS + $4))
    until [[ $(peer_state "$1" "$2") == "$3" ]]; do
        ((SECONDS < deadline)) || return 1
        sleep 5
    done
}

snapshot_diff() {  # snapshot_diff <before> <after>: names whose fingerprint differs
    local -A was=()
    local name value changed=()
    while read -r name value; do
        [[ -n $name ]] && was[$name]=$value
    done <<< "$1"
    while read -r name value; do
        [[ -n $name ]] || continue
        [[ ${was[$name]-} == "$value" ]] || changed+=("$name")
        unset "was[$name]"
    done <<< "$2"
    changed+=("${!was[@]}")
    ((${#changed[@]})) || return 0
    printf '%s\n' "${changed[@]}" | sort | paste -sd' ' -
}

# -------------------------------------------------------------------- stages
stage_install() {
    connect "$GATEWAY_HOST" || return 1
    install_gateway || return 1
    check_gateway
}

stage_rerun() {
    local before after token_before changed
    ensure_installed || return 1
    before=$(remote "$GATEWAY_HOST" gateway.sh snapshot 2>> "$LOG")
    log "before the re-run:" "$before"
    grep -q '^wg0.public-key [0-9a-f]' <<< "$before" || { fail "no wg0 on the gateway to compare"; return 1; }
    token_before=$TOKEN
    run_quickstart rerun || return 1
    after=$(remote "$GATEWAY_HOST" gateway.sh snapshot 2>> "$LOG")
    log "after the re-run:" "$after"
    changed=$(snapshot_diff "$before" "$after")
    if [[ -z $changed ]]; then
        pass "nothing rotated: $(grep -c . <<< "$after") fingerprints of keys, peers, AmneziaWG parameters, REALITY key, token"
    else
        fail "the re-run changed: $changed"
    fi
    if [[ $TOKEN == "$token_before" ]]; then
        pass "break-glass token kept in group_vars/all.secrets.yml"
    else
        fail "the re-run generated a new break-glass token"
    fi
    check_gateway
}

traffic_check() {  # traffic_check <wg|awg|vless>: a portal device, its config on the client VM, real traffic
    local proto=$1 variant=$1 file out egress
    file=traffic-$proto.conf
    if [[ $proto == vless ]]; then variant=json; file=traffic-vless.json; fi
    new_device admin "$TOKEN" "$proto" || { fail "$proto: the portal did not create a device"; return 1; }
    fetch_config admin "$TOKEN" "$NEW_ID" "$variant" "$file" \
        || { fail "$proto: cannot download the device config or copy it to the client"; return 1; }
    if [[ $proto == vless ]]; then
        out=$(client_run vless "$REMOTE_DIR/client/$file")
    else
        out=$(client_run tunnel "$proto" "$REMOTE_DIR/client/$file" --wait "$(handshake_wait "$proto")")
    fi
    egress=$(kv EGRESS "$out")
    if [[ $proto != vless && $(kv HANDSHAKE "$out") != yes ]]; then
        fail "$proto: no handshake with the gateway"
    elif [[ $proto == vless && $(kv XRAY "$out") != started ]]; then
        fail "vless: the Xray client does not start with the panel's config"
    elif [[ $egress == "$GATEWAY_EGRESS" ]]; then
        pass "$proto: internet through the gateway (egress $egress)"
        if [[ $(kv IPV6 "$out") == blocked ]]; then pass "$proto: IPv6 is blocked through the tunnel/proxy"; else fail "$proto: IPv6 protection missing"; fi
    else
        fail "$proto: egress ${egress:-none}, expected the gateway's $GATEWAY_EGRESS"
    fi
}

stage_traffic() {
    local proto
    [[ -n $CLIENT_HOST ]] || { skip "set CLIENT_HOST or CONNECTOR_HOST: the VPN clients run on another VM"; return 0; }
    ensure_installed || return 1
    prepare_client || return 1
    gateway_egress || return 1
    profile_use full || return 1
    for proto in "${PROTO_LIST[@]}"; do
        traffic_check "$proto"
    done
    revoke_devices
    profile_restore
}

oidc_check() {  # oidc_check <user> <password> <expect> <what>
    if PASSWORD=$2 python3 "$KIT_DIR/oidc_e2e.py" --panel "$PANEL_URL" "${TLS_ARGS[@]}" --user "$1" --expect "$3" \
        >> "$LOG" 2>&1; then
        pass "OIDC $1: $4"
    else
        fail "OIDC $1: $4 does not hold (see $LOG)"
    fi
}

stage_oidc() {
    local env discovery code secret
    ensure_installed || return 1
    info "lab Keycloak in Docker on the gateway, TCP $KEYCLOAK_PORT"
    remote "$GATEWAY_HOST" PUBLIC_IP="$GATEWAY_HOST" PANEL_URL="$PANEL_URL" KC_IMAGE="$KEYCLOAK_IMAGE" \
        KC_PORT="$KEYCLOAK_PORT" keycloak-setup.sh >> "$LOG" 2>&1 \
        || { fail "keycloak-setup.sh failed on the gateway"; return 1; }
    env=$(ssh_to "$GATEWAY_HOST" "${SUDO}cat $REMOTE_DIR/keycloak.env" 2>> "$LOG")
    secret=$(kv CLIENT_SECRET "$env")
    [[ -n $secret ]] || { fail "no client secret in $REMOTE_DIR/keycloak.env on the gateway"; return 1; }
    add_secret "$secret"
    add_secret "$(kv KC_ADMIN_PASSWORD "$env")"
    add_secret "$(kv ALICE_PASSWORD "$env")"
    add_secret "$(kv BOB_PASSWORD "$env")"
    add_secret "$(kv CAROL_PASSWORD "$env")"
    discovery=http://$GATEWAY_HOST:$KEYCLOAK_PORT/realms/corp/.well-known/openid-configuration
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$discovery" 2>> "$LOG")
    if [[ $code != 200 ]]; then
        fail "Keycloak discovery answered ${code:-nothing} to this machine: open TCP $KEYCLOAK_PORT on the gateway"
        return 1
    fi
    pass "lab Keycloak answers: $discovery"
    qs_set AUTH_MODE oidc
    qs_set OIDC_DISCOVERY_URL "$discovery"
    qs_set OIDC_ALLOW_INSECURE_HTTP true
    qs_set OIDC_CLIENT_ID corpvpn
    qs_set OIDC_CLIENT_SECRET "$secret"
    qs_set AUTH_ADMIN_GROUPS vpn-admins
    qs_set AUTH_OPERATOR_GROUPS ""
    qs_set AUTH_USER_GROUPS vpn-users
    run_quickstart oidc || return 1
    oidc_check alice "$(kv ALICE_PASSWORD "$env")" admin "group vpn-admins -> admin"
    oidc_check bob "$(kv BOB_PASSWORD "$env")" user "group vpn-users -> user"
    oidc_check carol "$(kv CAROL_PASSWORD "$env")" denied "no VPN group -> refused"
    if signs_in admin "$TOKEN" admin; then
        pass "the break-glass admin still signs in"
    else
        fail "break-glass sign-in fails with OIDC on"
    fi
}

ldap_check() {  # ldap_check <user> <password> <expect> <what>
    if signs_in "$1" "$2" "$3"; then pass "LDAP $1: $4"; else fail "LDAP $1: $4 does not hold (see $LOG)"; fi
}

offboarding() {  # offboarding <dave's password>: a device follows its owner's directory account
    local password=$1 proto out ref id awg=false
    if has_proto wg; then proto=wg; elif has_proto awg; then proto=awg; else proto=vless; fi
    has_proto awg && [[ $proto != vless ]] && awg=true
    new_device dave "$password" "$proto" || { fail "offboarding: dave cannot add a device in the portal"; return 1; }
    id=$NEW_ID
    out=$(papi device-show --id "$id")
    ref=$(kv ref "$out")
    if [[ $(kv status "$out") != active ]]; then
        fail "offboarding: dave's new device is $(kv status "$out")"
    elif [[ $proto != vless && $(peer_state wg0 "$ref") != yes ]]; then
        fail "offboarding: dave's new device has no peer on wg0"
    else
        pass "offboarding: dave adds a device in the portal ($proto)"
    fi
    remote "$CONNECTOR_HOST" samba-ad-setup.sh user-disable dave >> "$LOG" 2>&1 \
        || { fail "cannot disable dave in the lab AD"; return 1; }
    out=$(papi directory-sync)
    log "$out"
    if [[ ",$(kv disabled "$out")," == *,dave,* ]]; then
        pass "offboarding: directory sync disables dave (disabled in AD)"
    else
        fail "offboarding: directory sync did not disable dave ($(kv error "$out"))"
    fi
    [[ $(kv status "$(papi user-show --username dave --provider ldap)") == disabled ]] \
        || fail "offboarding: dave is not disabled in the panel"
    [[ $(kv status "$(papi device-show --id "$id")") == suspended ]] \
        || fail "offboarding: dave's device is not suspended"
    if [[ $proto != vless ]]; then
        if [[ $(peer_state wg0 "$ref") == no ]] && { ! $awg || wait_peer awg0 "$ref" no 90; }; then
            pass "offboarding: the device is suspended and its peer removed"
        else
            fail "offboarding: the suspended device's peer is still on the gateway"
        fi
    fi
    if signs_in dave "$password" refused; then
        pass "offboarding: dave can no longer sign in"
    else
        fail "offboarding: dave still signs in"
    fi
    remote "$CONNECTOR_HOST" samba-ad-setup.sh user-enable dave >> "$LOG" 2>&1 \
        || { fail "cannot enable dave in the lab AD"; return 1; }
    if signs_in dave "$password" user \
        && [[ $(kv status "$(papi device-show --id "$id")") == active ]] \
        && { [[ $proto == vless ]] || [[ $(peer_state wg0 "$ref") == yes ]]; }; then
        pass "offboarding: re-enabled in AD, dave signs in and the device is back"
    else
        fail "offboarding: after re-enabling, dave's sign-in or device did not come back"
    fi
}

stage_ldap() {
    local connector_ip src env svc
    [[ -n $CONNECTOR_HOST ]] || { skip "CONNECTOR_HOST is not set: the lab AD runs there"; return 0; }
    ensure_installed || return 1
    connect "$CONNECTOR_HOST" || return 1
    gateway_egress || return 1
    connector_ip=$(python3 -c 'import socket, sys; print(socket.gethostbyname(sys.argv[1]))' "$CONNECTOR_HOST" \
        2>> "$LOG") || { fail "cannot resolve $CONNECTOR_HOST"; return 1; }
    src=$(kv SRC "$(remote "$GATEWAY_HOST" gateway.sh route-src "$connector_ip" 2>> "$LOG")")
    info "lab AD (Samba in Docker) on the connector, LDAPS from the gateway only"
    remote "$CONNECTOR_HOST" SAMBA_IMAGE="$SAMBA_IMAGE" samba-ad-setup.sh setup "$GATEWAY_EGRESS${src:+,$src}" \
        >> "$LOG" 2>&1 || { fail "samba-ad-setup.sh failed on the connector"; return 1; }
    env=$(ssh_to "$CONNECTOR_HOST" "${SUDO}cat $REMOTE_DIR/samba/samba.env" 2>> "$LOG")
    svc=$(kv SVC_PASSWORD "$env")
    [[ -n $svc ]] || { fail "no passwords in $REMOTE_DIR/samba/samba.env on the connector"; return 1; }
    add_secret "$svc"
    add_secret "$(kv DOMAIN_ADMIN_PASSWORD "$env")"
    add_secret "$(kv FRANK_PASSWORD "$env")"
    add_secret "$(kv DAVE_PASSWORD "$env")"
    add_secret "$(kv ERIN_PASSWORD "$env")"
    ssh_to "$CONNECTOR_HOST" "${SUDO}cat $REMOTE_DIR/samba/ca.pem" > "$WORK_DIR/samba-ca.pem" 2>> "$LOG" \
        || { fail "cannot fetch the lab CA certificate"; return 1; }
    remote "$GATEWAY_HOST" gateway.sh hosts-entry "$connector_ip" "$DC_NAME" >> "$LOG" 2>&1 \
        || { fail "cannot add $DC_NAME to the gateway's /etc/hosts"; return 1; }
    pass "lab AD ready: $DC_NAME at $connector_ip"
    qs_set AUTH_MODE ldap
    qs_set LDAP_URL "ldaps://$DC_NAME"
    qs_set LDAP_START_TLS false
    qs_set LDAP_BIND_DN "CN=svc-corpvpn,CN=Users,DC=corp,DC=example"
    qs_set LDAP_BIND_PASSWORD "$svc"
    qs_set LDAP_USER_BASE_DN "DC=corp,DC=example"
    qs_set LDAP_CA_FILE "$WORK_DIR/samba-ca.pem"
    qs_set AUTH_ADMIN_GROUPS vpn-admins
    qs_set AUTH_OPERATOR_GROUPS ""
    qs_set AUTH_USER_GROUPS vpn-users
    run_quickstart ldap || return 1
    ldap_check frank "$(kv FRANK_PASSWORD "$env")" admin "group vpn-admins -> admin"
    ldap_check dave "$(kv DAVE_PASSWORD "$env")" user "group vpn-users -> user"
    ldap_check erin "$(kv ERIN_PASSWORD "$env")" user "nested group vpn-nested in vpn-users -> user"
    ldap_check dave not-the-password failed "wrong password -> refused"
    ldap_check dave "" failed "empty password -> refused"
    ldap_check nobody-here not-the-password failed "unknown user -> refused"
    ldap_check svc-corpvpn "$svc" denied "account in no VPN group -> refused"
    offboarding "$(kv DAVE_PASSWORD "$env")"
    revoke_devices
}

expect_policy() {  # expect_policy <label> <case> <office status> <egress> [AllowedIPs of the config]
    local label=$1 case=$2 office=$3 egress=$4 allowed=${5:-} problems=()
    case $case in
        full)
            [[ $office == 200 ]] || problems+=("office unreachable ($office)")
            [[ $egress == "$GATEWAY_EGRESS" ]] || problems+=("internet egress $egress")
            ;;
        split)
            [[ $office == 200 ]] || problems+=("office unreachable ($office)")
            [[ $egress == none ]] || problems+=("internet reachable through the gateway ($egress)")
            if [[ -n $allowed ]]; then
                [[ ",$allowed," != *,0.0.0.0/0,* ]] || problems+=("the config routes everything ($allowed)")
                [[ ",$allowed," == *",$OFFICE_CIDR,"* ]] || problems+=("the config lacks $OFFICE_CIDR ($allowed)")
            fi
            ;;
        blocked)
            [[ $office == fail ]] || problems+=("office reachable ($office)")
            [[ $egress == "$GATEWAY_EGRESS" ]] || problems+=("internet egress $egress")
            ;;
    esac
    if ((${#problems[@]})); then
        fail "$label, $case profile: ${problems[*]}"
        return 1
    fi
    case $case in
        full) pass "$label, full profile: office reachable, internet through the gateway" ;;
        split) pass "$label, split profile: office reachable; the gateway drops internet traffic even when routed to it" ;;
        blocked) pass "$label, profile without the office: the gateway drops office traffic, internet works" ;;
    esac
}

policy_tunnel() {  # policy_tunnel <case> <wg|awg>
    local case=$1 variant=$2 file args out
    file=policy-$case-$variant.conf
    fetch_config admin "$TOKEN" "$PEER_DEVICE" "$variant" "$file" \
        || { fail "$variant, $case profile: cannot download the device config"; return 1; }
    args=(tunnel "$variant" "$REMOTE_DIR/client/$file" --wait "$(handshake_wait "$variant")" --probe "$OFFICE_URL")
    # split: route everything into the tunnel anyway; the gateway must still say no
    [[ $case != split ]] || args+=(--route-all)
    out=$(client_run "${args[@]}")
    [[ $(kv HANDSHAKE "$out") == yes ]] || { fail "$variant, $case profile: no handshake with the gateway"; return 1; }
    expect_policy "$variant" "$case" "$(probe_status "$OFFICE_URL" "$out")" "$(kv EGRESS "$out")" "$(kv ALLOWED "$out")"
}

policy_vless() {  # policy_vless <case>: the gateway's per-user Xray rules, the client proxying everything
    local case=$1 file out
    file=policy-$case-vless.json
    fetch_config admin "$TOKEN" "$VLESS_DEVICE" json "$file" \
        || { fail "vless, $case profile: cannot download the device config"; return 1; }
    out=$(client_run vless "$REMOTE_DIR/client/$file" --probe "$OFFICE_URL" --route-all)
    [[ $(kv XRAY "$out") == started ]] || { fail "vless, $case profile: the Xray client does not start"; return 1; }
    expect_policy vless "$case" "$(probe_status "$OFFICE_URL" "$out")" "$(kv EGRESS "$out")"
}

operator_download() {  # the operator's download of a split-profile device follows the profile too
    local file=$CLIENT_DIR/policy-operator.conf ref allowed
    ref=$(kv ref "$(papi device-show --id "$PEER_DEVICE")")
    papi peer-config --ref "$ref" --out "$file" > /dev/null \
        || { fail "operator download /api/peers/<key>/config failed"; return 1; }
    allowed=$(awk -F= '/^[[:space:]]*AllowedIPs[[:space:]]*=/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' "$file")
    if [[ ",$allowed," == *",$OFFICE_CIDR,"* && ",$allowed," != *,0.0.0.0/0,* && ",$allowed," == *,::/0,* ]]; then
        pass "operator download (/api/peers/<key>/config) follows the split profile"
    else
        fail "operator download (/api/peers/<key>/config) has AllowedIPs ${allowed:-none}, the profile $OFFICE_CIDR"
    fi
}

policy_case() {  # policy_case <full|split|blocked>
    local case=$1 variant
    case $case in
        full) profile_use full "$OFFICE_CIDR" ;;
        split) profile_use split "$OFFICE_CIDR" ;;
        blocked) profile_use full ;;
    esac || return 1
    if [[ -n $PEER_DEVICE ]]; then
        for variant in wg awg; do
            if has_proto "$variant"; then policy_tunnel "$case" "$variant"; fi
        done
        if [[ $case == split ]]; then operator_download; fi
    fi
    if [[ -n $VLESS_DEVICE ]]; then policy_vless "$case"; fi
}

stage_policy() {
    local out age case
    [[ -n $CONNECTOR_HOST ]] || { skip "CONNECTOR_HOST is not set: split mode needs the connector VM"; return 0; }
    ensure_installed || return 1
    connect "$CONNECTOR_HOST" || return 1
    out=$(remote "$CONNECTOR_HOST" office-lan.sh up "$OFFICE_LAN" "$OFFICE_HOST" "$OFFICE_PORT" 2>> "$LOG")
    [[ $(kv OFFICE "$out") == "$OFFICE_URL" ]] || { fail "cannot build the simulated office LAN on the connector"; return 1; }
    pass "simulated office LAN behind the connector: $OFFICE_URL"
    qs_set SERVER_B_IP "$CONNECTOR_HOST"
    qs_set SERVER_B_SSH_KEY "$SSH_KEY"
    qs_set CORP_CIDRS "$OFFICE_CIDR"
    qs_set SITE_LAN_INTERFACE cvoffice0
    run_quickstart policy || return 1
    age=$(kv SITE_LINK "$(remote "$GATEWAY_HOST" gateway.sh site-link 2>> "$LOG")")
    if [[ $age =~ ^[0-9]+$ ]] && ((age < 300)); then
        pass "site link up: last handshake ${age}s ago"
    else
        fail "no fresh site-link handshake (${age:-no answer}): can the connector reach UDP 51830 on the gateway?"
    fi
    prepare_client || return 1
    gateway_egress || return 1
    profile_use full "$OFFICE_CIDR" || return 1
    PEER_DEVICE="" VLESS_DEVICE=""
    if has_proto wg || has_proto awg; then
        if has_proto wg; then new_device admin "$TOKEN" wg; else new_device admin "$TOKEN" awg; fi
        PEER_DEVICE=$NEW_ID
        [[ -n $PEER_DEVICE ]] || fail "the portal did not create a WireGuard device"
    fi
    if has_proto vless; then
        new_device admin "$TOKEN" vless
        VLESS_DEVICE=$NEW_ID
        [[ -n $VLESS_DEVICE ]] || fail "the portal did not create a VLESS device"
    fi
    for case in full split blocked; do
        policy_case "$case"
    done
    revoke_devices
    profile_restore
}

# ------------------------------------------------------------------- driver
is_stage() {
    local stage
    for stage in "${STAGES[@]}"; do [[ $stage == "$1" ]] && return 0; done
    return 1
}

list_stages() {
    local stage
    for stage in "${STAGES[@]}"; do printf '  %-8s %s\n' "$stage" "${STAGE_INFO[$stage]}"; done
}

usage() {
    cat <<EOF
usage: run.sh [-e FILE] [stage...]
       run.sh --list

Installs CorpVPN on fresh VMs with deploy/quickstart.sh and checks it end to
end. Stages run in the order given; without any, all of them in this order:
$(list_stages)

  -e, --env FILE   settings (default: $KIT_DIR/acceptance.env)
  -l, --list       list the stages
  -h, --help       this help
EOF
}

run_stage() {  # run_stage <stage>
    local stage=$1 start=$SECONDS status
    LOG=$LOG_DIR/$stage.log
    : > "$LOG"
    STAGE_FAILED=0 STAGE_NOTE="" STAGE_SKIPPED="" DEVICES=()
    say ""
    say "==> $stage: ${STAGE_INFO[$stage]}"
    if [[ $stage != install && ${RESULTS[install]:-} == FAIL ]]; then
        skip "the install stage failed"
    elif ! "stage_$stage" && ((STAGE_FAILED == 0)); then
        fail "the stage stopped early (see $LOG)"
    fi
    if [[ -n $STAGE_SKIPPED ]]; then
        status=SKIP
        STAGE_NOTE=$STAGE_SKIPPED
        say "   SKIP  $STAGE_SKIPPED"
    elif ((STAGE_FAILED)); then
        status=FAIL
    else
        status=PASS
    fi
    RESULTS[$stage]=$status
    SUMMARY+=("$(printf '%-4s  %-8s %8s  %s' "$status" "$stage" "$(duration $((SECONDS - start)))" "$STAGE_NOTE")")
    redact "$LOG"
}

summary() {  # the result table, also in WORK_DIR/summary.txt; returns 0 only if every stage passed
    local line failed=0 total=${#SUMMARY[@]} role host
    for line in "${SUMMARY[@]}"; do [[ $line == PASS* ]] || failed=$((failed + 1)); done
    {
        echo ""
        echo "== CorpVPN acceptance summary"
        echo "revision   ${REVISION:-unknown}"
        for role in gateway connector client; do
            case $role in
                gateway) host=$GATEWAY_HOST ;;
                connector) host=$CONNECTOR_HOST ;;
                client) host=$CLIENT_HOST ;;
            esac
            [[ -z $host ]] || printf '%-10s %s  %s\n' "$role" "$host" "${HOST_OS[$host]:-}"
        done
        printf '%s\n' "${SUMMARY[@]}"
        if ((failed)); then
            echo "Result: FAIL ($failed of $total stages did not pass). Logs: $LOG_DIR"
        else
            echo "Result: PASS ($total of $total stages). Logs: $LOG_DIR"
        fi
    } | tee "$WORK_DIR/summary.txt"
    ((failed == 0))
}

main() {
    local env_file=$KIT_DIR/acceptance.env selected=() stage tool
    if ((BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4))); then
        echo "bash 4.4 or newer is required" >&2
        return 2
    fi
    while (($#)); do
        case $1 in
            -e|--env) [[ $# -ge 2 ]] || { usage >&2; return 2; }; env_file=$2; shift 2 ;;
            -l|--list) list_stages; return 0 ;;
            -h|--help) usage; return 0 ;;
            -*) echo "unknown option: $1" >&2; usage >&2; return 2 ;;
            *) is_stage "$1" || { echo "unknown stage: $1 (stages: ${STAGES[*]})" >&2; return 2; }
               selected+=("$1"); shift ;;
        esac
    done
    ((${#selected[@]})) || selected=("${STAGES[@]}")
    load_settings "$env_file" || return 2
    for tool in ssh tar python3 curl; do
        command -v "$tool" > /dev/null || { echo "$tool is required on this machine" >&2; return 2; }
    done
    (umask 077 && mkdir -p "$WORK_DIR" "$LOG_DIR" "$CLIENT_DIR") || { echo "cannot create $WORK_DIR" >&2; return 2; }
    chmod 700 "$WORK_DIR"
    REVISION=$(cat "$WORK_DIR/revision" 2> /dev/null)
    ssh_setup
    trap cleanup EXIT
    echo "CorpVPN acceptance: ${selected[*]}"
    echo "work directory: $WORK_DIR"
    for stage in "${selected[@]}"; do
        run_stage "$stage"
    done
    summary
}

# Sourced (tests): define the functions only.
(return 0 2> /dev/null) || { main "$@"; exit $?; }
