#!/usr/bin/env bash
# Acceptance kit, runs as root on the CLIENT VM: real VPN clients built from
# the panel's own client configs.
#
#   vpn-client.sh prepare                install wireguard-tools, curl, ping, python3
#   vpn-client.sh unpack                 client binaries from the gateway: a tar.gz on
#                                        stdin (gateway.sh pack-client-tools)
#   vpn-client.sh missing <protocols>    client tools that are absent or do not run
#   vpn-client.sh tunnel wg|awg <file.conf> [--wait SECONDS] [--probe URL]... [--route-all]
#   vpn-client.sh vless <file.json> [--probe URL]... [--route-all]
#   vpn-client.sh egress                 this VM's own public address
#   vpn-client.sh down                   remove whatever a check left behind
#
# tunnel: the WireGuard / AmneziaWG interface is created in the root namespace,
# so its UDP socket uses this VM's uplink, and then moved into the namespace
# "cvacc": only that namespace routes through the tunnel, while the VM keeps its
# own connectivity and the SSH session. vless: Xray runs with the panel's JSON
# and every check goes through its local SOCKS port. --route-all sends
# everything into the tunnel / proxy whatever the config's split says, to show
# that the GATEWAY enforces the access profile.
#
# A check prints facts, one per line, and leaves the verdict to the caller:
#   ALLOWED=<AllowedIPs of the config>  HANDSHAKE=yes|no  XRAY=started|failed
#   EGRESS=<public address seen through the tunnel or proxy>|none
#   PROBE <url> <HTTP status>|fail
# EGRESS_URL (default https://1.1.1.1/cdn-cgi/trace) reports the caller's address.
set -uo pipefail

NS=cvacc
IFACE=cvacc0
EGRESS_URL=${EGRESS_URL:-https://1.1.1.1/cdn-cgi/trace}
RUN_DIR=/run/corpvpn-acceptance
XRAY_PID=$RUN_DIR/xray.pid

die() { echo "error: $*" >&2; exit 2; }
in_ns() { ip netns exec "$NS" "$@"; }

strip_conf() {  # strip_conf <file>: only the keys `wg setconf` / `awg setconf` accept
    awk '
        /^[[:space:]]*\[/ { gsub(/[[:space:]]/, ""); print; next }
        /^[[:space:]]*([#;]|$)/ { next }
        {
            key = $0; sub(/[[:space:]]*=.*/, "", key); gsub(/[[:space:]]/, "", key)
            value = $0; sub(/^[^=]*=[[:space:]]*/, "", value); sub(/[[:space:]]+$/, "", value)
            if (value == "") next
            if (key ~ /^(PrivateKey|ListenPort|FwMark|PublicKey|PresharedKey|AllowedIPs|Endpoint|PersistentKeepalive|Jc|Jmin|Jmax|S[1-4]|H[1-4]|I[1-5])$/)
                print key " = " value
        }' "$1"
}

conf_value() {  # conf_value <file> <Key>: the first value of Key, spaces removed
    awk -v want="$2" '
        { key = $0; sub(/[[:space:]]*=.*/, "", key); gsub(/[[:space:]]/, "", key) }
        key == want { sub(/^[^=]*=/, ""); gsub(/[[:space:]]/, ""); print; exit }' "$1"
}

first_v4() {  # first_v4 "10.66.0.2/32,fd00::2/128" -> 10.66.0.2/32
    local item items
    IFS=, read -r -a items <<< "$1"
    for item in "${items[@]}"; do
        [[ -n $item && $item != *:* ]] && { echo "$item"; return 0; }
    done
    return 1
}

next_address() {  # next_address 172.30.0.0/24 -> 172.30.0.1 (a /32 stays itself)
    local net=${1%/*} bits=32 a b c d n
    [[ $1 == */* ]] && bits=${1#*/}
    IFS=. read -r a b c d <<< "$net"
    n=$(( (a << 24) | (b << 16) | (c << 8) | d ))
    ((bits < 32)) && n=$((n + 1))
    echo "$(( (n >> 24) & 255 )).$(( (n >> 16) & 255 )).$(( (n >> 8) & 255 )).$(( n & 255 ))"
}

url_host() {  # url_host https://1.1.1.1/cdn-cgi/trace -> 1.1.1.1
    local rest=${1#*://}
    rest=${rest%%/*}
    echo "${rest%%:*}"
}

parse_egress() {  # parse_egress <body>: the address of an "ip=" line, or a bare address
    local ip
    ip=$(printf '%s\n' "$1" | sed -n 's/^ip=//p' | head -n1 | tr -d '[:space:]')
    if [[ -z $ip ]]; then
        ip=$(printf '%s' "$1" | tr -d '[:space:]')
        [[ $ip =~ ^[0-9a-fA-F.:]+$ ]] || ip=""
    fi
    echo "${ip:-none}"
}

probe() {  # probe <url> [curl options...]: the HTTP status, or "fail"; one retry
    local url=$1 code
    shift
    for _ in 1 2; do
        code=$("$@" curl -s -o /dev/null -m 8 -w '%{http_code}' "$url" 2>/dev/null)
        [[ $code =~ ^[1-5][0-9][0-9]$ ]] && { echo "$code"; return 0; }
        sleep 1
    done
    echo fail
}

down() {
    if [[ -f $XRAY_PID ]]; then
        kill "$(cat "$XRAY_PID")" 2>/dev/null
        rm -f "$XRAY_PID"
    fi
    pkill -f "amneziawg-go $IFACE" 2>/dev/null
    ip netns del "$NS" 2>/dev/null
    ip link del "$IFACE" 2>/dev/null
    rm -f "/var/run/amneziawg/$IFACE.sock" "/var/run/wireguard/$IFACE.sock"
    return 0
}

tunnel() {  # tunnel <wg|awg> <config> [--wait SECONDS] [--probe URL]... [--route-all]
    local kind=${1:-} conf=${2:-} wait=30 route_all=false probes=() tool=wg
    [[ $kind == wg || $kind == awg ]] || die "tunnel: the first argument is wg or awg"
    [[ -f $conf ]] || die "no such config: $conf"
    shift 2
    while (($#)); do
        case $1 in
            --wait) wait=${2:?--wait needs seconds}; shift 2 ;;
            --probe) probes+=("${2:?--probe needs a URL}"); shift 2 ;;
            --route-all) route_all=true; shift ;;
            *) die "unknown option: $1" ;;
        esac
    done
    [[ $kind == awg ]] && tool=awg
    command -v "$tool" >/dev/null || die "$tool is missing (vpn-client.sh prepare / unpack)"
    local addr mtu allowed peer target stripped hs deadline egress url nets net
    addr=$(first_v4 "$(conf_value "$conf" Address)") || die "no IPv4 Address in $conf"
    mtu=$(conf_value "$conf" MTU)
    allowed=$(conf_value "$conf" AllowedIPs)
    peer=$(conf_value "$conf" PublicKey)

    down
    trap down EXIT
    if [[ $kind == wg ]]; then
        ip link add "$IFACE" type wireguard || die "cannot create a WireGuard interface (kernel module?)"
    else
        command -v amneziawg-go >/dev/null || die "amneziawg-go is missing (vpn-client.sh unpack)"
        amneziawg-go "$IFACE" >/dev/null 2>&1 || die "amneziawg-go did not start"
        for _ in $(seq 1 25); do ip link show "$IFACE" >/dev/null 2>&1 && break; sleep 0.2; done
    fi
    stripped=$(mktemp)
    strip_conf "$conf" > "$stripped"
    "$tool" setconf "$IFACE" "$stripped" || { rm -f "$stripped"; die "$tool setconf rejected $conf"; }
    rm -f "$stripped"
    ip netns add "$NS" || die "cannot create the namespace $NS"
    ip link set "$IFACE" netns "$NS" || die "cannot move $IFACE into $NS"
    in_ns ip link set lo up
    in_ns ip addr add "$addr" dev "$IFACE"
    in_ns ip link set "$IFACE" mtu "${mtu:-1380}" up
    in_ns ip -6 addr add fd66::2/128 dev "$IFACE"
    echo "ALLOWED=$allowed"
    if $route_all; then
        in_ns "$tool" set "$IFACE" peer "$peer" allowed-ips 0.0.0.0/0,::/0 || die "cannot widen AllowedIPs"
        in_ns ip route add default dev "$IFACE"
        in_ns ip -6 route add default dev "$IFACE"
    else
        IFS=, read -r -a nets <<< "$allowed"
        for net in "${nets[@]}"; do
            [[ -z $net ]] && continue
            if [[ $net == *:* ]]; then
                in_ns ip -6 route add "$net" dev "$IFACE"
                continue
            fi
            if [[ $net == 0.0.0.0/0 ]]; then
                in_ns ip route add default dev "$IFACE"
            else
                in_ns ip route add "$net" dev "$IFACE"
            fi
        done
    fi

    # A handshake starts with the first packet; AmneziaWG peers reach awg0
    # through the gateway's peer sync, so allow for its interval.
    if ((${#probes[@]})); then
        target=$(url_host "${probes[0]}")
    elif $route_all || [[ ",$allowed," == *,0.0.0.0/0,* ]]; then
        target=$(url_host "$EGRESS_URL")
    else
        target=$(next_address "$(first_v4 "$allowed")")
    fi
    deadline=$((SECONDS + wait))
    while :; do
        hs=$(in_ns "$tool" show "$IFACE" latest-handshakes 2>/dev/null | awk '{print $2; exit}')
        [[ ${hs:-0} =~ ^[1-9][0-9]*$ ]] && break
        ((SECONDS >= deadline)) && break
        in_ns ping -c1 -W1 "$target" >/dev/null 2>&1
        sleep 1
    done
    if [[ ${hs:-0} =~ ^[1-9][0-9]*$ ]]; then echo "HANDSHAKE=yes"; else echo "HANDSHAKE=no"; fi

    egress=none
    for _ in 1 2; do
        egress=$(parse_egress "$(in_ns curl -s -m 8 "$EGRESS_URL" 2>/dev/null)")
        [[ $egress != none ]] && break
        sleep 2
    done
    echo "EGRESS=$egress"
    if [[ ",$allowed," == *,::/0,* ]] && [[ $(probe "http://[2606:4700:4700::1111]/" in_ns) == fail ]]; then
        echo "IPV6=blocked"
    else
        echo "IPV6=unprotected"
    fi
    for url in "${probes[@]}"; do
        echo "PROBE $url $(probe "$url" in_ns)"
    done
}

vless_config() {  # vless_config <src> <dst> <route-all true|false>: prints the SOCKS port
    python3 - "$@" <<'PY'
import json, os, sys

src, dst, route_all = sys.argv[1], sys.argv[2], sys.argv[3] == "true"
cfg = json.load(open(src, encoding="utf-8"))
port = next(i["port"] for i in cfg.get("inbounds", []) if i.get("protocol") == "socks")
if route_all:
    proxy = next(o.get("tag", "proxy") for o in cfg.get("outbounds", []) if o.get("protocol") == "vless")
    cfg["routing"] = {"domainStrategy": "AsIs",
                      "rules": [{"type": "field", "network": "tcp,udp", "outboundTag": proxy}]}
fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as handle:
    json.dump(cfg, handle)
print(port)
PY
}

vless() {  # vless <client.json> [--probe URL]... [--route-all]
    local src=${1:-} route_all=false probes=()
    [[ -f $src ]] || die "no such config: $src"
    shift
    while (($#)); do
        case $1 in
            --probe) probes+=("${2:?--probe needs a URL}"); shift 2 ;;
            --route-all) route_all=true; shift ;;
            *) die "unknown option: $1" ;;
        esac
    done
    local xray cfg=$RUN_DIR/xray.json log=$RUN_DIR/xray.log port ready=false egress url
    xray=$(command -v xray || echo /usr/local/bin/xray)
    [[ -x $xray ]] || die "xray is missing (vpn-client.sh unpack)"
    down
    trap down EXIT
    mkdir -p "$RUN_DIR"
    chmod 700 "$RUN_DIR"
    port=$(vless_config "$src" "$cfg" "$route_all") || die "not an Xray client config with a SOCKS inbound: $src"
    "$xray" run -c "$cfg" > "$log" 2>&1 &
    echo $! > "$XRAY_PID"
    for _ in $(seq 1 20); do
        if [[ $(ss -Hltn "sport = :$port" 2>/dev/null) == *LISTEN* ]]; then ready=true; break; fi
        kill -0 "$(cat "$XRAY_PID")" 2>/dev/null || break
        sleep 0.5
    done
    if ! $ready; then
        echo "XRAY=failed"
        tail -n 5 "$log" >&2
        return 0
    fi
    echo "XRAY=started"
    egress=none
    for _ in 1 2; do
        egress=$(parse_egress "$(curl -s -m 12 --socks5-hostname "127.0.0.1:$port" "$EGRESS_URL" 2>/dev/null)")
        [[ $egress != none ]] && break
        sleep 2
    done
    echo "EGRESS=$egress"
    if [[ $(probe "http://[2606:4700:4700::1111]/" env ALL_PROXY="socks5h://127.0.0.1:$port") == fail ]]; then
        echo "IPV6=blocked"
    else
        echo "IPV6=unprotected"
    fi
    for url in "${probes[@]}"; do
        echo "PROBE $url $(probe "$url" env ALL_PROXY="socks5h://127.0.0.1:$port")"
    done
    [[ $egress != none ]] || tail -n 5 "$log" >&2
}

egress() {
    echo "EGRESS=$(parse_egress "$(curl -s -m 10 "$EGRESS_URL" 2>/dev/null)")"
}

prepare() {
    local need=()
    command -v wg >/dev/null || need+=(wireguard-tools)
    command -v curl >/dev/null || need+=(curl)
    command -v ping >/dev/null || need+=(iputils-ping)
    command -v python3 >/dev/null || need+=(python3)
    ((${#need[@]})) || return 0
    export DEBIAN_FRONTEND=noninteractive
    { apt-get update -qq && apt-get install -y -qq --no-install-recommends "${need[@]}"; } >/dev/null \
        || die "apt-get install ${need[*]} failed"
}

unpack() {
    tar -C / -xzf - || die "cannot unpack the client binaries"
}

missing() {  # missing <protocols>: one line per tool that a check needs and cannot run
    local protos=",${1:-wg,awg,vless},"
    command -v wg >/dev/null || echo wireguard-tools
    command -v curl >/dev/null || echo curl
    if [[ $protos == *,awg,* ]]; then
        awg --version >/dev/null 2>&1 || echo awg
        amneziawg-go --version >/dev/null 2>&1 || echo amneziawg-go
    fi
    if [[ $protos == *,vless,* ]]; then
        "$(command -v xray || echo /usr/local/bin/xray)" version >/dev/null 2>&1 || echo xray
    fi
    return 0
}

main() {
    local command=${1:-}
    (($#)) && shift
    [[ $EUID -eq 0 || -z $command ]] || die "run as root"
    case $command in
        prepare) prepare ;;
        unpack) unpack ;;
        missing) missing "$@" ;;
        tunnel) tunnel "$@" ;;
        vless) vless "$@" ;;
        egress) egress ;;
        down) down ;;
        *) die "usage: vpn-client.sh prepare|unpack|missing|tunnel|vless|egress|down (see the header)" ;;
    esac
}

# Sourced (tests): define the functions only.
(return 0 2>/dev/null) || main "$@"
