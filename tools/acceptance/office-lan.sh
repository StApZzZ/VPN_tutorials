#!/usr/bin/env bash
# Acceptance kit, runs as root on the CONNECTOR: a simulated office LAN. The
# network namespace "cvoffice" holds one office host that answers HTTP; the
# connector reaches it over a veth pair, so split mode can route corporate
# traffic to it through the site link.
#
#   office-lan.sh up <connector-address/prefix> <office-host-address> [port]
#   office-lan.sh down
#
#   office-lan.sh up 172.30.0.1/24 172.30.0.2      -> http://172.30.0.2:8080/
#
# Re-running "up" is safe. The HTTP server is the transient systemd unit
# corpvpn-office-http, so it outlives the SSH session.
set -euo pipefail

NS=cvoffice
HOST_IF=cvoffice0
NS_IF=cvoffice1
UNIT=corpvpn-office-http
WEB_DIR=/var/lib/corpvpn-acceptance/office

up() {
    local connector=${1:?connector address/prefix} host=${2:?office host address} port=${3:-8080}
    local prefix=${connector#*/}
    [[ $connector == */* ]] || { echo "the connector address needs a prefix, e.g. 172.30.0.1/24" >&2; exit 2; }
    if ! command -v curl >/dev/null || ! command -v python3 >/dev/null; then
        apt-get update -qq >/dev/null
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends curl python3 >/dev/null
    fi
    local namespaces
    namespaces=$(ip netns list)
    grep -qw "$NS" <<< "$namespaces" || ip netns add "$NS"
    if ! ip link show "$HOST_IF" >/dev/null 2>&1; then
        ip link add "$HOST_IF" type veth peer name "$NS_IF"
        ip link set "$NS_IF" netns "$NS"
    fi
    ip addr flush dev "$HOST_IF"
    ip addr add "$connector" dev "$HOST_IF"
    ip link set "$HOST_IF" up
    ip -n "$NS" link set lo up
    ip -n "$NS" addr flush dev "$NS_IF"
    ip -n "$NS" addr add "$host/$prefix" dev "$NS_IF"
    ip -n "$NS" link set "$NS_IF" up
    ip -n "$NS" route replace default via "${connector%/*}"

    mkdir -p "$WEB_DIR"
    echo "CorpVPN acceptance: office host" > "$WEB_DIR/index.html"
    if ! systemctl is-active --quiet "$UNIT"; then
        systemctl reset-failed "$UNIT" >/dev/null 2>&1 || true
        systemd-run --quiet --unit "$UNIT" \
            ip netns exec "$NS" python3 -m http.server "$port" --bind "$host" --directory "$WEB_DIR"
    fi
    for _ in $(seq 1 20); do
        if curl -fsS -o /dev/null -m 2 "http://$host:$port/"; then
            echo "OFFICE=http://$host:$port/"
            return 0
        fi
        sleep 0.5
    done
    echo "the office host does not answer on http://$host:$port/ (journalctl -u $UNIT)" >&2
    exit 1
}

down() {
    systemctl stop "$UNIT" >/dev/null 2>&1 || true
    ip link del "$HOST_IF" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
}

case ${1:-} in
    up) shift; up "$@" ;;
    down) down ;;
    *) echo "usage: office-lan.sh up <connector-address/prefix> <office-host-address> [port] | down" >&2; exit 2 ;;
esac
