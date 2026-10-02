#!/usr/bin/env bash
# Acceptance kit, runs as root on the GATEWAY: read-only probes of what the
# installer and the panel built, plus a little lab plumbing.
#
#   gateway.sh snapshot                  fingerprints of everything a re-run must keep:
#                                        keys, peers, AmneziaWG parameters, REALITY key,
#                                        VLESS clients, break-glass token (short hashes only)
#   gateway.sh services <protocols>      units, the policy table, Xray restarts
#   gateway.sh peer <interface> <public-key>
#   gateway.sh site-link                 seconds since the last site-link handshake
#   gateway.sh route-src <ip>            the source address the gateway uses towards <ip>
#   gateway.sh hosts-entry <ip> <name>   one tagged /etc/hosts line (lab DNS)
#   gateway.sh pack-client-tools <protocols>
#                                        tar.gz of amneziawg-go, awg and Xray for the
#                                        client VM (stdout)
set -uo pipefail

HOSTS_FILE=${HOSTS_FILE:-/etc/hosts}
HOSTS_TAG="# corpvpn-acceptance"
PANEL_ENV=/opt/vpn-panel/.env
XRAY_CONFIG=${XRAY_CONFIG:-/etc/xray/config.json}

item() {  # item <name> <text>: "<name> <short hash>", or "<name> absent"
    if [[ -n $2 ]]; then
        printf '%s %s\n' "$1" "$(printf '%s' "$2" | sha256sum | cut -c1-16)"
    else
        printf '%s absent\n' "$1"
    fi
}

xray_field() {  # xray_field private-key|clients: from the VLESS inbound of the Xray config
    python3 - "$1" "$XRAY_CONFIG" <<'PY'
import json, sys

try:
    cfg = json.load(open(sys.argv[2], encoding="utf-8"))
except (OSError, ValueError):
    sys.exit(0)
for inbound in cfg.get("inbounds", []):
    if inbound.get("protocol") != "vless":
        continue
    if sys.argv[1] == "private-key":
        print(((inbound.get("streamSettings") or {}).get("realitySettings") or {}).get("privateKey", ""))
    else:
        print("\n".join(sorted(c.get("id", "") for c in (inbound.get("settings") or {}).get("clients", []))))
PY
}

snapshot() {
    local f
    item wg0.public-key "$(wg show wg0 public-key 2>/dev/null)"
    item wg0.peers "$(wg show wg0 peers 2>/dev/null | sort)"
    if ip link show awg0 >/dev/null 2>&1; then
        item awg0.public-key "$(awg show awg0 public-key 2>/dev/null)"
        item awg0.peers "$(awg show awg0 peers 2>/dev/null | sort)"
        item awg0.obfuscation "$(awg show awg0 2>/dev/null | grep -E '^[[:space:]]*(jc|jmin|jmax|s[1-4]|h[1-4]|i[1-5]):')"
    fi
    for f in /etc/wireguard/wg0_private.key /etc/wireguard/clientsPrivateKeys.json \
             /etc/wireguard/wg-site.key /etc/wireguard/wg-site.psk \
             /etc/amnezia/amneziawg/awg0_priv /etc/amnezia/amneziawg/obfuscation.json; do
        [[ -f $f ]] && item "file:${f##*/}" "$(cat "$f")"
    done
    if [[ -f $XRAY_CONFIG ]]; then
        item reality.private-key "$(xray_field private-key)"
        item xray.clients "$(xray_field clients)"
    fi
    item panel.token "$(grep -E '^PANEL_SECRET_TOKEN=' "$PANEL_ENV" 2>/dev/null)"
}

services() {  # services <protocols>
    local protos=",${1:-wg,awg,vless}," unit units=(nginx vpn-panel wg-quick@wg0)
    [[ $protos == *,awg,* ]] && units+=(awg-quick@awg0)
    [[ $protos == *,vless,* ]] && units+=(xray)
    for unit in "${units[@]}"; do
        echo "UNIT $unit $(systemctl is-active "$unit" 2>/dev/null)"
    done
    if nft list table inet corpvpn_policy >/dev/null 2>&1; then
        echo "NFT corpvpn_policy present"
    else
        echo "NFT corpvpn_policy missing"
    fi
    [[ $protos == *,vless,* ]] && echo "RESTARTS xray $(systemctl show -p NRestarts --value xray 2>/dev/null)"
    return 0
}

peer() {  # peer <interface> <public-key>: PEER=yes|no|no-interface
    local iface=${1:?interface} key=${2:?public key} peers
    ip link show "$iface" >/dev/null 2>&1 || { echo "PEER=no-interface"; return 0; }
    # wg0 is kernel WireGuard; awg0 is userspace AmneziaWG, which only awg reads.
    peers=$(wg show "$iface" peers 2>/dev/null) || peers=$(awg show "$iface" peers 2>/dev/null)
    if grep -qxF -- "$key" <<< "$peers"; then echo "PEER=yes"; else echo "PEER=no"; fi
}

site_link() {
    local ts
    ip link show wg-site >/dev/null 2>&1 || { echo "SITE_LINK=absent"; return 0; }
    ts=$(wg show wg-site latest-handshakes 2>/dev/null | awk '{print $2; exit}')
    if [[ ${ts:-0} =~ ^[1-9][0-9]*$ ]]; then
        echo "SITE_LINK=$(( $(date +%s) - ts ))"
    else
        echo "SITE_LINK=never"
    fi
}

route_src() {  # route_src <ip>: SRC=<address>, before any NAT on the way
    local route
    route=$(ip -4 route get "${1:?address}" 2>/dev/null)
    [[ $route =~ \ src\ ([0-9.]+) ]] && echo "SRC=${BASH_REMATCH[1]}"
    return 0
}

hosts_entry() {  # hosts_entry <ip> <name>: replaces the kit's earlier line for <name>
    local ip=${1:?address} name=${2:?name} tmp
    [[ $ip =~ ^[0-9.]+$ && $name =~ ^[A-Za-z0-9.-]+$ ]] || { echo "bad address or name" >&2; return 2; }
    tmp=$(mktemp)
    grep -vF -- " $name $HOSTS_TAG" "$HOSTS_FILE" > "$tmp"
    printf '%s %s %s\n' "$ip" "$name" "$HOSTS_TAG" >> "$tmp"
    cat "$tmp" > "$HOSTS_FILE"
    rm -f "$tmp"
}

pack_client_tools() {  # pack_client_tools <protocols>: tar.gz on stdout
    local protos=",${1:-awg,vless}," files=() path dir
    if [[ $protos == *,awg,* ]]; then
        for path in "$(command -v amneziawg-go)" "$(command -v awg)"; do
            [[ -n $path ]] && files+=("${path#/}")
        done
    fi
    if [[ $protos == *,vless,* ]]; then
        path=$(command -v xray || echo /usr/local/bin/xray)
        [[ -x $path ]] && files+=("${path#/}")
        # geoip.dat / geosite.dat: the client JSON routes by them
        for dir in /usr/local/share/xray /usr/share/xray; do
            [[ -d $dir ]] && files+=("${dir#/}")
        done
    fi
    ((${#files[@]})) || { echo "no client binaries on the gateway" >&2; return 1; }
    tar -C / -czhf - "${files[@]}"
}

main() {
    local command=${1:-}
    (($#)) && shift
    case $command in
        snapshot) snapshot ;;
        services) services "$@" ;;
        peer) peer "$@" ;;
        site-link) site_link ;;
        route-src) route_src "$@" ;;
        hosts-entry) hosts_entry "$@" ;;
        pack-client-tools) pack_client_tools "$@" ;;
        *) echo "usage: gateway.sh snapshot|services|peer|site-link|route-src|hosts-entry|pack-client-tools" >&2
           return 2 ;;
    esac
}

# Sourced (tests): define the functions only.
(return 0 2>/dev/null) || main "$@"
