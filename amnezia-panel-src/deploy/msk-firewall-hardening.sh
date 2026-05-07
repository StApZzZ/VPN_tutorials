#!/usr/bin/env bash
set -euo pipefail

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/vpn-panel/firewall-msk-${STAMP}}"
ROLLBACK_DELAY="${ROLLBACK_DELAY:-180s}"
ROLLBACK_UNIT="${ROLLBACK_UNIT:-vpn-firewall-rollback-${STAMP}}"
ROLLBACK_SCRIPT="/root/${ROLLBACK_UNIT}.sh"

mkdir -p "$BACKUP_DIR"

iptables-save > "$BACKUP_DIR/iptables-save.v4"
ip6tables-save > "$BACKUP_DIR/iptables-save.v6"
nft list ruleset > "$BACKUP_DIR/nft-ruleset.txt"
firewall-offline-cmd --list-all-zones > "$BACKUP_DIR/firewalld-offline-zones.txt" 2>&1 || true
firewall-cmd --list-all-zones > "$BACKUP_DIR/firewalld-runtime-zones.txt" 2>&1 || true
ip -br addr > "$BACKUP_DIR/ip-addr.txt"
ip route > "$BACKUP_DIR/ip-route.txt"
ss -tulpn > "$BACKUP_DIR/ss-tulpn.txt"

cat > "$ROLLBACK_SCRIPT" <<EOF
#!/usr/bin/env bash
set -euo pipefail
systemctl stop firewalld || true
iptables-restore < "$BACKUP_DIR/iptables-save.v4" || true
ip6tables-restore < "$BACKUP_DIR/iptables-save.v6" || true
echo "Rolled back firewall from $BACKUP_DIR"
EOF
chmod 700 "$ROLLBACK_SCRIPT"

systemctl reset-failed "${ROLLBACK_UNIT}.service" "${ROLLBACK_UNIT}.timer" >/dev/null 2>&1 || true
systemd-run --unit "$ROLLBACK_UNIT" --on-active="$ROLLBACK_DELAY" "$ROLLBACK_SCRIPT" >/dev/null

systemctl stop firewalld || true

firewall-offline-cmd --set-default-zone=public || true
firewall-offline-cmd --zone=public --remove-service=dhcpv6-client || true
firewall-offline-cmd --zone=public --add-service=ssh || true
firewall-offline-cmd --zone=public --add-port=80/tcp || true
firewall-offline-cmd --zone=public --add-port=443/tcp || true
firewall-offline-cmd --zone=public --add-port=34011/udp || true
firewall-offline-cmd --zone=public --add-port=51821/udp || true
firewall-offline-cmd --zone=public --add-masquerade || true
firewall-offline-cmd --zone=public --add-interface=ens192 || true
firewall-offline-cmd --zone=trusted --add-interface=wg0 || true
firewall-offline-cmd --zone=trusted --add-interface=wg-nl || true

systemctl enable --now firewalld
firewall-cmd --permanent --zone=public --remove-service=dhcpv6-client || true
firewall-cmd --reload

# Docker is no longer installed, but nftables still has old Docker chains/rules.
# Delete only known Docker artifacts and leave WireGuard/Xray rules alone.
iptables -t nat -D POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE 2>/dev/null || true

ip6tables -D FORWARD -j DOCKER-USER 2>/dev/null || true
ip6tables -D FORWARD -j DOCKER-FORWARD 2>/dev/null || true
for chain in DOCKER-FORWARD DOCKER-CT DOCKER-INTERNAL DOCKER-BRIDGE DOCKER DOCKER-USER; do
  ip6tables -F "$chain" 2>/dev/null || true
done
for chain in DOCKER-FORWARD DOCKER-CT DOCKER-INTERNAL DOCKER-BRIDGE DOCKER DOCKER-USER; do
  ip6tables -X "$chain" 2>/dev/null || true
done

ip6tables -t nat -D PREROUTING -m addrtype --dst-type LOCAL -j DOCKER 2>/dev/null || true
ip6tables -t nat -D OUTPUT ! -d ::1/128 -m addrtype --dst-type LOCAL -j DOCKER 2>/dev/null || true
ip6tables -t nat -F DOCKER 2>/dev/null || true
ip6tables -t nat -X DOCKER 2>/dev/null || true

echo "backup_dir=$BACKUP_DIR"
echo "rollback_script=$ROLLBACK_SCRIPT"
echo "rollback_timer=${ROLLBACK_UNIT}.timer"
echo "rollback_delay=$ROLLBACK_DELAY"
echo "firewalld_state=$(firewall-cmd --state)"
firewall-cmd --get-active-zones
firewall-cmd --zone=public --list-all
