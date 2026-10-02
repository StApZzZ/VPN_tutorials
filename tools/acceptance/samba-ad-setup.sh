#!/usr/bin/env bash
# Acceptance kit, runs as root on the CONNECTOR: a lab Active Directory (Samba
# AD DC in Docker) for the LDAP sign-in and offboarding checks.
#
#   samba-ad-setup.sh setup <allowed-source>[,<allowed-source>...]
#   samba-ad-setup.sh user-disable <name>
#   samba-ad-setup.sh user-enable <name>
#
# Domain CORP.EXAMPLE, domain controller dc.corp.example. LDAPS (TCP 636) is
# published on IPv4 and accepted only from the given addresses (the gateway).
# As AD CS would, a lab CA issues the DC certificate with SKI, AKI and a SAN:
# strict verifiers (Python 3.13 and later) reject the certificate Samba makes
# for itself. Users get their username as CN, so bind DNs are predictable
# (CN=svc-corpvpn,CN=Users,DC=corp,DC=example):
#   svc-corpvpn  service account for the panel; in no VPN group -> refused
#   frank        vpn-admins                                     -> admin
#   dave         vpn-users                                      -> user
#   erin         vpn-nested, itself a member of vpn-users       -> user
# Passwords are generated once into /var/lib/corpvpn-acceptance/samba/samba.env
# (mode 600) and never printed; the lab CA certificate is .../samba/ca.pem.
# SAMBA_IMAGE overrides the DC image. Lab only: samba-tool takes passwords on
# its command line. Re-running is safe.
set -euo pipefail

IMAGE=${SAMBA_IMAGE:-nowsci/samba-domain@sha256:953f973514f19f236b0eb838b0e8c98c274b44f70c2bf7f817a0aa931e8f3eb9}
DIR=/var/lib/corpvpn-acceptance/samba
SECRETS=$DIR/samba.env
DC=corpvpn-dc
DC_NAME=dc.corp.example
TLS_DIR=/var/lib/samba/private/tls
RULE=corpvpn-acceptance-ldaps
NEW_SECRETS=false

st() { docker exec "$DC" samba-tool "$@"; }

load_secrets() {
    local var
    if [[ ! -f $SECRETS ]]; then
        (
            umask 077
            for var in DOMAIN_ADMIN_PASSWORD SVC_PASSWORD FRANK_PASSWORD DAVE_PASSWORD ERIN_PASSWORD; do
                echo "$var=Aa1-$(openssl rand -hex 12)"
            done > "$SECRETS"
        )
        NEW_SECRETS=true
    fi
    # shellcheck source=/dev/null
    source "$SECRETS"
}

ensure_docker() {
    if ! command -v docker >/dev/null; then
        apt-get update -qq >/dev/null
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io >/dev/null
    fi
    systemctl enable --now docker >/dev/null 2>&1 || true
}

allow_ldaps() {  # allow_ldaps <ip,ip,...>: TCP 636 to the DC only from these sources
    local rule args sources ip
    for _ in $(seq 1 20); do  # drop this script's rules from earlier runs
        rule=$(iptables -S DOCKER-USER)
        rule=$(grep -m1 -- "--comment $RULE" <<< "$rule") || break
        read -r -a args <<< "${rule/-A /-D }"
        iptables "${args[@]}"
    done
    iptables -I DOCKER-USER -p tcp --dport 636 -m comment --comment "$RULE" -j DROP
    IFS=, read -r -a sources <<< "$1"
    for ip in "${sources[@]}"; do
        [[ -n $ip ]] && iptables -I DOCKER-USER -p tcp --dport 636 -s "$ip" -m comment --comment "$RULE" -j RETURN
    done
}

start_dc() {
    local running all
    running=$(docker ps --format '{{.Names}}')
    all=$(docker ps -a --format '{{.Names}}')
    if grep -qx "$DC" <<< "$running"; then
        return 0
    elif grep -qx "$DC" <<< "$all"; then
        docker start "$DC" >/dev/null
    else
        # The domain password goes through an env file, not the command line.
        docker run -d --name "$DC" --hostname dc --privileged --restart unless-stopped \
            --env-file <(printf 'DOMAIN=CORP.EXAMPLE\nDOMAINPASS=%s\nNOCOMPLEXITY=true\nINSECURELDAP=false\nDNSFORWARDER=1.1.1.1\n' \
                         "$DOMAIN_ADMIN_PASSWORD") \
            -p 0.0.0.0:636:636 "$IMAGE" >/dev/null
    fi
}

wait_dc() {
    for _ in $(seq 1 100); do
        st domain info 127.0.0.1 >/dev/null 2>&1 && return 0
        sleep 3
    done
    echo "the domain controller did not come up within 5 minutes (docker logs $DC)" >&2
    exit 1
}

lab_pki() {  # a lab CA and a DC certificate with SKI, AKI and SAN, as AD CS issues them
    local pki=$DIR/pki
    mkdir -p "$pki"
    if [[ ! -f $pki/dc.pem ]]; then
        openssl req -x509 -newkey rsa:3072 -nodes -keyout "$pki/ca.key" -out "$pki/ca.pem" -days 90 \
            -subj "/CN=CorpVPN Acceptance Lab CA" -addext "basicConstraints=critical,CA:TRUE" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "subjectKeyIdentifier=hash"
        openssl req -newkey rsa:2048 -nodes -keyout "$pki/dc.key" -out "$pki/dc.csr" -subj "/CN=$DC_NAME"
        cat > "$pki/dc.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$DC_NAME
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
        openssl x509 -req -in "$pki/dc.csr" -CA "$pki/ca.pem" -CAkey "$pki/ca.key" -CAcreateserial \
            -out "$pki/dc.pem" -days 90 -extfile "$pki/dc.ext"
    fi
    cp "$pki/ca.pem" "$DIR/ca.pem"
    # Samba keeps its own certificate until the files are replaced.
    if ! docker exec "$DC" cat "$TLS_DIR/cert.pem" 2>/dev/null | cmp -s - "$pki/dc.pem"; then
        docker cp "$pki/ca.pem" "$DC:$TLS_DIR/ca.pem"
        docker cp "$pki/dc.pem" "$DC:$TLS_DIR/cert.pem"
        docker cp "$pki/dc.key" "$DC:$TLS_DIR/key.pem"
        docker exec "$DC" sh -c "chown root:root $TLS_DIR/*.pem && chmod 600 $TLS_DIR/key.pem"
        docker restart "$DC" >/dev/null
        wait_dc
    fi
}

ensure_user() {  # ensure_user <name> <password>: exists with CN = name, enabled
    local name=$1 password=$2
    if ! st user show "$name" >/dev/null 2>&1; then
        st user create "$name" "$password" --use-username-as-cn --given-name="${name^}" --surname=Lab \
            --mail-address="$name@corp.example" >/dev/null
    elif $NEW_SECRETS; then
        st user setpassword "$name" --newpassword="$password" >/dev/null
    fi
    st user enable "$name" >/dev/null
}

ensure_member() {  # ensure_member <group> <member>
    local members
    members=$(st group listmembers "$1" 2>/dev/null || true)
    grep -qx "$2" <<< "$members" || st group addmembers "$1" "$2" >/dev/null
}

setup() {
    local allowed=${1:?allowed source addresses, comma-separated} group
    mkdir -p "$DIR"
    chmod 700 "$DIR"
    load_secrets
    ensure_docker
    allow_ldaps "$allowed"
    start_dc
    wait_dc
    lab_pki
    for group in vpn-users vpn-admins vpn-nested; do
        st group show "$group" >/dev/null 2>&1 || st group add "$group" >/dev/null
    done
    ensure_user svc-corpvpn "$SVC_PASSWORD"
    ensure_user frank "$FRANK_PASSWORD"
    ensure_user dave "$DAVE_PASSWORD"
    ensure_user erin "$ERIN_PASSWORD"
    ensure_member vpn-admins frank
    ensure_member vpn-users dave
    ensure_member vpn-nested erin
    ensure_member vpn-users vpn-nested     # erin is a member only through this nesting
    echo "DC ready: $DC_NAME, lab CA $DIR/ca.pem, passwords in $SECRETS"
    echo "vpn-users: $(st group listmembers vpn-users | tr '\n' ' ')"
}

case ${1:-} in
    setup) shift; setup "$@" ;;
    user-disable) st user disable "${2:?user name}" ;;
    user-enable) st user enable "${2:?user name}" ;;
    *) echo "usage: samba-ad-setup.sh setup <allowed-source>[,...] | user-disable <name> | user-enable <name>" >&2
       exit 2 ;;
esac
