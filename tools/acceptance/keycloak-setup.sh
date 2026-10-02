#!/usr/bin/env bash
# Acceptance kit: a lab Keycloak in Docker on the gateway, realm "corp" with
# the CorpVPN client, groups and test users:
#   alice  vpn-admins  -> admin
#   bob    vpn-users   -> user
#   carol  no group    -> refused
# Lab only (start-dev, plain HTTP on KC_PORT). Run as root on the gateway after
# the quickstart; run.sh does it in its oidc stage:
#
#   PUBLIC_IP=203.0.113.10 PANEL_URL=https://203.0.113.10 bash keycloak-setup.sh
#
# PUBLIC_IP is the address (or DNS name) that browsers and the panel use to
# reach Keycloak. The test passwords and the client secret are generated once
# into /var/lib/corpvpn-acceptance/keycloak.env (mode 600) and never printed.
# Re-running is safe.
set -euo pipefail

PUBLIC_IP=${PUBLIC_IP:?set PUBLIC_IP}
PANEL_URL=${PANEL_URL:?set PANEL_URL}
KC_IMAGE=${KC_IMAGE:-quay.io/keycloak/keycloak@sha256:09a381c715ab0b111835b70f2905955274843a219c6f27efb348e4d9f4086858}
KC_PORT=${KC_PORT:-8081}
STATE_DIR=/var/lib/corpvpn-acceptance
OUT=$STATE_DIR/keycloak.env
NAME=corpvpn-keycloak

rand() { openssl rand -hex 12; }

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
if [[ -f "$OUT" ]]; then
    # shellcheck source=/dev/null
    source "$OUT"
else
    KC_ADMIN_PASSWORD=$(rand)
    CLIENT_SECRET=$(rand)
    ALICE_PASSWORD=$(rand)
    BOB_PASSWORD=$(rand)
    CAROL_PASSWORD=$(rand)
    umask 077
    cat > "$OUT" <<EOF
KC_ADMIN_PASSWORD=$KC_ADMIN_PASSWORD
CLIENT_SECRET=$CLIENT_SECRET
ALICE_PASSWORD=$ALICE_PASSWORD
BOB_PASSWORD=$BOB_PASSWORD
CAROL_PASSWORD=$CAROL_PASSWORD
EOF
fi

command -v docker >/dev/null || { apt-get update -qq && apt-get install -y -qq docker.io >/dev/null; }

if ! docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    # The bootstrap password goes through an env file, not the command line.
    docker run -d --name "$NAME" --restart unless-stopped -p "$KC_PORT:8080" \
        --env-file <(printf 'KC_BOOTSTRAP_ADMIN_USERNAME=admin\nKC_BOOTSTRAP_ADMIN_PASSWORD=%s\n' "$KC_ADMIN_PASSWORD") \
        "$KC_IMAGE" start-dev --hostname="http://$PUBLIC_IP:$KC_PORT" >/dev/null
fi

echo "waiting for Keycloak ..."
ready=false
for _ in $(seq 1 90); do
    if curl -fsS "http://127.0.0.1:$KC_PORT/realms/master" >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 2
done
$ready || { echo "Keycloak did not answer on port $KC_PORT within 3 minutes (docker logs $NAME)" >&2; exit 1; }

kc() { docker exec "$NAME" /opt/keycloak/bin/kcadm.sh "$@"; }
kc config credentials --server http://localhost:8080 --realm master --user admin --password "$KC_ADMIN_PASSWORD" >/dev/null

# Lab only: the default sslRequired=external makes Keycloak demand HTTPS from
# every client outside private ranges - browsers on the internet and the panel
# fetching discovery over the gateway's public address both get "HTTPS
# required". Realms from earlier runs are switched too.
kc get realms/corp >/dev/null 2>&1 || kc create realms -s realm=corp -s enabled=true -s sslRequired=NONE >/dev/null
kc update realms/corp -s sslRequired=NONE

cid=$(kc get clients -r corp -q clientId=corpvpn --fields id --format csv --noquotes)
if [[ -z "$cid" ]]; then
    kc create clients -r corp -s clientId=corpvpn -s enabled=true -s publicClient=false \
        -s standardFlowEnabled=true -s directAccessGrantsEnabled=false -s "secret=$CLIENT_SECRET" >/dev/null
    cid=$(kc get clients -r corp -q clientId=corpvpn --fields id --format csv --noquotes)
    kc create "clients/$cid/protocol-mappers/models" -r corp -s name=groups -s protocol=openid-connect \
        -s protocolMapper=oidc-group-membership-mapper \
        -s 'config."claim.name"=groups' -s 'config."full.path"=false' \
        -s 'config."id.token.claim"=true' -s 'config."access.token.claim"=true' -s 'config."userinfo.token.claim"=true' >/dev/null
fi
# The panel's address may differ from an earlier run: keep the URIs current.
kc update "clients/$cid" -r corp -s "redirectUris=[\"$PANEL_URL/auth/oidc/callback\"]" \
    -s "attributes.\"post.logout.redirect.uris\"=$PANEL_URL/*"

for group in vpn-admins vpn-users; do
    [[ -n "$(kc get groups -r corp -q search="$group" --fields id --format csv --noquotes)" ]] \
        || kc create groups -r corp -s "name=$group" >/dev/null
done

add_user() {  # add_user <name> <password> [group]
    local name=$1 password=$2 group=${3:-} uid gid
    uid=$(kc get users -r corp -q username="$name" -q exact=true --fields id --format csv --noquotes)
    if [[ -z "$uid" ]]; then
        kc create users -r corp -s "username=$name" -s enabled=true -s "email=$name@corp.example" \
            -s emailVerified=true -s "firstName=${name^}" -s lastName=Lab >/dev/null
        uid=$(kc get users -r corp -q username="$name" -q exact=true --fields id --format csv --noquotes)
    fi
    kc set-password -r corp --username "$name" --new-password "$password" >/dev/null
    if [[ -n "$group" ]]; then
        gid=$(kc get groups -r corp -q search="$group" --fields id --format csv --noquotes)
        kc update "users/$uid/groups/$gid" -r corp -s realm=corp -s "userId=$uid" -s "groupId=$gid" -n >/dev/null
    fi
}
add_user alice "$ALICE_PASSWORD" vpn-admins
add_user bob "$BOB_PASSWORD" vpn-users
add_user carol "$CAROL_PASSWORD"          # in no VPN group: must be refused

cat <<EOF

Keycloak is up: http://$PUBLIC_IP:$KC_PORT (admin password in $OUT)
Add to quickstart.env and re-run the quickstart:

AUTH_MODE=oidc
OIDC_DISCOVERY_URL=http://$PUBLIC_IP:$KC_PORT/realms/corp/.well-known/openid-configuration
OIDC_CLIENT_ID=corpvpn
OIDC_CLIENT_SECRET=<CLIENT_SECRET from $OUT>
AUTH_ADMIN_GROUPS=vpn-admins
AUTH_USER_GROUPS=vpn-users
EOF
