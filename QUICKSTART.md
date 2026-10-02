# Install CorpVPN

Use a fresh Ubuntu 22.04/24.04 or Debian 12/13 VM and a Linux, macOS or WSL controller with Python 3.10+, Ansible, OpenSSH and tar. Install the pinned controller tools with `pip install -r deploy/requirements.txt`. SSH must work as root or as a user with passwordless sudo. On Windows, use a checkout inside the WSL filesystem and `deploy/quickstart.ps1`.

```sh
cp deploy/quickstart.env.example deploy/quickstart.env
chmod 600 deploy/quickstart.env
# Edit SERVER_A_IP and SSH_KEY, then select TLS and identity settings.
bash deploy/quickstart.sh
```

Configuration is KEY=VALUE data, never shell code. Quote values containing spaces or `#`. The installer saves its generated inventory and settings with mode 600. The administrative token is saved in `deploy/ansible/group_vars/all.secrets.yml`; read it locally and sign in as `admin`. Tokens are never printed in install logs. Keep the controller files private.

For a public panel, set `PANEL_FQDN` and `CERTBOT_EMAIL` with `TLS_MODE=letsencrypt`, or provide `TLS_CERT_FILE` and `TLS_KEY_FILE` with `TLS_MODE=custom`. The name must resolve to the gateway and TCP 80 must reach nginx for ACME renewal. The default self-signed certificate is suitable for a controlled evaluation: trust its certificate explicitly. `TLS_MODE=none` requires a TLS reverse proxy, its `TRUSTED_PROXY_CIDRS` and an HTTPS `PANEL_PUBLIC_URL`.

Open TCP 443 and your selected UDP tunnel ports. For a site connector, also permit UDP 51830 into the gateway. Keep SSH restricted to administrators. Active host firewalls are checked; configure explicit compatible rules before retrying a conflict.

Set `PROTOCOLS=wg,awg,vless`, or select a subset. Defaults: WG 51820, AWG 51821, matching /22 pools, REALITY decoy `www.cloudflare.com`. Changing deployed pools or rotating keys requires a migration because issued configurations depend on them. Re-running with the same inputs preserves peers, keys, administrator token and AWG parameters.

For office networks, set `SERVER_B_IP`, optional `SERVER_B_SSH_KEY`, `CORP_CIDRS` and `CORP_DNS`. The connector dials the gateway; it needs no public inbound VPN port. Corporate ranges must not contain the gateway's own network or overlap tunnel pools. Docker is supported through explicit connector forwarding integration. Create full, split or empty split (blocked) profiles in the panel after installation.

OIDC and LDAP can be enabled independently with `OIDC_ENABLED=true` and `LDAP_ENABLED=true`; `AUTH_MODE` remains a convenience selector. Set exact group policies, using full LDAP DNs or full OIDC group paths where qualification matters. See [Keycloak](docs/IDP-KEYCLOAK.md), [ADFS](docs/IDP-ADFS.md) and [LDAP](docs/IDP-AD-LDAP.md).

Use `deploy/ansible/group_vars/overrides.yml` for persistent advanced settings. `deploy/run.sh` applies it last; quickstart does not overwrite it. Host `.env` edits are overwritten by deployment. Back up before an upgrade or topology change. See [operations](docs/OPERATIONS.md).
