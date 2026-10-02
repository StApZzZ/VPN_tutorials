# CorpVPN acceptance kit

Use disposable VMs. The kit deploys the gateway and optionally a site connector, creates test identities/devices, changes the default profile, and installs pinned Keycloak/Samba containers for the identity-provider checks. It restores the original default profile and revokes test VPN devices on exit. It does not delete provider resources.

Copy `acceptance.env.example` to a private file, fill in gateway/connector addresses and the SSH key, then run:

```sh
bash tools/acceptance/run.sh -e /private/acceptance.env
bash tools/acceptance/run.sh --list
bash tools/acceptance/run.sh -e /private/acceptance.env traffic ldap policy
```

Install the controller dependencies from `deploy/requirements.txt`. SSH must work as root or with passwordless sudo. Settings are a trusted shell file for this operator-run test harness; the product installer's `quickstart.env` is parsed as data. Outputs, lab passwords and client credentials stay under the protected `WORK_DIR`; never publish that directory.

| Stage | Evidence |
|---|---|
| install | Product installer, panel health, admin form/API login and services |
| rerun | Stable fingerprints of keys, peers, REALITY, token and AWG parameters |
| traffic | Real WG, AWG and VLESS clients use the gateway's IPv4 egress |
| oidc | Keycloak admin/user groups and refusal without a VPN group |
| ldap | LDAPS, nested AD group, incorrect credentials and disable/re-enable with peer removal |
| policy | Connector with Docker, full/split/blocked profiles and forced-routing bypass attempts |

The lab OIDC provider uses HTTP with an explicit `OIDC_ALLOW_INSECURE_HTTP=true` override. Production discovery and endpoints require HTTPS by default. Samba uses a lab CA distributed privately by the harness. Run stages that use the same connector/client sequentially across gateways.

`local_e2e.py` checks local invitations, one-time consumption, TOTP replay, recovery codes, password reset, CSRF and scoped metrics/auditor tokens against a real panel. Supply the admin token through `ADMIN_TOKEN`, not argv:

```sh
python3 tools/acceptance/local_e2e.py --panel https://vpn.example.com
```

Add `--insecure` only for a disposable self-signed lab. The script disables its test accounts and revokes API tokens on exit. Browser UI, reboot and backup/restore checks are separate release gates documented in `docs/RELEASE-TESTS.md`.
