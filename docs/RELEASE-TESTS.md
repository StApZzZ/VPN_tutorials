# CorpVPN v2 release acceptance

This report records the release gates for the cleaned v2 tree. Private inventories, credentials, cloud identifiers and raw logs are retained outside the repository. Runtime acceptance used the executable sources of commit `9e4629a5d6b4610acf0914796654010ee87b227c`; the final release adds this report and the backend configuration example for the AWG mirror path. The source commit and tree are recorded in the release SBOM; checksums cover the source archive, SBOM and this report.

## Automated gates

The same test suite passed on Python 3.10, 3.12 and 3.13: **432 passed tests and 40 subtests** per interpreter. Privileged systemd and Ansible TLS integration tests run separately with deployment dependencies; the ordinary Python-only matrix skips these environment-dependent cases. Python syntax/pyflakes, JavaScript syntax, shell syntax/shellcheck, nine installer environment tests, a real privileged systemd regression for template-service/timer shutdown in both restore and uninstall, TLS assertion checks on the pinned Ansible 2.21 controller, all deployment playbook syntax checks and Ansible production lint passed. A real local Ansible regression verifies equal-length/equal-mtime source upgrades, unchanged deployment, drift repair and preservation of the private environment.

Remote CI also passed its Python matrix, deployment, dependency, secret and native jobs. `pip-audit` found no known vulnerabilities in the hash-locked Python runtime. Native CI compiled the actual pinned AWG and Xray sources, verified 50 embedded Go modules against the release inventory, and passed `govulncheck` for the AWG binary and Xray source/import graph. Xray uses the checked-in security dependency manifests and a checksum-verified Go toolchain. A module-level OpenPGP warning does not apply to the built Xray import graph: no OpenPGP package or module is embedded in that binary. No scanner suppression is used for the native CI gates.

A private comparison against known personal values and credentials, plus a general gitleaks scan, passed for the distributable tree and release artifacts. Reviewed matches are standard runtime paths, synthetic fixtures, deny-network constants and a public Go module checksum. Mandatory MIT copyright remains. Already-public history is retained as requested; private source Git history, state, inventories and backups are excluded.

## Real VM matrix

| Gateway OS / architecture | Installation and repeat | WG / AWG / VLESS | Full / split / blocked | Identity and offboarding | Restore and reboot |
| --- | --- | --- | --- | --- | --- |
| Ubuntu 22.04.5 / x86-64 | PASS | PASS | PASS | PASS | PASS |
| Ubuntu 24.04.4 / x86-64 | PASS | PASS | PASS | PASS | PASS |
| Debian 12.14 / x86-64 | PASS | PASS | PASS | PASS | PASS |
| Debian 13.5 / x86-64 | PASS | PASS | PASS | PASS | PASS |

The stand used four gateways and one Ubuntu 24.04 connector/client VM. Initial installations used fresh OS images. The release candidate gate additionally purged the product with the shipped uninstall playbook and reinstalled it on each OS, retaining the OS package/build caches and acceptance-only identity fixtures. Uninstall stopped and removed owned timers and mirror services, left no VPN interfaces, and removed active state and firewall rules while preserving an unrelated nginx site and Docker rule. The subsequent Xray final-policy and synchronous AWG revocation fixes were deployed through the ordinary upgrade path and checked in the protocol/profile, reboot and isolation matrix on each OS. A sudo deployment through an unprivileged SSH account also passed.

Repeat deployment with active WG/AWG/VLESS credentials preserved gateway keys, peers, administrator token, REALITY keys/short ID and AWG parameters. Actual source file digests were compared to the tested panel sources. Shared TCP 443 routed HTTPS and REALITY correctly; REALITY decoy validation and traffic succeeded.

Network checks used real tunnel clients and a Docker office LAN. All three protocols reached permitted destinations; forced routes failed for destinations excluded by split/blocked profiles. DNS allowances were limited to TCP/UDP 53. Reachable positive-control HTTP services at the metadata address and on a second connected VPN peer confirmed that WG/AWG/VLESS isolation worked; VLESS loopback access was denied. Cold site-link startup required a handshake on both hosts. The pinned Xray version's final private-address safeguard was exercised with real office traffic: explicit profile grants passed it, while excluded networks, DNS port restrictions and hard-denied destinations remained blocked. Revoking a grant removed its final outbound permission. Client IPv6 capture/drop checks and policy/credential persistence after reboot passed.

Identity checks covered Keycloak OIDC administrator/user/denied groups, break-glass access, Samba LDAPS administrator/user/nested groups, invalid/empty passwords, missing users, group removal and restoration with device suspension. With the AWG mirror timer stopped, explicit suspension and revocation removed live and persisted peers before the API returned on every gateway; a subsequent mirror run did not restore the credential. A concurrent mirror regression checks locking before reading its source. Local invitations, password reset, TOTP, one-time recovery codes and scoped metrics/auditor tokens were exercised against the real panel. Unit/regression tests additionally cover CSRF, OIDC state/PKCE/nonce, exact group matching, AD account restrictions, malformed directory responses, concurrent consumption/allocation and pool limits.

SQLite backups passed integrity checks. The shipped restore playbook recovered private configuration, keys, peer state, local password/TOTP and recovery codes; recovery codes remained single-use after restoration. A real LDAPS transport outage preserved both directory user and device states, reported an error and recovered on the next successful sync. Services, firewall policy and credential fingerprints survived reboot. Health timers and sandbox configuration were inspected. HTTPS UI login, management tabs, device issuance and the English/Russian switch passed a real Chromium check on Ubuntu 24.04.

## Scope and reproduction

Supported deployment is one IPv4 gateway, optional Docker-compatible IPv4 site connector and SQLite. ARM64, HA, PostgreSQL, SCIM, RHEL and IPv6 tunnels are not acceptance-tested or supported by this release. Lab HTTPS certificates were explicitly trusted/self-signed, and Keycloak's isolated HTTP fixture used the explicit insecure-HTTP option; production OIDC requires HTTPS by default. LDAPS used a lab CA with certificate validation enabled. ACME issuance with a public domain was not exercised. IPv6 tests establish the generated tunnel/proxy protections; traffic outside a proxy or split tunnel still requires the endpoint policy described in the security model. Xray configuration changes can briefly interrupt VLESS sessions.

The public acceptance kit reproduces install, rerun, traffic, OIDC, LDAP and network-profile scenarios on disposable VMs:

```sh
bash tools/acceptance/run.sh -e /private/acceptance.env install rerun traffic oidc ldap policy
cd deploy/ansible
ansible-playbook -i localhost, -c local --become native-check.yml
```

Use private SSH/inventory files and perform destructive cleanup only on the declared stand. The release source archive is checked byte-for-byte against the committed Git tree, including executable modes. Its SBOM passes the official CycloneDX 1.6 schema, and rebuilding from the same commit produces identical artifacts. After acceptance, all owned test VMs and the stand SSH resource were removed; project API verification confirmed their absence and preservation of unrelated resources.
