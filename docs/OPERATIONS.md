# Operations, upgrades and disaster recovery

Keep the original installer configuration, override file and protected secrets. Use the same inputs for upgrades. Run a backup, deploy the new release, confirm `/health` and administrator `/api/health`, then test each enabled protocol. Schema migrations are additive; restoration of the complete previous backup is the rollback path. Changing keys, REALITY decoy or network pools is a planned client migration, not a routine upgrade.

`corpvpn-backup.timer` runs daily. `/usr/local/sbin/corpvpn-backup` uses SQLite's online backup API under the shared backend lock. It archives identity/backend databases, local TOTP encryption key, WG/AWG keys and parameters, Xray, `.env`, TLS material and persisted policy. Each archive has an internal manifest with checksums and public keys. Archives and controller settings contain secrets and must remain private. Retention and encrypted/off-host copies are configured through `vpn_panel_backup_*` overrides. Configure age recipients before copying archives off the gateway. A backup stored only on the gateway cannot survive loss of that VM.

For recovery, decrypt an age archive into a protected controller directory, then validate it before changes:

```sh
python3 deploy/ansible/roles/backup/files/corpvpn-restore --archive backup.tar.gz
bash deploy/run.sh --host 203.0.113.10 --ssh-key ~/.ssh/id_ed25519 \
  --playbook restore.yml -- -e corpvpn_restore_archive=/private/backup.tar.gz
bash deploy/run.sh --host 203.0.113.10 --ssh-key ~/.ssh/id_ed25519
```

The restore playbook validates hashes and paths, stops writers/tunnels, restores content and leaves them stopped until deployment verifies and starts them. Restore on a fresh VM before its first normal deployment so keys are reused. On an existing gateway, schedule downtime. The same public endpoint and network inputs keep client configs usable; update DNS after a replacement VM. Compare manifest public keys, issue a test connection, reboot and test again. The validator rejects traversal, special files, escaping links and incomplete manifests. Custom backup locations require an operator-reviewed adaptation of restore paths.

Health and backup timers write status and node-exporter textfile metrics. `/metrics` uses a named metrics token; detailed per-peer series are off by default. The [monitoring example](../deploy/monitoring/README.md) covers policy freshness, directory sync, backups and gateway health. Monitor journal errors as well as HTTP status. A directory outage must generate an alert, not mass user removal.

Service units restrict capabilities, filesystem writes, devices, kernel interfaces and namespace creation. The panel still runs with the privilege needed for WG/nft and Xray lifecycle; protect the host as a privileged gateway. Only the documented configuration/state paths are writable by the panel sandbox.

For removal, use `uninstall.yml` with the correct private inventory. It stops only CorpVPN services, removes its nginx configuration and its own firewall tables, and preserves keys/state by default. `corpvpn_uninstall_purge=true` explicitly removes CorpVPN state and keys. Previously created local backups are retained separately; remove them only after confirming the required recovery copies. Review the inventory before invoking a purge.

Xray configuration changes restart the service and briefly disconnect existing VLESS sessions. Directory-sync and bulk offboarding batch their changes into one apply; an unchanged apply skips the restart. Schedule routing/profile changes when that interruption is acceptable. This release does not provide zero-downtime Xray updates or HA.

Xray is built from the source commit pinned in `deploy/versions.yml`, using a separate checksum-verified Go toolchain and the checked-in `xray-go.mod` / `xray-go.sum` security dependency manifests. The upstream release archive supplies only GeoIP/GeoSite data. The installed binary hash and build inputs are recorded in its build stamp; repeated deployment reuses a matching binary, and drift triggers a rebuild. First installation requires outbound access to the pinned GitHub sources, Go downloads, module proxy and checksum database. Source compilation needs additional time and disk space. The native CI job compiles the same sources, checks the embedded module inventory and runs `govulncheck` against Xray source and the AmneziaWG binary.

The panel owns the `direct` Freedom outbound's `finalRules`: it regenerates explicit grants for concrete profile/direct-IP destinations and DNS port 53 so newer Xray private-address safeguards permit authorized office access. Per-user routing remains the authorization check; metadata, loopback, site-link control addresses and IPv6 remain blocked before any grant. Removed grants disappear on the next apply.

Suspension and revocation remove a separate AWG peer from both live state and its persisted configuration before returning. The peer mirror and removal share a lock, so a timer using older input cannot restore the credential. New/resumed peers are mirrored by the timer; wait for convergence before comparing peer fingerprints.
