# Changelog

## v2

Corporate gateway and employee portal with OIDC, LDAP/AD and invited local accounts; role-scoped APIs, TOTP and recovery codes; full/split/blocked access profiles with boot-time policy; larger IPv4 pools; shared HTTPS/REALITY TCP 443; pinned installations; consistent backups and guarded restoration; service sandboxing; audit export and monitoring; local English/Russian UI.

Installer upgrades verify deployed content even when file sizes and timestamps match. Tunnel policy covers both local-input and forwarded traffic; DNS allowances are restricted to DNS ports. Site links wait for a handshake on both hosts after configuration changes. Xray is compiled with locked security dependency updates and audited alongside AmneziaWG.

This release supports one IPv4 gateway, optional connector and SQLite. See the support matrix and test report for verified operating systems.

## init

The previously published baseline is retained under the `init` tag. Its history remains available for provenance; v2 distributes only the cleaned corporate tree.
