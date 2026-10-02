# Supported configuration

The v2 target is one IPv4 gateway with SQLite and an optional IPv4 WireGuard office connector. Supported targets are Ubuntu 22.04/24.04 and Debian 12/13 on x86-64, contingent on the release acceptance report. ARM64 component checksums are supplied, but ARM64 is not claimed as acceptance-tested.

Real tests cover fresh installation, repeat deployment, WG/AWG/VLESS traffic, full/split/blocked profiles, directory and local authentication, disable/offboarding, reboot and backup restore. The release report records actual results and limitations. Self-signed TLS is used only with explicit client trust in the lab; production should use operator certificates or ACME.

Ansible needs SSH and sudo/root, apt mirrors, Python package access, Go module sources and pinned component archives. HTTP_PROXY, HTTPS_PROXY and NO_PROXY can configure downloads. A fully offline mirror/install path is not supplied. Allow deployment time for the first AWG source build.

HA, clustering, PostgreSQL, SCIM, RHEL and IPv6 tunnels are excluded. VPN policy does not replace a company's endpoint firewall or protect local internet connections outside a split tunnel. The connector can coexist with Docker when the installer integrates its forwarding rules; external firewall policy conflicts must be resolved explicitly.
