# CorpVPN

CorpVPN provides a corporate IPv4 VPN gateway with WireGuard, AmneziaWG and VLESS/REALITY, an employee portal, access profiles and administrative audit. One gateway, an optional outbound site connector and SQLite form the supported deployment.

Employees sign in with OIDC, LDAP/Active Directory or individually invited local accounts. Administrators define roles and network profiles; operators issue and suspend devices without receiving employees' private credentials. Directory failures preserve existing access and produce an alert; confirmed offboarding suspends devices. Local administrators require TOTP by default.

Start with [QUICKSTART.md](QUICKSTART.md). Read the [architecture](docs/ARCHITECTURE.md), [administrator guide](docs/ADMIN.md), [operations guide](docs/OPERATIONS.md), [employee guide](docs/USER.md) and [security model](docs/SECURITY-MODEL.md) before exposing a gateway.

The panel and Xray listen on loopback. nginx shares TCP 443 using TLS SNI: the REALITY decoy name goes to Xray on 127.0.0.1:8443; other names go to the panel's TLS listener on 127.0.0.1:8444. The default client pools are 10.66.0.0/22 and 10.66.4.0/22, with UDP ports 51820 and 51821. Network policy is enforced at boot and after changes. VPN clients cannot reach loopback, link-local metadata or one another by default.

The interface defaults to English and offers Russian. All UI assets are served locally under a restrictive Content Security Policy. Component versions and checksums are in `deploy/versions.yml`; Python installations use `panel/requirements.lock` with hashes.

Target operating systems are Ubuntu 22.04/24.04 and Debian 12/13. See the [support matrix](docs/SUPPORT.md) and release test report for verified configurations. HA, PostgreSQL, SCIM, RHEL and IPv6 tunnels are outside v2. WG/AWG configurations capture IPv6 and drop it at the IPv4 gateway; split tunnels preserve IPv4 local internet access. VLESS client JSON blocks IPv6 within the proxy. Applications outside the proxy require a client firewall or TUN client to prevent bypass.

For development, create a virtualenv, install `requirements.txt`, copy `panel/.env.example` to a private env file and set a writable `CORPVPN_STATE_DIR`. Run `PYTHONPATH=panel pytest` and `PYTHONPATH=panel python -m uvicorn main:app --host 127.0.0.1`. Real kernel operations need a disposable Linux VM; the test suite substitutes VPN backends.

This software is MIT licensed. Keep [LICENSE](LICENSE) and [NOTICE](NOTICE) when redistributing it.
