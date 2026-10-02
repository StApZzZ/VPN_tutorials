# Employee guide

Open the HTTPS address provided by your administrator. Sign in through corporate SSO, LDAP, or a local account invitation. For local invitations, set a long password, enrol the authenticator when requested and store recovery codes privately. The link works once and expires after 72 hours. Contact your administrator if a link expires or if you lose all factors.

In My devices, add a device and select an offered protocol. Download its configuration or scan its QR code into a compatible WireGuard, AmneziaWG or Xray client. Configuration files contain private credentials: do not forward them or put them in shared storage. Use one device entry for each physical device. Revoke a lost or replaced device immediately.

WireGuard and AmneziaWG use UDP. VLESS/REALITY can connect through TCP 443 when UDP is restricted. A VLESS share link transfers connection settings; use the full client JSON when split routing is required. The supplied Xray JSON uses local SOCKS/HTTP proxy ports; an application must use that proxy or your VPN client must provide a suitable TUN mode.

Your profile determines corporate networks, DNS, full/split routing, device limits and expiry. Full routing sends internet traffic through the gateway; IPv6 is blocked through the tunnel. Split routing preserves local IPv4 internet traffic. WG/AWG configurations capture and block IPv6 in both modes. VLESS JSON blocks IPv6 within the proxy; traffic from applications outside the proxy requires an endpoint firewall or suitable TUN client. Neither a share link nor a changed client config grants access beyond the server policy.

If connection fails, check clock synchronization (for TOTP), the device's status and expiry, then try the other protocol offered by your profile. Give the administrator the device name, time and error message, without sending private keys or recovery codes.
