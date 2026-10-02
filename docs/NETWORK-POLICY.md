# Network policy

Profiles are enforced on the server as well as expressed in issued configs. `NETWORK_POLICY_MODE=enforce` is the installer default. WG/AWG traffic uses per-device nftables policy; Xray evaluates per-client profile rules before domain-routing overrides. The policy persisted to `/etc/nftables.d/50-corpvpn-policy.nft` loads before tunnels at boot. A periodic refresh repairs missing tables and reports failed applies.

Full profiles can reach public internet; corporate ranges require explicit allowance. Split profiles can reach allowed IPv4 CIDRs and selected DNS resolvers on TCP/UDP 53 only. Empty split profiles allow only those DNS queries. The client isolation baseline prevents WG/AWG devices from reaching other devices, gateway services and link-local metadata. Xray also has a UID-based egress guard against loopback and link-local addresses. Disabling a user or device removes usable credentials/policy; editing a client config cannot expand server permissions.

Configure every corporate range through `CORP_CIDRS`, including networks the gateway can reach directly. Extra protected infrastructure can be added with `vpn_panel_forward_deny_cidrs`. `vpn_panel_client_to_client` defaults to false; enable it only with an explicit network design.

The installer changes only CorpVPN tables. Existing host/cloud firewalls may impose additional restrictions; they are detected rather than flushed. The optional connector only forwards corporate ranges and installs explicit Docker-compatible forwarding when Docker is present.

WG/AWG client configs include `::/0` so IPv6 does not bypass the gateway; IPv6 is dropped because IPv6 tunnels are outside this release. Split profiles intentionally preserve local internet routing and are not an all-traffic privacy service. Check the release report for traffic and IPv6 acceptance evidence.
