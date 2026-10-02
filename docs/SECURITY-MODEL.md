# Security model

Trust boundaries are the employee browser/client, TLS ingress, the privileged gateway, the optional connector and the identity provider. A gateway administrator can read VPN credentials and control traffic. An employee or operator must not gain that authority through an API, an unqualified group mismatch or a client-supplied address.

HTTPS terminates at nginx. Only loopback reaches the backend panel; forwarded headers are accepted from nginx, which replaces client-supplied forwarding headers. REALITY and HTTPS share 443 by SNI and use loopback backends with PROXY protocol. Host and cloud firewall rules remain the operator's responsibility. Use trusted proxy allow-lists for external TLS termination.

Sessions and API/invitation tokens are random and stored as hashes. Session mutations require CSRF; OIDC uses browser-bound state, nonce and PKCE with signed-token issuer/audience verification. Directory operations use bounded worker concurrency/timeouts, login limits and strict LDAP TLS without referral credential forwarding. Missing claims or failed directory searches preserve access and alert. Explicit disable remains sticky.

Passwords use scrypt; TOTP secrets are encrypted with a protected local key included in backups. TOTP counters and recovery-code consumption use atomic database updates. MFA setup cannot replace an active factor through a stolen session; an administrator-verified reset is required. The emergency admin token is a separate recovery mechanism and must be network-restricted and protected.

WG/AWG kernel policy and Xray policy prevent client isolation bypass, unauthorized corporate ranges and loopback/link-local metadata access. Xray's process output guard provides a second boundary for DNS rebinding and encrypted destination handling. IPv6 tunnels are unsupported; full-tunnel configurations route IPv6 to the gateway to drop it. Split clients retain their own local internet route by design.

The panel is privileged and sandboxed, not isolated from the VPN keys it must manage. A panel process compromise may expose managed keys/state and affect VPN traffic. Administrative hosts and identity-provider configuration are trusted. Host-root compromise, hostile hypervisors, HA failover, automatic SCIM offboarding and PostgreSQL are outside the supported boundary. Keep patched packages, restricted SSH and off-host encrypted backups.

Audit is retained locally and can be exported by a read-only auditor. It is not tamper-proof against root. Use a separate authenticated log collector for stronger retention guarantees. Link tokens and OIDC callback parameters are masked in nginx access logs; key-bearing responses use no-store and strict-origin. UI resources are local and CSP forbids inline script execution.
