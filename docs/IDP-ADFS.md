# ADFS and other OIDC providers

Use an OIDC provider with signed ID tokens, discovery/JWKS and authorization code plus PKCE support. Register the exact panel callback `/auth/oidc/callback`; set OIDC discovery, client ID/secret and public HTTPS origin through the installer or persistent overrides.

Configure username and group claim names (`OIDC_USERNAME_CLAIMS`, `OIDC_GROUPS_CLAIMS`) to match signed claims. Prefer stable subject identifiers and qualified group values. Entra group-overage tokens require an appropriate mapper/provider integration; the panel does not query Microsoft Graph to recover an omitted groups claim. Missing groups are refused and logged without disabling existing devices.

Assurance claim mapping varies by provider. Set required ACR/AMR to values actually returned for an MFA-authenticated user, then test denial without that assurance. No claim mapping can enforce a challenge that the provider does not perform.

Only the protocol implementation and acceptance-tested provider are verified by this release. ADFS/Entra-specific tenant configuration must be validated in your environment; it is not claimed as live tenant-tested. See the support matrix and security model.
