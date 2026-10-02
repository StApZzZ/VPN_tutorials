# Keycloak OIDC

Create a confidential OIDC client with the panel's exact HTTPS callback URL `/auth/oidc/callback`, authorization code flow and PKCE S256. Configure a groups claim mapper; include full group paths when organizational qualification matters. Give VPN users a dedicated group and map it through the panel's Group policies screen.

Set `OIDC_ENABLED=true`, `OIDC_DISCOVERY_URL`, `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET`. `PANEL_PUBLIC_URL` or `OIDC_REDIRECT_URL` determines the callback. Register the post-logout redirect when enabling IdP logout. Do not enable insecure transport for production. Only the disposable acceptance realm permits HTTP inside its test environment.

The panel verifies issuer, audience, signature, expiry, nonce and browser-bound one-use state. A missing configured groups claim is an authentication error and does not offboard an existing account. Provider tests check discovery and key availability; they do not substitute for a real browser sign-in.

MFA must be enforced by the IdP as well as represented in signed claims. Configure `AUTH_MFA_REQUIRED_ROLES`, `OIDC_REQUIRED_ACR` and/or `OIDC_REQUIRED_AMR` to match your provider's actual assurance claims. Test a negative MFA case before granting administrator access. A session already created before a policy change should be revoked.

OIDC-only offboarding is administrative disable or time-limited attestation. For prompt automated directory offboarding, configure LDAP reconciliation alongside OIDC. See the administrator and security guides.
