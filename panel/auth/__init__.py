"""Corporate identity for the CorpVPN (v2 Phase 3).

Providers: break-glass local admin (`local`), OpenID Connect (`oidc`) and
LDAP / Active Directory (`ldap`). Every successful sign-in goes through
`identity.admit()`, which maps directory groups to a role via group policies,
upserts the user and returns it; `sessions` then issues a server-side session.
"""
