"""Turn an authenticated identity from any provider into a panel user."""
from __future__ import annotations

import hmac
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import config
from auth import policy, store

# Longest accepted sign-in input: longer is refused before the limiter, a
# directory or the audit log sees it (the body of one POST may be 1 MB).
USERNAME_MAX = 256
PASSWORD_MAX = 1024

# Why a user is disabled (users.disabled_reason). Codes, not prose: the UI
# translates them.
REASON_ADMIN = "admin"
REASON_DIRECTORY_DISABLED = "directory_disabled"
REASON_DIRECTORY_MISSING = "directory_missing"
REASON_NO_VPN_GROUP = "no_vpn_group"
REASON_ATTESTATION = "attestation_expired"


def secure_equals(given: str, expected: str) -> bool:
    """Constant-time string comparison for secrets and user input in any script.

    secrets.compare_digest() on str raises TypeError for non-ASCII text, which
    turned a Cyrillic username or a garbage header into an HTTP 500.
    """
    return hmac.compare_digest((given or "").encode("utf-8"), (expected or "").encode("utf-8"))


@dataclass
class Identity:
    provider: str
    external_id: str
    username: str
    email: str = ""
    display_name: str = ""
    groups: list[str] = field(default_factory=list)
    disabled: bool = False
    directory_dn: str = ""
    # False when the IdP sent no group information at all (no configured claim,
    # or an overage marker): "unknown", which is not the same as "in no group".
    groups_known: bool = True
    # OIDC authentication context: how the IdP says the user signed in.
    acr: str = ""
    amr: list[str] = field(default_factory=list)


class AuthFailed(Exception):
    """Wrong credentials or a protocol error. The message is for logs/audit only."""


class DirectoryUnavailable(AuthFailed):
    """The directory gave no complete answer: unreachable, TLS failure, service
    bind refused, busy, a time/size limit, a referral, missing read rights.

    Never a reason to disable anyone, and not a wrong password either. `code`
    says which part failed: tls, unreachable, bind, search.
    """

    def __init__(self, message: str, code: str = "unreachable") -> None:
        super().__init__(message)
        self.code = code


class AccessDenied(Exception):
    """Authenticated, but not allowed to use the VPN (disabled / no group policy)."""


class GroupsUnknown(AuthFailed):
    """The IdP sent no group information and AUTH_DEFAULT_ROLE is not set.
    Nothing about the user changes: an Entra group overage or a broken claim
    mapper must not offboard anyone."""


class MfaRequired(AuthFailed):
    """The role needs a second factor (AUTH_MFA_REQUIRED_ROLES) that this sign-in
    did not prove. Nothing about the user changes."""


def decide(identity: Identity) -> tuple[str | None, str]:
    """(role, access_profile_id) from group policies; role None = no access."""
    if identity.groups_known:
        matched = policy.resolve_policy(identity.provider, identity.groups, store.list_policies())
        if matched is not None:
            return matched["role"], matched.get("access_profile_id", "") or ""
    if config.AUTH_DEFAULT_ROLE in store.ROLE_RANK:
        return config.AUTH_DEFAULT_ROLE, ""
    return None, ""


def mfa_satisfied(identity: Identity, role: str) -> bool:
    """OIDC_REQUIRED_ACR / OIDC_REQUIRED_AMR for the roles in AUTH_MFA_REQUIRED_ROLES.

    Any listed acr value, and any listed amr value, satisfies its requirement;
    an empty list is not checked. Local accounts prove MFA with TOTP instead.
    """
    if identity.provider != "oidc" or role not in config.AUTH_MFA_REQUIRED_ROLES:
        return True
    if config.OIDC_REQUIRED_ACR and identity.acr not in config.OIDC_REQUIRED_ACR:
        return False
    if config.OIDC_REQUIRED_AMR and not set(identity.amr) & set(config.OIDC_REQUIRED_AMR):
        return False
    return True


def role_for(identity: Identity) -> str | None:
    return decide(identity)[0]


def attestation_due(user: dict[str, Any]) -> datetime | None:
    """When an OIDC user must have signed in again (AUTH_ATTESTATION_DAYS), else None.

    The panel cannot ask the IdP whether the account still exists, so a sign-in
    (which re-checks the groups) every AUTH_ATTESTATION_DAYS stands in for it.
    """
    if user.get("provider") != "oidc" or config.AUTH_ATTESTATION_DAYS <= 0:
        return None
    last = store.parse_iso(user.get("last_login_at", ""))
    return last + timedelta(days=config.AUTH_ATTESTATION_DAYS) if last else None


def admit(identity: Identity, ip: str = "") -> dict[str, Any]:
    """Apply group policies and upsert the user.

    Raises AccessDenied (disabled, or in no VPN group: an active user is then
    disabled and their devices suspended), GroupsUnknown or MfaRequired (the
    user is left exactly as they were).

    A user an administrator disabled stays disabled, whatever the directory says.
    A user disabled by the directory checks (directory_sync, attestation, an
    earlier denied sign-in) comes back here: this sign-in just re-checked the
    account and its groups.
    """
    actor = f"{identity.provider}:{identity.username}"
    existing = store.find_user(identity.provider, identity.external_id)
    target = (existing or {}).get("id", "")
    if existing and existing["status"] != "active" and existing.get("disabled_source") == "admin":
        store.audit("auth.denied", actor=actor, target=target, details={"reason": REASON_ADMIN}, ip=ip)
        raise AccessDenied(REASON_ADMIN)
    if identity.disabled:
        _deny(existing, actor, ip, REASON_DIRECTORY_DISABLED)
    role, profile_id = decide(identity)
    if role is None and not identity.groups_known:
        store.audit("auth.failed", actor=actor, target=target, ip=ip,
                    details={"reason": "the identity provider sent no group information"})
        raise GroupsUnknown("no groups claim")
    if role is None:
        _deny(existing, actor, ip, REASON_NO_VPN_GROUP)
    if not mfa_satisfied(identity, role):
        store.audit("auth.mfa_required", actor=actor, target=target, ip=ip,
                    details={"role": role, "acr": identity.acr, "amr": identity.amr})
        raise MfaRequired(f"role {role} needs a second factor")
    user = store.upsert_user(
        provider=identity.provider,
        external_id=identity.external_id,
        username=identity.username,
        email=identity.email,
        display_name=identity.display_name,
        role=role,
        groups=identity.groups,
        directory_dn=identity.directory_dn,
        access_profile_id=profile_id,
    )
    if user["status"] != "active":
        store.set_user_status(user["id"], "active")
        store.audit("user.enable", actor=actor, target=user["id"], ip=ip,
                    details={"username": user["username"], "via": "sign-in",
                             "previous_reason": user["disabled_reason"]})
        user = store.get_user(user["id"])
        import devices  # heavy backend imports only when needed

        devices.resume_user_devices(user["id"], actor=actor)
    store.audit("auth.login", actor=actor, target=user["id"], details={"role": role}, ip=ip)
    return user


def _deny(existing: dict[str, Any] | None, actor: str, ip: str, reason: str) -> None:
    if existing and existing["status"] == "active":
        store.set_user_status(existing["id"], "disabled", reason, source="directory")
        store.delete_user_sessions(existing["id"])
        import devices

        devices.suspend_user_devices(existing["id"], actor=actor)
    store.audit("auth.denied", actor=actor, target=(existing or {}).get("id", ""), details={"reason": reason}, ip=ip)
    raise AccessDenied(reason)


# ----------------------------------------------------------------- break-glass
def local_allowed_from(ip: str) -> bool:
    if not config.AUTH_LOCAL_ALLOWED_CIDRS:
        return True
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in config.AUTH_LOCAL_ALLOWED_CIDRS:
        try:
            if address in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def check_token(token: str) -> bool:
    expected = config.PANEL_SECRET_TOKEN.strip()
    return bool(expected) and secure_equals((token or "").strip(), expected)


def is_break_glass(username: str, password: str, ip: str) -> bool:
    if not config.AUTH_LOCAL_ENABLED:
        return False
    if not secure_equals((username or "").strip(), config.PANEL_USERNAME):
        return False
    return check_token(password) and local_allowed_from(ip)


def is_break_glass_user(user: dict[str, Any]) -> bool:
    return user["provider"] == "local" and user["external_id"] == config.PANEL_USERNAME


def local_admin_user() -> dict[str, Any]:
    """The break-glass account's user row.

    The account is controlled by AUTH_LOCAL_ENABLED and PANEL_SECRET_TOKEN, not
    by the panel (which refuses to disable it), so a successful break-glass
    sign-in makes sure the row is active.
    """
    user = store.upsert_user(
        provider="local",
        external_id=config.PANEL_USERNAME,
        username=config.PANEL_USERNAME,
        email="",
        display_name="Break-glass admin",
        role="admin",
        groups=[],
    )
    if user["status"] != "active":
        store.set_user_status(user["id"], "active")
        user = store.get_user(user["id"])
    return user
