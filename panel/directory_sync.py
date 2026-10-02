"""Periodic directory reconciliation — the offboarding path.

Run by a systemd timer (deploy/ansible/roles/app) and from the panel.

  * LDAP users: each active user is re-read from the directory. Disabled there
    (userAccountControl, accountExpires, LDAP_DISABLED_FILTER) or no longer in
    any VPN group -> the user is disabled, every session revoked and every
    device suspended. Not found -> the same, but only when two runs in a row say
    so (an account being moved between OUs, replication lag). Otherwise role,
    groups and profile are refreshed. Users the directory checks disabled
    earlier are re-read as well and come back once the directory allows them.
  * The directory must answer completely: a search error stops the LDAP part
    without changing anything, and a run that would disable more users than
    DIRECTORY_SYNC_MAX_DISABLE allows is refused as a whole
    (directory.sync_aborted): a lost read permission or a wrong base DN looks
    exactly like "everybody left".
  * Devices past their access-profile TTL are suspended as expired.
  * OIDC users: the panel cannot query the IdP directory, so it uses attestation:
    an active user whose last sign-in is older than AUTH_ATTESTATION_DAYS is
    disabled until they sign in again (sign-in re-checks their groups). In the
    last AUTH_ATTESTATION_WARN_DAYS before that, directory.attestation_due is
    audited once (syslog / SIEM can notify the employee).
  * Expired sessions and sign-in state are purged.

    python directory_sync.py          # prints a JSON summary; exit 1 on errors
"""
from __future__ import annotations

import contextlib
import json
import math
import os
import sys
import tempfile
import threading
from datetime import timedelta
from typing import Any, Iterator, Optional

import config
import devices
from auth import identity, ldap_auth, store
from auth.identity import AuthFailed, Identity, decide

try:  # POSIX servers; elsewhere only the in-process lock applies
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

# A percentage limit never goes below this many users (small directories).
MIN_DISABLE_LIMIT = 5

_run_lock = threading.Lock()


def _lock_path() -> str:
    db_path = str(config.CORPVPN_DB_PATH)
    base = os.path.dirname(db_path) if "://" not in db_path else tempfile.gettempdir()
    return os.path.join(base or tempfile.gettempdir(), ".corpvpn-directory-sync.lock")


@contextlib.contextmanager
def _exclusive() -> Iterator[bool]:
    """One run at a time across the timer's process and the panel's "sync now"."""
    if not _run_lock.acquire(blocking=False):
        yield False
        return
    try:
        if fcntl is None:
            yield True
            return
        os.makedirs(os.path.dirname(_lock_path()), exist_ok=True)
        with open(_lock_path(), "a") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                yield False
                return
            try:
                yield True
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)
    finally:
        _run_lock.release()


def disable_limit(active: int) -> int:
    """How many LDAP users one run may disable; 0 = no limit.

    DIRECTORY_SYNC_MAX_DISABLE is a number of users ("25") or a share of the
    active LDAP users ("10%", never below MIN_DISABLE_LIMIT).
    """
    raw = config.DIRECTORY_SYNC_MAX_DISABLE.strip()
    if raw.endswith("%"):
        share = float(raw[:-1] or 0) / 100
        return max(MIN_DISABLE_LIMIT, math.ceil(share * active)) if share > 0 else 0
    return max(0, int(raw or 0))


def _disable(user: dict[str, Any], reason: str, summary: dict[str, Any], source: str = "directory") -> None:
    store.set_user_status(user["id"], "disabled", reason, source=source)
    revoked = store.delete_user_sessions(user["id"])
    suspended = devices.suspend_user_devices(user["id"], actor="directory_sync")
    store.audit(
        "directory.disable",
        actor="directory_sync",
        target=user["id"],
        details={"username": user["username"], "provider": user["provider"], "reason": reason,
                 "sessions_revoked": revoked, "devices_suspended": suspended},
    )
    summary["disabled"].append({"username": user["username"], "reason": reason})


def _verdict(user: dict[str, Any], found: Optional[Identity]) -> tuple[str, str, Optional[str], str]:
    """(action, reason, role, profile_id); action: allow | disable | missing."""
    if found is None:
        action = "disable" if user.get("directory_missing_since") else "missing"
        return action, identity.REASON_DIRECTORY_MISSING, None, ""
    if found.disabled:
        return "disable", identity.REASON_DIRECTORY_DISABLED, None, ""
    role, profile_id = decide(found)
    if role is None:
        return "disable", identity.REASON_NO_VPN_GROUP, None, ""
    return "allow", "", role, profile_id


def _refresh(user: dict[str, Any], found: Identity, role: str, profile_id: str, summary: dict[str, Any]) -> None:
    if (
        role != user["role"]
        or sorted(found.groups) != sorted(user["groups"])
        or profile_id != user.get("access_profile_id", "")
        or found.directory_dn != user.get("directory_dn", "")
    ):
        store.update_user_directory(user["id"], role=role, groups=found.groups,
                                    access_profile_id=profile_id, directory_dn=found.directory_dn)
        store.audit(
            "directory.update",
            actor="directory_sync",
            target=user["id"],
            details={"username": user["username"], "role": role, "previous_role": user["role"]},
        )
        summary["updated"] += 1
    elif user.get("directory_missing_since"):
        store.set_directory_missing(user["id"], "")


def _enable(user: dict[str, Any], found: Identity, role: str, profile_id: str, summary: dict[str, Any]) -> None:
    store.update_user_directory(user["id"], role=role, groups=found.groups,
                                access_profile_id=profile_id, directory_dn=found.directory_dn)
    store.set_user_status(user["id"], "active")
    resumed = devices.resume_user_devices(user["id"], actor="directory_sync")
    store.audit(
        "directory.enable",
        actor="directory_sync",
        target=user["id"],
        details={"username": user["username"], "previous_reason": user["disabled_reason"],
                 "devices_resumed": resumed},
    )
    summary["enabled"].append({"username": user["username"], "previous_reason": user["disabled_reason"]})


def _sync_ldap(summary: dict[str, Any]) -> None:
    active = store.list_users(provider="ldap", status="active")
    # Disabled by the directory checks before: the directory may allow them again.
    # An administrator's disable is never undone here.
    returning = [u for u in store.list_users(provider="ldap", status="disabled")
                 if u.get("disabled_source") == "directory"]
    plan = []
    for user in active + returning:
        summary["checked"] += 1
        try:
            found = ldap_auth.lookup(user.get("directory_dn", ""), user["username"])
        except ldap_auth.AmbiguousUser as exc:
            summary["errors"].append(f"{user['username']}: {exc}")
            continue
        except AuthFailed as exc:
            # The directory did not answer completely: change nothing at all.
            summary["errors"].append(str(exc))
            return
        plan.append((user, found, _verdict(user, found)))

    leaving = [user["username"] for user, _, verdict in plan if user["status"] == "active" and verdict[0] == "disable"]
    limit = disable_limit(len(active))
    if limit and len(leaving) > limit:
        summary["errors"].append(
            f"refused to disable {len(leaving)} of {len(active)} LDAP users in one run "
            f"(DIRECTORY_SYNC_MAX_DISABLE allows {limit}); check the directory and the service "
            "account's read permissions, then disable them by hand or raise the limit"
        )
        store.audit("directory.sync_aborted", actor="directory_sync",
                    details={"would_disable": len(leaving), "active": len(active), "limit": limit,
                             "users": leaving[:50]})
        return

    for user, found, (action, reason, role, profile_id) in plan:
        if user["status"] != "active":
            if action == "allow":
                _enable(user, found, role, profile_id, summary)
        elif action == "disable":
            _disable(user, reason, summary)
        elif action == "missing":
            store.set_directory_missing(user["id"], store.iso(store.now()))
            store.audit("directory.missing", actor="directory_sync", target=user["id"],
                        details={"username": user["username"]})
            summary["missing"].append(user["username"])
        else:
            _refresh(user, found, role, profile_id, summary)


def _attest_oidc(summary: dict[str, Any]) -> None:
    moment = store.now()
    warn = timedelta(days=max(0, config.AUTH_ATTESTATION_WARN_DAYS))
    for user in store.list_users(provider="oidc", status="active"):
        summary["checked"] += 1
        due = identity.attestation_due(user)
        if due is None or due <= moment:
            _disable(user, identity.REASON_ATTESTATION, summary, source="attestation")
            continue
        warned = store.parse_iso(user.get("attestation_warned_at", ""))
        last = store.parse_iso(user["last_login_at"])
        if warn and due - moment <= warn and (warned is None or warned < last):
            store.set_attestation_warned(user["id"], store.iso(moment))
            store.audit(
                "directory.attestation_due",
                actor="directory_sync",
                target=user["id"],
                details={"username": user["username"], "email": user["email"], "due_at": store.iso(due),
                         "days_left": (due - moment).days},
            )
            summary["attestation_due"] += 1


def run() -> dict[str, Any]:
    summary: dict[str, Any] = {"checked": 0, "updated": 0, "disabled": [], "enabled": [], "missing": [],
                               "attestation_due": 0, "errors": []}
    with _exclusive() as mine:
        if not mine:
            summary["errors"].append("another directory sync is running")
            return summary
        if ldap_auth.enabled():
            _sync_ldap(summary)
        if config.AUTH_ATTESTATION_DAYS > 0:
            _attest_oidc(summary)
        summary["expired_devices"] = devices.enforce_expiry(actor="directory_sync")
        store.purge_expired_sessions(store.now())
        if summary["updated"]:
            # Access profiles may have changed; device changes refreshed on their own.
            import network_policy

            network_policy.safe_refresh("directory sync")
    return summary


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, ensure_ascii=False))
    sys.exit(1 if result["errors"] else 0)
