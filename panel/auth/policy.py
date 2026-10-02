"""Directory group -> panel role.

Group names arrive in different shapes depending on the source:
  * LDAP memberOf:     CN=VPN-Admins,OU=Groups,DC=corp,DC=example,DC=com
  * Keycloak groups:   /corp/vpn-admins   (full path) or vpn-admins
  * ADFS / Entra:      VPN-Admins, CORP\\VPN-Admins, or an object id

A qualified policy (a DN, a /path or DOMAIN\\name) matches only that very group:
DNs are compared RDN by RDN (attribute types and values case-insensitive,
escapes resolved), paths and DOMAIN\\name case-insensitively. A group of the
same name in another OU, Keycloak subtree or domain does not match. Two
qualified values of different kinds never match either, so write the policy
in the form the IdP emits.

A bare name (VPN-Admins, an object id) matches every group with that name,
wherever it lives: the CN of a DN, the last segment of a path, the name after
DOMAIN\\. The same short-name comparison applies when the IdP itself sends bare
names, since there is nothing else to compare then.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from string import hexdigits
from typing import Iterable, Optional

from ldap3.core.exceptions import LDAPInvalidDnError
from ldap3.utils.dn import parse_dn

from auth.store import ROLE_RANK

_SPACES = re.compile(r"\s+")


@dataclass(frozen=True)
class GroupForm:
    kind: str   # "dn" | "path" | "domain" | "name"
    key: str    # normalised full value, compared within the same kind
    name: str   # normalised short name, compared when one side is a bare name


def _fold(value: str) -> str:
    return _SPACES.sub(" ", value.strip()).casefold()


def _unescape(value: str) -> str:
    """RFC 4514 value escapes: \\, \\+ ... and \\XX hex pairs (UTF-8 bytes)."""
    out = bytearray()
    i = 0
    while i < len(value):
        if value[i] == "\\" and i + 1 < len(value):
            pair = value[i + 1:i + 3]
            if len(pair) == 2 and all(c in hexdigits for c in pair):
                out += bytes.fromhex(pair)
                i += 3
            else:
                out += value[i + 1].encode("utf-8")
                i += 2
            continue
        out += value[i].encode("utf-8")
        i += 1
    return out.decode("utf-8", "replace")


def _dn_form(raw: str) -> Optional[GroupForm]:
    try:
        parts = parse_dn(raw, escape=False, strip=True)
    except (LDAPInvalidDnError, ValueError, IndexError):
        return None
    if not parts:
        return None
    rdns: list[list[str]] = [[]]
    for attr, value, separator in parts:
        rdns[-1].append(f"{attr.strip().casefold()}={_fold(_unescape(value))}")
        if separator != "+":
            rdns.append([])
    key = ",".join("+".join(sorted(avas)) for avas in rdns if avas)
    first_attr, first_value, _ = parts[0]
    name = _fold(_unescape(first_value)) if first_attr.strip().casefold() in ("cn", "ou", "uid") else key
    return GroupForm("dn", key, name)


def group_form(value: str) -> Optional[GroupForm]:
    raw = (value or "").strip()
    if not raw:
        return None
    if raw.startswith("/"):
        segments = [_fold(s) for s in raw.split("/") if s.strip()]
        if segments:
            return GroupForm("path", "/" + "/".join(segments), segments[-1])
        return None
    if "\\" in raw and "=" not in raw:
        domain, _, name = raw.partition("\\")
        if domain.strip() and name.strip():
            return GroupForm("domain", f"{_fold(domain)}\\{_fold(name)}", _fold(name))
    if "=" in raw:
        form = _dn_form(raw)
        if form is not None:
            return form
    return GroupForm("name", _fold(raw), _fold(raw))


def group_matches(policy_group: str, user_group: str) -> bool:
    wanted, have = group_form(policy_group), group_form(user_group)
    if wanted is None or have is None:
        return False
    if wanted.kind == "name" or have.kind == "name":
        return wanted.name == have.name
    return wanted.kind == have.kind and wanted.key == have.key


def resolve_policy(provider: str, groups: Iterable[str], policies: list[dict]) -> Optional[dict]:
    """The best matching policy, or None when nothing matches.

    Lowest `priority` wins; on a tie the more privileged role wins. The policy
    carries the role and (optionally) the access profile.
    """
    groups = [g for g in groups if g and str(g).strip()]
    best: Optional[tuple[int, int, int, dict]] = None
    for index, policy in enumerate(policies):
        if policy["provider"] not in ("any", provider):
            continue
        if not any(group_matches(policy["group_name"], group) for group in groups):
            continue
        candidate = (int(policy["priority"]), -ROLE_RANK[policy["role"]], index, policy)
        if best is None or candidate[:3] < best[:3]:
            best = candidate
    return best[3] if best else None


def resolve_role(provider: str, groups: Iterable[str], policies: list[dict]) -> Optional[str]:
    policy = resolve_policy(provider, groups, policies)
    return policy["role"] if policy else None
