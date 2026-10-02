"""LDAP / Active Directory: password sign-in and directory lookups for sync.

Sign-in: bind with the read-only service account, find the user by
LDAP_USER_FILTER, then bind as that user with the submitted password. Groups
come from LDAP_GROUP_ATTR (memberOf) plus an optional group search, by default
AD's LDAP_MATCHING_RULE_IN_CHAIN so nested groups count.

Only a complete, successful answer counts. Busy, unavailable, time or size
limits, referrals, missing read rights, a dropped connection or a TLS failure
raise DirectoryUnavailable, so neither a sign-in nor directory_sync ever acts on
a partial view of the directory (a failed nested-group search is not "in no VPN
group"). Referrals are never chased: that would send the service account's
password to whichever host the referral names.

Use ldaps:// or StartTLS in production: the password crosses the wire in the
user bind.
"""
from __future__ import annotations

import ssl
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from ldap3 import BASE, NONE, SUBTREE, SYNC, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.core.tls import check_hostname
from ldap3.utils.conv import escape_filter_chars

import config
from auth.identity import AuthFailed, DirectoryUnavailable, Identity

# AD userAccountControl: ACCOUNTDISABLE
_UAC_DISABLED = 0x2
# AD accountExpires (FILETIME: 100 ns ticks since 1601); 0 and 2^63-1 mean never.
_NEVER_EXPIRES = (0, 0x7FFFFFFFFFFFFFFF)
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

RESULT_SUCCESS = 0
RESULT_SIZE_LIMIT = 4
RESULT_NO_SUCH_OBJECT = 32
RESULT_INVALID_CREDENTIALS = 49

# Tests swap these for a shared ldap3 mock server and MOCK_SYNC.
_server_factory = None
_strategy = SYNC


class AmbiguousUser(AuthFailed):
    """More than one entry matches the username: never guess which account it is."""


def enabled() -> bool:
    return bool(config.LDAP_ENABLED and config.LDAP_URL and config.LDAP_USER_BASE_DN)


def tls_context() -> ssl.SSLContext:
    """TLS for ldaps:// and StartTLS: the platform's defaults for a verified client
    connection, LDAP_CA_FILE as the trust anchor (empty = system store).

    LDAP_TLS_STRICT=false drops VERIFY_X509_STRICT (a default since Python 3.13),
    which rejects e.g. a DC certificate without an Authority Key Identifier, as
    Samba generates for itself.
    """
    context = ssl.create_default_context(cafile=config.LDAP_CA_FILE or None)
    if not config.LDAP_TLS_STRICT:
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    # ldap3 matches the host name itself after the handshake (it also accepts a
    # CN-only certificate, as older DCs have).
    context.check_hostname = False
    return context


class _Tls(Tls):
    """ldap3's Tls with the SSLContext from tls_context()."""

    def wrap_socket(self, connection, do_handshake=False):
        wrapped = tls_context().wrap_socket(
            connection.socket, server_side=False, do_handshake_on_connect=do_handshake,
            server_hostname=connection.server.host,
        )
        if do_handshake:
            check_hostname(wrapped, connection.server.host, self.valid_names)
        connection.socket = wrapped


def _server() -> Server:
    if _server_factory is not None:
        return _server_factory()
    return Server(
        config.LDAP_URL,
        use_ssl=config.LDAP_URL.lower().startswith("ldaps://"),
        tls=_Tls(validate=ssl.CERT_REQUIRED),
        get_info=NONE,
        connect_timeout=config.LDAP_TIMEOUT,
        allowed_referral_hosts=[],
    )


def _transport_error(exc: Exception) -> DirectoryUnavailable:
    """Name the failing layer: a TLS problem must not read as a wrong password."""
    detail = str(exc)
    lowered = detail.lower()
    if "ssl" in lowered or "certificate" in lowered or "tls" in lowered:
        return DirectoryUnavailable(
            f"LDAP TLS error: {detail} (check LDAP_CA_FILE, the directory's certificate and "
            "its host name; LDAP_TLS_STRICT)", code="tls")
    return DirectoryUnavailable(f"LDAP server unreachable: {detail}", code="unreachable")


def _connect(user: Optional[str], password: Optional[str]) -> Connection:
    try:
        conn = Connection(
            _server(),
            user=user,
            password=password,
            client_strategy=_strategy,
            receive_timeout=config.LDAP_TIMEOUT,
            raise_exceptions=False,
            read_only=True,
            auto_referrals=False,
        )
        if _server_factory is None:
            conn.open()
            if config.LDAP_START_TLS:
                conn.start_tls()
    except LDAPException as exc:
        raise _transport_error(exc) from exc
    return conn


def _bind(user: Optional[str], password: Optional[str], service: bool = False) -> Optional[Connection]:
    """A bound connection, or None when the directory says invalidCredentials.

    Any other refusal is a directory problem for the service account and a
    failed sign-in for a user (AD reports locked, expired or "must change
    password" accounts as invalidCredentials anyway).
    """
    conn = _connect(user, password)
    try:
        if conn.bind():
            return conn
    except LDAPException as exc:
        raise _transport_error(exc) from exc
    result = conn.result or {}
    if result.get("result") == RESULT_INVALID_CREDENTIALS:
        return None
    if result.get("result") is None:
        raise _transport_error(Exception(conn.last_error or "no response to the bind"))
    reason = f"LDAP bind refused: {result.get('description')} {result.get('message') or ''}".strip()
    if service:
        raise DirectoryUnavailable(reason, code="bind")
    raise AuthFailed(reason)


def _unbind(conn: Connection) -> None:
    try:
        conn.unbind()
    except Exception:  # a broken connection is closed anyway
        pass


def _service() -> Connection:
    conn = _bind(config.LDAP_BIND_DN or None, config.LDAP_BIND_PASSWORD or None, service=True)
    if conn is None:
        raise DirectoryUnavailable(
            "LDAP service bind rejected: invalid credentials (check LDAP_BIND_DN / LDAP_BIND_PASSWORD)",
            code="bind")
    return conn


def _attrs() -> list[str]:
    wanted = [
        config.LDAP_USERNAME_ATTR,
        config.LDAP_EMAIL_ATTR,
        config.LDAP_DISPLAY_NAME_ATTR,
        config.LDAP_GROUP_ATTR,
        "userAccountControl",
        "accountExpires",
        "msDS-User-Account-Control-Computed",
        "pwdLastSet",
        "objectGUID",
        "entryUUID",
    ]
    return [a for a in dict.fromkeys(wanted) if a]


def _first(entry_attrs: dict[str, Any], name: str) -> Any:
    value = entry_attrs.get(name)
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _external_id(dn: str, attrs: dict[str, Any]) -> str:
    guid = _first(attrs, "objectGUID")
    if isinstance(guid, (bytes, bytearray)) and len(guid) == 16:
        return str(uuid.UUID(bytes_le=bytes(guid)))
    if isinstance(guid, str) and guid.strip("{}").count("-") == 4:
        return guid.strip("{}").lower()
    entry_uuid = _first(attrs, "entryUUID")
    if entry_uuid:
        return str(entry_uuid).lower()
    return dn.lower()


def _uac_disabled(attrs: dict[str, Any]) -> bool:
    raw = _first(attrs, "userAccountControl")
    try:
        return bool(int(raw) & _UAC_DISABLED) if raw not in (None, "") else False
    except (TypeError, ValueError):
        return False


def _expired(attrs: dict[str, Any], moment: Optional[datetime] = None) -> bool:
    """AD accountExpires in the past: the usual "last working day" offboarding.

    Without a schema ldap3 returns the raw number (as text); with one, a datetime.
    """
    raw = _first(attrs, "accountExpires")
    moment = moment or datetime.now(timezone.utc)
    if isinstance(raw, datetime):
        expires = raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
        return _FILETIME_EPOCH < expires <= moment
    try:
        ticks = int(raw)
    except (TypeError, ValueError):
        return False
    if ticks in _NEVER_EXPIRES or ticks < 0:
        return False
    return _FILETIME_EPOCH + timedelta(microseconds=ticks // 10) <= moment


def _search(conn: Connection, base: str, flt: str, scope=SUBTREE, attributes=None,
            missing_ok: bool = False) -> list:
    """Entries of a complete, successful search; anything else raises
    DirectoryUnavailable. noSuchObject is an empty answer only when missing_ok."""
    try:
        conn.search(base, flt, scope, attributes=attributes or [])
    except LDAPException as exc:
        raise _transport_error(exc) from exc
    result = conn.result or {}
    code = result.get("result")
    if code == RESULT_SUCCESS:
        return list(conn.entries)
    if code == RESULT_NO_SUCH_OBJECT and missing_ok:
        return []
    raise DirectoryUnavailable(f"LDAP search failed under {base!r}: {result.get('description') or code}",
                               code="search")


def _search_one(conn: Connection, base: str, flt: str, scope=SUBTREE,
                missing_ok: bool = False) -> Optional[tuple[str, dict[str, Any]]]:
    """(dn, attributes) of the one matching entry, None when there is none."""
    try:
        conn.search(base, flt, scope, attributes=_attrs(), size_limit=2)
    except LDAPException as exc:
        raise _transport_error(exc) from exc
    result = conn.result or {}
    code = result.get("result")
    entries = list(conn.entries)
    if code == RESULT_SIZE_LIMIT or (code == RESULT_SUCCESS and len(entries) > 1):
        raise AmbiguousUser(f"more than one entry matches {flt!r}")
    if code == RESULT_SUCCESS:
        return (entries[0].entry_dn, entries[0].entry_attributes_as_dict) if entries else None
    if code == RESULT_NO_SUCH_OBJECT and missing_ok:
        return None
    raise DirectoryUnavailable(f"LDAP search failed under {base!r}: {result.get('description') or code}",
                               code="search")


def _groups(conn: Connection, dn: str, attrs: dict[str, Any]) -> list[str]:
    groups = [str(g) for g in (attrs.get(config.LDAP_GROUP_ATTR) or [])]
    if config.LDAP_GROUP_SEARCH_FILTER:
        flt = config.LDAP_GROUP_SEARCH_FILTER.format(user_dn=escape_filter_chars(dn))
        # A failed or partial search raises: never a partial group list.
        groups.extend(entry.entry_dn for entry in _search(conn, config.LDAP_GROUP_BASE_DN, flt,
                                                          attributes=["cn"]))
    return sorted(set(groups), key=str.lower)


def _ad_login_restricted(attrs: dict[str, Any]) -> bool:
    # AD computes lockout/password-expiry from domain policy; lockoutTime alone
    # stays nonzero after automatic unlock and must not be used as a boolean.
    raw = _first(attrs, "msDS-User-Account-Control-Computed")
    try:
        computed = int(raw) if raw not in (None, "") else 0
        password_last_set = _first(attrs, "pwdLastSet")
        must_change = password_last_set not in (None, "") and int(password_last_set) == 0
    except (TypeError, ValueError) as exc:
        raise DirectoryUnavailable("Invalid AD account status attributes", code="status") from exc
    return bool(computed & (0x0010 | 0x00800000)) or must_change


def _disabled(conn: Connection, dn: str, attrs: dict[str, Any]) -> bool:
    if _uac_disabled(attrs) or _expired(attrs) or _ad_login_restricted(attrs):
        return True
    if config.LDAP_DISABLED_FILTER:
        # A match of the entry itself means disabled (FreeIPA nsAccountLock, ppolicy...).
        return bool(_search(conn, dn, config.LDAP_DISABLED_FILTER, BASE, missing_ok=True))
    return False


def _identity(conn: Connection, dn: str, attrs: dict[str, Any], fallback_username: str) -> Identity:
    username = str(_first(attrs, config.LDAP_USERNAME_ATTR) or fallback_username)
    return Identity(
        provider="ldap",
        external_id=_external_id(dn, attrs),
        username=username,
        email=str(_first(attrs, config.LDAP_EMAIL_ATTR) or ""),
        display_name=str(_first(attrs, config.LDAP_DISPLAY_NAME_ATTR) or username),
        groups=_groups(conn, dn, attrs),
        disabled=_disabled(conn, dn, attrs),
        directory_dn=dn,
    )


def _user_filter(username: str) -> str:
    return config.LDAP_USER_FILTER.format(username=escape_filter_chars(username))


def authenticate(username: str, password: str) -> Identity:
    """Raises AuthFailed for a wrong or unknown account, DirectoryUnavailable
    when the directory cannot answer."""
    username = (username or "").strip()
    # An empty password turns a simple bind into an unauthenticated bind, which
    # many servers accept: never let it through.
    if not username or not password:
        raise AuthFailed("empty username or password")
    service = _service()
    try:
        found = _search_one(service, config.LDAP_USER_BASE_DN, _user_filter(username))
        if found is None:
            raise AuthFailed("user not found")
        dn, attrs = found
        user_conn = _bind(dn, password)
        if user_conn is None:
            raise AuthFailed("invalid credentials")
        _unbind(user_conn)
        return _identity(service, dn, attrs, username)
    finally:
        _unbind(service)


def lookup(directory_dn: str, username: str) -> Optional[Identity]:
    """Current directory state of a user for directory_sync.

    None only when the directory positively answered "no such user" (success
    with no entry). Raises DirectoryUnavailable for anything less certain and
    AmbiguousUser when the username matches several entries.
    """
    service = _service()
    try:
        found = None
        if directory_dn:
            found = _search_one(service, directory_dn, "(objectClass=*)", scope=BASE, missing_ok=True)
        if found is None and username:
            found = _search_one(service, config.LDAP_USER_BASE_DN, _user_filter(username))
        if found is None:
            return None
        dn, attrs = found
        return _identity(service, dn, attrs, username)
    finally:
        _unbind(service)


def test_connection() -> dict[str, Any]:
    """Service bind plus a search of LDAP_USER_BASE_DN; `code` says what failed."""
    try:
        service = _service()
    except DirectoryUnavailable as exc:
        return {"ok": False, "code": exc.code, "detail": str(exc)}
    try:
        _search(service, config.LDAP_USER_BASE_DN, "(objectClass=*)", BASE)
    except DirectoryUnavailable as exc:
        return {"ok": False, "code": exc.code, "detail": str(exc)}
    finally:
        _unbind(service)
    return {"ok": True, "code": "ok", "detail": "service bind and base DN search succeeded"}
