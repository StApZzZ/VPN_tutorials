"""FastAPI dependencies: who is calling, and may they.

Three ways in:
  * session cookie (browser)            -> role from the user record, CSRF enforced
  * Authorization: Bearer <token>        -> break-glass admin or a named API token
  * Basic <PANEL_USERNAME>:<token>       -> break-glass admin, for tools that only speak Basic
The token paths honour AUTH_API_TOKEN_ENABLED and AUTH_LOCAL_ALLOWED_CIDRS. A
wrong token counts against the client IP's failure budget, and a client over
it gets no token checked at all.

Named tokens may carry a read-only scope instead of a role (store.TOKEN_SCOPES):
require_metrics admits a "metrics" token (or an admin) to GET /metrics,
require_auditor an "auditor" token (or an admin) to the audit log.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Callable, Optional

from fastapi import HTTPException, Request, status

import config
from auth import sessions, store, tokens
from auth.identity import USERNAME_MAX, check_token, local_allowed_from, secure_equals

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_UNRESOLVED = object()


@dataclass(frozen=True)
class Principal:
    user_id: str
    username: str
    display_name: str
    role: str
    provider: str
    via: str  # "session" | "token"
    csrf: str = ""

    def has(self, role: str) -> bool:
        return store.ROLE_RANK.get(self.role, 0) >= store.ROLE_RANK[role]


def _token_principal(request: Request) -> Optional[Principal]:
    if not config.AUTH_API_TOKEN_ENABLED:
        return None
    header = request.headers.get("authorization", "")
    bearer = header[:7].lower() == "bearer "
    if bearer:
        token = header[7:].strip()
    elif header[:6].lower() == "basic ":
        try:
            username, _, password = base64.b64decode(header[6:]).decode("utf-8").partition(":")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            username = password = ""
        token = password if secure_equals(username, config.PANEL_USERNAME) else ""
    else:
        return None
    ip = sessions.client_ip(request)
    if limiter.blocked_ip(ip) or not local_allowed_from(ip):
        return None
    if token and check_token(token):
        return Principal(
            user_id="",
            username=config.PANEL_USERNAME,
            display_name="API token",
            role="admin",
            provider="local",
            via="token",
        )
    named = tokens.verify(token) if token and bearer else None
    if named is None:
        limiter.failed(ip)
        return None
    return Principal(
        user_id="",
        username=f"token:{named['name']}",
        display_name=f"API token {named['name']}",
        role=named["role"],
        provider="token",
        via="token",
    )


def current_principal(request: Request) -> Optional[Principal]:
    # Resolved once per request, including "nobody": a wrong token is counted once.
    cached = getattr(request.state, "principal", _UNRESOLVED)
    if cached is not _UNRESOLVED:
        return cached
    principal = _token_principal(request)
    if principal is None:
        resolved = sessions.resolve(sessions.read_cookie(request))
        if resolved is not None:
            session, user = resolved
            principal = Principal(
                user_id=user["id"],
                username=user["username"],
                display_name=user["display_name"] or user["username"],
                role=user["role"],
                provider=user["provider"],
                via="session",
                csrf=session["csrf"],
            )
    request.state.principal = principal
    return principal


def _wants_html(request: Request) -> bool:
    return request.method in SAFE_METHODS and "text/html" in request.headers.get("accept", "")


def require_role(role: str) -> Callable[[Request], Principal]:
    def dependency(request: Request) -> Principal:
        principal = current_principal(request)
        if principal is None:
            if _wants_html(request):
                raise HTTPException(status.HTTP_302_FOUND, headers={"Location": "/login"})
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated", headers={"WWW-Authenticate": "Bearer"})
        if not principal.has(role):
            if _wants_html(request):
                raise HTTPException(status.HTTP_302_FOUND, headers={"Location": "/me"})
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"requires role {role}")
        if principal.via == "session" and request.method not in SAFE_METHODS:
            sent = request.headers.get("x-csrf-token", "")
            if not sent or not secure_equals(sent, principal.csrf):
                raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF token missing or invalid")
        return principal

    return dependency


require_user = require_role("user")
require_operator = require_role("operator")
require_admin = require_role("admin")


def _require_scope(scope: str) -> Callable[[Request], Principal]:
    def dependency(request: Request) -> Principal:
        principal = current_principal(request)
        if principal is not None and principal.via == "token" and principal.role == scope:
            if request.method not in SAFE_METHODS:
                raise HTTPException(status.HTTP_403_FORBIDDEN, f"the {scope} scope is read-only")
            return principal
        return require_admin(request)

    return dependency


require_metrics = _require_scope("metrics")
require_auditor = _require_scope("auditor")


# ------------------------------------------------------------- brute-force guard
class FailureLimiter:
    """Sliding-window failure budgets, checked before a password reaches any
    directory:

      * per username, across all source IPs (AUTH_MAX_FAILURES). Keep it BELOW
        the directory's own lockout threshold: then no number of addresses a
        password spray comes from can make the panel lock an AD account;
      * per client IP, across all usernames (AUTH_MAX_FAILURES_PER_IP): sprays
        and API-token guessing.

    In-process only (the panel runs one worker). Usernames are kept as hashes,
    emptied keys are dropped and the number of keys is capped (oldest out), so
    a stream of unique usernames cannot grow memory.
    """

    MAX_KEYS = 100_000
    _MAX_EVENTS = 256  # per key; every budget is far smaller

    def __init__(self) -> None:
        self._events: OrderedDict[tuple[str, str], deque] = OrderedDict()
        self._noticed: OrderedDict[tuple[str, str], float] = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _user_key(username: str) -> tuple[str, str]:
        folded = (username or "").strip()[:USERNAME_MAX].casefold()
        return "user", hashlib.sha256(folded.encode("utf-8")).hexdigest()

    @staticmethod
    def _remember(table: OrderedDict, key, value) -> None:
        table[key] = value
        table.move_to_end(key)
        while len(table) > FailureLimiter.MAX_KEYS:
            table.popitem(last=False)

    def _count(self, key: tuple[str, str], now: float) -> int:
        events = self._events.get(key)
        if events is None:
            return 0
        while events and now - events[0] > config.AUTH_FAILURE_WINDOW_SECONDS:
            events.popleft()
        if not events:
            del self._events[key]
        return len(events)

    def blocked_ip(self, ip: str) -> bool:
        with self._lock:
            return self._count(("ip", ip or ""), time.monotonic()) >= config.AUTH_MAX_FAILURES_PER_IP

    def blocked_user(self, username: str) -> bool:
        with self._lock:
            return self._count(self._user_key(username), time.monotonic()) >= config.AUTH_MAX_FAILURES

    def blocked(self, ip: str, username: str = "") -> bool:
        return self.blocked_ip(ip) or (bool(username) and self.blocked_user(username))

    def failed(self, ip: str, username: str = "") -> None:
        """Count a failure against the IP and, when given, the username."""
        now = time.monotonic()
        keys = [("ip", ip or "")] + ([self._user_key(username)] if username else [])
        with self._lock:
            for key in keys:
                events = self._events.get(key)
                if events is None:
                    events = deque(maxlen=self._MAX_EVENTS)
                self._remember(self._events, key, events)
                events.append(now)

    def reset(self, ip: str = "", username: str = "") -> None:
        """A successful sign-in restores the username's budget, not the IP's (one
        account the attacker owns must not refill a spray's budget). Without
        arguments: forget everything."""
        with self._lock:
            if not ip and not username:
                self._events.clear()
                self._noticed.clear()
            elif username:
                self._events.pop(self._user_key(username), None)

    def first_notice(self, ip: str, username: str = "") -> bool:
        """True once per (IP, username) and window: auth.locked is audited once,
        not for every refused attempt."""
        key = (ip or "", self._user_key(username)[1] if username else "")
        now = time.monotonic()
        with self._lock:
            last = self._noticed.get(key)
            if last is not None and now - last <= config.AUTH_FAILURE_WINDOW_SECONDS:
                return False
            self._remember(self._noticed, key, now)
            return True


limiter = FailureLimiter()
