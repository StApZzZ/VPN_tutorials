"""Local accounts, hashed one-use invitations and RFC 6238 authenticators."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import struct
import threading
import time
import tempfile
import functools
import unicodedata
from urllib.parse import quote, urlencode

from cryptography.fernet import Fernet
from sqlalchemy import text

import config
from auth import store

_HASH_SLOTS = threading.BoundedSemaphore(2)
_DUMMY_SALT = b"CorpVPN-dummy-01"


def engine():
    engine = store._engine()
    with engine.begin() as conn:
        conn.execute(text("""CREATE TABLE IF NOT EXISTS local_credentials (
            user_id TEXT PRIMARY KEY, password_hash TEXT NOT NULL DEFAULT '',
            totp_secret TEXT NOT NULL DEFAULT '', totp_pending TEXT NOT NULL DEFAULT '',
            last_counter INTEGER NOT NULL DEFAULT -1, recovery_json TEXT NOT NULL DEFAULT '[]')"""))
        conn.execute(text("""CREATE TABLE IF NOT EXISTS local_invites (
            token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires INTEGER NOT NULL,
            consumed INTEGER NOT NULL DEFAULT 0)"""))
    return engine


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def crypt():
    key = config.PANEL_DATA_KEY.encode()
    if not key:
        path = Path(config.LOCAL_DATA_KEY_PATH)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not path.exists():
            fd, temporary = tempfile.mkstemp(prefix=".local-key-", dir=path.parent)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(Fernet.generate_key())
                    handle.flush()
                    os.fsync(handle.fileno())
                try:
                    # An exclusive hard link publishes a complete file atomically.
                    os.link(temporary, path)
                except FileExistsError:
                    pass
            finally:
                os.unlink(temporary)
        key = path.read_bytes()
    return Fernet(key)


def locked(fn):
    @functools.wraps(fn)
    def run(*args, **kwargs):
        from devices import backend_lock
        with backend_lock():
            return fn(*args, **kwargs)
    return run


def password_bytes(password: str) -> bytes:
    return unicodedata.normalize("NFC", password).encode("utf-8")


def derive(password: str, salt: bytes) -> bytes:
    with _HASH_SLOTS:
        return hashlib.scrypt(password_bytes(password), salt=salt, n=2**17, r=8, p=1,
                              dklen=32, maxmem=256 * 1024 * 1024)


def hash_password(password: str) -> str:
    if not 12 <= len(password) <= 128:
        raise store.StoreError("password_length_12_128")
    salt = secrets.token_bytes(16)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(derive(password, salt)).decode()


def check_password(password: str, value: str) -> bool:
    if not value or len(password) > 128:
        derive(password[:128], _DUMMY_SALT)
        return False
    try:
        scheme, salt, expected = value.split("$")
        if scheme != "scrypt":
            raise ValueError("invalid password hash")
        result = derive(password, base64.b64decode(salt, validate=True))
        return hmac.compare_digest(result, base64.b64decode(expected, validate=True))
    except (ValueError, TypeError):
        return False


def required(user: dict) -> bool:
    return config.AUTH_LOCAL_TOTP == "all" or (config.AUTH_LOCAL_TOTP == "admins" and user["role"] == "admin")


def totp(secret: str, counter: int, digits: int = 6) -> str:
    raw = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    data = hmac.new(raw, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = data[-1] & 15
    number = (struct.unpack(">I", data[offset:offset + 4])[0] & 0x7fffffff) % (10**digits)
    return str(number).zfill(digits)


def matching_counter(secret: str, code: str) -> int | None:
    if not re.fullmatch(r"[0-9]{6}", code):
        return None
    now = int(time.time()) // 30
    for counter in (now, now - 1, now + 1):
        if counter >= 0 and hmac.compare_digest(totp(secret, counter), code):
            return counter
    return None


def credentials(user_id: str) -> dict | None:
    with engine().connect() as conn:
        row = conn.execute(text("SELECT * FROM local_credentials WHERE user_id=:id"), {"id": user_id}).mappings().first()
    return dict(row) if row else None


def local_user(user_id: str) -> dict:
    user = store.get_user(user_id)
    if not user or user["provider"] != "local" or not user["external_id"].startswith("u:"):
        raise store.StoreError("local_user_not_found")
    return user


def users() -> list[dict]:
    out = []
    for user in store.list_users(provider="local"):
        if user["external_id"].startswith("u:"):
            cred = credentials(user["id"]) or {}
            out.append({**user, "password_set": bool(cred.get("password_hash")), "totp_enabled": bool(cred.get("totp_secret"))})
    return out


@locked
def create(username: str, role: str, profile: str = "", display_name: str = "") -> dict:
    username = unicodedata.normalize("NFC", username.strip()).casefold()
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", username) or username in {config.PANEL_USERNAME.casefold(), "unassigned"}:
        raise store.StoreError("invalid_or_reserved_username")
    if role not in store.ROLES:
        raise store.StoreError("invalid_role")
    store._validate_profile_ref(profile)
    if store.find_user("local", "u:" + username):
        raise store.StoreError("username_exists")
    user = store.upsert_user(provider="local", external_id="u:" + username, username=username,
                             email="", display_name=display_name, role=role, groups=[], login=False,
                             access_profile_id=profile)
    with engine().begin() as conn:
        conn.execute(text("INSERT INTO local_credentials(user_id) VALUES(:id)"), {"id": user["id"]})
    return user


@locked
def update(user_id: str, role: str, profile: str, display_name: str) -> dict:
    local_user(user_id)
    if role not in store.ROLES:
        raise store.StoreError("invalid_role")
    store._validate_profile_ref(profile)
    with engine().begin() as conn:
        conn.execute(text("UPDATE users SET role=:role, access_profile_id=:profile, display_name=:name WHERE id=:id"),
                     {"role": role, "profile": profile, "name": display_name, "id": user_id})
        conn.execute(text("DELETE FROM sessions WHERE user_id=:id"), {"id": user_id})
    return local_user(user_id)


@locked
def invite(user_id: str) -> str:
    local_user(user_id)
    token = secrets.token_urlsafe(24)
    with engine().begin() as conn:
        conn.execute(text("DELETE FROM local_invites WHERE user_id=:id OR expires<:now"), {"id": user_id, "now": int(time.time())})
        conn.execute(text("INSERT INTO local_invites(token_hash,user_id,expires) VALUES(:hash,:id,:expires)"),
                     {"hash": digest(token), "id": user_id, "expires": int(time.time()) + 72 * 3600})
        conn.execute(text("UPDATE local_credentials SET password_hash='', totp_secret='', totp_pending='', recovery_json='[]', last_counter=-1 WHERE user_id=:id"), {"id": user_id})
        conn.execute(text("DELETE FROM sessions WHERE user_id=:id"), {"id": user_id})
    return token


def invitation(token: str) -> dict:
    if len(token) > 128:
        raise store.StoreError("invalid_invite")
    with engine().connect() as conn:
        row = conn.execute(text("SELECT * FROM local_invites WHERE token_hash=:hash AND consumed=0 AND expires>:now"),
                           {"hash": digest(token), "now": int(time.time())}).mappings().first()
    if not row:
        raise store.StoreError("invalid_or_expired_invite")
    user = local_user(row["user_id"])
    if user["status"] != "active":
        raise store.StoreError("user_disabled")
    return user


@locked
def begin_totp(user_id: str) -> dict:
    user = local_user(user_id)
    cred = credentials(user_id)
    if cred["totp_secret"]:
        raise store.StoreError("totp_already_enabled_use_admin_reset")
    if cred["totp_pending"]:
        secret = crypt().decrypt(cred["totp_pending"].encode()).decode()
    else:
        secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
        sealed = crypt().encrypt(secret.encode()).decode()
        with engine().begin() as conn:
            # Keep concurrent requests on one pending secret.
            conn.execute(text("UPDATE local_credentials SET totp_pending=:secret WHERE user_id=:id AND totp_pending=''"), {"secret": sealed, "id": user_id})
        secret = crypt().decrypt(credentials(user_id)["totp_pending"].encode()).decode()
    uri = "otpauth://totp/" + quote("CorpVPN:" + user["username"], safe="") + "?" + urlencode({"secret": secret, "issuer": "CorpVPN", "algorithm": "SHA1", "digits": 6, "period": 30})
    return {"secret": secret, "uri": uri}


def _enrol(conn, user_id: str, code: str) -> list[str]:
    cred = conn.execute(text("SELECT * FROM local_credentials WHERE user_id=:id"), {"id": user_id}).mappings().first()
    if cred and cred["totp_secret"]:
        raise store.StoreError("totp_already_enabled_use_admin_reset")
    if not cred or not cred["totp_pending"]:
        raise store.StoreError("totp_not_started")
    secret = crypt().decrypt(cred["totp_pending"].encode()).decode()
    counter = matching_counter(secret, code)
    if counter is None:
        raise store.StoreError("invalid_totp")
    codes = [secrets.token_hex(8) for _ in range(10)]
    conn.execute(text("UPDATE local_credentials SET totp_secret=totp_pending,totp_pending='',last_counter=:counter,recovery_json=:codes WHERE user_id=:id"),
                 {"id": user_id, "counter": counter, "codes": json.dumps([digest(c) for c in codes])})
    return codes


@locked
def finish_totp(user_id: str, code: str) -> list[str]:
    local_user(user_id)
    with engine().begin() as conn:
        return _enrol(conn, user_id, code)


def accept_invite(token: str, password: str, code: str) -> tuple[dict, list[str]]:
    user = invitation(token)
    password_hash = hash_password(password)
    with engine().begin() as conn:
        claimed = conn.execute(text("UPDATE local_invites SET consumed=1 WHERE token_hash=:hash AND consumed=0 AND expires>:now"),
                               {"hash": digest(token), "now": int(time.time())})
        if claimed.rowcount != 1:
            raise store.StoreError("invalid_or_expired_invite")
        user = dict(conn.execute(text("SELECT * FROM users WHERE id=:id"), {"id": user["id"]}).mappings().one())
        if user["status"] != "active":
            raise store.StoreError("user_disabled")
        codes = _enrol(conn, user["id"], code) if code or required(user) else []
        conn.execute(text("UPDATE local_credentials SET password_hash=:hash WHERE user_id=:id"), {"hash": password_hash, "id": user["id"]})
    return user, codes


def verify_factor(user_id: str, code: str) -> bool:
    cred = credentials(user_id)
    if not cred or not cred["totp_secret"]:
        return False
    secret = crypt().decrypt(cred["totp_secret"].encode()).decode()
    counter = matching_counter(secret, code)
    with engine().begin() as conn:
        if counter is not None:
            result = conn.execute(text("UPDATE local_credentials SET last_counter=:counter WHERE user_id=:id AND last_counter<:counter AND totp_secret=:secret"), {"counter": counter, "id": user_id, "secret": cred["totp_secret"]})
            return result.rowcount == 1
        previous = cred["recovery_json"]
        codes = json.loads(previous)
        hashed = digest(code)
        if hashed not in codes:
            return False
        codes.remove(hashed)
        result = conn.execute(text("UPDATE local_credentials SET recovery_json=:codes WHERE user_id=:id AND recovery_json=:previous AND totp_secret=:secret"),
                              {"codes": json.dumps(codes), "previous": previous, "id": user_id, "secret": cred["totp_secret"]})
        return result.rowcount == 1


def authenticate(username: str, password: str, code: str) -> dict | None:
    user = store.find_user("local", "u:" + unicodedata.normalize("NFC", username.strip()).casefold())
    cred = credentials(user["id"]) if user else None
    if not check_password(password, (cred or {}).get("password_hash", "")):
        return None
    if user["status"] != "active":
        return None
    if cred["totp_secret"]:
        if not verify_factor(user["id"], code):
            return None
    elif required(user):
        return None
    with engine().begin() as conn:
        conn.execute(text("UPDATE users SET last_login_at=:stamp WHERE id=:id"), {"stamp": store.iso(store.now()), "id": user["id"]})
    return user
