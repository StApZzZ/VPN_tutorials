"""Identity store: schema migrations and user upsert semantics."""
from sqlalchemy import create_engine, text

import config
from auth import store

# users as the first 2.0 pre-release created it (no access profile, no disable source)
OLD_USERS = (
    "CREATE TABLE users (id TEXT PRIMARY KEY, provider TEXT NOT NULL, external_id TEXT NOT NULL, "
    "username TEXT NOT NULL, email TEXT NOT NULL DEFAULT '', display_name TEXT NOT NULL DEFAULT '', "
    "role TEXT NOT NULL, status TEXT NOT NULL, groups_json TEXT NOT NULL DEFAULT '[]', "
    "directory_dn TEXT NOT NULL DEFAULT '', disabled_reason TEXT NOT NULL DEFAULT '', "
    "created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_login_at TEXT NOT NULL DEFAULT '', "
    "UNIQUE (provider, external_id))"
)


def _user(**kw):
    return store.upsert_user(**{"provider": "ldap", "external_id": "x", "username": "x", "email": "",
                                "display_name": "", "role": "user", "groups": [], **kw})


def test_disabled_users_of_an_old_database_get_a_source(tmp_path, monkeypatch):
    path = tmp_path / "old.db"
    engine = create_engine(f"sqlite:///{path}")
    with engine.begin() as conn:
        conn.execute(text(OLD_USERS))
        for uid, status, reason in (
            ("alice", "disabled", "disabled by root"),
            ("bob", "disabled", "not found in directory"),
            ("carol", "disabled", "no sign-in for 30 days"),
            ("dave", "disabled", "left the company"),
            ("erin", "active", ""),
        ):
            conn.execute(text("INSERT INTO users VALUES (:u, 'ldap', :u, :u, '', '', 'user', :s, '[]', '', :r, "
                              "'2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z', '')"), {"u": uid, "s": status, "r": reason})
    engine.dispose()
    monkeypatch.setattr(config, "CORPVPN_DB_PATH", str(path))
    store.reset_schema_cache()
    rows = {u["username"]: (u["disabled_source"], u["disabled_reason"]) for u in store.list_users()}
    assert rows == {
        "alice": ("admin", "admin"),
        "bob": ("directory", "directory_missing"),
        "carol": ("attestation", "attestation_expired"),
        "dave": ("admin", "left the company"),  # unknown provenance stays sticky
        "erin": ("", ""),
    }


def test_upsert_never_changes_the_status():
    user = _user()
    store.set_user_status(user["id"], "disabled", "admin", source="admin")
    again = _user(role="operator", groups=["G"])
    assert again["status"] == "disabled" and again["disabled_source"] == "admin"
    assert again["role"] == "operator" and again["groups"] == ["G"]
    store.set_user_status(user["id"], "active")
    assert store.get_user(user["id"])["disabled_source"] == ""


def test_pending_oidc_sign_ins_are_capped_per_ip():
    for n in range(store.OIDC_STATES_PER_IP + 5):
        store.put_oidc_state(f"s{n:02d}", "nonce", "verifier", binding_hash="b", ip="198.51.100.7")
    store.put_oidc_state("other", "nonce", "verifier", binding_hash="b", ip="198.51.100.8")
    with store._engine().connect() as conn:
        per_ip = dict(conn.execute(text("SELECT ip, COUNT(*) FROM oidc_states GROUP BY ip")).all())
    assert per_ip == {"198.51.100.7": store.OIDC_STATES_PER_IP, "198.51.100.8": 1}
    assert store.pop_oidc_state("s24")["binding_hash"] == "b"  # the newest survive


def test_upsert_tolerates_a_concurrent_first_sign_in(monkeypatch):
    first = _user()
    real = store.find_user
    calls = []

    def racing(provider, external_id):
        # the first lookup misses the row another worker is inserting right now
        calls.append(provider)
        return None if len(calls) == 1 else real(provider, external_id)

    monkeypatch.setattr(store, "find_user", racing)
    again = _user(username="x2")
    assert again["id"] == first["id"] and again["username"] == "x2"
    assert len(store.list_users()) == 1
