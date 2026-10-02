"""
SQLite engine factory (Phase 1).

Data-access modules resolve their engine LAZILY via get_engine(path, ddl):
the path is read from config at call time and engines are cached per path.
This keeps one engine per DB in production while letting tests repoint
config.*_DB_PATH to a temp file without import-order tricks or module
reloads.  WAL mode is enabled for better write concurrency.

Usage:
    import db
    def _engine() -> Engine:
        return db.get_engine(config.VLESS_DB_PATH, _DDL)
"""

from __future__ import annotations

import threading
from pathlib import Path

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine

_engines: dict[str, Engine] = {}
_lock = threading.Lock()


def make_engine(db_path: str) -> Engine:
    # A value containing "://" is a full SQLAlchemy URL (e.g. a shared
    # PostgreSQL: postgresql+psycopg://...). Anything else is a filesystem path →
    # local SQLite. This lets one logical store move to Postgres via its
    # *_DB_PATH env var while the others stay on SQLite, with no call-site
    # changes (xray_clients/routing_overrides/... all keep get_engine).
    if "://" in str(db_path):
        # pool_pre_ping survives the network/Postgres dropping an idle connection;
        # SQLite pragmas below are intentionally skipped for non-SQLite backends.
        return create_engine(db_path, pool_pre_ping=True)

    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    url = f"sqlite:///{db_path}"
    engine = create_engine(url, connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _set_wal(connection, _):
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")

    return engine


def get_engine(db_path: str, ddl: str | None = None) -> Engine:
    """Cached engine for db_path; runs ddl once when the engine is first built."""
    key = str(db_path)
    engine = _engines.get(key)
    if engine is not None:
        return engine
    with _lock:
        engine = _engines.get(key)
        if engine is not None:
            return engine
        engine = make_engine(key)
        if ddl:
            with engine.connect() as conn:
                conn.execute(text(ddl))
                conn.commit()
        _engines[key] = engine
        return engine


def dispose_all_engines() -> None:
    """Dispose every cached engine and clear the cache.

    Closes pooled connections and releases the underlying SQLite file handles.
    Production rarely needs this, but tests that repoint config.*_DB_PATH at a
    fresh temp DB call it in tearDown so the temp file can be deleted: Windows
    refuses to unlink a file an open handle still holds, whereas POSIX tolerates
    it (which is why this never surfaced on the Linux deploy target). Disposing
    also gives each test a clean engine cache regardless of OS.
    """
    with _lock:
        for engine in _engines.values():
            engine.dispose()
        _engines.clear()
