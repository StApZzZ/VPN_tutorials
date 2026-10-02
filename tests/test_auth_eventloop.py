"""A slow directory or IdP must not stall the panel.

The panel is one uvicorn process with one event loop, so this runs it for real
(on a localhost port) instead of through TestClient, which gives every request
a loop of its own.
"""
import socket
import threading
import time

import httpx
import pytest
import uvicorn

import config
import main
from auth import ldap_auth


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def panel(monkeypatch):
    for name, value in {
        "LDAP_ENABLED": True, "LDAP_URL": "ldaps://dc.corp.example", "LDAP_USER_BASE_DN": "dc=corp,dc=example",
        "OIDC_ENABLED": False, "PANEL_SECRET_TOKEN": "break-glass-token-123", "PANEL_USERNAME": "admin",
    }.items():
        monkeypatch.setattr(config, name, value)
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(main.app, host="127.0.0.1", port=port, log_level="warning",
                                           lifespan="off"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(5)


def test_a_slow_ldap_sign_in_does_not_block_other_requests(panel, monkeypatch):
    entered, release = threading.Event(), threading.Event()

    def slow_directory(username, password):
        entered.set()
        release.wait(10)  # a DC that takes its time (LDAP_TIMEOUT is 10 s)
        raise ldap_auth.AuthFailed("invalid credentials")

    monkeypatch.setattr(ldap_auth, "authenticate", slow_directory)
    pending = threading.Thread(target=lambda: httpx.post(f"{panel}/login", timeout=15,
                                                         data={"username": "ivan", "password": "x"}))
    pending.start()
    try:
        assert entered.wait(5), "the sign-in never reached the directory"
        started = time.monotonic()
        page = httpx.get(f"{panel}/login", timeout=5)
        elapsed = time.monotonic() - started
    finally:
        release.set()
        pending.join(15)
    assert page.status_code == 200
    assert elapsed < 0.5, f"GET /login waited {elapsed:.2f}s behind the pending sign-in"
