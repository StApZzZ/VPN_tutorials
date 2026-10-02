"""Named API tokens: the network allow-list and the read-only scopes."""
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import config
from auth import tokens
from auth.deps import Principal, require_metrics
from device_support import admin_session

# /metrics itself belongs to main.py; the dependency is tested on its own here.
probe = FastAPI()


@probe.get("/probe")
def read_probe(principal: Principal = Depends(require_metrics)):
    return {"role": principal.role}


@probe.post("/probe")
def write_probe(principal: Principal = Depends(require_metrics)):
    return {"role": principal.role}


def bearer(raw):
    return {"Authorization": f"Bearer {raw}"}


def test_named_tokens_honour_the_network_allow_list(client, monkeypatch):
    raw, _ = tokens.create("ci", "admin", "test")
    monkeypatch.setattr(config, "AUTH_LOCAL_ALLOWED_CIDRS", ("10.0.0.0/8",))
    assert client.get("/api/peers", headers=bearer(raw)).status_code == 401  # the test client is not in 10/8
    monkeypatch.setattr(config, "AUTH_LOCAL_ALLOWED_CIDRS", ())
    assert client.get("/api/peers", headers=bearer(raw)).status_code == 200


@pytest.mark.parametrize("scope", ["metrics", "auditor"])
def test_scoped_tokens_pass_no_role_check(client, scope):
    raw, row = tokens.create(scope, scope, "test")
    assert row["role"] == scope
    for path in ("/api/auth/me", "/api/peers", "/api/devices", "/api/auth/users", "/api/auth/tokens"):
        assert client.get(path, headers=bearer(raw)).status_code == 403, path


def test_metrics_scope_reads_metrics_only(client):
    probe_client = TestClient(probe)
    metrics, _ = tokens.create("prometheus", "metrics", "test")
    admin, _ = tokens.create("root", "admin", "test")
    operator, _ = tokens.create("ci", "operator", "test")
    auditor, _ = tokens.create("siem", "auditor", "test")
    assert probe_client.get("/probe", headers=bearer(metrics)).json() == {"role": "metrics"}
    assert probe_client.post("/probe", headers=bearer(metrics)).status_code == 403  # read-only
    assert probe_client.get("/probe", headers=bearer(admin)).status_code == 200
    assert probe_client.get("/probe", headers=bearer(operator)).status_code == 403
    assert probe_client.get("/probe", headers=bearer(auditor)).status_code == 403
    assert probe_client.get("/probe").status_code == 401


def test_auditor_scope_reads_and_exports_the_audit_log(client):
    raw, _ = tokens.create("siem", "auditor", "test")
    assert client.get("/api/auth/audit", headers=bearer(raw)).status_code == 200
    assert client.get("/api/auth/audit/export", headers=bearer(raw)).status_code == 200


def test_scopes_are_offered_by_the_token_api(client):
    h = admin_session(client)
    created = client.post("/api/auth/tokens", json={"name": "prometheus", "role": "metrics"}, headers=h)
    assert created.status_code == 201 and created.json()["role"] == "metrics"
    assert client.post("/api/auth/tokens", json={"name": "x", "role": "superuser"}, headers=h).status_code == 400
