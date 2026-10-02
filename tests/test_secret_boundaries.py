"""Management and audit views do not disclose bearer credentials."""
import hashlib

import config_links as links
import devices
import main
from auth import store
from device_support import admin_session


def test_vless_handles_manage_credentials_without_listing_them(client, xray):
    headers = admin_session(client)
    issued = client.post("/api/xray/clients", json={"name": "Laptop"}, headers=headers)
    assert issued.status_code == 201
    secret = issued.json()["id"]
    listing = client.get("/api/xray/clients")
    assert secret not in listing.text
    handle = listing.json()[0]["id"]
    assert handle and handle != secret
    assert main._xray_reference(handle) == secret
    assert main._xray_reference(secret) == secret
    renamed = client.put("/api/xray/clients/"+handle, json={"name": "Renamed"}, headers=headers)
    assert renamed.status_code == 200 and secret not in renamed.text
    paused = client.post("/api/xray/clients/"+handle+"/toggle", headers=headers)
    assert paused.status_code == 200 and secret not in paused.text
    # Legacy credential inputs still work and their path is redacted from audit.
    deleted = client.delete("/api/xray/clients/"+secret, headers=headers)
    assert deleted.status_code == 200
    rows = store.list_audit()
    assert secret not in str(rows)
    assert any(row["target"] == "/api/xray/clients/{client_id}" for row in rows)


def test_config_link_handle_can_revoke_without_revealing_claim_code(client, wg):
    headers = admin_session(client)
    peer = wg.create_peer("Laptop")
    devices.adopt_unmanaged("test")
    issued = client.post("/api/config-links", json={"peer_public_key": peer["public_key"]}, headers=headers)
    assert issued.status_code == 201
    code = issued.json()["code"]
    listing = client.get("/api/config-links")
    assert code not in listing.text
    handle = hashlib.sha256(code.encode()).hexdigest()
    assert listing.json()[0]["code"] == handle
    assert links.resolve_handle(handle) == code
    revoked = client.delete("/api/config-links/"+handle, headers=headers)
    assert revoked.status_code == 200 and code not in revoked.text
    assert links.get_link(code)["state"] == "revoked"
