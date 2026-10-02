"""The standard-library REALITY helper agrees with a separate X25519 implementation."""
import base64
import importlib.machinery
import importlib.util
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
import pytest

path = Path(__file__).resolve().parents[1]/"deploy/ansible/roles/xray/files/corpvpn-xray"
loader = importlib.machinery.SourceFileLoader("xray_deploy_helper",str(path))
spec = importlib.util.spec_from_loader(loader.name,loader)
helper = importlib.util.module_from_spec(spec)
loader.exec_module(helper)


@pytest.mark.parametrize("raw", [bytes(range(32)), b"\x00"*32, b"\xff"*32, secrets.token_bytes(32)])
def test_public_key_matches_cryptography(raw):
    private = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    expected = X25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    assert helper.public_key(private) == base64.urlsafe_b64encode(expected).decode().rstrip("=")


def test_bad_keys_are_rejected():
    with pytest.raises(helper.ToolError):helper.public_key("short")
