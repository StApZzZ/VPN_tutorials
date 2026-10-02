"""Tests for reality_keycheck — detects a panel that hands out a stale REALITY
public key (or a short ID / server name the server does not accept).

The vector below was produced by `xray x25519` so the pure-Python derivation
stays byte-for-byte compatible with the tool. The keypair is a throwaway
generated for this test.
"""

import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "panel"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import reality_keycheck as rk  # noqa: E402

# Authoritative vector from `xray x25519 -i <PRIV>` (throwaway key):
VECTOR_PRIV = "QbRGc6jSp-hznXk4il9PYIc-Hacei4BjRYHRj6hRCCc"
VECTOR_PUB = "p-qt05yyhTjrGZXdHAjKgBS37JROhRD_aNdg6ZUZ2lE"


def _unrelated_public_key() -> str:
    raw = X25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return rk._b64url_nopad(raw)


def _server_config(**reality):
    settings = {"privateKey": VECTOR_PRIV, "shortIds": ["0123456789abcdef", ""], "serverNames": ["www.example.com"]}
    settings.update(reality)
    return {
        "inbounds": [
            {"tag": "metrics", "port": 11111, "protocol": "http"},
            # Behind the shared TCP 443 the inbound listens on loopback.
            {"tag": "vless-in", "listen": "127.0.0.1", "port": 8443, "protocol": "vless",
             "streamSettings": {"realitySettings": settings}},
        ]
    }


class DerivePublicKeyTests(unittest.TestCase):
    def test_matches_xray_vector(self):
        self.assertEqual(rk.derive_public_key(VECTOR_PRIV), VECTOR_PUB)

    def test_accepts_standard_base64_and_padding(self):
        # same 32 bytes, re-encoded as standard base64 with padding
        raw = rk._b64url_decode(VECTOR_PRIV)
        std = base64.b64encode(raw).decode()
        self.assertEqual(rk.derive_public_key(std), VECTOR_PUB)

    def test_rejects_wrong_length(self):
        with self.assertRaises(ValueError):
            rk.derive_public_key(base64.urlsafe_b64encode(b"too-short").decode())


class CompareTests(unittest.TestCase):
    def test_match_is_ok(self):
        result = rk.compare(VECTOR_PRIV, VECTOR_PUB)
        self.assertTrue(result.ok)
        self.assertEqual(result.expected_public_key, VECTOR_PUB)

    def test_stale_key_is_detected(self):
        stale = _unrelated_public_key()  # any key that does not match VECTOR_PRIV
        result = rk.compare(VECTOR_PRIV, stale)
        self.assertFalse(result.ok)
        self.assertIn("STALE", result.detail.upper())
        self.assertNotIn("bot", result.detail)

    def test_empty_panel_key_is_not_ok(self):
        result = rk.compare(VECTOR_PRIV, "")
        self.assertFalse(result.ok)
        self.assertIn("empty", result.detail.lower())

    def test_whitespace_is_tolerated(self):
        self.assertTrue(rk.compare(VECTOR_PRIV, f"  {VECTOR_PUB}\n").ok)


class ServerConfigTests(unittest.TestCase):
    def test_everything_a_link_carries_is_checked(self):
        cfg = _server_config()
        self.assertTrue(rk.check_server_config(cfg, VECTOR_PUB, "0123456789abcdef", "www.example.com").ok)
        self.assertTrue(rk.check_server_config(cfg, VECTOR_PUB, "", "www.example.com").ok)  # "" is allowed
        wrong_sid = rk.check_server_config(cfg, VECTOR_PUB, "deadbeef", "www.example.com")
        self.assertFalse(wrong_sid.ok)
        self.assertIn("shortIds", wrong_sid.detail)
        wrong_name = rk.check_server_config(cfg, VECTOR_PUB, "0123456789abcdef", "www.example.org")
        self.assertFalse(wrong_name.ok)
        self.assertIn("serverNames", wrong_name.detail)
        stale = rk.check_server_config(cfg, _unrelated_public_key(), "deadbeef")
        self.assertFalse(stale.ok)
        self.assertIn("STALE", stale.detail)
        self.assertIn("shortIds", stale.detail)

    def test_inbound_is_found_by_tag_then_port(self):
        other = X25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        cfg = _server_config()
        cfg["inbounds"].insert(0, {"tag": "other", "port": 443, "streamSettings": {
            "realitySettings": {"privateKey": rk._b64url_nopad(other)}}})
        self.assertEqual(rk.reality_settings(cfg, "vless-in")["privateKey"], VECTOR_PRIV)
        self.assertNotEqual(rk.reality_settings(cfg, port=443)["privateKey"], VECTOR_PRIV)
        with self.assertRaises(ValueError):
            rk.reality_settings({"inbounds": [{"tag": "vless-in"}]}, "vless-in")


class ParsingAndCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _write(self, name: str, text: str) -> str:
        path = Path(self.tmp.name) / name
        path.write_text(text, encoding="utf-8")
        return str(path)

    def test_read_server_private_key_from_config(self):
        path = self._write("config.json", json.dumps(_server_config()))
        self.assertEqual(rk.read_server_private_key(path), VECTOR_PRIV)

    def test_read_panel_reality_params_from_env(self):
        env = (
            "# panel env\n"
            "PANEL_SECRET_TOKEN=secret-should-be-ignored\n"
            f'XRAY_CLIENT_REALITY_PUBLIC_KEY="{VECTOR_PUB}"\n'
            "XRAY_CLIENT_REALITY_SHORT_ID=0123456789abcdef\n"
            "XRAY_CLIENT_REALITY_SERVER_NAME=www.example.com\n"
            "XRAY_CLIENT_SERVER=203.0.113.10\n"
        )
        params = rk.read_panel_reality_params(self._write("panel.env", env))
        self.assertEqual(params["public_key"], VECTOR_PUB)
        self.assertEqual(params["short_id"], "0123456789abcdef")
        self.assertEqual(params["server_name"], "www.example.com")
        self.assertEqual(params["server"], "203.0.113.10")
        self.assertNotIn("secret-should-be-ignored", params.values())

    def test_compare_exit_codes(self):
        server = self._write("config.json", json.dumps(_server_config()))
        good = self._write("good.env", f"XRAY_CLIENT_REALITY_PUBLIC_KEY={VECTOR_PUB}\n"
                                       "XRAY_CLIENT_REALITY_SHORT_ID=0123456789abcdef\n"
                                       "XRAY_CLIENT_REALITY_SERVER_NAME=www.example.com\n")
        bad_sid = self._write("bad.env", f"XRAY_CLIENT_REALITY_PUBLIC_KEY={VECTOR_PUB}\n"
                                         "XRAY_CLIENT_REALITY_SHORT_ID=deadbeef\n")
        self.assertEqual(rk._main(["compare", "--xray-config", server, "--env", good]), 0)
        self.assertEqual(rk._main(["compare", "--xray-config", server, "--env", bad_sid]), 2)
        self.assertEqual(rk._main(["compare", "--server-public-key", VECTOR_PUB, "--env", bad_sid]), 0)
        self.assertEqual(rk._main(["compare", "--xray-config", str(Path(self.tmp.name) / "missing"),
                                   "--env", good]), 1)


if __name__ == "__main__":
    unittest.main()
