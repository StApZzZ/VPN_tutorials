"""Tests for the one-shot AmneziaWG config links (config_links.py + /awg/*).

Same tmp-DB / ASGITransport setup as the other panel API tests.

Two properties get most of the attention here because the whole design exists for
them:
  * GET /awg/<code> must NOT consume. Chat apps fetch a link preview with GET,
    so a consuming GET would burn every link before its owner ever tapped it.
  * consume_link() must be a single conditional UPDATE. Two concurrent claims may
    never both be served, and a read-then-write would double-deliver.
"""

import asyncio
import sys
import tempfile
import threading
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "panel"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

if "dotenv" not in sys.modules:
    dotenv_stub = types.ModuleType("dotenv")
    dotenv_stub.load_dotenv = lambda *args, **kwargs: None
    sys.modules["dotenv"] = dotenv_stub

try:
    import httpx
    import config
    import config_links as cl
    import db
    import main
    from sqlalchemy import text as _sql

    SERVICE_DEPS_AVAILABLE = True
except ModuleNotFoundError:
    httpx = None
    config = None
    cl = None
    db = None
    main = None
    SERVICE_DEPS_AVAILABLE = False


PEER_KEY = "wJ8pQ0Zr7t1vX3sK5nB2mL4hG6dF8cA0eR2yU4iO6pQ="  # gitleaks:allow -- synthetic test fixture
SAMPLE_CONF = "[Interface]\nPrivateKey = fake\nAddress = 10.66.4.7/32\n\n[Peer]\nEndpoint = 203.0.113.7:51821\n"


def _expire_in_db(code: str) -> None:
    """Backdate a link's expires_at without touching its status."""
    with cl._engine().begin() as conn:
        conn.execute(
            _sql("UPDATE config_links SET expires_at = :e WHERE code = :c"),
            {"e": "2000-01-01T00:00:00Z", "c": code},
        )


@unittest.skipUnless(SERVICE_DEPS_AVAILABLE, "panel dependencies are not installed")
class ConfigLinkStoreTests(unittest.TestCase):
    def setUp(self):
        # Engines resolve config.CONFIG_LINKS_DB_PATH lazily — repoint per test.
        self.tmpdir = tempfile.TemporaryDirectory()
        self.original_db = config.CONFIG_LINKS_DB_PATH
        config.CONFIG_LINKS_DB_PATH = str(Path(self.tmpdir.name) / "config_links.db")

    def tearDown(self):
        config.CONFIG_LINKS_DB_PATH = self.original_db
        db.dispose_all_engines()
        self.tmpdir.cleanup()

    def test_create_get_happy_path(self):
        link = cl.create_link(
            peer_public_key=PEER_KEY, user_id="3f2a9c01", label="Вася"
        )
        # secrets.token_urlsafe(24) — ~192 bits, not the 10-char typable alphabet.
        self.assertGreaterEqual(len(link["code"]), 30)
        self.assertEqual(link["status"], cl.STATUS_ACTIVE)
        self.assertEqual(link["state"], cl.STATUS_ACTIVE)

        got = cl.get_link(link["code"])
        self.assertEqual(got["peer_public_key"], PEER_KEY)
        self.assertEqual(got["user_id"], "3f2a9c01")      # user ids are hex strings
        self.assertEqual(got["label"], "Вася")
        self.assertEqual(got["protocol"], cl.DEFAULT_PROTOCOL)
        self.assertEqual(got["consumed_at"], "")

    def test_codes_are_case_sensitive(self):
        # Unlike a web-invite code these are clicked, never typed, and
        # token_urlsafe is case-sensitive — folding case would shrink the space.
        link = cl.create_link(peer_public_key=PEER_KEY, code="AbC-dEf_123")
        self.assertIsNotNone(cl.get_link("AbC-dEf_123"))
        self.assertIsNone(cl.get_link("abc-def_123"))
        self.assertEqual(link["code"], "AbC-dEf_123")

    def test_default_ttl_is_seven_days(self):
        link = cl.create_link(peer_public_key=PEER_KEY)
        expires_at = cl._parse(link["expires_at"])
        expected = datetime.now(timezone.utc) + timedelta(days=config.CONFIG_LINK_TTL_DAYS)
        self.assertLess(abs((expires_at - expected).total_seconds()), 120)

    def test_ttl_days_override(self):
        link = cl.create_link(peer_public_key=PEER_KEY, ttl_days=30)
        expires_at = cl._parse(link["expires_at"])
        self.assertGreater(expires_at, datetime.now(timezone.utc) + timedelta(days=29))

    def test_ttl_is_capped_at_thirty_days(self):
        link = cl.create_link(peer_public_key=PEER_KEY, ttl_days=365)
        expires_at = cl._parse(link["expires_at"])
        self.assertLess(expires_at, datetime.now(timezone.utc) + timedelta(days=30, minutes=5))

    def test_revoking_a_peers_links_spares_other_peers(self):
        mine = cl.create_link(peer_public_key=PEER_KEY)
        used = cl.create_link(peer_public_key=PEER_KEY)
        cl.consume_link(used["code"])
        other = cl.create_link(peer_public_key="b3RoZXIta2V5")
        self.assertEqual(cl.revoke_links_for_peer(PEER_KEY), 1)
        self.assertEqual(cl.get_link(mine["code"])["state"], cl.STATUS_REVOKED)
        self.assertEqual(cl.get_link(used["code"])["state"], cl.STATUS_CONSUMED)   # history kept
        self.assertEqual(cl.get_link(other["code"])["state"], cl.STATUS_ACTIVE)

    def test_get_link_never_consumes(self):
        link = cl.create_link(peer_public_key=PEER_KEY)
        for _ in range(5):
            self.assertEqual(cl.get_link(link["code"])["state"], cl.STATUS_ACTIVE)
        self.assertEqual(cl.consume_link(link["code"])["state"], cl.STATUS_CONSUMED)

    def test_consume_then_second_consume_fails(self):
        link = cl.create_link(peer_public_key=PEER_KEY)
        consumed = cl.consume_link(link["code"])
        self.assertEqual(consumed["status"], cl.STATUS_CONSUMED)
        self.assertTrue(consumed["consumed_at"])
        with self.assertRaises(cl.ConfigLinkAlreadyUsed):
            cl.consume_link(link["code"])

    def test_concurrent_consume_has_exactly_one_winner(self):
        """The property the conditional UPDATE exists for — assert it, don't trust it."""
        link = cl.create_link(peer_public_key=PEER_KEY)
        workers = 8
        barrier = threading.Barrier(workers)
        wins: list[dict] = []
        losses: list[Exception] = []
        lock = threading.Lock()

        def claim():
            barrier.wait()
            try:
                result = cl.consume_link(link["code"])
            except Exception as exc:  # noqa: BLE001 — recorded and asserted below
                with lock:
                    losses.append(exc)
            else:
                with lock:
                    wins.append(result)

        threads = [threading.Thread(target=claim) for _ in range(workers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)

        self.assertEqual(len(wins), 1, f"expected exactly one winner, got {len(wins)}")
        self.assertEqual(len(losses), workers - 1)
        for exc in losses:
            self.assertIsInstance(exc, cl.ConfigLinkAlreadyUsed)

    def test_expired_link_is_rejected(self):
        link = cl.create_link(peer_public_key=PEER_KEY)
        _expire_in_db(link["code"])
        self.assertEqual(cl.get_link(link["code"])["state"], cl.STATE_EXPIRED)
        with self.assertRaises(cl.ConfigLinkExpired):
            cl.consume_link(link["code"])
        # …and it stays unconsumed rather than being silently burned.
        self.assertEqual(cl.get_link(link["code"])["status"], cl.STATUS_ACTIVE)

    def test_unknown_code_raises_not_found(self):
        with self.assertRaises(cl.ConfigLinkNotFound):
            cl.consume_link("definitely-not-a-real-code")
        self.assertIsNone(cl.get_link("definitely-not-a-real-code"))
        self.assertIsNone(cl.get_link(""))
        self.assertIsNone(cl.get_link(None))

    def test_revoked_link_cannot_be_consumed(self):
        link = cl.create_link(peer_public_key=PEER_KEY)
        self.assertEqual(cl.revoke_link(link["code"])["state"], cl.STATUS_REVOKED)
        with self.assertRaises(cl.ConfigLinkRevoked):
            cl.consume_link(link["code"])

    def test_create_requires_a_peer_public_key(self):
        # A link is a pure read of an EXISTING peer; there is no "create me one".
        with self.assertRaises(cl.ConfigLinkError):
            cl.create_link(peer_public_key="")

    def test_explicit_code_collision_raises(self):
        cl.create_link(peer_public_key=PEER_KEY, code="fixed-code-1")
        with self.assertRaises(cl.ConfigLinkError):
            cl.create_link(peer_public_key=PEER_KEY, code="fixed-code-1")

    def test_list_and_purge(self):
        keep = cl.create_link(peer_public_key=PEER_KEY, user_id="a1")
        stale = cl.create_link(peer_public_key=PEER_KEY, user_id="b2")
        self.assertEqual(len(cl.list_links()), 2)
        self.assertEqual(len(cl.list_links(user_id="b2")), 1)

        _expire_in_db(stale["code"])
        self.assertEqual(cl.purge_expired(), 1)
        self.assertIsNone(cl.get_link(stale["code"]))
        self.assertIsNotNone(cl.get_link(keep["code"]))


def _configure_panel(tmpdir: str) -> dict:
    """Point config at a temp sandbox for the public /awg/ routes."""
    originals = {
        name: getattr(config, name)
        for name in (
            "CONFIG_LINKS_DB_PATH",
            "CONFIG_LINK_PUBLIC_BASE_URL",
            "PANEL_SECRET_TOKEN",
            "VLESS_DB_PATH",
            "ROUTING_DB_PATH",
            "AWG_DB_PATH",
            "ROUTING_OVERRIDES_PATH",
            "XRAY_CLIENTS_PATH",
        )
    }
    base = Path(tmpdir)
    config.CONFIG_LINKS_DB_PATH = str(base / "config_links.db")
    config.CONFIG_LINK_PUBLIC_BASE_URL = "https://invite.example.org"
    config.PANEL_SECRET_TOKEN = "test-token"
    config.VLESS_DB_PATH = str(base / "vless.db")
    config.ROUTING_DB_PATH = str(base / "routing_rules.db")
    config.AWG_DB_PATH = str(base / "awg.db")
    config.ROUTING_OVERRIDES_PATH = str(base / "routing_overrides.json")
    config.XRAY_CLIENTS_PATH = str(base / "xray_clients.json")
    return originals


@unittest.skipUnless(SERVICE_DEPS_AVAILABLE, "panel dependencies are not installed")
class ConfigLinkPublicRouteTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.originals = _configure_panel(self.tmpdir.name)
        # The routes must only ever READ the peer — every mutating vpn_manager
        # entry point is stubbed so a stray call shows up as a failed assertion
        # rather than as a rotated key.
        self.conf_patcher = patch.object(main.vm, "get_client_conf", return_value=SAMPLE_CONF)
        self.get_client_conf = self.conf_patcher.start()
        self.mutators = {}
        self.mutator_patchers = []
        for name in ("create_peer", "delete_peer", "rename_peer", "deactivate_peer", "activate_peer"):
            patcher = patch.object(main.vm, name)
            self.mutators[name] = patcher.start()
            self.mutator_patchers.append(patcher)
        self.http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app),
            base_url="http://invite.test",
        )
        self.auth = {"Authorization": "Bearer test-token"}

    async def asyncTearDown(self):
        await self.http.aclose()
        self.conf_patcher.stop()
        for patcher in self.mutator_patchers:
            patcher.stop()
        for name, value in self.originals.items():
            setattr(config, name, value)
        db.dispose_all_engines()
        self.tmpdir.cleanup()

    def _assert_no_peer_mutation(self):
        for name, mock in self.mutators.items():
            self.assertFalse(mock.called, f"{name} must never be called by a config link")

    def _link(self, **kwargs) -> dict:
        kwargs.setdefault("peer_public_key", PEER_KEY)
        kwargs.setdefault("label", "Вася")
        return cl.create_link(**kwargs)

    async def test_get_landing_is_idempotent_and_never_consumes(self):
        """The Chat application-crawler property: previews must not burn the link."""
        link = self._link()
        for _ in range(3):
            resp = await self.http.get(f"/awg/{link['code']}")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(cl.get_link(link["code"])["state"], cl.STATUS_ACTIVE)

        # …and the claim that follows the preview still works.
        claim = await self.http.post(f"/awg/{link['code']}/claim")
        self.assertEqual(claim.status_code, 200)
        self._assert_no_peer_mutation()

    async def test_claim_consumes_once_and_renders_the_config(self):
        link = self._link()
        resp = await self.http.post(f"/awg/{link['code']}/claim")
        self.assertEqual(resp.status_code, 200)
        # Raw .conf text, an inline QR and a self-contained download — no second
        # request, which would race the consumed flag.
        self.assertIn("[Interface]", resp.text)
        self.assertIn("203.0.113.7:51821", resp.text)
        self.assertIn("data:image/png;base64,", resp.text)
        self.assertIn("data:application/octet-stream;base64,", resp.text)
        self.assertEqual(cl.get_link(link["code"])["state"], cl.STATUS_CONSUMED)

        second = await self.http.post(f"/awg/{link['code']}/claim")
        self.assertEqual(second.status_code, 410)
        self.assertNotIn("[Interface]", second.text)
        self._assert_no_peer_mutation()

    async def test_get_after_claim_reports_consumed(self):
        link = self._link()
        await self.http.post(f"/awg/{link['code']}/claim")
        resp = await self.http.get(f"/awg/{link['code']}")
        self.assertEqual(resp.status_code, 410)
        self.assertIn("already been used", resp.text)
        self.assertNotIn("[Interface]", resp.text)

    async def test_concurrent_claims_serve_exactly_one(self):
        link = self._link()
        first, second = await asyncio.gather(
            self.http.post(f"/awg/{link['code']}/claim"),
            self.http.post(f"/awg/{link['code']}/claim"),
        )
        statuses = sorted([first.status_code, second.status_code])
        self.assertEqual(statuses, [200, 410])
        served = [r for r in (first, second) if "[Interface]" in r.text]
        self.assertEqual(len(served), 1)
        self.assertEqual(cl.get_link(link["code"])["state"], cl.STATUS_CONSUMED)

    async def test_expired_link_cannot_be_claimed(self):
        link = self._link()
        _expire_in_db(link["code"])
        landing = await self.http.get(f"/awg/{link['code']}")
        self.assertEqual(landing.status_code, 404)
        claim = await self.http.post(f"/awg/{link['code']}/claim")
        self.assertEqual(claim.status_code, 404)
        self.assertNotIn("[Interface]", claim.text)

    async def test_unknown_and_expired_render_the_same_page(self):
        """No enumeration oracle: a scanner must not learn whether a code existed."""
        link = self._link()
        _expire_in_db(link["code"])
        expired = await self.http.get(f"/awg/{link['code']}")
        unknown = await self.http.get("/awg/PkWq3Nv8Tz1Lm5Rb7Xc0Yd2Hf4Jg6Ks")
        revoked_link = self._link()
        cl.revoke_link(revoked_link["code"])
        revoked = await self.http.get(f"/awg/{revoked_link['code']}")

        self.assertEqual(expired.status_code, unknown.status_code, 404)
        self.assertEqual(revoked.status_code, 404)
        self.assertEqual(expired.text, unknown.text)
        self.assertEqual(revoked.text, unknown.text)

    async def test_failed_config_build_does_not_burn_the_single_use(self):
        link = self._link()
        self.get_client_conf.return_value = None
        broken = await self.http.post(f"/awg/{link['code']}/claim")
        self.assertEqual(broken.status_code, 503)
        self.assertEqual(cl.get_link(link["code"])["state"], cl.STATUS_ACTIVE)

        # Same again when the build raises rather than returning None.
        self.get_client_conf.side_effect = RuntimeError("wg down")
        raised = await self.http.post(f"/awg/{link['code']}/claim")
        self.assertEqual(raised.status_code, 503)
        self.assertEqual(cl.get_link(link["code"])["state"], cl.STATUS_ACTIVE)

        # Once the peer is readable again the user's one use is still there.
        self.get_client_conf.side_effect = None
        self.get_client_conf.return_value = SAMPLE_CONF
        ok = await self.http.post(f"/awg/{link['code']}/claim")
        self.assertEqual(ok.status_code, 200)
        self.assertIn("[Interface]", ok.text)
        self._assert_no_peer_mutation()

    async def test_landing_shows_owner_and_expiry(self):
        link = self._link(label="Пётр")
        resp = await self.http.get(f"/awg/{link['code']}")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Пётр", resp.text)
        # The button posts to the claim route rather than linking to it.
        self.assertIn(f"/awg/{link['code']}/claim", resp.text)
        self.assertNotIn("[Interface]", resp.text)


@unittest.skipUnless(SERVICE_DEPS_AVAILABLE, "panel dependencies are not installed")
class ConfigLinkAdminApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.originals = _configure_panel(self.tmpdir.name)
        self.conf_patcher = patch.object(main.vm, "get_client_conf", return_value=SAMPLE_CONF)
        self.conf_patcher.start()
        self.http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app),
            base_url="http://panel.test",
        )
        self.auth = {"Authorization": "Bearer test-token"}

    async def asyncTearDown(self):
        await self.http.aclose()
        self.conf_patcher.stop()
        for name, value in self.originals.items():
            setattr(config, name, value)
        db.dispose_all_engines()
        self.tmpdir.cleanup()

    async def test_create_requires_auth(self):
        resp = await self.http.post("/api/config-links", json={"peer_public_key": PEER_KEY})
        self.assertEqual(resp.status_code, 401)

    async def test_create_returns_public_url_on_the_invite_host(self):
        resp = await self.http.post(
            "/api/config-links",
            headers=self.auth,
            json={"peer_public_key": PEER_KEY, "user_id": "3f2a9c01", "label": "Вася"},
        )
        self.assertEqual(resp.status_code, 201)
        body = resp.json()
        self.assertEqual(
            body["url"], f"https://invite.example.org/awg/{body['code']}"
        )
        self.assertTrue(body["expires_at"].endswith("Z"))

        # The minted code works end to end on the public route.
        landing = await self.http.get(f"/awg/{body['code']}")
        self.assertEqual(landing.status_code, 200)

if __name__ == "__main__":
    unittest.main()
