import json
import sys
import tempfile
import types
import unittest
import zipfile
from io import BytesIO
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "amnezia-panel-src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

if "dotenv" not in sys.modules:
    dotenv_stub = types.ModuleType("dotenv")
    dotenv_stub.load_dotenv = lambda *args, **kwargs: None
    sys.modules["dotenv"] = dotenv_stub

try:
    import config
    import routing_overrides as ro
    import xray_clients as xc
    import xray_manager as xm
    from models import PeerInfo, PeerStatus, RoutingMatchType, RoutingOverride, RoutingRoute
    SERVICE_DEPS_AVAILABLE = True
except ModuleNotFoundError:
    config = None
    ro = None
    xc = None
    xm = None
    PeerInfo = None
    PeerStatus = None
    RoutingMatchType = None
    RoutingOverride = None
    RoutingRoute = None
    SERVICE_DEPS_AVAILABLE = False

try:
    from fastapi.testclient import TestClient
    import main
except ModuleNotFoundError:
    TestClient = None
    main = None


@unittest.skipUnless(SERVICE_DEPS_AVAILABLE, "panel dependencies are not installed")
class RoutingOverrideServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.original_store = config.ROUTING_OVERRIDES_PATH
        self.original_xray_clients = config.XRAY_CLIENTS_PATH
        config.ROUTING_OVERRIDES_PATH = str(Path(self.tmpdir.name) / "routing_overrides.json")
        config.XRAY_CLIENTS_PATH = str(Path(self.tmpdir.name) / "xray_clients.json")

    def tearDown(self):
        config.ROUTING_OVERRIDES_PATH = self.original_store
        config.XRAY_CLIENTS_PATH = self.original_xray_clients
        self.tmpdir.cleanup()

    def test_normalize_domain_accepts_trimmed_and_lowercases(self):
        self.assertEqual(ro.normalize_domain("  Example.COM. "), "example.com")
        self.assertEqual(ro.normalize_domain("  Пример.РФ. "), "xn--e1afmkfd.xn--p1ai")

    def test_normalize_domain_rejects_invalid_inputs(self):
        invalid_values = [
            "https://example.com",
            "example.com/path",
            "example.com:443",
            "exa mple.com",
            "-example.com",
            "example..com",
        ]

        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(ro.RoutingOverrideValidationError):
                    ro.normalize_domain(value)

    def test_duplicate_detection_uses_match_type_and_normalized_domain(self):
        ro.create_override(
            match_type=RoutingMatchType.EXACT,
            value="YouTube.com",
            route=RoutingRoute.NON_RU,
            comment="first",
        )

        with self.assertRaises(ro.RoutingOverrideConflict):
            ro.create_override(
                match_type=RoutingMatchType.EXACT,
                value="youtube.com.",
                route=RoutingRoute.RU,
                comment="duplicate",
            )

    def test_matches_override_respects_exact_and_suffix_semantics(self):
        exact = RoutingOverride(
            id="exact001",
            match_type=RoutingMatchType.EXACT,
            value="gosuslugi.ru",
            normalized_value="gosuslugi.ru",
            route=RoutingRoute.RU,
            comment="",
            enabled=True,
            created_at="2026-04-20T10:00:00+00:00",
            updated_at="2026-04-20T10:00:00+00:00",
        )
        suffix = exact.model_copy(
            update={
                "id": "suffix001",
                "match_type": RoutingMatchType.SUFFIX,
                "value": "youtube.com",
                "normalized_value": "youtube.com",
                "route": RoutingRoute.NON_RU,
            }
        )

        self.assertTrue(ro.matches_override("gosuslugi.ru", exact))
        self.assertFalse(ro.matches_override("api.gosuslugi.ru", exact))
        self.assertTrue(ro.matches_override("youtube.com", suffix))
        self.assertTrue(ro.matches_override("music.youtube.com", suffix))
        self.assertFalse(ro.matches_override("notyoutube.com", suffix))

    def test_check_domain_reports_matching_manual_override_or_fallback(self):
        ro.create_override(
            match_type=RoutingMatchType.SUFFIX,
            value="example.com",
            route=RoutingRoute.RU,
            comment="route whole zone direct",
        )
        exact_non_ru = ro.create_override(
            match_type=RoutingMatchType.EXACT,
            value="youtube.com",
            route=RoutingRoute.NON_RU,
            comment="route exact host to NL",
        )
        disabled = ro.create_override(
            match_type=RoutingMatchType.EXACT,
            value="disabled.example.net",
            route=RoutingRoute.NON_RU,
            comment="disabled rule must be ignored",
        )
        ro.toggle_override(disabled.id)

        suffix_match = ro.check_domain("api.example.com")
        self.assertTrue(suffix_match.matched)
        self.assertEqual(suffix_match.route, RoutingRoute.RU)
        self.assertEqual(suffix_match.outbound, "direct")
        self.assertEqual(suffix_match.rendered_rule, "domain:example.com -> direct")

        exact_match = ro.check_domain("YouTube.com.")
        self.assertTrue(exact_match.matched)
        self.assertEqual(exact_match.override_id, exact_non_ru.id)
        self.assertEqual(exact_match.match_type, RoutingMatchType.EXACT)
        self.assertEqual(exact_match.outbound, "to-egress")

        ru_zone_match = ro.check_domain("shop.ozon.ru")
        self.assertTrue(ru_zone_match.matched)
        self.assertEqual(ru_zone_match.source, "builtin_ru_zone")
        self.assertEqual(ru_zone_match.route, RoutingRoute.RU)
        self.assertEqual(ru_zone_match.outbound, "direct")
        self.assertEqual(ru_zone_match.rendered_rule, "domain:ru -> direct")

        rf_zone_match = ro.check_domain("пример.рф")
        self.assertTrue(rf_zone_match.matched)
        self.assertEqual(rf_zone_match.source, "builtin_ru_zone")
        self.assertEqual(rf_zone_match.normalized_value, "xn--e1afmkfd.xn--p1ai")
        self.assertEqual(rf_zone_match.rendered_rule, "domain:xn--p1ai -> direct")

        fallback = ro.check_domain("disabled.example.net")
        self.assertFalse(fallback.matched)
        self.assertEqual(fallback.source, "fallback")
        self.assertIn("geoip:ru", fallback.outbound)

    def test_preview_orders_by_route_then_match_type_then_creation_time(self):
        ro.create_override(
            match_type=RoutingMatchType.SUFFIX,
            value="youtube.com",
            route=RoutingRoute.NON_RU,
            comment="suffix non-ru",
        )
        ro.create_override(
            match_type=RoutingMatchType.SUFFIX,
            value="gosuslugi.ru",
            route=RoutingRoute.RU,
            comment="suffix ru",
        )
        ro.create_override(
            match_type=RoutingMatchType.EXACT,
            value="video.youtube.com",
            route=RoutingRoute.NON_RU,
            comment="exact non-ru",
        )
        ro.create_override(
            match_type=RoutingMatchType.EXACT,
            value="nalog.ru",
            route=RoutingRoute.RU,
            comment="exact ru",
        )

        preview = ro.get_preview()

        self.assertEqual(
            [rule.rendered_rule for rule in preview.manual_rules],
            [
                "full:nalog.ru -> direct",
                "domain:gosuslugi.ru -> direct",
                "full:video.youtube.com -> to-egress",
                "domain:youtube.com -> to-egress",
            ],
        )
        self.assertEqual(
            preview.rendered_routing,
            {
                "domainStrategy": "IPIfNonMatch",
                "rules": [
                    {
                        "type": "field",
                        "ip": ["geoip:private"],
                        "outboundTag": "direct",
                    },
                    {
                        "type": "field",
                        "domain": ["full:nalog.ru"],
                        "outboundTag": "direct",
                    },
                    {
                        "type": "field",
                        "domain": ["domain:gosuslugi.ru"],
                        "outboundTag": "direct",
                    },
                    {
                        "type": "field",
                        "domain": ["full:video.youtube.com"],
                        "outboundTag": "to-egress",
                    },
                    {
                        "type": "field",
                        "domain": ["domain:youtube.com"],
                        "outboundTag": "to-egress",
                    },
                    {
                        "type": "field",
                        "domain": ["domain:ru"],
                        "outboundTag": "direct",
                    },
                    {
                        "type": "field",
                        "domain": ["domain:xn--p1ai"],
                        "outboundTag": "direct",
                    },
                    {
                        "type": "field",
                        "ip": ["geoip:ru"],
                        "outboundTag": "direct",
                    },
                    {
                        "type": "field",
                        "network": "tcp,udp",
                        "outboundTag": "to-egress",
                    },
                ],
            },
        )

    def test_toggle_and_delete_affect_persistence(self):
        created = ro.create_override(
            match_type=RoutingMatchType.EXACT,
            value="kinopoisk.ru",
            route=RoutingRoute.RU,
        )

        toggled = ro.toggle_override(created.id)
        self.assertFalse(toggled.enabled)

        stored = json.loads(Path(config.ROUTING_OVERRIDES_PATH).read_text(encoding="utf-8"))
        self.assertEqual(len(stored), 1)
        self.assertFalse(stored[0]["enabled"])

        ro.delete_override(created.id)
        self.assertEqual(ro.list_overrides(), [])

    def test_xray_export_writes_rendered_routing(self):
        original_export_path = config.XRAY_ROUTING_EXPORT_PATH
        original_merged_path = config.XRAY_MERGED_CONFIG_EXPORT_PATH
        original_state_path = config.XRAY_ACTION_STATE_PATH
        config.XRAY_ROUTING_EXPORT_PATH = str(Path(self.tmpdir.name) / "routing.generated.json")
        config.XRAY_MERGED_CONFIG_EXPORT_PATH = str(Path(self.tmpdir.name) / "config.generated.json")
        config.XRAY_ACTION_STATE_PATH = str(Path(self.tmpdir.name) / "xray_action_state.json")
        try:
            ro.create_override(
                match_type=RoutingMatchType.EXACT,
                value="nalog.ru",
                route=RoutingRoute.RU,
            )
            exported = xm.export_routing()

            self.assertEqual(exported.export_path, config.XRAY_ROUTING_EXPORT_PATH)
            stored = json.loads(Path(config.XRAY_ROUTING_EXPORT_PATH).read_text(encoding="utf-8"))
            self.assertEqual(stored, exported.rendered_routing)
            self.assertGreater(exported.bytes_written, 0)
            self.assertIsNone(exported.merged_config_path)
            self.assertEqual(exported.merged_bytes_written, 0)
            self.assertIn("merged config skipped", exported.detail)

            state = json.loads(Path(config.XRAY_ACTION_STATE_PATH).read_text(encoding="utf-8"))
            self.assertEqual(state["action"], "export")
            self.assertEqual(state["status"], "ok")
        finally:
            config.XRAY_ROUTING_EXPORT_PATH = original_export_path
            config.XRAY_MERGED_CONFIG_EXPORT_PATH = original_merged_path
            config.XRAY_ACTION_STATE_PATH = original_state_path

    def test_xray_runtime_status_reflects_configured_commands(self):
        original_export_path = config.XRAY_ROUTING_EXPORT_PATH
        original_merged_path = config.XRAY_MERGED_CONFIG_EXPORT_PATH
        original_base_path = config.XRAY_BASE_CONFIG_PATH
        original_state_path = config.XRAY_ACTION_STATE_PATH
        original_backup_dir = config.XRAY_APPLY_BACKUP_DIR
        original_validate = config.XRAY_VALIDATE_COMMAND
        original_reload = config.XRAY_RELOAD_COMMAND
        config.XRAY_ROUTING_EXPORT_PATH = str(Path(self.tmpdir.name) / "routing.generated.json")
        config.XRAY_MERGED_CONFIG_EXPORT_PATH = str(Path(self.tmpdir.name) / "config.generated.json")
        config.XRAY_BASE_CONFIG_PATH = str(Path(self.tmpdir.name) / "config.json")
        config.XRAY_ACTION_STATE_PATH = str(Path(self.tmpdir.name) / "xray_action_state.json")
        config.XRAY_APPLY_BACKUP_DIR = str(Path(self.tmpdir.name) / "backups")
        config.XRAY_VALIDATE_COMMAND = "python3 -c 'print(\"ok\")'"
        config.XRAY_RELOAD_COMMAND = "python3 -c 'print(\"reloaded\")'"
        try:
            status = xm.get_runtime_status()
            self.assertFalse(status.export_exists)
            self.assertFalse(status.merged_config_exists)
            self.assertFalse(status.base_config_exists)
            self.assertFalse(status.action_state_exists)
            self.assertTrue(status.validate_command_configured)
            self.assertTrue(status.reload_command_configured)
            self.assertEqual(status.base_config_path, config.XRAY_BASE_CONFIG_PATH)
            self.assertEqual(status.merged_config_path, config.XRAY_MERGED_CONFIG_EXPORT_PATH)
            self.assertEqual(status.apply_backup_dir, config.XRAY_APPLY_BACKUP_DIR)
            self.assertEqual(status.xray_clients_total, 0)
            self.assertEqual(status.xray_clients_enabled, 0)
            self.assertFalse(status.routing_export_in_sync)
            self.assertIsNone(status.merged_config_export_in_sync)
        finally:
            config.XRAY_ROUTING_EXPORT_PATH = original_export_path
            config.XRAY_MERGED_CONFIG_EXPORT_PATH = original_merged_path
            config.XRAY_BASE_CONFIG_PATH = original_base_path
            config.XRAY_ACTION_STATE_PATH = original_state_path
            config.XRAY_APPLY_BACKUP_DIR = original_backup_dir
            config.XRAY_VALIDATE_COMMAND = original_validate
            config.XRAY_RELOAD_COMMAND = original_reload

    def test_build_merged_config_replaces_routing_section(self):
        original_export_path = config.XRAY_ROUTING_EXPORT_PATH
        original_merged_path = config.XRAY_MERGED_CONFIG_EXPORT_PATH
        original_base_path = config.XRAY_BASE_CONFIG_PATH
        config.XRAY_ROUTING_EXPORT_PATH = str(Path(self.tmpdir.name) / "routing.generated.json")
        config.XRAY_MERGED_CONFIG_EXPORT_PATH = str(Path(self.tmpdir.name) / "config.generated.json")
        config.XRAY_BASE_CONFIG_PATH = str(Path(self.tmpdir.name) / "config.json")
        try:
            Path(config.XRAY_BASE_CONFIG_PATH).write_text(
                json.dumps(
                    {
                        "log": {"loglevel": "warning"},
                        "inbounds": [
                            {
                                "tag": config.XRAY_CLIENT_INBOUND_TAG,
                                "settings": {"clients": []},
                            }
                        ],
                        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
                        "routing": {"domainStrategy": "AsIs", "rules": [{"type": "field"}]},
                    }
                ),
                encoding="utf-8",
            )
            ro.create_override(
                match_type=RoutingMatchType.EXACT,
                value="nalog.ru",
                route=RoutingRoute.RU,
            )

            merged = xm.build_merged_config()

            self.assertEqual(merged["log"], {"loglevel": "warning"})
            self.assertEqual(merged["outbounds"], [{"tag": "direct", "protocol": "freedom"}])
            self.assertEqual(merged["routing"]["domainStrategy"], "IPIfNonMatch")
            self.assertTrue(any(rule.get("ip") == ["geoip:ru"] for rule in merged["routing"]["rules"]))
        finally:
            config.XRAY_ROUTING_EXPORT_PATH = original_export_path
            config.XRAY_MERGED_CONFIG_EXPORT_PATH = original_merged_path
            config.XRAY_BASE_CONFIG_PATH = original_base_path

    def test_xray_export_writes_merged_config_when_base_config_exists(self):
        original_export_path = config.XRAY_ROUTING_EXPORT_PATH
        original_merged_path = config.XRAY_MERGED_CONFIG_EXPORT_PATH
        original_base_path = config.XRAY_BASE_CONFIG_PATH
        original_state_path = config.XRAY_ACTION_STATE_PATH
        config.XRAY_ROUTING_EXPORT_PATH = str(Path(self.tmpdir.name) / "routing.generated.json")
        config.XRAY_MERGED_CONFIG_EXPORT_PATH = str(Path(self.tmpdir.name) / "config.generated.json")
        config.XRAY_BASE_CONFIG_PATH = str(Path(self.tmpdir.name) / "config.json")
        config.XRAY_ACTION_STATE_PATH = str(Path(self.tmpdir.name) / "xray_action_state.json")
        try:
            Path(config.XRAY_BASE_CONFIG_PATH).write_text(
                json.dumps(
                    {
                        "inbounds": [
                            {
                                "tag": config.XRAY_CLIENT_INBOUND_TAG,
                                "protocol": "vless",
                                "settings": {"clients": []},
                                "sniffing": {"enabled": True},
                            }
                        ],
                        "outbounds": [{"tag": "direct"}, {"tag": "to-egress"}],
                        "routing": {"rules": []},
                    }
                ),
                encoding="utf-8",
            )
            ro.create_override(
                match_type=RoutingMatchType.EXACT,
                value="nalog.ru",
                route=RoutingRoute.RU,
            )

            exported = xm.export_routing()

            self.assertEqual(exported.merged_config_path, config.XRAY_MERGED_CONFIG_EXPORT_PATH)
            self.assertGreater(exported.merged_bytes_written, 0)
            self.assertIsNotNone(exported.merged_config_sha256)
            merged = json.loads(Path(config.XRAY_MERGED_CONFIG_EXPORT_PATH).read_text(encoding="utf-8"))
            self.assertEqual(merged["routing"], exported.rendered_routing)
            self.assertEqual(merged["outbounds"], [{"tag": "direct"}, {"tag": "to-egress"}])
        finally:
            config.XRAY_ROUTING_EXPORT_PATH = original_export_path
            config.XRAY_MERGED_CONFIG_EXPORT_PATH = original_merged_path
            config.XRAY_BASE_CONFIG_PATH = original_base_path
            config.XRAY_ACTION_STATE_PATH = original_state_path

    def test_xray_clients_create_share_and_inject_into_inbound(self):
        original_server = config.XRAY_CLIENT_SERVER
        original_public_key = config.XRAY_CLIENT_REALITY_PUBLIC_KEY
        original_short_id = config.XRAY_CLIENT_REALITY_SHORT_ID
        config.XRAY_CLIENT_SERVER = "203.0.113.10"
        config.XRAY_CLIENT_REALITY_PUBLIC_KEY = "public-key"
        config.XRAY_CLIENT_REALITY_SHORT_ID = "abcd1234"
        try:
            client = xc.create_client(name="Kate Laptop", email=None)
            share = xc.get_share(client.id)

            self.assertEqual(client.email, "kate-laptop@panel")
            self.assertTrue(share.settings_ready)
            self.assertIn(f"vless://{client.id}@203.0.113.10:443", share.share_link)
            self.assertIn("security=reality", share.share_link)
            self.assertIn("pbk=public-key", share.share_link)
            self.assertEqual(share.outbound_config["protocol"], "vless")
            self.assertEqual(share.client_config["remarks"], "Kate Laptop")
            self.assertEqual(share.client_config["inbounds"][0]["protocol"], "socks")
            self.assertEqual(share.client_config["inbounds"][0]["port"], config.XRAY_CLIENT_LOCAL_SOCKS_PORT)
            self.assertEqual(share.client_config["inbounds"][1]["protocol"], "http")
            self.assertEqual(share.client_config["outbounds"][0], share.outbound_config)
            self.assertEqual(share.client_config["routing"]["rules"][0]["outboundTag"], "direct")
            self.assertEqual(share.client_config["routing"]["rules"][1]["outboundTag"], "proxy")
            reality_settings = share.outbound_config["streamSettings"]["realitySettings"]
            self.assertEqual(reality_settings["password"], "public-key")
            self.assertNotIn("publicKey", reality_settings)

            rendered = xc.inject_clients_into_config(
                {
                    "inbounds": [
                        {
                            "tag": config.XRAY_CLIENT_INBOUND_TAG,
                            "settings": {"clients": [{"id": "placeholder"}]},
                        }
                    ]
                }
            )
            self.assertEqual(rendered["inbounds"][0]["settings"]["clients"][0]["id"], client.id)

            disabled = xc.toggle_client(client.id)
            self.assertFalse(disabled.enabled)
            rendered_disabled = xc.inject_clients_into_config(
                {
                    "inbounds": [
                        {
                            "tag": config.XRAY_CLIENT_INBOUND_TAG,
                            "settings": {"clients": [{"id": "placeholder"}]},
                        }
                    ]
                }
            )
            self.assertEqual(rendered_disabled["inbounds"][0]["settings"]["clients"], [])
        finally:
            config.XRAY_CLIENT_SERVER = original_server
            config.XRAY_CLIENT_REALITY_PUBLIC_KEY = original_public_key
            config.XRAY_CLIENT_REALITY_SHORT_ID = original_short_id

    def test_xray_client_settings_status_reports_missing_reality_fields(self):
        original_public_key = config.XRAY_CLIENT_REALITY_PUBLIC_KEY
        original_short_id = config.XRAY_CLIENT_REALITY_SHORT_ID
        config.XRAY_CLIENT_REALITY_PUBLIC_KEY = ""
        config.XRAY_CLIENT_REALITY_SHORT_ID = ""
        try:
            status = xc.get_settings_status()

            self.assertFalse(status.ready)
            self.assertEqual(status.status, "needs_configuration")
            self.assertIn("XRAY_CLIENT_REALITY_PUBLIC_KEY is not configured", status.errors)
            self.assertIn("XRAY_CLIENT_REALITY_SHORT_ID is not configured", status.errors)

            client = xc.create_client(name="Kate", email=None)
            share = xc.get_share(client.id)
            self.assertFalse(share.settings_ready)
            self.assertEqual(share.settings_errors, status.errors)
        finally:
            config.XRAY_CLIENT_REALITY_PUBLIC_KEY = original_public_key
            config.XRAY_CLIENT_REALITY_SHORT_ID = original_short_id

    def test_xray_doctor_status_reports_blockers_and_warnings(self):
        original_base_path = config.XRAY_BASE_CONFIG_PATH
        original_validate = config.XRAY_VALIDATE_COMMAND
        original_reload = config.XRAY_RELOAD_COMMAND
        original_public_key = config.XRAY_CLIENT_REALITY_PUBLIC_KEY
        original_short_id = config.XRAY_CLIENT_REALITY_SHORT_ID
        config.XRAY_BASE_CONFIG_PATH = str(Path(self.tmpdir.name) / "missing-config.json")
        config.XRAY_VALIDATE_COMMAND = ""
        config.XRAY_RELOAD_COMMAND = ""
        config.XRAY_CLIENT_REALITY_PUBLIC_KEY = ""
        config.XRAY_CLIENT_REALITY_SHORT_ID = ""
        try:
            doctor = xm.get_doctor_status()
            checks = {check.id: check for check in doctor.checks}

            self.assertFalse(doctor.ready)
            self.assertEqual(doctor.status, "needs_attention")
            self.assertEqual(checks["client_settings"].status, "error")
            self.assertEqual(checks["enabled_client"].status, "error")
            self.assertEqual(checks["base_config_exists"].status, "error")
            self.assertEqual(checks["validate_command"].status, "error")
            self.assertEqual(checks["routing_export_sync"].status, "warn")
        finally:
            config.XRAY_BASE_CONFIG_PATH = original_base_path
            config.XRAY_VALIDATE_COMMAND = original_validate
            config.XRAY_RELOAD_COMMAND = original_reload
            config.XRAY_CLIENT_REALITY_PUBLIC_KEY = original_public_key
            config.XRAY_CLIENT_REALITY_SHORT_ID = original_short_id

    def test_xray_doctor_status_detects_base_config_placeholders(self):
        original_base_path = config.XRAY_BASE_CONFIG_PATH
        original_validate = config.XRAY_VALIDATE_COMMAND
        original_reload = config.XRAY_RELOAD_COMMAND
        original_public_key = config.XRAY_CLIENT_REALITY_PUBLIC_KEY
        original_short_id = config.XRAY_CLIENT_REALITY_SHORT_ID
        config.XRAY_BASE_CONFIG_PATH = str(Path(self.tmpdir.name) / "config.json")
        config.XRAY_VALIDATE_COMMAND = "xray run -test -config {config_path}"
        config.XRAY_RELOAD_COMMAND = "systemctl reload xray"
        config.XRAY_CLIENT_REALITY_PUBLIC_KEY = "public-key"
        config.XRAY_CLIENT_REALITY_SHORT_ID = "abcd1234"
        try:
            Path(config.XRAY_BASE_CONFIG_PATH).write_text(
                json.dumps(
                    {
                        "inbounds": [
                            {
                                "tag": config.XRAY_CLIENT_INBOUND_TAG,
                                "protocol": "vless",
                                "settings": {"clients": []},
                                "streamSettings": {
                                    "realitySettings": {
                                        "privateKey": "REPLACE_WITH_REALITY_PRIVATE_KEY"
                                    }
                                },
                                "sniffing": {"enabled": True},
                            }
                        ],
                        "outbounds": [{"tag": "direct"}, {"tag": "to-egress"}],
                        "routing": {"rules": []},
                    }
                ),
                encoding="utf-8",
            )
            xc.create_client(name="Kate", email=None)

            doctor = xm.get_doctor_status()
            checks = {check.id: check for check in doctor.checks}

            self.assertFalse(doctor.ready)
            self.assertEqual(checks["base_config_placeholders"].status, "error")
            self.assertIn("privateKey", checks["base_config_placeholders"].detail)
        finally:
            config.XRAY_BASE_CONFIG_PATH = original_base_path
            config.XRAY_VALIDATE_COMMAND = original_validate
            config.XRAY_RELOAD_COMMAND = original_reload
            config.XRAY_CLIENT_REALITY_PUBLIC_KEY = original_public_key
            config.XRAY_CLIENT_REALITY_SHORT_ID = original_short_id

    def test_xray_doctor_status_ready_with_configured_stack(self):
        original_export_path = config.XRAY_ROUTING_EXPORT_PATH
        original_merged_path = config.XRAY_MERGED_CONFIG_EXPORT_PATH
        original_base_path = config.XRAY_BASE_CONFIG_PATH
        original_state_path = config.XRAY_ACTION_STATE_PATH
        original_backup_dir = config.XRAY_APPLY_BACKUP_DIR
        original_validate = config.XRAY_VALIDATE_COMMAND
        original_reload = config.XRAY_RELOAD_COMMAND
        original_public_key = config.XRAY_CLIENT_REALITY_PUBLIC_KEY
        original_short_id = config.XRAY_CLIENT_REALITY_SHORT_ID
        config.XRAY_ROUTING_EXPORT_PATH = str(Path(self.tmpdir.name) / "routing.generated.json")
        config.XRAY_MERGED_CONFIG_EXPORT_PATH = str(Path(self.tmpdir.name) / "config.generated.json")
        config.XRAY_BASE_CONFIG_PATH = str(Path(self.tmpdir.name) / "config.json")
        config.XRAY_ACTION_STATE_PATH = str(Path(self.tmpdir.name) / "xray_action_state.json")
        config.XRAY_APPLY_BACKUP_DIR = str(Path(self.tmpdir.name) / "backups")
        config.XRAY_VALIDATE_COMMAND = "xray run -test -config {config_path}"
        config.XRAY_RELOAD_COMMAND = "systemctl reload xray"
        config.XRAY_CLIENT_REALITY_PUBLIC_KEY = "public-key"
        config.XRAY_CLIENT_REALITY_SHORT_ID = "abcd1234"
        try:
            Path(config.XRAY_BASE_CONFIG_PATH).write_text(
                json.dumps(
                    {
                        "inbounds": [
                            {
                                "tag": config.XRAY_CLIENT_INBOUND_TAG,
                                "protocol": "vless",
                                "settings": {"clients": []},
                                "sniffing": {"enabled": True},
                            }
                        ],
                        "outbounds": [{"tag": "direct"}, {"tag": "to-egress"}],
                        "routing": {"rules": []},
                    }
                ),
                encoding="utf-8",
            )
            xc.create_client(name="Kate", email=None)
            with patch.object(
                xm.subprocess,
                "run",
                return_value=types.SimpleNamespace(returncode=0, stdout="ok\n", stderr=""),
            ):
                xm.apply_xray()

            doctor = xm.get_doctor_status()
            checks = {check.id: check for check in doctor.checks}

            self.assertTrue(doctor.ready)
            self.assertEqual(doctor.status, "ready")
            self.assertEqual(checks["client_settings"].status, "ok")
            self.assertEqual(checks["enabled_client"].status, "ok")
            self.assertEqual(checks["live_clients_sync"].status, "ok")
            self.assertEqual(checks["base_config_mergeable"].status, "ok")
            self.assertEqual(checks["base_config_placeholders"].status, "ok")
            self.assertEqual(checks["client_inbound"].status, "ok")
            self.assertEqual(checks["client_inbound_sniffing"].status, "ok")
            self.assertEqual(checks["to_egress_outbound"].status, "ok")
            self.assertEqual(checks["merged_config_sync"].status, "ok")
        finally:
            config.XRAY_ROUTING_EXPORT_PATH = original_export_path
            config.XRAY_MERGED_CONFIG_EXPORT_PATH = original_merged_path
            config.XRAY_BASE_CONFIG_PATH = original_base_path
            config.XRAY_ACTION_STATE_PATH = original_state_path
            config.XRAY_APPLY_BACKUP_DIR = original_backup_dir
            config.XRAY_VALIDATE_COMMAND = original_validate
            config.XRAY_RELOAD_COMMAND = original_reload
            config.XRAY_CLIENT_REALITY_PUBLIC_KEY = original_public_key
            config.XRAY_CLIENT_REALITY_SHORT_ID = original_short_id

    def test_xray_doctor_status_detects_clients_missing_from_live_config(self):
        original_export_path = config.XRAY_ROUTING_EXPORT_PATH
        original_merged_path = config.XRAY_MERGED_CONFIG_EXPORT_PATH
        original_base_path = config.XRAY_BASE_CONFIG_PATH
        original_state_path = config.XRAY_ACTION_STATE_PATH
        original_validate = config.XRAY_VALIDATE_COMMAND
        original_reload = config.XRAY_RELOAD_COMMAND
        original_public_key = config.XRAY_CLIENT_REALITY_PUBLIC_KEY
        original_short_id = config.XRAY_CLIENT_REALITY_SHORT_ID
        config.XRAY_ROUTING_EXPORT_PATH = str(Path(self.tmpdir.name) / "routing.generated.json")
        config.XRAY_MERGED_CONFIG_EXPORT_PATH = str(Path(self.tmpdir.name) / "config.generated.json")
        config.XRAY_BASE_CONFIG_PATH = str(Path(self.tmpdir.name) / "config.json")
        config.XRAY_ACTION_STATE_PATH = str(Path(self.tmpdir.name) / "xray_action_state.json")
        config.XRAY_VALIDATE_COMMAND = "xray run -test -config {config_path}"
        config.XRAY_RELOAD_COMMAND = "systemctl reload xray"
        config.XRAY_CLIENT_REALITY_PUBLIC_KEY = "public-key"
        config.XRAY_CLIENT_REALITY_SHORT_ID = "abcd1234"
        try:
            Path(config.XRAY_BASE_CONFIG_PATH).write_text(
                json.dumps(
                    {
                        "inbounds": [
                            {
                                "tag": config.XRAY_CLIENT_INBOUND_TAG,
                                "protocol": "vless",
                                "settings": {"clients": []},
                                "sniffing": {"enabled": True},
                            }
                        ],
                        "outbounds": [{"tag": "direct"}, {"tag": "to-egress"}],
                        "routing": {"rules": []},
                    }
                ),
                encoding="utf-8",
            )
            xc.create_client(name="Kate", email=None)
            xm.export_routing()

            doctor = xm.get_doctor_status()
            checks = {check.id: check for check in doctor.checks}

            self.assertFalse(doctor.ready)
            self.assertEqual(checks["live_clients_sync"].status, "error")
            self.assertIn("Kate", checks["live_clients_sync"].detail)
        finally:
            config.XRAY_ROUTING_EXPORT_PATH = original_export_path
            config.XRAY_MERGED_CONFIG_EXPORT_PATH = original_merged_path
            config.XRAY_BASE_CONFIG_PATH = original_base_path
            config.XRAY_ACTION_STATE_PATH = original_state_path
            config.XRAY_VALIDATE_COMMAND = original_validate
            config.XRAY_RELOAD_COMMAND = original_reload
            config.XRAY_CLIENT_REALITY_PUBLIC_KEY = original_public_key
            config.XRAY_CLIENT_REALITY_SHORT_ID = original_short_id

    def test_xray_clients_reject_duplicate_email(self):
        xc.create_client(name="Kate", email="kate@panel")

        with self.assertRaises(xc.XrayClientConflict):
            xc.create_client(name="Kate 2", email="KATE@panel")

    def test_xray_validate_uses_persisted_merged_config_and_updates_state(self):
        original_export_path = config.XRAY_ROUTING_EXPORT_PATH
        original_merged_path = config.XRAY_MERGED_CONFIG_EXPORT_PATH
        original_base_path = config.XRAY_BASE_CONFIG_PATH
        original_state_path = config.XRAY_ACTION_STATE_PATH
        original_validate = config.XRAY_VALIDATE_COMMAND
        config.XRAY_ROUTING_EXPORT_PATH = str(Path(self.tmpdir.name) / "routing.generated.json")
        config.XRAY_MERGED_CONFIG_EXPORT_PATH = str(Path(self.tmpdir.name) / "config.generated.json")
        config.XRAY_BASE_CONFIG_PATH = str(Path(self.tmpdir.name) / "config.json")
        config.XRAY_ACTION_STATE_PATH = str(Path(self.tmpdir.name) / "xray_action_state.json")
        config.XRAY_VALIDATE_COMMAND = "xray run -test -config {config_path}"
        try:
            Path(config.XRAY_BASE_CONFIG_PATH).write_text(
                json.dumps(
                    {
                        "inbounds": [
                            {
                                "tag": config.XRAY_CLIENT_INBOUND_TAG,
                                "settings": {"clients": []},
                            }
                        ],
                        "outbounds": [{"tag": "direct"}],
                        "routing": {"rules": []},
                    }
                ),
                encoding="utf-8",
            )
            ro.create_override(
                match_type=RoutingMatchType.EXACT,
                value="youtube.com",
                route=RoutingRoute.NON_RU,
            )

            with patch.object(
                xm.subprocess,
                "run",
                return_value=types.SimpleNamespace(returncode=0, stdout="ok\n", stderr=""),
            ) as run_mock:
                result = xm.validate_routing()

            self.assertEqual(result.merged_config_path, config.XRAY_MERGED_CONFIG_EXPORT_PATH)
            self.assertIn(config.XRAY_MERGED_CONFIG_EXPORT_PATH, result.command)
            self.assertTrue(Path(config.XRAY_MERGED_CONFIG_EXPORT_PATH).exists())
            run_mock.assert_called_once()

            state = json.loads(Path(config.XRAY_ACTION_STATE_PATH).read_text(encoding="utf-8"))
            self.assertEqual(state["action"], "validate")
            self.assertEqual(state["status"], "ok")
            self.assertEqual(state["merged_config_path"], config.XRAY_MERGED_CONFIG_EXPORT_PATH)
        finally:
            config.XRAY_ROUTING_EXPORT_PATH = original_export_path
            config.XRAY_MERGED_CONFIG_EXPORT_PATH = original_merged_path
            config.XRAY_BASE_CONFIG_PATH = original_base_path
            config.XRAY_ACTION_STATE_PATH = original_state_path
            config.XRAY_VALIDATE_COMMAND = original_validate

    def test_xray_runtime_status_reports_last_action_and_sync(self):
        original_export_path = config.XRAY_ROUTING_EXPORT_PATH
        original_merged_path = config.XRAY_MERGED_CONFIG_EXPORT_PATH
        original_base_path = config.XRAY_BASE_CONFIG_PATH
        original_state_path = config.XRAY_ACTION_STATE_PATH
        config.XRAY_ROUTING_EXPORT_PATH = str(Path(self.tmpdir.name) / "routing.generated.json")
        config.XRAY_MERGED_CONFIG_EXPORT_PATH = str(Path(self.tmpdir.name) / "config.generated.json")
        config.XRAY_BASE_CONFIG_PATH = str(Path(self.tmpdir.name) / "config.json")
        config.XRAY_ACTION_STATE_PATH = str(Path(self.tmpdir.name) / "xray_action_state.json")
        try:
            Path(config.XRAY_BASE_CONFIG_PATH).write_text(
                json.dumps(
                    {
                        "inbounds": [
                            {
                                "tag": config.XRAY_CLIENT_INBOUND_TAG,
                                "settings": {"clients": []},
                            }
                        ],
                        "outbounds": [{"tag": "direct"}],
                        "routing": {"rules": []},
                    }
                ),
                encoding="utf-8",
            )
            ro.create_override(
                match_type=RoutingMatchType.EXACT,
                value="nalog.ru",
                route=RoutingRoute.RU,
            )
            xm.export_routing()

            status = xm.get_runtime_status()

            self.assertTrue(status.export_exists)
            self.assertTrue(status.merged_config_exists)
            self.assertTrue(status.action_state_exists)
            self.assertTrue(status.routing_export_in_sync)
            self.assertTrue(status.merged_config_export_in_sync)
            self.assertIsNotNone(status.last_action)
            self.assertEqual(status.last_action.action, "export")
            self.assertEqual(status.last_action.status, "ok")
        finally:
            config.XRAY_ROUTING_EXPORT_PATH = original_export_path
            config.XRAY_MERGED_CONFIG_EXPORT_PATH = original_merged_path
            config.XRAY_BASE_CONFIG_PATH = original_base_path
            config.XRAY_ACTION_STATE_PATH = original_state_path

    def test_xray_apply_promotes_generated_config_with_backup_and_reload(self):
        original_export_path = config.XRAY_ROUTING_EXPORT_PATH
        original_merged_path = config.XRAY_MERGED_CONFIG_EXPORT_PATH
        original_base_path = config.XRAY_BASE_CONFIG_PATH
        original_state_path = config.XRAY_ACTION_STATE_PATH
        original_backup_dir = config.XRAY_APPLY_BACKUP_DIR
        original_validate = config.XRAY_VALIDATE_COMMAND
        original_reload = config.XRAY_RELOAD_COMMAND
        config.XRAY_ROUTING_EXPORT_PATH = str(Path(self.tmpdir.name) / "routing.generated.json")
        config.XRAY_MERGED_CONFIG_EXPORT_PATH = str(Path(self.tmpdir.name) / "config.generated.json")
        config.XRAY_BASE_CONFIG_PATH = str(Path(self.tmpdir.name) / "config.json")
        config.XRAY_ACTION_STATE_PATH = str(Path(self.tmpdir.name) / "xray_action_state.json")
        config.XRAY_APPLY_BACKUP_DIR = str(Path(self.tmpdir.name) / "backups")
        config.XRAY_VALIDATE_COMMAND = "xray run -test -config {config_path}"
        config.XRAY_RELOAD_COMMAND = "systemctl reload xray"
        original_live = {
            "inbounds": [
                {
                    "tag": config.XRAY_CLIENT_INBOUND_TAG,
                    "settings": {"clients": []},
                }
            ],
            "outbounds": [{"tag": "direct"}],
            "routing": {"rules": []},
        }
        try:
            Path(config.XRAY_BASE_CONFIG_PATH).write_text(
                json.dumps(original_live),
                encoding="utf-8",
            )
            ro.create_override(
                match_type=RoutingMatchType.EXACT,
                value="nalog.ru",
                route=RoutingRoute.RU,
            )

            with patch.object(
                xm.subprocess,
                "run",
                return_value=types.SimpleNamespace(returncode=0, stdout="ok\n", stderr=""),
            ) as run_mock:
                applied = xm.apply_xray()

            self.assertEqual(run_mock.call_count, 2)
            self.assertEqual(applied.live_config_path, config.XRAY_BASE_CONFIG_PATH)
            self.assertEqual(applied.merged_config_path, config.XRAY_MERGED_CONFIG_EXPORT_PATH)
            self.assertTrue(Path(applied.backup_path).exists())
            self.assertEqual(json.loads(Path(applied.backup_path).read_text(encoding="utf-8")), original_live)
            self.assertEqual(
                json.loads(Path(config.XRAY_BASE_CONFIG_PATH).read_text(encoding="utf-8")),
                json.loads(Path(config.XRAY_MERGED_CONFIG_EXPORT_PATH).read_text(encoding="utf-8")),
            )

            state = json.loads(Path(config.XRAY_ACTION_STATE_PATH).read_text(encoding="utf-8"))
            self.assertEqual(state["action"], "apply")
            self.assertEqual(state["status"], "ok")
            self.assertEqual(state["backup_path"], applied.backup_path)
        finally:
            config.XRAY_ROUTING_EXPORT_PATH = original_export_path
            config.XRAY_MERGED_CONFIG_EXPORT_PATH = original_merged_path
            config.XRAY_BASE_CONFIG_PATH = original_base_path
            config.XRAY_ACTION_STATE_PATH = original_state_path
            config.XRAY_APPLY_BACKUP_DIR = original_backup_dir
            config.XRAY_VALIDATE_COMMAND = original_validate
            config.XRAY_RELOAD_COMMAND = original_reload

    def test_xray_apply_restores_backup_when_reload_fails(self):
        original_export_path = config.XRAY_ROUTING_EXPORT_PATH
        original_merged_path = config.XRAY_MERGED_CONFIG_EXPORT_PATH
        original_base_path = config.XRAY_BASE_CONFIG_PATH
        original_state_path = config.XRAY_ACTION_STATE_PATH
        original_backup_dir = config.XRAY_APPLY_BACKUP_DIR
        original_validate = config.XRAY_VALIDATE_COMMAND
        original_reload = config.XRAY_RELOAD_COMMAND
        config.XRAY_ROUTING_EXPORT_PATH = str(Path(self.tmpdir.name) / "routing.generated.json")
        config.XRAY_MERGED_CONFIG_EXPORT_PATH = str(Path(self.tmpdir.name) / "config.generated.json")
        config.XRAY_BASE_CONFIG_PATH = str(Path(self.tmpdir.name) / "config.json")
        config.XRAY_ACTION_STATE_PATH = str(Path(self.tmpdir.name) / "xray_action_state.json")
        config.XRAY_APPLY_BACKUP_DIR = str(Path(self.tmpdir.name) / "backups")
        config.XRAY_VALIDATE_COMMAND = "xray run -test -config {config_path}"
        config.XRAY_RELOAD_COMMAND = "systemctl reload xray"
        original_live = {
            "inbounds": [
                {
                    "tag": config.XRAY_CLIENT_INBOUND_TAG,
                    "settings": {"clients": []},
                }
            ],
            "outbounds": [{"tag": "direct"}],
            "routing": {"rules": []},
        }
        try:
            Path(config.XRAY_BASE_CONFIG_PATH).write_text(
                json.dumps(original_live),
                encoding="utf-8",
            )
            ro.create_override(
                match_type=RoutingMatchType.EXACT,
                value="nalog.ru",
                route=RoutingRoute.RU,
            )

            with patch.object(
                xm.subprocess,
                "run",
                side_effect=[
                    types.SimpleNamespace(returncode=0, stdout="validated\n", stderr=""),
                    types.SimpleNamespace(returncode=1, stdout="", stderr="reload failed\n"),
                ],
            ):
                with self.assertRaises(xm.XrayCommandError):
                    xm.apply_xray()

            self.assertEqual(
                json.loads(Path(config.XRAY_BASE_CONFIG_PATH).read_text(encoding="utf-8")),
                original_live,
            )
            state = json.loads(Path(config.XRAY_ACTION_STATE_PATH).read_text(encoding="utf-8"))
            self.assertEqual(state["action"], "apply")
            self.assertEqual(state["status"], "error")
            self.assertTrue(state["backup_path"])
        finally:
            config.XRAY_ROUTING_EXPORT_PATH = original_export_path
            config.XRAY_MERGED_CONFIG_EXPORT_PATH = original_merged_path
            config.XRAY_BASE_CONFIG_PATH = original_base_path
            config.XRAY_ACTION_STATE_PATH = original_state_path
            config.XRAY_APPLY_BACKUP_DIR = original_backup_dir
            config.XRAY_VALIDATE_COMMAND = original_validate
            config.XRAY_RELOAD_COMMAND = original_reload


@unittest.skipUnless(
    SERVICE_DEPS_AVAILABLE and TestClient is not None and main is not None,
    "fastapi/panel dependencies are not installed",
)
class RoutingOverrideApiTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.original_store = config.ROUTING_OVERRIDES_PATH
        self.original_xray_clients = config.XRAY_CLIENTS_PATH
        self.original_token = config.PANEL_SECRET_TOKEN
        self.original_awg_settings_path = config.AWG_SETTINGS_PATH
        self.original_server_public_host = config.SERVER_PUBLIC_HOST
        self.original_wg_endpoint_host = config.WG_ENDPOINT_HOST
        self.original_xray_client_server = config.XRAY_CLIENT_SERVER
        config.ROUTING_OVERRIDES_PATH = str(Path(self.tmpdir.name) / "routing_overrides.json")
        config.XRAY_CLIENTS_PATH = str(Path(self.tmpdir.name) / "xray_clients.json")
        config.PANEL_SECRET_TOKEN = "test-token"
        config.AWG_SETTINGS_PATH = str(Path(self.tmpdir.name) / "awg_settings.json")
        config.SERVER_PUBLIC_HOST = "vpn.example.com"
        config.WG_ENDPOINT_HOST = "vpn.example.com"
        config.XRAY_CLIENT_SERVER = "vpn.example.com"
        Path(config.AWG_SETTINGS_PATH).write_text(
            json.dumps(
                {
                    "endpoint_host": "vpn.example.com",
                    "endpoint_port": 34011,
                    "dns_servers": "1.1.1.1,1.0.0.1",
                    "persistent_keepalive": 25,
                    "Jc": 0,
                    "Jmin": 0,
                    "Jmax": 0,
                    "S1": 0,
                    "S2": 0,
                    "S3": 0,
                    "S4": 0,
                    "H1": 0,
                    "H2": 0,
                    "H3": 0,
                    "H4": 0,
                    "I1": "",
                    "I2": "",
                    "I3": "",
                    "I4": "",
                    "I5": "",
                }
            ),
            encoding="utf-8",
        )
        self.apply_patcher = patch.object(
            main.xm,
            "apply_xray",
            return_value=types.SimpleNamespace(status="ok"),
        )
        self.apply_mock = self.apply_patcher.start()
        self.client = TestClient(main.app)

    def tearDown(self):
        self.client.close()
        self.apply_patcher.stop()
        config.ROUTING_OVERRIDES_PATH = self.original_store
        config.XRAY_CLIENTS_PATH = self.original_xray_clients
        config.PANEL_SECRET_TOKEN = self.original_token
        config.AWG_SETTINGS_PATH = self.original_awg_settings_path
        config.SERVER_PUBLIC_HOST = self.original_server_public_host
        config.WG_ENDPOINT_HOST = self.original_wg_endpoint_host
        config.XRAY_CLIENT_SERVER = self.original_xray_client_server
        self.tmpdir.cleanup()

    def _auth_headers(self):
        return {"Authorization": f"Bearer {config.PANEL_SECRET_TOKEN}"}

    def test_app_startup_rejects_placeholder_panel_secret(self):
        self.client.close()
        config.PANEL_SECRET_TOKEN = ""

        with self.assertRaisesRegex(RuntimeError, "PANEL_SECRET_TOKEN"):
            with TestClient(main.app):
                pass

        config.PANEL_SECRET_TOKEN = "test-token"
        self.client = TestClient(main.app)

    def test_routing_endpoints_require_auth(self):
        cases = [
            ("get", "/api/routing/overrides", None),
            ("post", "/api/routing/overrides", {"match_type": "exact", "value": "youtube.com", "route": "non_ru", "comment": ""}),
            ("put", "/api/routing/overrides/missing", {"match_type": "exact", "value": "youtube.com", "route": "non_ru", "comment": ""}),
            ("post", "/api/routing/overrides/missing/toggle", None),
            ("delete", "/api/routing/overrides/missing", None),
            ("get", "/api/routing/check?host=youtube.com", None),
            ("get", "/api/routing/preview", None),
            ("get", "/api/routing/exported-routing", None),
            ("get", "/api/routing/exported-merged-config", None),
            ("post", "/api/routing/apply", None),
            ("get", "/api/xray/settings", None),
            ("get", "/api/xray/doctor", None),
            ("get", "/api/xray/clients", None),
            ("post", "/api/xray/clients", {"name": "Kate", "email": None}),
            ("put", "/api/xray/clients/missing", {"name": "Kate", "email": None}),
            ("post", "/api/xray/clients/missing/toggle", None),
            ("delete", "/api/xray/clients/missing", None),
            ("get", "/api/xray/clients/missing/share", None),
            ("get", "/api/xray/clients/missing/config", None),
            ("get", "/api/xray/clients/missing/bundle", None),
            ("get", "/api/peers/missing/artifacts", None),
            ("get", "/api/peers/missing/config", None),
            ("get", "/api/peers/missing/qr", None),
        ]

        for method, url, payload in cases:
            with self.subTest(method=method, url=url):
                request = getattr(self.client, method)
                response = request(url, json=payload) if payload is not None else request(url)
                self.assertEqual(response.status_code, 401)

    def test_create_update_toggle_delete_and_list_flow(self):
        create_response = self.client.post(
            "/api/routing/overrides",
            headers=self._auth_headers(),
            json={
                "match_type": "suffix",
                "value": "YouTube.com",
                "route": "non_ru",
                "comment": "force via NL",
            },
        )
        self.assertEqual(create_response.status_code, 201)
        created = create_response.json()
        self.assertTrue(created["enabled"])
        self.assertEqual(created["normalized_value"], "youtube.com")

        list_response = self.client.get("/api/routing/overrides", headers=self._auth_headers())
        self.assertEqual(list_response.status_code, 200)
        self.assertEqual(len(list_response.json()), 1)

        update_response = self.client.put(
            f"/api/routing/overrides/{created['id']}",
            headers=self._auth_headers(),
            json={
                "match_type": "exact",
                "value": "music.youtube.com",
                "route": "non_ru",
                "comment": "more specific",
            },
        )
        self.assertEqual(update_response.status_code, 200)
        updated = update_response.json()
        self.assertEqual(updated["match_type"], "exact")
        self.assertEqual(updated["normalized_value"], "music.youtube.com")

        toggle_response = self.client.post(
            f"/api/routing/overrides/{created['id']}/toggle",
            headers=self._auth_headers(),
        )
        self.assertEqual(toggle_response.status_code, 200)
        self.assertFalse(toggle_response.json()["enabled"])

        preview_response = self.client.get("/api/routing/preview", headers=self._auth_headers())
        self.assertEqual(preview_response.status_code, 200)
        self.assertEqual(preview_response.json()["manual_overrides_enabled"], 0)

        delete_response = self.client.delete(
            f"/api/routing/overrides/{created['id']}",
            headers=self._auth_headers(),
        )
        self.assertEqual(delete_response.status_code, 200)
        self.assertEqual(delete_response.json(), {"status": "deleted"})

        final_list = self.client.get("/api/routing/overrides", headers=self._auth_headers())
        self.assertEqual(final_list.json(), [])

    def test_duplicate_override_returns_409(self):
        ro.create_override(
            match_type=RoutingMatchType.EXACT,
            value="gosuslugi.ru",
            route=RoutingRoute.RU,
        )

        response = self.client.post(
            "/api/routing/overrides",
            headers=self._auth_headers(),
            json={
                "match_type": "exact",
                "value": "GOSUSLUGI.RU.",
                "route": "non_ru",
                "comment": "",
            },
        )
        self.assertEqual(response.status_code, 409)

    def test_preview_endpoint_reports_no_rules(self):
        response = self.client.get("/api/routing/preview", headers=self._auth_headers())
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["manual_overrides_enabled"], 0)
        self.assertEqual(payload["manual_rules"], [])
        self.assertEqual(
            payload["routing_order"],
            [
                "geoip:private -> direct",
                "manual:ru overrides -> direct",
                "manual:non_ru overrides -> to-egress",
                "builtin:.ru/.xn--p1ai -> direct",
                "geoip:ru -> direct",
                "default -> to-egress",
            ],
        )
        self.assertEqual(
            payload["rendered_routing"],
            {
                "domainStrategy": "IPIfNonMatch",
                "rules": [
                    {
                        "type": "field",
                        "ip": ["geoip:private"],
                        "outboundTag": "direct",
                    },
                    {
                        "type": "field",
                        "domain": ["domain:ru"],
                        "outboundTag": "direct",
                    },
                    {
                        "type": "field",
                        "domain": ["domain:xn--p1ai"],
                        "outboundTag": "direct",
                    },
                    {
                        "type": "field",
                        "ip": ["geoip:ru"],
                        "outboundTag": "direct",
                    },
                    {
                        "type": "field",
                        "network": "tcp,udp",
                        "outboundTag": "to-egress",
                    },
                ],
            },
        )

    def test_routing_check_endpoint_reports_manual_match_and_fallback(self):
        ro.create_override(
            match_type=RoutingMatchType.SUFFIX,
            value="gosuslugi.ru",
            route=RoutingRoute.RU,
        )

        match_response = self.client.get(
            "/api/routing/check?host=api.gosuslugi.ru",
            headers=self._auth_headers(),
        )
        self.assertEqual(match_response.status_code, 200)
        matched = match_response.json()
        self.assertTrue(matched["matched"])
        self.assertEqual(matched["route"], "ru")
        self.assertEqual(matched["outbound"], "direct")
        self.assertEqual(matched["rendered_rule"], "domain:gosuslugi.ru -> direct")

        fallback_response = self.client.get(
            "/api/routing/check?host=example.org",
            headers=self._auth_headers(),
        )
        self.assertEqual(fallback_response.status_code, 200)
        fallback = fallback_response.json()
        self.assertFalse(fallback["matched"])
        self.assertEqual(fallback["source"], "fallback")

        builtin_response = self.client.get(
            "/api/routing/check?host=ozon.ru",
            headers=self._auth_headers(),
        )
        self.assertEqual(builtin_response.status_code, 200)
        builtin = builtin_response.json()
        self.assertTrue(builtin["matched"])
        self.assertEqual(builtin["source"], "builtin_ru_zone")
        self.assertEqual(builtin["outbound"], "direct")

        invalid_response = self.client.get(
            "/api/routing/check?host=https://example.org",
            headers=self._auth_headers(),
        )
        self.assertEqual(invalid_response.status_code, 400)

    def test_runtime_endpoint_reports_configuration_state(self):
        response = self.client.get("/api/routing/runtime", headers=self._auth_headers())
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("export_path", payload)
        self.assertIn("merged_config_path", payload)
        self.assertIn("base_config_path", payload)
        self.assertIn("action_state_path", payload)
        self.assertIn("apply_backup_dir", payload)
        self.assertIn("base_config_exists", payload)
        self.assertIn("validate_command_configured", payload)
        self.assertIn("reload_command_configured", payload)
        self.assertIn("routing_export_in_sync", payload)
        self.assertIn("last_action", payload)
        self.assertIn("xray_clients_total", payload)
        self.assertIn("xray_clients_enabled", payload)

    def test_xray_settings_endpoint_reports_readiness(self):
        response = self.client.get("/api/xray/settings", headers=self._auth_headers())
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("ready", payload)
        self.assertIn("errors", payload)
        self.assertIn("local_socks_port", payload)
        self.assertIn("local_http_port", payload)
        self.assertIn("reality_public_key_configured", payload)
        self.assertIn("reality_short_id_configured", payload)

    def test_xray_doctor_endpoint_reports_readiness(self):
        response = self.client.get("/api/xray/doctor", headers=self._auth_headers())
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("ready", payload)
        self.assertIn("checks", payload)
        self.assertIn("settings", payload)
        self.assertIn("runtime", payload)

    def test_preview_endpoint_orders_only_enabled_rules(self):
        ru_rule = ro.create_override(
            match_type=RoutingMatchType.SUFFIX,
            value="yandex.ru",
            route=RoutingRoute.RU,
        )
        ro.create_override(
            match_type=RoutingMatchType.EXACT,
            value="passport.yandex.ru",
            route=RoutingRoute.RU,
        )
        non_ru_rule = ro.create_override(
            match_type=RoutingMatchType.EXACT,
            value="youtube.com",
            route=RoutingRoute.NON_RU,
        )
        ro.toggle_override(ru_rule.id)
        ro.toggle_override(non_ru_rule.id)

        response = self.client.get("/api/routing/preview", headers=self._auth_headers())
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["manual_overrides_enabled"], 1)
        self.assertEqual(
            [rule["rendered_rule"] for rule in payload["manual_rules"]],
            ["full:passport.yandex.ru -> direct"],
        )

    def test_xray_client_api_create_share_toggle_delete_flow(self):
        create_response = self.client.post(
            "/api/xray/clients",
            headers=self._auth_headers(),
            json={"name": "Kate Laptop", "email": None},
        )
        self.assertEqual(create_response.status_code, 201)
        created = create_response.json()
        self.assertEqual(created["email"], "kate-laptop@panel")
        self.assertTrue(created["enabled"])

        share_response = self.client.get(
            f"/api/xray/clients/{created['id']}/share",
            headers=self._auth_headers(),
        )
        self.assertEqual(share_response.status_code, 200)
        self.assertIn("vless://", share_response.json()["share_link"])
        self.assertEqual(share_response.json()["id"], created["id"])

        artifacts_response = self.client.get(
            f"/api/xray/clients/{created['id']}/artifacts",
            headers=self._auth_headers(),
        )
        self.assertEqual(artifacts_response.status_code, 200)
        artifacts_payload = artifacts_response.json()
        self.assertEqual(artifacts_payload["client_id"], created["id"])
        self.assertEqual(artifacts_payload["default_protocol"], "vless")
        self.assertEqual(len(artifacts_payload["available_protocols"]), 1)
        self.assertEqual(artifacts_payload["available_protocols"][0]["protocol"], "vless")
        self.assertIn(f"/api/xray/clients/{created['id']}/share?protocol=vless", artifacts_payload["available_protocols"][0]["share_endpoint"])

        explicit_share_response = self.client.get(
            f"/api/xray/clients/{created['id']}/share?protocol=vless",
            headers=self._auth_headers(),
        )
        self.assertEqual(explicit_share_response.status_code, 200)
        self.assertEqual(
            explicit_share_response.json()["share_link"],
            share_response.json()["share_link"],
        )

        config_response = self.client.get(
            f"/api/xray/clients/{created['id']}/config",
            headers=self._auth_headers(),
        )
        self.assertEqual(config_response.status_code, 200)
        downloaded_config = config_response.json()
        self.assertEqual(downloaded_config["remarks"], "Kate Laptop")
        self.assertEqual(downloaded_config["inbounds"][0]["protocol"], "socks")
        self.assertEqual(downloaded_config["outbounds"][0]["protocol"], "vless")
        self.assertIn("pbk=public-key", share_response.json()["share_link"])
        self.assertEqual(
            downloaded_config["outbounds"][0]["streamSettings"]["realitySettings"]["password"],
            "public-key",
        )
        self.assertNotIn(
            "publicKey",
            downloaded_config["outbounds"][0]["streamSettings"]["realitySettings"],
        )
        self.assertEqual(downloaded_config["routing"]["rules"][1]["outboundTag"], "proxy")

        bundle_response = self.client.get(
            f"/api/xray/clients/{created['id']}/bundle",
            headers=self._auth_headers(),
        )
        self.assertEqual(bundle_response.status_code, 200)
        with zipfile.ZipFile(BytesIO(bundle_response.content)) as archive:
            names = set(archive.namelist())
            self.assertIn("vless-link.txt", names)
            self.assertIn("Kate-Laptop.xray-client.json", names)
            self.assertIn("xray-share.json", names)
            self.assertIn("xray-doctor.json", names)
            self.assertIn("routing-preview.json", names)
            self.assertIn("manual-check-windows.md", names)
            self.assertIn("README.txt", names)

            self.assertIn("vless://", archive.read("vless-link.txt").decode("utf-8"))
            bundled_config = json.loads(
                archive.read("Kate-Laptop.xray-client.json").decode("utf-8")
            )
            self.assertEqual(bundled_config["outbounds"][0]["protocol"], "vless")
            doctor = json.loads(archive.read("xray-doctor.json").decode("utf-8"))
            self.assertIn("checks", doctor)
            checklist = archive.read("manual-check-windows.md").decode("utf-8")
            self.assertIn("Проверка VPN вручную на Windows", checklist)

        unsupported_protocol = self.client.get(
            f"/api/xray/clients/{created['id']}/share?protocol=amneziawg",
            headers=self._auth_headers(),
        )
        self.assertEqual(unsupported_protocol.status_code, 400)
        self.assertIn("not implemented yet", unsupported_protocol.json()["detail"])

        toggle_response = self.client.post(
            f"/api/xray/clients/{created['id']}/toggle",
            headers=self._auth_headers(),
        )
        self.assertEqual(toggle_response.status_code, 200)
        self.assertFalse(toggle_response.json()["enabled"])

        delete_response = self.client.delete(
            f"/api/xray/clients/{created['id']}",
            headers=self._auth_headers(),
        )
        self.assertEqual(delete_response.status_code, 200)
        self.assertEqual(delete_response.json(), {"status": "deleted"})
        self.assertEqual(self.apply_mock.call_count, 3)

    def test_peer_artifacts_api_reports_wg_and_awg_catalog_and_protocol_specific_config(self):
        peer = PeerInfo(
            public_key="peer/public+key=",
            protocol="wg",
            name="Kate Phone",
            vpn_ip="10.8.0.2",
            status=PeerStatus.NEVER,
            created_at="2026-04-27T10:00:00+00:00",
        )
        peer_conf = (
            "[Interface]\n"
            "PrivateKey = private-key\n"
            "Address = 10.8.0.2/32\n\n"
            "[Peer]\n"
            "PublicKey = server-key\n"
            "Endpoint = 203.0.113.10:51820\n"
            "AllowedIPs = 0.0.0.0/0\n"
        )
        awg_conf = (
            "[Interface]\n"
            "PrivateKey = private-key\n"
            "Address = 10.8.0.2/32\n"
            "Jc = 0\n\n"
            "[Peer]\n"
            "PublicKey = server-key\n"
            "Endpoint = vpn.example.com:34011\n"
            "AllowedIPs = 0.0.0.0/0\n"
        )

        with patch.object(main.vm, "get_all_peers", return_value=[peer]), patch.object(
            main.vm,
            "get_client_conf",
            side_effect=lambda pubkey, protocol=None: awg_conf if getattr(protocol, "value", protocol) == "amneziawg" else peer_conf,
        ):
            artifacts_response = self.client.get(
                f"/api/peers/{peer.public_key}/artifacts",
                headers=self._auth_headers(),
            )
            self.assertEqual(artifacts_response.status_code, 200)
            artifacts_payload = artifacts_response.json()
            self.assertEqual(artifacts_payload["peer_public_key"], peer.public_key)
            self.assertEqual(artifacts_payload["peer_name"], "Kate Phone")
            self.assertEqual(artifacts_payload["default_protocol"], "wg")
            self.assertEqual(len(artifacts_payload["available_protocols"]), 2)
            self.assertEqual(
                [option["protocol"] for option in artifacts_payload["available_protocols"]],
                ["wg", "amneziawg"],
            )
            encoded_pubkey = quote(peer.public_key, safe="")
            self.assertIn(
                f"/api/peers/{encoded_pubkey}/config?protocol=wg",
                artifacts_payload["available_protocols"][0]["config_endpoint"],
            )
            self.assertIn(
                f"/api/peers/{encoded_pubkey}/config?protocol=amneziawg",
                artifacts_payload["available_protocols"][1]["config_endpoint"],
            )

            config_response = self.client.get(
                f"/api/peers/{peer.public_key}/config?protocol=wg",
                headers=self._auth_headers(),
            )
            self.assertEqual(config_response.status_code, 200)
            self.assertIn("[Interface]", config_response.text)
            self.assertIn("attachment; filename=\"Kate-Phone.conf\"", config_response.headers["content-disposition"])

            qr_response = self.client.get(
                f"/api/peers/{peer.public_key}/qr?protocol=wg",
                headers=self._auth_headers(),
            )
            self.assertEqual(qr_response.status_code, 200)
            self.assertEqual(qr_response.headers["content-type"], "image/png")

            awg_response = self.client.get(
                f"/api/peers/{peer.public_key}/config?protocol=amneziawg",
                headers=self._auth_headers(),
            )
            self.assertEqual(awg_response.status_code, 200)
            self.assertIn("Endpoint = vpn.example.com:34011", awg_response.text)
            self.assertIn("Jc = 0", awg_response.text)

    def test_xray_client_api_rolls_back_store_when_apply_fails(self):
        self.apply_mock.side_effect = xm.XrayCommandError("reload failed")

        response = self.client.post(
            "/api/xray/clients",
            headers=self._auth_headers(),
            json={"name": "Broken Client", "email": None},
        )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(xc.list_clients(), [])

    def test_existing_peers_endpoint_still_works_with_new_routes(self):
        with patch.object(main.vm, "get_all_peers", return_value=[]):
            response = self.client.get("/api/peers", headers=self._auth_headers())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])


if __name__ == "__main__":
    unittest.main()
