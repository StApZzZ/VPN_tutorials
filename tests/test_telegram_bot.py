import sys
import tempfile
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "amnezia-panel-src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

if "dotenv" not in sys.modules:
    dotenv_stub = types.ModuleType("dotenv")
    dotenv_stub.load_dotenv = lambda *args, **kwargs: None
    sys.modules["dotenv"] = dotenv_stub

try:
    import httpx
    import config
    import main
    import telegram_access
    import telegram_bot
    import telegram_command_docs
    import telegram_name_backfill

    SERVICE_DEPS_AVAILABLE = True
except ModuleNotFoundError:
    httpx = None
    config = None
    main = None
    telegram_access = None
    telegram_bot = None
    telegram_command_docs = None
    telegram_name_backfill = None
    SERVICE_DEPS_AVAILABLE = False


class RecordingTelegram:
    def __init__(self):
        self.messages: list[tuple[int, str]] = []
        self.reply_markups: list[dict | None] = []
        self.photos: list[tuple[int, object, str]] = []
        self.documents: list[tuple[int, object, str]] = []
        self.invoices: list[dict] = []
        self.pre_checkout_answers: list[dict] = []
        self.callback_answers: list[dict] = []

    async def send_message(self, chat_id: int, text: str, reply_markup: dict | None = None) -> None:
        self.messages.append((chat_id, text))
        self.reply_markups.append(reply_markup)

    async def send_photo(self, chat_id: int, photo, caption: str = "") -> None:
        self.photos.append((chat_id, photo, caption))

    async def send_document(self, chat_id: int, document, caption: str = "") -> None:
        self.documents.append((chat_id, document, caption))

    async def send_invoice(
        self,
        chat_id: int,
        title: str,
        description: str,
        payload: str,
        amount_stars: int,
        label: str,
    ) -> None:
        self.invoices.append(
            {
                "chat_id": chat_id,
                "title": title,
                "description": description,
                "payload": payload,
                "amount_stars": amount_stars,
                "label": label,
            }
        )

    async def answer_pre_checkout_query(
        self,
        pre_checkout_query_id: str,
        ok: bool,
        error_message: str = "",
    ) -> None:
        self.pre_checkout_answers.append(
            {
                "pre_checkout_query_id": pre_checkout_query_id,
                "ok": ok,
                "error_message": error_message,
            }
        )

    async def answer_callback_query(
        self,
        callback_query_id: str,
        text: str = "",
        show_alert: bool = False,
    ) -> None:
        self.callback_answers.append(
            {
                "callback_query_id": callback_query_id,
                "text": text,
                "show_alert": show_alert,
            }
        )


class ProfileLookupTelegram:
    def __init__(self, profiles: dict[int, dict]):
        self.profiles = dict(profiles)

    async def get_chat(self, chat_id: int) -> dict:
        profile = self.profiles.get(chat_id)
        if profile is None:
            raise RuntimeError(f"profile not found for {chat_id}")
        return dict(profile)


@unittest.skipUnless(SERVICE_DEPS_AVAILABLE, "panel dependencies are not installed")
class TelegramAccessStoreTests(unittest.TestCase):
    def test_access_store_invite_bind_and_reload(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "telegram_access.json"
            access = telegram_access.TelegramAccessStore(path=path, admin_user_ids={123})

            self.assertEqual(telegram_access.parse_id_set("123, 456\n789"), {123, 456, 789})
            self.assertTrue(access.is_admin(123))
            self.assertTrue(access.is_known_user(123))
            self.assertFalse(access.is_known_user(222))

            access.invite_user(222, invited_by=123)
            self.assertTrue(access.is_known_user(222))
            self.assertIsNone(access.client_for_user(222))

            access.bind_client(222, "client-uuid", invited_by=123)
            self.assertEqual(access.client_for_user(222), "client-uuid")

            reloaded = telegram_access.TelegramAccessStore(path=path, admin_user_ids={123})
            self.assertEqual(reloaded.client_for_user(222), "client-uuid")
            record = reloaded.load()["users"]["222"]
            self.assertEqual(record["invited_by"], 123)
            self.assertIn("created_at", record)
            self.assertIn("updated_at", record)
            self.assertEqual(record["account_type"], "free")
            self.assertEqual(record["discount_percent"], 0)
            self.assertEqual(record["bonus_balance_stars"], 0)
            self.assertEqual(record["trial_invite_id"], "")
            self.assertEqual(record["preferred_language"], "")
            self.assertEqual(record["telegram_language_code"], "")
            self.assertEqual(record["language_prompted_at"], "")
            self.assertEqual(reloaded.trial_period_days(), 7)
            self.assertEqual(reloaded.referral_bonus_percent(), 10)

    def test_access_store_subscription_settings_discount_and_payments(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "telegram_access.json"
            path.write_text(
                '{"users": {"222": {"invited_by": 123, "client_id": "client-uuid"}}}\n',
                encoding="utf-8",
            )
            access = telegram_access.TelegramAccessStore(path=path, admin_user_ids={123})

            self.assertEqual(access.subscription_price_stars(), 100)
            self.assertEqual(access.subscription_period_days(), 30)
            self.assertEqual(access.subscription_max_12m_discount_percent(), 0)
            self.assertEqual(access.user_record(222)["account_type"], "free")
            self.assertEqual(access.user_record(222)["preferred_language"], "")

            access.set_subscription_price_stars(250)
            access.set_subscription_max_12m_discount_percent(20)
            access.set_discount_percent(222, 20)
            self.assertEqual(access.price_for_user(222), 200)
            quote = access.payment_quote_for_user(222, months=3)
            self.assertEqual(quote["months"], 3)
            self.assertEqual(quote["package_discount_percent"], 5)
            self.assertEqual(quote["total_discount_percent"], 25)
            self.assertEqual(quote["period_days"], 90)
            self.assertEqual(quote["base_amount_stars"], 562)
            access.clear_discount_percent(222)
            self.assertEqual(access.price_for_user(222), 250)

            now = datetime(2026, 4, 22, 12, 0, tzinfo=timezone.utc)
            access.grant_subscription(222, days=30, now=now)
            first_expiry = telegram_access.parse_timestamp(
                access.user_record(222)["subscription_expires_at"]
            )
            self.assertEqual(first_expiry, now + timedelta(days=30))
            access.grant_subscription(222, days=30, now=now + timedelta(days=10))
            second_expiry = telegram_access.parse_timestamp(
                access.user_record(222)["subscription_expires_at"]
            )
            self.assertEqual(second_expiry, now + timedelta(days=60))

            payment_quote = access.payment_quote_for_user(222, months=6)
            payment = access.create_payment(
                222,
                amount_stars=payment_quote["amount_stars"],
                base_amount_stars=payment_quote["base_amount_stars"],
                bonus_spent_stars=payment_quote["bonus_spent_stars"],
                months=payment_quote["months"],
                period_days=payment_quote["period_days"],
                personal_discount_percent=payment_quote["personal_discount_percent"],
                package_discount_percent=payment_quote["package_discount_percent"],
                total_discount_percent=payment_quote["total_discount_percent"],
            )
            self.assertEqual(access.payment_for_payload(payment["payload"])["status"], "pending")
            self.assertEqual(access.payment_for_payload(payment["payload"])["months"], 6)
            self.assertEqual(access.payment_for_payload(payment["payload"])["period_days"], 180)
            access.complete_payment(payment["payload"], telegram_payment_charge_id="charge-id")

            reloaded = telegram_access.TelegramAccessStore(path=path, admin_user_ids={123})
            self.assertEqual(
                reloaded.payment_for_payload(payment["payload"])["telegram_payment_charge_id"],
                "charge-id",
            )
            self.assertEqual(reloaded.subscription_max_12m_discount_percent(), 20)

    def test_access_store_pending_invites_leads_trials_and_bonus(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "telegram_access.json"
            access = telegram_access.TelegramAccessStore(path=path, admin_user_ids={123})
            access.set_trial_period_days(5)

            lead = access.record_lead(
                user_id=333,
                chat_id=333,
                chat_type="private",
                profile={"username": "newuser", "first_name": "New"},
                message_text="/start",
            )
            self.assertEqual(lead["message_count"], 1)
            self.assertEqual(len(access.public_lead_records()), 1)

            invite = access.create_invite(created_by=222, target_username_hint="@newuser")
            self.assertEqual(invite["status"], "pending")
            self.assertNotIn("token", access.public_invite_records()[0])

            accepted = access.accept_invite(
                invite["token"],
                user_id=333,
                now=datetime(2026, 4, 22, 12, 0, tzinfo=timezone.utc),
            )
            self.assertEqual(accepted["invite"]["status"], "accepted")
            self.assertEqual(access.public_lead_records(), [])
            self.assertTrue(access.is_subscription_active(333, now=datetime(2026, 4, 22, 12, 1, tzinfo=timezone.utc)))
            self.assertTrue(access.is_trial_active(333, now=datetime(2026, 4, 22, 12, 1, tzinfo=timezone.utc)))

            payment = access.create_payment(333, amount_stars=100)
            access.complete_payment(payment["payload"], telegram_payment_charge_id="charge-id")
            bonus = access.award_referral_bonus_for_payment(
                payment["payload"],
                now=datetime(2026, 4, 22, 12, 2, tzinfo=timezone.utc),
            )
            self.assertIsNotNone(bonus)
            self.assertEqual(access.bonus_balance_for_user(222), 10)

            self.assertIsNone(
                access.award_referral_bonus_for_payment(
                    payment["payload"],
                    now=datetime(2026, 4, 22, 12, 3, tzinfo=timezone.utc),
                )
            )
            self.assertEqual(access.bonus_balance_for_user(222), 10)

    def test_access_store_phone_invite_requires_claim_approval(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "telegram_access.json"
            access = telegram_access.TelegramAccessStore(path=path, admin_user_ids={123})
            invite = access.create_invite(created_by=123, target_phone_hint="+155500011")

            with self.assertRaisesRegex(ValueError, "Phone invite requires admin approval"):
                access.accept_invite(invite["token"], user_id=333)

            claim = access.create_invite_claim(
                invite_id=invite["id"],
                claimant_tg_id=333,
                claimant_username="@phoneuser",
            )
            accepted = access.accept_invite(
                invite["token"],
                user_id=333,
                claim_id=claim["id"],
                approved_by=123,
            )

            self.assertEqual(accepted["invite"]["status"], "accepted")
            self.assertEqual(access.invite_claim_for_id(claim["id"])["status"], "approved")

    def test_access_store_user_language_persists_and_migrates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "telegram_access.json"
            path.write_text(
                '{"users": {"222": {"invited_by": 123, "client_id": "client-uuid"}}}\n',
                encoding="utf-8",
            )
            access = telegram_access.TelegramAccessStore(path=path, admin_user_ids={123})

            self.assertEqual(access.preferred_language_for_user(222, "ru-RU"), "ru")
            access.update_user_language(
                222,
                preferred_language="ru",
                telegram_language_code="ru",
                mark_prompted=True,
            )

            reloaded = telegram_access.TelegramAccessStore(path=path, admin_user_ids={123})
            record = reloaded.user_record(222)
            self.assertEqual(record["preferred_language"], "ru")
            self.assertEqual(record["telegram_language_code"], "ru")
            self.assertTrue(record["language_prompted_at"])
            self.assertEqual(reloaded.preferred_language_for_user(222), "ru")

    def test_access_store_telegram_profile_prefers_username_for_display_name(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "telegram_access.json"
            access = telegram_access.TelegramAccessStore(path=path, admin_user_ids={123})

            access.update_user_profile(
                222,
                {
                    "username": "ExampleUser",
                    "first_name": "Example",
                    "last_name": "Person",
                },
            )

            record = access.user_record(222)
            self.assertEqual(record["username"], "exampleuser")
            self.assertEqual(record["first_name"], "Example")
            self.assertEqual(record["last_name"], "Person")
            self.assertEqual(record["display_name"], "@exampleuser")
            self.assertEqual(access.display_name_for_user(222), "@exampleuser")
            self.assertEqual(
                access.desired_client_name_for_user(222, existing_name="Telegram 222"),
                "@exampleuser",
            )

    def test_access_store_telegram_profile_falls_back_to_first_and_last_name(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "telegram_access.json"
            access = telegram_access.TelegramAccessStore(path=path, admin_user_ids={123})

            access.update_user_profile(
                222,
                {
                    "first_name": "Kate",
                    "last_name": "Ivanova",
                },
            )

            record = access.user_record(222)
            self.assertEqual(record["display_name"], "Kate Ivanova")
            self.assertEqual(access.display_name_for_user(222), "Kate Ivanova")
            public = access.public_user_record(222)
            self.assertEqual(public["display_name"], "Kate Ivanova")
            self.assertEqual(public["first_name"], "Kate")
            self.assertEqual(public["last_name"], "Ivanova")

    def test_desired_client_name_preserves_existing_name_without_profile(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "telegram_access.json"
            access = telegram_access.TelegramAccessStore(path=path, admin_user_ids={123})

            access.invite_user(222, invited_by=123)

            self.assertEqual(
                access.desired_client_name_for_user(222, existing_name="Legacy Name"),
                "Legacy Name",
            )
            self.assertEqual(
                access.desired_client_name_for_user(222, default_name="Telegram 222"),
                "Telegram 222",
            )


@unittest.skipUnless(SERVICE_DEPS_AVAILABLE, "panel dependencies are not installed")
class TelegramBotTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.original_values = {
            "ROUTING_OVERRIDES_PATH": config.ROUTING_OVERRIDES_PATH,
            "XRAY_CLIENTS_PATH": config.XRAY_CLIENTS_PATH,
            "TELEGRAM_ACCESS_PATH": config.TELEGRAM_ACCESS_PATH,
            "TELEGRAM_COMMAND_DOCS_PATH": config.TELEGRAM_COMMAND_DOCS_PATH,
            "TELEGRAM_ADMIN_USER_IDS": config.TELEGRAM_ADMIN_USER_IDS,
            "TELEGRAM_ALLOWED_CHAT_IDS": config.TELEGRAM_ALLOWED_CHAT_IDS,
            "PANEL_SECRET_TOKEN": config.PANEL_SECRET_TOKEN,
            "XRAY_CLIENT_REALITY_PUBLIC_KEY": config.XRAY_CLIENT_REALITY_PUBLIC_KEY,
            "XRAY_CLIENT_REALITY_SHORT_ID": config.XRAY_CLIENT_REALITY_SHORT_ID,
            "AWG_SETTINGS_PATH": config.AWG_SETTINGS_PATH,
            "SERVER_PUBLIC_HOST": config.SERVER_PUBLIC_HOST,
            "WG_ENDPOINT_HOST": config.WG_ENDPOINT_HOST,
            "XRAY_CLIENT_SERVER": config.XRAY_CLIENT_SERVER,
        }
        config.ROUTING_OVERRIDES_PATH = str(Path(self.tmpdir.name) / "routing_overrides.json")
        config.XRAY_CLIENTS_PATH = str(Path(self.tmpdir.name) / "xray_clients.json")
        config.TELEGRAM_ACCESS_PATH = str(Path(self.tmpdir.name) / "telegram_access.json")
        config.TELEGRAM_COMMAND_DOCS_PATH = str(Path(self.tmpdir.name) / "telegram_command_docs.conf")
        config.TELEGRAM_ADMIN_USER_IDS = "12345"
        config.TELEGRAM_ALLOWED_CHAT_IDS = ""
        config.PANEL_SECRET_TOKEN = "test-token"
        config.XRAY_CLIENT_REALITY_PUBLIC_KEY = "public-key"
        config.XRAY_CLIENT_REALITY_SHORT_ID = "abcd1234"
        config.AWG_SETTINGS_PATH = str(Path(self.tmpdir.name) / "awg_settings.json")
        config.SERVER_PUBLIC_HOST = "vpn.example.com"
        config.WG_ENDPOINT_HOST = "vpn.example.com"
        config.XRAY_CLIENT_SERVER = "vpn.example.com"
        Path(config.AWG_SETTINGS_PATH).write_text(
            (
                "{\n"
                '  "endpoint_host": "vpn.example.com",\n'
                '  "endpoint_port": 34011,\n'
                '  "dns_servers": "1.1.1.1,1.0.0.1",\n'
                '  "persistent_keepalive": 25,\n'
                '  "Jc": 0,\n'
                '  "Jmin": 0,\n'
                '  "Jmax": 0,\n'
                '  "S1": 0,\n'
                '  "S2": 0,\n'
                '  "S3": 0,\n'
                '  "S4": 0,\n'
                '  "H1": 0,\n'
                '  "H2": 0,\n'
                '  "H3": 0,\n'
                '  "H4": 0,\n'
                '  "I1": "",\n'
                '  "I2": "",\n'
                '  "I3": "",\n'
                '  "I4": "",\n'
                '  "I5": ""\n'
                "}\n"
            ),
            encoding="utf-8",
        )
        self.apply_patcher = patch.object(
            main.xm,
            "apply_xray",
            return_value=types.SimpleNamespace(status="ok"),
        )
        self.apply_mock = self.apply_patcher.start()

        self.http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app),
            base_url="http://panel.test",
        )
        self.panel = telegram_bot.PanelClient(
            base_url="http://panel.test",
            token="test-token",
            http=self.http,
        )
        self.auth_headers = {"Authorization": "Bearer test-token"}
        self.telegram = RecordingTelegram()
        self.admin_user_id = 12345
        self.chat_id = self.admin_user_id
        self.command_docs = telegram_command_docs.TelegramCommandDocsStore(
            path=config.TELEGRAM_COMMAND_DOCS_PATH
        )
        self.access = telegram_access.TelegramAccessStore(
            path=config.TELEGRAM_ACCESS_PATH,
            admin_user_ids={self.admin_user_id},
        )
        self.bot = telegram_bot.TelegramVpnBot(
            panel=self.panel,
            telegram=self.telegram,
            access=self.access,
            command_docs=self.command_docs,
            bot_username="vpn_test_bot",
        )

    async def asyncTearDown(self):
        await self.http.aclose()
        self.apply_patcher.stop()
        for name, value in self.original_values.items():
            setattr(config, name, value)
        self.tmpdir.cleanup()

    def _update(
        self,
        text: str,
        user_id: int | None = None,
        chat_id: int | None = None,
        chat_type: str = "private",
        username: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
        language_code: str | None = None,
    ) -> dict:
        effective_user_id = self.admin_user_id if user_id is None else user_id
        from_user = {"id": effective_user_id}
        if username is not None:
            from_user["username"] = username
        if first_name is not None:
            from_user["first_name"] = first_name
        if last_name is not None:
            from_user["last_name"] = last_name
        if language_code is not None:
            from_user["language_code"] = language_code
        return {
            "update_id": 1,
            "message": {
                "from": from_user,
                "chat": {
                    "id": effective_user_id if chat_id is None else chat_id,
                    "type": chat_type,
                },
                "text": text,
            },
        }

    def _pre_checkout_update(
        self,
        payload: str,
        amount_stars: int,
        user_id: int,
        currency: str = "XTR",
    ) -> dict:
        return {
            "update_id": 2,
            "pre_checkout_query": {
                "id": "pre-checkout-id",
                "from": {"id": user_id},
                "currency": currency,
                "total_amount": amount_stars,
                "invoice_payload": payload,
            },
        }

    def _successful_payment_update(
        self,
        payload: str,
        amount_stars: int,
        user_id: int,
        currency: str = "XTR",
    ) -> dict:
        return {
            "update_id": 3,
            "message": {
                "from": {"id": user_id},
                "chat": {"id": user_id, "type": "private"},
                "successful_payment": {
                    "currency": currency,
                    "total_amount": amount_stars,
                    "invoice_payload": payload,
                    "telegram_payment_charge_id": "charge-id",
                },
            },
        }

    def _callback_update(
        self,
        data: str,
        user_id: int,
        chat_id: int | None = None,
    ) -> dict:
        return {
            "update_id": 4,
            "callback_query": {
                "id": "callback-id",
                "from": {"id": user_id},
                "data": data,
                "message": {
                    "chat": {
                        "id": user_id if chat_id is None else chat_id,
                        "type": "private",
                    }
                },
            },
        }

    def _custom_command_docs_raw(self) -> str:
        return """[help.admin]
/help :: custom admin help
/status :: custom admin status
/apps :: custom admin apps
/install :: custom admin install
/instruction :: custom admin instruction
/language :: custom admin language hint
/clients :: custom admin clients list
/doctor :: custom doctor help
/grant <telegram-user-id> [days] :: custom admin grant help
/invite <@username or +phone or telegram-user-id> :: custom admin invite help

[help.user.en]
/help :: custom user help
/status :: custom status help
/apps :: custom app links command
/install :: custom install command
/instruction :: custom instruction command
/language :: custom language command

[help.user.ru]
/help :: пользовательская справка
/status :: пользовательская подсказка статуса
/apps :: пользовательские ссылки на приложения
/install :: пользовательская установка
/instruction :: пользовательская инструкция
/language :: пользовательский выбор языка

[text.apps.en]
Custom EN apps
https://example.test/apps

[text.apps.ru]
Пользовательские приложения
https://example.test/ru-apps

[text.install.en]
Custom EN install
Step 1

[text.install.ru]
Пользовательская установка
Шаг 1

[text.instruction.en]
Custom EN instruction
Open the bot
Install the app
Use /link or /qr

[text.instruction.ru]
Пользовательская инструкция
Шаг А
Шаг Б

[menu.user.root.en]
subscription :: Membership :: submenu:user.subscription
setup :: Setup :: submenu:user.setup
help :: Help :: command:/help
language :: Language :: command:/language
admin :: Admin :: submenu:admin.root

[menu.user.root.ru]
subscription :: Подписка :: submenu:user.subscription
setup :: Настройка :: submenu:user.setup
help :: Справка :: command:/help
language :: Язык :: command:/language
admin :: Admin :: submenu:admin.root

[menu.user.subscription.en]
status :: Status :: command:/status
back :: Back :: back:user.root

[menu.user.subscription.ru]
status :: Статус :: command:/status
back :: Назад :: back:user.root

[menu.user.config.en]
help :: Help :: command:/help
back :: Back :: back:user.root

[menu.user.config.ru]
help :: Справка :: command:/help
back :: Назад :: back:user.root

[menu.user.setup.en]
apps :: Apps :: command:/apps
install :: Install :: command:/install
instruction :: Instruction :: command:/instruction
back :: Back :: back:user.root

[menu.user.setup.ru]
apps :: Приложения :: command:/apps
install :: Установка :: command:/install
instruction :: Инструкция :: command:/instruction
back :: Назад :: back:user.root

[menu.admin.root]
clients :: Clients :: submenu:admin.clients
users :: Users :: submenu:admin.users
invites :: Invites :: submenu:admin.invites
billing :: Billing :: submenu:admin.billing
broadcast :: Broadcast :: submenu:admin.broadcast
system :: System :: submenu:admin.system
back :: Back :: back:user.root

[menu.admin.clients]
clients :: Clients list :: command:/clients
back :: Back :: back:admin.root

[menu.admin.users]
grant :: Grant :: helper:/grant
back :: Back :: back:admin.root

[menu.admin.invites]
invite :: Invite :: helper:/invite
back :: Back :: back:admin.root

[menu.admin.billing]
help :: Help :: command:/help
back :: Back :: back:admin.root

[menu.admin.broadcast]
help :: Help :: command:/help
back :: Back :: back:admin.root

[menu.admin.system]
doctor :: Doctor :: command:/doctor
back :: Back :: back:admin.root
"""

    def _callback_update(
        self,
        data: str,
        user_id: int | None = None,
        chat_id: int | None = None,
    ) -> dict:
        effective_user_id = self.admin_user_id if user_id is None else user_id
        return {
            "update_id": 4,
            "callback_query": {
                "id": "callback-id",
                "from": {"id": effective_user_id},
                "message": {
                    "chat": {
                        "id": effective_user_id if chat_id is None else chat_id,
                        "type": "private",
                    }
                },
                "data": data,
            },
        }

    async def test_new_command_creates_panel_client_and_returns_share_link(self):
        await self.bot.handle_update(self._update("/new Bot Smoke"))

        clients = await self.panel.list_clients()
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0]["name"], "Bot Smoke")
        self.assertTrue(clients[0]["enabled"])
        self.assertTrue(any("vless://" in text for _, text in self.telegram.messages))
        self.assertTrue(
            any("Created and applied VLESS client" in text for _, text in self.telegram.messages)
        )
        self.apply_mock.assert_called_once()

    async def test_disable_and_delete_commands_update_panel_clients(self):
        created = await self.panel.create_client("Disposable")

        await self.bot.handle_update(self._update(f"/disable {created['id']}"))
        disabled = await self.panel.get_client(created["id"])
        self.assertFalse(disabled["enabled"])
        self.assertTrue(any("disabled" in text for _, text in self.telegram.messages))

        await self.bot.handle_update(self._update(f"/delete {created['id']}"))
        self.assertEqual(await self.panel.list_clients(), [])

    async def test_panel_api_failure_is_sent_to_chat(self):
        async def fail_create(name: str):
            raise telegram_bot.PanelApiError("apply failed")

        self.panel.create_client = fail_create

        await self.bot.handle_update(self._update("/new Broken"))

        self.assertTrue(
            any("Panel API error: apply failed" in text for _, text in self.telegram.messages)
        )

    async def test_unknown_user_without_invite_is_ignored(self):
        await self.bot.handle_update(self._update("/new Should Not Exist", user_id=999))

        self.assertEqual(await self.panel.list_clients(), [])
        self.assertEqual(self.access.public_lead_records(), [])
        self.assertEqual(self.telegram.messages, [])

    async def test_known_user_ru_system_language_gets_prompt_and_ru_status(self):
        user_id = 222
        self.access.invite_user(user_id, invited_by=self.admin_user_id)

        await self.bot.handle_update(self._update("/status", user_id=user_id, language_code="ru"))

        record = self.access.user_record(user_id)
        self.assertEqual(record["preferred_language"], "ru")
        self.assertEqual(record["telegram_language_code"], "ru")
        self.assertTrue(record["language_prompted_at"])
        self.assertIn("Выберите язык", self.telegram.messages[0][1])
        self.assertEqual(
            self.telegram.reply_markups[0]["inline_keyboard"][0][0]["callback_data"],
            "language:set:ru",
        )
        self.assertTrue(any("Подписка активна: нет" in text for _, text in self.telegram.messages))

    async def test_known_user_unsupported_system_language_defaults_to_english(self):
        user_id = 222
        self.access.invite_user(user_id, invited_by=self.admin_user_id)

        await self.bot.handle_update(self._update("/status", user_id=user_id, language_code="de"))

        record = self.access.user_record(user_id)
        self.assertEqual(record["preferred_language"], "en")
        self.assertEqual(record["telegram_language_code"], "de")
        self.assertTrue(any("Subscription active: False" in text for _, text in self.telegram.messages))

    async def test_language_command_and_callback_switch_language(self):
        user_id = 222
        self.access.invite_user(user_id, invited_by=self.admin_user_id)

        await self.bot.handle_update(self._update("/language", user_id=user_id, language_code="en"))
        self.assertEqual(self.access.user_record(user_id)["preferred_language"], "en")
        self.assertTrue(self.telegram.reply_markups[-1])

        await self.bot.handle_update(
            self._callback_update("language:set:ru", user_id=user_id)
        )

        self.assertEqual(self.access.user_record(user_id)["preferred_language"], "ru")
        self.assertEqual(self.telegram.callback_answers[-1]["text"], "Язык переключён на русский.")
        self.assertEqual(self.telegram.messages[-1], (user_id, "Язык переключён на русский."))

    async def test_language_callback_ignores_unknown_user(self):
        await self.bot.handle_update(self._callback_update("language:set:ru", user_id=999))

        self.assertEqual(self.telegram.messages, [])
        self.assertEqual(self.telegram.callback_answers, [])

    async def test_private_known_user_gets_root_menu_keyboard(self):
        user_id = 222
        self.access.invite_user(user_id, invited_by=self.admin_user_id)
        self.access.update_user_language(
            user_id,
            preferred_language="en",
            telegram_language_code="en",
            mark_prompted=True,
        )

        await self.bot.handle_update(self._update("/status", user_id=user_id, language_code="en"))

        self.assertEqual(
            [button["text"] for row in self.telegram.reply_markups[-1]["keyboard"] for button in row],
            ["Subscription", "Instruction", "Apps & Setup", "Support"],
        )

    async def test_admin_root_menu_includes_admin_button(self):
        await self.bot.handle_update(self._update("/status", user_id=self.admin_user_id))

        self.assertEqual(
            [button["text"] for row in self.telegram.reply_markups[-1]["keyboard"] for button in row],
            ["Subscription", "Instruction", "Apps & Setup", "Support", "Admin"],
        )

    async def test_root_menu_text_opens_submenu(self):
        user_id = 222
        self.access.invite_user(user_id, invited_by=self.admin_user_id)
        self.access.update_user_language(
            user_id,
            preferred_language="en",
            telegram_language_code="en",
            mark_prompted=True,
        )

        await self.bot.handle_update(self._update("Subscription", user_id=user_id))

        self.assertEqual(self.telegram.messages[-1], (user_id, "Subscription\n\nChoose an action:"))
        self.assertEqual(
            self.telegram.reply_markups[-1]["inline_keyboard"][0][0]["callback_data"],
            "menu:tap:user.subscription:status",
        )

    @unittest.skip("legacy root menu labels were replaced by instruction/support buttons")
    async def test_menu_back_returns_to_root_prompt(self):
        user_id = 222
        self.access.invite_user(user_id, invited_by=self.admin_user_id)
        self.access.update_user_language(
            user_id,
            preferred_language="ru",
            telegram_language_code="ru",
            mark_prompted=True,
        )

        await self.bot.handle_update(self._callback_update("menu:open:user.root", user_id=user_id))

        self.assertEqual(
            self.telegram.messages[-1],
            (user_id, "Используйте кнопки ниже, чтобы открыть доступные разделы."),
        )
        self.assertEqual(
            [button["text"] for row in self.telegram.reply_markups[-1]["keyboard"] for button in row],
            ["Подписка", "Конфиг", "Приложения и установка", "Справка", "Язык"],
        )

    async def test_menu_back_returns_updated_root_prompt(self):
        user_id = 222
        self.access.invite_user(user_id, invited_by=self.admin_user_id)
        self.access.update_user_language(
            user_id,
            preferred_language="ru",
            telegram_language_code="ru",
            mark_prompted=True,
        )

        await self.bot.handle_update(self._callback_update("menu:open:user.root", user_id=user_id))

        self.assertEqual(
            self.telegram.messages[-1],
            (user_id, "Используйте кнопки ниже, чтобы открыть доступные разделы."),
        )
        self.assertEqual(
            [button["text"] for row in self.telegram.reply_markups[-1]["keyboard"] for button in row],
            ["Подписка", "Инструкция", "Приложения и установка", "Поддержка"],
        )

    async def test_menu_command_callback_executes_status(self):
        user_id = 222
        self.access.invite_user(user_id, invited_by=self.admin_user_id)
        self.access.update_user_language(
            user_id,
            preferred_language="en",
            telegram_language_code="en",
            mark_prompted=True,
        )

        await self.bot.handle_update(
            self._callback_update("menu:tap:user.subscription:status", user_id=user_id)
        )

        self.assertTrue(any("Subscription active: False" in text for _, text in self.telegram.messages))

    async def test_menu_command_callback_executes_instruction(self):
        user_id = 222
        self.access.invite_user(user_id, invited_by=self.admin_user_id)
        self.access.update_user_language(
            user_id,
            preferred_language="ru",
            telegram_language_code="ru",
            mark_prompted=True,
        )

        await self.bot.handle_update(
            self._callback_update("menu:tap:user.root:instruction", user_id=user_id)
        )

        self.assertIn(
            "Подробная инструкция с самого начала:",
            self.telegram.messages[-1][1],
        )

    async def test_menu_helper_cards_for_invite_and_grant(self):
        await self.bot.handle_update(
            self._callback_update("menu:tap:admin.invites:invite", user_id=self.admin_user_id)
        )
        await self.bot.handle_update(
            self._callback_update("menu:tap:admin.users:grant", user_id=self.admin_user_id)
        )

        self.assertIn("Usage:", self.telegram.messages[-2][1])
        self.assertIn("/invite <@username or +phone or telegram-user-id>", self.telegram.messages[-2][1])
        self.assertIn("Send this command manually with arguments.", self.telegram.messages[-2][1])
        self.assertIn("/grant <telegram-user-id> [days]", self.telegram.messages[-1][1])

    async def test_regular_user_cannot_open_admin_menu(self):
        user_id = 222
        self.access.invite_user(user_id, invited_by=self.admin_user_id)
        self.access.update_user_language(
            user_id,
            preferred_language="en",
            telegram_language_code="en",
            mark_prompted=True,
        )

        await self.bot.handle_update(self._callback_update("menu:open:admin.root", user_id=user_id))

        self.assertEqual(self.telegram.messages, [])
        self.assertEqual(self.telegram.callback_answers[-1]["text"], "Access denied.")
        self.assertTrue(self.telegram.callback_answers[-1]["show_alert"])

    async def test_admin_can_list_link_and_doctor(self):
        created = await self.panel.create_client("Admin Client")

        await self.bot.handle_update(self._update("/clients"))
        await self.bot.handle_update(self._update(f"/link {created['id']}"))
        await self.bot.handle_update(self._update("/doctor"))

        self.assertTrue(any("VLESS clients:" in text for _, text in self.telegram.messages))
        self.assertTrue(
            any(
                "The next message will contain the raw link for quick copy." in text
                for _, text in self.telegram.messages
            )
        )
        self.assertTrue(any(text.startswith("vless://") for _, text in self.telegram.messages))
        self.assertTrue(any("Xray doctor:" in text for _, text in self.telegram.messages))
        self.assertFalse(any("Выберите язык" in text for _, text in self.telegram.messages))

    async def test_known_user_can_create_pending_invite_by_username(self):
        known_user_id = 222
        self.access.invite_user(known_user_id, invited_by=self.admin_user_id)

        await self.bot.handle_update(
            self._update("/invite @new_user", user_id=known_user_id)
        )

        invites = self.access.load()["invites"]
        self.assertEqual(len(invites), 1)
        invite = next(iter(invites.values()))
        self.assertEqual(invite["status"], "pending")
        self.assertEqual(invite["created_by"], known_user_id)
        self.assertEqual(invite["target_username_hint"], "@new_user")
        self.assertTrue(any("https://t.me/vpn_test_bot?start=" in text for _, text in self.telegram.messages))

    async def test_known_user_can_create_pending_invite_by_phone(self):
        known_user_id = 222
        self.access.invite_user(known_user_id, invited_by=self.admin_user_id)

        await self.bot.handle_update(self._update("/invite +1 555 000 11", user_id=known_user_id))

        invite = next(iter(self.access.load()["invites"].values()))
        self.assertEqual(invite["target_phone_hint"], "+155500011")
        self.assertFalse(self.access.is_known_user(333))

    async def test_start_invite_accepts_trial_creates_client_notifies_creator_and_is_idempotent(self):
        known_user_id = 222
        invited_user_id = 333
        self.access.invite_user(known_user_id, invited_by=self.admin_user_id)
        await self.bot.handle_update(self._update("/invite @trial_user", user_id=known_user_id))
        invite = next(iter(self.access.load()["invites"].values()))
        self.telegram.messages.clear()

        await self.bot.handle_update(
            self._update(
                f"/start {invite['token']}",
                user_id=invited_user_id,
                username="trial_user",
            )
        )

        accepted = next(iter(self.access.load()["invites"].values()))
        self.assertEqual(accepted["status"], "accepted")
        self.assertEqual(accepted["target_user_id"], invited_user_id)
        self.assertTrue(self.access.is_subscription_active(invited_user_id))
        self.assertTrue(self.access.is_trial_active(invited_user_id))
        self.assertIsNotNone(self.access.client_for_user(invited_user_id))
        self.assertEqual(len(await self.panel.list_clients()), 1)
        self.assertTrue(
            any(
                chat_id == invited_user_id and "Invite accepted" in text and "/help" in text
                for chat_id, text in self.telegram.messages
            )
        )
        self.assertTrue(
            any(
                chat_id == known_user_id and "Invite activated" in text and invite["id"] in text
                for chat_id, text in self.telegram.messages
            )
        )

        self.telegram.messages.clear()
        await self.bot.handle_update(
            self._update(
                f"/start {invite['token']}",
                user_id=invited_user_id,
                username="trial_user",
            )
        )

        accepted_again = next(iter(self.access.load()["invites"].values()))
        self.assertEqual(accepted_again["status"], "accepted")
        self.assertEqual(accepted_again["used_count"], 1)
        self.assertEqual(len(await self.panel.list_clients()), 1)
        self.assertTrue(
            any(
                chat_id == invited_user_id and "Invite already activated" in text and "/help" in text
                for chat_id, text in self.telegram.messages
            )
        )
        self.assertFalse(
            any(
                chat_id == invited_user_id and "Invite is not available" in text
                for chat_id, text in self.telegram.messages
            )
        )

    async def test_start_invite_username_mismatch_creates_claim_and_notifies_admin(self):
        known_user_id = 222
        interceptor_id = 444
        self.access.invite_user(known_user_id, invited_by=self.admin_user_id)
        await self.bot.handle_update(self._update("/invite @real_user", user_id=known_user_id))
        invite = next(iter(self.access.load()["invites"].values()))
        self.telegram.messages.clear()

        await self.bot.handle_update(
            self._update(
                f"/start {invite['token']}",
                user_id=interceptor_id,
                username="wrong_user",
            )
        )

        stored = next(iter(self.access.load()["invites"].values()))
        self.assertEqual(stored["status"], "pending")
        self.assertFalse(self.access.is_known_user(interceptor_id))
        claims = self.access.public_invite_claim_records()
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0]["status"], "pending")
        self.assertEqual(claims[0]["claimant_tg_id"], interceptor_id)
        self.assertEqual(await self.panel.list_clients(), [])
        self.assertFalse(any(chat_id == interceptor_id for chat_id, _ in self.telegram.messages))
        self.assertTrue(
            any(
                chat_id == self.admin_user_id and "Invite claim requires review" in text
                for chat_id, text in self.telegram.messages
            )
        )
        self.assertTrue(
            any(
                isinstance(markup, dict)
                and markup.get("inline_keyboard")
                and markup["inline_keyboard"][0][0]["callback_data"].startswith("invite_claim:approve:")
                for markup in self.telegram.reply_markups
            )
        )

    async def test_start_invite_by_target_user_id_auto_approves(self):
        invited_user_id = 333
        invite = self.access.create_invite(
            created_by=self.admin_user_id,
            target_user_id=invited_user_id,
        )

        await self.bot.handle_update(
            self._update(f"/start {invite['token']}", user_id=invited_user_id, language_code="ru")
        )

        stored = self.access.invite_for_id(invite["id"])
        record = self.access.user_record(invited_user_id)
        self.assertEqual(stored["status"], "accepted")
        self.assertEqual(stored["target_user_id"], invited_user_id)
        self.assertEqual(stored["used_count"], 1)
        self.assertEqual(record["preferred_language"], "ru")
        self.assertEqual(record["telegram_language_code"], "ru")
        self.assertTrue(self.access.is_trial_active(invited_user_id))
        self.assertIsNotNone(self.access.client_for_user(invited_user_id))
        self.assertTrue(any("Приглашение принято" in text for _, text in self.telegram.messages))

    async def test_phone_invite_never_auto_approves_and_can_be_approved(self):
        creator_id = 222
        claimant_id = 555
        self.access.invite_user(creator_id, invited_by=self.admin_user_id)
        invite = self.access.create_invite(created_by=creator_id, target_phone_hint="+155500011")

        await self.bot.handle_update(
            self._update(f"/start {invite['token']}", user_id=claimant_id, username="phoneuser")
        )

        self.assertFalse(self.access.is_known_user(claimant_id))
        self.assertEqual(await self.panel.list_clients(), [])
        claim = self.access.public_invite_claim_records()[0]
        self.assertEqual(claim["status"], "pending")
        self.assertEqual(claim["claimant_tg_id"], claimant_id)
        self.assertFalse(any(chat_id == claimant_id for chat_id, _ in self.telegram.messages))

        await self.bot.handle_update(
            self._callback_update(f"invite_claim:approve:{claim['id']}")
        )

        approved_claim = self.access.invite_claim_for_id(claim["id"])
        stored = self.access.invite_for_id(invite["id"])
        self.assertEqual(approved_claim["status"], "approved")
        self.assertEqual(stored["status"], "accepted")
        self.assertEqual(stored["target_user_id"], claimant_id)
        self.assertTrue(self.access.is_trial_active(claimant_id))
        self.assertIsNotNone(self.access.client_for_user(claimant_id))
        self.assertEqual(len(await self.panel.list_clients()), 1)
        self.assertTrue(
            any(
                chat_id == claimant_id and "Invite accepted" in text and "/help" in text
                for chat_id, text in self.telegram.messages
            )
        )
        self.assertTrue(any("Invite claim approved" in text for _, text in self.telegram.messages))
        self.assertTrue(
            any(
                chat_id == creator_id and "Invite activated" in text and invite["id"] in text
                for chat_id, text in self.telegram.messages
            )
        )

    async def test_invite_claim_reject_keeps_user_ignored(self):
        claimant_id = 556
        invite = self.access.create_invite(
            created_by=self.admin_user_id,
            target_username_hint="@real_user",
        )
        await self.bot.handle_update(
            self._update(f"/start {invite['token']}", user_id=claimant_id, username="wrong_user")
        )
        claim = self.access.public_invite_claim_records()[0]

        await self.bot.handle_update(
            self._callback_update(f"invite_claim:reject:{claim['id']}")
        )

        rejected_claim = self.access.invite_claim_for_id(claim["id"])
        stored = self.access.invite_for_id(invite["id"])
        self.assertEqual(rejected_claim["status"], "rejected")
        self.assertEqual(stored["status"], "pending")
        self.assertFalse(self.access.is_known_user(claimant_id))
        self.assertEqual(await self.panel.list_clients(), [])

    async def test_reused_and_expired_invites_do_not_grant_access(self):
        first_user_id = 333
        second_user_id = 444
        invite = self.access.create_invite(
            created_by=self.admin_user_id,
            target_username_hint="@first_user",
        )
        await self.bot.handle_update(
            self._update(f"/start {invite['token']}", user_id=first_user_id, username="first_user")
        )
        self.telegram.messages.clear()

        await self.bot.handle_update(
            self._update(f"/start {invite['token']}", user_id=second_user_id, username="first_user")
        )

        self.assertFalse(self.access.is_known_user(second_user_id))
        self.assertEqual(len(await self.panel.list_clients()), 1)
        self.assertFalse(any(chat_id == second_user_id for chat_id, _ in self.telegram.messages))

        expired_user_id = 777
        expired = self.access.create_invite(
            created_by=self.admin_user_id,
            target_username_hint="@expired_user",
        )
        payload = self.access.load()
        payload["invites"][expired["id"]]["expires_at"] = "2026-01-01T00:00:00Z"
        self.access.save(payload)

        await self.bot.handle_update(
            self._update(
                f"/start {expired['token']}",
                user_id=expired_user_id,
                username="expired_user",
            )
        )

        self.assertFalse(self.access.is_known_user(expired_user_id))
        self.assertFalse(any(chat_id == expired_user_id for chat_id, _ in self.telegram.messages))

    async def test_start_invite_by_admin_only_checks_without_mutation(self):
        known_user_id = 222
        self.access.invite_user(known_user_id, invited_by=self.admin_user_id)
        await self.bot.handle_update(self._update("/invite @real_user", user_id=known_user_id))
        invite = next(iter(self.access.load()["invites"].values()))
        self.telegram.messages.clear()

        await self.bot.handle_update(
            self._update(
                f"/start {invite['token']}",
                user_id=self.admin_user_id,
                username="admin_user",
            )
        )

        stored = next(iter(self.access.load()["invites"].values()))
        self.assertEqual(stored["status"], "pending")
        self.assertEqual(await self.panel.list_clients(), [])
        self.assertTrue(
            any("Invite check only. No changes applied." in text for _, text in self.telegram.messages)
        )

    async def test_invited_user_without_config_gets_not_assigned_message(self):
        user_id = 222
        self.access.invite_user(user_id, invited_by=self.admin_user_id)

        await self.bot.handle_update(self._update("/link", user_id=user_id))

        self.assertTrue(
            any("Subscription is not active" in text for _, text in self.telegram.messages)
        )

    async def test_bound_user_gets_only_own_config(self):
        user_id = 222
        own = await self.panel.create_client("Own Client")
        other = await self.panel.create_client("Other Client")
        self.access.invite_user(user_id, invited_by=self.admin_user_id)
        self.access.bind_client(user_id, own["id"], invited_by=self.admin_user_id)
        self.access.grant_subscription(user_id)

        await self.bot.handle_update(self._update("/link", user_id=user_id))
        self.assertTrue(
            any(
                "The next message will contain the raw link for quick copy." in text
                for _, text in self.telegram.messages
            )
        )
        self.assertTrue(any(text.startswith("vless://") for _, text in self.telegram.messages))
        self.assertTrue(any("/help" in text for _, text in self.telegram.messages))

        await self.bot.handle_update(self._update("/qr", user_id=user_id))
        await self.bot.handle_update(self._update("/bundle", user_id=user_id))
        self.assertEqual(len(self.telegram.photos), 1)
        self.assertEqual(len(self.telegram.documents), 1)

        self.telegram.messages.clear()
        await self.bot.handle_update(self._update(f"/link {other['id']}", user_id=user_id))
        self.assertEqual(self.telegram.messages, [(user_id, "Access denied.")])

    async def test_bound_user_can_get_wg_and_awg_artifacts(self):
        user_id = 222
        own = await self.panel.create_client("Own Client")
        self.access.invite_user(user_id, invited_by=self.admin_user_id)
        self.access.bind_client(user_id, own["id"], invited_by=self.admin_user_id)
        self.access.grant_subscription(user_id)
        peer = {
            "public_key": "peer-public-key",
            "name": "@buyer",
            "deactivated": False,
        }

        with patch.object(self.panel, "create_peer", new=AsyncMock(return_value=peer)) as create_peer_mock, patch.object(
            self.panel,
            "get_peer",
            new=AsyncMock(return_value=peer),
        ) as get_peer_mock, patch.object(
            self.panel,
            "update_peer",
            new=AsyncMock(return_value=peer),
        ), patch.object(
            self.panel,
            "set_peer_enabled",
            new=AsyncMock(return_value=peer),
        ), patch.object(
            self.panel,
            "get_peer_config",
            new=AsyncMock(
                side_effect=[
                    telegram_bot.Download("buyer-wg.conf", b"wg-conf", "text/plain"),
                    telegram_bot.Download("buyer-awg.conf", b"awg-conf", "text/plain"),
                ]
            ),
        ) as get_peer_config_mock, patch.object(
            self.panel,
            "get_peer_qr",
            new=AsyncMock(return_value=telegram_bot.Download("buyer-wg.png", b"png", "image/png")),
        ) as get_peer_qr_mock:
            await self.bot.handle_update(self._update("/wg", user_id=user_id))
            await self.bot.handle_update(self._update("/awg", user_id=user_id))

        create_peer_mock.assert_awaited_once()
        get_peer_mock.assert_awaited_once_with("peer-public-key")
        self.assertEqual(get_peer_config_mock.await_count, 2)
        get_peer_qr_mock.assert_awaited_once()
        self.assertEqual(self.access.peer_for_user(user_id), "peer-public-key")
        self.assertEqual(len(self.telegram.documents), 2)
        self.assertEqual(len(self.telegram.photos), 1)
        self.assertTrue(any("WireGuard config" in text for _, text in self.telegram.messages))
        self.assertTrue(any("AmneziaWG config" in text for _, text in self.telegram.messages))

    async def test_panel_client_peer_artifacts_support_public_keys_with_slashes(self):
        peer = {
            "public_key": "peer/public+key=",
            "name": "Slash Peer",
            "deactivated": False,
        }
        peer_conf = (
            "[Interface]\n"
            "PrivateKey = private-key\n"
            "Address = 10.8.0.2/32\n\n"
            "[Peer]\n"
            "PublicKey = server-key\n"
            "Endpoint = vpn.example.com:34011\n"
            "AllowedIPs = 0.0.0.0/0\n"
        )

        with patch.object(
            main.vm,
            "get_all_peers",
            return_value=[
                types.SimpleNamespace(
                    public_key=peer["public_key"],
                    protocol="wg",
                    name=peer["name"],
                    vpn_ip="10.8.0.2",
                    status="never",
                    created_at="2026-04-27T10:00:00+00:00",
                )
            ],
        ), patch.object(main.vm, "get_client_conf", return_value=peer_conf):
            config_download = await self.panel.get_peer_config(peer["public_key"], protocol="amneziawg")
            qr_download = await self.panel.get_peer_qr(peer["public_key"], protocol="wg", peer_name=peer["name"])

        self.assertEqual(config_download.filename, "Slash-Peer.conf")
        self.assertIn(b"Endpoint = vpn.example.com:34011", config_download.content)
        self.assertEqual(qr_download.filename, "Slash-Peer-wg.png")
        self.assertEqual(qr_download.content_type, "image/png")

    async def test_wg_and_awg_require_active_subscription(self):
        user_id = 222
        own = await self.panel.create_client("Own Client")
        self.access.invite_user(user_id, invited_by=self.admin_user_id)
        self.access.bind_client(user_id, own["id"], invited_by=self.admin_user_id)
        self.access.update_user_language(
            user_id,
            preferred_language="en",
            telegram_language_code="en",
            mark_prompted=True,
        )

        await self.bot.handle_update(self._update("/wg", user_id=user_id))
        await self.bot.handle_update(self._update("/awg", user_id=user_id))

        self.assertFalse(self.access.peer_for_user(user_id))
        self.assertEqual(len(self.telegram.documents), 0)
        self.assertTrue(all("Subscription is not active" in text for _, text in self.telegram.messages))

    async def test_support_command_creates_ticket_and_notifies_admin(self):
        user_id = 222
        self.access.invite_user(user_id, invited_by=self.admin_user_id)
        self.access.update_user_language(
            user_id,
            preferred_language="en",
            telegram_language_code="en",
            mark_prompted=True,
        )

        await self.bot.handle_update(self._update("/support Need help with setup", user_id=user_id))

        tickets = self.access.public_support_ticket_records()
        self.assertEqual(len(tickets), 1)
        self.assertEqual(tickets[0]["ticket_id"], "T000001")
        self.assertEqual(tickets[0]["message_count"], 1)
        self.assertTrue(any(chat_id == user_id and "Support ticket T000001 created" in text for chat_id, text in self.telegram.messages))
        self.assertTrue(any(chat_id == self.admin_user_id and "New support ticket: T000001" in text for chat_id, text in self.telegram.messages))

    async def test_support_compose_prompt_captures_next_message(self):
        user_id = 222
        self.access.invite_user(user_id, invited_by=self.admin_user_id)
        self.access.update_user_language(
            user_id,
            preferred_language="en",
            telegram_language_code="en",
            mark_prompted=True,
        )

        await self.bot.handle_update(self._update("/support", user_id=user_id))
        await self.bot.handle_update(self._update("The app does not import my config", user_id=user_id))

        self.assertFalse(self.access.support_compose_started_at_for_user(user_id))
        tickets = self.access.public_support_ticket_records()
        self.assertEqual(len(tickets), 1)
        self.assertEqual(tickets[0]["message_count"], 1)
        self.assertIn("Write one text message with your question for support.", self.telegram.messages[0][1])
        self.assertTrue(any(chat_id == user_id and "Support ticket T000001 created" in text for chat_id, text in self.telegram.messages))
        self.assertTrue(any(chat_id == self.admin_user_id and "New support ticket: T000001" in text for chat_id, text in self.telegram.messages))

    async def test_admin_ticket_commands_reply_and_archive(self):
        user_id = 222
        self.access.invite_user(user_id, invited_by=self.admin_user_id)
        self.access.update_user_profile(user_id, {"username": "buyer", "first_name": "Buyer"})
        self.access.create_or_append_support_ticket(user_id, "I need help", author="user")
        self.telegram.messages.clear()

        await self.bot.handle_update(self._update("/tickets"))
        await self.bot.handle_update(self._update("/ticket T000001"))
        await self.bot.handle_update(self._update("/replyticket T000001 Hello from admin"))
        await self.bot.handle_update(self._update("/archiveticket T000001"))

        self.assertTrue(any(chat_id == self.admin_user_id and "Support queue:" in text for chat_id, text in self.telegram.messages))
        self.assertTrue(any(chat_id == self.admin_user_id and "Support ticket: T000001" in text for chat_id, text in self.telegram.messages))
        self.assertTrue(any(chat_id == user_id and "Support reply for T000001" in text for chat_id, text in self.telegram.messages))
        self.assertTrue(any(chat_id == user_id and "T000001" in text and "/support" in text for chat_id, text in self.telegram.messages))
        self.assertEqual(self.access.public_support_ticket_detail("T000001")["status"], "archived")

    async def test_user_cannot_run_admin_commands(self):
        user_id = 222
        self.access.invite_user(user_id, invited_by=self.admin_user_id)

        await self.bot.handle_update(self._update("/clients", user_id=user_id))

        self.assertEqual(self.telegram.messages[-1], (user_id, "Access denied."))

    async def test_config_commands_do_not_leak_in_non_private_chat(self):
        user_id = 222
        own = await self.panel.create_client("Own Client")
        self.access.invite_user(user_id, invited_by=self.admin_user_id)
        self.access.bind_client(user_id, own["id"], invited_by=self.admin_user_id)

        await self.bot.handle_update(
            self._update("/link", user_id=user_id, chat_id=-100, chat_type="group")
        )

        self.assertEqual(len(self.telegram.messages), 1)
        self.assertEqual(self.telegram.messages[0][0], -100)
        self.assertIn("Use private chat", self.telegram.messages[0][1])
        self.assertNotIn("vless://", self.telegram.messages[0][1])

    async def test_admin_bind_and_newfor_bind_clients_to_users(self):
        user_id = 222
        created = await self.panel.create_client("Existing Client")

        await self.bot.handle_update(self._update(f"/bind {user_id} {created['id']}"))
        self.assertEqual(self.access.client_for_user(user_id), created["id"])

        new_user_id = 333
        await self.bot.handle_update(self._update(f"/newfor {new_user_id} New For User"))
        bound_client_id = self.access.client_for_user(new_user_id)
        self.assertIsNotNone(bound_client_id)
        self.assertTrue(self.access.is_subscription_active(new_user_id))
        self.assertTrue(any("Bound to Telegram user: 333" in text for _, text in self.telegram.messages))

    async def test_admin_newfor_is_idempotent_for_retried_same_name(self):
        user_id = 333

        await self.bot.handle_update(self._update(f"/newfor {user_id} Elena_new"))
        first_client_id = self.access.client_for_user(user_id)
        self.assertIsNotNone(first_client_id)

        clients_after_first = await self.panel.list_clients()
        self.assertEqual(len(clients_after_first), 1)

        self.telegram.messages.clear()
        await self.bot.handle_update(self._update(f"/newfor {user_id} Elena_new"))

        clients_after_retry = await self.panel.list_clients()
        self.assertEqual(len(clients_after_retry), 1)
        self.assertEqual(self.access.client_for_user(user_id), first_client_id)
        self.assertTrue(
            any("Client already existed and remains bound to this Telegram user." in text for _, text in self.telegram.messages)
        )

    async def test_status_pay_and_successful_payment_activate_subscription(self):
        user_id = 222
        self.access.invite_user(user_id, invited_by=self.admin_user_id)

        await self.bot.handle_update(self._update("/status", user_id=user_id))
        await self.bot.handle_update(self._update("/pay", user_id=user_id))

        self.assertTrue(any("Subscription active: False" in text for _, text in self.telegram.messages))
        self.assertEqual(len(self.telegram.invoices), 0)
        self.assertTrue(any("Choose subscription period:" in text for _, text in self.telegram.messages))

        await self.bot.handle_update(self._callback_update(f"pay:months:{user_id}:1", user_id=user_id))
        self.assertEqual(len(self.telegram.invoices), 1)
        invoice = self.telegram.invoices[0]
        self.assertEqual(invoice["chat_id"], user_id)
        self.assertEqual(invoice["amount_stars"], 100)

        await self.bot.handle_update(
            self._pre_checkout_update(invoice["payload"], amount_stars=100, user_id=user_id)
        )
        self.assertEqual(self.telegram.pre_checkout_answers[-1]["ok"], True)

        await self.bot.handle_update(
            self._successful_payment_update(invoice["payload"], amount_stars=100, user_id=user_id)
        )

        self.assertTrue(self.access.is_subscription_active(user_id))
        self.assertIsNotNone(self.access.client_for_user(user_id))
        self.assertEqual(len(await self.panel.list_clients()), 1)
        self.assertTrue(any("Payment received." in text for _, text in self.telegram.messages))

    async def test_trial_payment_awards_referral_bonus_and_bonus_reduces_next_invoice(self):
        inviter_id = 222
        invited_user_id = 333
        self.access.invite_user(inviter_id, invited_by=self.admin_user_id)

        await self.bot.handle_update(self._update("/invite @buyer", user_id=inviter_id))
        invite = next(iter(self.access.load()["invites"].values()))
        await self.bot.handle_update(
            self._update(f"/start {invite['token']}", user_id=invited_user_id, username="buyer")
        )

        await self.bot.handle_update(self._update("/pay", user_id=invited_user_id))
        await self.bot.handle_update(
            self._callback_update(f"pay:months:{invited_user_id}:1", user_id=invited_user_id)
        )
        invoice = self.telegram.invoices[-1]
        await self.bot.handle_update(
            self._successful_payment_update(invoice["payload"], amount_stars=100, user_id=invited_user_id)
        )

        self.assertEqual(self.access.bonus_balance_for_user(inviter_id), 10)
        self.assertEqual(len(self.access.public_bonus_ledger_records(user_id=inviter_id)), 1)

        await self.bot.handle_update(
            self._successful_payment_update(invoice["payload"], amount_stars=100, user_id=invited_user_id)
        )
        self.assertEqual(self.access.bonus_balance_for_user(inviter_id), 10)

        self.telegram.invoices.clear()
        await self.bot.handle_update(self._update("/pay", user_id=inviter_id))
        await self.bot.handle_update(
            self._callback_update(f"pay:months:{inviter_id}:1", user_id=inviter_id)
        )
        self.assertEqual(self.telegram.invoices[-1]["amount_stars"], 90)
        payment = self.access.payment_for_payload(self.telegram.invoices[-1]["payload"])
        self.assertEqual(payment["bonus_spent_stars"], 10)

    async def test_invite_accept_creates_client_named_from_telegram_username(self):
        invite = self.access.create_invite(
            created_by=self.admin_user_id,
            target_username_hint="@buyer_user",
        )

        await self.bot.handle_update(
            self._update(
                f"/start {invite['token']}",
                user_id=222,
                username="Buyer_User",
                first_name="Buyer",
                language_code="en",
            )
        )

        client_id = self.access.client_for_user(222)
        self.assertTrue(client_id)
        client = await self.panel.get_client(client_id)
        self.assertEqual(client["name"], "@buyer_user")
        self.assertEqual(self.access.user_record(222)["display_name"], "@buyer_user")

    async def test_known_user_message_renames_bound_client_and_preserves_email(self):
        user_id = 222
        client = await self.panel.create_client("Telegram 222")
        original_email = client["email"]
        self.access.invite_user(user_id, invited_by=self.admin_user_id)
        self.access.bind_client(user_id, client["id"], invited_by=self.admin_user_id)

        await self.bot.handle_update(
            self._update(
                "/status",
                user_id=user_id,
                username="buyer_user",
                first_name="Buyer",
                language_code="en",
            )
        )

        renamed = await self.panel.get_client(client["id"])
        self.assertEqual(renamed["name"], "@buyer_user")
        self.assertEqual(renamed["email"], original_email)
        self.assertEqual(self.access.user_record(user_id)["display_name"], "@buyer_user")

    async def test_discount_changes_invoice_amount_and_full_discount_grants_without_invoice(self):
        discounted_user_id = 222
        free_user_id = 333
        self.access.invite_user(discounted_user_id, invited_by=self.admin_user_id)
        self.access.invite_user(free_user_id, invited_by=self.admin_user_id)
        self.access.set_subscription_max_12m_discount_percent(20)
        self.access.set_discount_percent(discounted_user_id, 25)
        self.access.set_discount_percent(free_user_id, 100)

        await self.bot.handle_update(self._update("/pay", user_id=discounted_user_id))
        await self.bot.handle_update(
            self._callback_update(f"pay:months:{discounted_user_id}:3", user_id=discounted_user_id)
        )
        self.assertEqual(self.telegram.invoices[-1]["amount_stars"], 210)
        payment = self.access.payment_for_payload(self.telegram.invoices[-1]["payload"])
        self.assertEqual(payment["months"], 3)
        self.assertEqual(payment["package_discount_percent"], 5)
        self.assertEqual(payment["total_discount_percent"], 30)

        await self.bot.handle_update(self._update("/pay", user_id=free_user_id))
        before_count = len(self.telegram.invoices)
        await self.bot.handle_update(
            self._callback_update(f"pay:months:{free_user_id}:12", user_id=free_user_id)
        )
        self.assertEqual(len(self.telegram.invoices), before_count)
        expiry = telegram_access.parse_timestamp(
            self.access.user_record(free_user_id)["subscription_expires_at"]
        )
        self.assertEqual(len(self.telegram.invoices), 1)
        self.assertTrue(self.access.is_subscription_active(free_user_id))
        self.assertIsNotNone(self.access.client_for_user(free_user_id))
        self.assertIsNotNone(expiry)
        self.assertGreaterEqual((expiry - datetime.now(timezone.utc)).days, 359)

    async def test_pre_checkout_rejects_invalid_payment(self):
        user_id = 222
        self.access.invite_user(user_id, invited_by=self.admin_user_id)
        await self.bot.handle_update(self._update("/pay", user_id=user_id))
        await self.bot.handle_update(self._callback_update(f"pay:months:{user_id}:1", user_id=user_id))
        invoice = self.telegram.invoices[0]

        await self.bot.handle_update(
            self._pre_checkout_update(invoice["payload"], amount_stars=99, user_id=user_id)
        )

        self.assertEqual(self.telegram.pre_checkout_answers[-1]["ok"], False)
        self.assertIn("amount", self.telegram.pre_checkout_answers[-1]["error_message"])

    async def test_expired_paid_user_cannot_fetch_config_and_maintenance_disables_client(self):
        user_id = 222
        client = await self.panel.create_client("Expiring Client")
        self.access.invite_user(user_id, invited_by=self.admin_user_id)
        self.access.bind_client(user_id, client["id"], invited_by=self.admin_user_id)
        self.access.set_subscription_expires_at(
            user_id,
            datetime.now(timezone.utc) - timedelta(days=1),
        )

        await self.bot.handle_update(self._update("/link", user_id=user_id))
        self.assertTrue(any("Subscription is not active" in text for _, text in self.telegram.messages))

        await self.bot.run_subscription_maintenance_once(now=datetime.now(timezone.utc))
        disabled = await self.panel.get_client(client["id"])
        self.assertFalse(disabled["enabled"])
        self.assertEqual(self.access.user_record(user_id)["account_type"], "free")

    async def test_subscription_maintenance_sends_expiry_notification_once(self):
        user_id = 222
        client = await self.panel.create_client("Notify Client")
        self.access.invite_user(user_id, invited_by=self.admin_user_id)
        self.access.bind_client(user_id, client["id"], invited_by=self.admin_user_id)
        now = datetime(2026, 4, 22, 12, 0, tzinfo=timezone.utc)
        self.access.set_subscription_expires_at(user_id, now + timedelta(days=1, hours=1))

        await self.bot.run_subscription_maintenance_once(now=now)
        await self.bot.run_subscription_maintenance_once(now=now)

        notifications = [
            text for _, text in self.telegram.messages if "Subscription expires in 1 day" in text
        ]
        self.assertEqual(len(notifications), 1)

    async def test_admin_subscription_commands(self):
        user_id = 222

        await self.bot.handle_update(self._update("/price 150"))
        await self.bot.handle_update(self._update(f"/discount {user_id} 40"))
        await self.bot.handle_update(self._update(f"/grant {user_id} 10"))

        self.assertEqual(self.access.subscription_price_stars(), 150)
        self.assertEqual(self.access.discount_for_user(user_id), 40)
        self.assertTrue(self.access.is_subscription_active(user_id))
        self.assertIsNotNone(self.access.client_for_user(user_id))

        await self.bot.handle_update(self._update("/trial 9"))
        self.assertEqual(self.access.trial_period_days(), 9)
        await self.bot.handle_update(self._update(f"/bonus {user_id}"))
        self.assertTrue(any("Referral bonus" in text for _, text in self.telegram.messages))

        await self.bot.handle_update(self._update(f"/expires {user_id} 2026-05-01"))
        expires_at = telegram_access.parse_timestamp(
            self.access.user_record(user_id)["subscription_expires_at"]
        )
        self.assertEqual(expires_at, datetime(2026, 5, 1, 20, 59, 59, tzinfo=timezone.utc))

        await self.bot.handle_update(self._update(f"/discount {user_id} clear"))
        self.assertEqual(self.access.discount_for_user(user_id), 0)

        await self.bot.handle_update(self._update(f"/revoke {user_id}"))
        self.assertEqual(self.access.user_record(user_id)["account_type"], "free")

    async def test_admin_broadcast_commands_target_expected_audiences(self):
        active_user_id = 222
        deactivated_user_id = 333
        invited_free_user_id = 444
        self.access.invite_user(active_user_id, invited_by=self.admin_user_id)
        self.access.invite_user(deactivated_user_id, invited_by=self.admin_user_id)
        self.access.invite_user(invited_free_user_id, invited_by=self.admin_user_id)
        self.access.grant_subscription(active_user_id, days=30)
        self.access.set_subscription_expires_at(
            deactivated_user_id,
            datetime.now(timezone.utc) - timedelta(days=1),
        )

        self.telegram.messages.clear()
        await self.bot.handle_update(self._update("/broadcastactive Active notice"))
        active_messages = [text for chat_id, text in self.telegram.messages if chat_id == active_user_id]
        deactivated_messages = [
            text for chat_id, text in self.telegram.messages if chat_id == deactivated_user_id
        ]
        invited_free_messages = [
            text for chat_id, text in self.telegram.messages if chat_id == invited_free_user_id
        ]
        self.assertEqual(active_messages, ["Active notice"])
        self.assertEqual(deactivated_messages, [])
        self.assertEqual(invited_free_messages, [])
        self.assertTrue(any("Broadcast audience: active" in text for _, text in self.telegram.messages))

        self.telegram.messages.clear()
        await self.bot.handle_update(self._update("/broadcastdeactivated Wake up"))
        active_messages = [text for chat_id, text in self.telegram.messages if chat_id == active_user_id]
        deactivated_messages = [
            text for chat_id, text in self.telegram.messages if chat_id == deactivated_user_id
        ]
        invited_free_messages = [
            text for chat_id, text in self.telegram.messages if chat_id == invited_free_user_id
        ]
        self.assertEqual(active_messages, [])
        self.assertEqual(deactivated_messages, ["Wake up"])
        self.assertEqual(invited_free_messages, ["Wake up"])
        self.assertTrue(
            any("Broadcast audience: deactivated" in text for _, text in self.telegram.messages)
        )

        self.telegram.messages.clear()
        await self.bot.handle_update(self._update("/broadcastall Hello everyone"))
        self.assertEqual(
            [text for chat_id, text in self.telegram.messages if chat_id == active_user_id],
            ["Hello everyone"],
        )
        self.assertEqual(
            [text for chat_id, text in self.telegram.messages if chat_id == deactivated_user_id],
            ["Hello everyone"],
        )
        self.assertEqual(
            [text for chat_id, text in self.telegram.messages if chat_id == invited_free_user_id],
            ["Hello everyone"],
        )
        self.assertEqual(
            [text for chat_id, text in self.telegram.messages if chat_id == self.admin_user_id],
            ["Broadcast audience: all\nSelected recipients: 3\nDelivered: 3\nFailed: 0"],
        )

    async def test_admin_broadcast_requires_message(self):
        await self.bot.handle_update(self._update("/broadcastactive"))
        self.assertEqual(
            self.telegram.messages[-1],
            (self.admin_user_id, "Usage: /broadcastactive <message>"),
        )

    async def test_apps_install_and_instruction_commands_return_expected_texts(self):
        user_id = 222
        self.access.invite_user(user_id, invited_by=self.admin_user_id)
        self.access.update_user_language(
            user_id,
            preferred_language="en",
            telegram_language_code="en",
            mark_prompted=True,
        )

        await self.bot.handle_update(self._update("/apps", user_id=user_id))
        await self.bot.handle_update(self._update("/install", user_id=user_id))
        await self.bot.handle_update(self._update("/instruction", user_id=user_id))

        en_text = "\n".join(text for _, text in self.telegram.messages)
        self.assertIn("https://amnezia.org/downloads", en_text)
        self.assertIn("https://storage.googleapis.com/amnezia/amnezia.org", en_text)
        self.assertIn(
            "https://storage.googleapis.com/amnezia/amnezia.org?m-path=/downloads",
            en_text,
        )
        self.assertIn("https://play.google.com/store/apps/details?id=org.amnezia.vpn", en_text)
        self.assertIn("https://apps.apple.com/us/app/amneziavpn/id1600529900", en_text)
        self.assertIn(
            "https://github.com/amnezia-vpn/amnezia-client/releases/latest",
            en_text,
        )
        self.assertIn(
            "https://docs.amnezia.org/documentation/instructions/connect-via-text-key/",
            en_text,
        )
        self.assertIn("Simple setup guide:", en_text)
        self.assertIn("skip download and go straight to Config;", en_text)
        self.assertIn("VLESS is the most private option, but it can be a bit slower.", en_text)
        self.assertIn("AWG is fast, almost like WG, but more private.", en_text)
        self.assertIn("WG is the fastest, but it is also the easiest protocol for DPI systems to recognize.", en_text)

        self.telegram.messages.clear()
        self.access.update_user_language(
            user_id,
            preferred_language="ru",
            telegram_language_code="ru",
            mark_prompted=True,
        )
        await self.bot.handle_update(self._update("/apps", user_id=user_id))
        await self.bot.handle_update(self._update("/install", user_id=user_id))
        await self.bot.handle_update(self._update("/instruction", user_id=user_id))

        ru_text = "\n".join(text for _, text in self.telegram.messages)
        self.assertIn("https://amnezia.org/ru/downloads", ru_text)
        self.assertIn("https://storage.googleapis.com/amnezia/amnezia.org", ru_text)
        self.assertIn(
            "https://storage.googleapis.com/amnezia/amnezia.org?m-path=/ru/downloads",
            ru_text,
        )
        self.assertIn("https://play.google.com/store/apps/details?id=org.amnezia.vpn", ru_text)
        self.assertIn("https://apps.apple.com/us/app/amneziavpn/id1600529900", ru_text)
        self.assertIn(
            "https://github.com/amnezia-vpn/amnezia-client/releases/latest",
            ru_text,
        )
        self.assertIn(
            "https://docs.amnezia.org/documentation/instructions/connect-via-text-key/",
            ru_text,
        )
        self.assertIn("Подробная инструкция с самого начала:", ru_text)
        self.assertIn("По умолчанию используйте VLESS:", ru_text)
        self.assertIn("VLESS: максимально приватно, но медленней.", ru_text)
        self.assertIn("AWG: быстро, почти как WG, но приватнее.", ru_text)
        self.assertIn("WG: самый быстрый, но узнаваемый протокол для систем РКН и DPI.", ru_text)

    async def test_invite_usage_for_regular_user_contains_examples(self):
        user_id = 222
        self.access.invite_user(user_id, invited_by=self.admin_user_id)

        await self.bot.handle_update(self._update("/invite invalid-target", user_id=user_id))

        self.assertIn("/invite <@username or +phone or telegram-user-id>", self.telegram.messages[-1][1])
        self.assertIn("/invite @pupkin", self.telegram.messages[-1][1])
        self.assertIn("/invite 1111111", self.telegram.messages[-1][1])

    async def test_telegram_billing_api_requires_auth(self):
        response = await self.http.get("/api/telegram/users")
        self.assertEqual(response.status_code, 401)

    async def test_telegram_billing_summary_users_and_payments_are_public_safe(self):
        user_id = 222
        self.access.invite_user(user_id, invited_by=self.admin_user_id)
        self.access.update_user_profile(
            user_id,
            {
                "username": "buyer",
                "first_name": "Buyer",
            },
        )
        self.access.set_discount_percent(user_id, 15)
        self.access.grant_subscription(user_id)
        payment = self.access.create_payment(user_id, amount_stars=100)
        self.access.complete_payment(
            payment["payload"],
            telegram_payment_charge_id="charge-id-super-secret",
        )

        summary_response = await self.http.get(
            "/api/telegram/billing/summary",
            headers=self.auth_headers,
        )
        users_response = await self.http.get("/api/telegram/users", headers=self.auth_headers)
        payments_response = await self.http.get("/api/telegram/payments", headers=self.auth_headers)

        self.assertEqual(summary_response.status_code, 200)
        self.assertEqual(users_response.status_code, 200)
        self.assertEqual(payments_response.status_code, 200)
        summary = summary_response.json()
        users = users_response.json()
        payments = payments_response.json()
        self.assertEqual(summary["settings"]["subscription_price_stars"], 100)
        self.assertEqual(summary["settings"]["subscription_max_12m_discount_percent"], 0)
        self.assertEqual(summary["settings"]["trial_period_days"], 7)
        self.assertEqual(summary["counts"]["total_users"], 1)
        self.assertEqual(summary["counts"]["active_paid"], 1)
        self.assertEqual(summary["counts"]["pending_invites"], 0)
        self.assertEqual(summary["counts"]["uninvited_leads"], 0)
        self.assertEqual(summary["counts"]["bonus_balance_stars"], 0)
        self.assertEqual(users[0]["telegram_user_id"], user_id)
        self.assertEqual(users[0]["display_name"], "@buyer")
        self.assertEqual(users[0]["username"], "buyer")
        self.assertEqual(users[0]["first_name"], "Buyer")
        self.assertTrue(users[0]["subscription_active"])
        self.assertEqual(users[0]["discount_percent"], 15)
        self.assertTrue(users[0]["last_completed_payment"]["telegram_payment_charge_id_present"])
        self.assertNotIn("charge-id-super-secret", payments_response.text)
        self.assertNotIn("charge-id-super-secret", users_response.text)
        self.assertNotIn("charge-id-super-secret", summary_response.text)
        self.assertEqual(payments[0]["telegram_payment_charge_id_short"], "charge-i...cret")

    async def test_telegram_billing_settings_validation_and_update(self):
        response = await self.http.put(
            "/api/telegram/billing/settings",
            headers=self.auth_headers,
            json={
                "subscription_price_stars": 175,
                "subscription_max_12m_discount_percent": 18,
                "trial_period_days": 9,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.access.subscription_price_stars(), 175)
        self.assertEqual(self.access.subscription_max_12m_discount_percent(), 18)
        self.assertEqual(self.access.trial_period_days(), 9)

        invalid = await self.http.put(
            "/api/telegram/billing/settings",
            headers=self.auth_headers,
            json={"subscription_price_stars": -1},
        )
        self.assertEqual(invalid.status_code, 422)

    async def test_panel_grant_uses_stored_display_name_for_new_client(self):
        user_id = 222
        self.access.update_user_profile(
            user_id,
            {
                "username": "buyer",
                "first_name": "Buyer",
            },
        )

        async def ensure_peer(access, ensured_user_id):
            access.bind_peer(ensured_user_id, "peer-public-key")
            return types.SimpleNamespace(public_key="peer-public-key")

        with patch.object(
            main,
            "_ensure_telegram_user_peer_enabled",
            new=AsyncMock(side_effect=ensure_peer),
        ):
            response = await self.http.post(
                f"/api/telegram/users/{user_id}/grant",
                headers=self.auth_headers,
                json={"days": 10},
            )
        self.assertEqual(response.status_code, 200)
        granted = response.json()
        client = await self.panel.get_client(granted["client"]["id"])
        self.assertEqual(client["name"], "@buyer")

    async def test_telegram_invites_and_leads_api(self):
        self.access.create_invite(created_by=self.admin_user_id, target_username_hint="@lead")
        self.access.record_lead(
            user_id=999,
            chat_id=999,
            chat_type="private",
            profile={"username": "lead"},
            message_text="/start",
        )

        invites_response = await self.http.get("/api/telegram/invites", headers=self.auth_headers)
        leads_response = await self.http.get("/api/telegram/leads", headers=self.auth_headers)

        self.assertEqual(invites_response.status_code, 200)
        self.assertEqual(leads_response.status_code, 200)
        invites = invites_response.json()
        leads = leads_response.json()
        self.assertEqual(invites[0]["status"], "pending")
        self.assertTrue(invites[0]["token_present"])
        self.assertNotIn("token", invites[0])
        self.assertEqual(leads[0]["telegram_user_id"], 999)

    async def test_telegram_support_api_round_trip(self):
        user_id = 222
        self.access.invite_user(user_id, invited_by=self.admin_user_id)
        self.access.update_user_profile(user_id, {"username": "buyer", "first_name": "Buyer"})
        self.access.create_or_append_support_ticket(user_id, "Need help", author="user")

        summary_response = await self.http.get(
            "/api/telegram/support/summary",
            headers=self.auth_headers,
        )
        open_response = await self.http.get(
            "/api/telegram/support/tickets?status=open",
            headers=self.auth_headers,
        )
        detail_response = await self.http.get(
            "/api/telegram/support/tickets/T000001",
            headers=self.auth_headers,
        )

        self.assertEqual(summary_response.status_code, 200)
        self.assertEqual(open_response.status_code, 200)
        self.assertEqual(detail_response.status_code, 200)
        self.assertEqual(summary_response.json()["counts"]["open_tickets"], 1)
        self.assertEqual(summary_response.json()["counts"]["new_tickets"], 1)
        self.assertEqual(open_response.json()[0]["ticket_id"], "T000001")
        self.assertEqual(detail_response.json()["messages"][0]["text"], "Need help")

        mark_read_response = await self.http.post(
            "/api/telegram/support/tickets/T000001/mark-read",
            headers=self.auth_headers,
        )
        self.assertEqual(mark_read_response.status_code, 200)
        self.assertEqual(mark_read_response.json()["unread_user_messages"], 0)

        with patch.object(main, "_send_telegram_bot_message", new=AsyncMock()) as send_mock:
            reply_response = await self.http.post(
                "/api/telegram/support/tickets/T000001/reply",
                headers=self.auth_headers,
                json={"message": "Hello from panel"},
            )
            archive_response = await self.http.post(
                "/api/telegram/support/tickets/T000001/archive",
                headers=self.auth_headers,
            )

        self.assertEqual(reply_response.status_code, 200)
        self.assertEqual(reply_response.json()["messages"][-1]["author"], "admin")
        self.assertEqual(archive_response.status_code, 200)
        self.assertEqual(archive_response.json()["status"], "archived")
        self.assertEqual(send_mock.await_count, 2)

        archived_response = await self.http.get(
            "/api/telegram/support/tickets?status=archived",
            headers=self.auth_headers,
        )
        self.assertEqual(archived_response.status_code, 200)
        self.assertEqual(archived_response.json()[0]["ticket_id"], "T000001")

    async def test_telegram_support_api_rejects_invalid_status(self):
        response = await self.http.get(
            "/api/telegram/support/tickets?status=unknown",
            headers=self.auth_headers,
        )
        self.assertEqual(response.status_code, 400)

    async def test_telegram_user_discount_and_expiry_api(self):
        user_id = 222

        discount_response = await self.http.put(
            f"/api/telegram/users/{user_id}/discount",
            headers=self.auth_headers,
            json={"discount_percent": 35},
        )
        self.assertEqual(discount_response.status_code, 200)
        self.assertEqual(discount_response.json()["user"]["discount_percent"], 35)

        invalid_discount = await self.http.put(
            f"/api/telegram/users/{user_id}/discount",
            headers=self.auth_headers,
            json={"discount_percent": 150},
        )
        self.assertEqual(invalid_discount.status_code, 422)

        async def ensure_peer(access, ensured_user_id):
            access.bind_peer(ensured_user_id, "peer-public-key")
            return types.SimpleNamespace(public_key="peer-public-key")

        with patch.object(
            main,
            "_ensure_telegram_user_peer_enabled",
            new=AsyncMock(side_effect=ensure_peer),
        ):
            expiry_response = await self.http.put(
                f"/api/telegram/users/{user_id}/expires",
                headers=self.auth_headers,
                json={"expires_at": "2026-05-01"},
            )
        self.assertEqual(expiry_response.status_code, 200)
        expires_at = telegram_access.parse_timestamp(
            expiry_response.json()["user"]["subscription_expires_at"]
        )
        self.assertEqual(expires_at, datetime(2026, 5, 1, 20, 59, 59, tzinfo=timezone.utc))

        clear_response = await self.http.put(
            f"/api/telegram/users/{user_id}/discount",
            headers=self.auth_headers,
            json={"clear": True},
        )
        self.assertEqual(clear_response.status_code, 200)
        self.assertEqual(clear_response.json()["user"]["discount_percent"], 0)

    async def test_telegram_user_grant_and_revoke_toggle_bound_client(self):
        user_id = 222

        async def ensure_peer(access, ensured_user_id):
            access.bind_peer(ensured_user_id, "peer-public-key")
            return types.SimpleNamespace(public_key="peer-public-key")

        ensure_peer_mock = AsyncMock(side_effect=ensure_peer)
        disable_peer_mock = AsyncMock()
        with patch.object(main, "_ensure_telegram_user_peer_enabled", new=ensure_peer_mock), patch.object(
            main,
            "_disable_telegram_user_peer",
            new=disable_peer_mock,
        ):
            grant_response = await self.http.post(
                f"/api/telegram/users/{user_id}/grant",
                headers=self.auth_headers,
                json={"days": 10},
            )
        self.assertEqual(grant_response.status_code, 200)
        granted = grant_response.json()
        self.assertTrue(granted["user"]["subscription_active"])
        client_id = granted["user"]["client_id"]
        peer_public_key = granted["user"]["peer_public_key"]
        self.assertTrue(client_id)
        self.assertTrue(peer_public_key)
        self.assertTrue((await self.panel.get_client(client_id))["enabled"])
        ensure_peer_mock.assert_awaited_once()

        with patch.object(main, "_disable_telegram_user_peer", new=disable_peer_mock):
            revoke_response = await self.http.post(
                f"/api/telegram/users/{user_id}/revoke",
                headers=self.auth_headers,
            )
        self.assertEqual(revoke_response.status_code, 200)
        self.assertEqual(revoke_response.json()["user"]["account_type"], "free")
        self.assertFalse((await self.panel.get_client(client_id))["enabled"])
        disable_peer_mock.assert_awaited()

    async def test_dashboard_contains_telegram_billing_placeholders(self):
        text = (SRC_DIR / "templates" / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn("Telegram billing", text)
        self.assertIn("telegram-users-body", text)
        self.assertIn("telegram-payments-body", text)
        self.assertIn("telegram-invites-body", text)
        self.assertIn("telegram-leads-body", text)
        self.assertIn("telegram-billing-trial-input", text)
        self.assertIn("telegram-command-docs-editor", text)
        self.assertIn("telegram-command-docs-save", text)
        self.assertIn("telegram-command-docs-reset", text)
        self.assertIn("telegram-command-docs-preview-install-en", text)
        self.assertIn("telegram-command-docs-preview-install-ru", text)
        self.assertIn("telegram-command-docs-preview-instruction-en", text)
        self.assertIn("telegram-command-docs-preview-instruction-ru", text)
        self.assertIn("telegram-command-docs-preview-menu-user-root-en", text)
        self.assertIn("telegram-command-docs-preview-menu-admin-system", text)
        self.assertIn("telegram-support-open-body", text)
        self.assertIn("telegram-support-reply-send", text)
        app_js = (SRC_DIR / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("user.display_name", app_js)
        self.assertIn("user.username", app_js)
        self.assertIn("refreshTelegramSupport()", app_js)
        self.assertIn("replyTelegramSupportTicket", app_js)

    def test_default_command_docs_include_mirror_links_and_install_preview(self):
        parsed = telegram_command_docs.parse_command_docs(telegram_command_docs.DEFAULT_RAW_CONFIG)
        preview = parsed.preview_payload()

        self.assertIn(
            "https://storage.googleapis.com/amnezia/amnezia.org",
            preview["apps_en"],
        )
        self.assertIn(
            "https://storage.googleapis.com/amnezia/amnezia.org?m-path=/downloads",
            preview["apps_en"],
        )
        self.assertIn(
            "https://storage.googleapis.com/amnezia/amnezia.org",
            preview["apps_ru"],
        )
        self.assertIn(
            "https://storage.googleapis.com/amnezia/amnezia.org?m-path=/ru/downloads",
            preview["apps_ru"],
        )
        self.assertIn(
            "https://play.google.com/store/apps/details?id=org.amnezia.vpn",
            preview["apps_en"],
        )
        self.assertIn(
            "https://apps.apple.com/us/app/amneziavpn/id1600529900",
            preview["apps_ru"],
        )
        self.assertIn(
            "https://storage.googleapis.com/amnezia/amnezia.org",
            preview["install_en"],
        )
        self.assertIn(
            "Downloads mirror: https://storage.googleapis.com/amnezia/amnezia.org?m-path=/downloads",
            preview["install_en"],
        )
        self.assertIn(
            "Desktop fallback: https://github.com/amnezia-vpn/amnezia-client/releases/latest",
            preview["install_en"],
        )
        self.assertIn(
            "https://storage.googleapis.com/amnezia/amnezia.org",
            preview["install_ru"],
        )
        self.assertIn(
            "https://github.com/amnezia-vpn/amnezia-client/releases/latest",
            preview["install_ru"],
        )
        self.assertIn(
            "Simple setup guide:",
            preview["instruction_en"],
        )
        self.assertIn(
            "Подробная инструкция с самого начала:",
            preview["instruction_ru"],
        )
        self.assertIn(
            "/invite <@username or +phone or telegram-user-id> - create invite link, for example /invite @pupkin or /invite 1111111",
            preview["help_user_en"],
        )
        self.assertIn(
            "/invite <@username or +phone or telegram-user-id>",
            preview["help_user_ru"],
        )
        self.assertIn(
            "/instruction - open the long-form setup instructions",
            preview["help_user_en"],
        )
        self.assertIn(
            "/support [message] - contact support through a ticket",
            preview["help_user_en"],
        )
        self.assertIn(
            "/wg - send your assigned WireGuard config and QR",
            preview["help_user_en"],
        )
        self.assertIn(
            "/awg - send your assigned AmneziaWG config",
            preview["help_user_en"],
        )
        self.assertIn(
            "/instruction - открыть подробную инструкцию по установке",
            preview["help_user_ru"],
        )
        self.assertIn("/invite @pupkin", preview["help_admin"])
        self.assertIn("Subscription -> submenu:user.subscription", preview["menu_user_root_en"])
        self.assertIn("Instruction -> command:/instruction", preview["menu_user_root_en"])
        self.assertIn("Support -> command:/support", preview["menu_user_root_en"])
        self.assertIn("Подписка -> submenu:user.subscription", preview["menu_user_root_ru"])
        self.assertIn("Config -> submenu:user.config", preview["menu_user_setup_en"])
        self.assertIn("Link -> command:/link", preview["menu_user_config_en"])
        self.assertIn("WG -> command:/wg", preview["menu_user_config_en"])
        self.assertIn("AWG -> command:/awg", preview["menu_user_config_en"])
        self.assertIn("VLESS is the most private option, but it can be a bit slower.", preview["instruction_en"])
        self.assertIn("AWG is fast, almost like WG, but more private.", preview["instruction_en"])
        self.assertIn("WG is the fastest, but it is also the easiest protocol for DPI systems to recognize.", preview["instruction_en"])
        self.assertIn("Конфиг -> submenu:user.config", preview["menu_user_setup_ru"])
        self.assertIn("Doctor -> command:/doctor", preview["menu_admin_system"])

    def test_command_docs_menu_validation_rejects_missing_screen(self):
        invalid_raw = telegram_command_docs.DEFAULT_RAW_CONFIG.replace(
            "subscription :: Subscription :: submenu:user.subscription",
            "subscription :: Subscription :: submenu:user.unknown",
        )
        with self.assertRaises(telegram_command_docs.TelegramCommandDocsError):
            telegram_command_docs.parse_command_docs(invalid_raw)

    def test_command_docs_menu_validation_rejects_duplicate_item(self):
        invalid_raw = telegram_command_docs.DEFAULT_RAW_CONFIG.replace(
            "[menu.admin.system]\ndoctor :: Doctor :: command:/doctor\nback :: Back :: back:admin.root\n",
            "[menu.admin.system]\ndoctor :: Doctor :: command:/doctor\ndoctor :: Doctor again :: command:/doctor\nback :: Back :: back:admin.root\n",
        )
        with self.assertRaises(telegram_command_docs.TelegramCommandDocsError):
            telegram_command_docs.parse_command_docs(invalid_raw)

    async def test_bot_uses_custom_command_docs_from_store(self):
        user_id = 222
        self.access.invite_user(user_id, invited_by=self.admin_user_id)
        self.access.update_user_language(
            user_id,
            preferred_language="en",
            telegram_language_code="en",
            mark_prompted=True,
        )
        self.command_docs.update_raw_config(self._custom_command_docs_raw())

        await self.bot.handle_update(self._update("/help", user_id=user_id))
        await self.bot.handle_update(self._update("/apps", user_id=user_id))
        await self.bot.handle_update(self._update("/instruction", user_id=user_id))
        self.access.update_user_language(
            user_id,
            preferred_language="ru",
            telegram_language_code="ru",
            mark_prompted=True,
        )
        await self.bot.handle_update(self._update("/install", user_id=user_id))
        await self.bot.handle_update(self._update("/help", user_id=self.admin_user_id))

        self.assertIn("Membership:", self.telegram.messages[0][1])
        self.assertIn("/status - custom status help", self.telegram.messages[0][1])
        self.assertEqual(self.telegram.messages[1], (user_id, "Custom EN apps\nhttps://example.test/apps"))
        self.assertEqual(
            self.telegram.messages[2],
            (user_id, "Custom EN instruction\nOpen the bot\nInstall the app\nUse /link or /qr"),
        )
        self.assertEqual(self.telegram.messages[3], (user_id, "Пользовательская установка\nШаг 1"))
        self.assertIn("/clients - custom admin clients list", self.telegram.messages[4][1])
        self.assertIn("Clients:", self.telegram.messages[4][1])

    async def test_telegram_command_docs_api_round_trip(self):
        get_response = await self.http.get(
            "/api/telegram/command-docs",
            headers=self.auth_headers,
        )
        self.assertEqual(get_response.status_code, 200)
        self.assertTrue(get_response.json()["valid"])
        self.assertIn("[help.admin]", get_response.json()["raw_config"])
        self.assertIn("install_en", get_response.json()["preview"])
        self.assertIn("instruction_en", get_response.json()["preview"])
        self.assertIn("menu_user_root_en", get_response.json()["preview"])
        self.assertIn(
            "https://storage.googleapis.com/amnezia/amnezia.org",
            get_response.json()["preview"]["apps_en"],
        )
        self.assertIn(
            "https://storage.googleapis.com/amnezia/amnezia.org?m-path=/downloads",
            get_response.json()["preview"]["apps_en"],
        )
        self.assertIn(
            "Simple setup guide:",
            get_response.json()["preview"]["instruction_en"],
        )

        custom_raw = self._custom_command_docs_raw()
        update_response = await self.http.put(
            "/api/telegram/command-docs",
            headers=self.auth_headers,
            json={"raw_config": custom_raw},
        )
        self.assertEqual(update_response.status_code, 200)
        payload = update_response.json()
        self.assertTrue(payload["valid"])
        self.assertIn("пользовательская подсказка статуса", payload["preview"]["help_user_ru"])
        self.assertEqual(
            Path(config.TELEGRAM_COMMAND_DOCS_PATH).read_text(encoding="utf-8"),
            telegram_command_docs.normalize_raw_config(custom_raw),
        )

        invalid_response = await self.http.put(
            "/api/telegram/command-docs",
            headers=self.auth_headers,
            json={"raw_config": "[help.admin]\n/clients only"},
        )
        self.assertEqual(invalid_response.status_code, 400)

    async def test_telegram_command_docs_reset_endpoint_restores_defaults(self):
        self.command_docs.update_raw_config(self._custom_command_docs_raw())

        response = await self.http.post(
            "/api/telegram/command-docs/reset",
            headers=self.auth_headers,
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["valid"])
        self.assertIn(
            "https://storage.googleapis.com/amnezia/amnezia.org",
            payload["preview"]["apps_en"],
        )
        self.assertIn(
            "https://storage.googleapis.com/amnezia/amnezia.org?m-path=/downloads",
            payload["preview"]["apps_en"],
        )
        self.assertIn(
            "https://docs.amnezia.org/documentation/instructions/connect-via-text-key/",
            payload["preview"]["install_en"],
        )
        self.assertIn(
            "Simple setup guide:",
            payload["preview"]["instruction_en"],
        )
        self.assertEqual(
            Path(config.TELEGRAM_COMMAND_DOCS_PATH).read_text(encoding="utf-8"),
            telegram_command_docs.normalize_raw_config(telegram_command_docs.DEFAULT_RAW_CONFIG),
        )

    async def test_telegram_name_backfill_renames_only_client_name(self):
        named_user_id = 222
        missing_user_id = 333
        named_client = await self.panel.create_client("Telegram 222")
        missing_client = await self.panel.create_client("Telegram 333")
        self.access.invite_user(named_user_id, invited_by=self.admin_user_id)
        self.access.invite_user(missing_user_id, invited_by=self.admin_user_id)
        self.access.bind_client(named_user_id, named_client["id"], invited_by=self.admin_user_id)
        self.access.bind_client(missing_user_id, missing_client["id"], invited_by=self.admin_user_id)

        with patch.object(
            telegram_name_backfill.xm,
            "apply_xray",
            return_value=types.SimpleNamespace(status="ok"),
        ):
            report = await telegram_name_backfill.backfill_telegram_client_names(
                telegram=ProfileLookupTelegram(
                    {
                        named_user_id: {
                            "username": "buyer",
                            "first_name": "Buyer",
                            "last_name": "Person",
                        }
                    }
                ),
                access=self.access,
            )

        renamed = await self.panel.get_client(named_client["id"])
        unchanged = await self.panel.get_client(missing_client["id"])
        self.assertEqual(renamed["name"], "@buyer")
        self.assertEqual(renamed["email"], named_client["email"])
        self.assertEqual(unchanged["name"], "Telegram 333")
        self.assertEqual(report["renamed"], 1)
        self.assertEqual(report["skipped_profile_lookup"], 1)
        self.assertTrue(report["applied"])

    def test_allowed_chat_ids_parser_accepts_commas_and_spaces(self):
        self.assertEqual(
            telegram_bot.parse_allowed_chat_ids("123, 456\n789"),
            {123, 456, 789},
        )

    def test_message_chunks_do_not_emit_empty_items(self):
        chunks = telegram_bot._message_chunks("x" * 10, limit=4)
        self.assertEqual(chunks, ["xxxx", "xxxx", "xx"])


if __name__ == "__main__":
    unittest.main()
