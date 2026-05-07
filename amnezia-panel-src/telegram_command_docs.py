import logging
import re
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

HELP_ADMIN_SECTION = "help.admin"
HELP_USER_EN_SECTION = "help.user.en"
HELP_USER_RU_SECTION = "help.user.ru"
TEXT_APPS_EN_SECTION = "text.apps.en"
TEXT_APPS_RU_SECTION = "text.apps.ru"
TEXT_INSTALL_EN_SECTION = "text.install.en"
TEXT_INSTALL_RU_SECTION = "text.install.ru"
TEXT_INSTRUCTION_EN_SECTION = "text.instruction.en"
TEXT_INSTRUCTION_RU_SECTION = "text.instruction.ru"
MENU_USER_ROOT_EN_SECTION = "menu.user.root.en"
MENU_USER_ROOT_RU_SECTION = "menu.user.root.ru"
MENU_USER_SUBSCRIPTION_EN_SECTION = "menu.user.subscription.en"
MENU_USER_SUBSCRIPTION_RU_SECTION = "menu.user.subscription.ru"
MENU_USER_CONFIG_EN_SECTION = "menu.user.config.en"
MENU_USER_CONFIG_RU_SECTION = "menu.user.config.ru"
MENU_USER_SETUP_EN_SECTION = "menu.user.setup.en"
MENU_USER_SETUP_RU_SECTION = "menu.user.setup.ru"
MENU_ADMIN_ROOT_SECTION = "menu.admin.root"
MENU_ADMIN_CLIENTS_SECTION = "menu.admin.clients"
MENU_ADMIN_USERS_SECTION = "menu.admin.users"
MENU_ADMIN_INVITES_SECTION = "menu.admin.invites"
MENU_ADMIN_BILLING_SECTION = "menu.admin.billing"
MENU_ADMIN_BROADCAST_SECTION = "menu.admin.broadcast"
MENU_ADMIN_SYSTEM_SECTION = "menu.admin.system"

SCREEN_USER_ROOT = "user.root"
SCREEN_USER_SUBSCRIPTION = "user.subscription"
SCREEN_USER_CONFIG = "user.config"
SCREEN_USER_SETUP = "user.setup"
SCREEN_ADMIN_ROOT = "admin.root"
SCREEN_ADMIN_CLIENTS = "admin.clients"
SCREEN_ADMIN_USERS = "admin.users"
SCREEN_ADMIN_INVITES = "admin.invites"
SCREEN_ADMIN_BILLING = "admin.billing"
SCREEN_ADMIN_BROADCAST = "admin.broadcast"
SCREEN_ADMIN_SYSTEM = "admin.system"

HELP_SECTIONS = (
    HELP_ADMIN_SECTION,
    HELP_USER_EN_SECTION,
    HELP_USER_RU_SECTION,
)
TEXT_SECTIONS = (
    TEXT_APPS_EN_SECTION,
    TEXT_APPS_RU_SECTION,
    TEXT_INSTALL_EN_SECTION,
    TEXT_INSTALL_RU_SECTION,
    TEXT_INSTRUCTION_EN_SECTION,
    TEXT_INSTRUCTION_RU_SECTION,
)
MENU_SECTIONS = (
    MENU_USER_ROOT_EN_SECTION,
    MENU_USER_ROOT_RU_SECTION,
    MENU_USER_SUBSCRIPTION_EN_SECTION,
    MENU_USER_SUBSCRIPTION_RU_SECTION,
    MENU_USER_CONFIG_EN_SECTION,
    MENU_USER_CONFIG_RU_SECTION,
    MENU_USER_SETUP_EN_SECTION,
    MENU_USER_SETUP_RU_SECTION,
    MENU_ADMIN_ROOT_SECTION,
    MENU_ADMIN_CLIENTS_SECTION,
    MENU_ADMIN_USERS_SECTION,
    MENU_ADMIN_INVITES_SECTION,
    MENU_ADMIN_BILLING_SECTION,
    MENU_ADMIN_BROADCAST_SECTION,
    MENU_ADMIN_SYSTEM_SECTION,
)
VALID_SECTIONS = HELP_SECTIONS + TEXT_SECTIONS + MENU_SECTIONS

SCREEN_SECTION_BY_LANG = {
    SCREEN_USER_ROOT: {"en": MENU_USER_ROOT_EN_SECTION, "ru": MENU_USER_ROOT_RU_SECTION},
    SCREEN_USER_SUBSCRIPTION: {
        "en": MENU_USER_SUBSCRIPTION_EN_SECTION,
        "ru": MENU_USER_SUBSCRIPTION_RU_SECTION,
    },
    SCREEN_USER_CONFIG: {"en": MENU_USER_CONFIG_EN_SECTION, "ru": MENU_USER_CONFIG_RU_SECTION},
    SCREEN_USER_SETUP: {"en": MENU_USER_SETUP_EN_SECTION, "ru": MENU_USER_SETUP_RU_SECTION},
}
SCREEN_SECTION_STATIC = {
    SCREEN_ADMIN_ROOT: MENU_ADMIN_ROOT_SECTION,
    SCREEN_ADMIN_CLIENTS: MENU_ADMIN_CLIENTS_SECTION,
    SCREEN_ADMIN_USERS: MENU_ADMIN_USERS_SECTION,
    SCREEN_ADMIN_INVITES: MENU_ADMIN_INVITES_SECTION,
    SCREEN_ADMIN_BILLING: MENU_ADMIN_BILLING_SECTION,
    SCREEN_ADMIN_BROADCAST: MENU_ADMIN_BROADCAST_SECTION,
    SCREEN_ADMIN_SYSTEM: MENU_ADMIN_SYSTEM_SECTION,
}
VALID_SCREEN_IDS = set(SCREEN_SECTION_BY_LANG) | set(SCREEN_SECTION_STATIC)

MENU_PREVIEW_KEYS = (
    ("menu_user_root_en", SCREEN_USER_ROOT, "en"),
    ("menu_user_root_ru", SCREEN_USER_ROOT, "ru"),
    ("menu_user_subscription_en", SCREEN_USER_SUBSCRIPTION, "en"),
    ("menu_user_subscription_ru", SCREEN_USER_SUBSCRIPTION, "ru"),
    ("menu_user_config_en", SCREEN_USER_CONFIG, "en"),
    ("menu_user_config_ru", SCREEN_USER_CONFIG, "ru"),
    ("menu_user_setup_en", SCREEN_USER_SETUP, "en"),
    ("menu_user_setup_ru", SCREEN_USER_SETUP, "ru"),
    ("menu_admin_root", SCREEN_ADMIN_ROOT, "en"),
    ("menu_admin_clients", SCREEN_ADMIN_CLIENTS, "en"),
    ("menu_admin_users", SCREEN_ADMIN_USERS, "en"),
    ("menu_admin_invites", SCREEN_ADMIN_INVITES, "en"),
    ("menu_admin_billing", SCREEN_ADMIN_BILLING, "en"),
    ("menu_admin_broadcast", SCREEN_ADMIN_BROADCAST, "en"),
    ("menu_admin_system", SCREEN_ADMIN_SYSTEM, "en"),
)

HELP_TITLES = {
    HELP_ADMIN_SECTION: "VPN panel bot commands:",
    HELP_USER_EN_SECTION: "VPN bot commands:",
    HELP_USER_RU_SECTION: "Команды VPN-бота:",
}

GROUP_LABELS = {
    "en": {
        "quick": "Quick actions",
        "other": "Other commands",
    },
    "ru": {
        "quick": "Быстрые действия",
        "other": "Другие команды",
    },
}

COMMAND_TOKEN_RE = re.compile(r"^/(?P<command>[a-z0-9_]+)")
MENU_ACTION_RE = re.compile(
    r"^(?P<kind>submenu|command|helper|back):(?P<target>[A-Za-z0-9_./-]+)$"
)

SYNTAX_HELP = """# Telegram bot command docs config
#
# Sections:
#   [help.admin]
#   [help.user.en]
#   [help.user.ru]
#   [text.apps.en]
#   [text.apps.ru]
#   [text.install.en]
#   [text.install.ru]
#   [text.instruction.en]
#   [text.instruction.ru]
#   [menu.user.root.en]
#   [menu.user.root.ru]
#   [menu.user.subscription.en]
#   [menu.user.subscription.ru]
#   [menu.user.config.en]
#   [menu.user.config.ru]
#   [menu.user.setup.en]
#   [menu.user.setup.ru]
#   [menu.admin.root]
#   [menu.admin.clients]
#   [menu.admin.users]
#   [menu.admin.invites]
#   [menu.admin.billing]
#   [menu.admin.broadcast]
#   [menu.admin.system]
#
# Rules:
# - Empty lines are allowed.
# - Lines starting with # are comments.
# - In help sections use:
#     /command [args] :: description
# - In text sections every non-comment line is copied as-is.
# - In menu sections use:
#     item_id :: Button label :: action
# - Supported menu actions:
#     submenu:<screen-id>
#     command:/status
#     helper:/invite
#     back:<screen-id>
"""

DEFAULT_RAW_CONFIG = """# Telegram bot command docs

[help.admin]
/help :: show grouped bot help
/status :: show your subscription status
/pay :: choose 1 / 3 / 6 / 12 month Telegram Stars package
/apps :: official Amnezia app download links
/install :: official Amnezia install/import guides
/instruction :: open the long-form setup instructions
/support <message> :: create or append a support ticket from the bot
/language :: explain that language selection is used for regular users only
/new <name> :: create VLESS client and return vless://
/newfor <telegram-user-id> <name> :: create VLESS client and bind it
/invite <@username or +phone or telegram-user-id> :: create invite link, for example /invite @pupkin or /invite 1111111
/invites :: list invite requests
/leads :: list users who wrote the bot but are not invited
/trial [days] :: show or set trial period
/bonus <telegram-user-id> :: show referral bonus balance
/broadcastactive <message> :: send message to users with active subscription
/broadcastdeactivated <message> :: send message to users without active subscription
/broadcastall <message> :: send message to all known non-admin users
/cancelinvite <invite-id> :: cancel pending invite
/bind <telegram-user-id> <client-id> :: bind existing VLESS client
/price [stars] :: show or set monthly subscription price
/discount <telegram-user-id> <percent|clear> :: set account discount
/expires <telegram-user-id> <YYYY-MM-DD> :: set subscription expiry date
/grant <telegram-user-id> [days] :: grant paid access
/revoke <telegram-user-id> :: revoke paid access and disable config
/tickets :: show support queue summary
/ticket <ticket-id> :: show support ticket thread preview
/replyticket <ticket-id> <message> :: reply to a user support ticket
/archiveticket <ticket-id> :: archive a resolved support ticket
/clients :: list VLESS clients
/link <client-id> :: return vless://
/qr <client-id> :: send QR PNG
/bundle <client-id> :: send smoke bundle zip
/disable <client-id> :: disable client
/enable <client-id> :: enable client
/delete <client-id> :: delete client
/doctor :: show Xray doctor summary

[help.user.en]
/help :: show grouped bot help
/status :: show your subscription status
/pay :: choose 1 / 3 / 6 / 12 month Telegram Stars package
/link :: return your assigned VLESS config
/qr :: send your assigned QR PNG
/bundle :: send your assigned smoke bundle zip
/wg :: send your assigned WireGuard config and QR
/awg :: send your assigned AmneziaWG config
/apps :: official Amnezia app download links
/install :: official Amnezia install/import guides
/instruction :: open the long-form setup instructions
/support [message] :: contact support through a ticket
/language :: choose message language
/invite <@username or +phone or telegram-user-id> :: create invite link, for example /invite @pupkin or /invite 1111111

[help.user.ru]
/help :: показать сгруппированную справку по боту
/status :: показать статус подписки
/pay :: выбрать пакет 1 / 3 / 6 / 12 месяцев через Telegram Stars
/link :: получить свой VLESS-конфиг
/qr :: получить QR-код своего конфига
/bundle :: получить архив настройки
/apps :: официальные ссылки на приложения Amnezia
/install :: инструкции по установке и импорту
/instruction :: открыть подробную инструкцию по установке
/language :: выбрать язык сообщений
/invite <@username or +phone or telegram-user-id> :: создать ссылку-приглашение, например /invite @pupkin или /invite 1111111

[text.apps.en]
Official Amnezia client links:
Official downloads: https://amnezia.org/downloads
Mirror home: https://storage.googleapis.com/amnezia/amnezia.org
Downloads mirror: https://storage.googleapis.com/amnezia/amnezia.org?m-path=/downloads
Windows: https://github.com/amnezia-vpn/amnezia-client/releases/latest
macOS: https://github.com/amnezia-vpn/amnezia-client/releases/latest
Linux: https://github.com/amnezia-vpn/amnezia-client/releases/latest
Android: https://play.google.com/store/apps/details?id=org.amnezia.vpn
iOS: https://apps.apple.com/us/app/amneziavpn/id1600529900
Beta and old versions: https://github.com/amnezia-vpn/amnezia-client/releases

[text.apps.ru]
Официальные клиенты Amnezia:
Официальные загрузки: https://amnezia.org/ru/downloads
Зеркало сайта: https://storage.googleapis.com/amnezia/amnezia.org
Зеркало загрузок: https://storage.googleapis.com/amnezia/amnezia.org?m-path=/ru/downloads
Windows: https://github.com/amnezia-vpn/amnezia-client/releases/latest
macOS: https://github.com/amnezia-vpn/amnezia-client/releases/latest
Linux: https://github.com/amnezia-vpn/amnezia-client/releases/latest
Android: https://play.google.com/store/apps/details?id=org.amnezia.vpn
iOS: https://apps.apple.com/us/app/amneziavpn/id1600529900
Бета и старые версии: https://github.com/amnezia-vpn/amnezia-client/releases

[text.install.en]
Official Amnezia install/import guides:
Official downloads: https://amnezia.org/downloads
Mirror home: https://storage.googleapis.com/amnezia/amnezia.org
Downloads mirror: https://storage.googleapis.com/amnezia/amnezia.org?m-path=/downloads
Desktop fallback: https://github.com/amnezia-vpn/amnezia-client/releases/latest
Text key: https://docs.amnezia.org/documentation/instructions/connect-via-text-key/
QR code: https://docs.amnezia.org/documentation/instructions/connect-via-qr-code/
Config file: https://docs.amnezia.org/documentation/instructions/connect-via-config/
Linux app install: https://docs.amnezia.org/documentation/installing-app-on-linux/

[text.install.ru]
Официальные инструкции Amnezia:
Официальные загрузки: https://amnezia.org/ru/downloads
Зеркало сайта: https://storage.googleapis.com/amnezia/amnezia.org
Зеркало загрузок: https://storage.googleapis.com/amnezia/amnezia.org?m-path=/ru/downloads
Резервная ссылка для desktop: https://github.com/amnezia-vpn/amnezia-client/releases/latest
Текстовый ключ: https://docs.amnezia.org/documentation/instructions/connect-via-text-key/
QR-код: https://docs.amnezia.org/documentation/instructions/connect-via-qr-code/
Файл конфигурации: https://docs.amnezia.org/documentation/instructions/connect-via-config/
Установка приложения на Linux: https://docs.amnezia.org/documentation/installing-app-on-linux/

[text.instruction.en]
Simple setup guide:
1. Tap the invite link in Telegram.
2. If Telegram opens the bot, press Start.
3. Wait until the bot confirms that access is active.
4. Open Apps and install the Amnezia app for your phone or computer.
5. Return to the bot and open Config.
6. If you can copy text easily, use /link.
7. If copying is hard, use /qr and scan the code in the Amnezia app.
8. If the app asks how to import the config, follow /install.
9. Turn the VPN on inside the app.

If something does not work:
- open /instruction again and follow the steps slowly;
- if the invite link does not open, copy it into your Telegram Saved Messages and tap it there;
- if the app is already installed, skip download and go straight to /link or /qr;
- if your phone wants to open the link in the wrong app, choose Telegram or copy the link into Telegram manually.

[text.instruction.ru]
Подробная инструкция с самого начала:

1. Вам прислали ссылку-приглашение.
Нажмите на эту ссылку прямо в Telegram.
Если открылся бот, нажмите кнопку Start или Написать.

2. Дождитесь сообщения от бота.
Бот должен написать, что приглашение принято и доступ активирован.
Если бот написал что-то другое, не закрывайте чат и перечитайте сообщение спокойно.

3. Посмотрите на нижние кнопки в боте.
Самые важные кнопки:
- Приложения: где скачать программу Amnezia.
- Установка: короткие ссылки на официальные способы подключения.
- Инструкция: эта подробная памятка.
- Конфиг: здесь вы получите данные для подключения.

4. Если приложение Amnezia ещё не установлено.
Откройте Приложения или отправьте команду /apps.
Выберите своё устройство:
- Android: телефон Samsung, Xiaomi, Pixel и другие.
- iPhone / iPad: устройства Apple.
- Windows: обычный компьютер или ноутбук.
- macOS: компьютер Apple.
Установите приложение и потом вернитесь обратно в чат с ботом.

5. Если приложение уже установлено.
Ничего скачивать заново не нужно.
Сразу возвращайтесь в бот и переходите к шагу с получением конфига.

6. Как получить конфиг.
Откройте Конфиг.
Там есть два основных варианта:
- /link: бот пришлёт ссылку для копирования.
- /qr: бот пришлёт QR-код, который можно отсканировать.

7. Что выбрать: /link или /qr.
Используйте /link, если вам удобно копировать текст.
Используйте /qr, если копировать неудобно, если вы боитесь ошибиться, или если приложение Amnezia умеет сканировать QR-коды.
Оба варианта делают одно и то же: передают приложению данные для подключения.

8. Как пользоваться /link.
После команды /link бот пришлёт сначала пояснение, а потом отдельным сообщением чистую ссылку.
Нужно скопировать только сообщение, которое начинается с vless://
В этом сообщении не должно быть ничего лишнего.
Если трудно копировать:
- зажмите палец на сообщении;
- выберите Копировать;
- если не получилось с первого раза, лучше используйте /qr.

9. Как пользоваться /qr.
Откройте команду /qr.
Бот пришлёт картинку с квадратным кодом.
Дальше откройте приложение Amnezia и найдите кнопку добавления или импорта конфига.
Если приложение предлагает сканирование QR-кода, наведите камеру на код.

10. Что делать внутри приложения Amnezia.
Откройте приложение.
Если оно спрашивает, как добавить подключение, выберите импорт конфигурации.
Если вы скопировали ссылку через /link, вставьте её туда, куда просит приложение.
Если приложение спрашивает, каким способом подключаться, просто используйте предложенный ботом конфиг и ничего вручную не меняйте.

11. Если не понимаете, куда вставлять ссылку.
Откройте Установка или команду /install.
Там собраны официальные инструкции Amnezia:
- подключение по текстовому ключу;
- подключение по QR-коду;
- подключение через файл конфигурации.
Для большинства людей достаточно двух вариантов: /link или /qr.

12. Когда конфиг импортирован.
В приложении появится новое подключение.
Нажмите кнопку включения VPN.
Если приложение попросит разрешение на создание VPN-подключения, согласитесь.

13. Как понять, что всё получилось.
Приложение покажет, что VPN включён.
После этого можно открыть нужный сайт или приложение и пользоваться им как обычно.

14. Если ссылка-приглашение не открывается.
- Скопируйте ссылку.
- Отправьте её сами себе в Избранное в Telegram.
- Нажмите на неё уже из Избранного.
- Либо найдите этого бота вручную в Telegram и откройте чат с ним.

15. Если телефон пытается открыть ссылку не там.
Иногда телефон предлагает открыть ссылку браузером или другим приложением.
В таком случае:
- выберите Telegram;
- или скопируйте ссылку и вставьте её в Telegram вручную.

16. Если что-то не получается.
Не пугайтесь и не пытайтесь менять непонятные настройки.
Сделайте так:
- вернитесь в бот;
- откройте Инструкция ещё раз;
- попробуйте вместо /link использовать /qr;
- если проблема осталась, отправьте в поддержку скриншот того шага, где стало непонятно, и напишите, какое у вас устройство: Android, iPhone, Windows или Mac.

[menu.user.root.en]
subscription :: Subscription :: submenu:user.subscription
config :: Config :: submenu:user.config
setup :: Apps & Setup :: submenu:user.setup
help :: Help :: command:/help
language :: Language :: command:/language
admin :: Admin :: submenu:admin.root

[menu.user.root.ru]
subscription :: Подписка :: submenu:user.subscription
config :: Конфиг :: submenu:user.config
setup :: Приложения и установка :: submenu:user.setup
help :: Справка :: command:/help
language :: Язык :: command:/language
admin :: Admin :: submenu:admin.root

[menu.user.subscription.en]
status :: Status :: command:/status
pay :: Pay :: command:/pay
back :: Back :: back:user.root

[menu.user.subscription.ru]
status :: Статус :: command:/status
pay :: Оплатить :: command:/pay
back :: Назад :: back:user.root

[menu.user.config.en]
link :: Link :: command:/link
qr :: QR :: command:/qr
bundle :: Bundle :: command:/bundle
back :: Back :: back:user.root

[menu.user.config.ru]
link :: Ссылка :: command:/link
qr :: QR-код :: command:/qr
bundle :: Архив :: command:/bundle
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
clients :: List clients :: command:/clients
new :: New client :: helper:/new
newfor :: New for user :: helper:/newfor
bind :: Bind client :: helper:/bind
link :: Client link :: helper:/link
qr :: Client QR :: helper:/qr
bundle :: Client bundle :: helper:/bundle
enable :: Enable client :: helper:/enable
disable :: Disable client :: helper:/disable
delete :: Delete client :: helper:/delete
back :: Back :: back:admin.root

[menu.admin.users]
grant :: Grant access :: helper:/grant
revoke :: Revoke access :: helper:/revoke
discount :: Discount :: helper:/discount
expires :: Set expiry :: helper:/expires
bonus :: Bonus :: helper:/bonus
back :: Back :: back:admin.root

[menu.admin.invites]
invites :: List invites :: command:/invites
leads :: Leads :: command:/leads
invite :: Create invite :: helper:/invite
cancelinvite :: Cancel invite :: helper:/cancelinvite
back :: Back :: back:admin.root

[menu.admin.billing]
price :: Price :: helper:/price
trial :: Trial :: helper:/trial
back :: Back :: back:admin.root

[menu.admin.broadcast]
broadcastactive :: Broadcast active :: helper:/broadcastactive
broadcastdeactivated :: Broadcast deactivated :: helper:/broadcastdeactivated
broadcastall :: Broadcast all :: helper:/broadcastall
back :: Back :: back:admin.root

[menu.admin.system]
doctor :: Doctor :: command:/doctor
back :: Back :: back:admin.root
"""


def _build_default_raw_config() -> str:
    return """# Telegram bot command docs

[help.admin]
/help :: show grouped bot help
/status :: show your subscription status
/pay :: choose 1 / 3 / 6 / 12 month Telegram Stars package
/apps :: official Amnezia app download links
/install :: official Amnezia install/import guides
/instruction :: open the long-form setup instructions
/support <message> :: create or append a support ticket from the bot
/language :: explain that language selection is used for regular users only
/new <name> :: create VLESS client and return vless://
/newfor <telegram-user-id> <name> :: create VLESS client and bind it
/invite <@username or +phone or telegram-user-id> :: create invite link, for example /invite @pupkin or /invite 1111111
/invites :: list invite requests
/leads :: list users who wrote the bot but are not invited
/trial [days] :: show or set trial period
/bonus <telegram-user-id> :: show referral bonus balance
/broadcastactive <message> :: send message to users with active subscription
/broadcastdeactivated <message> :: send message to users without active subscription
/broadcastall <message> :: send message to all known non-admin users
/cancelinvite <invite-id> :: cancel pending invite
/bind <telegram-user-id> <client-id> :: bind existing VLESS client
/price [stars] :: show or set monthly subscription price
/discount <telegram-user-id> <percent|clear> :: set account discount
/expires <telegram-user-id> <YYYY-MM-DD> :: set subscription expiry date
/grant <telegram-user-id> [days] :: grant paid access
/revoke <telegram-user-id> :: revoke paid access and disable config
/tickets :: show support queue summary
/ticket <ticket-id> :: show support ticket thread preview
/replyticket <ticket-id> <message> :: reply to a user support ticket
/archiveticket <ticket-id> :: archive a resolved support ticket
/clients :: list VLESS clients
/link <client-id> :: return vless://
/qr <client-id> :: send QR PNG
/bundle <client-id> :: send smoke bundle zip
/disable <client-id> :: disable client
/enable <client-id> :: enable client
/delete <client-id> :: delete client
/doctor :: show Xray doctor summary

[help.user.en]
/help :: show grouped bot help
/status :: show your subscription status
/pay :: choose 1 / 3 / 6 / 12 month Telegram Stars package
/link :: return your assigned VLESS config
/qr :: send your assigned QR PNG
/bundle :: send your assigned smoke bundle zip
/wg :: send your assigned WireGuard config and QR
/awg :: send your assigned AmneziaWG config
/apps :: official Amnezia app download links
/install :: official Amnezia install/import guides
/instruction :: open the long-form setup instructions
/support [message] :: contact support through a ticket
/language :: choose message language
/invite <@username or +phone or telegram-user-id> :: create invite link, for example /invite @pupkin or /invite 1111111

[help.user.ru]
/help :: показать сгруппированную справку по боту
/status :: показать статус подписки
/pay :: выбрать пакет 1 / 3 / 6 / 12 месяцев через Telegram Stars
/link :: получить свой VLESS-конфиг
/qr :: получить QR-код своего конфига
/bundle :: получить архив настройки
/wg :: получить свой WireGuard-конфиг и QR
/awg :: получить свой AmneziaWG-конфиг
/apps :: официальные ссылки на приложения Amnezia
/install :: инструкции по установке и импорту
/instruction :: открыть подробную инструкцию по установке
/support [сообщение] :: написать в поддержку через заявку
/language :: выбрать язык сообщений
/invite <@username or +phone or telegram-user-id> :: создать ссылку-приглашение, например /invite @pupkin или /invite 1111111

[text.apps.en]
Official Amnezia client links:
Official downloads: https://amnezia.org/downloads
Mirror home: https://storage.googleapis.com/amnezia/amnezia.org
Downloads mirror: https://storage.googleapis.com/amnezia/amnezia.org?m-path=/downloads
Windows: https://github.com/amnezia-vpn/amnezia-client/releases/latest
macOS: https://github.com/amnezia-vpn/amnezia-client/releases/latest
Linux: https://github.com/amnezia-vpn/amnezia-client/releases/latest
Android: https://play.google.com/store/apps/details?id=org.amnezia.vpn
iOS: https://apps.apple.com/us/app/amneziavpn/id1600529900
Beta and old versions: https://github.com/amnezia-vpn/amnezia-client/releases

[text.apps.ru]
Официальные клиенты Amnezia:
Официальные загрузки: https://amnezia.org/ru/downloads
Зеркало сайта: https://storage.googleapis.com/amnezia/amnezia.org
Зеркало загрузок: https://storage.googleapis.com/amnezia/amnezia.org?m-path=/ru/downloads
Windows: https://github.com/amnezia-vpn/amnezia-client/releases/latest
macOS: https://github.com/amnezia-vpn/amnezia-client/releases/latest
Linux: https://github.com/amnezia-vpn/amnezia-client/releases/latest
Android: https://play.google.com/store/apps/details?id=org.amnezia.vpn
iOS: https://apps.apple.com/us/app/amneziavpn/id1600529900
Бета и старые версии: https://github.com/amnezia-vpn/amnezia-client/releases

[text.install.en]
Official Amnezia install/import guides:
Official downloads: https://amnezia.org/downloads
Mirror home: https://storage.googleapis.com/amnezia/amnezia.org
Downloads mirror: https://storage.googleapis.com/amnezia/amnezia.org?m-path=/downloads
Desktop fallback: https://github.com/amnezia-vpn/amnezia-client/releases/latest
Text key: https://docs.amnezia.org/documentation/instructions/connect-via-text-key/
QR code: https://docs.amnezia.org/documentation/instructions/connect-via-qr-code/
Config file: https://docs.amnezia.org/documentation/instructions/connect-via-config/
Linux app install: https://docs.amnezia.org/documentation/installing-app-on-linux/

[text.install.ru]
Официальные инструкции Amnezia:
Официальные загрузки: https://amnezia.org/ru/downloads
Зеркало сайта: https://storage.googleapis.com/amnezia/amnezia.org
Зеркало загрузок: https://storage.googleapis.com/amnezia/amnezia.org?m-path=/ru/downloads
Резервная ссылка для desktop: https://github.com/amnezia-vpn/amnezia-client/releases/latest
Текстовый ключ: https://docs.amnezia.org/documentation/instructions/connect-via-text-key/
QR-код: https://docs.amnezia.org/documentation/instructions/connect-via-qr-code/
Файл конфигурации: https://docs.amnezia.org/documentation/instructions/connect-via-config/
Установка приложения на Linux: https://docs.amnezia.org/documentation/installing-app-on-linux/

[text.instruction.en]
Simple setup guide:
1. Tap the invite link in Telegram and press Start in the bot.
2. Wait until the bot confirms that access is active.
3. Open Instruction to keep this checklist nearby, then open Apps & Setup to install the Amnezia app.
4. Inside Apps & Setup open Config. By default use VLESS:
- VLESS is the most private option, but it can be a bit slower.
- AWG is fast, almost like WG, but more private.
- WG is the fastest, but it is also the easiest protocol for DPI systems to recognize.
5. If copying text is easy, use /link. If it is easier to scan, use /qr.
6. If you need a faster alternative, request /wg or /awg. VLESS still stays the default recommendation.
7. If the app asks how to import the config, follow the guides from /install.
8. Turn the VPN on inside the app.

If something does not work:
- open /instruction again and go step by step;
- if the invite link opens in the wrong place, copy it into Telegram manually;
- if the app is already installed, skip download and go straight to Config;
- if you need help, send /support and then one text message describing the problem.

[text.instruction.ru]
Подробная инструкция с самого начала:
1. Нажмите на ссылку-приглашение в Telegram и откройте бота.
2. Дождитесь сообщения, что доступ активирован.
3. Откройте Инструкция, чтобы держать эту памятку под рукой, а затем раздел Приложения и установка.
4. Внутри Приложения и установка сначала можно открыть Приложения и Установка, а затем Конфиг.
5. По умолчанию используйте VLESS:
- VLESS: максимально приватно, но медленней.
- AWG: быстро, почти как WG, но приватнее.
- WG: самый быстрый, но узнаваемый протокол для систем РКН и DPI.
6. Если вам удобно копировать текст, используйте /link. Если удобнее сканировать, используйте /qr.
7. Если нужен более быстрый альтернативный вариант, можно запросить /wg или /awg. Но основная рекомендация всё равно VLESS.
8. Если приложение спрашивает, как импортировать конфиг, откройте /install.
9. Включите VPN внутри приложения.

Если что-то не получается:
- спокойно перечитайте шаги ещё раз;
- если приложение уже установлено, сразу переходите в Конфиг;
- если ссылка открывается не в Telegram, вставьте её в Telegram вручную;
- если нужна помощь, отправьте /support и затем одним текстовым сообщением опишите проблему.

[menu.user.root.en]
subscription :: Subscription :: submenu:user.subscription
instruction :: Instruction :: command:/instruction
setup :: Apps & Setup :: submenu:user.setup
support :: Support :: command:/support
admin :: Admin :: submenu:admin.root

[menu.user.root.ru]
subscription :: Подписка :: submenu:user.subscription
instruction :: Инструкция :: command:/instruction
setup :: Приложения и установка :: submenu:user.setup
support :: Поддержка :: command:/support
admin :: Admin :: submenu:admin.root

[menu.user.subscription.en]
status :: Status :: command:/status
pay :: Pay :: command:/pay
back :: Back :: back:user.root

[menu.user.subscription.ru]
status :: Статус :: command:/status
pay :: Оплатить :: command:/pay
back :: Назад :: back:user.root

[menu.user.config.en]
link :: Link :: command:/link
qr :: QR :: command:/qr
bundle :: Bundle :: command:/bundle
wg :: WG :: command:/wg
awg :: AWG :: command:/awg
back :: Back :: back:user.setup

[menu.user.config.ru]
link :: Ссылка :: command:/link
qr :: QR-код :: command:/qr
bundle :: Архив :: command:/bundle
wg :: WG :: command:/wg
awg :: AWG :: command:/awg
back :: Назад :: back:user.setup

[menu.user.setup.en]
apps :: Apps :: command:/apps
install :: Install :: command:/install
config :: Config :: submenu:user.config
back :: Back :: back:user.root

[menu.user.setup.ru]
apps :: Приложения :: command:/apps
install :: Установка :: command:/install
config :: Конфиг :: submenu:user.config
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
clients :: List clients :: command:/clients
new :: New client :: helper:/new
newfor :: New for user :: helper:/newfor
bind :: Bind client :: helper:/bind
link :: Client link :: helper:/link
qr :: Client QR :: helper:/qr
bundle :: Client bundle :: helper:/bundle
enable :: Enable client :: helper:/enable
disable :: Disable client :: helper:/disable
delete :: Delete client :: helper:/delete
back :: Back :: back:admin.root

[menu.admin.users]
grant :: Grant access :: helper:/grant
revoke :: Revoke access :: helper:/revoke
discount :: Discount :: helper:/discount
expires :: Set expiry :: helper:/expires
bonus :: Bonus :: helper:/bonus
tickets :: Tickets :: command:/tickets
ticket :: Ticket preview :: helper:/ticket
replyticket :: Reply ticket :: helper:/replyticket
archiveticket :: Archive ticket :: helper:/archiveticket
back :: Back :: back:admin.root

[menu.admin.invites]
invites :: List invites :: command:/invites
leads :: Leads :: command:/leads
invite :: Create invite :: helper:/invite
cancelinvite :: Cancel invite :: helper:/cancelinvite
back :: Back :: back:admin.root

[menu.admin.billing]
price :: Price :: helper:/price
trial :: Trial :: helper:/trial
back :: Back :: back:admin.root

[menu.admin.broadcast]
broadcastactive :: Broadcast active :: helper:/broadcastactive
broadcastdeactivated :: Broadcast deactivated :: helper:/broadcastdeactivated
broadcastall :: Broadcast all :: helper:/broadcastall
back :: Back :: back:admin.root

[menu.admin.system]
doctor :: Doctor :: command:/doctor
back :: Back :: back:admin.root
"""


DEFAULT_RAW_CONFIG = _build_default_raw_config()


class TelegramCommandDocsError(ValueError):
    pass


@dataclass(frozen=True)
class HelpEntry:
    command: str
    description: str

    @property
    def token(self) -> str:
        match = COMMAND_TOKEN_RE.match(self.command.strip().lower())
        return match.group("command") if match else ""


@dataclass(frozen=True)
class MenuAction:
    kind: str
    target: str
    raw: str

    @property
    def command(self) -> str:
        return self.target.lstrip("/") if self.kind in {"command", "helper"} else ""


@dataclass(frozen=True)
class MenuItem:
    item_id: str
    label: str
    action: MenuAction


def normalize_raw_config(raw_config: str) -> str:
    return raw_config.replace("\r\n", "\n").replace("\r", "\n").strip("\n") + "\n"


def _menu_section_for_screen(screen_id: str, lang: str) -> str:
    if screen_id in SCREEN_SECTION_STATIC:
        return SCREEN_SECTION_STATIC[screen_id]
    screen_lang = "ru" if lang == "ru" else "en"
    return SCREEN_SECTION_BY_LANG[screen_id][screen_lang]


def _help_section_for_role(is_admin: bool, lang: str) -> str:
    if is_admin:
        return HELP_ADMIN_SECTION
    return HELP_USER_RU_SECTION if lang == "ru" else HELP_USER_EN_SECTION


def _parse_menu_action(value: str, line_number: int) -> MenuAction:
    action = value.strip()
    match = MENU_ACTION_RE.fullmatch(action)
    if not match:
        raise TelegramCommandDocsError(
            f"Line {line_number}: invalid menu action '{action}'."
        )
    kind = match.group("kind")
    target = match.group("target")
    if kind in {"submenu", "back"}:
        if target not in VALID_SCREEN_IDS:
            raise TelegramCommandDocsError(
                f"Line {line_number}: unknown menu screen '{target}'."
            )
    else:
        command_match = COMMAND_TOKEN_RE.match(target)
        if not command_match or command_match.group("command") != target.lstrip("/"):
            raise TelegramCommandDocsError(
                f"Line {line_number}: menu action '{action}' must target a bare /command."
            )
    return MenuAction(kind=kind, target=target, raw=action)


@dataclass
class ParsedTelegramCommandDocs:
    raw_config: str
    help_sections: dict[str, list[HelpEntry]]
    text_sections: dict[str, str]
    menu_sections: dict[str, list[MenuItem]]

    def _help_entry_map(self, section: str) -> dict[str, HelpEntry]:
        return {
            entry.token: entry
            for entry in self.help_sections[section]
            if entry.token
        }

    def lookup_help_entry(self, command: str, is_admin: bool, lang: str) -> HelpEntry | None:
        token = command.lstrip("/").strip().lower()
        section = _help_section_for_role(is_admin=is_admin, lang=lang)
        entry = self._help_entry_map(section).get(token)
        if entry is not None:
            return entry
        if is_admin:
            fallback_section = HELP_USER_RU_SECTION if lang == "ru" else HELP_USER_EN_SECTION
            return self._help_entry_map(fallback_section).get(token)
        return None

    def menu_screen_items(self, screen_id: str, lang: str) -> list[MenuItem]:
        return list(self.menu_sections[_menu_section_for_screen(screen_id, lang)])

    def root_menu_items(self, is_admin: bool, lang: str) -> list[MenuItem]:
        items = self.menu_screen_items(SCREEN_USER_ROOT, lang)
        filtered: list[MenuItem] = []
        for item in items:
            if item.action.kind == "submenu" and item.action.target.startswith("admin."):
                if is_admin:
                    filtered.append(item)
                continue
            filtered.append(item)
        return filtered

    def root_menu_item_for_label(self, label: str, is_admin: bool, lang: str) -> MenuItem | None:
        for item in self.root_menu_items(is_admin=is_admin, lang=lang):
            if item.label == label:
                return item
        return None

    def menu_item_by_id(self, screen_id: str, item_id: str, lang: str) -> MenuItem | None:
        for item in self.menu_screen_items(screen_id, lang):
            if item.item_id == item_id:
                return item
        return None

    def render_help(self, is_admin: bool, lang: str) -> str:
        lang = "ru" if lang == "ru" else "en"
        section = _help_section_for_role(is_admin=is_admin, lang=lang)
        title = HELP_TITLES[section]
        remaining = {entry.token: entry for entry in self.help_sections[section] if entry.token}
        lines = [title]

        def add_group(group_label: str, entries: list[HelpEntry]) -> None:
            if not entries:
                return
            lines.append("")
            lines.append(f"{group_label}:")
            lines.extend(f"{entry.command} - {entry.description}" for entry in entries)
            for entry in entries:
                remaining.pop(entry.token, None)

        root_items = self.root_menu_items(is_admin=is_admin, lang=lang)
        for item in root_items:
            if item.action.kind == "submenu" and item.action.target == SCREEN_ADMIN_ROOT:
                for admin_item in self.menu_screen_items(SCREEN_ADMIN_ROOT, "en"):
                    if admin_item.action.kind != "submenu":
                        continue
                    admin_entries = self._entries_for_screen(
                        screen_id=admin_item.action.target,
                        lang="en",
                        section=section,
                    )
                    add_group(admin_item.label, admin_entries)
                continue
            if item.action.kind == "submenu":
                add_group(
                    item.label,
                    self._entries_for_screen(
                        screen_id=item.action.target,
                        lang=lang,
                        section=section,
                    ),
                )

        quick_entries: list[HelpEntry] = []
        for item in root_items:
            if item.action.kind not in {"command", "helper"}:
                continue
            if item.action.command == "help":
                entry = self.lookup_help_entry(item.action.command, is_admin=is_admin, lang=lang)
            else:
                entry = self._help_entry_map(section).get(item.action.command)
            if entry is not None and entry.token in remaining:
                quick_entries.append(entry)
        add_group(GROUP_LABELS[lang]["quick"], quick_entries)

        if remaining:
            add_group(
                GROUP_LABELS[lang]["other"],
                list(remaining.values()),
            )
        return "\n".join(lines)

    def _entries_for_screen(
        self,
        screen_id: str,
        lang: str,
        section: str,
    ) -> list[HelpEntry]:
        entry_map = self._help_entry_map(section)
        entries: list[HelpEntry] = []
        for item in self.menu_screen_items(screen_id, lang):
            if item.action.kind not in {"command", "helper"}:
                continue
            entry = entry_map.get(item.action.command)
            if entry is not None:
                entries.append(entry)
        return entries

    def render_apps(self, lang: str) -> str:
        return self.text_sections[TEXT_APPS_RU_SECTION if lang == "ru" else TEXT_APPS_EN_SECTION]

    def render_install(self, lang: str) -> str:
        return self.text_sections[TEXT_INSTALL_RU_SECTION if lang == "ru" else TEXT_INSTALL_EN_SECTION]

    def render_instruction(self, lang: str) -> str:
        return self.text_sections[
            TEXT_INSTRUCTION_RU_SECTION if lang == "ru" else TEXT_INSTRUCTION_EN_SECTION
        ]

    def render_menu_preview(self, screen_id: str, lang: str) -> str:
        lines = [f"{screen_id}:"]
        for item in self.menu_screen_items(screen_id, lang):
            lines.append(f"{item.label} -> {item.action.raw}")
        return "\n".join(lines)

    def preview_payload(self) -> dict[str, str]:
        payload = {
            "help_admin": self.render_help(is_admin=True, lang="en"),
            "help_user_en": self.render_help(is_admin=False, lang="en"),
            "help_user_ru": self.render_help(is_admin=False, lang="ru"),
            "apps_en": self.render_apps("en"),
            "apps_ru": self.render_apps("ru"),
            "install_en": self.render_install("en"),
            "install_ru": self.render_install("ru"),
            "instruction_en": self.render_instruction("en"),
            "instruction_ru": self.render_instruction("ru"),
        }
        for key, screen_id, lang in MENU_PREVIEW_KEYS:
            payload[key] = self.render_menu_preview(screen_id, lang)
        return payload


def parse_command_docs(raw_config: str) -> ParsedTelegramCommandDocs:
    normalized = normalize_raw_config(raw_config)
    help_sections = {section: [] for section in HELP_SECTIONS}
    text_section_lines = {section: [] for section in TEXT_SECTIONS}
    menu_sections = {section: [] for section in MENU_SECTIONS}
    seen_sections: set[str] = set()
    current_section = ""

    for line_number, raw_line in enumerate(normalized.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped:
            if current_section in TEXT_SECTIONS:
                text_section_lines[current_section].append("")
            continue
        if stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip()
            if section not in VALID_SECTIONS:
                raise TelegramCommandDocsError(f"Line {line_number}: unknown section '{section}'.")
            if section in seen_sections:
                raise TelegramCommandDocsError(f"Line {line_number}: duplicate section '{section}'.")
            current_section = section
            seen_sections.add(section)
            continue
        if not current_section:
            raise TelegramCommandDocsError(f"Line {line_number}: content must belong to a section.")
        if current_section in HELP_SECTIONS:
            if "::" not in raw_line:
                raise TelegramCommandDocsError(
                    f"Line {line_number}: help lines must use '::' separator."
                )
            command_text, description = [item.strip() for item in raw_line.split("::", 1)]
            if not command_text or not description:
                raise TelegramCommandDocsError(
                    f"Line {line_number}: both command and description are required."
                )
            if not COMMAND_TOKEN_RE.match(command_text):
                raise TelegramCommandDocsError(
                    f"Line {line_number}: help command must start with /command."
                )
            help_sections[current_section].append(
                HelpEntry(command=command_text, description=description)
            )
            continue
        if current_section in TEXT_SECTIONS:
            text_section_lines[current_section].append(raw_line.rstrip())
            continue
        parts = [item.strip() for item in raw_line.split("::", 2)]
        if len(parts) != 3:
            raise TelegramCommandDocsError(
                f"Line {line_number}: menu lines must use 'item_id :: label :: action'."
            )
        item_id, label, action_text = parts
        if not item_id or not label or not action_text:
            raise TelegramCommandDocsError(
                f"Line {line_number}: menu item id, label and action are required."
            )
        if any(existing.item_id == item_id for existing in menu_sections[current_section]):
            raise TelegramCommandDocsError(
                f"Line {line_number}: duplicate menu item id '{item_id}' in [{current_section}]."
            )
        menu_sections[current_section].append(
            MenuItem(
                item_id=item_id,
                label=label,
                action=_parse_menu_action(action_text, line_number),
            )
        )

    missing_sections = [section for section in VALID_SECTIONS if section not in seen_sections]
    if missing_sections:
        raise TelegramCommandDocsError(
            f"Missing required sections: {', '.join(missing_sections)}."
        )

    for section, commands in help_sections.items():
        if not commands:
            raise TelegramCommandDocsError(f"Section [{section}] must contain at least one command.")

    text_sections: dict[str, str] = {}
    for section, lines in text_section_lines.items():
        text = "\n".join(lines).strip()
        if not text:
            raise TelegramCommandDocsError(f"Section [{section}] must not be empty.")
        text_sections[section] = text

    for section, items in menu_sections.items():
        if not items:
            raise TelegramCommandDocsError(f"Section [{section}] must contain at least one menu item.")

    return ParsedTelegramCommandDocs(
        raw_config=normalized,
        help_sections=help_sections,
        text_sections=text_sections,
        menu_sections=menu_sections,
    )


class TelegramCommandDocsStore:
    def __init__(self, path: str):
        self.path = Path(path)

    def read_raw_config(self) -> str:
        if not self.path.exists():
            return normalize_raw_config(DEFAULT_RAW_CONFIG)
        return normalize_raw_config(self.path.read_text(encoding="utf-8"))

    def load_effective(self) -> ParsedTelegramCommandDocs:
        raw_config = self.read_raw_config()
        try:
            return parse_command_docs(raw_config)
        except TelegramCommandDocsError as exc:
            logger.warning(
                "Invalid telegram command docs config at %s: %s. Using defaults.",
                self.path,
                exc,
            )
            return parse_command_docs(DEFAULT_RAW_CONFIG)

    def describe(self) -> dict[str, object]:
        raw_config = self.read_raw_config()
        try:
            parsed = parse_command_docs(raw_config)
            valid = True
            error = ""
        except TelegramCommandDocsError as exc:
            parsed = parse_command_docs(DEFAULT_RAW_CONFIG)
            valid = False
            error = str(exc)
        return {
            "path": str(self.path),
            "valid": valid,
            "error": error,
            "raw_config": raw_config,
            "syntax_help": SYNTAX_HELP.strip(),
            "preview": parsed.preview_payload(),
        }

    def update_raw_config(self, raw_config: str) -> dict[str, object]:
        parsed = parse_command_docs(raw_config)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(parsed.raw_config, encoding="utf-8")
        return self.describe()

    def reset_to_defaults(self) -> dict[str, object]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(normalize_raw_config(DEFAULT_RAW_CONFIG), encoding="utf-8")
        return self.describe()
