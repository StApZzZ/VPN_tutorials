"""Local assets, translations, role navigation and hardened responses."""
import json
from pathlib import Path

from device_support import admin_session

ROOT=Path(__file__).resolve().parents[1]/"panel"


def test_local_catalogs_have_matching_keys():
    en=json.loads((ROOT/"static/i18n/en.json").read_text())
    ru=json.loads((ROOT/"static/i18n/ru.json").read_text())
    assert en.keys()==ru.keys()
    assert en["Local users"]=="Local users" and ru["Local users"]!=en["Local users"]


def test_language_and_security_headers(client):
    en=client.get("/login")
    assert '<html lang="en"' in en.text and "Sign in" in en.text
    ru=client.get("/login?lang=ru")
    assert '<html lang="ru"' in ru.text
    assert '<html lang="ru"' in client.get("/login").text  # saved selection
    client.cookies.clear()
    assert '<html lang="en"' in client.get("/login",headers={"Accept-Language":"ru-RU, en;q=0.8"}).text
    assert en.headers["cache-control"]=="no-store"
    assert en.headers["referrer-policy"]=="strict-origin"
    csp=en.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "'unsafe-inline'" not in csp
    assert "https://cdn" not in en.text and "onclick=" not in en.text
    assert en.headers["x-content-type-options"]=="nosniff"
    assert client.get("/docs").status_code==404


def test_management_navigation_and_csrf_are_rendered(client):
    admin_session(client)
    page=client.get("/").text
    for tab in ["Devices","Access profiles","Local users","Directory users","Address pools","Audit","Routing"]:
        assert 'data-tab="'+tab+'"' in page
    assert 'name="csrf-token" content="' in page
    assert '/static/ui.js?v=' in page and '/static/panel.css?v=' in page
