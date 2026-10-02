"""Small server-side language catalogue; no external assets or build step."""
import json
from pathlib import Path
from jinja2 import pass_context

CATALOGUES = {language: json.loads((Path(__file__).parent / "static/i18n" / (language + ".json")).read_text()) for language in ("en", "ru")}


def language(request):
    selected = request.query_params.get("lang") or request.cookies.get("corpvpn-language")
    if selected in CATALOGUES:
        return selected
    return "en"


@pass_context
def translate(context, key):
    request = context.get("request")
    return CATALOGUES[language(request) if request else "en"].get(key, key)
