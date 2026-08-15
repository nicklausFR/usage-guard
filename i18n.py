"""Gettext support shared by the Windows application."""
import gettext
import json
import locale
import os
from pathlib import Path


DOMAIN = "usage-guard"
LOCALE_DIR = Path(__file__).with_name("locales")
_translation = gettext.NullTranslations()


def settings_path():
    overridden = os.environ.get("USAGE_GUARD_SETTINGS_PATH")
    if overridden:
        return Path(overridden)
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    return base / "Usage Guard" / "settings.json"


def language_preference(default="auto"):
    try:
        value = json.loads(settings_path().read_text(encoding="utf-8")).get("language", default)
    except (OSError, ValueError, TypeError, AttributeError):
        value = default
    return value if value in {"auto", "fr", "en"} else default


def save_language_preference(language):
    language = str(language).lower()
    if language not in {"auto", "fr", "en"}:
        raise ValueError("Unsupported language")
    path = settings_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        data = {}
    data["language"] = language
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def system_language():
    configured = os.environ.get("USAGE_GUARD_LANGUAGE", "auto").strip().lower()
    if configured and configured != "auto":
        return configured.split("_", 1)[0].split("-", 1)[0]
    language = (locale.getlocale()[0] or "fr").lower()
    return language.split("_", 1)[0].split("-", 1)[0]


def configure(language="auto"):
    global _translation
    selected = system_language() if not language or language == "auto" else str(language)
    _translation = gettext.translation(
        DOMAIN, LOCALE_DIR, languages=[selected], fallback=True
    )
    return selected


def _(message):
    return _translation.gettext(message)


configure()
