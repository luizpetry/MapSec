"""Internationalization system for Mapsec GUI."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from mapsec.i18n.translations import EN, PT_BR

_LANGUAGES: dict[str, dict[str, str]] = {
    "en": EN,
    "pt_BR": PT_BR,
}

_current_lang: str = "en"


def set_language(lang: str) -> None:
    """Set the active language ('en' or 'pt_BR')."""
    global _current_lang
    if lang in _LANGUAGES:
        _current_lang = lang


def get_language() -> str:
    """Get the current language code."""
    return _current_lang


def t(key: str, **kwargs: Any) -> str:
    """Translate a key to the current language.

    Falls back to English if key not found, then to the key itself.
    Supports str.format() interpolation via kwargs.
    """
    text = _LANGUAGES.get(_current_lang, {}).get(key)
    if text is None:
        text = EN.get(key, key)
    if kwargs:
        try:
            text = text.format(**kwargs)
        except (KeyError, IndexError):
            pass
    return text


def get_available_languages() -> list[tuple[str, str]]:
    """Return list of (code, display_name) pairs."""
    return [
        ("en", "English"),
        ("pt_BR", "Portugu\u00eas (BR)"),
    ]


def save_language(lang: str) -> None:
    """Save language preference to config file."""
    config_path = Path.home() / ".mapsec" / "config.json"
    config: dict[str, Any] = {}
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    config["language"] = lang
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")


def load_language() -> str:
    """Load language preference from config file. Returns 'en' if not set."""
    config_path = Path.home() / ".mapsec" / "config.json"
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
            lang = config.get("language", "en")
            if lang in _LANGUAGES:
                set_language(lang)
                return lang
        except (json.JSONDecodeError, OSError):
            pass
    return "en"
