"""Internationalization support for VulnClaw.

Supported languages:
    en     — English (default)
    zh-CN  — Simplified Chinese (also loads from zh.json for compatibility)

Language priority:
    1. Explicit user selection (CLI / config / env)
    2. Saved application config (session.language)
    3. English (en) fallback
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional


_LANG_FILE_MAP = {
    "en": "en.json",
    "zh-cn": "zh.json",
}

SUPPORTED_LANGUAGES = ("en", "zh-CN")
_LANG_ALIASES: dict[str, str] = {
    "zh": "zh-CN",
    "en-us": "en",
    "en-US": "en",
}
NATIVE_NAMES: dict[str, str] = {
    "en": "English",
    "zh-CN": "简体中文",
}


def _normalize_lang(lang: str) -> str:
    """Normalize a language code to one of the supported forms.

    Returns 'en' or 'zh-CN'. Falls back to 'en' for unknown codes.
    """
    lower = lang.lower().strip()
    if lower in _LANG_FILE_MAP:
        return "en" if lower == "en" else "zh-CN"
    alias = _LANG_ALIASES.get(lower)
    if alias:
        return alias
    # Try partial match (e.g. "zh-Hans" → zh-CN)
    if lower.startswith("zh"):
        return "zh-CN"
    if lower.startswith("en"):
        return "en"
    return "en"


def _file_for_lang(lang: str) -> str:
    """Return the JSON filename for a normalized language code."""
    key = lang.lower().strip()
    return _LANG_FILE_MAP.get(key, "en.json")


class I18nLoader:
    """Load and manage translations."""

    def __init__(self, lang: str = "en") -> None:
        self.lang = _normalize_lang(lang)
        self.translations: dict[str, str] = {}
        self.logger = logging.getLogger(__name__)
        self._load_translations()

    def _get_lang_dir(self) -> str:
        """Get the directory containing language files."""
        return os.path.join(os.path.dirname(__file__))

    def _load_translations(self) -> None:
        """Load translations from JSON file."""
        lang_file = os.path.join(self._get_lang_dir(), _file_for_lang(self.lang))
        fallback_file = os.path.join(self._get_lang_dir(), "en.json")

        try:
            with open(lang_file, "r", encoding="utf-8") as f:
                self.translations = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            try:
                with open(fallback_file, "r", encoding="utf-8") as f:
                    self.translations = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError, PermissionError, OSError) as e:
                self.logger.warning(
                    "Failed to load fallback translation file '%s': %s. "
                    "Translations will be empty.",
                    fallback_file, type(e).__name__,
                )
                self.translations = {}

    def t(self, key: str, **kwargs: Any) -> str:
        """Translate a key to current language.

        Args:
            key: Translation key
            **kwargs: Placeholder values for template strings

        Returns:
            Translated string with placeholders replaced
        """
        text = self.translations.get(key, key)
        if kwargs:
            try:
                text = text.format(**kwargs)
            except KeyError:
                pass
        return text

    @staticmethod
    def detect_language() -> str:
        """Detect language from environment.

        Priority:
        1. VULNCLAW_LANG environment variable
        2. Default to 'en'

        Returns:
            Normalized language code ('en' or 'zh-CN')
        """
        lang_env = os.environ.get("VULNCLAW_LANG", "").lower()
        if lang_env:
            return _normalize_lang(lang_env)
        return "en"


# Global translator instance
_translator: Optional[I18nLoader] = None


def init_i18n(lang: Optional[str] = None, config: Any = None) -> I18nLoader:
    """Initialize the global translator.

    Args:
        lang: Explicit language override
        config: VulnClaw config object with session.language setting
    """
    global _translator
    if lang is None:
        if config is not None and hasattr(config, "session"):
            session_lang = getattr(config.session, "language", "auto")
            if session_lang and session_lang != "auto":
                lang = session_lang
        if lang is None or lang == "auto":
            lang = I18nLoader.detect_language()
    _translator = I18nLoader(lang)
    return _translator


def _(key: str, **kwargs: Any) -> str:
    """Translate a key using the global translator."""
    if _translator is None:
        init_i18n()
    return _translator.t(key, **kwargs)


def get_current_lang() -> str:
    """Return the currently active language code."""
    if _translator is not None:
        return _translator.lang
    return "en"
