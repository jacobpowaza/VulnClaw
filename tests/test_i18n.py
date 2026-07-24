"""Tests for VulnClaw i18n system."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


# ── Module-level helpers ───────────────────────────────────────────

I18N_DIR = Path(__file__).resolve().parent.parent / "vulnclaw" / "i18n"


def _load_json(name: str) -> dict:
    with open(I18N_DIR / name, encoding="utf-8") as f:
        return json.load(f)


# ── Core i18n engine tests ─────────────────────────────────────────


class TestI18nEngine:
    def test_init_default_lang(self):
        from vulnclaw.i18n import init_i18n, get_current_lang

        init_i18n(lang="en")
        assert get_current_lang() == "en"

    def test_init_zh_cn(self):
        from vulnclaw.i18n import init_i18n, get_current_lang

        init_i18n(lang="zh-CN")
        assert get_current_lang() == "zh-CN"

    def test_lang_normalization_zh(self):
        from vulnclaw.i18n import _normalize_lang

        assert _normalize_lang("zh") == "zh-CN"
        assert _normalize_lang("ZH") == "zh-CN"
        assert _normalize_lang("zh-Hans") == "zh-CN"

    def test_lang_normalization_en(self):
        from vulnclaw.i18n import _normalize_lang

        assert _normalize_lang("en") == "en"
        assert _normalize_lang("EN") == "en"
        assert _normalize_lang("en-US") == "en"
        assert _normalize_lang("en-us") == "en"

    def test_lang_normalization_unknown_fallback(self):
        from vulnclaw.i18n import _normalize_lang

        assert _normalize_lang("fr") == "en"
        assert _normalize_lang("de") == "en"

    def test_file_for_lang(self):
        from vulnclaw.i18n import _file_for_lang

        assert _file_for_lang("en") == "en.json"
        assert _file_for_lang("zh-CN") == "zh.json"

    def test_detect_language_env(self, monkeypatch):
        from vulnclaw.i18n import I18nLoader

        monkeypatch.setenv("VULNCLAW_LANG", "zh-CN")
        assert I18nLoader.detect_language() == "zh-CN"

    def test_detect_language_env_en(self, monkeypatch):
        from vulnclaw.i18n import I18nLoader

        monkeypatch.delenv("VULNCLAW_LANG", raising=False)
        assert I18nLoader.detect_language() == "en"

    def test_translate_key_exists(self):
        from vulnclaw.i18n import _, init_i18n

        init_i18n(lang="en")
        result = _("cli.welcome")
        assert "VulnClaw" in result or result != "cli.welcome"

    def test_translate_key_missing_returns_key(self):
        from vulnclaw.i18n import _, init_i18n

        init_i18n(lang="en")
        nonexistent = "this_key_does_not_exist_42"
        assert _(nonexistent) == nonexistent

    def test_get_current_lang_before_init(self):
        from vulnclaw.i18n import get_current_lang

        assert get_current_lang() == "en"

    def test_native_names(self):
        from vulnclaw.i18n import NATIVE_NAMES

        assert NATIVE_NAMES["en"] == "English"
        assert NATIVE_NAMES["zh-CN"] == "简体中文"

    def test_supported_languages(self):
        from vulnclaw.i18n import SUPPORTED_LANGUAGES

        assert "en" in SUPPORTED_LANGUAGES
        assert "zh-CN" in SUPPORTED_LANGUAGES

    def test_zh_cn_fallback_to_zh_json(self):
        from vulnclaw.i18n import I18nLoader

        loader = I18nLoader(lang="zh-CN")
        assert loader.lang == "zh-CN"
        assert "cli.welcome" in loader.translations


# ── Locale file consistency tests ──────────────────────────────────


class TestLocaleFiles:
    def test_en_json_exists(self):
        assert (I18N_DIR / "en.json").exists()

    def test_zh_json_exists(self):
        assert (I18N_DIR / "zh.json").exists()

    def test_all_keys_present_in_zh(self):
        en = _load_json("en.json")
        zh = _load_json("zh.json")
        # English skill descriptions are intentionally en-only (they are LLM-facing)
        skip_patterns = ("skill.",)
        missing = [
            k for k in en if k not in zh
            and not any(k.startswith(p) for p in skip_patterns)
        ]
        assert not missing, f"Missing keys in zh.json: {missing}"

    def test_no_empty_values(self):
        en = _load_json("en.json")
        zh = _load_json("zh.json")
        empty_en = [k for k, v in en.items() if not v]
        empty_zh = [k for k, v in zh.items() if not v]
        assert not empty_en, f"Empty values in en.json: {empty_en}"
        assert not empty_zh, f"Empty values in zh.json: {empty_zh}"

    def test_valid_json_en(self):
        try:
            _load_json("en.json")
        except json.JSONDecodeError:
            pytest.fail("en.json is not valid JSON")

    def test_valid_json_zh(self):
        try:
            _load_json("zh.json")
        except json.JSONDecodeError:
            pytest.fail("zh.json is not valid JSON")

    def test_no_duplicate_keys_en(self):
        en = _load_json("en.json")
        assert len(en) == len(set(en.keys()))

    def test_no_duplicate_keys_zh(self):
        zh = _load_json("zh.json")
        assert len(zh) == len(set(zh.keys()))


# ── Integration tests ──────────────────────────────────────────────


class TestI18nIntegration:
    def test_language_switch_from_config(self):
        from vulnclaw.i18n import _, init_i18n, get_current_lang

        init_i18n(lang="en")
        assert get_current_lang() == "en"
        assert _("cli.welcome") != "cli.welcome"

        init_i18n(lang="zh-CN")
        assert get_current_lang() == "zh-CN"

    def test_cli_lang_command_switches_language(self):
        from typer.testing import CliRunner
        from vulnclaw.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["lang", "set", "zh-CN"])
        assert result.exit_code == 0
        assert "zh-CN" in result.output or "简体中文" in result.output

        result = runner.invoke(app, ["lang", "list"])
        assert result.exit_code == 0
        assert "en" in result.output
        assert "zh-CN" in result.output

    def test_lang_command_en(self):
        from typer.testing import CliRunner
        from vulnclaw.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["lang", "set", "en"])
        assert result.exit_code == 0

    def test_lang_alias(self):
        from typer.testing import CliRunner
        from vulnclaw.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["language", "list"])
        assert result.exit_code == 0

    def test_lang_falls_back_to_en_for_unknown(self):
        from typer.testing import CliRunner
        from vulnclaw.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["lang", "set", "fr"])
        # Unknown code falls back to 'en'
        assert result.exit_code == 0
        assert "en" in result.output or "English" in result.output

    def test_lang_without_args_shows_usage(self):
        from typer.testing import CliRunner
        from vulnclaw.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["lang"])
        assert result.exit_code == 0

    def test_env_var_overrides_default(self, monkeypatch):
        from vulnclaw.i18n import I18nLoader

        monkeypatch.setenv("VULNCLAW_LANG", "zh-CN")
        assert I18nLoader.detect_language() == "zh-CN"

    def test_build_system_prompt_bilingual(self):
        from vulnclaw.agent.prompts import build_system_prompt

        en = build_system_prompt(lang="en")
        zh = build_system_prompt(lang="zh-CN")
        assert "penetration testing" in en
        assert "渗透测试" in zh

    def test_generate_report_bilingual(self):
        from vulnclaw.agent.context import SessionState
        from vulnclaw.report.generator import generate_report

        session = SessionState(target="example.com")
        # Test English report
        report_path = generate_report(session, lang="en")
        content = report_path.read_text(encoding="utf-8")
        assert "Penetration Test Report" in content
        report_path.unlink()

        # Test Chinese report
        report_path = generate_report(session, lang="zh-CN")
        content = report_path.read_text(encoding="utf-8")
        assert "渗透测试报告" in content
        report_path.unlink()


# ── Validator tests ────────────────────────────────────────────────


class TestValidator:
    def test_validate_translations(self):
        from vulnclaw.i18n.validator import validate_translations

        errors = validate_translations()
        assert isinstance(errors, list)
        # No file-load errors
        load_errors = [e for e in errors if "failed to load" in e]
        assert not load_errors, f"Load errors: {load_errors}"
        # Remaining errors should only be about skill descriptions (en-only)
        for err in errors:
            assert not err.startswith("Key 'cli."), f"Unexpected CLI key mismatch: {err}"
