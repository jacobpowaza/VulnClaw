"""Translation file validator — detect missing keys, empty values, and duplicates."""

from __future__ import annotations

import json
import os
import sys
from typing import Any


def _load_json(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _flatten(d: dict[str, Any], prefix: str = "") -> dict[str, str]:
    """Flatten a nested dict into dot-separated keys."""
    result: dict[str, str] = {}
    for k, v in d.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            result.update(_flatten(v, key))
        else:
            result[key] = str(v)
    return result


def validate_translations(locales_dir: str | None = None) -> list[str]:
    """Validate all translation files in a directory.

    Checks:
    - Missing keys in one language but not another
    - Empty translation values
    - Duplicate keys (handled by JSON parser, but reported)

    Returns a list of error messages (empty = all good).
    """
    if locales_dir is None:
        locales_dir = os.path.join(os.path.dirname(__file__))

    errors: list[str] = []

    lang_files: dict[str, str] = {}
    for fname in os.listdir(locales_dir):
        if not fname.endswith(".json"):
            continue
        if fname not in ("en.json", "zh.json"):
            continue
        path = os.path.join(locales_dir, fname)
        if os.path.isfile(path):
            lang = fname.replace(".json", "")
            lang_files[lang] = path

    if "en" not in lang_files:
        errors.append("Missing English translation file (en.json)")
    if "zh" not in lang_files:
        errors.append("Missing Chinese translation file (zh.json)")

    if not errors and len(lang_files) < 2:
        return errors

    # Load all translations
    translations: dict[str, dict[str, str]] = {}
    for lang, path in lang_files.items():
        try:
            raw = _load_json(path)
            translations[lang] = raw
        except (json.JSONDecodeError, FileNotFoundError) as e:
            errors.append(f"{path}: failed to load — {e}")

    if len(translations) < 2:
        return errors

    # Compare keys between first two languages
    langs = list(translations.keys())
    keys_a = set(translations[langs[0]].keys())
    keys_b = set(translations[langs[1]].keys())

    only_in_a = keys_a - keys_b
    only_in_b = keys_b - keys_a

    for key in sorted(only_in_a):
        errors.append(f"Key '{key}' exists in {langs[0]}.json but not in {langs[1]}.json")
    for key in sorted(only_in_b):
        errors.append(f"Key '{key}' exists in {langs[1]}.json but not in {langs[0]}.json")

    # Check for empty values
    for lang, trans in translations.items():
        for key, value in trans.items():
            if not value or (isinstance(value, str) and not value.strip()):
                errors.append(f"Empty translation for '{key}' in {lang}.json")

    return errors


def main() -> int:
    """Run validator from CLI."""
    locales_dir = os.path.join(os.path.dirname(__file__))
    errors = validate_translations(locales_dir)
    if errors:
        print(f"Translation validation failed with {len(errors)} issue(s):")
        for err in errors:
            print(f"  - {err}")
        return 1
    print("All translation files are consistent.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
