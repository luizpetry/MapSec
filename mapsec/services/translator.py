import json
import os
import time
from pathlib import Path


class CveTranslator:
    """Translates CVE descriptions with caching support."""

    def __init__(self, cache_path: str = None):
        self._last_call = 0.0
        self._rate_limit = 0.3
        self.is_translating = False

        if cache_path is None:
            cache_path = os.path.join(os.path.expanduser("~"), ".mapsec", "cve_translations.json")

        self._cache_path = cache_path
        self._cache: dict[str, dict[str, str]] = {}
        self._load_cache()

        # Try to import deep_translator; if unavailable, translation is a no-op
        self._translator_available = True
        try:
            from deep_translator import GoogleTranslator
            self._GoogleTranslator = GoogleTranslator
        except ImportError:
            self._translator_available = False

    def _load_cache(self) -> None:
        """Load the translation cache from disk."""
        try:
            with open(self._cache_path, "r", encoding="utf-8") as f:
                self._cache = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self._cache = {}

    def _save_cache(self) -> None:
        """Save the translation cache to disk."""
        os.makedirs(os.path.dirname(self._cache_path), exist_ok=True)
        with open(self._cache_path, "w", encoding="utf-8") as f:
            json.dump(self._cache, f, ensure_ascii=False, indent=2)

    def translate_text(self, text: str, source: str = "en", target: str = "pt") -> str:
        """Translate a single text string with caching and rate limiting."""
        if not text or not self._translator_available:
            return text

        # Check cache first
        if target in self._cache.get(text, {}):
            return self._cache[text][target]

        # Rate limiting
        elapsed = time.time() - self._last_call
        if elapsed < self._rate_limit:
            time.sleep(self._rate_limit - elapsed)

        try:
            translator = self._GoogleTranslator(source=source, target=target)
            result = translator.translate(text)
            self._last_call = time.time()

            if result:
                # Cache the result
                if text not in self._cache:
                    self._cache[text] = {}
                self._cache[text][target] = result
                self._save_cache()
                return result
        except Exception:
            pass

        return text

    def translate_cve_descriptions(self, cves: list[dict], target: str = "pt") -> list[dict]:
        """Translate descriptions of a list of CVE dictionaries."""
        self.is_translating = True
        try:
            result = []
            for cve in cves:
                cve_id = cve.get("id", "")
                description = cve.get("description", "")

                if not description:
                    result.append({"id": cve_id, "description": ""})
                    continue

                translated = self.translate_text(description, source="en", target=target)
                result.append({"id": cve_id, "description": translated})
            return result
        finally:
            self.is_translating = False
