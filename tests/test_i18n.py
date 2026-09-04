import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from i18n import language_preference, save_language_preference


class LanguagePreferenceTest(unittest.TestCase):
    def test_auto_french_and_english_preferences_are_persistent(self):
        with tempfile.TemporaryDirectory() as directory:
            previous = os.environ.get("USAGE_GUARD_SETTINGS_PATH")
            os.environ["USAGE_GUARD_SETTINGS_PATH"] = str(Path(directory) / "settings.json")
            try:
                for language in ("auto", "fr", "en"):
                    save_language_preference(language)
                    self.assertEqual(language_preference(), language)
            finally:
                if previous is None:
                    os.environ.pop("USAGE_GUARD_SETTINGS_PATH", None)
                else:
                    os.environ["USAGE_GUARD_SETTINGS_PATH"] = previous

    def test_all_marked_desktop_and_static_pwa_strings_are_translated(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                str(root / "tools" / "audit_i18n.py"),
                "--root",
                str(root),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
