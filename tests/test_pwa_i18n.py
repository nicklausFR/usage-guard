import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PwaI18nTest(unittest.TestCase):
    def test_pwa_loads_translation_layer_before_application(self):
        index = (ROOT / "pwa" / "index.html").read_text(encoding="utf-8")
        self.assertLess(index.index("i18n.js?v="), index.index("app.js?v="))

    def test_language_choice_applies_to_pwa_immediately(self):
        app = (ROOT / "pwa" / "app.js").read_text(encoding="utf-8")
        self.assertIn("UG_I18N?.setLanguage(language)", app)
        self.assertIn("UG_I18N?.setLanguage(data.settings.language)", app)

    def test_translation_layer_covers_main_sections_and_dynamic_content(self):
        source = (ROOT / "pwa" / "i18n.js").read_text(encoding="utf-8")
        for french, english in (
            ("Nouvelle limitation", "New limitation"),
            ("Volume de temps", "Amount of time"),
            ("Sur une période", "Over a date range"),
            ("Enregistrer la règle", "Save rule"),
            ("Nom de la limitation", "Limitation name"),
            ("Nouvelle notification", "New notification"),
            ("Paramètres", "Settings"),
            ("Catalogue des activités de", "Activity catalogue for"),
            ("Tout l’ordinateur", "Entire computer"),
            ("Aucune donnée historique.", "No historical data."),
        ):
            self.assertIn(f'"{french}": "{english}"', source)
        self.assertIn("MutationObserver", source)

    def test_date_and_time_formatting_uses_selected_language(self):
        app = (ROOT / "pwa" / "app.js").read_text(encoding="utf-8")
        self.assertIn("const pwaLocale", app)
        self.assertGreaterEqual(app.count("pwaLocale()"), 10)
        self.assertEqual(app.count('"fr-FR"'), 1)

    @unittest.skipUnless(shutil.which("node"), "Node.js is not installed")
    def test_runtime_translation_examples(self):
        result = subprocess.run(
            ["node", str(ROOT / "tools" / "check_pwa_i18n.js")],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
