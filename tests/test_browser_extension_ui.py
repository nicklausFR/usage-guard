from pathlib import Path
import json
import re
import unittest


class BrowserExtensionUiTest(unittest.TestCase):
    def test_limit_banner_is_translucent_and_click_through(self):
        script = (
            Path(__file__).parents[1] / "browser_extension" / "content.js"
        ).read_text(encoding="utf-8")

        self.assertIn('"background:rgba(100,18,24,.62)"', script)
        self.assertIn('"pointer-events:none"', script)
        self.assertIn('"pointer-events:auto"', script)
        self.assertIn('ui.overlay.style.display = blocked ? "block" : "none"', script)
        self.assertIn('state?.enforcement_action === "warn"', script)
        self.assertIn("const blocked = blocksMedia(state)", script)

    def test_limit_banner_keeps_progress_on_the_main_row(self):
        script = (
            Path(__file__).parents[1] / "browser_extension" / "content.js"
        ).read_text(encoding="utf-8")

        self.assertIn(
            'ui.banner.style.display = applyBannerSettings(ui, state) ? "flex" : "none"',
            script,
        )
        self.assertIn('"flex:1 1 160px;min-width:60px;height:5px', script)
        self.assertIn("banner.append(label, progress, countdown, bonus)", script)
        self.assertNotIn("clear:both", script)

    def test_banner_options_cover_visibility_position_and_transparency(self):
        root = Path(__file__).parents[1] / "browser_extension"
        script = (root / "content.js").read_text(encoding="utf-8")
        options = (root / "options.html").read_text(encoding="utf-8")
        manifest = json.loads(
            (root / "manifest.json").read_text(encoding="utf-8")
        )

        self.assertIn("storage", manifest["permissions"])
        self.assertEqual(manifest["options_ui"]["page"], "options.html")
        self.assertTrue((root / "options.js").is_file())
        for mode in ("warning", "periodic", "always", "hidden"):
            self.assertIn(f'value="{mode}"', options)
        self.assertIn('value="top"', options)
        self.assertIn('value="bottom"', options)
        self.assertIn('id="opacity" type="range"', options)
        self.assertIn("periodicCycleStartedAt", script)
        self.assertIn("elapsed % every < visible", script)

    def test_banner_options_are_localized_with_english_as_the_default(self):
        root = Path(__file__).parents[1] / "browser_extension"
        options = (root / "options.html").read_text(encoding="utf-8")
        script = (root / "options.js").read_text(encoding="utf-8")
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        english = json.loads(
            (root / "_locales" / "en" / "messages.json").read_text(encoding="utf-8")
        )
        french = json.loads(
            (root / "_locales" / "fr" / "messages.json").read_text(encoding="utf-8")
        )

        self.assertEqual(manifest["default_locale"], "en")
        self.assertIn('lang="en"', options)
        self.assertIn('data-i18n="optionsHeading"', options)
        self.assertIn('chrome.i18n.getMessage(key,substitutions)', script)
        self.assertEqual(set(english), set(french))
        used_keys = set(re.findall(r'data-i18n="([^"]+)"', options))
        used_keys.update({"optionsTitle", "opacityValue", "settingsSaved"})
        self.assertEqual(used_keys - set(english), set())

    def test_extension_catalogs_generate_every_committed_message(self):
        project = Path(__file__).parents[1]
        extension = project / "browser_extension"
        for language in ("en", "fr"):
            messages = json.loads(
                (extension / "_locales" / language / "messages.json").read_text(
                    encoding="utf-8"
                )
            )
            catalog = (
                project
                / "locales"
                / language
                / "LC_MESSAGES"
                / "browser-extension.po"
            ).read_text(encoding="utf-8")
            catalog_keys = set(re.findall(r'^msgid "([^\"]+)"$', catalog, re.MULTILINE))
            self.assertEqual(set(messages) - catalog_keys, set())

    def test_extension_button_uses_the_configured_duration_unit(self):
        script = (
            Path(__file__).parents[1] / "browser_extension" / "content.js"
        ).read_text(encoding="utf-8")

        self.assertIn("function formatConfiguredDuration(value, unit)", script)
        self.assertIn("state.extension_unit", script)
        self.assertIn('unit === "minutes"', script)
        self.assertIn('unit === "hours"', script)

    def test_private_tabs_are_published_without_their_url(self):
        script = (
            Path(__file__).parents[1] / "browser_extension" / "background.js"
        ).read_text(encoding="utf-8")

        self.assertIn("if (tab?.incognito) {", script)
        self.assertIn("JSON.stringify({generic: true, audible: !!tab.audible})", script)
        self.assertIn("tabs.filter((tab) => !tab.incognito)", script)

    def test_page_media_playback_is_reported_even_when_the_tab_is_muted(self):
        root = Path(__file__).parents[1] / "browser_extension"
        content = (root / "content.js").read_text(encoding="utf-8")
        background = (root / "background.js").read_text(encoding="utf-8")

        self.assertIn("function pageMediaPlaying()", content)
        self.assertIn("playing: pageMediaPlaying()", content)
        self.assertIn('["play", "pause", "ended", "emptied"]', content)
        self.assertIn("publishTab(sender.tab, !!message.playing)", background)
        self.assertIn("audible: !!tab.audible || !!pageMediaPlaying", background)


if __name__ == "__main__":
    unittest.main()
