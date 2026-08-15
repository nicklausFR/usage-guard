from pathlib import Path
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

    def test_limit_banner_keeps_progress_on_the_main_row(self):
        script = (
            Path(__file__).parents[1] / "browser_extension" / "content.js"
        ).read_text(encoding="utf-8")

        self.assertIn('ui.banner.style.display = "flex"', script)
        self.assertIn('"flex:1 1 160px;min-width:60px;height:5px', script)
        self.assertIn("banner.append(label, progress, countdown, bonus)", script)
        self.assertNotIn("clear:both", script)


if __name__ == "__main__":
    unittest.main()
