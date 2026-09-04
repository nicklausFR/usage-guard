import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.build_dev_extension import build_dev_extension


class DevelopmentExtensionBuildTest(unittest.TestCase):
    def test_build_is_isolated_repeatable_and_targets_development(self):
        source_manifest = json.loads(
            (ROOT / "browser_extension" / "manifest.json").read_text(
                encoding="utf-8"
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "extension-dev"
            result = build_dev_extension(
                ROOT / "browser_extension", destination
            )
            (destination / "obsolete.txt").write_text("old", encoding="utf-8")
            build_dev_extension(ROOT / "browser_extension", destination)
            manifest = json.loads(
                (result / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(result, destination.resolve())
            self.assertEqual(manifest["version"], source_manifest["version"])
            self.assertEqual(manifest["version_name"], "development")
            self.assertIn("DEV", manifest["name"])
            self.assertEqual(
                manifest["host_permissions"],
                ["http://127.0.0.1:18765/*"],
            )
            self.assertIn(
                "127.0.0.1:18765",
                (destination / "README.md").read_text(encoding="utf-8"),
            )
            self.assertTrue((destination / "options.html").is_file())
            self.assertTrue((destination / "options.js").is_file())
            self.assertFalse((destination / "obsolete.txt").exists())
        self.assertNotIn("version_name", source_manifest)
        self.assertEqual(
            source_manifest["host_permissions"],
            ["http://127.0.0.1:8765/*"],
        )

    def test_background_selects_a_distinct_development_bridge(self):
        background = (
            ROOT / "browser_extension" / "background.js"
        ).read_text(encoding="utf-8")
        self.assertIn('version_name === "development"', background)
        self.assertIn("DEVELOPMENT ? 18765 : 8765", background)


if __name__ == "__main__":
    unittest.main()
