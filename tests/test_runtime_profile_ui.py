import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class RuntimeProfileUiTest(unittest.TestCase):
    def test_pwa_has_a_development_badge_driven_by_runtime_state(self):
        markup = (ROOT / "pwa" / "index.html").read_text(encoding="utf-8")
        script = (ROOT / "pwa" / "app.js").read_text(encoding="utf-8")
        style = (ROOT / "pwa" / "style.css").read_text(encoding="utf-8")
        self.assertIn('id="runtime-profile-badge"', markup)
        self.assertIn("function renderRuntimeProfile", script)
        self.assertIn("data.runtime?.profile", script)
        self.assertIn('CORE ${mirror.healthy?"OK":"ÉCART"}', script)
        self.assertIn('SERVICE ${service.connected?"OK":"OFF"}', script)
        self.assertIn('service?.host==="windows_service"?" · SCM"', script)
        self.assertIn('AUTH ${mirror.authority==="service"?"SERVICE":"LEGACY"}', script)
        self.assertIn(".runtime-profile-badge", style)

    def test_backend_pwa_copy_contains_the_same_profile_marker(self):
        for name in ("index.html", "app.js", "style.css"):
            self.assertEqual(
                (ROOT / "pwa" / name).read_bytes(),
                (ROOT / "usage_guard_backend" / "pwa" / name).read_bytes(),
            )


if __name__ == "__main__":
    unittest.main()
