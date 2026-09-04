import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from control_sources.tray import TrayControlSource


class TrayControlSourceTest(unittest.TestCase):
    def test_local_pwa_uses_a_persistent_isolated_browser_without_extensions(self):
        tray = TrayControlSource.__new__(TrayControlSource)
        tray._pwa_launching_until = 0.0

        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"LOCALAPPDATA": directory}
        ), patch(
            "control_sources.tray.config.REMOTE_API_PORT", 8766, create=True
        ), patch.object(tray, "_pwa_window", return_value=0), patch.object(
            tray, "_app_browser", return_value=Path("brave.exe")
        ), patch("control_sources.tray.subprocess.Popen") as launch:
            tray.toggle_panel()

        arguments = launch.call_args.args[0]
        self.assertEqual(arguments[0], "brave.exe")
        self.assertIn("--disable-extensions", arguments)
        self.assertIn("--disable-background-mode", arguments)
        self.assertIn("--no-first-run", arguments)
        self.assertIn("--no-default-browser-check", arguments)
        profile = next(
            item for item in arguments if item.startswith("--user-data-dir=")
        )
        self.assertIn(str(Path(directory)), profile)
        self.assertTrue(profile.endswith("PWA Browser"))
        self.assertIn("--app=http://127.0.0.1:8766", arguments)

    def test_tray_avoids_registry_promotion_and_block_covers_taskbar(self):
        root = Path(__file__).parents[1]
        gui = (root / "gui.py").read_text(encoding="utf-8")
        limiter = (root / "app_limiter.py").read_text(encoding="utf-8")

        self.assertNotIn("NotifyIconSettings", gui)
        self.assertNotIn("IsPromoted", gui)
        self.assertNotIn("retry_delays_ms", gui)
        self.assertIn('reason="explorer-restart"', gui)
        self.assertIn('os.startfile("ms-settings:taskbar")', gui)
        self.assertIn("Garder l’icône visible dans la barre", gui)
        self.assertIn("geometry = screens[0].geometry()", limiter)
        self.assertIn("self.clearMask()", limiter)
        self.assertNotIn("self.setMask(usable)", limiter)

    def test_stop_closes_local_pwa_before_monitoring_service(self):
        events = []
        tray = TrayControlSource.__new__(TrayControlSource)
        tray.service = SimpleNamespace(stop=lambda: events.append("service"))
        tray._pwa_launching_until = 3.0

        with patch.object(tray, "_pwa_window", return_value=42), patch(
            "control_sources.tray.ctypes.windll.user32.PostMessageW",
            side_effect=lambda *_: events.append("pwa"),
        ):
            tray.stop()

        self.assertEqual(events, ["pwa", "service"])
        self.assertEqual(tray._pwa_launching_until, 0.0)


if __name__ == "__main__":
    unittest.main()
