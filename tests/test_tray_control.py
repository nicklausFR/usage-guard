import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from control_sources.tray import TrayControlSource


class TrayControlSourceTest(unittest.TestCase):
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
