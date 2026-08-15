import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guard import MonitoringService


class MultimediaTargetTest(unittest.TestCase):
    def test_configured_players_are_multimedia(self):
        self.assertTrue(MonitoringService._is_multimedia_target("app:potplayermini64"))
        self.assertTrue(MonitoringService._is_multimedia_target("app:vlc"))

    def test_configured_video_sites_are_multimedia(self):
        self.assertTrue(
            MonitoringService._is_multimedia_target("site:brave.exe:youtube.com")
        )
        self.assertTrue(
            MonitoringService._is_multimedia_target("site:brave.exe:netflix.com")
        )

    def test_regular_apps_are_not_multimedia(self):
        self.assertFalse(MonitoringService._is_multimedia_target("app:chatgpt"))


if __name__ == "__main__":
    unittest.main()
