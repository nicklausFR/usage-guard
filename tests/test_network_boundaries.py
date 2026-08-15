import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from activity import ActivityWatchProbe
from activitywatch_manager import ActivityWatchManager
from usage_guard import config


class NetworkBoundaryTest(unittest.TestCase):
    def test_activitywatch_probe_rejects_non_loopback_urls(self):
        previous = config.ACTIVITYWATCH_BASE_URL
        try:
            config.ACTIVITYWATCH_BASE_URL = "file:///tmp/untrusted"
            self.assertEqual(ActivityWatchProbe().base_url, "http://localhost:5600")
        finally:
            config.ACTIVITYWATCH_BASE_URL = previous

    def test_activitywatch_manager_rejects_remote_hosts(self):
        previous = config.ACTIVITYWATCH_BASE_URL
        try:
            config.ACTIVITYWATCH_BASE_URL = "http://attacker.example:5600"
            self.assertEqual(ActivityWatchManager().base_url, "http://localhost:5600")
        finally:
            config.ACTIVITYWATCH_BASE_URL = previous


if __name__ == "__main__":
    unittest.main()
