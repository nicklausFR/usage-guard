import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from activity_keys import is_other_sites_aggregate_key


class ActivityKeyTest(unittest.TestCase):
    def test_other_sites_aggregate_key_match_is_exact(self):
        self.assertTrue(is_other_sites_aggregate_key(
            "site:brave.exe:other-sites"
        ))
        for value in (
            "site::other-sites",
            "site:brave.exe:other-sites:child",
            "site:brave.exe:other-sites-extra",
            "app:brave.exe:other-sites",
            "site:brave.exe:other-sites ",
            " site:brave.exe:other-sites",
            None,
        ):
            with self.subTest(value=value):
                self.assertFalse(is_other_sites_aggregate_key(value))


if __name__ == "__main__":
    unittest.main()
