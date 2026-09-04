import tempfile
import unittest
from pathlib import Path

from usage_guard_backend.bootstrap_admin import create_initial_admin
from usage_guard_backend.server import Store


class ServerAdminBootstrapTest(unittest.TestCase):
    def test_first_admin_is_created_server_side_and_second_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "backend.sqlite3"

            created = create_initial_admin(
                database, "owner", "temporary-strong", "owner@example.test",
            )

            self.assertTrue(created["is_admin"])
            self.assertEqual(created["role"], "admin")
            self.assertTrue(Store(database).has_admin())
            with self.assertRaisesRegex(ValueError, "existe déjà"):
                create_initial_admin(database, "other", "temporary-strong")


if __name__ == "__main__":
    unittest.main()
