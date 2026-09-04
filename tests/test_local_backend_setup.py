import json
import tempfile
import unittest
from pathlib import Path

from tools.init_local_backend import initialize_local_backend
from usage_guard_backend.server import Store


class LocalBackendSetupTest(unittest.TestCase):
    def test_initializer_creates_one_local_device_and_sid_users(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "backend.sqlite3"
            settings = root / "backend.json"
            configuration = {
                "installation_profile": "local",
                "display_name": "PC local",
                "administrator": {
                    "username": "guardian",
                    "protected_password": "encrypted-not-plaintext",
                    "email": "admin@example.test",
                },
                "users": [{
                    "username": "alice", "role": "limited",
                    "permissions": {
                        "view_activity": True, "view_analysis": True,
                        "view_limits": True, "view_notifications": True,
                        "manage_activity": True, "manage_limits": False,
                        "manage_notifications": True,
                    },
                }, {
                    "username": "bob", "role": "limited",
                    "permissions": {},
                }],
                "windows_identities": [{
                    "windows_sid": "S-1-5-21-1-2-3-1001",
                    "windows_domain": "PC", "windows_username": "Alice",
                    "usage_guard_username": "alice",
                }, {
                    "windows_sid": "S-1-5-21-1-2-3-1002",
                    "windows_domain": "PC", "windows_username": "Bob",
                    "usage_guard_username": "bob",
                }],
            }

            result = initialize_local_backend(
                database, settings, configuration,
                secret_unprotector=lambda protected: (
                    "usage-guard-admin-password"
                    if protected == "encrypted-not-plaintext" else ""
                ),
            )

            self.assertEqual(result["installation_profile"], "local")
            self.assertTrue(result["base_url"].startswith("http://127.0.0.1:"))
            self.assertNotIn("password", settings.read_text(encoding="utf-8").casefold())
            store = Store(database)
            self.assertTrue(store.authenticate("guardian", "usage-guard-admin-password")["is_admin"])
            self.assertIsNone(store.authenticate("guardian", "wrong-password"))
            self.assertEqual(
                store.user_for_windows_sid(
                    result["device_id"], "S-1-5-21-1-2-3-1001"
                )["usage_guard_username"],
                "alice",
            )
            self.assertEqual(len(store.device_windows_identities(result["device_id"])), 2)

    def test_initializer_never_overwrites_existing_database(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "backend.sqlite3"
            database.write_bytes(b"existing")
            with self.assertRaisesRegex(RuntimeError, "réparée"):
                initialize_local_backend(
                    database, root / "backend.json", {},
                    secret_unprotector=lambda _value: "unused",
                )
            self.assertEqual(database.read_bytes(), b"existing")


if __name__ == "__main__":
    unittest.main()
