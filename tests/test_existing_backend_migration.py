import json
import tempfile
import unittest
from pathlib import Path

from tools.migrate_existing_backend import merged_settings, migrate_file


class ExistingBackendMigrationTest(unittest.TestCase):
    def setUp(self):
        self.existing = {
            "enabled": True,
            "base_url": "https://example.test/usage-guard/",
            "device_id": "device-existing",
            "device_token": "s" * 48,
            "poll_seconds": 15,
        }
        self.migration = {
            "installation_profile": "server",
            "reuse_existing_credentials": True,
            "base_url": "https://example.test/usage-guard",
            "device_id": "device-existing",
            "display_name": "Bureau",
            "windows_identities": [{
                "windows_sid": "s-1-5-21-1-2-3-1001",
                "windows_domain": "PC",
                "windows_username": "Alice",
                "usage_guard_username": "alice",
            }],
            "device_token": "untrusted-wizard-value",
        }

    def test_merge_preserves_device_id_secret_and_existing_settings(self):
        result = merged_settings(self.existing, self.migration)
        self.assertEqual(result["device_id"], "device-existing")
        self.assertEqual(result["device_token"], "s" * 48)
        self.assertEqual(result["poll_seconds"], 15)
        self.assertEqual(result["installation_profile"], "server")
        self.assertEqual(
            result["windows_identities"][0]["windows_sid"],
            "S-1-5-21-1-2-3-1001",
        )

    def test_merge_rejects_another_device_or_server(self):
        with self.assertRaisesRegex(ValueError, "identité protégée"):
            merged_settings(self.existing, {**self.migration, "device_id": "other"})
        with self.assertRaisesRegex(ValueError, "serveur"):
            merged_settings(self.existing, {
                **self.migration, "base_url": "https://other.example/usage-guard",
            })

    def test_failed_migration_does_not_replace_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            existing = root / "backend.json"
            migration = root / "migration.json"
            existing.write_text(json.dumps(self.existing), encoding="utf-8")
            migration.write_text(
                json.dumps({**self.migration, "windows_identities": []}),
                encoding="utf-8",
            )
            before = existing.read_bytes()
            with self.assertRaises(ValueError):
                migrate_file(existing, migration)
            self.assertEqual(existing.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
