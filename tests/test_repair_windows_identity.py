import tempfile
import unittest
from pathlib import Path

from usage_guard_backend.repair_windows_identity import repair
from usage_guard_backend.server import Store


class RepairWindowsIdentityTest(unittest.TestCase):
    def test_repair_is_explicit_backed_up_and_reattributes_existing_usage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "backend.sqlite3"
            backups = root / "backups"
            store = Store(database)
            store.create_user("admin", "temporary-strong", role="admin")
            store.create_user("eva", "temporary-strong", role="limited")
            store.create_user("nicklaus", "temporary-strong", role="limited")
            store.register_device("pc-main", "ordinateur-principal", token="x" * 48)
            store.set_device_windows_identities("pc-main", [{
                "windows_sid": "S-1-5-21-1-2-3-1001",
                "windows_domain": "NUC11PHKi7",
                "windows_username": "nicklaus",
                "usage_guard_username": "eva",
            }], "admin")
            with store.connect() as db:
                with db:
                    db.execute("UPDATE users SET role='user' WHERE username='eva'")
                    db.execute(
                        "INSERT INTO activity_intervals(device_id,interval_id,windows_sid,"
                        "usage_guard_username,target_key,started_at,ended_at,policy_revision,received_at) "
                        "VALUES(?,?,?,?,?,?,?,?,?)",
                        ("pc-main", "one", "S-1-5-21-1-2-3-1001", "eva", "app:test",
                         "2026-08-24T01:47:00+02:00", "2026-08-24T01:48:00+02:00",
                         0, "2026-08-24T01:49:00+02:00"),
                    )

            preview = repair(
                database, "eva", "nicklaus", "nicklaus", backups,
            )
            self.assertFalse(preview["applied"])
            self.assertFalse(backups.exists())

            result = repair(
                database, "eva", "nicklaus", "nicklaus", backups, apply=True,
            )

            self.assertTrue(result["applied"])
            self.assertTrue(Path(result["backup"]).is_file())
            self.assertEqual(
                Store(database).device_windows_identities("pc-main")[0][
                    "usage_guard_username"
                ],
                "nicklaus",
            )
            with store.connect() as db:
                owner = db.execute(
                    "SELECT usage_guard_username FROM activity_intervals "
                    "WHERE device_id='pc-main' AND interval_id='one'"
                ).fetchone()[0]
            self.assertEqual(owner, "nicklaus")


if __name__ == "__main__":
    unittest.main()
