import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from usage_guard_backend.prune_server_backups import (
    apply_prune_plan,
    build_prune_plan,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "usage_guard_backend" / "prune_server_backups.py"


class PruneServerBackupsTest(unittest.TestCase):
    def make_backup(self, directory, name, stamp, size=1):
        path = directory / name
        path.write_bytes(b"x" * size)
        os.utime(path, (stamp, stamp))
        return path

    def run_script(self, directory, *arguments):
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--backup-dir",
                str(directory),
                *arguments,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_dry_run_keeps_five_newest_without_deleting(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            backups = [
                self.make_backup(
                    directory,
                    f"backend-before-v1.{index:03d}-20260828-{index:06d}.sqlite3",
                    index,
                )
                for index in range(1, 8)
            ]

            completed = self.run_script(directory)

            self.assertEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("Mode: DRY RUN", completed.stdout)
            self.assertIn("to delete: 2", completed.stdout)
            self.assertIn("No files deleted", completed.stdout)
            self.assertTrue(all(path.exists() for path in backups))

    def test_apply_deletes_only_old_automatic_backups(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            old = self.make_backup(
                directory,
                "backend-before-v1.001-20260828-000001.sqlite3",
                1,
            )
            recent = self.make_backup(
                directory,
                "backend-before-v1.002-20260828-000002.sqlite3",
                2,
            )
            manual = self.make_backup(directory, "pre-v2-cutover.sqlite3", 0)
            active = self.make_backup(directory, "backend.sqlite3", 0)

            completed = self.run_script(directory, "--keep", "1", "--apply")

            self.assertEqual(completed.returncode, 0, completed.stdout)
            self.assertFalse(old.exists())
            self.assertTrue(recent.exists())
            self.assertTrue(manual.exists())
            self.assertTrue(active.exists())

    def test_embedded_timestamp_wins_over_version_name_and_mtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            newer = self.make_backup(
                directory,
                "backend-before-v1.001-20260828-120000.sqlite3",
                1,
            )
            older = self.make_backup(
                directory,
                "backend-before-v9.999-20260827-120000.sqlite3",
                999,
            )

            completed = self.run_script(directory, "--keep", "1", "--apply")

            self.assertEqual(completed.returncode, 0, completed.stdout)
            self.assertTrue(newer.exists())
            self.assertFalse(older.exists())

    def test_invalid_dates_and_special_backups_are_never_candidates(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            invalid_date = self.make_backup(
                directory,
                "backend-before-v1.001-20261340-250000.sqlite3",
                1,
            )
            test_backup = self.make_backup(
                directory,
                "backend-before-v2.000-powershell5-test.sqlite3",
                2,
            )
            valid = self.make_backup(
                directory,
                "backend-before-v1.002-20260828-120000.sqlite3",
                3,
            )

            completed = self.run_script(directory, "--keep", "1", "--apply")

            self.assertEqual(completed.returncode, 0, completed.stdout)
            self.assertTrue(invalid_date.exists())
            self.assertTrue(test_backup.exists())
            self.assertTrue(valid.exists())

    def test_protected_fresh_backup_must_be_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fresh = self.make_backup(
                directory,
                "backend-before-v1.001-20260828-120000.sqlite3",
                1,
            )
            self.make_backup(
                directory,
                "backend-before-v1.002-20260828-130000.sqlite3",
                2,
            )

            completed = self.run_script(
                directory, "--keep", "1", "--protect", str(fresh), "--apply"
            )

            self.assertEqual(completed.returncode, 1)
            self.assertIn("pruning cancelled", completed.stdout)
            self.assertTrue(fresh.exists())

    def test_replaced_file_is_refused_before_deletion(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            old = self.make_backup(
                directory,
                "backend-before-v1.001-20260828-120000.sqlite3",
                1,
            )
            self.make_backup(
                directory,
                "backend-before-v1.002-20260828-130000.sqlite3",
                2,
            )
            plan = build_prune_plan(directory, 1)
            old.unlink()
            old.write_bytes(b"replacement")

            with self.assertRaisesRegex(ValueError, "replaced"):
                apply_prune_plan(plan)

            self.assertTrue(old.exists())

    def test_refuses_zero_retention(self):
        with tempfile.TemporaryDirectory() as temporary:
            completed = self.run_script(Path(temporary), "--keep", "0", "--apply")

            self.assertEqual(completed.returncode, 1)
            self.assertIn("greater than zero", completed.stdout)

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links unavailable")
    def test_symbolic_link_is_never_deleted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "backups"
            directory.mkdir()
            target = self.make_backup(root, "outside.sqlite3", 1)
            link = directory / "backend-before-v1.001-20260828-000001.sqlite3"
            try:
                link.symlink_to(target)
            except OSError as error:
                self.skipTest(f"symbolic links unavailable: {error}")

            completed = self.run_script(directory, "--keep", "1", "--apply")

            self.assertEqual(completed.returncode, 0, completed.stdout)
            self.assertTrue(link.exists())
            self.assertTrue(target.exists())


if __name__ == "__main__":
    unittest.main()
