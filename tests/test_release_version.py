import tempfile
import unittest
from datetime import datetime
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from release_version import (
    entries,
    next_available_version,
    next_version,
    plan_release,
    prepare_release,
    render_service_worker,
)


CHANGELOG = """# Journal des versions

01/08/2026 10:00 — v1.001 — Première publication.
02/08/2026 11:00 — v1.002 — Deuxième publication.
"""

WORKER = """const CACHE=`usage-guard-shell-v59:${self.location.port}`;
const SHELL=["style.css?v=59","i18n.js?v=59","app.js?v=59"];
"""
INDEX = '<link href="style.css?v=59"><script src="i18n.js?v=59"></script><script src="app.js?v=59"></script>'
APP = 'navigator.serviceWorker.register("service-worker.js?v=59")'


class ReleaseVersionTest(unittest.TestCase):
    def _deployment_script(self):
        path = Path(__file__).parents[1] / "usage_guard_backend" / "deploy-server.ps1"
        if not path.is_file():
            self.skipTest(
                "The private infrastructure deployment script is not distributed."
            )
        return path.read_text(encoding="utf-8")

    def test_deploy_script_reports_release_errors_without_a_powershell_stack(self):
        script = self._deployment_script()
        self.assertIn("function Stop-Deployment", script)
        self.assertIn("ECHEC DU DEPLOIEMENT", script)
        self.assertIn("longueur actuelle", script)
        self.assertIn("Invoke-ReleaseVersion", script)

    def test_deploy_keeps_only_five_automatic_database_backups(self):
        script = self._deployment_script()
        self.assertIn("[int]$BackupRetentionCount = 5", script)
        self.assertIn("prune_server_backups.py", script)
        self.assertIn("--keep $BackupRetentionCount --protect '$backupFile' --apply", script)
        self.assertIn("le deploiement valide reste actif", script)
        self.assertIn("PRAGMA quick_check", script)
        rollback_index = script.index("throw $failure")
        retention_index = script.index("Retention des sauvegardes automatiques")
        finished_index = script.index("Deploiement termine")
        self.assertLess(rollback_index, retention_index)
        self.assertLess(retention_index, finished_index)

    def test_pwa_sync_updates_in_place_without_requiring_delete_rights(self):
        script = (
            Path(__file__).parents[1] / "usage_guard_backend" / "sync_pwa.py"
        ).read_text(encoding="utf-8")
        self.assertIn("dirs_exist_ok=True", script)
        self.assertNotIn("shutil.rmtree", script)

    def test_project_changelog_and_pwa_share_one_current_version(self):
        root = Path(__file__).resolve().parents[1]
        changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
        versions = [entry.version for entry in entries(changelog)]
        self.assertTrue(versions)
        for index, (previous, current) in enumerate(zip(versions, versions[1:])):
            previous_major = int(previous.split(".")[0])
            current_major, current_revision = map(int, current.split("."))
            is_explicit_major_break = (
                current_major == previous_major + 1 and current_revision == 0
            )
            is_stable_reset = (
                previous_major >= 2 and current == "1.000"
            )
            self.assertTrue(
                current == next_available_version(previous, versions[:index])
                or is_explicit_major_break
                or is_stable_reset,
                f"Transition de version invalide : {previous} -> {current}",
            )
        current = versions[-1]
        self.assertFalse((root / "VERSION").exists())
        self.assertIn(
            f"style.css?v={current}",
            (root / "pwa" / "index.html").read_text(encoding="utf-8"),
        )
        self.assertIn(
            f"i18n.js?v={current}",
            (root / "pwa" / "index.html").read_text(encoding="utf-8"),
        )
        self.assertIn(
            f"service-worker.js?v={current}",
            (root / "pwa" / "app.js").read_text(encoding="utf-8"),
        )
        self.assertIn(
            "usage-guard-shell-v" + current.replace(".", "-"),
            (root / "pwa" / "service-worker.js").read_text(encoding="utf-8"),
        )

    def test_revision_increments_and_rolls_to_next_major(self):
        self.assertEqual(next_version("1.002"), "1.003")
        self.assertEqual(next_version("1.999"), "2.001")
        self.assertEqual(
            next_available_version("1.000", {"1.001", "1.002"}), "1.003",
        )

    def test_release_after_stable_reset_skips_historical_v1_collisions(self):
        changelog = CHANGELOG + (
            "03/08/2026 12:00 — v2.000 — Préversion de développement.\n"
            "04/08/2026 12:00 — v1.000 — Première base stable du produit.\n"
        )
        plan = plan_release(
            changelog,
            changes="Correctif après le retour à la version stable",
            deployed_version="1.000",
        )
        self.assertEqual(plan.version, "1.003")

    def test_explicit_major_break_can_start_at_zero(self):
        plan = plan_release(
            CHANGELOG,
            changes="Rupture volontaire du protocole client",
            requested_version="2.000",
            deployed_version="1.002",
        )
        self.assertEqual(plan.version, "2.000")

    def test_stable_reset_accepts_the_one_off_v2_to_v1_transition(self):
        changelog = CHANGELOG + (
            "03/08/2026 12:00 — v2.000 — Préversion de développement.\n"
        )

        plan = plan_release(
            changelog,
            changes="Première base stable du produit",
            requested_version="1.000",
            deployed_version="2.000",
            stable_reset=True,
        )

        self.assertEqual(plan.version, "1.000")
        self.assertTrue(plan.new_entry)

    def test_stable_reset_refuses_any_target_other_than_v1(self):
        changelog = CHANGELOG + (
            "03/08/2026 12:00 — v2.000 — Préversion de développement.\n"
        )
        with self.assertRaisesRegex(ValueError, "réinitialisation stable"):
            plan_release(
                changelog,
                changes="Transition stable invalide",
                requested_version="1.001",
                deployed_version="2.000",
                stable_reset=True,
            )

    def test_new_release_is_based_on_deployed_version(self):
        plan = plan_release(
            CHANGELOG,
            changes="Ajout d’une nouvelle vue",
            deployed_version="1.002",
        )
        self.assertEqual(plan.version, "1.003")
        self.assertTrue(plan.new_entry)

    def test_prepared_failed_release_can_be_resumed(self):
        plan = plan_release(
            CHANGELOG,
            changes="Deuxième publication",
            deployed_version="1.001",
        )
        self.assertEqual(plan.version, "1.002")
        self.assertFalse(plan.new_entry)

    def test_republish_keeps_deployed_version(self):
        plan = plan_release(
            CHANGELOG, deployed_version="1.001", republish=True
        )
        self.assertEqual(plan.version, "1.001")
        self.assertFalse(plan.new_entry)

    def test_prepare_appends_changelog_and_versions_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            changelog = root / "CHANGELOG.md"
            index = root / "index.html"
            app = root / "app.js"
            worker = root / "service-worker.js"
            changelog.write_text(CHANGELOG, encoding="utf-8")
            index.write_text(INDEX, encoding="utf-8")
            app.write_text(APP, encoding="utf-8")
            worker.write_text(WORKER, encoding="utf-8")
            plan = plan_release(CHANGELOG, changes="Troisième publication")

            entry = prepare_release(
                changelog,
                index,
                app,
                worker,
                plan,
                now=datetime(2026, 8, 15, 14, 30),
            )

            self.assertEqual(
                entry,
                "15/08/2026 14:30 — v1.003 — Troisième publication.",
            )
            self.assertIn(entry, changelog.read_text(encoding="utf-8"))
            rendered = worker.read_text(encoding="utf-8")
            self.assertIn("usage-guard-shell-v1-003", rendered)
            self.assertIn("style.css?v=1.003", rendered)
            self.assertIn("i18n.js?v=1.003", rendered)
            self.assertIn("app.js?v=1.003", rendered)
            self.assertIn("style.css?v=1.003", index.read_text(encoding="utf-8"))
            self.assertIn("i18n.js?v=1.003", index.read_text(encoding="utf-8"))
            self.assertIn("app.js?v=1.003", index.read_text(encoding="utf-8"))
            self.assertIn(
                "service-worker.js?v=1.003", app.read_text(encoding="utf-8")
            )

    def test_invalid_changes_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "une seule phrase"):
            plan_release(CHANGELOG, changes="Première phrase. Deuxième phrase")

    def test_worker_requires_all_markers(self):
        with self.assertRaisesRegex(ValueError, "marqueurs"):
            render_service_worker('const CACHE="missing";', "1.003")


if __name__ == "__main__":
    unittest.main()
