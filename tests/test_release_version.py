import tempfile
import unittest
from datetime import datetime
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from release_version import (
    entries,
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
    def test_deploy_script_reports_release_errors_without_a_powershell_stack(self):
        script = (Path(__file__).parents[1] / "usage_guard_backend" / "deploy-server.ps1").read_text(encoding="utf-8")
        self.assertIn("function Stop-Deployment", script)
        self.assertIn("ECHEC DU DEPLOIEMENT", script)
        self.assertIn("longueur actuelle", script)
        self.assertIn("Invoke-ReleaseVersion", script)

    def test_project_changelog_and_pwa_share_one_current_version(self):
        root = Path(__file__).resolve().parents[1]
        changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
        versions = [entry.version for entry in entries(changelog)]
        self.assertTrue(versions)
        for previous, current in zip(versions, versions[1:]):
            self.assertEqual(next_version(previous), current)
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
