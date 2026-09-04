import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import build_exe
from tools import build_v2_candidate


class V2BuildExecutableTest(unittest.TestCase):
    def test_root_builder_targets_the_v2_candidate_and_controlled_switch(self):
        self.assertEqual(build_exe.INSTALLED_EXECUTABLE.name, "usage-guard.exe")
        self.assertEqual(build_exe.STAGING_DIST, ROOT / "build" / "v2-release")
        command = build_exe.switch_command(build_exe.STAGING_DIST / "usage-guard.exe")
        self.assertIn("switch_to_v2.ps1", " ".join(command))
        self.assertIn("-CandidatePath", command)

    def test_candidate_builder_accepts_an_isolated_destination(self):
        self.assertTrue(callable(build_v2_candidate.build_candidate))
        source = (ROOT / "tools" / "build_v2_candidate.py").read_text(encoding="utf-8")
        self.assertIn('"--add-data", f"{ROOT / \'pwa\'};pwa"', source)
        self.assertIn('str(ROOT / "main.py")', source)

    def test_switch_only_installs_candidates_from_the_controlled_staging_area(self):
        source = (ROOT / "tools" / "switch_to_v2.ps1").read_text(encoding="utf-8")
        self.assertIn('build\\v2-release', source)
        self.assertIn('usage-guard.previous.exe', source)
        self.assertIn('Update-ProductionService', source)
        self.assertIn('install_production_service.ps1', source)
        self.assertIn('Start-V1Rollback', source)

    def test_service_update_is_backed_up_and_can_enable_the_backend(self):
        source = (ROOT / "tools" / "install_production_service.ps1").read_text(encoding="utf-8")
        self.assertIn('[switch]$EnableBackend', source)
        self.assertIn('UsageGuardServiceBackup-', source)
        self.assertIn('throw $failed', source)


if __name__ == "__main__":
    unittest.main()
