import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class TestSuiteIsolationTest(unittest.TestCase):
    def test_test_process_itself_uses_the_isolated_profile(self):
        import runtime_profile

        self.assertEqual(runtime_profile.current_profile().name, "test")
        self.assertEqual(runtime_profile.current_profile().remote_api_port, 0)

    def test_unittest_discovery_without_package_import_is_also_isolated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local_app_data = root / "local-app-data"
            production = local_app_data / "Usage Guard"
            production.mkdir(parents=True)
            (production / "backend.json").write_text(json.dumps({
                "enabled": True,
                "base_url": "https://production.invalid/usage-guard",
                "device_id": "production-device",
                "device_token": "x" * 40,
            }), encoding="utf-8")
            probe = root / "test_discovery_probe.py"
            probe.write_text("""
import unittest

import backend_client
import runtime_profile
import usage_guard


class DiscoveryIsolationProbe(unittest.TestCase):
    def test_profile_and_paths(self):
        profile = runtime_profile.current_profile()
        self.assertEqual(profile.name, "test")
        self.assertEqual(profile.remote_api_port, 0)
        self.assertIn("Usage Guard Test", str(usage_guard._usage_path()))
        backend = backend_client.load_backend_settings()
        self.assertFalse(backend["enabled"])
        self.assertNotEqual(backend["device_id"], "production-device")
""", encoding="utf-8")
            environment = dict(os.environ)
            environment.pop("USAGE_GUARD_PROFILE", None)
            environment["LOCALAPPDATA"] = str(local_app_data)
            existing_python_path = environment.get("PYTHONPATH", "")
            environment["PYTHONPATH"] = str(ROOT) + (
                os.pathsep + existing_python_path if existing_python_path else ""
            )

            result = subprocess.run(
                [
                    sys.executable, "-m", "unittest", "discover",
                    "-s", str(root), "-p", "test_discovery_probe.py",
                ],
                cwd=ROOT, env=environment, capture_output=True, text=True,
                timeout=20,
            )

            self.assertEqual(
                result.returncode, 0, result.stdout + result.stderr,
            )

    def test_package_selects_isolated_profile_before_application_imports(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = dict(os.environ)
            # Even a stale caller environment must not opt the complete test
            # process back into the production installation.
            environment["USAGE_GUARD_PROFILE"] = "production"
            environment["LOCALAPPDATA"] = directory
            production = Path(directory) / "Usage Guard"
            production.mkdir(parents=True)
            (production / "backend.json").write_text(json.dumps({
                "enabled": True,
                "base_url": "https://production.invalid/usage-guard",
                "device_id": "production-device",
                "device_token": "x" * 40,
            }), encoding="utf-8")

            source = """
import json
import tests
import backend_client
import runtime_profile
import usage_guard

profile = runtime_profile.current_profile()
print(json.dumps({
    "profile": profile.name,
    "data_directory": str(profile.local_data_directory()),
    "usage_path": str(usage_guard._usage_path()),
    "remote_api_port": profile.remote_api_port,
    "browser_bridge_port": profile.browser_bridge_port,
    "decision_pipe_name": profile.decision_pipe_name,
    "backend": backend_client.load_backend_settings(),
}))
"""
            result = subprocess.run(
                [sys.executable, "-c", source],
                cwd=ROOT,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
            )
            state = json.loads(result.stdout)

        self.assertEqual(state["profile"], "test")
        self.assertEqual(state["remote_api_port"], 0)
        self.assertEqual(state["browser_bridge_port"], 0)
        self.assertEqual(
            state["decision_pipe_name"],
            r"\\.\pipe\UsageGuardDecisionTest",
        )
        self.assertIn("Usage Guard Test", state["data_directory"])
        self.assertIn("Usage Guard Test", state["usage_path"])
        self.assertFalse(state["backend"]["enabled"])
        self.assertNotEqual(
            state["backend"]["base_url"],
            "https://production.invalid/usage-guard",
        )
        self.assertNotEqual(state["backend"]["device_id"], "production-device")

    def test_explicit_production_profile_checks_remain_available(self):
        import runtime_profile

        production = runtime_profile.profile_named("production")
        self.assertTrue(production.production)
        self.assertTrue(production.allow_backend)
        self.assertEqual(production.remote_api_port, 8766)


if __name__ == "__main__":
    unittest.main()
