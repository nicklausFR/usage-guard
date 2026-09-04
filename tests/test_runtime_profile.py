import json
import os
import subprocess
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import runtime_profile
import remote_api
from backend_client import load_backend_settings
from browser_bridge import BrowserBridge
from usage_guard import APP_DIR, Config, _usage_path, configure_windows_autostart


@contextmanager
def active_profile(name):
    previous = runtime_profile.current_profile()
    runtime_profile._set_active_profile_for_tests(runtime_profile.profile_named(name))
    try:
        yield runtime_profile.current_profile()
    finally:
        runtime_profile._set_active_profile_for_tests(previous)


class RuntimeProfileTest(unittest.TestCase):
    def test_production_profile_preserves_current_identifiers(self):
        profile = runtime_profile.profile_named("production")
        self.assertEqual(profile.mutex_name, "Local\\UsageGuardSingleInstance")
        self.assertEqual(profile.browser_bridge_port, 8765)
        self.assertEqual(profile.remote_api_port, 8766)
        self.assertEqual(profile.data_directory_name, "Usage Guard")
        self.assertTrue(profile.allow_backend)
        self.assertTrue(profile.allow_autostart_changes)

    def test_development_profile_is_fully_separate_and_offline(self):
        profile = runtime_profile.profile_named("dev")
        self.assertNotEqual(
            profile.mutex_name,
            runtime_profile.profile_named("production").mutex_name,
        )
        self.assertEqual(profile.browser_bridge_port, 18765)
        self.assertEqual(profile.remote_api_port, 18766)
        self.assertEqual(profile.data_directory_name, "Usage Guard Dev")
        self.assertFalse(profile.allow_backend)
        self.assertFalse(profile.allow_autostart_changes)

    def test_profile_option_is_removed_before_qt_receives_arguments(self):
        arguments = ["main.py", "--profile", "dev", "--background"]
        previous = runtime_profile.current_profile()
        try:
            selected = runtime_profile.configure_from_argv(arguments, {})
            self.assertEqual(selected.name, "dev")
            self.assertEqual(arguments, ["main.py", "--background"])
        finally:
            runtime_profile._set_active_profile_for_tests(previous)

    def test_environment_selects_profile_and_cli_has_priority(self):
        environment = {runtime_profile.PROFILE_ENVIRONMENT_VARIABLE: "dev"}
        self.assertEqual(
            runtime_profile.resolve_profile([], environment).name,
            "dev",
        )
        self.assertEqual(
            runtime_profile.resolve_profile(["--profile=production"], environment).name,
            "production",
        )

    def test_unknown_profile_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Profil Usage Guard inconnu"):
            runtime_profile.resolve_profile(["--profile", "unknown"], {})

    def test_development_paths_and_ports_do_not_touch_production(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            "os.environ", {"LOCALAPPDATA": directory}
        ), active_profile("dev") as profile:
            expected = Path(directory) / "Usage Guard Dev"
            self.assertEqual(profile.local_data_directory(), expected)
            self.assertEqual(_usage_path(), expected / "activity.json")
            with patch.object(
                remote_api.config, "REMOTE_API_PORT", profile.remote_api_port
            ), patch.object(
                remote_api.config, "REMOTE_API_TOKEN_PATH", "", create=True
            ):
                self.assertEqual(
                    remote_api._token_path(), expected / "remote-api-token.txt"
                )
            self.assertEqual(BrowserBridge().port, 18765)
            self.assertNotEqual(_usage_path(), APP_DIR / "activity.json")

    def test_development_config_disables_backend_and_autostart(self):
        with tempfile.TemporaryDirectory() as directory, active_profile("dev"):
            config_path = Path(directory) / "config.yaml"
            config_path.write_text(
                "BACKEND_ENABLED: true\nAUTOSTART_WITH_WINDOWS: true\n"
                "REMOTE_API_PORT: 8766\n",
                encoding="utf-8",
            )
            config = Config(config_path)
            self.assertFalse(config.BACKEND_ENABLED)
            self.assertFalse(config.AUTOSTART_WITH_WINDOWS)
            self.assertEqual(config.REMOTE_API_PORT, 18766)
            self.assertFalse(configure_windows_autostart(True))

    def test_saved_development_backend_credentials_cannot_enable_sync(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            "os.environ", {"LOCALAPPDATA": directory}
        ), active_profile("dev"):
            settings = Path(directory) / "Usage Guard Dev" / "backend.json"
            settings.parent.mkdir(parents=True)
            settings.write_text(
                '{"enabled":true,"base_url":"https://example.test",'
                '"device_id":"dev","device_token":"' + "x" * 32 + '"}',
                encoding="utf-8",
            )
            self.assertFalse(load_backend_settings()["enabled"])

    def test_development_profile_is_applied_before_application_imports(self):
        script = """
import json
import backend_client
import browser_bridge
import usage_guard
from runtime_profile import current_profile
print(json.dumps({
    "profile": current_profile().name,
    "usage_path": str(usage_guard.USAGE_PATH),
    "remote_port": usage_guard.config.REMOTE_API_PORT,
    "bridge_port": browser_bridge.browser_bridge.port,
    "backend_enabled": backend_client.load_backend_settings()["enabled"],
    "autostart": usage_guard.config.AUTOSTART_WITH_WINDOWS,
}))
"""
        with tempfile.TemporaryDirectory() as directory:
            environment = dict(os.environ)
            environment.update({
                "LOCALAPPDATA": directory,
                "PYTHONDONTWRITEBYTECODE": "1",
                runtime_profile.PROFILE_ENVIRONMENT_VARIABLE: "dev",
            })
            result = subprocess.run(
                [sys.executable, "-c", script],
                cwd=Path(__file__).resolve().parents[1],
                env=environment,
                capture_output=True,
                text=True,
                check=True,
            )
        state = json.loads(result.stdout)
        self.assertEqual(state["profile"], "dev")
        self.assertEqual(state["remote_port"], 18766)
        self.assertEqual(state["bridge_port"], 18765)
        self.assertFalse(state["backend_enabled"])
        self.assertFalse(state["autostart"])
        self.assertIn("Usage Guard Dev", state["usage_path"])


if __name__ == "__main__":
    unittest.main()
