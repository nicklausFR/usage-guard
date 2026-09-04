import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import setup_client


class FakeAdminApi:
    instances = []

    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.logged_out = False
        self.calls = []
        self.__class__.instances.append(self)

    def login(self, username, password):
        self.calls.append(("login", username, password))
        return {"is_admin": True}

    def request(self, path, payload=None, method=None):
        self.calls.append((path, payload, method))
        if path == "/api/v1/admin/users":
            return {
                "users": [
                    {"username": "admin", "role": "admin"},
                    {"username": "alice", "role": "limited"},
                    {"username": "helper", "role": "user"},
                ],
                "devices": [
                    {"device_id": "device-old", "label": "Bureau"},
                ],
            }
        if path == "/api/v1/admin/device-enrollments":
            return {"enrollment": {"code": "a" * 24, "device_id": "new-id"}}
        raise AssertionError(path)

    def logout(self):
        self.logged_out = True


class SetupClientTest(unittest.TestCase):
    def setUp(self):
        FakeAdminApi.instances.clear()

    def test_wizard_authenticates_admin_and_assigns_limited_user(self):
        with (
            patch.object(setup_client, "AdminApi", FakeAdminApi),
            patch.object(
                setup_client, "prompt",
                side_effect=[
                    "https://example.test/usage-guard", "root", "Portable Alice",
                ],
            ),
            patch.object(setup_client, "choose", side_effect=[0, 0]),
            patch.object(setup_client.getpass, "getpass", return_value="secret-password"),
            patch.object(setup_client.socket, "gethostname", return_value="PC-WINDOWS"),
        ):
            result = setup_client.run_wizard()

        self.assertEqual(result["limited_username"], "alice")
        self.assertEqual(result["display_name"], "Portable Alice")
        self.assertNotIn("password", result)
        api = FakeAdminApi.instances[0]
        self.assertEqual(api.calls[0], ("login", "root", "secret-password"))
        enrollment = next(call for call in api.calls if call[0].endswith("device-enrollments"))
        self.assertEqual(enrollment[1]["username"], "alice")
        self.assertEqual(enrollment[1]["device_id"], "")
        self.assertTrue(api.logged_out)

    def test_wizard_can_rotate_an_existing_device(self):
        with (
            patch.object(setup_client, "AdminApi", FakeAdminApi),
            patch.object(
                setup_client, "prompt",
                side_effect=["https://example.test/usage-guard", "root", "Bureau rénové"],
            ),
            patch.object(setup_client, "choose", side_effect=[0, 1]),
            patch.object(setup_client.getpass, "getpass", return_value="secret-password"),
        ):
            setup_client.run_wizard()

        api = FakeAdminApi.instances[0]
        enrollment = next(call for call in api.calls if call[0].endswith("device-enrollments"))
        self.assertEqual(enrollment[1]["device_id"], "device-old")
        self.assertEqual(enrollment[1]["display_name"], "Bureau rénové")

    def test_result_file_contains_only_one_time_installation_material(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            setup_client.atomic_json(output, {
                "base_url": "https://example.test/usage-guard",
                "enrollment_code": "one-time",
                "display_name": "PC",
            })
            content = output.read_text(encoding="utf-8")
        self.assertNotIn("password", content.casefold())

    def test_windows_mapping_uses_explicit_sid_and_never_guesses_by_name(self):
        mapping = setup_client.windows_identity_mapping({
            "windows_sid": "s-1-5-21-1-2-3-1001",
            "windows_domain": "PC",
            "windows_username": "Alice",
            "is_windows_admin": True,
        }, "person-alice")

        self.assertEqual(mapping["windows_sid"], "S-1-5-21-1-2-3-1001")
        self.assertEqual(mapping["usage_guard_username"], "person-alice")
        self.assertTrue(mapping["is_windows_admin"])
        with self.assertRaises(ValueError):
            setup_client.windows_identity_mapping({
                "windows_username": "Alice",
            }, "person-alice")

    def test_windows_mapping_rejects_duplicate_sid_or_usage_guard_user(self):
        first = {
            "windows_sid": "S-1-5-21-1-2-3-1001",
            "windows_username": "Alice",
            "usage_guard_username": "alice",
        }
        with self.assertRaisesRegex(ValueError, "Windows"):
            setup_client.validate_windows_identity_mappings([first, dict(first)])
        with self.assertRaisesRegex(ValueError, "Usage Guard"):
            setup_client.validate_windows_identity_mappings([
                first,
                {**first, "windows_sid": "S-1-5-21-1-2-3-1002"},
            ])

    def test_qt_wizard_places_profile_choice_before_server_login(self):
        source = (
            Path(__file__).parents[1] / "tools" / "setup_client_qt.py"
        ).read_text(encoding="utf-8")
        self.assertLess(source.index("self.profile_panel"), source.index("self.login_panel"))
        self.assertIn("Local — un seul ordinateur", source)
        self.assertIn("Connecté à un serveur", source)
        self.assertIn("enumerate_windows_accounts", source)
        self.assertIn("current_windows_session_identity", source)
        self.assertIn('labels.append(_("session active"))', source)
        self.assertIn("self.setMinimumWidth(880)", source)
        self.assertIn("Qt.ToolTipRole", source)
        self.assertIn("self.display_name.setText(socket.gethostname())", source)
        self.assertIn('"windows_identities": mappings', source)
        self.assertIn('== "limited"', source)
        self.assertNotIn('role.addItem("Utilisateur", "user")', source)

    def test_installer_deletes_the_temporary_enrollment_result(self):
        script = (
            Path(__file__).parents[1] / "tools" / "install_client.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("Configurer-Usage-Guard.exe", script)
        self.assertIn("Remove-Item -LiteralPath $wizardResult", script)
        self.assertNotIn("password", script.casefold())

    def test_existing_installation_reuses_device_identity_without_reenrollment(self):
        root = Path(__file__).parents[1]
        wizard = (root / "tools" / "setup_client_qt.py").read_text(
            encoding="utf-8"
        )
        installer = (root / "tools" / "install_client.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn('parser.add_argument("--existing-device-id"', wizard)
        self.assertIn('"reuse_existing_credentials": True', wizard)
        self.assertIn('/windows-identities",', wizard)
        self.assertIn('@("--existing-device-id", $existingDeviceId)', installer)
        self.assertIn("-MigrationConfiguration $wizardResult", installer)
        self.assertLess(
            installer.index("if ($Update -and $windowsIdentities.Count -lt 1)"),
            installer.index("Copy-Item -LiteralPath $candidate"),
        )

    def test_packaged_installer_does_not_require_system_python(self):
        root = Path(__file__).parents[1]
        client = (root / "tools" / "install_client.ps1").read_text(encoding="utf-8")
        service = (root / "tools" / "install_production_service.ps1").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("python.exe", client.casefold())
        self.assertNotIn("python.exe", service.casefold())
        self.assertIn("UsageGuardService.exe", client)
        self.assertIn("UsageGuardService.exe", service)


if __name__ == "__main__":
    unittest.main()
