import ast
import json
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import call, patch

from tools import build_client_release, install_client_launcher


ROOT = Path(__file__).parents[1]


class InstallClientLauncherTest(unittest.TestCase):
    def test_launcher_is_gui_elevated_and_runs_the_packaged_installer(self):
        source = (ROOT / "tools" / "install_client_launcher.py").read_text(
            encoding="utf-8"
        )
        ast.parse(source)
        self.assertIn('ShellExecuteW(', source)
        self.assertIn('"runas"', source)
        self.assertIn('"tools" / "install_client.ps1"', source)
        self.assertIn('"-PackageRoot", str(root)', source)
        self.assertIn('CREATE_NO_WINDOW', source)
        self.assertIn('getattr(sys, "_MEIPASS", "")', source)
        self.assertIn('capture_output=True', source)
        self.assertIn('"ms-settings:taskbar"', source)

    def test_failure_log_keeps_powershell_diagnostics(self):
        completed = subprocess.CompletedProcess(
            ["powershell.exe"], 1, stdout="préparation", stderr="cause réelle"
        )
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(install_client_launcher.os.environ, {"PROGRAMDATA": directory}),
        ):
            path = install_client_launcher.write_install_log(completed)
            content = path.read_text(encoding="utf-8")
        self.assertIn("exit=1", content)
        self.assertIn("préparation", content)
        self.assertIn("cause réelle", content)
        self.assertEqual(
            install_client_launcher.failure_summary(completed), "cause réelle"
        )

    def test_release_builder_includes_the_installer_executable(self):
        source = (ROOT / "tools" / "build_client_release.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('INSTALLER_NAME = f"Installer-Usage-Guard-{CLIENT_VERSION}.exe"', source)
        self.assertIn('"--uac-admin"', source)
        self.assertIn('build_installer_launcher(root, installer_root)', source)
        self.assertIn('"--add-data"', source)
        self.assertIn('output / INSTALLER_NAME', source)
        self.assertIn('build_setup_wizard(root)', source)
        self.assertIn('build_service_runtime(root)', source)
        self.assertIn('update_root / "service-runtime"', source)
        self.assertIn('write_internal_manifest(update_root)', source)
        self.assertIn('write_internal_manifest(installer_root)', source)
        self.assertIn('installer_root / SETUP_NAME', source)
        self.assertIn('path.relative_to(update_root)', source)
        self.assertIn('ROOT / "browser_extension"', source)
        self.assertNotIn('update_root / SETUP_NAME', source)

    def test_initial_installer_explains_browser_extension_activation(self):
        source = (ROOT / "tools" / "install_client_launcher.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("show_browser_extension_guidance", source)
        self.assertIn("Browser Extension", source)
        self.assertIn("chaque profil de navigateur", source)

    def test_initial_installer_and_update_zip_have_distinct_payloads(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "candidate.exe"
            setup = root / "setup.exe"
            runtime = root / "runtime"
            runtime.mkdir()
            candidate.write_bytes(b"desktop")
            setup.write_bytes(b"setup")
            (runtime / "UsageGuardService.exe").write_bytes(b"service")

            def fake_launcher(work_root, payload_root):
                self.assertTrue((payload_root / build_client_release.SETUP_NAME).is_file())
                self.assertTrue((payload_root / "client-manifest.json").is_file())
                self.assertTrue(
                    (payload_root / "service-runtime" / "UsageGuardService.exe").is_file()
                )
                self.assertFalse(
                    (payload_root / build_client_release.SERVICE_RUNTIME_ARCHIVE).exists()
                )
                launcher = work_root / build_client_release.INSTALLER_NAME
                launcher.write_bytes(b"installer")
                return launcher

            with (
                patch.object(build_client_release, "build_candidate", return_value=candidate),
                patch.object(build_client_release, "build_setup_wizard", return_value=setup),
                patch.object(build_client_release, "build_service_runtime", return_value=runtime),
                patch.object(build_client_release, "build_installer_launcher", side_effect=fake_launcher),
            ):
                manifest = build_client_release.build_release(output=root / "output")

            package = root / "output" / manifest["filename"]
            with zipfile.ZipFile(package) as archive:
                names = set(archive.namelist())
                internal = json.loads(archive.read("client-manifest.json"))
            self.assertNotIn(build_client_release.SETUP_NAME, names)
            self.assertIn("usage-guard.exe", names)
            self.assertNotIn("usage-guard-v2.exe", names)
            self.assertIn("browser-extension/manifest.json", names)
            self.assertIn(build_client_release.SERVICE_RUNTIME_ARCHIVE, names)
            self.assertFalse(any(name.startswith("service-runtime/") for name in names))
            self.assertLessEqual(
                len(names), build_client_release.LEGACY_MAX_PACKAGE_MEMBERS
            )
            self.assertEqual(internal["version"], build_client_release.CLIENT_VERSION)
            self.assertEqual(names, set(internal["files"]) | {"client-manifest.json"})
            with zipfile.ZipFile(package) as outer:
                runtime_archive = root / "runtime.zip"
                runtime_archive.write_bytes(
                    outer.read(build_client_release.SERVICE_RUNTIME_ARCHIVE)
                )
            with zipfile.ZipFile(runtime_archive) as runtime_zip:
                self.assertIn("UsageGuardService.exe", runtime_zip.namelist())
            self.assertTrue(
                (root / "output" / build_client_release.INSTALLER_NAME).is_file()
            )

    def test_internal_manifest_keeps_client_and_pwa_versions_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "package"
            pwa = root / "pwa"
            package.mkdir()
            pwa.mkdir()
            (package / "usage-guard.exe").write_bytes(b"desktop")
            (pwa / "index.html").write_text(
                '<script src="app.js?v=1.102"></script>', encoding="utf-8"
            )
            (pwa / "service-worker.js").write_text(
                'const CACHE=`usage-guard-shell-v1-102:${self.location.port}`;',
                encoding="utf-8",
            )
            with (
                patch.object(build_client_release, "CLIENT_VERSION", "1.004"),
                patch.object(build_client_release, "PWA_ROOT", pwa),
            ):
                manifest_path = build_client_release.write_internal_manifest(package)

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["version"], "1.004")
            self.assertEqual(manifest["pwa_version"], "1.102")

    def test_ci_can_require_authenticode_signing(self):
        with (
            patch.dict(
                build_client_release.os.environ,
                {"USAGE_GUARD_REQUIRE_SIGNING": "1"},
                clear=True,
            ),
            self.assertRaisesRegex(RuntimeError, "Certificat"),
        ):
            build_client_release.sign_windows_executable(Path("client.exe"))

    def test_authenticode_signature_is_verified_after_signing(self):
        executable = Path("client.exe")
        with (
            patch.dict(
                build_client_release.os.environ,
                {
                    "USAGE_GUARD_SIGNING_THUMBPRINT": "ABC123",
                    "USAGE_GUARD_REQUIRE_SIGNING": "1",
                    "USAGE_GUARD_TIMESTAMP_URL": "https://timestamp.example",
                },
                clear=True,
            ),
            patch.object(build_client_release.shutil, "which", return_value="signtool.exe"),
            patch.object(build_client_release.subprocess, "run") as run,
        ):
            build_client_release.sign_windows_executable(executable)

        self.assertEqual(
            run.call_args_list,
            [
                call(
                    [
                        "signtool.exe", "sign", "/sha1", "ABC123", "/fd", "SHA256",
                        "/tr", "https://timestamp.example", "/td", "SHA256",
                        str(executable),
                    ],
                    check=True,
                ),
                call(
                    ["signtool.exe", "verify", "/pa", "/v", str(executable)],
                    check=True,
                ),
            ],
        )


if __name__ == "__main__":
    unittest.main()
