import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from client_update import ClientUpdateManager, version_tuple


class FakeClient:
    def __init__(self, package, update):
        self.package = Path(package)
        self.update = dict(update)
        self.maintenance = []

    def update_manifest(self):
        return dict(self.update)

    def download_update(self, _update, destination):
        shutil.copy2(self.package, destination)

    def begin_update_maintenance(self, version, duration_seconds=900):
        self.maintenance.append((version, duration_seconds))


def make_package(path, version="9.000", corrupt=False, extra=False, duplicate=False):
    files = {
        "tools/install_client.ps1": b"Write-Output 'install'\n",
        "client_version.py": f'CLIENT_VERSION = "{version}"\n'.encode(),
    }
    manifest = {
        "version": version,
        "files": {
            name: ("0" * 64 if corrupt and name == "client_version.py" else hashlib.sha256(content).hexdigest())
            for name, content in files.items()
        },
    }
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
        if extra:
            archive.writestr("unexpected.exe", b"not listed")
        if duplicate:
            archive.writestr("client_version.py", files["client_version.py"])
        archive.writestr("client-manifest.json", json.dumps(manifest))


class ClientUpdateTest(unittest.TestCase):
    def test_optional_release_is_downloaded_and_installed_only_on_request(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "release.zip"
            make_package(package)
            launched = []
            client = FakeClient(package, {
                "version": "9.000", "minimum_version": "2.000",
                "mandatory": False, "sha256": "a" * 64, "size": 10,
            })
            manager = ClientUpdateManager(
                root / "service",
                client,
                launcher=lambda installer, stage: launched.append((installer, stage)),
            )

            manager.check()

            self.assertEqual(manager.status()["state"], "update_available")
            self.assertFalse(manager.status()["mandatory"])
            self.assertEqual(launched, [])
            with (
                patch("client_update.sys.platform", "win32"),
                patch("client_update.threading.Thread") as thread,
            ):
                thread.return_value.start.side_effect = lambda: thread.call_args.kwargs[
                    "target"
                ](*thread.call_args.kwargs["args"])
                manager.request_install()
            self.assertEqual(manager.status()["state"], "installing")
            self.assertEqual(len(launched), 1)
            self.assertEqual(client.maintenance, [("9.000", 900)])

    def test_mandatory_release_still_waits_for_an_explicit_request(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "release.zip"
            make_package(package)
            launched = []
            manager = ClientUpdateManager(
                root / "service",
                FakeClient(package, {
                    "version": "9.000", "minimum_version": "9.000",
                    "mandatory": False, "sha256": "a" * 64, "size": 10,
                }),
                launcher=lambda installer, stage: launched.append((installer, stage)),
            )

            with patch("client_update.sys.platform", "win32"):
                manager.check()

            self.assertTrue(manager.status()["mandatory"])
            self.assertEqual(manager.status()["state"], "update_available")
            self.assertEqual(launched, [])

    def test_install_request_refreshes_a_manifest_changed_during_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "release.zip"
            make_package(package)
            client = FakeClient(package, {
                "version": "8.999", "minimum_version": "2.000",
                "mandatory": False, "sha256": "a" * 64, "size": 10,
            })
            manager = ClientUpdateManager(root / "service", client)
            manager.check()
            client.update = {
                "version": "9.000", "minimum_version": "2.000",
                "mandatory": False, "sha256": "b" * 64, "size": 20,
            }

            with patch("client_update.threading.Thread") as thread:
                manager.request_install()

            self.assertEqual(manager.status()["available_version"], "9.000")
            self.assertEqual(manager.status()["manifest"]["sha256"], "b" * 64)
            self.assertEqual(
                thread.call_args.kwargs["args"][0]["version"], "9.000"
            )

    def test_corrupt_internal_file_is_never_staged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "release.zip"
            make_package(package, corrupt=True)
            manager = ClientUpdateManager(
                root / "service",
                FakeClient(package, {
                    "version": "9.000", "minimum_version": "2.000",
                    "mandatory": False, "sha256": "a" * 64, "size": 10,
                }),
            )
            manager.check()
            with self.assertRaises(ValueError):
                manager.stage(manager.status()["manifest"])
            self.assertNotEqual(manager.status()["state"], "ready")

    def test_unlisted_or_duplicate_members_are_refused(self):
        for option in ("extra", "duplicate"):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                package = root / "release.zip"
                make_package(package, **{option: True})
                manager = ClientUpdateManager(
                    root / "service",
                    FakeClient(package, {
                        "version": "9.000", "minimum_version": "2.000",
                        "mandatory": False, "sha256": "a" * 64, "size": 10,
                    }),
                )
                manager.check()
                with self.assertRaises(ValueError):
                    manager.stage(manager.status()["manifest"])

    def test_interrupted_install_is_recovered_as_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = root / "service" / "client-updates" / "staged" / "9.000"
            (stage / "tools").mkdir(parents=True)
            (stage / "tools" / "install_client.ps1").write_text("install")
            state = stage.parents[1] / "state.json"
            state.write_text(json.dumps({
                "state": "installing", "available_version": "9.000",
                "stage_path": str(stage),
            }), encoding="utf-8")

            manager = ClientUpdateManager(root / "service", object())

            self.assertEqual(manager.status()["state"], "ready")
            self.assertIn("interrompue", manager.status()["error"])

    def test_launcher_failure_leaves_verified_release_retryable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "release.zip"
            make_package(package)
            manager = ClientUpdateManager(
                root / "service",
                FakeClient(package, {
                    "version": "9.000", "minimum_version": "2.000",
                    "mandatory": False, "sha256": "a" * 64, "size": 10,
                }),
                launcher=lambda *_args: (_ for _ in ()).throw(OSError("failed")),
            )
            manager.check()
            manager.stage(manager.status()["manifest"])
            with patch("client_update.sys.platform", "win32"):
                with self.assertRaises(OSError):
                    manager.install()
            self.assertEqual(manager.status()["state"], "ready")
            self.assertIn("failed", manager.status()["error"])

    def test_detached_installer_failure_leaves_verified_release_retryable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "release.zip"
            make_package(package)

            class FailedProcess:
                @staticmethod
                def wait():
                    return 17

            manager = ClientUpdateManager(
                root / "service",
                FakeClient(package, {
                    "version": "9.000", "minimum_version": "2.000",
                    "mandatory": False, "sha256": "a" * 64, "size": 10,
                }),
                launcher=lambda *_args: FailedProcess(),
            )
            manager.check()
            manager.stage(manager.status()["manifest"])
            with (
                patch("client_update.sys.platform", "win32"),
                patch("client_update.threading.Thread") as thread,
            ):
                manager.install()
            watcher = thread.call_args.kwargs["target"]
            watcher(*thread.call_args.kwargs["args"])

            self.assertEqual(manager.status()["state"], "ready")
            self.assertIn("code de sortie 17", manager.status()["error"])
            self.assertIn("install-client.log", manager.status()["error"])

    def test_real_launcher_records_hidden_powershell_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = root / "client-updates" / "staged" / "9.000"
            installer = stage / "tools" / "install_client.ps1"
            installer.parent.mkdir(parents=True)
            installer.write_text("Write-Output install", encoding="utf-8")
            process = object()
            with patch("client_update.subprocess.Popen", return_value=process) as popen:
                result = ClientUpdateManager._launch_installer(installer, stage)

            self.assertIs(result, process)
            self.assertEqual(popen.call_args.kwargs["stderr"], subprocess.STDOUT)
            self.assertTrue(popen.call_args.kwargs["stdout"].closed)
            self.assertEqual(
                popen.call_args.kwargs["creationflags"],
                getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            log = root / "client-updates" / "install-client.log"
            self.assertIn("update installer launched", log.read_text(encoding="utf-8"))

    @unittest.skipUnless(sys.platform == "win32", "Lancement PowerShell Windows")
    def test_real_hidden_powershell_process_executes_the_installer_script(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = root / "client-updates" / "staged" / "9.000"
            installer = stage / "tools" / "install_client.ps1"
            installer.parent.mkdir(parents=True)
            installer.write_text(
                "param([switch]$Update,[string]$PackageRoot)\n"
                "$marker=Join-Path $PackageRoot 'launcher-ran.txt'\n"
                "[IO.File]::WriteAllText($marker,'ok')\n",
                encoding="utf-8",
            )

            process = ClientUpdateManager._launch_installer(installer, stage)
            self.assertEqual(process.wait(timeout=15), 0)
            self.assertEqual((stage / "launcher-ran.txt").read_text(), "ok")

    def test_version_comparison_is_numeric(self):
        self.assertLess(version_tuple("2.009"), version_tuple("2.010"))

    def test_first_stable_version_supersedes_every_legacy_v2_prerelease(self):
        self.assertGreater(version_tuple("1.000"), version_tuple("2.999"))
        self.assertGreater(version_tuple("1.001"), version_tuple("1.000"))


if __name__ == "__main__":
    unittest.main()
