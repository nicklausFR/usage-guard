import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]


class InstallerAtomicityTest(unittest.TestCase):
    def test_local_release_installer_verifies_both_manifests_before_elevation(self):
        script = (
            ROOT / "tools" / "install_local_client_release.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("Get-FileHash -LiteralPath $packagePath", script)
        self.assertIn('$internalManifestPath = Join-Path $stage "client-manifest.json"', script)
        self.assertIn("$internal.files.PSObject.Properties", script)
        self.assertIn("Get-FileHash -LiteralPath $target", script)
        self.assertIn("[StringComparison]::OrdinalIgnoreCase", script)
        self.assertLess(
            script.index("Get-FileHash -LiteralPath $target"),
            script.index('Start-Process -FilePath "powershell.exe" -Verb RunAs'),
        )
        self.assertIn("-PackageRoot `\"$stage`\" -Update", script)

    def test_desktop_installer_uses_global_lock_and_atomic_file_replace(self):
        script = (ROOT / "tools" / "install_client.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn('"Global\\UsageGuardClientInstall"', script)
        self.assertIn("[IO.File]::Replace($next, $installed, $previous", script)
        self.assertIn("[IO.File]::Replace($previous, $installed, $failedInstalled", script)
        self.assertIn("-PackageVersion $packageVersion", script)
        self.assertIn('Join-Path $PackageRoot "client-manifest.json"', script)

    def test_desktop_installer_safely_expands_the_packaged_service_runtime(self):
        script = (ROOT / "tools" / "install_client.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn('Join-Path $PackageRoot "service-runtime.zip"', script)
        self.assertIn("$runtimeArchive.Entries.Count -gt 4096", script)
        self.assertIn("$expandedBytes -gt 1GB", script)
        self.assertIn("[IO.Compression.ZipFile]::ExtractToDirectory(", script)
        self.assertIn("[StringComparison]::OrdinalIgnoreCase", script)
        self.assertLess(
            script.index("$installMutex.WaitOne(0)"),
            script.index("Expand-PackagedServiceRuntime\n", script.index("WaitOne(0)")),
        )

    def test_desktop_installer_migrates_the_legacy_executable_safely(self):
        script = (ROOT / "tools" / "install_client.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn('Join-Path $PackageRoot "usage-guard.exe"', script)
        self.assertIn('Join-Path $appDir "usage-guard.exe"', script)
        self.assertIn('Join-Path $appDir "usage-guard-v2.exe"', script)
        self.assertIn("$hadAnyInstalled = $hadInstalled -or $hadLegacyInstalled", script)
        self.assertIn("elseif ($hadAnyInstalled)", script)
        self.assertIn(
            "Copy-Item -LiteralPath $legacyInstalled -Destination $previous -Force",
            script,
        )
        service = script.index("& $serviceInstaller")
        retarget = script.index("Set-DesktopTasks $installed", service)
        health = script.index("Wait-DesktopReady `", retarget)
        remove_legacy = script.index(
            "Remove-Item -LiteralPath $legacyInstalled -Force", health
        )
        self.assertLess(service, retarget)
        self.assertLess(retarget, health)
        self.assertLess(health, remove_legacy)
        self.assertIn("Set-DesktopTasks $legacyInstalled $windowsIdentities", script)
        self.assertNotIn("if (-not $Update) {", script)

    def test_desktop_installer_requires_fresh_child_and_local_pwa_readiness(self):
        script = (ROOT / "tools" / "install_client.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("function Get-DesktopReadyMarkerPaths", script)
        self.assertIn("ProfileList\\$sid", script)
        self.assertIn('"AppData\\Local\\Usage Guard\\ready.pid"', script)
        self.assertIn("$marker.LastWriteTimeUtc -lt $notBeforeUtc", script)
        self.assertIn('-Filter "ProcessId = $readyProcessId"', script)
        self.assertIn("$markedExecutable, $expected", script)
        self.assertIn("[int]$timeoutSeconds = 180", script)
        self.assertIn('Invoke-WebRequest -UseBasicParsing `', script)
        self.assertIn('http://127.0.0.1:8766/', script)
        self.assertIn('service-worker.js?readiness=', script)
        self.assertIn("$packageManifest.pwa_version", script)
        self.assertIn("$servedPwaVersion, $servedCacheVersion", script)
        self.assertIn("$servedPwaVersion, $expectedPwaVersion", script)
        self.assertIn("$pwaVersion))", script)
        self.assertNotIn("Test-LocalPwaReady $packageVersion", script)
        stale_marker = script.index(
            "Remove-Item -LiteralPath $markerPath -Force -ErrorAction SilentlyContinue"
        )
        start = script.index("$startedDesktopTasks = Start-DesktopTasks", stale_marker)
        wait = script.index("Wait-DesktopReady `", start)
        self.assertLess(stale_marker, start)
        self.assertLess(start, wait)
        self.assertNotIn("Wait-DesktopExecutable", script)

    def test_browser_extension_is_installed_and_rolled_back_with_the_client(self):
        script = (ROOT / "tools" / "install_client.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn('Join-Path $PackageRoot "browser-extension"', script)
        self.assertIn('Join-Path $browserExtensionRoot "current"', script)
        self.assertIn('Join-Path $browserExtensionRoot "previous"', script)
        self.assertIn("function Install-BrowserExtension", script)
        self.assertIn("function Restore-BrowserExtension", script)
        install_call = script.index("    Install-BrowserExtension\n")
        service_call = script.index("& $serviceInstaller", install_call)
        rollback_call = script.index("    Restore-BrowserExtension\n", service_call)
        self.assertLess(install_call, service_call)
        self.assertLess(service_call, rollback_call)

    def test_desktop_tasks_target_explicit_windows_sids_not_the_uac_admin(self):
        script = (ROOT / "tools" / "install_client.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("function Set-DesktopTasks", script)
        self.assertIn("$definition.Principal.UserId = $sid", script)
        self.assertIn("$trigger.UserId = $sid", script)
        self.assertIn("$mapping.windows_sid", script)
        self.assertNotIn("$definition.Principal.UserId = $identity.Name", script)
        self.assertNotIn("Start-Process -FilePath $installed", script)

    def test_legacy_partial_identity_forces_interactive_migration(self):
        script = (ROOT / "tools" / "install_client.ps1").read_text(
            encoding="utf-8"
        )
        normalization = script.index("Assert-WindowsIdentities $windowsIdentities")
        clear_invalid = script.index("$windowsIdentities = @()", normalization)
        wizard_decision = script.index("$needsWizard = (")
        self.assertLess(normalization, clear_invalid)
        self.assertLess(clear_invalid, wizard_decision)
        self.assertIn(
            "versions antérieures pouvaient enregistrer une association",
            script,
        )

    def test_local_configuration_is_initialized_by_the_protected_service_runtime(self):
        client = (ROOT / "tools" / "install_client.ps1").read_text(
            encoding="utf-8"
        )
        service = (
            ROOT / "tools" / "install_production_service.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("-LocalConfiguration $wizardResult", client)
        self.assertIn("init-local --configuration $LocalConfiguration", service)
        self.assertIn('Join-Path $serviceData "backend.sqlite3"', service)
        self.assertIn("Remove-Item -LiteralPath $wizardResult", client)

    def test_service_installer_never_reads_the_unbounded_activity_archive(self):
        service = (
            ROOT / "tools" / "install_production_service.ps1"
        ).read_text(encoding="utf-8")

        self.assertNotIn("$sourceActivity", service)
        self.assertNotIn('Join-Path $userData "activity.json"', service)
        self.assertNotIn("$activity.app_limit_settings", service)
        self.assertNotIn("$activity.computer_block", service)
        self.assertIn(
            "leaving it absent keeps ControlRegistry", service,
        )

    def test_service_runtime_is_staged_versioned_and_health_checked(self):
        script = (
            ROOT / "tools" / "install_production_service.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn('"Global\\UsageGuardServiceInstall"', script)
        self.assertIn('Join-Path $serviceRoot "versions"', script)
        self.assertIn("$runtimeId = $PackageVersion", script)
        self.assertIn("Copy-Item -LiteralPath $sourceRuntime", script)
        self.assertIn("& $serviceExecutable --startup auto update", script)
        self.assertIn("& $serviceExecutable health-service", script)
        self.assertIn("sc.exe config $serviceName binPath= $existingImagePath", script)
        self.assertIn("$replacementBackup", script)
        self.assertIn(
            "[IO.File]::Replace($temporary, $path, $replacementBackup, $true)",
            script,
        )
        self.assertNotIn(
            "[IO.File]::Replace($temporary, $path, $null, $true)",
            script,
        )
        self.assertNotIn(
            "Get-ChildItem -LiteralPath $installDir -Force",
            script,
        )

    def test_existing_device_migration_preserves_protected_credentials(self):
        client = (ROOT / "tools" / "install_client.ps1").read_text(
            encoding="utf-8"
        )
        service = (
            ROOT / "tools" / "install_production_service.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("$existingDeviceId", client)
        self.assertIn("$reuseExistingCredentials", client)
        self.assertIn("migrate-backend --existing $protectedBackend", service)
        self.assertLess(
            service.index('$protectedBackendExisted = Test-Path'),
            service.index('elseif (-not [string]::IsNullOrWhiteSpace($MigrationConfiguration))'),
        )

    def test_uninstaller_resolves_the_active_versioned_service_executable(self):
        script = (
            ROOT / "tools" / "uninstall_production_service.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("Get-CimInstance Win32_Service", script)
        self.assertIn("Get-ServiceExecutablePath $imagePath", script)

    def test_service_exposes_desktop_independent_health_check(self):
        source = (ROOT / "windows_service_production.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("def _health_check(require_desktop=True):", source)
        self.assertIn('if command == "health-service":', source)
        self.assertIn("_health_check(require_desktop=False)", source)


if __name__ == "__main__":
    unittest.main()
