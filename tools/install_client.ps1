[CmdletBinding()]
param(
    [string]$EnrollmentCode,
    [string]$BackendUrl,
    [string]$DisplayName = $env:COMPUTERNAME,
    [string]$PackageRoot,
    [switch]$Update
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($PackageRoot)) {
    $PackageRoot = Split-Path -Parent $PSScriptRoot
}
$PackageRoot = [IO.Path]::GetFullPath($PackageRoot)
$candidate = Join-Path $PackageRoot "usage-guard.exe"
$serviceInstaller = Join-Path $PackageRoot "tools\install_production_service.ps1"
$serviceRuntime = Join-Path $PackageRoot "service-runtime"
$serviceRuntimeArchive = Join-Path $PackageRoot "service-runtime.zip"
$serviceCandidate = Join-Path $serviceRuntime "UsageGuardService.exe"
$manifestPath = Join-Path $PackageRoot "client-manifest.json"
$setupWizard = Join-Path $PackageRoot "Configurer-Usage-Guard.exe"
$browserExtensionCandidate = Join-Path $PackageRoot "browser-extension"
$browserExtensionManifest = Join-Path $browserExtensionCandidate "manifest.json"
$appDir = Join-Path $env:ProgramFiles "Usage Guard\App"
$installed = Join-Path $appDir "usage-guard.exe"
$previous = Join-Path $appDir "usage-guard.previous.exe"
$next = Join-Path $appDir "usage-guard.next.exe"
$legacyInstalled = Join-Path $appDir "usage-guard-v2.exe"
$legacyPrevious = Join-Path $appDir "usage-guard-v2.previous.exe"
$legacyNext = Join-Path $appDir "usage-guard-v2.next.exe"
$browserExtensionRoot = Join-Path $env:ProgramFiles "Usage Guard\Browser Extension"
$browserExtensionInstalled = Join-Path $browserExtensionRoot "current"
$browserExtensionPrevious = Join-Path $browserExtensionRoot "previous"
$browserExtensionNext = Join-Path $browserExtensionRoot "next"
$shortcut = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup\Usage Guard.lnk"
$protectedBackend = Join-Path $env:ProgramData "Usage Guard\Service\backend.json"
$wizardResult = $null
$installationProfile = "server"
$windowsIdentities = @()
$existingBackend = $null
$existingDeviceId = ""
$reuseExistingCredentials = $false
$hadInstalled = Test-Path -LiteralPath $installed
$hadLegacyInstalled = Test-Path -LiteralPath $legacyInstalled
$hadAnyInstalled = $hadInstalled -or $hadLegacyInstalled
$hadBrowserExtension = Test-Path -LiteralPath $browserExtensionInstalled -PathType Container
$browserExtensionChanged = $false

function Expand-PackagedServiceRuntime {
    if (Test-Path -LiteralPath $serviceCandidate -PathType Leaf) { return }
    if (-not (Test-Path -LiteralPath $serviceRuntimeArchive -PathType Leaf)) {
        throw "Paquet client incomplet : $serviceCandidate"
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $runtimeArchive = [IO.Compression.ZipFile]::OpenRead($serviceRuntimeArchive)
    try {
        $expandedBytes = [int64]0
        if ($runtimeArchive.Entries.Count -gt 4096) {
            throw "Runtime du service démesuré."
        }
        $destinationRoot = [IO.Path]::GetFullPath(
            $serviceRuntime + [IO.Path]::DirectorySeparatorChar
        )
        foreach ($entry in $runtimeArchive.Entries) {
            $expandedBytes += [int64]$entry.Length
            if ($expandedBytes -gt 1GB) {
                throw "Runtime du service démesuré."
            }
            $target = [IO.Path]::GetFullPath(
                (Join-Path $serviceRuntime $entry.FullName)
            )
            if (-not $target.StartsWith(
                    $destinationRoot,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                throw "Chemin interdit dans le runtime du service."
            }
        }
    }
    finally {
        $runtimeArchive.Dispose()
    }

    $temporaryRuntime = Join-Path $PackageRoot (
        "service-runtime.unpack-" + [guid]::NewGuid().ToString("N")
    )
    try {
        [IO.Compression.ZipFile]::ExtractToDirectory(
            $serviceRuntimeArchive, $temporaryRuntime
        )
        $temporaryCandidate = Join-Path $temporaryRuntime "UsageGuardService.exe"
        if (-not (Test-Path -LiteralPath $temporaryCandidate -PathType Leaf)) {
            throw "Runtime du service incomplet."
        }
        Remove-Item -LiteralPath $serviceRuntime -Recurse -Force `
            -ErrorAction SilentlyContinue
        Move-Item -LiteralPath $temporaryRuntime -Destination $serviceRuntime
    }
    finally {
        Remove-Item -LiteralPath $temporaryRuntime -Recurse -Force `
            -ErrorAction SilentlyContinue
    }
}

function Assert-WindowsIdentities([array]$mappings) {
    if ($mappings.Count -lt 1) {
        throw "Aucune session Windows n’est associée à Usage Guard."
    }
    $seenSids = @{}
    foreach ($mapping in $mappings) {
        $sid = ([string]$mapping.windows_sid).ToUpperInvariant()
        $usageGuardUsername = ([string]$mapping.usage_guard_username).Trim()
        if ($sid -notmatch '^S-\d+(?:-\d+)+$' -or
            [string]::IsNullOrWhiteSpace($usageGuardUsername) -or
            $seenSids.ContainsKey($sid)) {
            throw "Association de session Windows invalide dans la configuration d’installation."
        }
        $seenSids[$sid] = $true
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Ce script doit être lancé dans PowerShell en tant qu’administrateur."
}
foreach ($required in @($candidate, $serviceInstaller, $manifestPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Paquet client incomplet : $required"
    }
}
if (-not (Test-Path -LiteralPath $browserExtensionManifest -PathType Leaf)) {
    throw "Paquet client incomplet : $browserExtensionManifest"
}
$packageManifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$packageVersion = [string]$packageManifest.version
if ($packageVersion -notmatch '^\d+\.\d+$') {
    throw "Version du paquet client invalide."
}
$pwaVersion = ([string]$packageManifest.pwa_version).Trim()
if (-not [string]::IsNullOrWhiteSpace($pwaVersion) -and
    $pwaVersion -notmatch '^\d+\.\d{3}$') {
    throw "Version PWA du paquet client invalide."
}

$installMutex = [Threading.Mutex]::new($false, "Global\UsageGuardClientInstall")
$installLockAcquired = $false
try {
    try {
        $installLockAcquired = $installMutex.WaitOne(0)
    }
    catch [Threading.AbandonedMutexException] {
        $installLockAcquired = $true
    }
    if (-not $installLockAcquired) {
        throw "Une autre installation ou mise à jour Usage Guard est déjà en cours."
    }

    Expand-PackagedServiceRuntime

if (Test-Path -LiteralPath $protectedBackend -PathType Leaf) {
    try {
        $existingBackend = Get-Content -LiteralPath $protectedBackend -Raw |
            ConvertFrom-Json
    }
    catch {
        throw "La configuration protégée de l’installation existante est illisible."
    }
    $existingDeviceId = ([string]$existingBackend.device_id).Trim()
    if ([string]::IsNullOrWhiteSpace([string]$existingBackend.installation_profile)) {
        $installationProfile = "server"
    }
    else {
        $installationProfile = [string]$existingBackend.installation_profile
    }
    if ($installationProfile -notin @("local", "server")) {
        throw "Profil de l’installation existante invalide."
    }
    if ([string]::IsNullOrWhiteSpace($BackendUrl)) {
        $BackendUrl = [string]$existingBackend.base_url
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$existingBackend.display_name)) {
        $DisplayName = [string]$existingBackend.display_name
    }
    $windowsIdentities = @($existingBackend.windows_identities)
    if ($windowsIdentities.Count -gt 0) {
        try {
            Assert-WindowsIdentities $windowsIdentities
        }
        catch {
            # Les versions antérieures pouvaient enregistrer une association
            # partielle sans SID. Elle impose la migration interactive au lieu
            # d’être considérée comme une configuration v2 terminée.
            $windowsIdentities = @()
        }
    }
}
elseif ($hadAnyInstalled) {
    throw "L’application existe déjà mais son identité protégée est introuvable. " +
        "L’installation est arrêtée pour éviter de créer un second appareil."
}

if ($Update -and $windowsIdentities.Count -lt 1) {
    throw "Cette installation exige d’abord la migration interactive des sessions Windows."
}
if (-not $Update -and $installationProfile -eq "local" -and
    $null -ne $existingBackend -and $windowsIdentities.Count -lt 1) {
    throw "Le profil local existant ne contient aucune association Windows et doit être réparé explicitement."
}

$needsWizard = (
    -not $Update -and
    [string]::IsNullOrWhiteSpace($EnrollmentCode) -and
    ($null -eq $existingBackend -or $windowsIdentities.Count -lt 1)
)
if ($needsWizard) {
    if (-not (Test-Path -LiteralPath $setupWizard -PathType Leaf)) {
        throw "Assistant d’installation introuvable : $setupWizard"
    }
    $wizardResult = Join-Path $env:TEMP ("UsageGuardEnrollment-" + [guid]::NewGuid().ToString("N") + ".json")
        $wizardArguments = @("--output", $wizardResult)
        if (-not [string]::IsNullOrWhiteSpace($BackendUrl)) {
            $wizardArguments += @("--default-base-url", $BackendUrl)
        }
        if (-not [string]::IsNullOrWhiteSpace($existingDeviceId)) {
            $wizardArguments += @("--existing-device-id", $existingDeviceId)
        }
        $quotedWizardArguments = @()
        foreach ($argument in $wizardArguments) {
            $quotedWizardArguments += ('"' + ([string]$argument).Replace('"', '\"') + '"')
        }
        $wizardProcess = Start-Process -FilePath $setupWizard `
            -ArgumentList $quotedWizardArguments -Wait -PassThru
        if ($wizardProcess.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $wizardResult -PathType Leaf)) {
            throw "Configuration de l’ordinateur annulée."
        }
        $enrollment = Get-Content -LiteralPath $wizardResult -Raw | ConvertFrom-Json
        $installationProfile = [string]$enrollment.installation_profile
        if ($installationProfile -notin @("local", "server")) {
            throw "Profil d’installation invalide."
        }
        $EnrollmentCode = [string]$enrollment.enrollment_code
        $BackendUrl = [string]$enrollment.base_url
        $DisplayName = [string]$enrollment.display_name
        $windowsIdentities = @($enrollment.windows_identities)
        $reuseExistingCredentials = [bool]$enrollment.reuse_existing_credentials
        if ($reuseExistingCredentials -and
            ($null -eq $existingBackend -or
             [string]$enrollment.device_id -ne $existingDeviceId -or
             -not [string]::IsNullOrWhiteSpace($EnrollmentCode))) {
            throw "La migration ne correspond pas à l’appareil déjà installé."
        }
        if ($installationProfile -eq "server" -and
            (([string]::IsNullOrWhiteSpace($EnrollmentCode) -and
              -not $reuseExistingCredentials) -or
             [string]::IsNullOrWhiteSpace($BackendUrl))) {
            throw "Réponse incomplète de l’assistant d’installation."
        }
        if ($installationProfile -eq "local") {
            Write-Host "Ordinateur '$DisplayName' préparé avec un backend SQLite local."
        }
        else {
            Write-Host "Ordinateur '$DisplayName' rattaché à l’utilisateur '$($enrollment.limited_username)'."
        }
}

function Get-DesktopTaskName([string]$sid) {
    return "UsageGuardDesktop-" + ($sid -replace '[^A-Za-z0-9]', '_')
}

function Set-DesktopTasks([string]$target, [array]$mappings) {
    Assert-WindowsIdentities $mappings
    $taskService = New-Object -ComObject Schedule.Service
    $taskService.Connect()
    $folder = $taskService.GetFolder("\")
    $created = @()
    foreach ($mapping in $mappings) {
        $sid = [string]$mapping.windows_sid
        if ($sid -notmatch '^S-\d+(?:-\d+)+$') {
            throw "SID Windows invalide dans la configuration d’installation."
        }
        $taskName = Get-DesktopTaskName $sid
        $definition = $taskService.NewTask(0)
        $definition.RegistrationInfo.Description = "Démarre Usage Guard pour la session Windows associée."
        $definition.Settings.Enabled = $true
        $definition.Settings.StartWhenAvailable = $true
        $definition.Settings.ExecutionTimeLimit = "PT0S"
        $definition.Settings.MultipleInstances = 2
        $definition.Principal.UserId = $sid
        $definition.Principal.LogonType = 3
        $definition.Principal.RunLevel = 0
        $trigger = $definition.Triggers.Create(9)
        $trigger.UserId = $sid
        $action = $definition.Actions.Create(0)
        $action.Path = $target
        $action.WorkingDirectory = $appDir
        $folder.RegisterTaskDefinition($taskName, $definition, 6, $null, $null, 3, $null) | Out-Null
        $created += $taskName
    }
    foreach ($task in @($folder.GetTasks(0))) {
        if (($task.Name -eq "UsageGuardDesktop" -or
             $task.Name.StartsWith("UsageGuardDesktop-")) -and
            $task.Name -notin $created) {
            $folder.DeleteTask($task.Name, 0)
        }
    }
    Remove-Item -LiteralPath $shortcut -Force -ErrorAction SilentlyContinue
    return $created
}

function Start-DesktopTasks {
    $taskService = New-Object -ComObject Schedule.Service
    $taskService.Connect()
    $folder = $taskService.GetFolder("\")
    $started = 0
    foreach ($task in @($folder.GetTasks(0))) {
        if ($task.Name.StartsWith("UsageGuardDesktop-")) {
            try { $task.Run($null) | Out-Null; $started += 1 } catch {}
        }
    }
    return $started
}

function Stop-DesktopProcesses {
    Get-Process usage-guard -ErrorAction SilentlyContinue | Stop-Process -Force
    Get-Process usage-guard-v2 -ErrorAction SilentlyContinue | Stop-Process -Force
}

function Get-DesktopReadyMarkerPaths([array]$mappings) {
    $paths = @()
    foreach ($mapping in $mappings) {
        $sid = [string]$mapping.windows_sid
        $profileKey = (
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
        )
        try {
            $profile = Get-ItemProperty -LiteralPath $profileKey `
                -Name ProfileImagePath -ErrorAction Stop
            $profileRoot = [Environment]::ExpandEnvironmentVariables(
                [string]$profile.ProfileImagePath
            )
            if ([string]::IsNullOrWhiteSpace($profileRoot)) { continue }
            $markerPath = [IO.Path]::GetFullPath(
                (Join-Path $profileRoot "AppData\Local\Usage Guard\ready.pid")
            )
            if ($markerPath -notin $paths) {
                $paths += $markerPath
            }
        }
        catch {
            Write-Warning "Profil Windows introuvable pour la session $sid."
        }
    }
    return $paths
}

function Test-DesktopReadyMarker(
    [string]$markerPath,
    [string]$target,
    [DateTime]$notBeforeUtc
) {
    try {
        $marker = Get-Item -LiteralPath $markerPath -ErrorAction Stop
        if ($marker.LastWriteTimeUtc -lt $notBeforeUtc) { return $false }

        $lines = @(Get-Content -LiteralPath $markerPath -ErrorAction Stop)
        if ($lines.Count -lt 2) { return $false }
        $readyProcessId = 0
        if (-not [int]::TryParse(
                ([string]$lines[0]).Trim(), [ref]$readyProcessId
            ) -or $readyProcessId -lt 1) {
            return $false
        }

        $expected = [IO.Path]::GetFullPath($target)
        $markedExecutable = [IO.Path]::GetFullPath(([string]$lines[1]).Trim())
        if (-not [string]::Equals(
                $markedExecutable, $expected,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            return $false
        }

        $process = Get-CimInstance Win32_Process `
            -Filter "ProcessId = $readyProcessId" -ErrorAction Stop
        $actual = [string]$process.ExecutablePath
        return (
            -not [string]::IsNullOrWhiteSpace($actual) -and
            [string]::Equals(
                [IO.Path]::GetFullPath($actual), $expected,
                [StringComparison]::OrdinalIgnoreCase
            )
        )
    }
    catch {
        return $false
    }
}

function Test-LocalPwaReady([string]$expectedPwaVersion) {
    try {
        $rootResponse = Invoke-WebRequest -UseBasicParsing `
            -Uri "http://127.0.0.1:8766/" -TimeoutSec 5
        if ([int]$rootResponse.StatusCode -ne 200) { return $false }

        $assetMatch = [regex]::Match(
            [string]$rootResponse.Content,
            'app\.js\?v=(\d+\.\d{3})'
        )
        if (-not $assetMatch.Success) { return $false }
        $servedPwaVersion = $assetMatch.Groups[1].Value

        $workerResponse = Invoke-WebRequest -UseBasicParsing `
            -Uri ("http://127.0.0.1:8766/service-worker.js?readiness=" + `
                [DateTime]::UtcNow.Ticks) -TimeoutSec 5
        if ([int]$workerResponse.StatusCode -ne 200) { return $false }
        $cacheMatch = [regex]::Match(
            [string]$workerResponse.Content,
            'usage-guard-shell-v(\d+)-(\d{3})'
        )
        if (-not $cacheMatch.Success) { return $false }
        $servedCacheVersion = (
            $cacheMatch.Groups[1].Value + "." + $cacheMatch.Groups[2].Value
        )
        if (-not [string]::Equals(
                $servedPwaVersion, $servedCacheVersion,
                [StringComparison]::Ordinal
            )) {
            return $false
        }
        return (
            [string]::IsNullOrWhiteSpace($expectedPwaVersion) -or
            [string]::Equals(
                $servedPwaVersion, $expectedPwaVersion,
                [StringComparison]::Ordinal
            )
        )
    }
    catch {
        return $false
    }
}

function Wait-DesktopReady(
    [string]$target,
    [array]$markerPaths,
    [DateTime]$notBeforeUtc,
    [string]$expectedPwaVersion,
    [int]$timeoutSeconds = 180
) {
    $expected = [IO.Path]::GetFullPath($target)
    $deadline = [DateTime]::UtcNow.AddSeconds($timeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        foreach ($markerPath in $markerPaths) {
            if ((Test-DesktopReadyMarker `
                    $markerPath $expected $notBeforeUtc) -and
                (Test-LocalPwaReady $expectedPwaVersion)) {
                return $true
            }
        }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Install-BrowserExtension {
    New-Item -ItemType Directory -Path $browserExtensionRoot -Force | Out-Null
    Remove-Item -LiteralPath $browserExtensionNext -Recurse -Force `
        -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath $browserExtensionCandidate `
        -Destination $browserExtensionNext -Recurse -Force
    if (Test-Path -LiteralPath $browserExtensionPrevious) {
        Remove-Item -LiteralPath $browserExtensionPrevious -Recurse -Force
    }
    if (Test-Path -LiteralPath $browserExtensionInstalled) {
        Move-Item -LiteralPath $browserExtensionInstalled `
            -Destination $browserExtensionPrevious
    }
    try {
        Move-Item -LiteralPath $browserExtensionNext `
            -Destination $browserExtensionInstalled
    }
    catch {
        if (Test-Path -LiteralPath $browserExtensionPrevious) {
            Move-Item -LiteralPath $browserExtensionPrevious `
                -Destination $browserExtensionInstalled
        }
        throw
    }
}

function Restore-BrowserExtension {
    Remove-Item -LiteralPath $browserExtensionNext -Recurse -Force `
        -ErrorAction SilentlyContinue
    if (-not $browserExtensionChanged) { return }
    Remove-Item -LiteralPath $browserExtensionInstalled -Recurse -Force `
        -ErrorAction SilentlyContinue
    if ($hadBrowserExtension -and
        (Test-Path -LiteralPath $browserExtensionPrevious -PathType Container)) {
        Move-Item -LiteralPath $browserExtensionPrevious `
            -Destination $browserExtensionInstalled
    }
}

if ($windowsIdentities.Count -gt 0) {
    Assert-WindowsIdentities $windowsIdentities
}
New-Item -ItemType Directory -Path $appDir -Force | Out-Null
try {
    Copy-Item -LiteralPath $candidate -Destination $next -Force
    Stop-DesktopProcesses
    if (Test-Path -LiteralPath $previous) {
        Remove-Item -LiteralPath $previous -Force
    }
    if ($hadInstalled) {
        [IO.File]::Replace($next, $installed, $previous, $true)
    }
    else {
        if ($hadLegacyInstalled) {
            Copy-Item -LiteralPath $legacyInstalled -Destination $previous -Force
        }
        Move-Item -LiteralPath $next -Destination $installed
    }
    Install-BrowserExtension
    $browserExtensionChanged = $true
    if ($installationProfile -eq "local" -and $null -ne $wizardResult) {
        & $serviceInstaller -EnableBackend -LocalConfiguration $wizardResult `
            -DisplayName $DisplayName -PackageVersion $packageVersion
    }
    elseif ($reuseExistingCredentials) {
        & $serviceInstaller -EnableBackend -MigrationConfiguration $wizardResult `
            -DisplayName $DisplayName -PackageVersion $packageVersion
    }
    else {
        & $serviceInstaller -EnableBackend -EnrollmentCode $EnrollmentCode `
            -BackendUrl $BackendUrl -DisplayName $DisplayName `
            -PackageVersion $packageVersion
    }
    if ($LASTEXITCODE -ne 0) { throw "Installation du service protégé impossible." }
    if ($windowsIdentities.Count -lt 1) {
        $installedBackend = Get-Content -LiteralPath $protectedBackend -Raw | ConvertFrom-Json
        $windowsIdentities = @($installedBackend.windows_identities)
    }
    Assert-WindowsIdentities $windowsIdentities
    Set-DesktopTasks $installed $windowsIdentities | Out-Null
    $desktopReadyMarkers = @(Get-DesktopReadyMarkerPaths $windowsIdentities)
    $desktopReadinessStartedAtUtc = [DateTime]::UtcNow
    foreach ($markerPath in $desktopReadyMarkers) {
        Remove-Item -LiteralPath $markerPath -Force -ErrorAction SilentlyContinue
    }
    $startedDesktopTasks = Start-DesktopTasks
    if ($startedDesktopTasks -lt 1) {
        Write-Warning "Usage Guard démarrera à la prochaine ouverture d’une session Windows associée."
    }
    elseif (-not (Wait-DesktopReady `
            $installed $desktopReadyMarkers $desktopReadinessStartedAtUtc `
            $pwaVersion)) {
        throw "Le nouveau client Usage Guard n’a pas confirmé son démarrage complet " +
            "depuis le chemin installé et sur la PWA locale."
    }
    if ($hadLegacyInstalled) {
        Remove-Item -LiteralPath $legacyInstalled -Force
        Remove-Item -LiteralPath $legacyPrevious -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $legacyNext -Force -ErrorAction SilentlyContinue
    }
    Write-Host "Usage Guard est installé et associé sous le nom '$DisplayName'."
    Write-Host "Extension navigateur disponible dans '$browserExtensionInstalled'."
}
catch {
    Stop-DesktopProcesses
    if ($hadInstalled -and (Test-Path -LiteralPath $previous)) {
        if (Test-Path -LiteralPath $installed) {
            $failedInstalled = Join-Path $appDir "usage-guard.failed.exe"
            Remove-Item -LiteralPath $failedInstalled -Force -ErrorAction SilentlyContinue
            [IO.File]::Replace($previous, $installed, $failedInstalled, $true)
            Remove-Item -LiteralPath $failedInstalled -Force -ErrorAction SilentlyContinue
        }
        else {
            Move-Item -LiteralPath $previous -Destination $installed
        }
        Set-DesktopTasks $installed $windowsIdentities | Out-Null
        Start-DesktopTasks | Out-Null
    }
    elseif ($hadLegacyInstalled) {
        Remove-Item -LiteralPath $installed -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path -LiteralPath $legacyInstalled) -and
            (Test-Path -LiteralPath $previous)) {
            Copy-Item -LiteralPath $previous -Destination $legacyInstalled -Force
        }
        Set-DesktopTasks $legacyInstalled $windowsIdentities | Out-Null
        Start-DesktopTasks | Out-Null
    }
    elseif (Test-Path -LiteralPath $installed) {
        Remove-Item -LiteralPath $installed -Force
    }
    Restore-BrowserExtension
    Remove-Item -LiteralPath $next -Force -ErrorAction SilentlyContinue
    throw
}
}
finally {
    if (-not [string]::IsNullOrWhiteSpace($wizardResult)) {
        Remove-Item -LiteralPath $wizardResult -Force -ErrorAction SilentlyContinue
    }
    if ($installLockAcquired) { $installMutex.ReleaseMutex() }
    $installMutex.Dispose()
}
