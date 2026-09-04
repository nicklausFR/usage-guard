[CmdletBinding()]
param(
    [switch]$EnableBackend,
    [string]$EnrollmentCode,
    [string]$BackendUrl,
    [string]$LocalConfiguration,
    [string]$MigrationConfiguration,
    [string]$DisplayName = $env:COMPUTERNAME,
    [Parameter(Mandatory)][string]$PackageVersion
)

$ErrorActionPreference = "Stop"
$serviceName = "UsageGuardDecision"
$projectRoot = Split-Path -Parent $PSScriptRoot
$sourceRuntime = Join-Path $projectRoot "service-runtime"
$sourceServiceExecutable = Join-Path $sourceRuntime "UsageGuardService.exe"
$serviceRoot = Join-Path $env:ProgramFiles "Usage Guard\Service"
$versionsDir = Join-Path $serviceRoot "versions"
$serviceData = Join-Path $env:ProgramData "Usage Guard\Service"
$userData = Join-Path $env:LOCALAPPDATA "Usage Guard"
$sourceBackend = Join-Path $userData "backend.json"
$protectedBackend = Join-Path $serviceData "backend.json"
$protectedDatabase = Join-Path $serviceData "backend.sqlite3"
$backupDir = Join-Path $env:TEMP ("UsageGuardServiceBackup-" + [guid]::NewGuid().ToString("N"))
$runtimeId = $PackageVersion + "-" + [guid]::NewGuid().ToString("N")
$newRuntimeDir = Join-Path $versionsDir $runtimeId
$serviceExecutable = Join-Path $newRuntimeDir "UsageGuardService.exe"

function Get-ServiceExecutablePath([string]$imagePath) {
    $value = [string]$imagePath
    if ($value.StartsWith('"')) {
        $closing = $value.IndexOf('"', 1)
        if ($closing -gt 1) { return $value.Substring(1, $closing - 1) }
    }
    return ($value -split '\s+', 2)[0]
}

function Write-JsonAtomic([string]$path, $value) {
    $temporary = $path + "." + [guid]::NewGuid().ToString("N") + ".tmp"
    $replacementBackup = $path + "." + [guid]::NewGuid().ToString("N") + ".bak"
    try {
        $value | ConvertTo-Json -Depth 30 | Set-Content `
            -LiteralPath $temporary -Encoding UTF8
        if (Test-Path -LiteralPath $path) {
            [IO.File]::Replace($temporary, $path, $replacementBackup, $true)
        }
        else {
            Move-Item -LiteralPath $temporary -Destination $path
        }
    }
    finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $replacementBackup -Force `
            -ErrorAction SilentlyContinue
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Ce script doit être lancé dans PowerShell en tant qu’administrateur."
}
if ($PackageVersion -notmatch '^\d+\.\d+$') {
    throw "Version du runtime de service invalide."
}
if (-not (Test-Path -LiteralPath $sourceServiceExecutable -PathType Leaf)) {
    throw "Runtime autonome du service absent : $sourceServiceExecutable"
}
if (-not (Test-Path -LiteralPath $protectedBackend) -and
    -not (Test-Path -LiteralPath $sourceBackend) -and
    [string]::IsNullOrWhiteSpace($EnrollmentCode) -and
    [string]::IsNullOrWhiteSpace($LocalConfiguration)) {
    throw "Configuration backend absente. Fournissez un code d’enrôlement pour une première installation."
}
if (-not [string]::IsNullOrWhiteSpace($LocalConfiguration) -and
    -not (Test-Path -LiteralPath $LocalConfiguration -PathType Leaf)) {
    throw "Configuration locale temporaire introuvable."
}
if (-not [string]::IsNullOrWhiteSpace($LocalConfiguration) -and
    -not [string]::IsNullOrWhiteSpace($EnrollmentCode)) {
    throw "Les profils Local et Serveur sont mutuellement exclusifs."
}
if (-not [string]::IsNullOrWhiteSpace($MigrationConfiguration) -and
    (-not [string]::IsNullOrWhiteSpace($EnrollmentCode) -or
     -not [string]::IsNullOrWhiteSpace($LocalConfiguration))) {
    throw "La migration d’un appareil existant ne peut pas créer une nouvelle identité."
}
if (-not [string]::IsNullOrWhiteSpace($MigrationConfiguration) -and
    -not (Test-Path -LiteralPath $MigrationConfiguration -PathType Leaf)) {
    throw "Configuration de migration temporaire introuvable."
}
if (-not [string]::IsNullOrWhiteSpace($MigrationConfiguration) -and
    -not (Test-Path -LiteralPath $protectedBackend -PathType Leaf)) {
    throw "La migration exige les identifiants protégés de l’appareil existant."
}
if (-not [string]::IsNullOrWhiteSpace($EnrollmentCode) -and
    [string]::IsNullOrWhiteSpace($BackendUrl)) {
    throw "L’adresse HTTPS du serveur est requise avec le code d’enrôlement."
}

$serviceMutex = [Threading.Mutex]::new($false, "Global\UsageGuardServiceInstall")
$serviceLockAcquired = $false
try {
    try {
        $serviceLockAcquired = $serviceMutex.WaitOne(0)
    }
    catch [Threading.AbandonedMutexException] {
        $serviceLockAcquired = $true
    }
    if (-not $serviceLockAcquired) {
        throw "Une autre installation du service Usage Guard est déjà en cours."
    }

    New-Item -ItemType Directory -Path $versionsDir -Force | Out-Null
    New-Item -ItemType Directory -Path $serviceData -Force | Out-Null
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    Copy-Item -LiteralPath $sourceRuntime -Destination $newRuntimeDir -Recurse -Force
    if (-not (Test-Path -LiteralPath $serviceExecutable -PathType Leaf)) {
        throw "Staging du runtime autonome incomplet."
    }
    & icacls.exe $serviceRoot /inheritance:r /grant:r `
        "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" `
        "*S-1-5-32-545:(OI)(CI)RX" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Protection des fichiers du service impossible." }

    $existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $existingImagePath = if ($null -ne $existing) {
        [string]((Get-CimInstance Win32_Service -Filter "Name='$serviceName'").PathName)
    } else { "" }
    $previousExecutable = Get-ServiceExecutablePath $existingImagePath
    $protectedBackendExisted = Test-Path -LiteralPath $protectedBackend
    $protectedDatabaseExisted = Test-Path -LiteralPath $protectedDatabase
    if ($protectedBackendExisted) {
        Copy-Item -LiteralPath $protectedBackend `
            -Destination (Join-Path $backupDir "backend.json") -Force
    }

    try {
        if (-not [string]::IsNullOrWhiteSpace($LocalConfiguration)) {
            & $serviceExecutable init-local --configuration $LocalConfiguration `
                --database $protectedDatabase --output $protectedBackend
            if ($LASTEXITCODE -ne 0) { throw "Initialisation du backend local impossible." }
        }
        elseif (-not [string]::IsNullOrWhiteSpace($EnrollmentCode)) {
            & $serviceExecutable enroll --base-url $BackendUrl --code $EnrollmentCode `
                --display-name $DisplayName --output $protectedBackend
            if ($LASTEXITCODE -ne 0) { throw "Enrôlement de l’ordinateur impossible." }
        }
        elseif (-not [string]::IsNullOrWhiteSpace($MigrationConfiguration)) {
            & $serviceExecutable migrate-backend --existing $protectedBackend `
                --configuration $MigrationConfiguration --output $protectedBackend
            if ($LASTEXITCODE -ne 0) {
                throw "Migration de l’identité Windows impossible."
            }
        }
        elseif (-not (Test-Path -LiteralPath $protectedBackend)) {
            $backend = Get-Content -LiteralPath $sourceBackend -Raw | ConvertFrom-Json
            $backend.enabled = $false
            Write-JsonAtomic $protectedBackend $backend
        }
        if ($EnableBackend -or -not [string]::IsNullOrWhiteSpace($EnrollmentCode)) {
            $backend = Get-Content -LiteralPath $protectedBackend -Raw | ConvertFrom-Json
            $backend.enabled = $true
            Write-JsonAtomic $protectedBackend $backend
        }
        # Do not read or copy activity.json here: it is an unbounded archive.
        # An existing protected controls file is preserved during upgrades.
        # On first installation, leaving it absent keeps ControlRegistry
        # uninitialized so the desktop can bootstrap only its bounded managed
        # controls after the service starts.
        & $serviceExecutable init-authkey
        if ($LASTEXITCODE -ne 0) { throw "Création de la clé du service impossible." }
        & icacls.exe $serviceData /inheritance:r /grant:r `
            "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Application des permissions ProgramData impossible." }

        if ($null -ne $existing -and $existing.Status -ne "Stopped") {
            Stop-Service -Name $serviceName -Force
            $existing.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
        }
        if ($null -eq $existing) {
            & $serviceExecutable --startup auto install
        }
        else {
            & $serviceExecutable --startup auto update
        }
        if ($LASTEXITCODE -ne 0) { throw "Bascule du service impossible." }
        & sc.exe failure $serviceName reset= 86400 `
            actions= restart/5000/restart/15000/restart/60000 | Out-Null
        & sc.exe failureflag $serviceName 1 | Out-Null
        Start-Service -Name $serviceName
        (Get-Service -Name $serviceName).WaitForStatus(
            "Running", [TimeSpan]::FromSeconds(20)
        )
        $deadline = [DateTime]::UtcNow.AddSeconds(40)
        $healthy = $false
        while ([DateTime]::UtcNow -lt $deadline) {
            & $serviceExecutable health-service
            if ($LASTEXITCODE -eq 0) { $healthy = $true; break }
            Start-Sleep -Milliseconds 500
        }
        if (-not $healthy) { throw "Le nouveau service protégé n’est pas opérationnel." }

        $keepDirectories = @($newRuntimeDir)
        if (-not [string]::IsNullOrWhiteSpace($previousExecutable)) {
            $previousDirectory = Split-Path -Parent $previousExecutable
            if ($previousDirectory -like "$versionsDir\*") {
                $keepDirectories += $previousDirectory
            }
        }
        foreach ($directory in Get-ChildItem -LiteralPath $versionsDir -Directory -Force) {
            if ($directory.FullName -notin $keepDirectories) {
                Remove-Item -LiteralPath $directory.FullName -Recurse -Force `
                    -ErrorAction SilentlyContinue
            }
        }
        Get-Service -Name $serviceName | Select-Object Name, Status, StartType
    }
    catch {
        $failed = $_
        $running = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -ne $running -and $running.Status -ne "Stopped") {
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            $running.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
        }
        if ($null -eq $existing -and $null -ne $running) {
            & $serviceExecutable remove | Out-Null
        }
        elseif ($null -ne $existing -and
            -not [string]::IsNullOrWhiteSpace($existingImagePath)) {
            & sc.exe config $serviceName binPath= $existingImagePath | Out-Null
            Start-Service -Name $serviceName -ErrorAction SilentlyContinue
        }
        $savedBackend = Join-Path $backupDir "backend.json"
        if (Test-Path -LiteralPath $savedBackend) {
            Copy-Item -LiteralPath $savedBackend -Destination $protectedBackend -Force
        }
        elseif (-not $protectedBackendExisted -and
            (Test-Path -LiteralPath $protectedBackend)) {
            Remove-Item -LiteralPath $protectedBackend -Force
        }
        if (-not $protectedDatabaseExisted -and
            (Test-Path -LiteralPath $protectedDatabase)) {
            Remove-Item -LiteralPath $protectedDatabase -Force
        }
        Remove-Item -LiteralPath $newRuntimeDir -Recurse -Force `
            -ErrorAction SilentlyContinue
        throw $failed
    }
    finally {
        Remove-Item -LiteralPath $backupDir -Recurse -Force `
            -ErrorAction SilentlyContinue
    }
}
finally {
    if ($serviceLockAcquired) { $serviceMutex.ReleaseMutex() }
    $serviceMutex.Dispose()
}
