[CmdletBinding()]
param(
    [string]$CandidatePath
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$v2 = Join-Path $root "dist-v2\usage-guard.exe"
$v2Previous = Join-Path $root "dist-v2\usage-guard.previous.exe"
$v1 = "D:\Code\python\Usage-guard\dist\usage-guard.exe"
$helper = Join-Path $PSScriptRoot "set_production_backend_mode.ps1"
$serviceInstaller = Join-Path $PSScriptRoot "install_production_service.ps1"
$healthCheck = Join-Path $PSScriptRoot "check_production_service.py"
$shortcut = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup\Usage Guard.lnk"

function Set-BackendMode([bool]$enabled) {
    $value = if ($enabled) { '$true' } else { '$false' }
    $argument = "& '$helper' -Enabled $value"
    $process = Start-Process -FilePath powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $argument
    )
    if ($process.ExitCode -ne 0) {
        throw "Le service n’a pas accepté le changement de mode backend."
    }
}

function Update-ProductionService {
    $argument = "& '$serviceInstaller' -EnableBackend"
    $process = Start-Process -FilePath powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $argument
    )
    if ($process.ExitCode -ne 0) {
        throw "La mise à jour du service anti-contournement a échoué."
    }
}

function Set-StartupTarget([string]$target, [string]$workingDirectory) {
    $directory = Split-Path -Parent $shortcut
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut($shortcut)
    $link.TargetPath = $target
    $link.WorkingDirectory = $workingDirectory
    $link.IconLocation = "$target,0"
    $link.Save()
}

function Start-V1Rollback {
    try { Set-BackendMode $false } catch {}
    if (Test-Path -LiteralPath $v1) {
        Set-StartupTarget $v1 (Split-Path -Parent $v1)
        Start-Process -FilePath $v1 -WorkingDirectory (Split-Path -Parent $v1)
    }
}

if ($CandidatePath) {
    $candidate = [IO.Path]::GetFullPath($CandidatePath)
    $allowedCandidateRoot = [IO.Path]::GetFullPath((Join-Path $root "build\v2-release"))
    if (-not $candidate.StartsWith($allowedCandidateRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Le candidat Usage Guard doit provenir du dossier de compilation contrôlé."
    }
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Exécutable Usage Guard compilé introuvable."
    }
}
elseif (-not (Test-Path -LiteralPath $v2)) { throw "Exécutable Usage Guard candidat introuvable." }
if (-not (Test-Path -LiteralPath $v1)) { throw "Exécutable v1 de secours introuvable." }

try {
    if (Get-Process usage-guard-v2 -ErrorAction SilentlyContinue) {
        & taskkill.exe /IM usage-guard-v2.exe /T /F | Out-Null
    }
    if (Get-Process usage-guard -ErrorAction SilentlyContinue) {
        & taskkill.exe /IM usage-guard.exe /T /F | Out-Null
    }
    Start-Sleep -Milliseconds 800
    if ($CandidatePath) {
        New-Item -ItemType Directory -Path (Split-Path -Parent $v2) -Force | Out-Null
        if (Test-Path -LiteralPath $v2Previous) { Remove-Item -LiteralPath $v2Previous -Force }
        if (Test-Path -LiteralPath $v2) { Move-Item -LiteralPath $v2 -Destination $v2Previous -Force }
        try {
            Copy-Item -LiteralPath $candidate -Destination $v2 -Force
        } catch {
            if ((Test-Path -LiteralPath $v2Previous) -and -not (Test-Path -LiteralPath $v2)) {
                Move-Item -LiteralPath $v2Previous -Destination $v2 -Force
            }
            throw
        }
    }
    Update-ProductionService
    Start-Process -FilePath $v2 -WorkingDirectory $root -WindowStyle Hidden

    $healthDeadline = [DateTime]::UtcNow.AddSeconds(30)
    $healthy = $false
    while ([DateTime]::UtcNow -lt $healthDeadline) {
        & python.exe $healthCheck
        if ($LASTEXITCODE -eq 0) {
            $healthy = $true
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $healthy -or -not (Get-Process usage-guard -ErrorAction SilentlyContinue)) {
        throw "Le service backend Usage Guard n’est pas opérationnel."
    }
    Set-StartupTarget $v2 $root
    Write-Host "Basculement Usage Guard confirmé. La version précédente est conservée pour rollback."
} catch {
    if (Get-Process usage-guard-v2 -ErrorAction SilentlyContinue) {
        & taskkill.exe /IM usage-guard-v2.exe /T /F | Out-Null
    }
    if ($CandidatePath -and (Test-Path -LiteralPath $v2Previous)) {
        if (Test-Path -LiteralPath $v2) { Remove-Item -LiteralPath $v2 -Force }
        Move-Item -LiteralPath $v2Previous -Destination $v2 -Force
    }
    Start-V1Rollback
    throw
}
