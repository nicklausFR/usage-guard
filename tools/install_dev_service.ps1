[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$serviceName = "UsageGuardDecisionDev"
$projectRoot = Split-Path -Parent $PSScriptRoot
$python = (Get-Command python.exe -ErrorAction Stop).Source
$installDir = Join-Path $env:ProgramFiles "Usage Guard Dev\Service"
$serviceScript = Join-Path $installDir "windows_service.py"
$serviceData = Join-Path $env:ProgramData "Usage Guard Dev\Service"
$legacyState = Join-Path $env:LOCALAPPDATA "Usage Guard Dev\decision-service-controls.json"
$protectedState = Join-Path $serviceData "decision-service-controls.json"
$serviceFiles = @(
    "windows_service.py",
    "windows_service_support.py",
    "decision_service.py",
    "control_registry.py",
    "command_policy.py",
    "limit_decision.py",
    "runtime_profile.py",
    "backend_client.py",
    "service_backend.py"
)

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Ce script doit être lancé dans PowerShell en tant qu’administrateur."
}

New-Item -ItemType Directory -Path $installDir -Force | Out-Null
New-Item -ItemType Directory -Path $serviceData -Force | Out-Null

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -ne $existing -and $existing.Status -ne "Stopped") {
    Stop-Service -Name $serviceName -Force
}
foreach ($file in $serviceFiles) {
    Copy-Item -LiteralPath (Join-Path $projectRoot $file) -Destination $installDir -Force
}
& icacls.exe $installDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Protection des fichiers du service impossible." }

if (-not (Test-Path -LiteralPath $protectedState) -and (Test-Path -LiteralPath $legacyState)) {
    Copy-Item -LiteralPath $legacyState -Destination $protectedState
}
Push-Location $installDir
try {
    & $python -c "from pathlib import Path; from decision_service import load_or_create_authkey; load_or_create_authkey(Path(r'$serviceData'), 'decision-service-admin.key')"
} finally {
    Pop-Location
}
if ($LASTEXITCODE -ne 0) { throw "Création de la clé du service impossible." }

& icacls.exe $serviceData /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Application des permissions ProgramData impossible." }

if ($null -eq $existing) {
    Push-Location $installDir
    try { & $python $serviceScript --startup auto install } finally { Pop-Location }
} else {
    Push-Location $installDir
    try { & $python $serviceScript --startup auto update } finally { Pop-Location }
}
if ($LASTEXITCODE -ne 0) { throw "Installation du service impossible." }

& sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
& sc.exe failureflag $serviceName 1 | Out-Null
Start-Service -Name $serviceName
Get-Service -Name $serviceName | Select-Object Name, Status, StartType
