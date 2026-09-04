[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$serviceName = "UsageGuardDecisionDev"
$python = (Get-Command python.exe -ErrorAction Stop).Source
$installDir = Join-Path $env:ProgramFiles "Usage Guard Dev\Service"
$serviceScript = Join-Path $installDir "windows_service.py"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Ce script doit être lancé dans PowerShell en tant qu’administrateur."
}

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -ne $existing) {
    if ($existing.Status -ne "Stopped") {
        Stop-Service -Name $serviceName -Force
    }
    Push-Location $installDir
    try { & $python $serviceScript remove } finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { throw "Suppression du service impossible." }
}

Write-Host "Service DEV supprimé. Les données ProgramData sont conservées pour permettre un retour en arrière."
