[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [bool]$Enabled
)

$ErrorActionPreference = "Stop"
$serviceName = "UsageGuardDecision"
$settingsPath = Join-Path $env:ProgramData "Usage Guard\Service\backend.json"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Ce script doit être lancé en tant qu’administrateur."
}
if (-not (Test-Path -LiteralPath $settingsPath)) {
    throw "Configuration backend protégée introuvable."
}
$service = Get-Service -Name $serviceName -ErrorAction Stop
if ($service.Status -ne "Stopped") {
    Stop-Service -Name $serviceName -Force
    $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
}
$settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
$settings.enabled = $Enabled
$settings | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $settingsPath -Encoding UTF8
Start-Service -Name $serviceName
(Get-Service -Name $serviceName).WaitForStatus("Running", [TimeSpan]::FromSeconds(20))
