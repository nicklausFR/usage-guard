[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$serviceName = "UsageGuardDecision"
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

function Get-ServiceExecutablePath([string]$imagePath) {
    $value = [string]$imagePath
    if ($value.StartsWith('"')) {
        $closing = $value.IndexOf('"', 1)
        if ($closing -gt 1) { return $value.Substring(1, $closing - 1) }
    }
    return ($value -split '\s+', 2)[0]
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Ce script doit être lancé dans PowerShell en tant qu’administrateur."
}
if ($null -ne $existing) {
    $imagePath = [string]((Get-CimInstance Win32_Service -Filter "Name='$serviceName'").PathName)
    $serviceExecutable = Get-ServiceExecutablePath $imagePath
    if ($existing.Status -ne "Stopped") { Stop-Service -Name $serviceName -Force }
    if (-not (Test-Path -LiteralPath $serviceExecutable -PathType Leaf)) {
        throw "Exécutable autonome du service introuvable : $serviceExecutable"
    }
    & $serviceExecutable remove
    if ($LASTEXITCODE -ne 0) { throw "Suppression du service impossible." }
}
Write-Host "Service production supprimé. Ses données protégées sont conservées."
