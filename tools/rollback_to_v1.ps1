[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$v1 = "D:\Code\python\Usage-guard\dist\usage-guard.exe"
$helper = Join-Path $PSScriptRoot "set_production_backend_mode.ps1"
$shortcut = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup\Usage Guard.lnk"

if (Get-Process usage-guard-v2 -ErrorAction SilentlyContinue) {
    & taskkill.exe /IM usage-guard-v2.exe /T /F | Out-Null
}
if (Get-Process usage-guard -ErrorAction SilentlyContinue) {
    & taskkill.exe /IM usage-guard.exe /T /F | Out-Null
}
$argument = "& '$helper' -Enabled `$false"
$process = Start-Process -FilePath powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList @(
    "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $argument
)
if ($process.ExitCode -ne 0) { throw "Désactivation du backend service impossible." }

$shell = New-Object -ComObject WScript.Shell
$link = $shell.CreateShortcut($shortcut)
$link.TargetPath = $v1
$link.WorkingDirectory = Split-Path -Parent $v1
$link.IconLocation = "$v1,0"
$link.Save()
Start-Process -FilePath $v1 -WorkingDirectory (Split-Path -Parent $v1)
Write-Host "Retour v1 effectué."
