[CmdletBinding()]
param(
    [string]$ManifestPath
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = Join-Path $projectRoot "usage_guard_backend\client_updates\manifest.json"
}
$ManifestPath = [IO.Path]::GetFullPath($ManifestPath)
if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw "Manifeste de mise à jour introuvable : $ManifestPath"
}

$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
$version = ([string]$manifest.version).Trim()
$filename = ([string]$manifest.filename).Trim()
$expectedHash = ([string]$manifest.sha256).Trim().ToLowerInvariant()
$expectedSize = [Int64]$manifest.size
if ($version -notmatch '^\d+\.\d{3}$') {
    throw "Version du manifeste invalide."
}
if ([string]::IsNullOrWhiteSpace($filename) -or
    [IO.Path]::GetFileName($filename) -ne $filename -or
    $expectedHash -notmatch '^[a-f0-9]{64}$' -or
    $expectedSize -lt 1) {
    throw "Manifeste de mise à jour invalide."
}

$packagePath = Join-Path (Split-Path -Parent $ManifestPath) $filename
if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf)) {
    throw "Paquet client introuvable : $packagePath"
}
$package = Get-Item -LiteralPath $packagePath
if ($package.Length -ne $expectedSize) {
    throw "Taille du paquet client incohérente."
}
$actualHash = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
    throw "Empreinte SHA-256 du paquet client incohérente."
}

$stage = Join-Path $env:TEMP ("UsageGuard-LocalUpdate-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $stage | Out-Null
try {
    Expand-Archive -LiteralPath $packagePath -DestinationPath $stage -Force
    $internalManifestPath = Join-Path $stage "client-manifest.json"
    if (-not (Test-Path -LiteralPath $internalManifestPath -PathType Leaf)) {
        throw "Manifeste interne du paquet absent."
    }
    $internal = Get-Content -LiteralPath $internalManifestPath -Raw | ConvertFrom-Json
    if ([string]$internal.version -ne $version) {
        throw "La version interne ne correspond pas au manifeste externe."
    }
    $entries = @($internal.files.PSObject.Properties)
    if ($entries.Count -lt 1) {
        throw "Le manifeste interne ne contient aucun fichier."
    }

    $stagePrefix = [IO.Path]::GetFullPath($stage).TrimEnd('\') + '\'
    foreach ($entry in $entries) {
        $relative = ([string]$entry.Name).Replace('/', '\')
        $internalHash = ([string]$entry.Value).Trim().ToLowerInvariant()
        if ([IO.Path]::IsPathRooted($relative) -or $internalHash -notmatch '^[a-f0-9]{64}$') {
            throw "Entrée invalide dans le manifeste interne : $($entry.Name)"
        }
        $target = [IO.Path]::GetFullPath((Join-Path $stage $relative))
        if (-not $target.StartsWith($stagePrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Chemin interdit dans le manifeste interne : $($entry.Name)"
        }
        if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
            throw "Fichier absent du paquet : $($entry.Name)"
        }
        $actualInternalHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualInternalHash -ne $internalHash) {
            throw "Empreinte interne invalide : $($entry.Name)"
        }
    }

    $installer = Join-Path $stage "tools\install_client.ps1"
    if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) {
        throw "Installateur interne absent du paquet."
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        & $installer -PackageRoot $stage -Update
    }
    else {
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$installer`" -PackageRoot `"$stage`" -Update"
        $process = Start-Process -FilePath "powershell.exe" -Verb RunAs `
            -ArgumentList $arguments -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "Installation locale interrompue (code $($process.ExitCode))."
        }
    }
    Write-Host "Usage Guard $version installé depuis le paquet local vérifié."
}
finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}
