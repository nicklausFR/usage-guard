[CmdletBinding()]
param(
    [switch]$Mandatory,
    [string]$MinimumVersion,
    [string]$Notes = '',
    [string]$Server = '',
    [string]$RemoteUser = '',
    [string]$RemoteDirectory = '',
    [string]$Python = 'python',
    [switch]$BuildOnly,
    [switch]$PublishExisting
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$builder = Join-Path $PSScriptRoot 'build_client_release.py'
$output = Join-Path $projectRoot 'usage_guard_backend\client_updates'
if ($BuildOnly -and $PublishExisting) {
    throw 'BuildOnly et PublishExisting ne peuvent pas être utilisés ensemble.'
}
if (-not $PublishExisting -and -not (Test-Path -LiteralPath $builder -PathType Leaf)) {
    throw "Generateur de release client introuvable : $builder"
}
if (-not $PublishExisting -and -not (Get-Command $Python -ErrorAction SilentlyContinue)) {
    throw "Python introuvable : $Python"
}

if (-not $PublishExisting) {
    $arguments = @($builder, '--output', $output, '--notes', $Notes)
    if ($Mandatory) { $arguments += '--mandatory' }
    if ($MinimumVersion) { $arguments += @('--minimum-version', $MinimumVersion) }

    Write-Host '==> Compilation du client et creation du paquet signe par empreintes'
    # Windows PowerShell 5 transforme les lignes informatives écrites sur
    # stderr par PyInstaller en NativeCommandError lorsque la préférence
    # globale vaut Stop. Capturez tout le journal, puis fiez-vous uniquement
    # au vrai code de sortie du générateur.
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $buildLines = @(& $Python @arguments 2>&1)
        $buildExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($buildExitCode -ne 0) {
        throw (($buildLines | ForEach-Object { $_.ToString() }) -join "`n")
    }
    $manifest = $buildLines | Select-Object -Last 1 | ConvertFrom-Json
}
else {
    Write-Host '==> Utilisation du paquet client deja construit'
    $existingManifest = Join-Path $output 'manifest.json'
    if (-not (Test-Path -LiteralPath $existingManifest -PathType Leaf)) {
        throw "Manifeste client existant introuvable : $existingManifest"
    }
    $manifest = Get-Content -LiteralPath $existingManifest -Raw | ConvertFrom-Json
}
$manifestPath = Join-Path $output 'manifest.json'
$packagePath = Join-Path $output $manifest.filename

if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf)) {
    throw "Paquet client introuvable : $packagePath"
}
if ((Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $manifest.sha256) {
    throw 'L empreinte locale du paquet ne correspond pas au manifeste.'
}

Write-Host "    Version : $($manifest.version)"
Write-Host "    Paquet  : $($manifest.filename)"
Write-Host "    SHA-256 : $($manifest.sha256)"
if ($BuildOnly) {
    Write-Host 'Build termine sans publication distante.'
    exit 0
}

if ([string]::IsNullOrWhiteSpace($Server) -or
    [string]::IsNullOrWhiteSpace($RemoteUser) -or
    [string]::IsNullOrWhiteSpace($RemoteDirectory)) {
    throw 'Server, RemoteUser and RemoteDirectory are required for publishing.'
}
if ($Server -notmatch '^[A-Za-z0-9.-]+$' -or
    $RemoteUser -notmatch '^[A-Za-z0-9._-]+$') {
    throw 'The remote server or user contains unsupported characters.'
}
if ($RemoteDirectory -notmatch '^/[A-Za-z0-9._/-]+$') {
    throw 'The remote directory contains unsupported characters.'
}
$remoteTarget = "$RemoteUser@$Server"

if (-not (Get-Command 'ssh.exe' -ErrorAction SilentlyContinue)) {
    throw 'Client OpenSSH introuvable (ssh.exe).'
}
if (-not (Get-Command 'scp.exe' -ErrorAction SilentlyContinue)) {
    throw 'Client SCP introuvable (scp.exe).'
}

$uploadId = [Guid]::NewGuid().ToString('N')
$remotePackageTemp = "$RemoteDirectory/.$($manifest.filename).$uploadId.tmp"
$remoteManifestTemp = "$RemoteDirectory/.manifest.json.$uploadId.tmp"
$quotedDirectory = "'$RemoteDirectory'"

function Copy-RemoteFileWithRetry {
    param(
        [Parameter(Mandatory)][string]$LocalPath,
        [Parameter(Mandatory)][string]$RemotePath,
        [Parameter(Mandatory)][string]$Description
    )
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        & scp.exe -q -o BatchMode=yes -o ConnectTimeout=10 `
            -o ServerAliveInterval=10 -o ServerAliveCountMax=12 -- `
            $LocalPath "${remoteTarget}:$RemotePath"
        if ($LASTEXITCODE -eq 0) { return }
        if ($attempt -lt 3) {
            Write-Warning "$Description interrompu (tentative $attempt/3), nouvel essai."
            Start-Sleep -Seconds 2
        }
    }
    throw "$Description impossible après 3 tentatives."
}

Write-Host '==> Preparation du stockage persistant distant'
& ssh.exe -o BatchMode=yes -o ConnectTimeout=10 $remoteTarget "mkdir -p -- $quotedDirectory"
if ($LASTEXITCODE -ne 0) { throw 'Creation du repertoire distant impossible.' }

try {
    Write-Host '==> Transfert dans des fichiers temporaires'
    Copy-RemoteFileWithRetry $packagePath $remotePackageTemp 'Transfert du paquet client'
    Copy-RemoteFileWithRetry $manifestPath $remoteManifestTemp 'Transfert du manifeste client'

    # Le manifeste est deplace en dernier : un client ne voit jamais une release
    # dont le ZIP correspondant est encore incomplet ou absent.
    $remotePublish = @(
        "test `"`$(wc -c < '$remotePackageTemp')`" = '$($manifest.size)'"
        "test `"`$(sha256sum '$remotePackageTemp' | cut -d ' ' -f 1)`" = '$($manifest.sha256)'"
        "mv -f -- '$remotePackageTemp' '$RemoteDirectory/$($manifest.filename)'"
        "mv -f -- '$remoteManifestTemp' '$RemoteDirectory/manifest.json'"
    ) -join ' && '
    Write-Host '==> Verification et publication atomique'
    & ssh.exe -o BatchMode=yes -o ConnectTimeout=10 $remoteTarget $remotePublish
    if ($LASTEXITCODE -ne 0) { throw 'Verification ou publication distante impossible.' }
}
catch {
    & ssh.exe -o BatchMode=yes -o ConnectTimeout=10 $remoteTarget "rm -f -- '$remotePackageTemp' '$remoteManifestTemp'" 2>$null
    throw
}

Write-Host "Release client $($manifest.version) publiee. La base serveur est restee hors du paquet."
