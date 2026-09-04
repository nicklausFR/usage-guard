"""Build a database-free Windows client ZIP and authenticated update manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from client_version import CLIENT_VERSION
from tools.build_v2_candidate import build_candidate


OUTPUT = ROOT / "usage_guard_backend" / "client_updates"
TOOL_FILES = (
    "install_client.ps1", "install_production_service.ps1",
    "uninstall_production_service.ps1",
)
INSTALLER_NAME = f"Installer-Usage-Guard-{CLIENT_VERSION}.exe"
SETUP_NAME = "Configurer-Usage-Guard.exe"
SERVICE_RUNTIME_NAME = "UsageGuardService"
BROWSER_EXTENSION_DIRNAME = "browser-extension"
SERVICE_RUNTIME_ARCHIVE = "service-runtime.zip"
# Client 1.013 and earlier reject update ZIPs containing more than 200 entries.
# Keep the outer package below that limit so the updater can install its own
# successor; the PyInstaller onedir runtime is stored as one verified member.
LEGACY_MAX_PACKAGE_MEMBERS = 200
PWA_ROOT = ROOT / "pwa"
PWA_ASSET_PATTERN = re.compile(r'app\.js\?v=(\d+\.\d{3})')
PWA_CACHE_PATTERN = re.compile(r'usage-guard-shell-v(\d+)-(\d{3})')


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pwa_asset_version(pwa_root=None):
    """Return the version shared by the packaged PWA entry point and cache."""
    pwa_root = Path(pwa_root or PWA_ROOT)
    index = (pwa_root / "index.html").read_text(encoding="utf-8")
    worker = (pwa_root / "service-worker.js").read_text(encoding="utf-8")
    asset_match = PWA_ASSET_PATTERN.search(index)
    cache_match = PWA_CACHE_PATTERN.search(worker)
    if not asset_match or not cache_match:
        raise RuntimeError("Version des assets PWA introuvable.")
    asset_version = asset_match.group(1)
    cache_version = f"{cache_match.group(1)}.{cache_match.group(2)}"
    if asset_version != cache_version:
        raise RuntimeError("Versions incohérentes entre les assets et le cache PWA.")
    return asset_version


def sign_windows_executable(path):
    """Authenticode-sign an executable when CI signing is configured."""
    thumbprint = os.environ.get("USAGE_GUARD_SIGNING_THUMBPRINT", "").strip()
    required = os.environ.get("USAGE_GUARD_REQUIRE_SIGNING", "").strip() == "1"
    if not thumbprint:
        if required:
            raise RuntimeError("Certificat de signature client absent.")
        return path
    signtool = shutil.which("signtool.exe") or shutil.which("signtool")
    if not signtool:
        raise RuntimeError("signtool introuvable pour la signature client.")
    timestamp_url = os.environ.get(
        "USAGE_GUARD_TIMESTAMP_URL", "http://timestamp.digicert.com"
    ).strip()
    command = [
        signtool, "sign", "/sha1", thumbprint, "/fd", "SHA256",
        "/tr", timestamp_url, "/td", "SHA256", str(path),
    ]
    subprocess.run(command, check=True)
    subprocess.run([signtool, "verify", "/pa", "/v", str(path)], check=True)
    return path


def build_installer_launcher(root, payload_root):
    work = root / "installer-work"
    dist = root / "installer-dist"
    command = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
        "--onefile", "--windowed", "--uac-admin",
        "--name", Path(INSTALLER_NAME).stem,
        "--icon", str(ROOT / "icons" / "usage-guard.ico"),
        "--paths", str(ROOT),
        "--specpath", str(work), "--workpath", str(work),
        "--distpath", str(dist),
        "--add-data", f"{payload_root}{';' if sys.platform == 'win32' else ':'}.",
        str(ROOT / "tools" / "install_client_launcher.py"),
    ]
    result = subprocess.run(command, cwd=ROOT, check=False)
    launcher = dist / INSTALLER_NAME
    if result.returncode or not launcher.is_file() or not launcher.stat().st_size:
        raise RuntimeError("Compilation de l’installateur graphique impossible.")
    return launcher


def build_setup_wizard(root):
    work = root / "setup-work"
    dist = root / "setup-dist"
    command = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
        "--onefile", "--windowed", "--name", Path(SETUP_NAME).stem,
        "--icon", str(ROOT / "icons" / "usage-guard.ico"),
        "--paths", str(ROOT),
        "--add-data",
        f"{ROOT / 'locales'}{';' if sys.platform == 'win32' else ':'}locales",
        "--specpath", str(work), "--workpath", str(work),
        "--distpath", str(dist),
        str(ROOT / "tools" / "setup_client_qt.py"),
    ]
    result = subprocess.run(command, cwd=ROOT, check=False)
    executable = dist / SETUP_NAME
    if result.returncode or not executable.is_file() or not executable.stat().st_size:
        raise RuntimeError("Compilation de l’assistant Qt autonome impossible.")
    return executable


def build_service_runtime(root):
    """Build a self-contained onedir runtime suitable for the Windows SCM."""
    work = root / "service-work"
    dist = root / "service-dist"
    command = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
        "--onedir", "--console", "--name", SERVICE_RUNTIME_NAME,
        "--hidden-import", "win32timezone", "--collect-data", "tzdata",
        "--paths", str(ROOT),
        "--add-data",
        f"{ROOT / 'usage_guard_backend' / 'pwa'}{';' if sys.platform == 'win32' else ':'}usage_guard_backend/pwa",
        "--specpath", str(work), "--workpath", str(work),
        "--distpath", str(dist),
        str(ROOT / "windows_service_production.py"),
    ]
    result = subprocess.run(command, cwd=ROOT, check=False)
    runtime = dist / SERVICE_RUNTIME_NAME
    executable = runtime / f"{SERVICE_RUNTIME_NAME}.exe"
    if result.returncode or not executable.is_file() or not executable.stat().st_size:
        raise RuntimeError("Compilation du service Windows autonome impossible.")
    return runtime


def write_internal_manifest(package_root):
    manifest_path = package_root / "client-manifest.json"
    files = {
        str(path.relative_to(package_root)).replace("\\", "/"): sha256(path)
        for path in sorted(package_root.rglob("*"))
        if path.is_file() and path != manifest_path
    }
    manifest_path.write_text(
        json.dumps({
            "version": CLIENT_VERSION,
            "pwa_version": pwa_asset_version(),
            "files": files,
        },
                   ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest_path


def pack_service_runtime(package_root):
    """Collapse the PyInstaller onedir runtime for legacy updater compatibility."""
    package_root = Path(package_root)
    runtime = package_root / "service-runtime"
    archive_path = package_root / SERVICE_RUNTIME_ARCHIVE
    if not runtime.is_dir():
        raise RuntimeError("Runtime du service absent du paquet client.")
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(runtime.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(runtime))
    shutil.rmtree(runtime)
    return archive_path


def build_release(output=OUTPUT, mandatory=False, minimum_version=None, notes=""):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="usage-guard-client-release-") as directory:
        root = Path(directory)
        executable = build_candidate(
            work=root / "pyinstaller-work", dist=root / "pyinstaller-dist",
        )
        if executable is None:
            raise RuntimeError("Compilation PyInstaller impossible.")
        sign_windows_executable(executable)
        update_root = root / "update-package"
        (update_root / "tools").mkdir(parents=True)
        shutil.copy2(executable, update_root / "usage-guard.exe")
        service_runtime = build_service_runtime(root)
        sign_windows_executable(
            service_runtime / f"{SERVICE_RUNTIME_NAME}.exe"
        )
        shutil.copytree(service_runtime, update_root / "service-runtime")
        for name in TOOL_FILES:
            shutil.copy2(ROOT / "tools" / name, update_root / "tools" / name)
        shutil.copytree(
            ROOT / "browser_extension",
            update_root / BROWSER_EXTENSION_DIRNAME,
        )
        write_internal_manifest(update_root)

        installer_root = root / "initial-installer-payload"
        shutil.copytree(update_root, installer_root)
        setup_wizard = build_setup_wizard(root)
        sign_windows_executable(setup_wizard)
        shutil.copy2(setup_wizard, installer_root / SETUP_NAME)
        write_internal_manifest(installer_root)
        installer = build_installer_launcher(root, installer_root)
        sign_windows_executable(installer)
        shutil.copy2(installer, output / INSTALLER_NAME)

        # The initial installer can embed the expanded directory, but update
        # ZIPs must remain readable by the already deployed 1.013 updater.
        pack_service_runtime(update_root)
        write_internal_manifest(update_root)
        filename = f"usage-guard-client-{CLIENT_VERSION}.zip"
        temporary_zip = root / filename
        package_files = [
            path for path in sorted(update_root.rglob("*")) if path.is_file()
        ]
        if len(package_files) > LEGACY_MAX_PACKAGE_MEMBERS:
            raise RuntimeError(
                "Paquet de mise à jour incompatible avec les anciens clients : "
                f"{len(package_files)} fichiers (maximum "
                f"{LEGACY_MAX_PACKAGE_MEMBERS})."
            )
        with zipfile.ZipFile(temporary_zip, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in package_files:
                archive.write(path, path.relative_to(update_root))
        destination = output / filename
        shutil.copy2(temporary_zip, destination)
    manifest = {
        "version": CLIENT_VERSION,
        "pwa_version": pwa_asset_version(),
        "minimum_version": minimum_version or CLIENT_VERSION,
        "mandatory": bool(mandatory),
        "filename": destination.name,
        "sha256": sha256(destination),
        "size": destination.stat().st_size,
        "published_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "notes": str(notes or ""),
    }
    temporary_manifest = output / "manifest.json.tmp"
    temporary_manifest.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary_manifest.replace(output / "manifest.json")
    print(json.dumps(manifest, ensure_ascii=False))
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--mandatory", action="store_true")
    parser.add_argument("--minimum-version")
    parser.add_argument("--notes", default="")
    args = parser.parse_args()
    build_release(args.output, args.mandatory, args.minimum_version, args.notes)


if __name__ == "__main__":
    main()
