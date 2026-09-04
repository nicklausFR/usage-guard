"""Stage verified client releases and launch the protected Windows installer."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import threading
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from client_version import CLIENT_VERSION


def version_tuple(value):
    text = str(value or "")
    parts = text.split(".")
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        raise ValueError("Version client invalide.")
    major, revision = (int(part) for part in parts)
    # Les versions 2.xxx étaient des préversions de développement antérieures
    # à la première base stable 1.000. Ce classement exceptionnel permet au
    # client stable de ne jamais proposer un ancien paquet 2.xxx en retour.
    if major == 2:
        return (0, major, revision)
    return (1, major, revision)


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ClientUpdateManager:
    def __init__(self, directory, client, interval_seconds=15 * 60, launcher=None):
        self.directory = Path(directory) / "client-updates"
        self.state_path = self.directory / "state.json"
        self.client = client
        self.interval_seconds = max(60, int(interval_seconds))
        self.launcher = launcher or self._launch_installer
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread = None
        self._download_thread = None
        self._status = self._normalize_loaded_status(self._load_status())

    def _load_status(self):
        try:
            saved = json.loads(self.state_path.read_text(encoding="utf-8"))
            return saved if isinstance(saved, dict) else {}
        except (OSError, TypeError, ValueError):
            return {}

    def _normalize_loaded_status(self, saved):
        """Recover a download or installation interrupted with the service."""
        saved = dict(saved or {})
        state = str(saved.get("state") or "idle")
        available = str(saved.get("available_version") or "")
        try:
            newer = bool(available) and version_tuple(available) > version_tuple(
                CLIENT_VERSION
            )
        except ValueError:
            newer = False
        if state == "installing" and newer:
            stage = Path(saved.get("stage_path") or "")
            installer = stage / "tools" / "install_client.ps1"
            if installer.is_file():
                return {
                    **saved,
                    "state": "ready",
                    "error": "La précédente installation a été interrompue ; nouvel essai autorisé.",
                    "recovered_at": _utc_now(),
                    "current_version": CLIENT_VERSION,
                }
        if state in {"downloading", "installing"}:
            return {
                **saved,
                "state": "idle",
                "error": "Opération de mise à jour interrompue ; le paquet sera téléchargé à nouveau.",
                "recovered_at": _utc_now(),
                "current_version": CLIENT_VERSION,
            }
        return saved

    def _save_status(self, **values):
        with self._lock:
            self._status = {
                **self._status, **values, "current_version": CLIENT_VERSION,
                "updated_at": _utc_now(),
            }
            self.directory.mkdir(parents=True, exist_ok=True)
            temporary = self.state_path.with_suffix(".tmp")
            temporary.write_text(
                json.dumps(self._status, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            os.replace(temporary, self.state_path)

    def status(self):
        with self._lock:
            return dict(self._status or {
                "state": "idle", "current_version": CLIENT_VERSION,
            })

    def start(self):
        if self._thread is not None or not hasattr(self.client, "update_manifest"):
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="usage-guard-client-update",
        )
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

    def _run(self):
        while not self._stop.is_set():
            try:
                self.check()
            except Exception as error:
                self._save_status(
                    state="error", error=f"{type(error).__name__}: {error}"[:500],
                )
            self._stop.wait(self.interval_seconds)

    def check(self):
        with self._lock:
            update = self.client.update_manifest()
            if not update:
                self._save_status(
                    state="up_to_date", available_version="", manifest=None,
                    mandatory=False, error="", last_checked_at=_utc_now(),
                )
                self._cleanup_releases()
                return self.status()
            available = str(update.get("version") or "")
            if version_tuple(available) <= version_tuple(CLIENT_VERSION):
                self._save_status(
                    state="up_to_date", available_version=available,
                    manifest=None, mandatory=False, error="",
                    last_checked_at=_utc_now(),
                )
                self._cleanup_releases()
                return self.status()
            minimum = str(update.get("minimum_version") or available)
            version_tuple(minimum)
            mandatory = bool(update.get("mandatory")) or (
                version_tuple(CLIENT_VERSION) < version_tuple(minimum)
            )
            current = self.status()
            if (
                current.get("available_version") == available
                and current.get("state") in {"downloading", "ready", "installing"}
            ):
                self._save_status(
                    manifest=dict(update), mandatory=mandatory,
                    last_checked_at=_utc_now(),
                )
                return self.status()
            self._save_status(
                state="update_available", available_version=available,
                mandatory=mandatory, manifest=dict(update), error="",
                last_checked_at=_utc_now(),
            )
            return self.status()

    def request_install(self):
        """Start an explicitly requested download without blocking the UI pipe."""
        # The backend package endpoint always exposes the current release. A
        # manifest cached just before a publication must therefore be refreshed
        # before downloading, otherwise the correct newer ZIP would be rejected
        # against the previous version's size and digest.
        self.check()
        with self._lock:
            current = self.status()
            if current.get("state") == "ready":
                return self.install()
            if current.get("state") in {"downloading", "installing"}:
                return current
            update = current.get("manifest")
            if not isinstance(update, dict) or not update.get("version"):
                raise ValueError("Aucune mise à jour disponible.")
            mandatory = bool(current.get("mandatory"))
            self._save_status(state="downloading", error="")
            self._download_thread = threading.Thread(
                target=self._download_requested_update,
                args=(dict(update), mandatory), daemon=True,
                name="usage-guard-client-update-download",
            )
            self._download_thread.start()
            return self.status()

    def _download_requested_update(self, update, mandatory):
        try:
            self.stage(update, mandatory)
            self.install()
        except Exception as error:
            with self._lock:
                current = self.status()
                retry_state = "ready" if current.get("state") == "ready" else "error"
                self._save_status(
                    state=retry_state,
                    error=f"{type(error).__name__}: {error}"[:500],
                )
        finally:
            self._download_thread = None

    def stage(self, update, mandatory=False):
        with self._lock:
            version = str(update.get("version") or "")
            version_tuple(version)
            self.directory.mkdir(parents=True, exist_ok=True)
            package = self.directory / f"client-{version}.zip"
            self._save_status(
                state="downloading", available_version=version,
                mandatory=bool(mandatory), error="",
            )
            self.client.download_update(update, package)
            stage = self.directory / "staged" / version
            temporary_stage = self.directory / "staged" / (version + ".tmp")
            if temporary_stage.exists():
                shutil.rmtree(temporary_stage)
            temporary_stage.mkdir(parents=True)
            try:
                self._extract_verified(package, temporary_stage, version)
                if stage.exists():
                    shutil.rmtree(stage)
                os.replace(temporary_stage, stage)
            except Exception:
                shutil.rmtree(temporary_stage, ignore_errors=True)
                raise
            self._save_status(
                state="ready", available_version=version,
                mandatory=bool(mandatory), stage_path=str(stage), error="",
            )
            self._cleanup_releases(keep_version=version)
            return self.status()

    @staticmethod
    def _extract_verified(package, destination, expected_version):
        with zipfile.ZipFile(package) as archive:
            members = archive.infolist()
            if len(members) > 200 or sum(item.file_size for item in members) > 1024 * 1024 * 1024:
                raise ValueError("Paquet client démesuré.")
            normalized_names = []
            for item in members:
                path = PurePosixPath(item.filename.replace("\\", "/"))
                if (
                    path.is_absolute() or ".." in path.parts
                    or not path.parts or path.parts[0] in {"", "."}
                ):
                    raise ValueError("Chemin interdit dans le paquet client.")
                if item.flag_bits & 0x1:
                    raise ValueError("Fichier chiffré interdit dans le paquet client.")
                if (item.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError("Lien symbolique interdit dans le paquet client.")
                normalized_names.append(path.as_posix().rstrip("/"))
            if len(normalized_names) != len(set(normalized_names)):
                raise ValueError("Nom de fichier dupliqué dans le paquet client.")
            try:
                internal = json.loads(archive.read("client-manifest.json"))
            except (KeyError, ValueError, UnicodeDecodeError) as error:
                raise ValueError("Manifest interne absent ou invalide.") from error
            if str(internal.get("version") or "") != expected_version:
                raise ValueError("Version interne du paquet incohérente.")
            files = internal.get("files")
            if not isinstance(files, dict):
                raise ValueError("Liste d’intégrité interne absente.")
            names = set(normalized_names)
            expected_names = set(files) | {"client-manifest.json"}
            if names != expected_names:
                raise ValueError("Contenu du paquet différent du manifeste interne.")
            for name, expected_hash in files.items():
                if name not in names or not isinstance(expected_hash, str):
                    raise ValueError(f"Fichier client absent : {name}")
                actual = hashlib.sha256(archive.read(name)).hexdigest()
                if not hmac.compare_digest(actual, expected_hash.lower()):
                    raise ValueError(f"Intégrité client refusée : {name}")
            archive.extractall(destination)

    def install(self):
        with self._lock:
            status = self.status()
            if status.get("state") != "ready":
                raise ValueError("Aucune mise à jour vérifiée prête à installer.")
            stage = Path(status.get("stage_path") or "")
            installer = stage / "tools" / "install_client.ps1"
            if sys.platform != "win32" or not installer.is_file():
                raise RuntimeError("Installateur Windows de mise à jour indisponible.")
            install_log = self.directory / "install-client.log"
            maintenance = getattr(self.client, "begin_update_maintenance", None)
            if callable(maintenance):
                maintenance(status.get("available_version"), duration_seconds=900)
            self._save_status(
                state="installing", install_started_at=_utc_now(), error="",
                install_log_path=str(install_log),
            )
            try:
                process = self.launcher(installer, stage)
            except Exception as error:
                self._save_status(
                    state="ready", error=f"Lancement de l’installation impossible : {error}"[:500],
                )
                raise
            if process is not None and callable(getattr(process, "wait", None)):
                threading.Thread(
                    target=self._watch_installer,
                    args=(process, str(status.get("available_version") or "")),
                    daemon=True,
                    name="usage-guard-client-install-watch",
                ).start()
            return self.status()

    def _watch_installer(self, process, version):
        """Make a pre-service-stop installer failure immediately retryable."""
        try:
            returncode = int(process.wait())
        except Exception as error:
            returncode = -1
            detail = f"surveillance impossible : {type(error).__name__}: {error}"
        else:
            detail = f"code de sortie {returncode}"
        if returncode == 0:
            return
        with self._lock:
            current = self.status()
            if (
                current.get("state") == "installing"
                and current.get("available_version") == version
            ):
                log_path = str(current.get("install_log_path") or "")
                suffix = f" Journal : {log_path}" if log_path else ""
                self._save_status(
                    state="ready",
                    error=(
                        f"Installation interrompue ({detail}). Le paquet vérifié "
                        f"peut être réessayé.{suffix}"
                    )[:500],
                )

    def _cleanup_releases(self, keep_version=""):
        """Keep only the release that can still be installed."""
        keep_version = str(keep_version or "")
        if not self.directory.exists():
            return
        for package in self.directory.glob("client-*.zip"):
            if package.stem == f"client-{keep_version}":
                continue
            try:
                package.unlink()
            except OSError:
                pass
        staged = self.directory / "staged"
        if staged.is_dir():
            for entry in staged.iterdir():
                if entry.name == keep_version:
                    continue
                try:
                    if entry.is_dir():
                        shutil.rmtree(entry)
                    else:
                        entry.unlink()
                except OSError:
                    pass

    @staticmethod
    def _launch_installer(installer, stage):
        # DETACHED_PROCESS combiné à CREATE_NO_WINDOW fait retourner
        # powershell.exe avec le code 0 sans exécuter -File sur Windows. Le
        # processus reste indépendant du terminal grâce à CREATE_NO_WINDOW ;
        # le service le surveille jusqu'à l'arrêt provoqué par l'installation.
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        log_path = Path(stage).parent.parent / "install-client.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("ab") as stream:
            stream.write(
                f"\n[{_utc_now()}] update installer launched\n".encode("utf-8")
            )
            return subprocess.Popen(
                [
                    "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-File", str(installer), "-Update", "-PackageRoot", str(stage),
                ],
                cwd=str(stage), creationflags=flags, close_fds=True,
                stdout=stream, stderr=subprocess.STDOUT,
            )
