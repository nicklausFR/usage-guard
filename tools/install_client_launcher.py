"""Elevated GUI bootstrap for the packaged Usage Guard installer."""

from __future__ import annotations

import ctypes
from datetime import datetime
import os
import subprocess
import sys
from pathlib import Path

from i18n import _


def package_root() -> Path:
    embedded_root = getattr(sys, "_MEIPASS", "")
    if getattr(sys, "frozen", False) and embedded_root:
        return Path(embedded_root).resolve()
    return Path(__file__).resolve().parent


def is_administrator() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def message(text: str, *, error: bool = False) -> None:
    flags = 0x10 if error else 0x40
    ctypes.windll.user32.MessageBoxW(None, text, _("Installation de Usage Guard"), flags)


def installer_log_path() -> Path:
    base = Path(os.environ.get("PROGRAMDATA") or os.environ.get("TEMP") or ".")
    return base / "Usage Guard" / "Installer" / "install-client.log"


def write_install_log(completed: subprocess.CompletedProcess) -> Path:
    path = installer_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    stdout = str(completed.stdout or "").strip()
    stderr = str(completed.stderr or "").strip()
    with path.open("a", encoding="utf-8") as stream:
        stream.write(
            f"\n[{datetime.now().astimezone().isoformat()}] "
            f"exit={completed.returncode}\n"
        )
        if stdout:
            stream.write(f"STDOUT\n{stdout}\n")
        if stderr:
            stream.write(f"STDERR\n{stderr}\n")
    return path


def failure_summary(completed: subprocess.CompletedProcess) -> str:
    output = completed.stderr or completed.stdout or ""
    lines = [
        line.strip()
        for line in str(output).splitlines()
        if line.strip()
    ]
    return lines[-1] if lines else _("Erreur non détaillée par PowerShell.")


def offer_tray_pinning() -> None:
    result = ctypes.windll.user32.MessageBoxW(
        None,
        _("Usage Guard est installé.\n\n"
          "Pour garder son icône visible en bas, à côté de vos autres icônes, "
          "faites-la glisser depuis le menu des icônes masquées vers la barre.\n\n"
          "Ouvrir maintenant les paramètres de la barre des tâches ?"),
        _("Installation de Usage Guard"),
        0x40 | 0x04,
    )
    if result == 6:  # IDYES
        ctypes.windll.shell32.ShellExecuteW(
            None, "open", "ms-settings:taskbar", None, None, 1,
        )


def show_browser_extension_guidance() -> None:
    message(
        _("L’extension navigateur a été copiée dans :\n"
          "{path}\n\nDans Brave ou Chrome, ouvrez la page Extensions, activez le "
          "mode développeur, choisissez « Charger l’extension non empaquetée », "
          "puis sélectionnez ce dossier.\n\n"
          "Cette activation est propre à chaque profil de navigateur.").format(
              path=r"C:\Program Files\Usage Guard\Browser Extension\current"
          )
    )


def request_elevation(executable: Path) -> int:
    result = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", str(executable), None, str(executable.parent), 1,
    )
    if result <= 32:
        message(_("L’autorisation administrateur est nécessaire pour installer Usage Guard."), error=True)
        return 1
    return 0


def install(root: Path) -> int:
    script = root / "tools" / "install_client.ps1"
    candidate = root / "usage-guard.exe"
    if not script.is_file() or not candidate.is_file():
        message(
            _("Le paquet est incomplet. Extrayez entièrement l’archive avant de lancer l’installation."),
            error=True,
        )
        return 1
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    completed = subprocess.run(
        [
            "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", str(script), "-PackageRoot", str(root),
        ],
        cwd=root,
        creationflags=creation_flags,
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )
    log_path = write_install_log(completed)
    if completed.returncode:
        message(
            _("L’installation n’a pas abouti. Aucun ancien client fonctionnel "
              "ne doit avoir été supprimé.\n\n"
              "Détail : {detail}\n\nJournal : {log}").format(
                  detail=failure_summary(completed), log=log_path
              ),
            error=True,
        )
    else:
        show_browser_extension_guidance()
        offer_tray_pinning()
    return int(completed.returncode)


def main() -> int:
    root = package_root()
    if sys.platform != "win32":
        return 1
    if not is_administrator():
        return request_elevation(Path(sys.executable).resolve())
    return install(root)


if __name__ == "__main__":
    raise SystemExit(main())
