"""Compile, install and restart the protected Usage Guard build.

Run with: ``python build_exe.py``
Check paths without changing anything with: ``python build_exe.py --check``

The build is produced in staging while the installed application keeps
running. The controlled switch only stops it after PyInstaller succeeded.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from tools.build_v2_candidate import build_candidate


ROOT = Path(__file__).resolve().parent
STAGING_WORK = ROOT / "build" / "v2-release-work"
STAGING_DIST = ROOT / "build" / "v2-release"
INSTALLED_EXECUTABLE = ROOT / "dist-v2" / "usage-guard.exe"
SWITCH_SCRIPT = ROOT / "tools" / "switch_to_v2.ps1"


def switch_command(candidate: Path) -> list[str]:
    return [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(SWITCH_SCRIPT),
        "-CandidatePath",
        str(candidate),
    ]


def print_check() -> None:
    print(f"Sources Usage Guard : {ROOT}")
    print(f"Exécutable installé : {INSTALLED_EXECUTABLE}")
    print(f"Compilation temporaire : {STAGING_DIST}")
    print(f"Service anti-contournement : {ROOT / 'tools' / 'check_production_service.py'}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="afficher les chemins sans compiler ni redémarrer",
    )
    arguments = parser.parse_args(argv)
    if arguments.check:
        print_check()
        return 0
    if sys.platform != "win32":
        parser.error("La compilation installable nécessite Windows.")
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("PyInstaller est requis : python -m pip install pyinstaller")
        return 1

    print("Compilation Usage Guard en arrière-plan — la protection reste active...")
    candidate = build_candidate(work=STAGING_WORK, dist=STAGING_DIST)
    if candidate is None:
        print("Échec de compilation : la version actuellement installée est inchangée.")
        return 1

    print("Compilation terminée. Installation de l’application et mise à jour du service protégé...")
    result = subprocess.run(switch_command(candidate), cwd=ROOT, check=False)
    if result.returncode:
        print("La bascule a échoué : la V1 de secours a été relancée.")
        return result.returncode
    print(f"Usage Guard et son service protégé sont à jour : {INSTALLED_EXECUTABLE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
