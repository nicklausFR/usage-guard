"""Build the Windows executable with PyInstaller.

Run with:  python build_exe.py
The executable is created in dist/usage-guard.exe.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
APP_NAME = "Usage Monitor"


def persistent_activity_path():
    """Location read by the compiled executable, outside PyInstaller's temp dir."""
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    return base / APP_NAME / "activity.json"


def migrate_activity_file():
    """Preserve existing development statistics on the first executable build."""
    source = ROOT / "activity.json"
    destination = persistent_activity_path()
    if source.exists() and not destination.exists():
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            print(f"Statistiques existantes copiees : {destination}")
        except OSError as error:
            # The executable has still been built successfully. This can occur
            # when the build is launched by another Windows account.
            print(f"Copie des statistiques ignoree ({error}).")


def main():
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("PyInstaller est requis. Installe-le avec : pip install pyinstaller")
        return 1

    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--name",
        "usage-guard",
        "--specpath",
        "build",
        "--workpath",
        "build",
        "--add-data",
        f"{ROOT / 'config.yaml'};.",
        "main.py",
    ]
    result = subprocess.run(command, cwd=ROOT, check=False)
    if result.returncode == 0:
        migrate_activity_file()
        print(f"Executable cree : {ROOT / 'dist' / 'usage-guard.exe'}")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
