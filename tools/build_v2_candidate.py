"""Build the current Usage Guard candidate without touching the installation."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "build" / "v2-candidate"
DIST = ROOT / "dist-v2"
EXECUTABLE = DIST / "usage-guard.exe"


def build_candidate(*, work: Path = WORK, dist: Path = DIST) -> Path | None:
    """Build into ``dist`` and leave the running installation untouched."""
    subprocess.run(
        [sys.executable, str(ROOT / "tools" / "compile_translations.py")],
        cwd=ROOT, check=True,
    )
    shutil.rmtree(work, ignore_errors=True)
    shutil.rmtree(dist, ignore_errors=True)
    dist.mkdir(parents=True, exist_ok=True)
    executable = dist / EXECUTABLE.name
    command = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
        "--onefile", "--windowed", "--name", "usage-guard",
        "--icon", str(ROOT / "icons" / "usage-guard.ico"),
        "--specpath", str(work), "--workpath", str(work),
        "--distpath", str(dist),
        "--add-data", f"{ROOT / 'config.yaml'};.",
        "--add-data", f"{ROOT / 'pwa'};pwa",
        "--add-data", f"{ROOT / 'locales'};locales",
        str(ROOT / "main.py"),
    ]
    result = subprocess.run(command, cwd=ROOT, check=False)
    if result.returncode or not executable.is_file() or not executable.stat().st_size:
        return None
    return executable


def main():
    executable = build_candidate()
    if executable is None:
        return 1
    print(executable)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
