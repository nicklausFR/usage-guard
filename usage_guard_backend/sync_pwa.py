"""Refresh the PWA copy packaged with the backend release."""
import shutil
from pathlib import Path


backend = Path(__file__).resolve().parent
source = backend.parent / "pwa"
destination = backend / "pwa"
# Some Windows worktrees allow replacing packaged files but deny deleting them.
# Updating in place keeps deployment repeatable without requiring elevation.
shutil.copytree(source, destination, dirs_exist_ok=True)
print(f"PWA backend synchronisée : {destination}")
