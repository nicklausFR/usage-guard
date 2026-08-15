"""Refresh the PWA copy packaged with the backend release."""
import shutil
from pathlib import Path


backend = Path(__file__).resolve().parent
source = backend.parent / "pwa"
destination = backend / "pwa"
if destination.exists():
    shutil.rmtree(destination)
shutil.copytree(source, destination)
print(f"PWA backend synchronisée : {destination}")
