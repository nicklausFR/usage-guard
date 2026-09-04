"""Build an isolated unpacked browser extension for the dev profile."""

from __future__ import annotations

import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "browser_extension"
DESTINATION = ROOT / "build" / "browser-extension-dev"


def build_dev_extension(
    source: Path = SOURCE,
    destination: Path = DESTINATION,
) -> Path:
    source = Path(source).resolve()
    destination = Path(destination).resolve()
    if source == destination or source in destination.parents:
        raise ValueError("Le dossier Dev doit être distinct de l’extension source.")
    if destination.exists():
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination)

    manifest_path = destination / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["name"] = "Usage Guard DEV — liaison navigateur"
    manifest["description"] = (
        "Extension isolée pour le profil de développement Usage Guard."
    )
    manifest["version_name"] = "development"
    manifest["host_permissions"] = ["http://127.0.0.1:18765/*"]
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (destination / "README.md").write_text(
        "# Usage Guard DEV Browser Bridge\n\n"
        "Cette extension isolée contacte uniquement le profil DEV sur "
        "`127.0.0.1:18765`.\n",
        encoding="utf-8",
    )
    return destination


def main() -> int:
    destination = build_dev_extension()
    print(f"Extension Usage Guard DEV prête : {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
