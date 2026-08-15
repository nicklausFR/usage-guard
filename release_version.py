"""Version releases from CHANGELOG.md, the sole version source."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


ENTRY_PATTERN = re.compile(
    r"^(?P<date>\d{2}/\d{2}/\d{4} \d{2}:\d{2}) — "
    r"v(?P<version>\d+\.\d{3}) — (?P<changes>.+)$",
    re.MULTILINE,
)
VERSION_PATTERN = re.compile(r"^\d+\.\d{3}$")
CACHE_PATTERN = re.compile(r"usage-guard-shell-v[0-9-]+")
ASSET_PATTERN = re.compile(r'(?P<asset>(?:style\.css|i18n\.js|app\.js)\?v=)[^"\]]+')
REGISTRATION_PATTERN = re.compile(r'(?P<asset>service-worker\.js\?v=)[^"\]]+')


@dataclass(frozen=True)
class ReleaseEntry:
    version: str
    changes: str


@dataclass(frozen=True)
class ReleasePlan:
    version: str
    changes: str | None
    new_entry: bool

    @property
    def cache(self) -> str:
        return "usage-guard-shell-v" + self.version.replace(".", "-")


def entries(changelog: str) -> list[ReleaseEntry]:
    return [
        ReleaseEntry(match.group("version"), match.group("changes").strip())
        for match in ENTRY_PATTERN.finditer(changelog)
    ]


def next_version(version: str) -> str:
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError(f"Version invalide : {version}")
    major_text, revision_text = version.split(".")
    major, revision = int(major_text), int(revision_text)
    if revision >= 999:
        return f"{major + 1}.001"
    return f"{major}.{revision + 1:03d}"


def normalize_changes(changes: str | None) -> str:
    value = re.sub(r"[\r\n]+", " ", str(changes or "")).strip()
    if not value:
        raise ValueError('Décrivez la version avec -Changes "…".')
    body = value.rstrip(".!?").strip()
    if re.search(r"[.!?]\s+", body):
        raise ValueError("-Changes doit contenir une seule phrase.")
    if not 10 <= len(body) <= 180:
        raise ValueError("-Changes doit contenir entre 10 et 180 caractères.")
    return body + "."


def plan_release(
    changelog: str,
    *,
    changes: str | None = None,
    requested_version: str | None = None,
    deployed_version: str | None = None,
    republish: bool = False,
) -> ReleasePlan:
    known = entries(changelog)
    if not known:
        raise ValueError("Aucune version N.NNN trouvée dans CHANGELOG.md.")
    versions = {entry.version: entry for entry in known}
    current = deployed_version or known[-1].version
    if current not in versions:
        raise ValueError(f"La version déployée v{current} est absente de CHANGELOG.md.")

    if republish:
        if changes or requested_version:
            raise ValueError("La republication n’accepte ni -Changes ni -Version.")
        return ReleasePlan(current, None, False)

    description = normalize_changes(changes)
    target = requested_version or next_version(current)
    if not VERSION_PATTERN.fullmatch(target):
        raise ValueError(f"Version invalide : {target}")
    if target == current:
        raise ValueError(f"La version v{target} est déjà déployée.")

    existing = versions.get(target)
    if existing:
        if target != known[-1].version or existing.changes != description:
            raise ValueError(f"La version v{target} existe déjà avec un autre contenu.")
        return ReleasePlan(target, description, False)
    if requested_version and tuple(map(int, target.split("."))) <= tuple(map(int, current.split("."))):
        raise ValueError("La nouvelle version doit être supérieure à la version déployée.")
    return ReleasePlan(target, description, True)


def render_service_worker(source: str, version: str) -> str:
    cache = "usage-guard-shell-v" + version.replace(".", "-")
    rendered, cache_count = CACHE_PATTERN.subn(cache, source, count=1)
    rendered, asset_count = ASSET_PATTERN.subn(
        lambda match: match.group("asset") + version, rendered
    )
    if cache_count != 1 or asset_count != 3:
        raise ValueError("Le service worker ne contient pas les marqueurs de version attendus.")
    return rendered


def render_asset_references(
    source: str, version: str, pattern: re.Pattern, expected: int
) -> str:
    rendered, count = pattern.subn(
        lambda match: match.group("asset") + version, source
    )
    if count != expected:
        raise ValueError("Les références de version attendues sont introuvables.")
    return rendered


def _replace_text(path: Path, value: str) -> None:
    path = path.resolve()
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(value)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def prepare_release(
    changelog_path: Path,
    index_path: Path,
    app_path: Path,
    service_worker_path: Path,
    plan: ReleasePlan,
    *,
    now: datetime | None = None,
) -> str | None:
    changelog = changelog_path.read_text(encoding="utf-8")
    index = index_path.read_text(encoding="utf-8")
    app = app_path.read_text(encoding="utf-8")
    worker = service_worker_path.read_text(encoding="utf-8")
    rendered_index = render_asset_references(index, plan.version, ASSET_PATTERN, 3)
    rendered_app = render_asset_references(app, plan.version, REGISTRATION_PATTERN, 1)
    rendered_worker = render_service_worker(worker, plan.version)
    entry = None
    if plan.new_entry:
        stamp = (now or datetime.now()).strftime("%d/%m/%Y %H:%M")
        entry = f"{stamp} — v{plan.version} — {plan.changes}"
        changelog = changelog.rstrip() + "\n" + entry + "\n"
    _replace_text(index_path, rendered_index)
    _replace_text(app_path, rendered_app)
    _replace_text(service_worker_path, rendered_worker)
    if entry:
        _replace_text(changelog_path, changelog)
    return entry


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "prepare"))
    parser.add_argument("--changelog", type=Path, required=True)
    parser.add_argument("--index", type=Path)
    parser.add_argument("--app", type=Path)
    parser.add_argument("--service-worker", type=Path)
    parser.add_argument("--changes")
    parser.add_argument("--version")
    parser.add_argument("--deployed-version")
    parser.add_argument("--republish", action="store_true")
    arguments = parser.parse_args()
    if arguments.mode == "prepare" and not all(
        (arguments.index, arguments.app, arguments.service_worker)
    ):
        parser.error("--index, --app et --service-worker sont requis avec prepare")
    try:
        changelog = arguments.changelog.read_text(encoding="utf-8")
        plan = plan_release(
            changelog,
            changes=arguments.changes,
            requested_version=arguments.version,
            deployed_version=arguments.deployed_version,
            republish=arguments.republish,
        )
        entry = None
        if arguments.mode == "prepare":
            entry = prepare_release(
                arguments.changelog,
                arguments.index,
                arguments.app,
                arguments.service_worker,
                plan,
            )
    except (OSError, ValueError) as error:
        print(json.dumps({"error": str(error)}, ensure_ascii=False))
        return 1
    print(json.dumps({
        "version": plan.version,
        "cache": plan.cache,
        "new_entry": plan.new_entry,
        "entry": entry,
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
