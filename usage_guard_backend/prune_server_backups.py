"""Prune old automatic Usage Guard backend backups safely.

The command is a dry run unless ``--apply`` is supplied.  It only considers
the transaction backups created by ``deploy-server.ps1``; manual recovery
points and the active database are never candidates.
"""

from __future__ import annotations

import argparse
import re
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


DEFAULT_BACKUP_DIRECTORY = Path(__file__).resolve().parent / "data" / "backups"
AUTOMATIC_BACKUP_NAME = re.compile(
    r"^backend-before-v[0-9]+\.[0-9]{3}-(?P<stamp>[0-9]{8}-[0-9]{6})\.sqlite3$",
    re.ASCII,
)


@dataclass(frozen=True)
class BackupCandidate:
    path: Path
    stamp: datetime
    device: int
    inode: int
    size: int


@dataclass(frozen=True)
class PrunePlan:
    directory: Path
    kept: tuple[BackupCandidate, ...]
    removed: tuple[BackupCandidate, ...]
    reclaimed_bytes: int


def automatic_backups(directory: Path) -> list[BackupCandidate]:
    """Return eligible regular files, newest first."""
    directory = directory.expanduser()
    if directory.is_symlink():
        raise ValueError(f"The backup directory is a symbolic link: {directory}")
    try:
        resolved = directory.resolve(strict=True)
    except FileNotFoundError as error:
        raise ValueError(f"Backup directory not found: {directory}") from error
    if not resolved.is_dir():
        raise ValueError(f"The backup path is not a directory: {resolved}")

    candidates: list[BackupCandidate] = []
    for path in resolved.iterdir():
        match = AUTOMATIC_BACKUP_NAME.fullmatch(path.name)
        if not match:
            continue
        try:
            metadata = path.lstat()
            stamp = datetime.strptime(match.group("stamp"), "%Y%m%d-%H%M%S")
        except (OSError, ValueError):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            continue
        candidates.append(
            BackupCandidate(
                path=path,
                stamp=stamp,
                device=metadata.st_dev,
                inode=metadata.st_ino,
                size=metadata.st_size,
            )
        )
    return sorted(
        candidates,
        key=lambda candidate: (candidate.stamp, candidate.path.name),
        reverse=True,
    )


def build_prune_plan(
    directory: Path, keep: int, protected_path: Path | None = None
) -> PrunePlan:
    if keep < 1:
        raise ValueError("The number of retained backups must be greater than zero.")
    backups = automatic_backups(directory)
    kept = tuple(backups[:keep])
    removed = tuple(backups[keep:])
    if protected_path is not None:
        try:
            protected = protected_path.expanduser().resolve(strict=True)
        except FileNotFoundError as error:
            raise ValueError(
                f"Protected fresh backup not found: {protected_path}"
            ) from error
        if protected.parent != directory.expanduser().resolve(strict=True):
            raise ValueError(
                f"Protected backup is outside the allowed directory: {protected}"
            )
        matching = next(
            (candidate for candidate in backups if candidate.path == protected), None
        )
        if matching is None:
            raise ValueError(
                f"Protected file is not a recognized automatic backup: {protected}"
            )
        if matching not in kept:
            raise ValueError(
                "The fresh backup is not among the retained files; pruning cancelled."
            )
    return PrunePlan(
        directory=(directory.expanduser().resolve()),
        kept=kept,
        removed=removed,
        reclaimed_bytes=sum(candidate.size for candidate in removed),
    )


def apply_prune_plan(plan: PrunePlan) -> None:
    """Delete only unchanged, direct children from the validated plan."""
    directory = plan.directory.resolve(strict=True)
    for candidate in plan.removed:
        path = candidate.path
        if path.parent.resolve(strict=True) != directory:
            raise ValueError(f"Path is outside the allowed directory: {path}")
        if not AUTOMATIC_BACKUP_NAME.fullmatch(path.name):
            raise ValueError(f"Unsupported backup name: {path.name}")
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"Backup became unsafe before deletion: {path}")
        if (metadata.st_dev, metadata.st_ino) != (
            candidate.device,
            candidate.inode,
        ):
            raise ValueError(f"Backup was replaced after the dry run: {path}")
        path.unlink()


def format_size(byte_count: int) -> str:
    value = float(byte_count)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"


def render_plan(plan: PrunePlan, apply: bool) -> str:
    mode = "DELETE" if apply else "DRY RUN"
    lines = [
        f"Mode: {mode}",
        f"Directory: {plan.directory}",
        f"Automatic backups retained: {len(plan.kept)}",
        f"Automatic backups to delete: {len(plan.removed)}",
        f"Reclaimable space: {format_size(plan.reclaimed_bytes)}",
        "Retained:",
    ]
    lines.extend(f"  = {candidate.path.name}" for candidate in plan.kept)
    lines.append("To delete:")
    lines.extend(f"  - {candidate.path.name}" for candidate in plan.removed)
    if not apply:
        lines.append("No files deleted. Run again with --apply after reviewing the plan.")
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Retain the newest automatic Usage Guard backups. Manual backups and "
            "backend.sqlite3 are never targeted."
        )
    )
    parser.add_argument(
        "--backup-dir",
        type=Path,
        default=DEFAULT_BACKUP_DIRECTORY,
        help=f"Backup directory (default: {DEFAULT_BACKUP_DIRECTORY})",
    )
    parser.add_argument(
        "--keep",
        type=int,
        default=5,
        help="Number of recent automatic backups to retain (default: 5)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Delete the selected files; without this option, only show the plan",
    )
    parser.add_argument(
        "--protect",
        type=Path,
        help=(
            "Fresh backup that must be among the retained files, otherwise "
            "pruning is cancelled"
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        plan = build_prune_plan(args.backup_dir, args.keep, args.protect)
        print(render_plan(plan, args.apply))
        if args.apply:
            apply_prune_plan(plan)
            print(f"Deletion complete: {len(plan.removed)} file(s).")
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
