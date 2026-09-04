"""Repair an explicit Windows SID mapping without guessing account names."""

from __future__ import annotations

import argparse
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

try:
    from .server import Store
except ImportError:  # pragma: no cover - direct server-side execution
    from server import Store


def repair(db_path, source_user, target_user, windows_username, backup_dir, apply=False):
    store = Store(db_path)
    source_key = str(source_user).strip().casefold()
    target_key = str(target_user).strip().casefold()
    windows_key = str(windows_username).strip().casefold()
    users = {item["username"].casefold(): item for item in store.list_users()}
    if target_key not in users or users[target_key].get("role") != "limited":
        raise ValueError("La cible doit être un utilisateur à limiter existant.")
    if source_key not in users:
        raise ValueError("L’utilisateur source est inconnu.")

    devices = store.list_devices()
    planned = []
    for device in devices:
        for identity in store.device_windows_identities(device["device_id"]):
            if (
                str(identity.get("usage_guard_username") or "").casefold() == source_key
                and str(identity.get("windows_username") or "").casefold() == windows_key
            ):
                planned.append({
                    "device_id": device["device_id"],
                    "device_name": str(device.get("label") or device["device_id"]),
                    "windows_sid": identity["windows_sid"],
                    "windows_username": identity["windows_username"],
                })
    if not planned:
        raise ValueError("Aucune association exacte à réparer.")
    result = {
        "source_user": users[source_key]["username"],
        "target_user": users[target_key]["username"],
        "matches": planned,
        "applied": False,
    }
    if not apply:
        return result

    identities_by_device = {
        device_id: store.device_windows_identities(device_id)
        for device_id in {item["device_id"] for item in planned}
    }

    backup_dir = Path(backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup_path = backup_dir / f"backend-before-identity-repair-{stamp}.sqlite3"
    with closing(sqlite3.connect(str(db_path))) as source, closing(
        sqlite3.connect(str(backup_path))
    ) as target:
        with target:
            source.backup(target)

    planned_devices = {item["device_id"] for item in planned}
    with store._lock, store.connect() as db:
        with db:
            role = db.execute(
                "SELECT role FROM users WHERE username=? COLLATE NOCASE", (target_user,)
            ).fetchone()
            if not role or role["role"] != "limited":
                raise ValueError("La cible n’est plus un utilisateur à limiter.")
            for device_id in sorted(planned_devices):
                current = db.execute(
                    "SELECT 1 FROM device_windows_identities "
                    "WHERE device_id=? AND windows_username=? COLLATE NOCASE "
                    "AND usage_guard_username=? COLLATE NOCASE",
                    (device_id, windows_username, source_user),
                ).fetchone()
                if not current:
                    raise ValueError(f"Association modifiée simultanément pour {device_id}.")
                identities = identities_by_device[device_id]
                changed = False
                for identity in identities:
                    if (
                        str(identity.get("usage_guard_username") or "").casefold() == source_key
                        and str(identity.get("windows_username") or "").casefold() == windows_key
                    ):
                        identity["usage_guard_username"] = users[target_key]["username"]
                        changed = True
                if not changed:
                    raise ValueError(f"Association modifiée simultanément pour {device_id}.")
                Store._replace_device_windows_identities(
                    db, device_id, identities, "repair_windows_identity"
                )
                for table in ("activity_intervals", "activity_live_intervals"):
                    db.execute(
                        f"UPDATE {table} SET usage_guard_username=? "
                        "WHERE device_id=? AND usage_guard_username=? COLLATE NOCASE",
                        (users[target_key]["username"], device_id, source_user),
                    )
    result["applied"] = True
    result["backup"] = str(backup_path)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--from-user", required=True)
    parser.add_argument("--to-user", required=True)
    parser.add_argument("--windows-username", required=True)
    parser.add_argument("--backup-dir", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        result = repair(
            args.database, args.from_user, args.to_user,
            args.windows_username, args.backup_dir, args.apply,
        )
    except (OSError, sqlite3.Error, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False))
        return 1
    print(json.dumps({"ok": True, **result}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
