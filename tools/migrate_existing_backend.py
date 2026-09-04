"""Safely add v2 installation metadata without rotating device credentials."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from tools.enroll_device import save_atomic


def _normalized_mappings(values):
    normalized = []
    seen_sids = set()
    seen_users = set()
    for value in values or []:
        item = dict(value or {})
        sid = str(item.get("windows_sid") or "").strip().upper()
        username = str(item.get("usage_guard_username") or "").strip()
        if not re.fullmatch(r"S-\d+(?:-\d+)+", sid) or not username:
            raise ValueError("Association de session Windows invalide.")
        if sid.casefold() in seen_sids or username.casefold() in seen_users:
            raise ValueError("Association de session Windows dupliquée.")
        seen_sids.add(sid.casefold())
        seen_users.add(username.casefold())
        item["windows_sid"] = sid
        item["usage_guard_username"] = username
        normalized.append(item)
    if not normalized:
        raise ValueError("La migration exige au moins une session Windows.")
    return normalized


def merged_settings(existing, migration):
    """Return migrated settings while preserving the protected device secret."""
    existing = dict(existing or {})
    migration = dict(migration or {})
    if (
        migration.get("installation_profile") != "server"
        or migration.get("reuse_existing_credentials") is not True
    ):
        raise ValueError("Configuration de migration invalide.")
    existing_device_id = str(existing.get("device_id") or "").strip()
    migration_device_id = str(migration.get("device_id") or "").strip()
    device_token = str(existing.get("device_token") or "").strip()
    if (
        not existing_device_id
        or existing_device_id != migration_device_id
        or len(device_token) < 32
    ):
        raise ValueError(
            "La migration ne correspond pas à l’identité protégée de cet appareil."
        )
    existing_url = str(existing.get("base_url") or "").strip().rstrip("/")
    migration_url = str(migration.get("base_url") or "").strip().rstrip("/")
    if not existing_url or existing_url != migration_url:
        raise ValueError("La migration ne correspond pas au serveur configuré.")
    result = dict(existing)
    result.update({
        "installation_profile": "server",
        "enabled": True,
        "base_url": existing_url,
        "display_name": str(
            migration.get("display_name") or existing.get("display_name") or ""
        ).strip(),
        "windows_identities": _normalized_mappings(
            migration.get("windows_identities")
        ),
    })
    # The existing protected credential is authoritative and is never accepted
    # from the temporary wizard result.
    result["device_id"] = existing_device_id
    result["device_token"] = device_token
    return result


def migrate_file(existing_path, migration_path, output_path=None):
    existing_path = Path(existing_path)
    migration_path = Path(migration_path)
    destination = Path(output_path or existing_path)
    existing = json.loads(existing_path.read_text(encoding="utf-8-sig"))
    migration = json.loads(migration_path.read_text(encoding="utf-8-sig"))
    save_atomic(destination, merged_settings(existing, migration))
    return destination


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--existing", required=True)
    parser.add_argument("--configuration", required=True)
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    migrate_file(args.existing, args.configuration, args.output)
    print("Migration de l’identité Windows enregistrée sans rotation du secret appareil.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
