"""Initialize the protected loopback backend without persisting plaintext secrets."""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import socket
import uuid
from pathlib import Path

from tools.enroll_device import save_atomic
from usage_guard_backend.server import Store


def unprotect_secret(protected):
    if os.name != "nt":
        raise RuntimeError("Le déchiffrement DPAPI exige Windows.")
    import win32crypt

    encoded = base64.b64decode(str(protected or ""), validate=True)
    _description, plaintext = win32crypt.CryptUnprotectData(
        encoded, None, None, None, 0
    )
    return plaintext.decode("utf-8")


def initialize_local_backend(
    database_path, settings_path, configuration, secret_unprotector=unprotect_secret,
):
    database_path = Path(database_path)
    settings_path = Path(settings_path)
    configuration = dict(configuration or {})
    if database_path.exists() or settings_path.exists():
        raise RuntimeError(
            "Une configuration locale existe déjà ; elle doit être réparée, pas remplacée."
        )
    if str(configuration.get("installation_profile") or "") != "local":
        raise ValueError("Configuration d’installation locale invalide.")
    administrator = dict(configuration.get("administrator") or {})
    admin_username = str(administrator.get("username") or "").strip()
    password = secret_unprotector(administrator.get("protected_password"))
    users = list(configuration.get("users") or [])
    identities = list(configuration.get("windows_identities") or [])
    if not users or not identities:
        raise ValueError("Associez au moins un utilisateur à une session Windows.")
    if admin_username.casefold() in {
        str(item.get("username") or "").strip().casefold() for item in users
    }:
        raise ValueError(
            "Le compte administrateur Usage Guard doit être distinct des sessions sans mot de passe."
        )

    database_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_database = database_path.with_name(
        f".{database_path.name}.{uuid.uuid4().hex}.tmp"
    )
    device_id = str(uuid.uuid4())
    device_token = secrets.token_urlsafe(48)
    display_name = str(
        configuration.get("display_name") or socket.gethostname()
    ).strip()
    store = None
    try:
        store = Store(temporary_database)
        store.create_user(
            admin_username, password, must_change=False,
            email=str(administrator.get("email") or ""),
            is_admin=True, role="admin",
        )
        password = None
        store.register_device(
            device_id, display_name, token=device_token,
            hostname=socket.gethostname(),
        )
        for source in users:
            source = dict(source or {})
            role = str(source.get("role") or "limited").strip().lower()
            if role != "limited":
                raise ValueError(
                    "Seul un utilisateur à limiter peut être associé à Windows."
                )
            store.create_user(
                source.get("username"), secrets.token_urlsafe(48),
                must_change=False, email="", role=role,
                permissions=dict(source.get("permissions") or {}),
                device_ids=[device_id],
            )
        store.set_device_windows_identities(
            device_id, identities, admin_username,
        )
        store.initialize_device_notification_policy(device_id)
        with store.connect() as db:
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")

        settings = {
            "installation_profile": "local",
            "enabled": True,
            "base_url": "http://127.0.0.1:8767/usage-guard",
            "device_id": device_id,
            "device_token": device_token,
            "poll_seconds": 15,
            "display_name": display_name,
            "windows_identities": store.device_windows_identities(device_id),
        }
        os.replace(temporary_database, database_path)
        save_atomic(settings_path, settings)
        return settings
    finally:
        password = None
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(temporary_database) + suffix)
            try:
                if candidate.exists():
                    candidate.unlink()
            except OSError:
                pass


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--configuration", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    configuration = json.loads(args.configuration.read_text(encoding="utf-8"))
    initialize_local_backend(args.database, args.output, configuration)
    print("Backend SQLite local initialisé sans mot de passe Windows.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
