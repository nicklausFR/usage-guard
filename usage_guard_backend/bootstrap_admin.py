"""Create the first Usage Guard administrator directly on the server."""

from __future__ import annotations

import argparse
import getpass
from pathlib import Path

try:
    from usage_guard_backend.server import DB_PATH, Store
except ModuleNotFoundError:  # Direct execution from the deployed backend folder.
    from server import DB_PATH, Store


def create_initial_admin(database, username, password, email=""):
    store = Store(Path(database))
    if store.has_admin():
        raise ValueError(
            "Un administrateur existe déjà. Utilisez la PWA pour gérer les comptes."
        )
    return store.create_user(
        username, password, must_change=False, email=email,
        is_admin=True, role="admin",
    )


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Crée le premier administrateur Usage Guard dans la base SQLite "
            "du serveur. Le mot de passe est demandé sans être affiché."
        )
    )
    parser.add_argument("--database", type=Path, default=DB_PATH)
    parser.add_argument("--username", required=True)
    parser.add_argument("--email", default="")
    arguments = parser.parse_args(argv)
    password = getpass.getpass("Mot de passe : ")
    confirmation = getpass.getpass("Confirmer le mot de passe : ")
    if password != confirmation:
        parser.error("Les deux mots de passe sont différents.")
    try:
        user = create_initial_admin(
            arguments.database, arguments.username, password, arguments.email,
        )
    except ValueError as error:
        parser.error(str(error))
    finally:
        password = confirmation = None
    print(f"Administrateur créé : {user['username']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
