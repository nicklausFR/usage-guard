"""Interactive, authenticated enrollment wizard for a Windows client."""

from __future__ import annotations

import argparse
import base64
import getpass
import http.cookiejar
import json
import os
import socket
import sys
import tempfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPCookieProcessor, Request, build_opener

from i18n import _


DEFAULT_BASE_URL = ""
INSTALLATION_PROFILES = ("local", "server")


def protect_secret(secret):
    """Protect a temporary Usage Guard secret with the installing Windows user."""
    if os.name != "nt":
        raise RuntimeError(_("La protection DPAPI exige Windows."))
    import win32crypt

    protected = win32crypt.CryptProtectData(
        str(secret or "").encode("utf-8"),
        "Usage Guard local setup", None, None, None, 0,
    )
    blob = protected[1] if isinstance(protected, tuple) else protected
    return base64.b64encode(blob).decode("ascii")


def windows_identity_mapping(account, usage_guard_username):
    account = dict(account or {})
    sid = str(account.get("windows_sid") or "").strip().upper()
    windows_username = str(account.get("windows_username") or "").strip()
    usage_guard_username = str(usage_guard_username or "").strip()
    if not sid.startswith("S-1-") or not windows_username:
        raise ValueError(_("Compte Windows existant invalide."))
    if not usage_guard_username:
        raise ValueError(_("Utilisateur Usage Guard manquant."))
    return {
        "windows_sid": sid,
        "windows_domain": str(account.get("windows_domain") or "").strip(),
        "windows_username": windows_username,
        "is_windows_admin": bool(account.get("is_windows_admin", False)),
        "usage_guard_username": usage_guard_username,
    }


def validate_windows_identity_mappings(mappings):
    normalized = [
        windows_identity_mapping(item, item.get("usage_guard_username"))
        for item in mappings or []
    ]
    if not normalized:
        raise ValueError(_("Associez au moins un compte Windows existant."))
    sids = [item["windows_sid"].casefold() for item in normalized]
    users = [item["usage_guard_username"].casefold() for item in normalized]
    if len(sids) != len(set(sids)):
        raise ValueError(_("Un compte Windows est associé plusieurs fois."))
    if len(users) != len(set(users)):
        raise ValueError(_("Un utilisateur Usage Guard est associé plusieurs fois."))
    return normalized


def prompt(label, default=""):
    suffix = f" [{default}]" if default else ""
    print(f"{label}{suffix} : ", end="", flush=True)
    value = sys.stdin.readline()
    if value == "":
        raise RuntimeError(_("Saisie interrompue."))
    return value.strip() or default


def choose(label, values):
    if not values:
        raise RuntimeError(_("Aucun choix disponible."))
    print(label)
    for index, description in enumerate(values, 1):
        print(f"  {index}. {description}")
    while True:
        raw = prompt(_("Choix"))
        if raw.isdigit() and 1 <= int(raw) <= len(values):
            return int(raw) - 1
        print(_("Choix invalide."))


class AdminApi:
    def __init__(self, base_url):
        self.base_url = str(base_url or "").strip().rstrip("/")
        parsed = urlparse(self.base_url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
            raise ValueError(_("L’adresse du serveur doit être une URL HTTPS sans paramètres."))
        self.origin = f"{parsed.scheme}://{parsed.netloc}"
        jar = http.cookiejar.CookieJar()
        self.opener = build_opener(HTTPCookieProcessor(jar))
        self.csrf_token = ""

    def request(self, path, payload=None, method=None):
        data = None
        headers = {"Accept": "application/json", "Origin": self.origin}
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.csrf_token and (method or "GET").upper() != "GET":
            headers["X-CSRF-Token"] = self.csrf_token
        request = Request(
            self.base_url + path, data=data, headers=headers,
            method=method or ("POST" if payload is not None else "GET"),
        )
        try:
            with self.opener.open(request, timeout=20) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            try:
                detail = json.loads(error.read().decode("utf-8")).get("error")
            except Exception:
                detail = None
            raise RuntimeError(detail or _("Erreur serveur HTTP {code}.").format(code=error.code)) from error
        except URLError as error:
            raise RuntimeError(_("Serveur inaccessible : {reason}").format(reason=error.reason)) from error

    def login(self, username, password):
        result = self.request(
            "/api/v1/auth/login",
            {"username": username, "password": password},
            "POST",
        )
        self.csrf_token = str(result.get("csrf_token") or "")
        if not result.get("is_admin"):
            raise RuntimeError(_("Ce compte n’est pas administrateur."))
        if result.get("must_change"):
            raise RuntimeError(
                _("Le mot de passe doit d’abord être changé dans la PWA distante.")
            )
        return result

    def logout(self):
        if not self.csrf_token:
            return
        try:
            self.request("/api/v1/auth/logout", {}, "POST")
        except RuntimeError:
            pass
        self.csrf_token = ""


def atomic_json(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            json.dump(payload, stream, ensure_ascii=False)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def run_wizard(default_base_url=DEFAULT_BASE_URL):
    print(_("\nConfiguration sécurisée de Usage Guard"))
    base_url = prompt(_("Adresse du serveur"), default_base_url)
    username = prompt(_("Identifiant administrateur"))
    password = getpass.getpass(_("Mot de passe administrateur : "), stream=sys.stdout)
    if not password:
        raise RuntimeError(_("Le mot de passe est requis."))
    api = AdminApi(base_url)
    try:
        api.login(username, password)
        # Remove the last plaintext reference as early as possible. Python cannot
        # guarantee memory erasure, but it is never persisted or passed to a child.
        password = None
        inventory = api.request("/api/v1/admin/users")
        limited_users = [
            user for user in inventory.get("users", [])
            if str(user.get("role") or "") == "limited"
        ]
        if not limited_users:
            raise RuntimeError(
                _("Aucun utilisateur à limiter n’existe. Créez-le d’abord dans la PWA.")
            )
        user_index = choose(
            _("Utilisateur dont les limites s’appliqueront sur ce PC :"),
            [str(user.get("username") or "") for user in limited_users],
        )
        limited_username = str(limited_users[user_index]["username"])

        devices = [
            device for device in inventory.get("devices", [])
            if not device.get("revoked_at")
        ]
        device_choices = [_("Nouvel ordinateur")] + [
            _("Réinstaller {name}").format(
                name=str(device.get("label") or device.get("device_id"))
            )
            for device in devices
        ]
        device_index = choose(_("Type d’installation :"), device_choices)
        selected = devices[device_index - 1] if device_index else None

        hostname = socket.gethostname()
        existing_name = str(selected.get("label") or "") if selected else ""
        display_name = prompt(_("Nom visible de l’ordinateur"), existing_name or hostname)
        if not display_name or len(display_name) > 80:
            raise RuntimeError(_("Le nom visible doit contenir entre 1 et 80 caractères."))

        result = api.request(
            "/api/v1/admin/device-enrollments",
            {
                "device_id": str(selected.get("device_id") or "") if selected else "",
                "username": limited_username,
                "display_name": display_name,
            },
            "POST",
        )
        enrollment = result.get("enrollment") or {}
        code = str(enrollment.get("code") or "")
        if len(code) < 16:
            raise RuntimeError(_("Le serveur n’a pas fourni de code d’enrôlement valide."))
        return {
            "base_url": api.base_url,
            "enrollment_code": code,
            "display_name": display_name,
            "device_id": str(enrollment.get("device_id") or ""),
            "limited_username": limited_username,
        }
    finally:
        password = None
        api.logout()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--default-base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run_wizard(args.default_base_url)
        atomic_json(args.output, result)
    except (OSError, RuntimeError, ValueError) as error:
        print(_("\nInstallation annulée : {error}").format(error=error))
        return 1
    print(_("\nEnrôlement autorisé. Installation locale en cours…"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
