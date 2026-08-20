"""Usage Guard remote backend: stdlib-only, loopback-only and session-authenticated."""
import base64
import copy
import hashlib
import hmac
import ipaddress
import json
import mimetypes
import os
import re
import secrets
import smtplib
import ssl
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import parseaddr
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse


ROOT = Path(__file__).resolve().parent
PWA_DIR = ROOT / "pwa"
HOST = os.environ.get("USAGE_GUARD_BACKEND_HOST", "127.0.0.1")
PORT = int(os.environ.get("USAGE_GUARD_BACKEND_PORT", "8767"))
PREFIX = "/" + os.environ.get("USAGE_GUARD_BACKEND_PREFIX", "usage-guard").strip("/")
DB_PATH = Path(os.environ.get("USAGE_GUARD_BACKEND_DB", ROOT / "data" / "backend.sqlite3"))
DEVICE_ID = os.environ.get("USAGE_GUARD_DEVICE_ID", "").strip()
DEVICE_TOKEN = os.environ.get("USAGE_GUARD_DEVICE_TOKEN", "").strip()
PUBLIC_ORIGIN = os.environ.get("USAGE_GUARD_PUBLIC_ORIGIN", "").rstrip("/")
MAX_BODY = 8 * 1024 * 1024
SESSION_SECONDS = 12 * 60 * 60
PASSWORD_MIN_LENGTH = 10
COMMAND_RETRY_SECONDS = 90
ACKED_LIMIT_RETRY_SECONDS = 10 * 60
PENDING_LIMIT_VISIBLE_SECONDS = 10 * 60
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$")
ALLOWED_ACTIONS = {
    "rename_target", "set_category", "make_root", "exclude_target",
    "unexclude_target", "delete_target", "merge_target", "rename_category",
    "move_category", "reorder_category", "clear_category", "make_category_root",
    "set_category_for_keys", "rename_browser", "make_browser_root",
    "clear_browser_category", "clear_site_category", "rename_site_category",
    "exclude_passive", "make_site_specific", "categorize_site", "exclude_site",
    "delete_site", "set_limit", "remove_limit", "reset_limit", "set_language",
    "set_notification_rule", "remove_notification_rule", "set_notification_warning",
    "set_default_limit_warning",
    "set_computer_block", "set_computer_block_enabled", "clear_computer_block",
}
PERMISSION_KEYS = (
    "view_activity", "view_analysis", "view_limits", "view_notifications",
    "manage_activity", "manage_limits", "manage_notifications",
)
DEFAULT_PERMISSIONS = {
    "view_activity": True, "view_analysis": True, "view_limits": True,
    "view_notifications": True,
    "manage_activity": False, "manage_limits": False, "manage_notifications": False,
}
LIMIT_ACTIONS = {"set_limit", "remove_limit", "reset_limit", "set_computer_block", "set_computer_block_enabled", "clear_computer_block"}
REFLECTED_RETRY_ACTIONS = {"set_limit", "remove_limit", "set_computer_block", "set_computer_block_enabled", "clear_computer_block"}
NOTIFICATION_ACTIONS = {
    "set_notification_rule", "remove_notification_rule", "set_notification_warning",
    "set_default_limit_warning",
}
EMAIL_SECURITY_MODES = {"starttls", "ssl", "none"}
DEFAULT_EMAIL_SETTINGS = {
    "enabled": False,
    "smtp_host": "",
    "smtp_port": 587,
    "security": "starttls",
    "username": "",
    "password": "",
    "sender": "",
    "recipient": "",
}
EMAIL_RATE_LIMIT = 30
EMAIL_RATE_WINDOW_SECONDS = 10 * 60
CLIENT_OFFLINE_SECONDS = 60


class DocumentConflict(ValueError):
    pass


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def json_hash(value):
    raw = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def analysis_snapshot_from_activity(activity, fallback=None):
    fallback = dict(fallback or {})
    activity = activity if isinstance(activity, dict) else {}
    days = activity.get("days") if isinstance(activity.get("days"), dict) else {}
    targets = activity.get("targets") if isinstance(activity.get("targets"), dict) else {}
    category_parents = activity.get("category_parents") if isinstance(activity.get("category_parents"), dict) else {}
    site_categories = list(activity.get("site_categories") or [])
    category_order = list(activity.get("category_order") or [])
    totals = {}
    daily_stats = []
    categories = set(category_parents) | set(category_parents.values())
    for metadata in targets.values():
        if not isinstance(metadata, dict):
            continue
        for field in ("category", "site_category", "category_scope"):
            value = str(metadata.get(field, "")).strip()
            if value and value != "__root__":
                categories.add(value)
    for day_key in sorted(days):
        values = days.get(day_key)
        if not isinstance(values, dict):
            continue
        usage = []
        for key, seconds in sorted(values.items(), key=lambda item: float(item[1] or 0), reverse=True):
            key = str(key)
            metadata = targets.get(key, {}) if isinstance(targets.get(key), dict) else {}
            entry = {
                "key": key,
                "label": str(metadata.get("label") or key),
                "category": str(metadata.get("category") or ""),
                "site_category": str(metadata.get("site_category") or ""),
                "category_scope": str(metadata.get("category_scope") or ""),
                "seconds": round(float(seconds or 0), 1),
                "web": key.startswith("site:"),
                "multimedia": False,
            }
            usage.append(entry)
            totals[key] = totals.get(key, 0.0) + entry["seconds"]
            for field in ("category", "site_category"):
                value = entry[field]
                if value and value != "__root__":
                    categories.add(value)
        daily_stats.append({
            "date": str(day_key),
            "usage": usage,
            "active": round(sum(item["seconds"] for item in usage), 1),
            "passive": [],
            "system": (activity.get("system_days") or {}).get(day_key, {}),
            "other_sites": [],
        })
    usage = []
    for key, seconds in sorted(totals.items(), key=lambda item: item[1], reverse=True):
        metadata = targets.get(key, {}) if isinstance(targets.get(key), dict) else {}
        usage.append({
            "key": key,
            "label": str(metadata.get("label") or key),
            "category": str(metadata.get("category") or ""),
            "site_category": str(metadata.get("site_category") or ""),
            "category_scope": str(metadata.get("category_scope") or ""),
            "seconds": round(seconds, 1),
            "web": str(key).startswith("site:"),
            "multimedia": False,
        })
    ordered_categories = [
        category for category in category_order
        if category and category != "__root__" and category in categories
    ]
    ordered_categories.extend(
        sorted(category for category in categories if category and category != "__root__" and category not in ordered_categories)
    )
    top_level = [
        category for category in ordered_categories
        if not category_parents.get(category)
    ]
    start = daily_stats[0]["date"] if daily_stats else fallback.get("date", utc_now()[:10])
    end = daily_stats[-1]["date"] if daily_stats else fallback.get("date", utc_now()[:10])
    return {
        **fallback,
        "scope": "all",
        "usage": usage,
        "passive": [],
        "daily_stats": daily_stats,
        "categories": ordered_categories,
        "top_level_categories": top_level,
        "category_parents": category_parents,
        "category_order": category_order,
        "site_categories": site_categories,
        "merge_candidates": [
            {
                "key": str(key),
                "label": str(metadata.get("label") or key) if isinstance(metadata, dict) else str(key),
                "category": str(metadata.get("category") or "") if isinstance(metadata, dict) else "",
                "site_category": str(metadata.get("site_category") or "") if isinstance(metadata, dict) else "",
                "category_scope": str(metadata.get("category_scope") or "") if isinstance(metadata, dict) else "",
            }
            for key, metadata in targets.items()
        ],
        "timeline": {"start": start, "end": end},
    }


def analysis_snapshot_usable(snapshot):
    if not isinstance(snapshot, dict):
        return False
    daily_stats = snapshot.get("daily_stats")
    if isinstance(daily_stats, list):
        for day in daily_stats:
            if isinstance(day, dict) and (
                day.get("usage") or day.get("passive") or day.get("active")
            ):
                return True
    usage = snapshot.get("usage")
    if isinstance(usage, list) and usage:
        return True
    return False


def apply_json_delta(base, delta):
    if not isinstance(delta, dict):
        raise ValueError("Delta JSON invalide")
    kind = delta.get("kind")

    if kind == "value":
        return delta.get("value")

    if kind == "dict":
        if not isinstance(base, dict):
            raise ValueError("Delta dictionnaire incompatible")
        result = dict(base)
        remove = delta.get("remove", [])
        set_values = delta.get("set", {})
        patch = delta.get("patch", {})
        if not isinstance(remove, list) or not isinstance(set_values, dict) or not isinstance(patch, dict):
            raise ValueError("Delta dictionnaire invalide")
        for key in remove:
            result.pop(str(key), None)
        result.update(set_values)
        for key, child in patch.items():
            if key not in result:
                raise ValueError("Delta dictionnaire sans base")
            result[key] = apply_json_delta(result[key], child)
        return result

    if kind == "list":
        if not isinstance(base, list):
            raise ValueError("Delta liste incompatible")
        start, stop, items = delta.get("start"), delta.get("stop"), delta.get("items")
        if (
            not isinstance(start, int)
            or not isinstance(stop, int)
            or not isinstance(items, list)
            or start < 0
            or stop < start
            or stop > len(base)
        ):
            raise ValueError("Delta liste invalide")
        return base[:start] + items + base[stop:]

    raise ValueError("Type de delta JSON inconnu")


def password_digest(password, salt):
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2 ** 14, r=8, p=1, dklen=32
    )


def validate_username(username):
    username = str(username or "").strip()
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("L’identifiant doit contenir 3 à 32 lettres, chiffres, points, tirets ou underscores.")
    return username


def validate_password(password):
    password = str(password or "")
    if len(password) < PASSWORD_MIN_LENGTH:
        raise ValueError(f"Le mot de passe doit contenir au moins {PASSWORD_MIN_LENGTH} caractères.")
    if len(password) > 256:
        raise ValueError("Le mot de passe est trop long.")
    return password


class LoginLimiter:
    def __init__(self, attempts=5, window=600, block=900):
        self.attempts, self.window, self.block = attempts, window, block
        self.failures, self.blocked_until = {}, {}
        self.lock = threading.Lock()

    def allowed(self, key):
        with self.lock:
            return self.blocked_until.get(key, 0) <= time.monotonic()

    def failed(self, key):
        now = time.monotonic()
        with self.lock:
            recent = [stamp for stamp in self.failures.get(key, []) if now - stamp <= self.window]
            recent.append(now)
            self.failures[key] = recent
            if len(recent) >= self.attempts:
                self.blocked_until[key] = now + self.block

    def succeeded(self, key):
        with self.lock:
            self.failures.pop(key, None)
            self.blocked_until.pop(key, None)


class EmailLimiter:
    def __init__(self, limit=EMAIL_RATE_LIMIT, window=EMAIL_RATE_WINDOW_SECONDS):
        self.limit, self.window = limit, window
        self.sent = {}
        self.lock = threading.Lock()

    def allow(self, recipient):
        now = time.monotonic()
        key = str(recipient or "").casefold()
        with self.lock:
            recent = [value for value in self.sent.get(key, []) if now - value < self.window]
            if len(recent) >= self.limit:
                self.sent[key] = recent
                return False
            recent.append(now)
            self.sent[key] = recent
            return True

class Store:
    def __init__(self, path=DB_PATH, email_encryption_key=None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._email_encryption_key = None
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                PRAGMA foreign_keys=ON;
                CREATE TABLE IF NOT EXISTS snapshots (
                    device_id TEXT PRIMARY KEY, payload TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS activity_stores (
                    device_id TEXT PRIMARY KEY, payload TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL,
                    payload TEXT NOT NULL, created_at TEXT NOT NULL,
                    delivered_at TEXT, acknowledged_at TEXT, result TEXT
                );
                CREATE INDEX IF NOT EXISTS commands_pending
                    ON commands(device_id, acknowledged_at, id);
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY COLLATE NOCASE,
                    salt BLOB NOT NULL, password_hash BLOB NOT NULL,
                    must_change INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    is_admin INTEGER NOT NULL DEFAULT 0,
                    permissions TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY, username TEXT NOT NULL COLLATE NOCASE,
                    csrf_token TEXT NOT NULL, expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
                CREATE TABLE IF NOT EXISTS email_settings (
                    id INTEGER PRIMARY KEY CHECK(id=1),
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS device_presence (
                    device_id TEXT PRIMARY KEY,
                    last_seen TEXT NOT NULL,
                    online INTEGER NOT NULL DEFAULT 0
                );
            """)
            columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
            if "is_admin" not in columns:
                db.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
            if "permissions" not in columns:
                db.execute("ALTER TABLE users ADD COLUMN permissions TEXT NOT NULL DEFAULT '{}'")
            email_columns = {row["name"] for row in db.execute("PRAGMA table_info(email_settings)")}
            if email_columns and "payload" not in email_columns:
                db.execute("DROP TABLE email_settings")
                db.execute(
                    "CREATE TABLE email_settings (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL, updated_at TEXT NOT NULL)"
                )
            if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] and not db.execute(
                "SELECT 1 FROM users WHERE is_admin=1 LIMIT 1"
            ).fetchone():
                db.execute(
                    "UPDATE users SET is_admin=1 WHERE username=(SELECT username FROM users ORDER BY created_at,username LIMIT 1)"
                )
        if email_encryption_key:
            self.configure_email_encryption_key(email_encryption_key)
        self.purge_stale_commands()

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            yield db
            db.commit()
        finally:
            db.close()

    def _save_document(self, table, device_id, document):
        payload = json.dumps(
            self._protect_document_recipients(document),
            ensure_ascii=False, separators=(",", ":"),
        )
        with self._lock, self.connect() as db:
            db.execute(
                f"INSERT INTO {table} VALUES(?,?,?) ON CONFLICT(device_id) DO UPDATE SET payload=excluded.payload, updated_at=excluded.updated_at",
                (device_id, payload, utc_now()),
            )

    def _load_document(self, table, device_id):
        with self.connect() as db:
            row = db.execute(
                f"SELECT payload,updated_at FROM {table} WHERE device_id=?",
                (device_id,),
            ).fetchone()
        if not row:
            return None, None
        return self._unprotect_document_recipients(
            json.loads(row["payload"])
        ), row["updated_at"]

    def _patch_document(self, table, device_id, delta, base_hash, target_hash):
        current, _ = self._load_document(table, device_id)
        if current is None:
            raise DocumentConflict("Document de base absent")
        if json_hash(current) != str(base_hash or ""):
            raise DocumentConflict("Document distant modifié")
        updated = apply_json_delta(current, delta)
        if json_hash(updated) != str(target_hash or ""):
            raise ValueError("Hash cible incohérent")
        self._save_document(table, device_id, updated)

    def save_snapshot(self, device_id, snapshot):
        self._save_document("snapshots", device_id, snapshot)

    def mark_device_seen(self, device_id):
        now = utc_now()
        with self._lock, self.connect() as db:
            row = db.execute(
                "SELECT online FROM device_presence WHERE device_id=?", (device_id,)
            ).fetchone()
            connected = row is None or not bool(row["online"])
            db.execute(
                """INSERT INTO device_presence(device_id,last_seen,online) VALUES(?,?,1)
                   ON CONFLICT(device_id) DO UPDATE SET last_seen=excluded.last_seen,online=1""",
                (device_id, now),
            )
        return connected

    def mark_device_offline_if_stale(self, device_id, stale_seconds=CLIENT_OFFLINE_SECONDS):
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=stale_seconds)).isoformat(timespec="seconds")
        with self._lock, self.connect() as db:
            cursor = db.execute(
                "UPDATE device_presence SET online=0 WHERE device_id=? AND online=1 AND last_seen<?",
                (device_id, cutoff),
            )
        return cursor.rowcount == 1

    def patch_snapshot(self, device_id, delta, base_hash, target_hash):
        self._patch_document("snapshots", device_id, delta, base_hash, target_hash)

    def snapshot(self, device_id):
        payload, updated_at = self._load_document("snapshots", device_id)
        return ({**payload, "backend_updated_at": updated_at} if payload else None)

    def save_activity_store(self, device_id, activity):
        self._save_document("activity_stores", device_id, activity)

    def patch_activity_store(self, device_id, delta, base_hash, target_hash):
        self._patch_document("activity_stores", device_id, delta, base_hash, target_hash)

    def activity_store(self, device_id):
        payload, updated_at = self._load_document("activity_stores", device_id)
        return ({"activity": payload, "updated_at": updated_at} if payload else None)

    @staticmethod
    def _valid_email_address(value, label):
        value = str(value or "").strip()
        address = parseaddr(value)[1]
        if value and (not address or "@" not in address or "\n" in value or "\r" in value):
            raise ValueError(f"{label} invalide.")
        return value

    def configure_email_encryption_key(self, secret):
        secret = str(secret or "").encode("utf-8")
        if len(secret) < 32:
            raise ValueError("Clé de chiffrement e-mail trop courte.")
        self._email_encryption_key = hashlib.sha256(
            b"usage-guard-email-settings\0" + secret
        ).digest()
        self._migrate_document_recipients()

    def _protect_document_recipients(self, document):
        protected = copy.deepcopy(document)

        def walk(value):
            if isinstance(value, dict):
                recipient = str(value.pop("email_recipient", "") or "").strip()
                if recipient:
                    value["email_recipient_protected"] = self._encrypt_email_settings({
                        "recipient": recipient,
                    })
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(protected)
        return protected

    def _unprotect_document_recipients(self, document):
        clear = copy.deepcopy(document)

        def walk(value):
            if isinstance(value, dict):
                protected = value.get("email_recipient_protected")
                if protected and not value.get("email_recipient"):
                    value["email_recipient"] = str(
                        self._decrypt_email_settings(protected).get("recipient", "")
                    )
                    value.pop("email_recipient_protected", None)
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(clear)
        return clear

    def _migrate_document_recipients(self):
        with self._lock, self.connect() as db:
            for table in ("snapshots", "activity_stores"):
                rows = db.execute(
                    f"SELECT device_id,payload FROM {table}"
                ).fetchall()
                for row in rows:
                    if '"email_recipient"' not in row["payload"]:
                        continue
                    protected = json.dumps(
                        self._protect_document_recipients(
                            json.loads(row["payload"])
                        ),
                        ensure_ascii=False, separators=(",", ":"),
                    )
                    db.execute(
                        f"UPDATE {table} SET payload=? WHERE device_id=?",
                        (protected, row["device_id"]),
                    )

    def _email_keys(self):
        if self._email_encryption_key is None:
            raise RuntimeError("Clé de chiffrement e-mail non configurée.")
        encryption = hmac.new(self._email_encryption_key, b"encryption", hashlib.sha256).digest()
        authentication = hmac.new(self._email_encryption_key, b"authentication", hashlib.sha256).digest()
        return encryption, authentication

    @staticmethod
    def _xor_email_payload(payload, key, nonce):
        output = bytearray(len(payload))
        offset = 0
        counter = 0
        while offset < len(payload):
            stream = hmac.new(
                key, nonce + counter.to_bytes(8, "big"), hashlib.sha256
            ).digest()
            chunk = min(len(stream), len(payload) - offset)
            for index in range(chunk):
                output[offset + index] = payload[offset + index] ^ stream[index]
            offset += chunk
            counter += 1
        return bytes(output)

    def _encrypt_email_settings(self, settings):
        encryption_key, authentication_key = self._email_keys()
        nonce = secrets.token_bytes(16)
        clear = json.dumps(
            settings, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        encrypted = self._xor_email_payload(clear, encryption_key, nonce)
        tag = hmac.new(authentication_key, nonce + encrypted, hashlib.sha256).digest()
        return "v1." + base64.urlsafe_b64encode(nonce + encrypted + tag).decode("ascii")

    def _decrypt_email_settings(self, payload):
        if not str(payload or "").startswith("v1."):
            raise ValueError("Configuration e-mail chiffrée invalide.")
        try:
            packed = base64.urlsafe_b64decode(str(payload)[3:].encode("ascii"))
        except (ValueError, UnicodeError) as error:
            raise ValueError("Configuration e-mail chiffrée invalide.") from error
        if len(packed) < 49:
            raise ValueError("Configuration e-mail chiffrée invalide.")
        nonce, encrypted, supplied_tag = packed[:16], packed[16:-32], packed[-32:]
        encryption_key, authentication_key = self._email_keys()
        expected_tag = hmac.new(authentication_key, nonce + encrypted, hashlib.sha256).digest()
        if not hmac.compare_digest(supplied_tag, expected_tag):
            raise ValueError("Configuration e-mail chiffrée illisible.")
        clear = self._xor_email_payload(encrypted, encryption_key, nonce)
        try:
            settings = json.loads(clear.decode("utf-8"))
        except (UnicodeError, ValueError) as error:
            raise ValueError("Configuration e-mail chiffrée invalide.") from error
        if not isinstance(settings, dict):
            raise ValueError("Configuration e-mail chiffrée invalide.")
        return settings

    def email_settings(self, include_password=False):
        with self.connect() as db:
            row = db.execute("SELECT payload,updated_at FROM email_settings WHERE id=1").fetchone()
        stored = self._decrypt_email_settings(row["payload"]) if row else {}
        settings = {**DEFAULT_EMAIL_SETTINGS, **stored}
        if row:
            settings["updated_at"] = row["updated_at"]
        settings["enabled"] = bool(settings["smtp_host"] and settings["sender"])
        password = str(settings.pop("password", ""))
        settings["password_configured"] = bool(password)
        if include_password:
            settings["password"] = password
        else:
            settings.pop("recipient", None)
        settings.pop("id", None)
        return settings

    def save_email_settings(self, payload):
        payload = dict(payload or {})
        current = self.email_settings(include_password=True)
        try:
            port = int(payload.get("smtp_port", current["smtp_port"]))
        except (TypeError, ValueError) as error:
            raise ValueError("Port SMTP invalide.") from error
        if not 1 <= port <= 65535:
            raise ValueError("Port SMTP invalide.")
        security = str(payload.get("security", current["security"])).strip().lower()
        if security not in EMAIL_SECURITY_MODES:
            raise ValueError("Sécurité SMTP invalide.")
        host = str(payload.get("smtp_host", current["smtp_host"])).strip()
        username = str(payload.get("username", current["username"])).strip()
        password = current.get("password", "")
        if payload.get("clear_password"):
            password = ""
        elif payload.get("password"):
            password = str(payload["password"])
        sender = self._valid_email_address(payload.get("sender", current["sender"]), "Adresse d’expédition")
        recipient = self._valid_email_address(payload.get("recipient", current["recipient"]), "Adresse de destination")
        enabled = bool(host and sender)
        if len(host) > 255 or len(username) > 320 or len(password) > 1024:
            raise ValueError("Paramètre SMTP trop long.")
        now = utc_now()
        encrypted = self._encrypt_email_settings({
            "enabled": enabled,
            "smtp_host": host,
            "smtp_port": port,
            "security": security,
            "username": username,
            "password": password,
            "sender": sender,
            "recipient": recipient,
        })
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO email_settings(id,payload,updated_at) VALUES(1,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                       payload=excluded.payload,updated_at=excluded.updated_at""",
                (encrypted, now),
            )
        return self.email_settings()

    def send_email_notification(self, title, message, recipient, force=False):
        settings = self.email_settings(include_password=True)
        if not settings["enabled"] and not force:
            return {"ok": True, "skipped": True, "reason": "disabled"}
        recipient = self._valid_email_address(recipient, "Adresse de destination")
        if not settings["smtp_host"] or not settings["sender"] or not recipient:
            raise ValueError("Configuration e-mail incomplète.")
        mail = EmailMessage()
        clean_title = str(title or "Notification").replace("\r", " ").replace("\n", " ").strip()[:200]
        clean_message = str(message or "")[:20000]
        mail["Subject"] = f"Usage Guard · {clean_title}"
        mail["From"] = settings["sender"]
        mail["To"] = recipient
        mail.set_content(clean_message)
        tls_context = ssl.create_default_context()
        smtp_class = smtplib.SMTP_SSL if settings["security"] == "ssl" else smtplib.SMTP
        options = {"timeout": 15}
        if settings["security"] == "ssl":
            options["context"] = tls_context
        with smtp_class(settings["smtp_host"], settings["smtp_port"], **options) as smtp:
            if settings["security"] == "starttls":
                smtp.starttls(context=tls_context)
            if settings["username"]:
                smtp.login(settings["username"], settings["password"])
            smtp.send_message(mail)
        return {"ok": True, "recipient": recipient}

    def queue(self, device_id, command):
        payload = json.dumps(command, ensure_ascii=False, separators=(",", ":"))
        with self._lock, self.connect() as db:
            cursor = db.execute("INSERT INTO commands(device_id,payload,created_at) VALUES(?,?,?)", (device_id, payload, utc_now()))
            return cursor.lastrowid

    def purge_stale_commands(self):
        acknowledged_cutoff = (datetime.now(timezone.utc) - timedelta(seconds=ACKED_LIMIT_RETRY_SECONDS)).isoformat(timespec="seconds")
        delivered_cutoff = (datetime.now(timezone.utc) - timedelta(seconds=PENDING_LIMIT_VISIBLE_SECONDS)).isoformat(timespec="seconds")
        with self._lock, self.connect() as db:
            db.execute(
                "DELETE FROM commands WHERE acknowledged_at IS NOT NULL AND (acknowledged_at < ? OR created_at < ?)",
                (acknowledged_cutoff, acknowledged_cutoff),
            )
            db.execute(
                "DELETE FROM commands WHERE acknowledged_at IS NULL AND delivered_at IS NOT NULL AND (delivered_at < ? OR created_at < ?)",
                (delivered_cutoff, delivered_cutoff),
            )

    def pending(self, device_id):
        snapshot = self.snapshot(device_id) or {}
        snapshot_updated_at = str(snapshot.get("backend_updated_at") or "")
        retry_cutoff = (datetime.now(timezone.utc) - timedelta(seconds=COMMAND_RETRY_SECONDS)).isoformat(timespec="seconds")
        acked_retry_cutoff = (datetime.now(timezone.utc) - timedelta(seconds=ACKED_LIMIT_RETRY_SECONDS)).isoformat(timespec="seconds")
        with self._lock, self.connect() as db:
            rows = db.execute(
                "SELECT id,payload,created_at,delivered_at,acknowledged_at,result FROM commands WHERE device_id=? ORDER BY id LIMIT 1000",
                (device_id,),
            ).fetchall()
            superseded = self._superseded_limit_command_ids(rows)
            obsolete_ids = set(superseded)
            deliver = []
            for row in rows:
                if row["id"] in superseded:
                    continue
                command = json.loads(row["payload"])
                action = command.get("action")
                acknowledged = bool(row["acknowledged_at"])
                if acknowledged and action not in REFLECTED_RETRY_ACTIONS:
                    continue
                result = json.loads(row["result"]) if row["result"] else None
                delivered_at = str(row["delivered_at"] or "")
                if (acknowledged or delivered_at) and self._limit_command_effect_present(snapshot, command, result):
                    obsolete_ids.add(row["id"])
                    continue
                if acknowledged and isinstance(result, dict) and result.get("ok") and (
                    str(row["acknowledged_at"] or "") < acked_retry_cutoff
                    or str(row["created_at"] or "") < acked_retry_cutoff
                ):
                    obsolete_ids.add(row["id"])
                    continue
                if delivered_at:
                    if action not in LIMIT_ACTIONS:
                        continue
                    if delivered_at < acked_retry_cutoff:
                        obsolete_ids.add(row["id"])
                        continue
                    if snapshot_updated_at and delivered_at <= snapshot_updated_at and delivered_at > retry_cutoff:
                        continue
                    if delivered_at > retry_cutoff:
                        continue
                deliver.append((row, command))
                if len(deliver) >= 100:
                    break
            if obsolete_ids:
                db.executemany("DELETE FROM commands WHERE id=?", [(command_id,) for command_id in obsolete_ids])
            if deliver:
                db.executemany("UPDATE commands SET delivered_at=? WHERE id=?", [(utc_now(), row["id"]) for row, _ in deliver])
        return [{"id": str(row["id"]), **command} for row, command in deliver]

    def acknowledge(self, device_id, command_id, result):
        payload = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
        with self._lock, self.connect() as db:
            cursor = db.execute(
                "UPDATE commands SET acknowledged_at=?,result=? WHERE id=? AND device_id=?",
                (utc_now(), payload, command_id, device_id),
            )
            return cursor.rowcount == 1

    def pending_limit_commands(self, device_id, snapshot):
        snapshot = snapshot or {}
        visible_cutoff = (datetime.now(timezone.utc) - timedelta(seconds=PENDING_LIMIT_VISIBLE_SECONDS)).isoformat(timespec="seconds")
        with self._lock, self.connect() as db:
            rows = db.execute(
                "SELECT id,payload,created_at,delivered_at,acknowledged_at,result FROM commands WHERE device_id=? ORDER BY id DESC LIMIT 200",
                (device_id,),
            ).fetchall()
            superseded = self._superseded_limit_command_ids(rows)
            obsolete_ids = set(superseded)
            commands = []
            for row in reversed(rows):
                if row["id"] in superseded:
                    continue
                command = json.loads(row["payload"])
                if command.get("action") not in LIMIT_ACTIONS:
                    continue
                if row["acknowledged_at"] and command.get("action") not in {"set_limit", "set_computer_block"}:
                    obsolete_ids.add(row["id"])
                    continue
                result = json.loads(row["result"]) if row["result"] else None
                completed_or_taken = bool(row["acknowledged_at"] or row["delivered_at"])
                if completed_or_taken and self._limit_command_effect_present(snapshot, command, result):
                    obsolete_ids.add(row["id"])
                    continue
                if row["acknowledged_at"] and isinstance(result, dict) and result.get("ok") and (
                    str(row["acknowledged_at"]) < visible_cutoff
                    or str(row["created_at"] or "") < visible_cutoff
                ):
                    obsolete_ids.add(row["id"])
                    continue
                if row["delivered_at"] and not row["acknowledged_at"] and str(row["delivered_at"]) < visible_cutoff:
                    obsolete_ids.add(row["id"])
                    continue
                commands.append({
                    "id": str(row["id"]),
                    "created_at": row["created_at"],
                    "delivered": bool(row["delivered_at"]),
                    "acknowledged": bool(row["acknowledged_at"]),
                    "result": result,
                    **command,
                })
            if obsolete_ids:
                db.executemany("DELETE FROM commands WHERE id=?", [(command_id,) for command_id in obsolete_ids])
        return commands

    @classmethod
    def _superseded_limit_command_ids(cls, rows):
        seen = set()
        superseded = set()
        for row in sorted(rows, key=lambda item: int(item["id"]), reverse=True):
            command = json.loads(row["payload"])
            keys = cls._command_supersede_keys(command)
            if not keys:
                continue
            if any(key in seen for key in keys):
                superseded.add(row["id"])
            else:
                seen.update(keys)
        return superseded

    @staticmethod
    def _command_supersede_keys(command):
        action = command.get("action")
        target_key = str(command.get("target_key", ""))
        if action == "set_limit":
            settings = command.get("settings") if isinstance(command.get("settings"), dict) else {}
            measured = str(settings.get("target_key") or target_key)
            keys = {("limit", value) for value in (target_key, measured) if value}
            return keys
        if action in {"remove_limit", "reset_limit"}:
            return {("limit", target_key)} if target_key else set()
        if action in {"set_computer_block", "set_computer_block_enabled", "clear_computer_block"}:
            return {("computer_block", "computer:all")}
        return set()

    _command_supersede_key = _command_supersede_keys

    @classmethod
    def _limit_command_effect_present(cls, snapshot, command, result=None):
        if cls._limit_command_reflected(snapshot, command, result):
            return True
        action = command.get("action")
        target_key = str(command.get("target_key", ""))
        if action == "set_limit":
            settings = command.get("settings") if isinstance(command.get("settings"), dict) else {}
            measured = str(settings.get("target_key") or target_key)
            expected = {value for value in (target_key, measured) if value}
            if isinstance(result, dict) and isinstance(result.get("limit"), dict):
                expected.update(
                    str(result["limit"].get(field) or "")
                    for field in ("key", "target_key")
                )
            expected.discard("")
            return any(
                str(item.get("key") or "") in expected
                or str(item.get("target_key") or "") in expected
                for item in snapshot.get("limits", [])
            )
        if action == "set_computer_block":
            return bool(snapshot.get("computer_block", {}).get("mode"))
        return False

    @staticmethod
    def _limit_command_reflected(snapshot, command, result=None):
        action = command.get("action")
        target_key = str(command.get("target_key", ""))
        if action == "set_limit":
            settings = command.get("settings") if isinstance(command.get("settings"), dict) else {}
            measured = str(settings.get("target_key") or target_key)
            if settings.get("create_new"):
                created_key = ""
                if isinstance(result, dict) and isinstance(result.get("limit"), dict):
                    created_key = str(result["limit"].get("key") or result["limit"].get("target_key") or "")
                if not created_key:
                    return False
                return any(
                    str(item.get("key") or item.get("target_key")) == created_key
                    for item in snapshot.get("limits", [])
                )
            return any(
                str(item.get("key") or item.get("target_key")) == target_key
                or str(item.get("target_key")) == measured
                for item in snapshot.get("limits", [])
            )
        if action == "set_computer_block":
            if not isinstance(result, dict) or not isinstance(result.get("computer_block"), dict):
                return False
            expected = result["computer_block"]
            current = snapshot.get("computer_block", {})
            if not current.get("mode"):
                return False
            return all(
                str(current.get(key, "")) == str(expected.get(key, ""))
                for key in ("mode", "started_at", "ends_at")
            )
        if action == "set_computer_block_enabled":
            if not isinstance(result, dict) or not isinstance(result.get("computer_block"), dict):
                return False
            current = snapshot.get("computer_block", {})
            return bool(current.get("mode")) and bool(current.get("enabled", True)) == bool(result["computer_block"].get("enabled", True))
        if action == "remove_limit":
            return not any(
                str(item.get("key") or item.get("target_key")) == target_key
                for item in snapshot.get("limits", [])
            )
        if action == "clear_computer_block":
            return not bool(snapshot.get("computer_block", {}).get("mode"))
        return False

    def list_users(self):
        with self.connect() as db:
            rows = db.execute(
                "SELECT username,must_change,created_at,updated_at,is_admin,permissions FROM users ORDER BY username COLLATE NOCASE"
            ).fetchall()
        return [self.public_user(row) for row in rows]

    @staticmethod
    def public_user(row):
        source = dict(row)
        try: saved = json.loads(source.get("permissions", "{}"))
        except (TypeError, ValueError): saved = {}
        is_admin = bool(source.get("is_admin"))
        result = {
            key: source[key] for key in ("username", "created_at", "updated_at")
            if key in source
        }
        result["must_change"] = bool(source.get("must_change"))
        result["is_admin"] = is_admin
        result["permissions"] = {
            key: True if is_admin else bool(saved.get(key, DEFAULT_PERMISSIONS[key]))
            for key in PERMISSION_KEYS
        }
        return result

    def create_user(self, username, password, must_change=True):
        username, password = validate_username(username), validate_password(password)
        salt = secrets.token_bytes(16)
        digest, now = password_digest(password, salt), utc_now()
        try:
            with self._lock, self.connect() as db:
                is_admin = not bool(db.execute("SELECT 1 FROM users LIMIT 1").fetchone())
                db.execute(
                    "INSERT INTO users(username,salt,password_hash,must_change,created_at,updated_at,is_admin,permissions) VALUES(?,?,?,?,?,?,?,?)",
                    (username, salt, digest, int(bool(must_change)), now, now, int(is_admin), json.dumps(DEFAULT_PERMISSIONS)),
                )
        except sqlite3.IntegrityError as error:
            raise ValueError("Cet utilisateur existe déjà.") from error
        return {"username": username, "must_change": bool(must_change), "created_at": now, "is_admin": is_admin, "permissions": {key: True for key in PERMISSION_KEYS} if is_admin else dict(DEFAULT_PERMISSIONS)}

    def update_user_access(self, username, is_admin, permissions, actor):
        username = validate_username(username)
        normalized = {key: bool(dict(permissions or {}).get(key, DEFAULT_PERMISSIONS[key])) for key in PERMISSION_KEYS}
        with self._lock, self.connect() as db:
            target = db.execute("SELECT username,is_admin FROM users WHERE username=?", (username,)).fetchone()
            if not target: raise ValueError("Utilisateur inconnu.")
            if target["is_admin"] and not is_admin:
                admins = db.execute("SELECT COUNT(*) FROM users WHERE is_admin=1").fetchone()[0]
                if admins <= 1: raise ValueError("Le dernier administrateur doit le rester.")
            db.execute(
                "UPDATE users SET is_admin=?,permissions=?,updated_at=? WHERE username=?",
                (int(bool(is_admin)), json.dumps(normalized, separators=(",", ":")), utc_now(), username),
            )
            db.execute("DELETE FROM sessions WHERE username=? AND username<>?", (username, actor))
        return next(user for user in self.list_users() if user["username"].casefold() == username.casefold())

    def delete_user(self, username):
        username = validate_username(username)
        with self._lock, self.connect() as db:
            count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if count <= 1:
                raise ValueError("Le dernier utilisateur ne peut pas être supprimé.")
            target = db.execute("SELECT is_admin FROM users WHERE username=?", (username,)).fetchone()
            if target and target["is_admin"] and db.execute("SELECT COUNT(*) FROM users WHERE is_admin=1").fetchone()[0] <= 1:
                raise ValueError("Le dernier administrateur ne peut pas être supprimé.")
            cursor = db.execute("DELETE FROM users WHERE username=?", (username,))
            if cursor.rowcount != 1:
                raise ValueError("Utilisateur inconnu.")

    def _verify(self, username, password, db=None):
        owns_connection = db is None
        if owns_connection:
            db = sqlite3.connect(self.path, timeout=10)
            db.row_factory = sqlite3.Row
        try:
            row = db.execute(
                "SELECT username,salt,password_hash,must_change,is_admin,permissions FROM users WHERE username=?",
                (str(username or "").strip(),),
            ).fetchone()
            if not row:
                password_digest(str(password or ""), b"\0" * 16)
                return None
            supplied = password_digest(str(password or ""), row["salt"])
            return row if hmac.compare_digest(supplied, row["password_hash"]) else None
        finally:
            if owns_connection:
                db.close()

    def authenticate(self, username, password):
        row = self._verify(username, password)
        return (self.public_user(row) if row else None)

    def create_session(self, username):
        raw_token, csrf = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("ascii")).hexdigest()
        expires = (datetime.now(timezone.utc) + timedelta(seconds=SESSION_SECONDS)).isoformat(timespec="seconds")
        with self._lock, self.connect() as db:
            db.execute("DELETE FROM sessions WHERE expires_at<=?", (utc_now(),))
            db.execute(
                "INSERT INTO sessions(token_hash,username,csrf_token,expires_at,created_at) VALUES(?,?,?,?,?)",
                (token_hash, username, csrf, expires, utc_now()),
            )
        return raw_token, csrf, expires

    def session(self, raw_token):
        if not raw_token:
            return None
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        with self.connect() as db:
            row = db.execute(
                "SELECT s.token_hash,s.username,s.csrf_token,s.expires_at,u.must_change,u.is_admin,u.permissions "
                "FROM sessions s JOIN users u ON u.username=s.username "
                "WHERE s.token_hash=? AND s.expires_at>?",
                (token_hash, utc_now()),
            ).fetchone()
        if not row:
            return None
        session = self.public_user(row)
        session.update({key: row[key] for key in ("token_hash", "csrf_token", "expires_at")})
        return session

    def delete_session(self, raw_token):
        if not raw_token:
            return
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        with self._lock, self.connect() as db:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))

    def change_password(self, username, current_password, new_password):
        new_password = validate_password(new_password)
        with self._lock, self.connect() as db:
            row = self._verify(username, current_password, db)
            if not row:
                raise ValueError("Mot de passe actuel incorrect.")
            salt, now = secrets.token_bytes(16), utc_now()
            db.execute(
                "UPDATE users SET salt=?,password_hash=?,must_change=0,updated_at=? WHERE username=?",
                (salt, password_digest(new_password, salt), now, username),
            )
            db.execute("DELETE FROM sessions WHERE username=?", (username,))


class BackendServer:
    def __init__(self, host=HOST, port=PORT, store=None, device_id=DEVICE_ID,
                 device_token=DEVICE_TOKEN, public_origin=PUBLIC_ORIGIN, pwa_dir=PWA_DIR):
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("The backend must listen on loopback only")
        if not device_id or len(device_token) < 32:
            raise RuntimeError("USAGE_GUARD_DEVICE_ID and a 32+ character DEVICE_TOKEN are required")
        parsed_origin = urlparse(public_origin)
        if parsed_origin.scheme != "https" or not parsed_origin.netloc or parsed_origin.path not in {"", "/"}:
            raise RuntimeError("USAGE_GUARD_PUBLIC_ORIGIN must be an HTTPS origin without a path")
        self.store = store or Store()
        self.store.configure_email_encryption_key(device_token)
        self.device_id, self.device_token = device_id, device_token
        self.public_origin, self.pwa_dir = public_origin.rstrip("/"), Path(pwa_dir)
        self.host, self.port, self.httpd = host, port, None
        self.login_limiter = LoginLimiter()
        self.email_limiter = EmailLimiter()
        self._presence_stop = threading.Event()
        self._presence_thread = None

    def _send_email_background(self, title, message, recipient):
        try:
            self.store.send_email_notification(title, message, recipient, False)
        except (ValueError, OSError, smtplib.SMTPException) as error:
            print(f"SMTP_FAILURE error={error}")

    def _dispatch_client_presence(self, connected):
        kind = "client_connected" if connected else "client_disconnected"
        title = "Client connecté — Usage Guard" if connected else "Client déconnecté — Usage Guard"
        message = (
            "Le client Usage Guard vient de se connecter au serveur."
            if connected else
            "Le client Usage Guard ne communique plus avec le serveur depuis au moins une minute."
        )
        snapshot = self.store.snapshot(self.device_id) or {}
        rules = [
            rule for rule in snapshot.get("notification_rules", [])
            if rule.get("enabled") and rule.get("kind") == kind
        ]
        if self.store.email_settings()["enabled"]:
            recipients = {
                str(rule.get("email_recipient", "")).strip() for rule in rules
                if "email" in (rule.get("channels") or ["windows"])
            }
            for recipient in filter(None, recipients):
                try:
                    recipient = self.store._valid_email_address(recipient, "Adresse de destination")
                except ValueError:
                    continue
                if self.email_limiter.allow(recipient):
                    threading.Thread(
                        target=self._send_email_background,
                        args=(title, message, recipient), daemon=True,
                    ).start()
        if any("windows" in (rule.get("channels") or ["windows"]) for rule in rules):
            self.store.queue(self.device_id, {
                "action": "notify_client_presence",
                "connected": connected,
                "windows_only": True,
            })

    def _presence_loop(self):
        while not self._presence_stop.wait(10):
            if self.store.mark_device_offline_if_stale(self.device_id):
                self._dispatch_client_presence(False)

    def start(self):
        owner = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "UsageGuardBackend/2"

            def do_GET(self):
                parsed = urlparse(self.path)
                if parsed.path == PREFIX + "/api/v1/health":
                    return self.json(HTTPStatus.OK, {"ok": True})
                if parsed.path == PREFIX + "/api/v1/agent/commands":
                    if not self.agent_authorized(): return self.error(HTTPStatus.UNAUTHORIZED, "Authentification appareil refusée")
                    if not self.valid_device_query(parsed): return self.error(HTTPStatus.FORBIDDEN, "Appareil inconnu")
                    if owner.store.mark_device_seen(owner.device_id):
                        owner._dispatch_client_presence(True)
                    return self.json(HTTPStatus.OK, {"commands": owner.store.pending(owner.device_id)})
                if parsed.path == PREFIX + "/api/v1/agent/users":
                    if not self.agent_authorized(): return self.error(HTTPStatus.UNAUTHORIZED, "Authentification appareil refusée")
                    if not self.valid_device_query(parsed): return self.error(HTTPStatus.FORBIDDEN, "Appareil inconnu")
                    return self.json(HTTPStatus.OK, {"users": owner.store.list_users()})
                if parsed.path == PREFIX + "/api/v1/agent/activity":
                    if not self.agent_authorized(): return self.error(HTTPStatus.UNAUTHORIZED, "Authentification appareil refusée")
                    if not self.valid_device_query(parsed): return self.error(HTTPStatus.FORBIDDEN, "Appareil inconnu")
                    return self.json(HTTPStatus.OK, owner.store.activity_store(owner.device_id) or {"activity": None})
                if parsed.path == PREFIX + "/api/v1/agent/email/settings":
                    if not self.agent_authorized(): return self.error(HTTPStatus.UNAUTHORIZED, "Authentification appareil refusée")
                    if not self.valid_device_query(parsed): return self.error(HTTPStatus.FORBIDDEN, "Appareil inconnu")
                    return self.json(HTTPStatus.OK, {"email_settings": owner.store.email_settings()})
                if parsed.path == PREFIX + "/api/v1/auth/session":
                    session = self.user_session()
                    if not session: return self.error(HTTPStatus.UNAUTHORIZED, "Connexion requise")
                    return self.json(HTTPStatus.OK, self.session_payload(session))
                if parsed.path == PREFIX + "/api/v1/admin/users":
                    session = self.user_session()
                    if not session: return self.error(HTTPStatus.UNAUTHORIZED, "Connexion requise")
                    if not session["is_admin"]: return self.error(HTTPStatus.FORBIDDEN, "Droits administrateur requis")
                    return self.json(HTTPStatus.OK, {"users": owner.store.list_users()})
                if parsed.path == PREFIX + "/api/v1/email/settings":
                    session = self.user_session()
                    if not session: return self.error(HTTPStatus.UNAUTHORIZED, "Connexion requise")
                    if session["must_change"]: return self.error(HTTPStatus.FORBIDDEN, "Changement de mot de passe requis")
                    if not session["is_admin"]:
                        return self.error(HTTPStatus.FORBIDDEN, "Droits administrateur requis")
                    return self.json(HTTPStatus.OK, {"email_settings": owner.store.email_settings()})
                if parsed.path == PREFIX + "/api/v1/overview":
                    session = self.user_session()
                    if not session: return self.error(HTTPStatus.UNAUTHORIZED, "Connexion requise")
                    if session["must_change"]: return self.error(HTTPStatus.FORBIDDEN, "Changement de mot de passe requis")
                    scope = parse_qs(parsed.query).get("scope", ["today"])[0]
                    if scope == "notifications":
                        snapshot = owner.store.snapshot(owner.device_id) or {}
                        rules = [
                            item for item in snapshot.get("notification_rules", [])
                            if item.get("mandatory")
                            or str(item.get("owner", "")).casefold() == session["username"].casefold()
                            or session["is_admin"] and not str(item.get("owner", "")).strip()
                        ]
                        if not session["permissions"]["view_notifications"]:
                            rules = [item for item in rules if item.get("mandatory")]
                        limits = snapshot.get("limits", []) if session["permissions"]["manage_notifications"] else []
                        return self.json(HTTPStatus.OK, {
                            "notification_rules": rules, "limits": limits,
                        })
                    required = "view_activity" if scope in {"today", "session"} else "view_analysis"
                    if not session["permissions"][required]: return self.error(HTTPStatus.FORBIDDEN, "Cette vue n’est pas autorisée")
                    snapshot = owner.store.snapshot(owner.device_id)
                    if snapshot and scope not in {"today", "session"}:
                        embedded_analysis = snapshot.get("analysis", snapshot)
                        activity = owner.store.activity_store(owner.device_id) or {}
                        if activity.get("activity"):
                            snapshot = analysis_snapshot_from_activity(
                                activity["activity"], embedded_analysis
                            )
                        else:
                            snapshot = embedded_analysis
                    if snapshot:
                        snapshot = {
                            **snapshot,
                            "pending_limit_commands": owner.store.pending_limit_commands(
                                owner.device_id, snapshot
                            ),
                        }
                    if snapshot and not session["permissions"]["view_limits"]:
                        snapshot = {**snapshot, "limits": [], "merge_candidates": [], "computer_block": {}, "pending_limit_commands": []}
                    if snapshot and not session["permissions"]["view_notifications"]:
                        snapshot = {**snapshot, "notification_rules": [
                            item for item in snapshot.get("notification_rules", [])
                            if item.get("mandatory")
                        ]}
                    elif snapshot:
                        snapshot = {**snapshot, "notification_rules": [
                            item for item in snapshot.get("notification_rules", [])
                            if item.get("mandatory")
                            or str(item.get("owner", "")).casefold() == session["username"].casefold()
                            or session["is_admin"] and not str(item.get("owner", "")).strip()
                        ]}
                    if not snapshot:
                        return self.json(HTTPStatus.OK, {
                            "error": "Aucune donnée reçue", "offline": True,
                            "pending_limit_commands": owner.store.pending_limit_commands(owner.device_id, {}),
                        })
                    return self.json(HTTPStatus.OK, snapshot)
                return self.static(parsed.path)

            def do_POST(self):
                parsed = urlparse(self.path)
                try: payload = self.body()
                except ValueError as error: return self.error(HTTPStatus.BAD_REQUEST, str(error))
                if parsed.path == PREFIX + "/api/v1/auth/login":
                    return self.login(payload)
                if parsed.path == PREFIX + "/api/v1/auth/logout":
                    session = self.require_user_write(allow_password_change=True)
                    if not session: return
                    owner.store.delete_session(self.session_cookie())
                    return self.json(HTTPStatus.OK, {"ok": True}, {"Set-Cookie": self.expired_cookie()})
                if parsed.path == PREFIX + "/api/v1/auth/password":
                    session = self.require_user_write(allow_password_change=True)
                    if not session: return
                    try:
                        owner.store.change_password(session["username"], payload.get("current_password"), payload.get("new_password"))
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    raw, csrf, expires = owner.store.create_session(session["username"])
                    return self.json(HTTPStatus.OK, {
                        "ok": True, "username": session["username"], "must_change": False,
                        "is_admin": bool(session["is_admin"]), "permissions": session["permissions"],
                        "csrf_token": csrf, "expires_at": expires,
                    }, {"Set-Cookie": self.session_cookie_header(raw)})
                if parsed.path == PREFIX + "/api/v1/agent/snapshot":
                    if not self.agent_authorized(): return self.error(HTTPStatus.UNAUTHORIZED, "Authentification appareil refusée")
                    if payload.get("device_id") != owner.device_id:
                        return self.error(HTTPStatus.BAD_REQUEST, "Charge utile appareil invalide")
                    try:
                        if isinstance(payload.get("snapshot"), dict):
                            owner.store.save_snapshot(owner.device_id, payload["snapshot"])
                        elif isinstance(payload.get("snapshot_delta"), dict):
                            owner.store.patch_snapshot(
                                owner.device_id,
                                payload["snapshot_delta"],
                                payload.get("base_hash"),
                                payload.get("target_hash"),
                            )
                        else:
                            return self.error(HTTPStatus.BAD_REQUEST, "Snapshot invalide")
                    except DocumentConflict as error:
                        return self.error(HTTPStatus.CONFLICT, str(error))
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.OK, {"ok": True})
                if parsed.path == PREFIX + "/api/v1/agent/activity":
                    if not self.agent_authorized(): return self.error(HTTPStatus.UNAUTHORIZED, "Authentification appareil refusée")
                    if payload.get("device_id") != owner.device_id:
                        return self.error(HTTPStatus.BAD_REQUEST, "Base d’activité invalide")
                    try:
                        if isinstance(payload.get("activity"), dict):
                            owner.store.save_activity_store(owner.device_id, payload["activity"])
                        elif isinstance(payload.get("activity_delta"), dict):
                            owner.store.patch_activity_store(
                                owner.device_id,
                                payload["activity_delta"],
                                payload.get("base_hash"),
                                payload.get("target_hash"),
                            )
                        else:
                            return self.error(HTTPStatus.BAD_REQUEST, "Base d’activité invalide")
                    except DocumentConflict as error:
                        return self.error(HTTPStatus.CONFLICT, str(error))
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.OK, {"ok": True, "stored_at": utc_now()})
                if parsed.path == PREFIX + "/api/v1/agent/email/settings":
                    if not self.agent_authorized(): return self.error(HTTPStatus.UNAUTHORIZED, "Authentification appareil refusée")
                    if payload.get("device_id") != owner.device_id:
                        return self.error(HTTPStatus.BAD_REQUEST, "Appareil invalide")
                    try:
                        settings = owner.store.save_email_settings(payload.get("settings", {}))
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.OK, {"ok": True, "email_settings": settings})
                if parsed.path == PREFIX + "/api/v1/agent/email/test":
                    if not self.agent_authorized(): return self.error(HTTPStatus.UNAUTHORIZED, "Authentification appareil refusée")
                    if payload.get("device_id") != owner.device_id:
                        return self.error(HTTPStatus.BAD_REQUEST, "Appareil invalide")
                    return self.send_email("Test de notification", "Ce message confirme que les notifications par e-mail de Usage Guard fonctionnent.", payload.get("recipient"), True)
                if parsed.path == PREFIX + "/api/v1/agent/email/send":
                    if not self.agent_authorized(): return self.error(HTTPStatus.UNAUTHORIZED, "Authentification appareil refusée")
                    if payload.get("device_id") != owner.device_id:
                        return self.error(HTTPStatus.BAD_REQUEST, "Appareil invalide")
                    return self.send_email(payload.get("title"), payload.get("message"), payload.get("recipient"), False)
                if parsed.path == PREFIX + "/api/v1/agent/users":
                    if not self.agent_authorized(): return self.error(HTTPStatus.UNAUTHORIZED, "Authentification appareil refusée")
                    if payload.get("device_id") != owner.device_id:
                        return self.error(HTTPStatus.BAD_REQUEST, "Appareil invalide")
                    try:
                        user = owner.store.create_user(payload.get("username"), payload.get("password"), True)
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.CREATED, {"ok": True, "user": user})
                agent_user_prefix = PREFIX + "/api/v1/agent/users/"
                if parsed.path.startswith(agent_user_prefix) and parsed.path.endswith("/access"):
                    if not self.agent_authorized(): return self.error(HTTPStatus.UNAUTHORIZED, "Authentification appareil refusée")
                    if payload.get("device_id") != owner.device_id:
                        return self.error(HTTPStatus.BAD_REQUEST, "Appareil invalide")
                    username = unquote(parsed.path[len(agent_user_prefix):-len("/access")].rstrip("/"))
                    try:
                        user = owner.store.update_user_access(
                            username, payload.get("is_admin", False), payload.get("permissions", {}), ""
                        )
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.OK, {"ok": True, "user": user})
                if parsed.path.startswith(PREFIX + "/api/v1/agent/commands/") and parsed.path.endswith("/ack"):
                    if not self.agent_authorized(): return self.error(HTTPStatus.UNAUTHORIZED, "Authentification appareil refusée")
                    command_id = parsed.path.removesuffix("/ack").rsplit("/", 1)[-1]
                    if payload.get("device_id") != owner.device_id or not command_id.isdigit():
                        return self.error(HTTPStatus.BAD_REQUEST, "Accusé invalide")
                    ok = owner.store.acknowledge(owner.device_id, int(command_id), payload.get("result", {}))
                    return self.json(HTTPStatus.OK if ok else HTTPStatus.NOT_FOUND, {"ok": ok})
                if parsed.path == PREFIX + "/api/v1/actions":
                    session = self.require_user_write()
                    if not session: return
                    if payload.get("action") not in ALLOWED_ACTIONS:
                        return self.error(HTTPStatus.BAD_REQUEST, "Commande non autorisée")
                    if payload.get("action") in LIMIT_ACTIONS:
                        permission = "manage_limits"
                    elif payload.get("action") in NOTIFICATION_ACTIONS:
                        permission = "manage_notifications"
                    else:
                        permission = "manage_activity"
                    if not session["permissions"][permission]:
                        return self.error(HTTPStatus.FORBIDDEN, "Modification non autorisée pour ce compte")
                    if payload.get("action") in {"set_notification_rule", "remove_notification_rule"}:
                        snapshot = owner.store.snapshot(owner.device_id) or {}
                        rules = snapshot.get("notification_rules", [])
                        rule_id = str(
                            payload.get("rule", {}).get("id", "")
                            if payload.get("action") == "set_notification_rule"
                            else payload.get("rule_id", "")
                        )
                        existing = next((item for item in rules if str(item.get("id", "")) == rule_id), None)
                        existing_owner = str(existing.get("owner", "")).strip() if existing else ""
                        if existing and existing_owner.casefold() != session["username"].casefold() and not (session["is_admin"] and not existing_owner):
                            return self.error(HTTPStatus.FORBIDDEN, "Cette notification appartient à un autre utilisateur")
                        if payload.get("action") == "set_notification_rule":
                            payload = {
                                **payload,
                                "rule": {**dict(payload.get("rule") or {}), "owner": session["username"]},
                            }
                    command_id = owner.store.queue(owner.device_id, {**payload, "actor": session["username"]})
                    return self.json(HTTPStatus.ACCEPTED, {"ok": True, "queued": True, "id": str(command_id)})
                if parsed.path in {PREFIX + "/api/v1/email/settings", PREFIX + "/api/v1/email/test"}:
                    session = self.require_user_write()
                    if not session: return
                    if not session["is_admin"]:
                        return self.error(HTTPStatus.FORBIDDEN, "Droits administrateur requis")
                    if parsed.path.endswith("/settings"):
                        try:
                            settings = owner.store.save_email_settings(payload)
                        except ValueError as error:
                            return self.error(HTTPStatus.BAD_REQUEST, str(error))
                        return self.json(HTTPStatus.OK, {"ok": True, "email_settings": settings})
                    return self.send_email("Test de notification", "Ce message confirme que les notifications par e-mail de Usage Guard fonctionnent.", payload.get("recipient"), True)
                admin_prefix = PREFIX + "/api/v1/admin/users/"
                if parsed.path.startswith(admin_prefix) and parsed.path.endswith("/access"):
                    session = self.require_user_write()
                    if not session: return
                    if not session["is_admin"]: return self.error(HTTPStatus.FORBIDDEN, "Droits administrateur requis")
                    username = unquote(parsed.path[len(admin_prefix):-len("/access")].rstrip("/"))
                    try:
                        user = owner.store.update_user_access(
                            username, payload.get("is_admin", False), payload.get("permissions", {}), session["username"]
                        )
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.OK, {"ok": True, "user": user})
                return self.error(HTTPStatus.NOT_FOUND, "Endpoint inconnu")

            def do_DELETE(self):
                parsed = urlparse(self.path)
                prefix = PREFIX + "/api/v1/agent/users/"
                if not parsed.path.startswith(prefix):
                    return self.error(HTTPStatus.NOT_FOUND, "Endpoint inconnu")
                if not self.agent_authorized(): return self.error(HTTPStatus.UNAUTHORIZED, "Authentification appareil refusée")
                if not self.valid_device_query(parsed): return self.error(HTTPStatus.FORBIDDEN, "Appareil inconnu")
                try:
                    owner.store.delete_user(unquote(parsed.path[len(prefix):]))
                except ValueError as error:
                    return self.error(HTTPStatus.BAD_REQUEST, str(error))
                return self.json(HTTPStatus.OK, {"ok": True})

            def send_email(self, title, message, recipient, force):
                try:
                    recipient = owner.store._valid_email_address(recipient, "Adresse de destination")
                except ValueError as error:
                    return self.error(HTTPStatus.BAD_REQUEST, str(error))
                if not force and not owner.store.email_settings()["enabled"]:
                    return self.json(HTTPStatus.OK, {"ok": True, "skipped": True, "reason": "disabled"})
                if not owner.email_limiter.allow(recipient):
                    return self.error(HTTPStatus.TOO_MANY_REQUESTS, "Trop d’envois vers cette adresse. Réessayez dans quelques minutes.")
                try:
                    result = owner.store.send_email_notification(title, message, recipient, force)
                except ValueError as error:
                    return self.error(HTTPStatus.BAD_REQUEST, str(error))
                except (OSError, smtplib.SMTPException) as error:
                    return self.error(HTTPStatus.BAD_GATEWAY, f"Envoi SMTP impossible : {error}")
                return self.json(HTTPStatus.OK, result)

            def login(self, payload):
                if not self.valid_origin(): return self.error(HTTPStatus.FORBIDDEN, "Origine refusée")
                username = str(payload.get("username", "")).strip()
                key = (self.client_ip(), username.casefold())
                if not owner.login_limiter.allowed(key):
                    return self.error(HTTPStatus.TOO_MANY_REQUESTS, "Trop de tentatives. Réessayez dans 15 minutes.")
                user = owner.store.authenticate(username, payload.get("password"))
                if not user:
                    owner.login_limiter.failed(key)
                    print(f"AUTH_FAILURE ip={key[0]} username={username[:32]!r}")
                    return self.error(HTTPStatus.UNAUTHORIZED, "Identifiant ou mot de passe incorrect")
                owner.login_limiter.succeeded(key)
                raw, csrf, expires = owner.store.create_session(user["username"])
                snapshot = owner.store.snapshot(owner.device_id) or {}
                login_rules = [
                    rule for rule in snapshot.get("notification_rules", [])
                    if rule.get("enabled") and rule.get("kind") == "pwa_login"
                ]
                actor, ip = user["username"], self.client_ip()
                title = f"{actor} connecté à la PWA — Usage Guard"
                message = f"{actor} vient de se connecter à la PWA depuis {ip}."
                recipients = {
                    str(rule.get("email_recipient", "")).strip()
                    for rule in login_rules
                    if "email" in (rule.get("channels") or ["windows"])
                    and str(rule.get("email_recipient", "")).strip()
                }
                if owner.store.email_settings()["enabled"]:
                    for recipient in recipients:
                        try:
                            recipient = owner.store._valid_email_address(recipient, "Adresse de destination")
                        except ValueError:
                            continue
                        if owner.email_limiter.allow(recipient):
                            threading.Thread(
                                target=owner._send_email_background,
                                args=(title, message, recipient), daemon=True,
                            ).start()
                if any("windows" in (rule.get("channels") or ["windows"]) for rule in login_rules):
                    owner.store.queue(owner.device_id, {
                        "action": "notify_pwa_login",
                        "actor": actor,
                        "ip": ip,
                        "windows_only": True,
                    })
                return self.json(HTTPStatus.OK, {
                    "ok": True, **user, "csrf_token": csrf, "expires_at": expires,
                }, {"Set-Cookie": self.session_cookie_header(raw)})

            def require_user_write(self, allow_password_change=False):
                if not self.valid_origin():
                    self.error(HTTPStatus.FORBIDDEN, "Origine refusée"); return None
                session = self.user_session()
                if not session:
                    self.error(HTTPStatus.UNAUTHORIZED, "Connexion requise"); return None
                if session["must_change"] and not allow_password_change:
                    self.error(HTTPStatus.FORBIDDEN, "Changement de mot de passe requis"); return None
                supplied = self.headers.get("X-CSRF-Token", "")
                if not supplied or not secrets.compare_digest(supplied, session["csrf_token"]):
                    self.error(HTTPStatus.FORBIDDEN, "Protection CSRF refusée"); return None
                return session

            def agent_authorized(self):
                supplied = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
                return bool(supplied) and secrets.compare_digest(supplied, owner.device_token)

            def valid_device_query(self, parsed):
                return parse_qs(parsed.query).get("device_id", [""])[0] == owner.device_id

            def valid_origin(self):
                return self.headers.get("Origin", "").rstrip("/") == owner.public_origin

            def client_ip(self):
                forwarded = self.headers.get("X-Forwarded-For", "").split(",", 1)[0].strip()
                try: return str(ipaddress.ip_address(forwarded))
                except ValueError: return self.client_address[0]

            def session_cookie(self):
                try:
                    cookie = SimpleCookie(self.headers.get("Cookie", ""))
                    return cookie.get("ug_session").value if cookie.get("ug_session") else ""
                except Exception:
                    return ""

            def user_session(self):
                return owner.store.session(self.session_cookie())

            @staticmethod
            def session_payload(session):
                return {
                    "authenticated": True, "username": session["username"],
                    "must_change": bool(session["must_change"]),
                    "is_admin": bool(session["is_admin"]),
                    "permissions": session["permissions"],
                    "csrf_token": session["csrf_token"], "expires_at": session["expires_at"],
                }

            @staticmethod
            def session_cookie_header(raw):
                return f"ug_session={raw}; Path={PREFIX}; Max-Age={SESSION_SECONDS}; Secure; HttpOnly; SameSite=Strict"

            @staticmethod
            def expired_cookie():
                return f"ug_session=; Path={PREFIX}; Max-Age=0; Secure; HttpOnly; SameSite=Strict"

            def body(self):
                try: length = int(self.headers.get("Content-Length", "0"))
                except ValueError: raise ValueError("Taille invalide")
                if length < 0 or length > MAX_BODY: raise ValueError("Charge utile trop volumineuse")
                try: payload = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
                except (UnicodeDecodeError, json.JSONDecodeError): raise ValueError("JSON invalide")
                if not isinstance(payload, dict): raise ValueError("Objet JSON requis")
                return payload

            def static(self, request_path):
                relative = request_path[len(PREFIX):].lstrip("/") if request_path.startswith(PREFIX) else ""
                if not relative: relative = "index.html"
                candidate = (owner.pwa_dir / relative).resolve()
                if owner.pwa_dir.resolve() not in candidate.parents or not candidate.is_file():
                    return self.error(HTTPStatus.NOT_FOUND, "Fichier inconnu")
                content = candidate.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.security_headers()
                self.send_header("Content-Type", mimetypes.guess_type(candidate.name)[0] or "application/octet-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers(); self.wfile.write(content)

            def json(self, status, payload, headers=None):
                content = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(status); self.security_headers()
                for name, value in (headers or {}).items(): self.send_header(name, value)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers(); self.wfile.write(content)

            def error(self, status, message): return self.json(status, {"error": message})

            def security_headers(self):
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'; style-src-attr 'unsafe-inline'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'")

            def log_message(self, format_, *args):
                print(f"{self.client_ip()} - {format_ % args}")

        self.httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self._presence_stop.clear()
        self._presence_thread = threading.Thread(target=self._presence_loop, daemon=True)
        self._presence_thread.start()
        self.httpd.serve_forever()

    def stop(self):
        self._presence_stop.set()
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None


if __name__ == "__main__":
    BackendServer().start()
