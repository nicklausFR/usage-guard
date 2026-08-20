"""Usage Guard remote backend: stdlib-only, loopback-only and session-authenticated."""
import hashlib
import hmac
import ipaddress
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
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
MAX_BODY = 2 * 1024 * 1024
SESSION_SECONDS = 12 * 60 * 60
PASSWORD_MIN_LENGTH = 10
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
NOTIFICATION_ACTIONS = {
    "set_notification_rule", "remove_notification_rule", "set_notification_warning",
    "set_default_limit_warning",
}


class DocumentConflict(ValueError):
    pass


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def json_hash(value):
    raw = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


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


class Store:
    def __init__(self, path=DB_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
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
            """)
            columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
            if "is_admin" not in columns:
                db.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
            if "permissions" not in columns:
                db.execute("ALTER TABLE users ADD COLUMN permissions TEXT NOT NULL DEFAULT '{}'")
            if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] and not db.execute(
                "SELECT 1 FROM users WHERE is_admin=1 LIMIT 1"
            ).fetchone():
                db.execute(
                    "UPDATE users SET is_admin=1 WHERE username=(SELECT username FROM users ORDER BY created_at,username LIMIT 1)"
                )

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
        payload = json.dumps(document, ensure_ascii=False, separators=(",", ":"))
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
        return json.loads(row["payload"]), row["updated_at"]

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

    def queue(self, device_id, command):
        payload = json.dumps(command, ensure_ascii=False, separators=(",", ":"))
        with self._lock, self.connect() as db:
            cursor = db.execute("INSERT INTO commands(device_id,payload,created_at) VALUES(?,?,?)", (device_id, payload, utc_now()))
            return cursor.lastrowid

    def pending(self, device_id):
        with self._lock, self.connect() as db:
            rows = db.execute(
                "SELECT id,payload FROM commands WHERE device_id=? AND delivered_at IS NULL AND acknowledged_at IS NULL ORDER BY id LIMIT 100",
                (device_id,),
            ).fetchall()
            if rows:
                db.executemany("UPDATE commands SET delivered_at=? WHERE id=?", [(utc_now(), row["id"]) for row in rows])
        return [{"id": str(row["id"]), **json.loads(row["payload"])} for row in rows]

    def acknowledge(self, device_id, command_id, result):
        payload = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
        with self._lock, self.connect() as db:
            cursor = db.execute(
                "UPDATE commands SET acknowledged_at=?,result=? WHERE id=? AND device_id=? AND acknowledged_at IS NULL",
                (utc_now(), payload, command_id, device_id),
            )
            return cursor.rowcount == 1

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
        self.device_id, self.device_token = device_id, device_token
        self.public_origin, self.pwa_dir = public_origin.rstrip("/"), Path(pwa_dir)
        self.host, self.port, self.httpd = host, port, None
        self.login_limiter = LoginLimiter()

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
                    return self.json(HTTPStatus.OK, {"commands": owner.store.pending(owner.device_id)})
                if parsed.path == PREFIX + "/api/v1/agent/users":
                    if not self.agent_authorized(): return self.error(HTTPStatus.UNAUTHORIZED, "Authentification appareil refusée")
                    if not self.valid_device_query(parsed): return self.error(HTTPStatus.FORBIDDEN, "Appareil inconnu")
                    return self.json(HTTPStatus.OK, {"users": owner.store.list_users()})
                if parsed.path == PREFIX + "/api/v1/agent/activity":
                    if not self.agent_authorized(): return self.error(HTTPStatus.UNAUTHORIZED, "Authentification appareil refusée")
                    if not self.valid_device_query(parsed): return self.error(HTTPStatus.FORBIDDEN, "Appareil inconnu")
                    return self.json(HTTPStatus.OK, owner.store.activity_store(owner.device_id) or {"activity": None})
                if parsed.path == PREFIX + "/api/v1/auth/session":
                    session = self.user_session()
                    if not session: return self.error(HTTPStatus.UNAUTHORIZED, "Connexion requise")
                    return self.json(HTTPStatus.OK, self.session_payload(session))
                if parsed.path == PREFIX + "/api/v1/admin/users":
                    session = self.user_session()
                    if not session: return self.error(HTTPStatus.UNAUTHORIZED, "Connexion requise")
                    if not session["is_admin"]: return self.error(HTTPStatus.FORBIDDEN, "Droits administrateur requis")
                    return self.json(HTTPStatus.OK, {"users": owner.store.list_users()})
                if parsed.path == PREFIX + "/api/v1/overview":
                    session = self.user_session()
                    if not session: return self.error(HTTPStatus.UNAUTHORIZED, "Connexion requise")
                    if session["must_change"]: return self.error(HTTPStatus.FORBIDDEN, "Changement de mot de passe requis")
                    scope = parse_qs(parsed.query).get("scope", ["today"])[0]
                    if scope == "notifications":
                        snapshot = owner.store.snapshot(owner.device_id) or {}
                        rules = snapshot.get("notification_rules", [])
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
                        snapshot = snapshot.get("analysis", snapshot)
                    if snapshot and not session["permissions"]["view_limits"]:
                        snapshot = {**snapshot, "limits": [], "merge_candidates": [], "computer_block": {}}
                    if snapshot and not session["permissions"]["view_notifications"]:
                        snapshot = {**snapshot, "notification_rules": [
                            item for item in snapshot.get("notification_rules", [])
                            if item.get("mandatory")
                        ]}
                    return self.json(HTTPStatus.OK, snapshot or {"error": "Aucune donnée reçue", "offline": True})
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
                    command_id = owner.store.queue(owner.device_id, {**payload, "actor": session["username"]})
                    return self.json(HTTPStatus.ACCEPTED, {"ok": True, "queued": True, "id": str(command_id)})
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
                if any(
                    rule.get("enabled") and rule.get("kind") == "pwa_login"
                    for rule in snapshot.get("notification_rules", [])
                ):
                    owner.store.queue(owner.device_id, {
                        "action": "notify_pwa_login",
                        "actor": user["username"],
                        "ip": self.client_ip(),
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
        self.httpd.serve_forever()

    def stop(self):
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None


if __name__ == "__main__":
    BackendServer().start()
