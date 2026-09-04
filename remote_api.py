"""Authenticated local API and PWA host for Usage Guard.

It is deliberately self-contained: deployment through a VPN or an HTTPS
reverse proxy can be added later without coupling the monitoring engine to a
specific cloud provider.
"""

import json
import secrets
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from command_policy import (
    SERVICE_ADMIN_TOKEN_FIELD, SOURCE_LOCAL_ADMIN, stamp_command,
)
from runtime_profile import current_profile
from usage_guard import APP_DIR, _site_host, config


PWA_DIR = APP_DIR / "pwa"
MAX_BODY = 2 * 1024 * 1024
ADMIN_SESSION_SECONDS = 8 * 60 * 60
ADMIN_HEADER = "X-Usage-Guard-Admin"
LOCAL_USER_NOTIFICATION_ACTIONS = {
    "set_notification_rule", "remove_notification_rule",
    "set_notification_warning", "set_default_limit_warning",
}
LOCAL_USER_ACTIVITY_ACTIONS = {
    "rename_target", "set_category", "make_root", "exclude_target",
    "unexclude_target", "dismiss_target", "delete_target", "merge_target",
    "rename_category",
    "move_category", "reorder_category", "clear_category",
    "make_category_root", "set_category_for_keys", "rename_browser",
    "make_browser_root", "clear_browser_category", "clear_site_category",
    "rename_site_category", "reorder_site_category", "exclude_passive",
    "make_site_specific",
    "categorize_site", "exclude_site", "delete_site", "set_language",
}
DELETE_LIMITS_AUTHORIZED_FIELD = "_usage_guard_delete_limits_authorized"
DELETE_OTHER_LIMITS_AUTHORIZED_FIELD = (
    "_usage_guard_delete_other_limits_authorized"
)


def _token_path():
    configured = str(getattr(config, "REMOTE_API_TOKEN_PATH", "")).strip()
    if configured:
        return Path(configured).expanduser()
    base = current_profile().local_data_directory()
    port = int(getattr(config, "REMOTE_API_PORT", 8766))
    filename = (
        "remote-api-token.txt"
        if port == current_profile().remote_api_port
        else f"remote-api-token-{port}.txt"
    )
    return base / filename


class RemoteControlServer:
    def __init__(
        self, snapshot_provider, command_handler, backend_client=None,
        admin_authenticator=None, backend_manager=None,
        windows_session_authenticator=None,
    ):
        self.snapshot_provider = snapshot_provider
        self.command_handler = command_handler
        self.backend_client = backend_client
        self.backend_manager = backend_manager
        self.admin_authenticator = admin_authenticator or (
            backend_client.authenticate_user if backend_client is not None else None
        )
        self.windows_session_authenticator = windows_session_authenticator
        self.host = str(getattr(config, "REMOTE_API_HOST", "127.0.0.1"))
        if self.host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("The local API must listen on loopback only")
        self.port = int(getattr(config, "REMOTE_API_PORT", 8766))
        self.token_path = _token_path()
        self.token = self._load_or_create_token()
        self._admin_sessions = {}
        self._admin_lock = threading.Lock()
        self._server = None
        self._thread = None

    def _issue_admin_session(self, user):
        token = secrets.token_urlsafe(48)
        expires_at = time.time() + ADMIN_SESSION_SECONDS
        session = {
            "username": str(user.get("username") or "Utilisateur"),
            "email": str(user.get("email") or ""),
            "is_admin": bool(user.get("is_admin")),
            "role": str(user.get("role") or (
                "admin" if user.get("is_admin") else "limited"
            )),
            "permissions": dict(user.get("permissions") or {}),
            "expires_at": expires_at,
        }
        service_token = str(user.get("_service_admin_token") or "")
        if service_token:
            session["_service_admin_token"] = service_token
        backend_token = str(user.get("_service_backend_token") or service_token)
        if backend_token:
            session["_service_backend_token"] = backend_token
        backend_session = user.get("_backend_management_session")
        if isinstance(backend_session, dict) and backend_session:
            session["_backend_management_session"] = dict(backend_session)
        with self._admin_lock:
            now = time.time()
            self._admin_sessions = {
                key: value for key, value in self._admin_sessions.items()
                if float(value.get("expires_at", 0)) > now
            }
            self._admin_sessions[token] = session
        return token, dict(session)

    @staticmethod
    def _public_admin_session(session):
        return {
            key: value for key, value in dict(session or {}).items()
            if not str(key).startswith("_")
        }

    def _admin_session(self, token):
        token = str(token or "")
        with self._admin_lock:
            session = self._admin_sessions.get(token)
            if not session or float(session.get("expires_at", 0)) <= time.time():
                self._admin_sessions.pop(token, None)
                return None
            return dict(session)

    def _drop_admin_session(self, token):
        with self._admin_lock:
            self._admin_sessions.pop(str(token or ""), None)

    def _load_or_create_token(self):
        try:
            if self.token_path.exists():
                token = self.token_path.read_text(encoding="utf-8").strip()
                if token:
                    return token
            token = secrets.token_urlsafe(32)
            self.token_path.parent.mkdir(parents=True, exist_ok=True)
            self.token_path.write_text(token + "\n", encoding="utf-8")
            return token
        except OSError:
            # A server without durable authentication must never listen on the
            # network.  It remains usable only on loopback for this session.
            self.host = "127.0.0.1"
            return secrets.token_urlsafe(32)

    def start(self):
        if self._server is not None:
            return
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if not self._valid_host():
                    return self._json(HTTPStatus.MISDIRECTED_REQUEST, {"error": "Hôte refusé."})
                parsed = urlparse(self.path)
                if parsed.path == "/api/v1/bootstrap":
                    if not self._is_loopback():
                        return self._json(HTTPStatus.FORBIDDEN, {"error": "Ouvrez d'abord la PWA sur cet ordinateur pour l'associer."})
                    windows_username = ""
                    if owner.windows_session_authenticator is not None:
                        try:
                            windows_user = owner.windows_session_authenticator()
                            if not windows_user.get("is_admin"):
                                windows_username = str(
                                    windows_user.get("username") or ""
                                )
                        except Exception:
                            pass
                    return self._json(HTTPStatus.OK, {
                        "token": owner.token,
                        "windows_username": windows_username,
                        "device_id": str(
                            getattr(owner.backend_client, "device_id", "local")
                            or "local"
                        ),
                        "device_label": str(
                            getattr(owner.backend_client, "display_name", "")
                            or "Cet ordinateur"
                        ),
                    })
                if parsed.path.startswith("/api/"):
                    if not self._authorized(parsed):
                        return self._unauthorized()
                    if parsed.path == "/api/v1/auth/session":
                        session = self._admin_session()
                        if not session:
                            return self._admin_required()
                        return self._json(HTTPStatus.OK, {
                            "authenticated": True,
                            **owner._public_admin_session(session),
                        })
                    if parsed.path in {"/api/v1/devices", "/api/v1/policies"}:
                        session = self._require_session()
                        if not session:
                            return
                        if self._has_backend_proxy(session):
                            try:
                                action = (
                                    "session_devices"
                                    if parsed.path.endswith("/devices") else
                                    "policy_users"
                                )
                                result = dict(
                                    self._backend_user_call(session, action)
                                    or {}
                                )
                                result["federated"] = True
                                return self._json(HTTPStatus.OK, result)
                            except Exception as error:
                                return self._backend_proxy_error(error)
                        device_id = str(
                            getattr(owner.backend_client, "device_id", "local")
                            or "local"
                        )
                        if parsed.path.endswith("/devices"):
                            label = str(
                                getattr(owner.backend_client, "display_name", "")
                                or "Cet ordinateur"
                            )
                            return self._json(HTTPStatus.OK, {
                                "federated": False, "devices": [{
                                "device_id": device_id, "label": label,
                                "online": True,
                            }]})
                        local_snapshot = owner.snapshot_provider({
                            "scope": "limits",
                        })
                        local_identity = dict(
                            dict(local_snapshot.get("runtime") or {}).get(
                                "windows_identity"
                            ) or {}
                        )
                        local_username = str(
                            local_identity.get("usage_guard_username")
                            or session["username"]
                        )
                        return self._json(HTTPStatus.OK, {
                            "federated": False, "users": [{
                            "username": local_username,
                            "device_ids": [device_id],
                            "catalog_device_id": device_id,
                        }]})
                    policy_prefix = "/api/v1/policies/"
                    if parsed.path.startswith(policy_prefix):
                        session = self._require_session()
                        if not session:
                            return
                        if not self._has_backend_proxy(session):
                            return self._json(HTTPStatus.SERVICE_UNAVAILABLE, {
                                "error": "Politique multi-ordinateur indisponible.",
                            })
                        relative = parsed.path[len(policy_prefix):].strip("/")
                        if not relative:
                            return self._json(
                                HTTPStatus.NOT_FOUND,
                                {"error": "Utilisateur absent."},
                            )
                        try:
                            if relative.endswith("/usage"):
                                username = unquote(relative[:-len("/usage")])
                                query = parse_qs(parsed.query)
                                result = self._backend_user_call(
                                    session, "policy_usage", {
                                        "username": username,
                                        "start": query.get("start", [""])[0],
                                        "end": query.get("end", [""])[0],
                                        "device_ids": query.get("device_id", []),
                                    },
                                )
                            else:
                                result = self._backend_user_call(
                                    session, "policy_overview", {
                                        "username": unquote(relative),
                                    },
                                )
                            return self._json(HTTPStatus.OK, result)
                        except Exception as error:
                            return self._backend_proxy_error(error)
                    action_prefix = "/api/v1/actions/"
                    if parsed.path.startswith(action_prefix):
                        session = self._require_session()
                        if not session:
                            return
                        if not self._has_backend_proxy(session):
                            return self._json(HTTPStatus.SERVICE_UNAVAILABLE, {
                                "error": "Suivi multi-ordinateur indisponible.",
                            })
                        command_id = parsed.path[len(action_prefix):].strip("/")
                        query = parse_qs(parsed.query)
                        try:
                            result = self._backend_user_call(
                                session, "device_action_status", {
                                    "command_id": command_id,
                                    "device_id": str(
                                        query.get("device_id", [""])[0]
                                    ),
                                },
                            )
                            return self._json(HTTPStatus.OK, result)
                        except Exception as error:
                            return self._backend_proxy_error(error)
                    if parsed.path == "/api/v1/overview":
                        session = self._require_session()
                        if not session:
                            return
                        query = parse_qs(parsed.query)
                        selection = {
                            key: values[0] for key, values in query.items()
                            if key in {
                                "scope", "day", "date", "start", "end",
                                "since", "before", "tz", "device_id",
                            }
                        }
                        if str(selection.get("device_id") or "") == "local":
                            backend = owner.backend_client or getattr(
                                owner.backend_manager, "client", None
                            )
                            actual_device_id = str(
                                getattr(backend, "device_id", "") or ""
                            ).strip()
                            if actual_device_id:
                                selection["device_id"] = actual_device_id
                            else:
                                selection.pop("device_id", None)
                        scope = str(selection.get("scope") or "today")
                        required = {
                            "today": "view_activity",
                            "session": "view_activity",
                            "limits": "view_limits",
                            "notifications": "view_notifications",
                        }.get(scope, "view_analysis")
                        if not session["is_admin"] and not session["permissions"].get(required):
                            return self._json(
                                HTTPStatus.FORBIDDEN,
                                {"error": "Cette vue n’est pas autorisée."},
                            )
                        if scope == "notifications" and self._has_backend_proxy(session):
                            query = parse_qs(parsed.query)
                            try:
                                return self._json(
                                    HTTPStatus.OK,
                                    self._backend_user_call(
                                        session, "notification_overview", {
                                            "owner": str(
                                                query.get(
                                                    "owner", [session["username"]]
                                                )[0] or session["username"]
                                            ),
                                            "device_id": str(
                                                query.get("device_id", [""])[0]
                                            ),
                                        },
                                    ),
                                )
                            except Exception as error:
                                requested_device = str(
                                    query.get("device_id", [""])[0]
                                )
                                if not self._targets_local_device(requested_device):
                                    return self._backend_proxy_error(error)
                        if self._has_backend_proxy(session):
                            try:
                                return self._json(
                                    HTTPStatus.OK,
                                    self._backend_user_call(
                                        session, "analysis_overview", selection,
                                    ),
                                )
                            except Exception as error:
                                if not self._targets_local_device(
                                    selection.get("device_id")
                                ):
                                    return self._backend_proxy_error(error)
                        if scope == "all":
                            # The legacy provider may own a very large desktop
                            # archive.  Never ask it to serialize that archive;
                            # historical analysis requires the normalized,
                            # cursor-paginated backend.
                            return self._json(HTTPStatus.SERVICE_UNAVAILABLE, {
                                "error": (
                                    "Historique normalisé momentanément "
                                    "indisponible."
                                ),
                            })
                        snapshot = owner.snapshot_provider(selection)
                        if not session["is_admin"] and not session["permissions"].get("view_limits"):
                            snapshot = {
                                **snapshot, "limits": [], "merge_candidates": [],
                                "computer_block": {}, "pending_limit_commands": [],
                            }
                        rules = snapshot.get("notification_rules", [])
                        if scope == "notifications":
                            query = parse_qs(parsed.query)
                            requested_owner = str(
                                query.get(
                                    "owner", [session["username"]]
                                )[0] or session["username"]
                            ).strip()
                            if (
                                not session["is_admin"]
                                and requested_owner.casefold()
                                != session["username"].casefold()
                            ):
                                return self._json(HTTPStatus.FORBIDDEN, {
                                    "error": "Notifications de cette personne non autorisées.",
                                })
                            rules = [
                                item for item in rules
                                if item.get("mandatory")
                                or str(item.get("owner", "")).casefold()
                                == requested_owner.casefold()
                                or (
                                    session["is_admin"]
                                    and requested_owner.casefold()
                                    == session["username"].casefold()
                                    and not str(item.get("owner", "")).strip()
                                )
                            ]
                        if not session["is_admin"] and not session["permissions"].get("view_notifications"):
                            rules = [item for item in rules if item.get("mandatory")]
                        elif not session["is_admin"] and scope != "notifications":
                            rules = [
                                item for item in rules
                                if item.get("mandatory")
                                or str(item.get("owner", "")).casefold()
                                == session["username"].casefold()
                            ]
                        snapshot = {**snapshot, "notification_rules": rules}
                        status = HTTPStatus.SERVICE_UNAVAILABLE if "error" in snapshot else HTTPStatus.OK
                        return self._json(status, snapshot)
                    if parsed.path == "/api/v1/backend/traffic":
                        return self._backend_traffic("GET")
                    if parsed.path == "/api/v1/backend/users":
                        return self._backend_users("GET")
                    if parsed.path == "/api/v1/admin/users":
                        return self._backend_users("GET")
                    if parsed.path == "/api/v1/backend/email":
                        return self._backend_email("GET")
                    if parsed.path == "/api/v1/backend/update":
                        return self._backend_update("GET")
                    return self._json(HTTPStatus.NOT_FOUND, {"error": "Endpoint inconnu."})
                return self._static(parsed.path)

            def do_PUT(self):
                if not self._valid_host():
                    return self._json(HTTPStatus.MISDIRECTED_REQUEST, {"error": "Hôte refusé."})
                self._command("set_limit")

            def do_DELETE(self):
                if not self._valid_host():
                    return self._json(HTTPStatus.MISDIRECTED_REQUEST, {"error": "Hôte refusé."})
                parsed = urlparse(self.path)
                if parsed.path.startswith((
                    "/api/v1/backend/users/", "/api/v1/admin/users/",
                )):
                    return self._backend_users("DELETE")
                self._command("remove_limit")

            def do_POST(self):
                if not self._valid_host():
                    return self._json(HTTPStatus.MISDIRECTED_REQUEST, {"error": "Hôte refusé."})
                parsed = urlparse(self.path)
                if parsed.path == "/api/v1/auth/login":
                    if not self._authorized(parsed):
                        return self._unauthorized()
                    try:
                        length = self._content_length()
                        payload = json.loads(self.rfile.read(length).decode("utf-8"))
                        if not isinstance(payload, dict):
                            raise ValueError
                    except (ValueError, json.JSONDecodeError):
                        return self._json(HTTPStatus.BAD_REQUEST, {"error": "JSON invalide."})
                    password = str(payload.get("password") or "")
                    authenticator = owner.admin_authenticator
                    if not password:
                        authenticator = owner.windows_session_authenticator
                    if authenticator is None:
                        return self._json(HTTPStatus.SERVICE_UNAVAILABLE, {
                            "error": "Authentification Usage Guard indisponible.",
                        })
                    try:
                        user = (
                            authenticator()
                            if not password else
                            authenticator(
                                payload.get("username"), password,
                                payload.get("email"),
                            )
                        )
                    except Exception as error:
                        message = getattr(error, "reason", None)
                        if hasattr(error, "read"):
                            try:
                                message = json.loads(error.read().decode("utf-8")).get("error", message)
                            except Exception:
                                pass
                        if not message and isinstance(
                            error, (RuntimeError, PermissionError, TimeoutError, ValueError)
                        ):
                            message = str(error).strip()
                        if not message:
                            message = "Connexion administrateur refusée."
                        return self._json(HTTPStatus.UNAUTHORIZED, {"error": str(message)})
                    if not password and (
                        user.get("is_admin")
                        or str(user.get("username") or "").casefold()
                        != str(payload.get("username") or "").strip().casefold()
                    ):
                        return self._json(HTTPStatus.UNAUTHORIZED, {
                            "error": "La session Windows proposée ne correspond pas."
                        })
                    if user.get("must_change"):
                        return self._json(HTTPStatus.FORBIDDEN, {
                            "error": "Changez d’abord ce mot de passe depuis la PWA distante.",
                        })
                    if user.get("must_set_email"):
                        return self._json(HTTPStatus.OK, {
                            "authenticated": False,
                            "username": str(user.get("username") or ""),
                            "email": "",
                            "must_set_email": True,
                            "is_admin": bool(user.get("is_admin")),
                        })
                    admin_token, session = owner._issue_admin_session(user)
                    return self._json(HTTPStatus.OK, {
                        "authenticated": True,
                        **owner._public_admin_session(session),
                        "admin_token": admin_token,
                    })
                if parsed.path == "/api/v1/auth/logout":
                    if not self._authorized(parsed):
                        return self._unauthorized()
                    owner._drop_admin_session(self.headers.get(ADMIN_HEADER, ""))
                    return self._json(HTTPStatus.OK, {"ok": True})
                if parsed.path in {"/api/v1/backend/email", "/api/v1/backend/email/test"}:
                    if not self._authorized(parsed):
                        return self._unauthorized()
                    try:
                        length = self._content_length()
                        payload = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
                        if not isinstance(payload, dict):
                            raise ValueError
                    except (ValueError, json.JSONDecodeError):
                        return self._json(HTTPStatus.BAD_REQUEST, {"error": "JSON invalide."})
                    return self._backend_email("TEST" if parsed.path.endswith("/test") else "POST", payload)
                if parsed.path == "/api/v1/backend/device/rename":
                    if not self._authorized(parsed):
                        return self._unauthorized()
                    try:
                        length = self._content_length()
                        payload = json.loads(self.rfile.read(length).decode("utf-8"))
                        if not isinstance(payload, dict):
                            raise ValueError
                    except (ValueError, json.JSONDecodeError):
                        return self._json(HTTPStatus.BAD_REQUEST, {"error": "JSON invalide."})
                    return self._backend_device("RENAME", payload)
                policy_prefix = "/api/v1/policies/"
                catalog_prefix = "/api/v1/catalogs/"
                policy_action = (
                    parsed.path.startswith(policy_prefix)
                    and parsed.path.endswith("/actions")
                )
                policy_cancel = (
                    parsed.path.startswith(policy_prefix)
                    and "/operations/" in parsed.path
                    and parsed.path.endswith("/cancel")
                )
                catalog_action = (
                    parsed.path.startswith(catalog_prefix)
                    and parsed.path.endswith("/actions")
                )
                if policy_action or policy_cancel or catalog_action:
                    if not self._authorized(parsed):
                        return self._unauthorized()
                    session = self._require_session()
                    if not session:
                        return
                    if not self._has_backend_proxy(session):
                        return self._json(HTTPStatus.SERVICE_UNAVAILABLE, {
                            "error": "Synchronisation multi-ordinateur indisponible.",
                        })
                    try:
                        length = self._content_length()
                        payload = (
                            json.loads(self.rfile.read(length).decode("utf-8"))
                            if length else {}
                        )
                        if not isinstance(payload, dict):
                            raise ValueError
                    except (ValueError, json.JSONDecodeError):
                        return self._json(
                            HTTPStatus.BAD_REQUEST, {"error": "JSON invalide."},
                        )
                    try:
                        if catalog_action:
                            username = unquote(parsed.path[
                                len(catalog_prefix):-len("/actions")
                            ].strip("/"))
                            result = self._backend_user_call(
                                session, "catalog_action", {
                                    "username": username, "command": payload,
                                },
                            )
                        elif policy_cancel:
                            relative = parsed.path[
                                len(policy_prefix):-len("/cancel")
                            ].rstrip("/")
                            username, operation_id = relative.split(
                                "/operations/", 1,
                            )
                            result = self._backend_user_call(
                                session, "cancel_policy_operation", {
                                    "username": unquote(username.strip("/")),
                                    "operation_id": operation_id.strip("/"),
                                },
                            )
                        else:
                            username = unquote(parsed.path[
                                len(policy_prefix):-len("/actions")
                            ].strip("/"))
                            result = self._backend_user_call(
                                session, "policy_action", {
                                    "username": username, "command": payload,
                                },
                            )
                        return self._json(
                            HTTPStatus.OK if policy_cancel else HTTPStatus.ACCEPTED,
                            result,
                        )
                    except Exception as error:
                        return self._backend_proxy_error(error)
                action_prefix = "/api/v1/actions/"
                if (
                    parsed.path.startswith(action_prefix)
                    and parsed.path.endswith("/cancel")
                ):
                    if not self._authorized(parsed):
                        return self._unauthorized()
                    session = self._require_session()
                    if not session:
                        return
                    if not self._has_backend_proxy(session):
                        return self._json(HTTPStatus.SERVICE_UNAVAILABLE, {
                            "error": "Annulation multi-ordinateur indisponible.",
                        })
                    try:
                        length = self._content_length()
                        payload = (
                            json.loads(self.rfile.read(length).decode("utf-8"))
                            if length else {}
                        )
                        if not isinstance(payload, dict):
                            raise ValueError
                    except (ValueError, json.JSONDecodeError):
                        return self._json(
                            HTTPStatus.BAD_REQUEST, {"error": "JSON invalide."},
                        )
                    command_id = parsed.path[
                        len(action_prefix):-len("/cancel")
                    ].strip("/")
                    try:
                        result = self._backend_user_call(
                            session, "cancel_device_action", {
                                "command_id": command_id,
                                "device_id": payload.get("device_id"),
                            },
                        )
                        return self._json(HTTPStatus.OK, result)
                    except Exception as error:
                        return self._backend_proxy_error(error)
                if parsed.path == "/api/v1/actions":
                    if not self._authorized(parsed):
                        return self._unauthorized()
                    session = self._require_session()
                    if not session:
                        return
                    try:
                        length = self._content_length()
                        command = json.loads(self.rfile.read(length).decode("utf-8"))
                        if not isinstance(command, dict):
                            raise ValueError
                    except (ValueError, json.JSONDecodeError):
                        return self._json(HTTPStatus.BAD_REQUEST, {"error": "JSON invalide."})
                    action = str(command.get("action") or "")
                    permanent_delete = action in {
                        "delete_target", "delete_site",
                    }
                    notification_mutation = action in {
                        "set_notification_rule", "remove_notification_rule",
                    }
                    if not session.get("is_admin"):
                        required = (
                            "manage_notifications"
                            if action in LOCAL_USER_NOTIFICATION_ACTIONS
                            else "manage_activity"
                            if action in LOCAL_USER_ACTIVITY_ACTIONS
                            else ""
                        )
                        if not required or not session.get(
                            "permissions", {}
                        ).get(required):
                            return self._json(HTTPStatus.FORBIDDEN, {
                                "error": "Modification non autorisée pour ce compte.",
                            })
                        if (
                            permanent_delete
                            and not session.get("permissions", {}).get(
                                "manage_limits"
                            )
                        ):
                            return self._json(HTTPStatus.FORBIDDEN, {
                                "error": (
                                    "La suppression définitive exige le droit "
                                    "de modifier les limitations."
                                ),
                            })
                        if notification_mutation:
                            if action == "set_notification_rule":
                                command = {
                                    **command,
                                    "rule": {
                                        **dict(command.get("rule") or {}),
                                        "owner": session["username"],
                                    },
                                }
                            else:
                                command["notification_owner"] = session["username"]
                    elif notification_mutation:
                        requested_owner = str(
                            (
                                dict(command.get("rule") or {}).get("owner")
                                if action == "set_notification_rule" else
                                command.get("notification_owner")
                            ) or session["username"]
                        ).strip()
                        if action == "set_notification_rule":
                            command = {
                                **command,
                                "rule": {
                                    **dict(command.get("rule") or {}),
                                    "owner": requested_owner,
                                },
                            }
                        else:
                            command["notification_owner"] = requested_owner
                    if permanent_delete:
                        if action == "delete_target":
                            deletion_target = str(
                                command.get("target_key") or ""
                            ).strip()
                        else:
                            browser = str(
                                command.get("browser") or ""
                            ).strip().lower()
                            host = _site_host(command.get("host")) or str(
                                command.get("host") or ""
                            ).strip().lower()
                            deletion_target = (
                                f"site:{browser}:{host}"
                                if browser and host else ""
                            )
                        can_manage_limits = bool(
                            session.get("is_admin")
                            or session.get("permissions", {}).get(
                                "manage_limits"
                            )
                        )
                        can_manage_other = bool(
                            session.get("is_admin")
                            or session.get("permissions", {}).get(
                                "manage_other_limits"
                            )
                        )
                        if can_manage_limits and not can_manage_other:
                            snapshot = owner.snapshot_provider({
                                "scope": "limits",
                            }) or {}
                            impacted = [
                                item for item in snapshot.get("limits", [])
                                if isinstance(item, dict)
                                and (
                                    str(item.get("key") or "")
                                    == deletion_target
                                    or str(item.get("target_key") or "")
                                    == deletion_target
                                )
                            ]
                            other_owners = {
                                str(
                                    item.get("requested_by")
                                    or item.get("actor") or ""
                                ).strip().casefold()
                                for item in impacted
                                if str(
                                    item.get("requested_by")
                                    or item.get("actor") or ""
                                ).strip()
                            } - {str(session["username"]).casefold()}
                            if other_owners:
                                return self._json(HTTPStatus.FORBIDDEN, {
                                    "error": (
                                        "Cette activité possède une limitation "
                                        "demandée par une autre personne."
                                    ),
                                })
                        command[DELETE_LIMITS_AUTHORIZED_FIELD] = (
                            can_manage_limits
                        )
                        command[DELETE_OTHER_LIMITS_AUTHORIZED_FIELD] = (
                            can_manage_other
                        )
                    if command.get("device_id") and self._has_backend_proxy(session):
                        try:
                            proxy_action = (
                                "notification_action"
                                if notification_mutation else "device_action"
                            )
                            result = self._backend_user_call(
                                session, proxy_action, {
                                    "device_id": command.get("device_id"),
                                    "command": {
                                        key: value for key, value in command.items()
                                        if key != "device_id"
                                    },
                                },
                            )
                            return self._json(HTTPStatus.ACCEPTED, result)
                        except Exception as error:
                            if not self._targets_local_device(
                                command.get("device_id")
                            ):
                                return self._backend_proxy_error(error)
                    if not session.get("is_admin") and notification_mutation:
                            snapshot = owner.snapshot_provider({
                                "scope": "notifications",
                            })
                            rules = snapshot.get("notification_rules", [])
                            rule_id = str(
                                command.get("rule", {}).get("id", "")
                                if action == "set_notification_rule"
                                else command.get("rule_id", "")
                            )
                            existing = next((
                                item for item in rules
                                if str(item.get("id", "")) == rule_id
                            ), None)
                            existing_owner = str(
                                (existing or {}).get("owner", "")
                            ).strip()
                            if existing and (
                                existing.get("mandatory")
                                or existing_owner.casefold()
                                != session["username"].casefold()
                            ):
                                return self._json(HTTPStatus.FORBIDDEN, {
                                    "error": "Cette notification appartient à un autre utilisateur.",
                                })
                    command.pop("device_id", None)
                    command.pop("idempotency_key", None)
                    command.setdefault("actor", session["username"])
                    command = stamp_command(command, SOURCE_LOCAL_ADMIN)
                    command[SERVICE_ADMIN_TOKEN_FIELD] = str(
                        session.get("_service_admin_token") or ""
                    )
                    result = owner.command_handler(command)
                    return self._json(HTTPStatus.OK if result.get("ok") else HTTPStatus.BAD_REQUEST, result)
                if parsed.path == "/api/v1/backend/traffic/reset":
                    if not self._authorized(parsed):
                        return self._unauthorized()
                    return self._backend_traffic("RESET")
                if parsed.path == "/api/v1/backend/update/install":
                    return self._backend_update("INSTALL")
                if parsed.path in {
                    "/api/v1/backend/users", "/api/v1/admin/users",
                } or (
                    parsed.path.startswith((
                        "/api/v1/backend/users/", "/api/v1/admin/users/",
                    )) and parsed.path.endswith("/access")
                ):
                    if not self._authorized(parsed):
                        return self._unauthorized()
                    try:
                        length = self._content_length()
                        payload = json.loads(self.rfile.read(length).decode("utf-8"))
                        if not isinstance(payload, dict):
                            raise ValueError
                    except (ValueError, json.JSONDecodeError):
                        return self._json(HTTPStatus.BAD_REQUEST, {"error": "JSON invalide."})
                    return self._backend_users(
                        "ACCESS" if parsed.path.endswith("/access") else "POST", payload
                    )
                if parsed.path == "/api/v1/admin/device-enrollments" or (
                    parsed.path.startswith("/api/v1/admin/devices/")
                    and parsed.path.endswith("/rename")
                ):
                    if not self._authorized(parsed):
                        return self._unauthorized()
                    session = self._require_admin()
                    if not session:
                        return
                    try:
                        length = self._content_length()
                        payload = (
                            json.loads(self.rfile.read(length).decode("utf-8"))
                            if length else {}
                        )
                        if not isinstance(payload, dict):
                            raise ValueError
                    except (ValueError, json.JSONDecodeError):
                        return self._json(
                            HTTPStatus.BAD_REQUEST, {"error": "JSON invalide."},
                        )
                    try:
                        if parsed.path.endswith("/rename"):
                            device_id = unquote(parsed.path[
                                len("/api/v1/admin/devices/"):-len("/rename")
                            ].strip("/"))
                            result = self._backend_admin_call(
                                session, "rename_managed_device", {
                                    "device_id": device_id,
                                    "label": payload.get("label"),
                                },
                            )
                        else:
                            result = self._backend_admin_call(
                                session, "create_device_enrollment", payload,
                            )
                            if isinstance(result, dict):
                                result = dict(result)
                                backend_url = self._backend_base_url()
                                if backend_url:
                                    result.setdefault("backend_url", backend_url)
                        return self._json(HTTPStatus.OK, result)
                    except Exception as error:
                        return self._backend_proxy_error(error)
                if parsed.path.endswith("/reset"):
                    self._command("reset_limit")
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "Endpoint inconnu."})

            def do_OPTIONS(self):
                self.send_response(HTTPStatus.NO_CONTENT)
                self.send_header("Access-Control-Allow-Headers", f"Authorization, Content-Type, {ADMIN_HEADER}")
                self.send_header("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE")
                self.end_headers()

            def _backend_traffic(self, method):
                parsed = urlparse(self.path)
                if not self._authorized(parsed):
                    return self._unauthorized()
                session = self._require_admin()
                if not session:
                    return
                client = owner.backend_manager or owner.backend_client
                if client is None:
                    return self._json(HTTPStatus.OK, {
                        "enabled": False, "configured": False,
                        "uploaded_bytes": 0, "elapsed_seconds": 0,
                        "upload_rate_bytes_per_minute": 0,
                        "reset_at": None, "last_upload_at": None,
                    })
                stats = self._backend_admin_call(
                    session,
                    "reset_traffic_stats" if method == "RESET" else "traffic_stats",
                )
                return self._json(HTTPStatus.OK, stats)

            def _backend_users(self, method, payload=None):
                parsed = urlparse(self.path)
                if not self._authorized(parsed):
                    return self._unauthorized()
                session = self._require_admin()
                if not session:
                    return
                client = owner.backend_manager or owner.backend_client
                if client is None:
                    return self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Backend distant non configuré."})
                try:
                    if method == "GET":
                        result = self._backend_admin_call(session, "list_users")
                    elif method == "POST":
                        result = self._backend_admin_call(session, "create_user", payload)
                    elif method == "ACCESS":
                        prefix = (
                            "/api/v1/admin/users/"
                            if parsed.path.startswith("/api/v1/admin/users/")
                            else "/api/v1/backend/users/"
                        )
                        username = unquote(
                            parsed.path.removeprefix(prefix).removesuffix("/access").rstrip("/")
                        )
                        result = self._backend_admin_call(session, "update_user_access", {
                            **dict(payload or {}), "username": username,
                        })
                    else:
                        prefix = (
                            "/api/v1/admin/users/"
                            if parsed.path.startswith("/api/v1/admin/users/")
                            else "/api/v1/backend/users/"
                        )
                        username = unquote(parsed.path.removeprefix(prefix))
                        result = self._backend_admin_call(
                            session, "delete_user", {"username": username},
                        )
                    return self._json(HTTPStatus.OK, result)
                except Exception as error:
                    message = (
                        getattr(error, "reason", None)
                        or str(error).strip()
                        or "Communication avec le backend impossible."
                    )
                    if hasattr(error, "read"):
                        try:
                            message = json.loads(error.read().decode("utf-8")).get("error", message)
                        except Exception:
                            pass
                    return self._json(HTTPStatus.BAD_GATEWAY, {"error": str(message)})

            def _backend_device(self, method, payload=None):
                parsed = urlparse(self.path)
                if not self._authorized(parsed):
                    return self._unauthorized()
                session = self._require_admin()
                if not session:
                    return
                try:
                    result = self._backend_admin_call(
                        session, "rename_device", dict(payload or {})
                    )
                    return self._json(HTTPStatus.OK, result)
                except Exception as error:
                    message = (
                        getattr(error, "reason", None)
                        or str(error).strip()
                        or "Renommage impossible."
                    )
                    return self._json(HTTPStatus.BAD_GATEWAY, {"error": str(message)})

            def _backend_email(self, method, payload=None):
                parsed = urlparse(self.path)
                if not self._authorized(parsed):
                    return self._unauthorized()
                session = self._require_admin()
                if not session:
                    return
                client = owner.backend_manager or owner.backend_client
                if client is None:
                    return self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Backend distant non configuré."})
                try:
                    if method == "GET":
                        result = self._backend_admin_call(session, "email_settings")
                    elif method == "TEST":
                        result = self._backend_admin_call(
                            session, "test_email_settings", payload,
                        )
                    else:
                        result = self._backend_admin_call(
                            session, "save_email_settings", payload,
                        )
                    return self._json(HTTPStatus.OK, result)
                except Exception as error:
                    message = (
                        getattr(error, "reason", None)
                        or str(error).strip()
                        or "Communication avec le backend impossible."
                    )
                    if hasattr(error, "read"):
                        try:
                            message = json.loads(error.read().decode("utf-8")).get("error", message)
                        except Exception:
                            pass
                    return self._json(HTTPStatus.BAD_GATEWAY, {"error": str(message)})

            def _backend_update(self, method):
                parsed = urlparse(self.path)
                if not self._authorized(parsed):
                    return self._unauthorized()
                session = self._require_admin()
                if not session:
                    return
                try:
                    result = self._backend_admin_call(
                        session,
                        "install_update" if method == "INSTALL" else "update_status",
                    )
                    return self._json(HTTPStatus.OK, result)
                except Exception as error:
                    return self._json(HTTPStatus.BAD_GATEWAY, {
                        "error": str(error).strip() or "Mise à jour indisponible.",
                    })

            @staticmethod
            def _backend_session_token(session):
                return str(
                    session.get("_service_backend_token")
                    or session.get("_service_admin_token") or ""
                )

            def _local_device_id(self):
                backend = owner.backend_client or getattr(
                    owner.backend_manager, "client", None
                )
                return str(getattr(backend, "device_id", "local") or "local")

            def _targets_local_device(self, device_id):
                return str(device_id or "").strip() in {
                    "", "local", self._local_device_id(),
                }

            def _has_backend_proxy(self, session):
                manager = owner.backend_manager or owner.backend_client
                return bool(
                    manager and (
                        self._backend_session_token(session)
                        and hasattr(manager, "backend_admin")
                        or session.get("_backend_management_session")
                        and all(hasattr(manager, method) for method in (
                            "session_devices", "policy_users",
                            "notification_overview", "notification_action",
                            "analysis_overview", "policy_overview",
                            "policy_usage", "policy_action",
                            "cancel_policy_operation", "catalog_action",
                            "device_action", "device_action_status",
                            "cancel_device_action",
                        ))
                    )
                )

            def _backend_user_call(self, session, action, payload=None):
                manager = owner.backend_manager or owner.backend_client
                if not manager:
                    raise RuntimeError("Backend distant non configuré.")
                payload = dict(payload or {})
                token = self._backend_session_token(session)
                if token and hasattr(manager, "backend_admin"):
                    return manager.backend_admin(token, action, payload)
                management_session = dict(
                    session.get("_backend_management_session") or {}
                )
                direct = {
                    "session_devices": lambda: manager.session_devices(
                        management_session
                    ),
                    "policy_users": lambda: manager.policy_users(
                        management_session
                    ),
                    "notification_overview": lambda: manager.notification_overview(
                        payload.get("owner"), payload.get("device_id"),
                        management_session,
                    ),
                    "analysis_overview": lambda: manager.analysis_overview(
                        payload, management_session,
                    ),
                    "policy_overview": lambda: manager.policy_overview(
                        payload.get("username"), management_session,
                    ),
                    "policy_usage": lambda: manager.policy_usage(
                        payload.get("username"), payload, management_session,
                    ),
                    "policy_action": lambda: manager.policy_action(
                        payload.get("username"), payload.get("command"),
                        management_session,
                    ),
                    "cancel_policy_operation": lambda: (
                        manager.cancel_policy_operation(
                            payload.get("username"), payload.get("operation_id"),
                            management_session,
                        )
                    ),
                    "catalog_action": lambda: manager.catalog_action(
                        payload.get("username"), payload.get("command"),
                        management_session,
                    ),
                    "device_action": lambda: manager.device_action(
                        payload.get("command"), payload.get("device_id"),
                        management_session,
                    ),
                    "device_action_status": lambda: manager.device_action_status(
                        payload.get("command_id"), payload.get("device_id"),
                        management_session,
                    ),
                    "cancel_device_action": lambda: manager.cancel_device_action(
                        payload.get("command_id"), payload.get("device_id"),
                        management_session,
                    ),
                    "notification_action": lambda: manager.notification_action(
                        payload.get("command"), payload.get("device_id"),
                        management_session,
                    ),
                }
                if action not in direct:
                    raise ValueError("Opération backend inconnue.")
                return direct[action]()

            def _backend_proxy_error(self, error):
                message = (
                    getattr(error, "reason", None)
                    or str(error).strip()
                    or "Communication avec le backend impossible."
                )
                if hasattr(error, "read"):
                    try:
                        message = json.loads(
                            error.read().decode("utf-8")
                        ).get("error", message)
                    except Exception:
                        pass
                return self._json(
                    HTTPStatus.BAD_GATEWAY, {"error": str(message)},
                )

            def _backend_base_url(self):
                manager = owner.backend_manager or owner.backend_client
                candidates = [
                    getattr(manager, "base_url", ""),
                    dict(getattr(manager, "settings", {}) or {}).get("base_url", ""),
                    getattr(getattr(manager, "client", None), "base_url", ""),
                ]
                for candidate in candidates:
                    value = str(candidate or "").strip().rstrip("/")
                    if value:
                        return value
                return ""

            def _backend_admin_call(self, session, action, payload=None):
                manager = owner.backend_manager or owner.backend_client
                service_token = str(session.get("_service_admin_token") or "")
                if service_token and hasattr(manager, "backend_admin"):
                    return manager.backend_admin(
                        service_token, action, dict(payload or {}),
                    )
                direct = {
                    "list_users": lambda: manager.list_users(),
                    "create_user": lambda: manager.create_user(
                        payload.get("username"), payload.get("password"),
                        payload.get("email", ""),
                        payload.get("is_admin", False), payload.get("permissions", {}),
                        *(
                            (payload.get("role"), payload.get("device_ids"))
                            if any(key in payload for key in ("role", "device_ids"))
                            else ()
                        ),
                    ),
                    "delete_user": lambda: manager.delete_user(payload.get("username")),
                    "create_device_enrollment": lambda: (
                        manager.create_device_enrollment(payload)
                    ),
                    "rename_managed_device": lambda: manager.rename_managed_device(
                        payload.get("device_id"), payload.get("label"),
                    ),
                    "update_user_access": lambda: manager.update_user_access(
                        payload.get("username"), payload.get("is_admin", False),
                        payload.get("permissions", {}), payload.get("email"),
                        *(
                            (payload.get("role"), payload.get("device_ids"))
                            if any(key in payload for key in ("role", "device_ids"))
                            else ()
                        ),
                    ),
                    "rename_device": lambda: manager.rename_device(
                        payload.get("label"), management_session=session,
                    ),
                    "traffic_stats": lambda: manager.traffic_stats(),
                    "reset_traffic_stats": lambda: manager.reset_traffic_stats(),
                    "email_settings": lambda: manager.email_settings(),
                    "save_email_settings": lambda: manager.save_email_settings(payload),
                    "test_email_settings": lambda: manager.test_email_settings(
                        payload.get("recipient")
                    ),
                    "update_status": lambda: {
                        "state": "unsupported", "current_version": "inconnue",
                    },
                }
                if action not in direct:
                    raise ValueError("Opération backend inconnue.")
                return direct[action]()

            def _command(self, action):
                parsed = urlparse(self.path)
                if not self._authorized(parsed):
                    return self._unauthorized()
                session = self._require_admin()
                if not session:
                    return
                key = self._target_key(parsed.path)
                if not key:
                    return self._json(HTTPStatus.NOT_FOUND, {"error": "Cible absente."})
                try:
                    length = self._content_length()
                    payload = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
                    if not isinstance(payload, dict):
                        raise ValueError
                except (ValueError, json.JSONDecodeError):
                    return self._json(HTTPStatus.BAD_REQUEST, {"error": "JSON invalide."})
                command = {"action": action, "target_key": key}
                if action == "set_limit":
                    command["settings"] = payload
                command["actor"] = session["username"]
                command = stamp_command(command, SOURCE_LOCAL_ADMIN)
                command[SERVICE_ADMIN_TOKEN_FIELD] = str(
                    session.get("_service_admin_token") or ""
                )
                result = owner.command_handler(command)
                return self._json(HTTPStatus.OK if result.get("ok") else HTTPStatus.BAD_REQUEST, result)

            @staticmethod
            def _target_key(path):
                prefix = "/api/v1/limits/"
                if not path.startswith(prefix):
                    return ""
                key = unquote(path[len(prefix):])
                return key.removesuffix("/reset")

            def _authorized(self, parsed):
                header = self.headers.get("Authorization", "")
                token = header.removeprefix("Bearer ").strip()
                return secrets.compare_digest(token, owner.token)

            def _admin_session(self):
                return owner._admin_session(self.headers.get(ADMIN_HEADER, ""))

            def _require_session(self):
                session = self._admin_session()
                if not session:
                    self._admin_required()
                return session

            def _require_admin(self):
                session = self._require_session()
                if not session:
                    return None
                if not session.get("is_admin"):
                    self._discard_body()
                    self._json(
                        HTTPStatus.FORBIDDEN,
                        {"error": "Droits administrateur requis."},
                    )
                    return None
                return session

            def _valid_host(self):
                host = self.headers.get("Host", "").lower()
                allowed = {"127.0.0.1", "localhost", "[::1]"}
                return host in allowed or host.split(":", 1)[0] in allowed or host.startswith("[::1]:")

            def _content_length(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length < 0 or length > MAX_BODY:
                    raise ValueError("invalid payload size")
                return length

            def _is_loopback(self):
                return self.client_address[0] in {"127.0.0.1", "::1"}

            def _unauthorized(self):
                self._discard_body()
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "Jeton d'association requis."})

            def _admin_required(self):
                self._discard_body()
                self._json(HTTPStatus.FORBIDDEN, {"error": "Connexion requise."})

            def _discard_body(self):
                """Consume a rejected request body so Windows can send the HTTP response."""
                try:
                    length = self._content_length()
                    if length:
                        self.rfile.read(length)
                except (OSError, TypeError, ValueError):
                    pass

            def _static(self, request_path):
                relative = "index.html" if request_path in {"", "/"} else request_path.lstrip("/")
                candidate = (PWA_DIR / relative).resolve()
                if PWA_DIR.resolve() not in candidate.parents and candidate != PWA_DIR.resolve():
                    return self._json(HTTPStatus.FORBIDDEN, {"error": "Chemin invalide."})
                if not candidate.is_file():
                    candidate = PWA_DIR / "index.html"
                content_type = {".html": "text/html", ".css": "text/css", ".js": "application/javascript", ".json": "application/manifest+json", ".svg": "image/svg+xml"}.get(candidate.suffix, "application/octet-stream")
                body = candidate.read_bytes()
                self.send_response(HTTPStatus.OK)
                self._security_headers()
                self.send_header("Content-Type", f"{content_type}; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _json(self, status, payload):
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self._security_headers()
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _security_headers(self):
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'; style-src-attr 'unsafe-inline'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'")

            def log_message(self, *_args):
                pass

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True, name="remote-pwa")
        self._thread.start()

    def stop(self):
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        self._server = None
        self._thread = None
