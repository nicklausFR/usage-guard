"""Authenticated local API and PWA host for Usage Guard.

It is deliberately self-contained: deployment through a VPN or an HTTPS
reverse proxy can be added later without coupling the monitoring engine to a
specific cloud provider.
"""

import json
import secrets
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from usage_guard import APP_DIR, APP_NAME, config


PWA_DIR = APP_DIR / "pwa"
MAX_BODY = 2 * 1024 * 1024


def _token_path():
    configured = str(getattr(config, "REMOTE_API_TOKEN_PATH", "")).strip()
    if configured:
        return Path(configured).expanduser()
    import os
    base = Path(os.environ.get("LOCALAPPDATA", APP_DIR)) / APP_NAME
    port = int(getattr(config, "REMOTE_API_PORT", 8766))
    filename = (
        "remote-api-token.txt"
        if port == 8766
        else f"remote-api-token-{port}.txt"
    )
    return base / filename


class RemoteControlServer:
    def __init__(self, snapshot_provider, command_handler, backend_client=None):
        self.snapshot_provider = snapshot_provider
        self.command_handler = command_handler
        self.backend_client = backend_client
        self.host = str(getattr(config, "REMOTE_API_HOST", "127.0.0.1"))
        if self.host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("The local API must listen on loopback only")
        self.port = int(getattr(config, "REMOTE_API_PORT", 8766))
        self.token_path = _token_path()
        self.token = self._load_or_create_token()
        self._server = None
        self._thread = None

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
                    return self._json(HTTPStatus.OK, {"token": owner.token})
                if parsed.path.startswith("/api/"):
                    if not self._authorized(parsed):
                        return self._unauthorized()
                    if parsed.path == "/api/v1/overview":
                        query = parse_qs(parsed.query)
                        selection = {
                            key: values[0] for key, values in query.items()
                            if key in {"scope", "date", "start", "end"}
                        }
                        snapshot = owner.snapshot_provider(selection)
                        status = HTTPStatus.SERVICE_UNAVAILABLE if "error" in snapshot else HTTPStatus.OK
                        return self._json(status, snapshot)
                    if parsed.path == "/api/v1/backend/users":
                        return self._backend_users("GET")
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
                if parsed.path.startswith("/api/v1/backend/users/"):
                    return self._backend_users("DELETE")
                self._command("remove_limit")

            def do_POST(self):
                if not self._valid_host():
                    return self._json(HTTPStatus.MISDIRECTED_REQUEST, {"error": "Hôte refusé."})
                parsed = urlparse(self.path)
                if parsed.path == "/api/v1/actions":
                    if not self._authorized(parsed):
                        return self._unauthorized()
                    try:
                        length = self._content_length()
                        command = json.loads(self.rfile.read(length).decode("utf-8"))
                        if not isinstance(command, dict):
                            raise ValueError
                    except (ValueError, json.JSONDecodeError):
                        return self._json(HTTPStatus.BAD_REQUEST, {"error": "JSON invalide."})
                    result = owner.command_handler(command)
                    return self._json(HTTPStatus.OK if result.get("ok") else HTTPStatus.BAD_REQUEST, result)
                if parsed.path == "/api/v1/backend/users" or (
                    parsed.path.startswith("/api/v1/backend/users/") and parsed.path.endswith("/access")
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
                if parsed.path.endswith("/reset"):
                    self._command("reset_limit")
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "Endpoint inconnu."})

            def do_OPTIONS(self):
                self.send_response(HTTPStatus.NO_CONTENT)
                self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
                self.send_header("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE")
                self.end_headers()

            def _backend_users(self, method, payload=None):
                parsed = urlparse(self.path)
                if not self._authorized(parsed):
                    return self._unauthorized()
                client = owner.backend_client
                if client is None or not client.configured:
                    return self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Backend distant non configuré."})
                try:
                    if method == "GET":
                        result = client.list_users()
                    elif method == "POST":
                        result = client.create_user(payload.get("username"), payload.get("password"))
                    elif method == "ACCESS":
                        username = unquote(
                            parsed.path.removeprefix("/api/v1/backend/users/").removesuffix("/access").rstrip("/")
                        )
                        result = client.update_user_access(
                            username, payload.get("is_admin", False), payload.get("permissions", {})
                        )
                    else:
                        username = unquote(parsed.path.removeprefix("/api/v1/backend/users/"))
                        result = client.delete_user(username)
                    return self._json(HTTPStatus.OK, result)
                except Exception as error:
                    message = getattr(error, "reason", None) or "Communication avec le backend impossible."
                    if hasattr(error, "read"):
                        try:
                            message = json.loads(error.read().decode("utf-8")).get("error", message)
                        except Exception:
                            pass
                    return self._json(HTTPStatus.BAD_GATEWAY, {"error": str(message)})

            def _command(self, action):
                parsed = urlparse(self.path)
                if not self._authorized(parsed):
                    return self._unauthorized()
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
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "Jeton d'association requis."})

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
