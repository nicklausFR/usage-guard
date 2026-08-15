"""Outbound HTTPS client for the Usage Guard remote backend."""
import json
import os
import threading
from pathlib import Path
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen

from usage_guard import APP_NAME, config, debug_log


def backend_settings_path():
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    return base / APP_NAME / "backend.json"


def load_backend_settings():
    try:
        saved = json.loads(backend_settings_path().read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        saved = {}
    return {
        "enabled": bool(saved.get("enabled", getattr(config, "BACKEND_ENABLED", False))),
        "base_url": str(saved.get("base_url", getattr(config, "BACKEND_BASE_URL", ""))).rstrip("/"),
        "device_id": str(saved.get("device_id", getattr(config, "BACKEND_DEVICE_ID", ""))).strip(),
        "device_token": str(saved.get("device_token", "")).strip(),
        "poll_seconds": max(5, int(saved.get("poll_seconds", getattr(config, "BACKEND_POLL_SECONDS", 15)))),
    }


class BackendClient:
    def __init__(self, snapshot_provider, command_handler, settings=None, activity_provider=None, activity_importer=None):
        self.snapshot_provider = snapshot_provider
        self.command_handler = command_handler
        self.activity_provider = activity_provider
        self.activity_importer = activity_importer
        settings = dict(settings or load_backend_settings())
        self.enabled = bool(settings.get("enabled"))
        self.base_url = str(settings.get("base_url", "")).rstrip("/")
        self.device_id = str(settings.get("device_id", "")).strip()
        self.device_token = str(settings.get("device_token", "")).strip()
        self.poll_seconds = max(5, int(settings.get("poll_seconds", 15)))
        self._stop = threading.Event()
        self._thread = None

    @property
    def configured(self):
        parsed = urlparse(self.base_url)
        return bool(
            self.enabled and parsed.scheme == "https" and parsed.netloc
            and self.device_id and len(self.device_token) >= 32
        )

    def start(self):
        if self._thread is not None or not self.configured:
            return
        self._thread = threading.Thread(target=self._run, daemon=True, name="usage-guard-backend")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

    def _run(self):
        while not self._stop.is_set():
            try:
                self._sync()
            except Exception as error:
                debug_log(f"backend sync failed: {type(error).__name__}")
            self._stop.wait(self.poll_seconds)

    def _sync(self):
        self._publish_state()
        response = self._request(
            "GET", "/api/v1/agent/commands?" + urlencode({"device_id": self.device_id})
        )
        changed = False
        for command in response.get("commands", []):
            command_id = str(command.pop("id", ""))
            result = self.command_handler(command)
            changed = changed or bool(result.get("ok"))
            if command_id:
                self._request("POST", f"/api/v1/agent/commands/{command_id}/ack", {
                    "device_id": self.device_id, "result": result,
                })
        if changed:
            self._publish_state()

    def _publish_state(self):
        if self.activity_provider:
            remote = self._request("GET", "/api/v1/agent/activity?" + urlencode({"device_id": self.device_id}))
            local = self.activity_provider()
            if remote.get("activity") and not local.get("days") and self.activity_importer:
                self.activity_importer(remote["activity"])
                local = self.activity_provider()
            self._request("POST", "/api/v1/agent/activity", {
                "device_id": self.device_id, "activity": local,
            })
        snapshot = self.snapshot_provider()
        if "error" not in snapshot:
            analysis = self.snapshot_provider({"scope": "all"})
            if "error" not in analysis:
                snapshot["analysis"] = analysis
            self._request("POST", "/api/v1/agent/snapshot", {
                "device_id": self.device_id, "snapshot": snapshot,
            })

    def list_users(self):
        return self._request(
            "GET", "/api/v1/agent/users?" + urlencode({"device_id": self.device_id})
        )

    def create_user(self, username, password):
        return self._request("POST", "/api/v1/agent/users", {
            "device_id": self.device_id, "username": username, "password": password,
        })

    def delete_user(self, username):
        return self._request(
            "DELETE", "/api/v1/agent/users/" + quote(str(username), safe="") + "?"
            + urlencode({"device_id": self.device_id})
        )

    def update_user_access(self, username, is_admin, permissions):
        return self._request(
            "POST", "/api/v1/agent/users/" + quote(str(username), safe="") + "/access",
            {
                "device_id": self.device_id,
                "is_admin": bool(is_admin),
                "permissions": dict(permissions or {}),
            },
        )

    def _request(self, method, path, payload=None):
        if not self.configured:
            raise RuntimeError("Backend HTTPS configuration is incomplete or invalid")
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            self.base_url + path, data=body, method=method,
            headers={
                "Authorization": f"Bearer {self.device_token}",
                "Content-Type": "application/json", "Accept": "application/json",
            },
        )
        with urlopen(request, timeout=10) as response:  # nosec B310
            content = response.read().decode("utf-8")
        return json.loads(content) if content else {}
