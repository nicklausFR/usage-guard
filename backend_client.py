"""Outbound HTTPS client for the Usage Guard remote backend."""
import json
import os
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen

from usage_guard import APP_NAME, config, debug_log


def _json_hash(value):
    import hashlib
    raw = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _json_delta(old, new):
    if old == new:
        return None

    if isinstance(old, dict) and isinstance(new, dict):
        removed = [key for key in old if key not in new]
        added = {key: new[key] for key in new if key not in old}
        patched = {}
        for key in old.keys() & new.keys():
            child = _json_delta(old[key], new[key])
            if child is not None:
                patched[key] = child
        return {
            "kind": "dict",
            "remove": removed,
            "set": added,
            "patch": patched,
        }

    if isinstance(old, list) and isinstance(new, list):
        start = 0
        while (
            start < len(old)
            and start < len(new)
            and old[start] == new[start]
        ):
            start += 1

        old_stop = len(old)
        new_stop = len(new)
        while (
            old_stop > start
            and new_stop > start
            and old[old_stop - 1] == new[new_stop - 1]
        ):
            old_stop -= 1
            new_stop -= 1

        return {
            "kind": "list",
            "start": start,
            "stop": old_stop,
            "items": new[start:new_stop],
        }

    return {"kind": "value", "value": new}


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
        self._last_activity = None
        self._last_snapshot = None
        self._traffic_lock = threading.Lock()
        self._traffic_reset_at = time.time()
        self._uploaded_bytes = 0
        self._last_upload_at = None
        self._email_lock = threading.Lock()
        self._pending_email_notifications = deque(maxlen=100)

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
                detail = f" HTTP {error.code}" if isinstance(error, HTTPError) else ""
                debug_log(f"backend sync failed: {type(error).__name__}{detail}")
            self._stop.wait(self.poll_seconds)

    def _sync(self):
        publish_error = None
        try:
            self._publish_state()
        except Exception as error:
            publish_error = error
            detail = f" HTTP {error.code}" if isinstance(error, HTTPError) else ""
            debug_log(f"backend publish failed before commands: {type(error).__name__}{detail}")
        response = self._request(
            "GET", "/api/v1/agent/commands?" + urlencode({"device_id": self.device_id})
        )
        changed = False
        for command in response.get("commands", []):
            command_id = str(command.pop("id", ""))
            if command_id:
                command["_remote_command_id"] = command_id
            debug_log(f"backend command received: id={command_id or '-'} action={command.get('action', '-')}")
            result = self.command_handler(command)
            changed = changed or bool(result.get("ok"))
            if command_id:
                self._request("POST", f"/api/v1/agent/commands/{command_id}/ack", {
                    "device_id": self.device_id, "result": result,
                })
        if changed:
            try:
                self._publish_state()
            except Exception as error:
                detail = f" HTTP {error.code}" if isinstance(error, HTTPError) else ""
                debug_log(f"backend publish failed after commands: {type(error).__name__}{detail}")
        elif publish_error:
            self._flush_email_notifications()
            return
        self._flush_email_notifications()

    def _publish_state(self):
        activity_error = None
        if self.activity_provider:
            try:
                local = self.activity_provider()

                if self._last_activity is None:
                    remote = self._request(
                        "GET",
                        "/api/v1/agent/activity?"
                        + urlencode({"device_id": self.device_id}),
                    )
                    if (
                        remote.get("activity")
                        and not local.get("days")
                        and self.activity_importer
                    ):
                        self.activity_importer(remote["activity"])
                        local = self.activity_provider()

                    if remote.get("activity"):
                        self._last_activity = remote["activity"]

                self._last_activity = self._publish_document(
                    "/api/v1/agent/activity",
                    "activity",
                    self._last_activity,
                    local,
                )
            except Exception as error:
                activity_error = error

        snapshot = self.snapshot_provider()
        if "error" not in snapshot:
            self._last_snapshot = self._publish_document(
                "/api/v1/agent/snapshot",
                "snapshot",
                self._last_snapshot,
                snapshot,
            )
        if activity_error:
            raise activity_error

    def _publish_document(self, path, field, previous, current):
        if previous is None:
            self._request("POST", path, {
                "device_id": self.device_id,
                field: current,
            })
            return current

        delta = _json_delta(previous, current)
        if delta is None:
            return current

        try:
            self._request("POST", path, {
                "device_id": self.device_id,
                f"{field}_delta": delta,
                "base_hash": _json_hash(previous),
                "target_hash": _json_hash(current),
            })
        except HTTPError as error:
            if error.code != 409:
                raise
            self._request("POST", path, {
                "device_id": self.device_id,
                field: current,
            })

        return current

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
        with urlopen(request, timeout=60) as response:  # nosec B310
            content = response.read().decode("utf-8")
        if body:
            self._record_uploaded_bytes(len(body))
        return json.loads(content) if content else {}

    def email_settings(self):
        return self._request(
            "GET", "/api/v1/agent/email/settings?" + urlencode({"device_id": self.device_id})
        )

    def save_email_settings(self, settings):
        return self._request("POST", "/api/v1/agent/email/settings", {
            "device_id": self.device_id, "settings": dict(settings or {}),
        })

    def test_email_settings(self, recipient):
        return self._request("POST", "/api/v1/agent/email/test", {
            "device_id": self.device_id, "recipient": str(recipient or "").strip(),
        })

    def queue_email_notification(self, title, message, recipient):
        with self._email_lock:
            self._pending_email_notifications.append({
                "title": str(title or "Notification"),
                "message": str(message or ""),
                "recipient": str(recipient or "").strip(),
            })

    def _flush_email_notifications(self):
        while True:
            with self._email_lock:
                if not self._pending_email_notifications:
                    return
                notification = self._pending_email_notifications[0]
            self._request("POST", "/api/v1/agent/email/send", {
                "device_id": self.device_id,
                **notification,
            })
            with self._email_lock:
                if self._pending_email_notifications and self._pending_email_notifications[0] is notification:
                    self._pending_email_notifications.popleft()

    def _record_uploaded_bytes(self, byte_count):
        now = time.time()
        with self._traffic_lock:
            self._uploaded_bytes += max(0, int(byte_count or 0))
            self._last_upload_at = now

    def traffic_stats(self):
        with self._traffic_lock:
            reset_at = self._traffic_reset_at
            uploaded = self._uploaded_bytes
            last_upload_at = self._last_upload_at
        elapsed = max(0.0, time.time() - reset_at)
        return {
            "enabled": self.enabled,
            "configured": self.configured,
            "uploaded_bytes": uploaded,
            "elapsed_seconds": elapsed,
            "upload_rate_bytes_per_minute": uploaded / (elapsed / 60) if elapsed else 0.0,
            "reset_at": datetime.fromtimestamp(reset_at, timezone.utc).isoformat(timespec="seconds"),
            "last_upload_at": (
                datetime.fromtimestamp(last_upload_at, timezone.utc).isoformat(timespec="seconds")
                if last_upload_at else None
            ),
        }

    def reset_traffic_stats(self):
        with self._traffic_lock:
            self._traffic_reset_at = time.time()
            self._uploaded_bytes = 0
            self._last_upload_at = None
        return self.traffic_stats()
