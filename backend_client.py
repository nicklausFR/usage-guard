"""Outbound HTTPS client for the Usage Guard remote backend."""
import json
import hashlib
import hmac
import os
import threading
import time
from collections import deque
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen

from client_version import CLIENT_VERSION

from command_policy import SOURCE_BACKEND, stamp_command
from runtime_profile import current_profile

COMPACT_ACTIVITY_BATCH_BYTES = 512 * 1024
COMPACT_SNAPSHOT_BYTES = 4 * 1024 * 1024
TIMELINE_ENDPOINT_RETRY_SECONDS = 5 * 60


def _default_log(message):
    # Keep this client importable by the Windows service without importing the
    # desktop application and its Qt-related dependency graph.
    try:
        from usage_guard import debug_log
        debug_log(message)
    except Exception:
        pass


def _json_hash(value):
    import hashlib
    raw = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def activity_intervals_by_sid(activity):
    """Convert closed mapped foreground sessions into stable upload records."""
    groups = {}
    for source in dict(activity or {}).get("sessions", []):
        if not isinstance(source, dict) or source.get("kind") != "active":
            continue
        sid = str(source.get("windows_sid") or "").strip().upper()
        started_at = str(source.get("started_at") or "").strip()
        ended_at = str(source.get("ended_at") or "").strip()
        target_key = str(source.get("key") or "").strip()
        if (
            not source.get("windows_identity_mapped")
            or not sid.startswith("S-1-") or not started_at or not ended_at
            or not target_key
        ):
            continue
        try:
            opened = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
            closed = datetime.fromisoformat(ended_at.replace("Z", "+00:00"))
        except ValueError:
            continue
        if (
            opened.tzinfo is None or closed.tzinfo is None
            or closed <= opened
        ):
            continue
        try:
            revision = max(0, int(source.get("policy_revision") or 0))
        except (TypeError, ValueError):
            continue
        category_key = str(source.get("category") or "").strip()
        category_keys = list(dict.fromkeys(
            str(category).strip()
            for category in source.get("category_lineage", [])
            if str(category).strip()
        ))
        if category_key and category_key not in category_keys:
            category_keys.insert(0, category_key)
        identity = json.dumps([
            sid, source.get("windows_session_id"), source.get("id"),
            target_key, category_keys,
            started_at, ended_at, revision,
        ], ensure_ascii=False, separators=(",", ":"))
        interval = {
            "interval_id": "activity-" + hashlib.sha256(
                identity.encode("utf-8")
            ).hexdigest(),
            "target_key": target_key,
            "category_key": category_key,
            "category_keys": category_keys,
            "started_at": started_at,
            "ended_at": ended_at,
            "policy_revision": revision,
        }
        groups.setdefault(sid, []).append(interval)
    return groups


def live_activity_intervals(activity, observed_at=None):
    """Return the current mapped foreground intervals bounded by this heartbeat."""
    observed_at = str(observed_at or datetime.now(timezone.utc).isoformat(
        timespec="milliseconds"
    ))
    activity = dict(activity or {})
    sources = list(activity.get("sessions", []))
    open_sessions = activity.get("open_sessions", {})
    if isinstance(open_sessions, dict):
        sources.extend(open_sessions.values())
    elif isinstance(open_sessions, list):
        sources.extend(open_sessions)
    intervals = []
    seen = set()
    for source in sources:
        if (
            not isinstance(source, dict) or source.get("kind") != "active"
            or source.get("ended_at")
            or not source.get("windows_identity_mapped")
        ):
            continue
        sid = str(source.get("windows_sid") or "").strip().upper()
        started_at = str(source.get("started_at") or "").strip()
        target_key = str(source.get("key") or "").strip()
        if not sid.startswith("S-1-") or not started_at or not target_key:
            continue
        try:
            revision = max(0, int(source.get("policy_revision") or 0))
        except (TypeError, ValueError):
            continue
        category_key = str(source.get("category") or "").strip()
        category_keys = list(dict.fromkeys(
            str(category).strip()
            for category in source.get("category_lineage", [])
            if str(category).strip()
        ))
        if category_key and category_key not in category_keys:
            category_keys.insert(0, category_key)
        identity = json.dumps([
            sid, source.get("windows_session_id"), source.get("id"),
            target_key, category_keys, started_at, revision,
        ], ensure_ascii=False, separators=(",", ":"))
        live_id = "live-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()
        if live_id in seen:
            continue
        seen.add(live_id)
        intervals.append({
            "live_id": live_id,
            "windows_sid": sid, "target_key": target_key,
            "category_key": category_key, "category_keys": category_keys,
            "started_at": started_at, "observed_at": observed_at,
            "policy_revision": revision,
        })
    return intervals


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


def _bounded_json_batches(items, max_items=500, max_bytes=COMPACT_ACTIVITY_BATCH_BYTES):
    """Yield request-safe batches bounded by both count and encoded bytes."""
    batch, used = [], 2
    for source in items or []:
        item = dict(source or {})
        encoded_size = len(json.dumps(
            item, ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")) + (1 if batch else 0)
        if encoded_size + 2 > max_bytes:
            raise ValueError("compact activity record exceeds byte limit")
        if batch and (len(batch) >= max_items or used + encoded_size > max_bytes):
            yield batch
            batch, used = [], 2
            encoded_size -= 1
        batch.append(item)
        used += encoded_size
    if batch:
        yield batch


def backend_settings_path():
    return current_profile().local_data_directory() / "backend.json"


def load_backend_settings():
    from usage_guard import config
    try:
        saved = json.loads(backend_settings_path().read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        saved = {}
    profile = current_profile()
    return {
        "enabled": profile.allow_backend and bool(
            saved.get("enabled", getattr(config, "BACKEND_ENABLED", False))
        ),
        "base_url": str(saved.get("base_url", getattr(config, "BACKEND_BASE_URL", ""))).rstrip("/"),
        "device_id": str(saved.get("device_id", getattr(config, "BACKEND_DEVICE_ID", ""))).strip(),
        "device_token": str(saved.get("device_token", "")).strip(),
        "display_name": str(saved.get("display_name", "")).strip(),
        "poll_seconds": max(5, int(saved.get("poll_seconds", getattr(config, "BACKEND_POLL_SECONDS", 15)))),
    }


class BackendClient:
    def __init__(
        self, snapshot_provider, command_handler, settings=None,
        logger=None,
        status_provider=None, status_acknowledger=None,
        interval_provider=None, interval_acknowledger=None,
        timeline_provider=None, timeline_acknowledger=None,
        live_interval_provider=None, daily_aggregate_provider=None,
        daily_aggregate_acknowledger=None,
    ):
        self.snapshot_provider = snapshot_provider
        self.command_handler = command_handler
        self.status_provider = status_provider
        self.status_acknowledger = status_acknowledger
        self.interval_provider = interval_provider
        self.interval_acknowledger = interval_acknowledger
        self.timeline_provider = timeline_provider
        self.timeline_acknowledger = timeline_acknowledger
        self.live_interval_provider = live_interval_provider
        self.daily_aggregate_provider = daily_aggregate_provider
        self.daily_aggregate_acknowledger = daily_aggregate_acknowledger
        self.log = logger or _default_log
        settings = dict(settings or load_backend_settings())
        self.enabled = bool(settings.get("enabled"))
        self.base_url = str(settings.get("base_url", "")).rstrip("/")
        self.device_id = str(settings.get("device_id", "")).strip()
        self.device_token = str(settings.get("device_token", "")).strip()
        self.display_name = str(settings.get("display_name", "")).strip()
        self.poll_seconds = max(5, int(settings.get("poll_seconds", 15)))
        self._stop = threading.Event()
        self._thread = None
        self._status_thread = None
        self.heartbeat_seconds = 10
        self._last_snapshot = None
        self._timeline_retry_at = 0.0
        self._daily_aggregate_retry_at = 0.0
        self._traffic_lock = threading.Lock()
        self._traffic_reset_at = time.time()
        self._uploaded_bytes = 0
        self._last_upload_at = None
        self._email_lock = threading.Lock()
        self._pending_email_notifications = deque(maxlen=100)

    @property
    def configured(self):
        parsed = urlparse(self.base_url)
        secure_transport = parsed.scheme == "https" or (
            parsed.scheme == "http"
            and parsed.hostname in {"127.0.0.1", "::1", "localhost"}
        )
        return bool(
            self.enabled and secure_transport and parsed.netloc
            and self.device_id and len(self.device_token) >= 32
        )

    def start(self):
        if self._thread is not None or not self.configured:
            return
        self._thread = threading.Thread(target=self._run, daemon=True, name="usage-guard-backend")
        self._thread.start()
        if self.status_provider:
            self._status_thread = threading.Thread(
                target=self._run_status, daemon=True,
                name="usage-guard-backend-heartbeat",
            )
            self._status_thread.start()

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None
        if self._status_thread is not None:
            self._status_thread.join(timeout=3)
            self._status_thread = None

    def _run(self):
        while not self._stop.is_set():
            try:
                self._sync()
            except Exception as error:
                detail = f" HTTP {error.code}" if isinstance(error, HTTPError) else ""
                self.log(f"backend sync failed: {type(error).__name__}{detail}")
            self._stop.wait(self.poll_seconds)

    def _run_status(self):
        while not self._stop.is_set():
            self._publish_status()
            self._stop.wait(self.heartbeat_seconds)

    def _publish_status(self):
        if not self.status_provider:
            return
        try:
            status = self.status_provider()
            if isinstance(status, dict):
                response = self._request("POST", "/api/v1/agent/status", {
                    "device_id": self.device_id,
                    "status": status,
                })
                if self.status_acknowledger:
                    self.status_acknowledger(
                        response.get("accepted_event_ids", [])
                    )
        except HTTPError as error:
            if error.code != 404:
                self.log(f"backend status failed: HTTP {error.code}")
        except Exception as error:
            self.log(f"backend status failed: {type(error).__name__}")

    def _sync(self):
        publish_error = None
        try:
            self._publish_state()
        except Exception as error:
            publish_error = error
            detail = f" HTTP {error.code}" if isinstance(error, HTTPError) else ""
            self.log(f"backend publish failed before commands: {type(error).__name__}{detail}")
        response = self._request(
            "GET", "/api/v1/agent/commands?" + urlencode({"device_id": self.device_id})
        )
        changed = False
        for command in response.get("commands", []):
            command_id = str(command.get("id", ""))
            command = stamp_command(command, SOURCE_BACKEND, command_id=command_id)
            command.pop("id", None)
            self.log(f"backend command received: id={command_id or '-'} action={command.get('action', '-')}")
            result = dict(self.command_handler(command) or {})
            deferred = bool(result.pop("_defer_ack", False))
            changed = changed or bool(result.get("ok") and not deferred)
            if command_id and not deferred:
                self._request("POST", f"/api/v1/agent/commands/{command_id}/ack", {
                    "device_id": self.device_id, "result": result,
                })
        if changed:
            try:
                self._publish_state()
            except Exception as error:
                detail = f" HTTP {error.code}" if isinstance(error, HTTPError) else ""
                self.log(f"backend publish failed after commands: {type(error).__name__}{detail}")
        elif publish_error:
            self._flush_email_notifications()
            return
        self._flush_email_notifications()

    def _publish_state(self):
        activity_error = None
        try:
            self._publish_compact_activity()
        except Exception as error:
            activity_error = error
        snapshot = self.snapshot_provider()
        if "error" not in snapshot:
            snapshot_size = len(json.dumps(
                snapshot, ensure_ascii=False, separators=(",", ":"),
            ).encode("utf-8"))
            if snapshot_size > COMPACT_SNAPSHOT_BYTES:
                raise ValueError("compact snapshot exceeds byte limit")
            self._last_snapshot = self._publish_document(
                "/api/v1/agent/snapshot",
                "snapshot",
                self._last_snapshot,
                snapshot,
            )
        if activity_error:
            raise activity_error

    def _publish_compact_activity(self):
        if self.interval_provider:
            for sid, intervals in dict(self.interval_provider() or {}).items():
                for batch in _bounded_json_batches(intervals):
                    self.upload_activity_intervals(sid, batch)
                    if self.interval_acknowledger:
                        self.interval_acknowledger([
                            item["interval_id"] for item in batch
                        ])
        if (
            self.timeline_provider
            and time.monotonic() >= self._timeline_retry_at
        ):
            try:
                for sid, sessions in dict(self.timeline_provider() or {}).items():
                    for batch in _bounded_json_batches(sessions):
                        self.upload_activity_timeline(sid, batch)
                        if self.timeline_acknowledger:
                            self.timeline_acknowledger([
                                item["record_id"] for item in batch
                            ])
                self._timeline_retry_at = 0.0
            except HTTPError as error:
                if error.code != 404:
                    raise
                # Keep the durable generic outbox for an upgraded server and
                # retry periodically.  A server deployed after this service
                # started must drain the queue without requiring a restart.
                self._timeline_retry_at = (
                    time.monotonic() + TIMELINE_ENDPOINT_RETRY_SECONDS
                )
        if self.live_interval_provider:
            self.replace_live_activity_intervals(
                list(self.live_interval_provider() or [])[:256]
            )
        if (
            self.daily_aggregate_provider
            and time.monotonic() >= self._daily_aggregate_retry_at
        ):
            try:
                for sid, aggregates in dict(
                    self.daily_aggregate_provider() or {}
                ).items():
                    values = list(aggregates or [])
                    if not values:
                        continue
                    response = self.upload_activity_daily_aggregates(
                        values, sid,
                    )
                    if self.daily_aggregate_acknowledger:
                        self.daily_aggregate_acknowledger(
                            response.get("accepted_ids", []), sid,
                        )
                self._daily_aggregate_retry_at = 0.0
            except HTTPError as error:
                if error.code != 404:
                    raise
                self._daily_aggregate_retry_at = (
                    time.monotonic() + TIMELINE_ENDPOINT_RETRY_SECONDS
                )

    def _publish_document(
        self, path, field, previous, current, *, complete=None,
    ):
        mode = (
            {f"{field}_complete": bool(complete)}
            if complete is not None else {}
        )
        if previous is None:
            self._request("POST", path, {
                "device_id": self.device_id,
                field: current,
                **mode,
            })
            return current

        delta = _json_delta(previous, current)
        if delta is None:
            return current

        base = previous
        for _attempt in range(3):
            delta = _json_delta(base, current)
            if delta is None:
                return current
            try:
                self._request("POST", path, {
                    "device_id": self.device_id,
                    f"{field}_delta": delta,
                    "base_hash": _json_hash(base),
                    "target_hash": _json_hash(current),
                    **mode,
                })
                return current
            except HTTPError as error:
                if error.code != 409:
                    raise
                remote = self._request(
                    "GET", path + "?" + urlencode({"device_id": self.device_id})
                ).get(field)
                if remote is None:
                    break
                base = remote

        # Compatibility fallback for an empty/old server. Normally conflicts
        # are rebased above, avoiding a complete multi-megabyte upload.
        self._request("POST", path, {
            "device_id": self.device_id,
            field: current,
            **mode,
        })

        return current

    def list_users(self, management_session=None):
        return self._management_request(
            management_session, "GET", "/api/v1/admin/users"
        )

    def session_devices(self, management_session=None):
        """List devices visible to the authenticated PWA account."""
        return self._management_request(
            management_session, "GET", "/api/v1/devices"
        )

    def policy_users(self, management_session=None):
        """List notification owners and their device assignments."""
        return self._management_request(
            management_session, "GET", "/api/v1/policies"
        )

    def notification_overview(
        self, owner, device_id, management_session=None,
    ):
        query = urlencode({
            "scope": "notifications", "owner": str(owner or ""),
            "device_id": str(device_id or ""),
        })
        return self._management_request(
            management_session, "GET", "/api/v1/overview?" + query,
        )

    def analysis_overview(self, selection, management_session=None):
        """Read one bounded overview page through the authenticated backend."""
        allowed = {
            "scope", "day", "date", "start", "end", "since", "before",
            "tz", "device_id",
        }
        query = urlencode({
            key: str(value)
            for key, value in dict(selection or {}).items()
            if key in allowed and value is not None and str(value) != ""
        })
        return self._management_request(
            management_session, "GET",
            "/api/v1/overview" + ("?" + query if query else ""),
        )

    def notification_action(
        self, command, device_id, management_session=None,
    ):
        payload = {
            **dict(command or {}), "device_id": str(device_id or ""),
        }
        return self._management_request(
            management_session, "POST", "/api/v1/actions", payload,
        )

    def device_action(self, command, device_id, management_session=None):
        payload = {
            **dict(command or {}), "device_id": str(device_id or ""),
        }
        return self._management_request(
            management_session, "POST", "/api/v1/actions", payload,
        )

    def device_action_status(
        self, command_id, device_id, management_session=None,
    ):
        query = urlencode({"device_id": str(device_id or "")})
        return self._management_request(
            management_session, "GET",
            "/api/v1/actions/" + quote(str(command_id), safe="") + "?" + query,
        )

    def cancel_device_action(
        self, command_id, device_id, management_session=None,
    ):
        return self._management_request(
            management_session, "POST",
            "/api/v1/actions/" + quote(str(command_id), safe="") + "/cancel",
            {"device_id": str(device_id or "")},
        )

    def policy_overview(self, username, management_session=None):
        """Read one person's shared policy through the PWA session."""
        return self._management_request(
            management_session, "GET",
            "/api/v1/policies/" + quote(str(username), safe=""),
        )

    def policy_usage(self, username, selection, management_session=None):
        """Read the bounded usage summary used by the shared limit editor."""
        selection = dict(selection or {})
        query = []
        for key in ("start", "end"):
            value = str(selection.get(key) or "").strip()
            if value:
                query.append((key, value))
        for device_id in selection.get("device_ids") or []:
            value = str(device_id or "").strip()
            if value:
                query.append(("device_id", value))
        path = "/api/v1/policies/" + quote(str(username), safe="") + "/usage"
        if query:
            path += "?" + urlencode(query)
        return self._management_request(management_session, "GET", path)

    def policy_action(self, username, command, management_session=None):
        """Mutate a shared personal/computer policy for selected devices."""
        return self._management_request(
            management_session, "POST",
            "/api/v1/policies/" + quote(str(username), safe="") + "/actions",
            dict(command or {}),
        )

    def cancel_policy_operation(
        self, username, operation_id, management_session=None,
    ):
        return self._management_request(
            management_session, "POST",
            "/api/v1/policies/" + quote(str(username), safe="")
            + "/operations/" + quote(str(operation_id), safe="") + "/cancel",
            {},
        )

    def catalog_action(self, username, command, management_session=None):
        """Apply one shared catalogue mutation to the selected computers."""
        return self._management_request(
            management_session, "POST",
            "/api/v1/catalogs/" + quote(str(username), safe="") + "/actions",
            dict(command or {}),
        )

    def create_user(
        self, username, password, email="", is_admin=False, permissions=None,
        role=None, device_ids=None, management_session=None,
    ):
        return self._management_request(management_session, "POST", "/api/v1/admin/users", {
            "username": username,
            "password": password, "email": str(email or ""),
            "is_admin": bool(is_admin),
            "permissions": dict(permissions or {}),
            "role": str(role or ("admin" if is_admin else "limited")),
            "device_ids": list(device_ids if device_ids is not None else [self.device_id]),
        })

    def delete_user(self, username, management_session=None):
        return self._management_request(
            management_session, "DELETE",
            "/api/v1/admin/users/" + quote(str(username), safe=""),
        )

    def update_user_access(
        self, username, is_admin, permissions, email=None, role=None,
        device_ids=None, management_session=None,
    ):
        payload = {
            "is_admin": bool(is_admin),
            "permissions": dict(permissions or {}),
            "role": str(role or ("admin" if is_admin else "limited")),
        }
        if device_ids is not None:
            payload["device_ids"] = list(device_ids)
        if email is not None:
            payload["email"] = str(email or "")
        return self._management_request(
            management_session, "POST",
            "/api/v1/admin/users/" + quote(str(username), safe="") + "/access",
            payload,
        )

    def authenticate_user(self, username, password, email=""):
        """Authenticate an application user through the public HTTPS backend."""
        if not self.configured:
            raise RuntimeError("Backend HTTPS configuration is incomplete or invalid")
        body = json.dumps({
            "username": str(username or ""),
            "password": str(password or ""),
            "email": str(email or ""),
        }).encode("utf-8")
        request = Request(
            self.base_url + "/api/v1/auth/login",
            data=body,
            method="POST",
            headers={
                "Origin": (
                    f"{urlparse(self.base_url).scheme}://"
                    f"{urlparse(self.base_url).netloc}"
                ),
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        with urlopen(request, timeout=30) as response:  # nosec B310
            content = response.read().decode("utf-8")
            cookie = str(response.headers.get("Set-Cookie") or "").split(";", 1)[0]
        result = json.loads(content) if content else {}
        if cookie and result.get("csrf_token"):
            result["_backend_management_session"] = {
                "cookie": cookie,
                "csrf_token": result["csrf_token"],
                "expires_at": result.get("expires_at"),
            }
        return result

    def _management_request(self, session, method, path, payload=None):
        session = dict(session or {})
        cookie = str(session.get("cookie") or "")
        csrf = str(session.get("csrf_token") or "")
        if not cookie or not csrf:
            raise PermissionError("Session serveur administrateur absente.")
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        parsed = urlparse(self.base_url)
        request = Request(
            self.base_url + path, data=body, method=method,
            headers={
                "Origin": f"{parsed.scheme}://{parsed.netloc}",
                "Cookie": cookie, "X-CSRF-Token": csrf,
                "Content-Type": "application/json", "Accept": "application/json",
            },
        )
        with urlopen(request, timeout=60) as response:  # nosec B310
            content = response.read().decode("utf-8")
        if body:
            self._record_uploaded_bytes(len(body))
        return json.loads(content) if content else {}

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

    def email_settings(self, management_session=None):
        return self._management_request(
            management_session, "GET", "/api/v1/email/settings"
        )

    def update_manifest(self):
        return self._request(
            "GET", "/api/v1/agent/update?" + urlencode({
                "device_id": self.device_id,
                "current_version": CLIENT_VERSION,
            })
        ).get("update")

    def windows_identities(self):
        """Return only the SID mappings belonging to this device."""
        result = self._request(
            "GET", "/api/v1/agent/windows-identities?" + urlencode({
                "device_id": self.device_id,
            }),
        )
        self.display_name = str(
            dict(result.get("device") or {}).get("display_name")
            or self.display_name
        ).strip()
        return result.get("windows_identities", [])

    def create_device_enrollment(self, payload, management_session=None):
        return self._management_request(
            management_session, "POST", "/api/v1/admin/device-enrollments",
            dict(payload or {}),
        )

    def rename_managed_device(
        self, device_id, label, management_session=None,
    ):
        return self._management_request(
            management_session, "POST",
            "/api/v1/admin/devices/" + quote(str(device_id), safe="")
            + "/rename",
            {"label": str(label or "").strip()},
        )

    def rename_device(self, label, management_session=None):
        result = self._management_request(
            management_session, "POST",
            "/api/v1/admin/devices/" + quote(self.device_id, safe="") + "/rename",
            {"label": str(label or "").strip()},
        )
        self.display_name = str(
            dict(result.get("device") or {}).get("label") or self.display_name
        ).strip()
        return result

    def begin_update_maintenance(self, version, duration_seconds=900):
        """Declare the expected service interruption before installing."""
        return self._request("POST", "/api/v1/agent/maintenance", {
            "device_id": self.device_id,
            "version": str(version or "").strip(),
            "duration_seconds": max(60, min(1800, int(duration_seconds))),
        })

    def user_policy(self, windows_sid):
        """Fetch the desired policy for one SID on this device only."""
        return self._request(
            "GET", "/api/v1/agent/policy?" + urlencode({
                "device_id": self.device_id,
                "windows_sid": str(windows_sid or "").strip().upper(),
            }),
        )

    def acknowledge_user_policy(self, windows_sid, revision, result):
        """Report the revision actually applied for this device and SID."""
        return self._request(
            "POST", "/api/v1/agent/policy/ack", {
                "device_id": self.device_id,
                "windows_sid": str(windows_sid or "").strip().upper(),
                "revision": int(revision),
                "result": dict(result or {}),
            },
        ).get("policy")

    def push_user_policy_action(
        self, windows_sid, command, idempotency_key, actor="",
    ):
        """Publish one durable local limit mutation for this mapped SID."""
        return self._request(
            "POST", "/api/v1/agent/policy/actions", {
                "device_id": self.device_id,
                "windows_sid": str(windows_sid or "").strip().upper(),
                "command": dict(command or {}),
                "idempotency_key": str(idempotency_key or "").strip(),
                "actor": str(actor or "").strip(),
            },
        )

    def push_user_catalog_action(
        self, windows_sid, command, idempotency_key, actor="",
    ):
        """Publish one local classification mutation for every mapped device."""
        return self._request(
            "POST", "/api/v1/agent/catalog/actions", {
                "device_id": self.device_id,
                "windows_sid": str(windows_sid or "").strip().upper(),
                "command": dict(command or {}),
                "idempotency_key": str(idempotency_key or "").strip(),
                "actor": str(actor or "").strip(),
            },
        )

    def upload_activity_intervals(self, windows_sid, intervals):
        """Upload idempotent timestamped intervals for this device and SID."""
        return self._request(
            "POST", "/api/v1/agent/activity/intervals", {
                "device_id": self.device_id,
                "windows_sid": str(windows_sid or "").strip().upper(),
                "intervals": list(intervals or []),
            },
        )

    def upload_activity_timeline(self, windows_sid, sessions):
        """Upload idempotent non-counting timeline records for one SID."""
        return self._request(
            "POST", "/api/v1/agent/activity/timeline", {
                "device_id": self.device_id,
                "windows_sid": str(windows_sid or "").strip().upper(),
                "sessions": list(sessions or []),
            },
        )

    def upload_activity_daily_aggregates(self, aggregates, windows_sid=""):
        """Upload a bounded analysis-only daily aggregate batch."""
        return self._request(
            "POST", "/api/v1/agent/activity/daily-aggregates", {
                "device_id": self.device_id, "schema_version": 1,
                "windows_sid": str(windows_sid or "").strip().upper(),
                "aggregates": list(aggregates or []),
            },
        )

    def replace_live_activity_intervals(self, intervals):
        """Replace this device's bounded current intervals in one atomic request."""
        return self._request(
            "POST", "/api/v1/agent/activity/live", {
                "device_id": self.device_id,
                "live_intervals": list(intervals or []),
            },
        )

    def user_usage_union(
        self, windows_sid, start, end, target_key=None, category_key=None,
    ):
        query = {
            "device_id": self.device_id,
            "windows_sid": str(windows_sid or "").strip().upper(),
            "start": str(start or ""), "end": str(end or ""),
        }
        if target_key is not None:
            query["target_key"] = str(target_key)
        if category_key is not None:
            query["category_key"] = str(category_key)
        return self._request(
            "GET", "/api/v1/agent/activity/union?" + urlencode(query),
        )

    def download_update(self, update, destination):
        update = dict(update or {})
        expected_hash = str(update.get("sha256") or "").lower()
        expected_size = int(update.get("size") or -1)
        if len(expected_hash) != 64 or expected_size < 1:
            raise ValueError("Manifest de mise à jour invalide.")
        destination = os.fspath(destination)
        temporary = destination + ".tmp"
        path = str(update.get("download_path") or "/api/v1/agent/update/package")
        separator = "&" if "?" in path else "?"
        request = Request(
            self.base_url + path + separator + urlencode({"device_id": self.device_id}),
            method="GET",
            headers={
                "Authorization": f"Bearer {self.device_token}",
                "Accept": "application/zip",
            },
        )
        digest, size = hashlib.sha256(), 0
        try:
            with urlopen(request, timeout=120) as response, open(temporary, "wb") as stream:  # nosec B310
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > expected_size:
                        raise ValueError("Paquet de mise à jour plus grand que prévu.")
                    digest.update(chunk)
                    stream.write(chunk)
            if size != expected_size or not hmac.compare_digest(digest.hexdigest(), expected_hash):
                raise ValueError("Intégrité du paquet de mise à jour refusée.")
            os.replace(temporary, destination)
        except Exception:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
        return destination

    def save_email_settings(self, settings, management_session=None):
        return self._management_request(
            management_session, "POST", "/api/v1/email/settings",
            dict(settings or {}),
        )

    def test_email_settings(self, recipient, management_session=None):
        return self._management_request(
            management_session, "POST", "/api/v1/email/test",
            {"recipient": str(recipient or "").strip()},
        )

    def queue_email_notification(self, title, message, recipient, kind=""):
        with self._email_lock:
            self._pending_email_notifications.append({
                "title": str(title or "Notification"),
                "message": str(message or ""),
                "recipient": str(recipient or "").strip(),
                "kind": str(kind or ""),
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
