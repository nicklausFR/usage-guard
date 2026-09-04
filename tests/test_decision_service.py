import sys
import io
import json
import sqlite3
import threading
import time
import tempfile
import unittest
import uuid
from datetime import datetime, timezone
from multiprocessing import AuthenticationError
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from decision_service import (
    MAX_MESSAGE_BYTES,
    PWA_AUTH_REQUEST_TIMEOUT_SECONDS,
    PROTOCOL_VERSION,
    PUBLIC_SERVICE_AUTHKEY,
    DecisionServiceClient,
    DecisionServiceHost,
    DecisionServiceManager,
    _json_bytes,
    dispatch_request,
)
from command_policy import (
    SOURCE_BACKEND, SOURCE_LOCAL_ADMIN, SOURCE_LOCAL_API, stamp_command,
)
from control_registry import ControlRegistry
from service_backend import (
    ACTIVITY_OUTBOX_PAGE_BYTES,
    DESKTOP_STALE_SECONDS,
    DurableActivityOutbox,
    ServiceBackendRuntime,
)


class DecisionServiceProtocolTest(unittest.TestCase):
    def test_client_timeout_keeps_callers_bounded_and_rejects_a_queue_pileup(self):
        release = threading.Event()
        first_finished = threading.Event()
        connection_count = []

        class Connection:
            def send_bytes(self, _payload):
                pass

            def recv_bytes(self, _maximum):
                if not connection_count:
                    raise AssertionError("Connexion non comptabilisée.")
                if len(connection_count) == 1:
                    release.wait(2)
                return _json_bytes({
                    "ok": True, "service": "usage-guard-decision",
                })

            def close(self):
                if len(connection_count) == 1:
                    first_finished.set()

        def connect(*_args, **_kwargs):
            connection_count.append(object())
            return Connection()

        with patch("decision_service.Client", side_effect=connect):
            client = DecisionServiceClient(
                "test-pipe", b"test-authentication-key",
                request_timeout_seconds=0.05,
            )
            started = time.monotonic()
            with self.assertRaisesRegex(TimeoutError, "délai imparti"):
                client.health()
            self.assertLess(time.monotonic() - started, 0.5)

            # The blocked worker remains the sole outstanding IPC operation;
            # another Qt-path call is rejected immediately instead of adding
            # a second complete timeout to the UI stall.
            started = time.monotonic()
            with self.assertRaisesRegex(TimeoutError, "déjà une requête"):
                client.health()
            self.assertLess(time.monotonic() - started, 0.2)
            self.assertEqual(len(connection_count), 1)

            release.set()
            self.assertTrue(first_finished.wait(1))
            deadline = time.monotonic() + 1
            while True:
                try:
                    response = client.health()
                    break
                except TimeoutError:
                    if time.monotonic() >= deadline:
                        self.fail("Le client IPC n’a pas repris après le délai.")
                    time.sleep(0.01)
            self.assertEqual(response["service"], "usage-guard-decision")
            self.assertEqual(len(connection_count), 2)

    def test_authentication_waits_for_the_slot_and_uses_its_longer_timeout(self):
        release_first = threading.Event()
        first_receiving = threading.Event()
        connection_count = []

        class Connection:
            def __init__(self, index):
                self.index = index

            def send_bytes(self, _payload):
                pass

            def recv_bytes(self, _maximum):
                if self.index == 1:
                    first_receiving.set()
                    release_first.wait(1)
                    return _json_bytes({
                        "ok": True, "service": "usage-guard-decision",
                    })
                time.sleep(0.08)
                return _json_bytes({
                    "ok": True,
                    "user": {"username": "admin", "is_admin": True},
                })

            def close(self):
                pass

        def connect(*_args, **_kwargs):
            connection_count.append(object())
            return Connection(len(connection_count))

        with patch("decision_service.Client", side_effect=connect):
            client = DecisionServiceClient(
                "test-pipe", b"test-authentication-key",
                request_timeout_seconds=0.05,
            )
            with self.assertRaises(TimeoutError):
                client.health()
            self.assertTrue(first_receiving.wait(1))

            timer = threading.Timer(0.04, release_first.set)
            timer.start()
            started = time.monotonic()
            user = client.authenticate_user(
                "admin", "correct-password", timeout_seconds=0.25,
            )
            elapsed = time.monotonic() - started
            timer.join(1)

            self.assertEqual(user["username"], "admin")
            self.assertGreater(elapsed, 0.1)
            self.assertLess(elapsed, 0.25)
            self.assertEqual(len(connection_count), 2)

    def test_pwa_requests_wait_for_an_existing_ipc_request(self):
        client = DecisionServiceClient("unused", b"unused")
        requests = []
        client.request = lambda operation, **payload: (
            requests.append((operation, payload))
            or ({"user": {}} if operation == "authenticate_windows_session"
                else {"result": {}})
        )

        client.authenticate_windows_session("S-1-5-21-test")
        client.backend_admin("admin-token", "session_devices")

        self.assertEqual(
            [operation for operation, _ in requests],
            ["authenticate_windows_session", "backend_admin"],
        )
        for _, payload in requests:
            self.assertTrue(payload["wait_for_slot"])
            self.assertEqual(
                payload["timeout_seconds"], PWA_AUTH_REQUEST_TIMEOUT_SECONDS,
            )

    def test_complete_activity_archive_is_rejected_before_ipc_serialization(self):
        class ArchiveMustNotBeSerialized(dict):
            def items(self):
                raise AssertionError("500 MB archive was traversed")

        client = DecisionServiceClient("unused", b"unused")
        client.request = lambda *_args, **_kwargs: self.fail("IPC was called")

        with self.assertRaisesRegex(ValueError, "archive d’activité complète"):
            client.publish_desktop_state(
                {"revision": 1}, ArchiveMustNotBeSerialized({"days": {}}),
            )

    def test_legacy_compressed_activity_payload_is_rejected(self):
        class BackendRuntime:
            def publish_desktop_state(
                self, snapshot, activity=None, *, preserve_activity=False,
            ):
                self.snapshot = snapshot
                self.activity = activity
                self.preserve_activity = preserve_activity
                return {}

        backend = BackendRuntime()
        response, _ = dispatch_request({
            "version": PROTOCOL_VERSION,
            "operation": "publish_desktop_state",
            "snapshot": {"revision": 1},
            "activity_encoding": "zlib-json-v1",
            "activity_data": "forbidden",
        }, backend_runtime=backend)

        self.assertFalse(response["ok"])
        self.assertIn("disabled", response["error"])

    def test_stale_desktop_cannot_keep_live_application_open(self):
        class Client:
            enabled = True
            configured = True
            device_id = "pc"
            device_token = "x" * 40
            _thread = None

            def __init__(self, *_args, **_kwargs):
                pass

            def traffic_stats(self):
                return {}

        with tempfile.TemporaryDirectory() as directory:
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={}, client_factory=Client,
            )
            runtime.publish_desktop_state(
                {"usage": []}, activity_export={
                    "cursor": 0, "bytes": 0, "intervals": [],
                    "live_intervals": [{
                        "live_id": "active-app-codex",
                        "target_key": "app:codex",
                        "started_at": "2026-08-27T10:00:00+00:00",
                        "observed_at": "2026-08-27T10:01:00+00:00",
                    }],
                },
            )
            runtime._desktop_seen_monotonic = (
                time.monotonic() - DESKTOP_STALE_SECONDS - 1
            )

            self.assertEqual(runtime.live_activity_intervals(), [])
            self.assertIsNone(runtime.activity())

    def test_local_windows_session_auth_never_accepts_an_admin_without_password(self):
        sid = "S-1-5-21-1-2-3-1001"

        class Client:
            enabled = True
            configured = True
            device_id = "local-device"
            device_token = "x" * 40
            _thread = None

            def __init__(self, *_args, **_kwargs):
                pass

            def traffic_stats(self):
                return {}

        class Store:
            def user_for_windows_sid(self, device_id, supplied_sid):
                self.lookup = (device_id, supplied_sid)
                return {"usage_guard_username": "alice"}

            def list_users(self):
                return [{
                    "username": "alice", "role": "limited",
                    "is_admin": False, "email": "",
                    "permissions": {"view_activity": True},
                }]

        with tempfile.TemporaryDirectory() as directory:
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(),
                settings={"installation_profile": "local"},
                client_factory=Client,
            )
            store = Store()
            runtime._local_server = type("Local", (), {"store": store})()
            user = runtime.authenticate_windows_session(sid.lower())

            self.assertEqual(user["username"], "alice")
            self.assertEqual(user["authentication"], "windows_session")
            self.assertEqual(store.lookup, ("local-device", sid))

            store.list_users = lambda: [{
                "username": "alice", "role": "admin", "is_admin": True,
                "permissions": {},
            }]
            with self.assertRaisesRegex(PermissionError, "mot de passe Usage Guard"):
                runtime.authenticate_windows_session(sid)

    def test_service_resolves_only_the_requested_sid_and_persists_cache(self):
        sid = "S-1-5-21-1-2-3-1001"

        class Client:
            def __init__(self, *_args, **_kwargs):
                settings = dict(_args[2] or {})
                self.enabled = bool(settings.get("enabled"))
                self.configured = self.enabled
                self._thread = None
                self.calls = 0

            def windows_identities(self):
                self.calls += 1
                return [{
                    "windows_sid": sid,
                    "windows_domain": "PC",
                    "windows_username": "Alice",
                    "usage_guard_username": "alice",
                }, {
                    "windows_sid": "S-1-5-21-1-2-3-1002",
                    "windows_domain": "PC",
                    "windows_username": "Bob",
                    "usage_guard_username": "bob",
                }]

            def traffic_stats(self):
                return {}

        with tempfile.TemporaryDirectory() as directory:
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={"enabled": True},
                client_factory=Client,
            )
            response, _ = dispatch_request({
                "version": PROTOCOL_VERSION,
                "operation": "resolve_windows_identity",
                "windows_sid": sid.lower(),
            }, backend_runtime=runtime)

            self.assertTrue(response["identity"]["mapped"])
            self.assertEqual(
                response["identity"]["usage_guard_username"], "alice"
            )
            self.assertNotIn("bob", response["identity"].values())
            self.assertEqual(runtime.client.calls, 1)

            restored = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={"enabled": False},
                client_factory=Client,
            )
            cached = restored.resolve_windows_identity(sid)
            self.assertTrue(cached["mapped"])
            self.assertEqual(cached["usage_guard_username"], "alice")
            self.assertEqual(restored.client.calls, 0)

    def test_service_caches_current_and_previous_personal_policy_by_sid(self):
        sid = "S-1-5-21-1-2-3-1001"

        class Client:
            policies = []

            def __init__(self, *_args, **_kwargs):
                settings = dict(_args[2] or {})
                self.enabled = bool(settings.get("enabled"))
                self.configured = self.enabled
                self._thread = None
                self.acknowledged = []

            def windows_identities(self):
                return [{
                    "windows_sid": sid,
                    "windows_domain": "PC",
                    "windows_username": "Alice",
                    "usage_guard_username": "alice",
                }]

            def user_policy(self, supplied_sid):
                if not self.policies:
                    raise AssertionError("No policy expected while offline")
                return {
                    "device_id": "pc-test",
                    "windows_sid": supplied_sid,
                    "usage_guard_username": "alice",
                    "configured": True,
                    "revision": self.policies.pop(0),
                    "policy": {"limits": [{"target_key": "app:test"}]},
                    "actor": "admin",
                    "created_at": "2026-08-24T08:00:00+00:00",
                }

            def acknowledge_user_policy(self, supplied_sid, revision, result):
                self.acknowledged.append((supplied_sid, revision, result))
                return {"revision": revision, "devices": []}

            def traffic_stats(self):
                return {}

        with tempfile.TemporaryDirectory() as directory:
            Client.policies = [1, 2]
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={"enabled": True},
                client_factory=Client,
            )
            self.assertEqual(runtime.user_policy(sid.lower())["revision"], 1)
            self.assertEqual(runtime.user_policy(sid)["revision"], 2)
            cached = runtime._personal_policies[sid]
            self.assertEqual(cached["current"]["revision"], 2)
            self.assertEqual(cached["previous"]["revision"], 1)

            response, _ = dispatch_request({
                "version": PROTOCOL_VERSION,
                "operation": "acknowledge_user_policy",
                "windows_sid": sid,
                "revision": 2,
                "result": {"ok": True},
            }, backend_runtime=runtime)
            self.assertTrue(response["ok"])
            self.assertFalse(runtime._personal_policies[sid]["ack_pending"])
            self.assertEqual(runtime.client.acknowledged, [
                (sid, 2, {"ok": True}),
            ])

            restored = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={"enabled": False},
                client_factory=Client,
            )
            offline = restored.user_policy(sid)
            self.assertEqual(offline["revision"], 2)
            self.assertEqual(offline["policy_status"], "cached")

    def test_service_caches_server_unioned_usage_by_mapped_sid(self):
        sid = "S-1-5-21-1-2-3-1001"

        class Client:
            def __init__(self, *_args, **_kwargs):
                settings = dict(_args[2] or {})
                self.enabled = bool(settings.get("enabled"))
                self.configured = self.enabled
                self._thread = None
                self.poll_seconds = 15
                self.queries = []

            def windows_identities(self):
                return [{
                    "windows_sid": sid, "windows_domain": "PC",
                    "windows_username": "Alice",
                    "usage_guard_username": "alice",
                }]

            def user_policy(self, supplied_sid):
                return {
                    "device_id": "pc-test", "windows_sid": supplied_sid,
                    "usage_guard_username": "alice", "configured": True,
                    "revision": 7,
                    "policy": {"limits": [{
                        "key": "app:editor", "target_key": "app:editor",
                        "enabled": True,
                    }, {
                        "key": "category:Travail",
                        "target_key": "category:Travail", "enabled": True,
                    }]},
                    "actor": "admin",
                    "created_at": "2026-08-24T08:00:00+00:00",
                }

            def user_usage_union(
                self, supplied_sid, start, end, target_key=None,
                category_key=None,
            ):
                self.queries.append((
                    supplied_sid, start, end, target_key, category_key,
                ))
                return {
                    "usage_guard_username": "alice",
                    "seconds": 120 if target_key else 300,
                }

            def traffic_stats(self):
                return {}

        with tempfile.TemporaryDirectory() as directory:
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={"enabled": True},
                client_factory=Client,
            )
            runtime.sync_personal_policies()
            cached = runtime.cached_personal_usage(sid)
            self.assertEqual(cached["policy_revision"], 7)
            self.assertEqual(cached["totals"]["app:editor"]["seconds"], 120)
            self.assertEqual(
                cached["totals"]["category:Travail"]["seconds"], 300
            )
            self.assertEqual(runtime.client.queries[0][3:], ("app:editor", None))
            self.assertEqual(runtime.client.queries[1][3:], (None, "Travail"))

            response, _ = dispatch_request({
                "version": PROTOCOL_VERSION, "operation": "personal_usage",
                "windows_sid": sid,
            }, backend_runtime=runtime)
            self.assertTrue(response["ok"])
            self.assertEqual(response["usage"]["usage_guard_username"], "alice")

            restored = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={"enabled": False},
                client_factory=Client,
            )
            self.assertEqual(
                restored.cached_personal_usage(sid)["totals"], cached["totals"]
            )

    def test_local_limit_upload_is_durable_and_replayed_after_reconnection(self):
        sid = "S-1-5-21-1-2-3-1001"

        class Client:
            online = False
            uploads = []

            def __init__(self, *_args, **_kwargs):
                self.enabled = True
                self.configured = True
                self.device_id = "pc-test"
                self._thread = None

            def push_user_policy_action(
                self, supplied_sid, command, operation_key, actor="",
            ):
                if not self.online:
                    raise OSError("offline")
                self.uploads.append((
                    supplied_sid, command, operation_key, actor,
                ))
                return {"ok": True, "revision": 2}

            def traffic_stats(self):
                return {}

        with tempfile.TemporaryDirectory() as directory:
            Client.online = False
            Client.uploads = []
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(),
                settings={"enabled": True, "installation_profile": "server"},
                client_factory=Client,
            )
            runtime.publish_desktop_state({
                "runtime": {"windows_identity": {"windows_sid": sid}},
            })
            queued = runtime.queue_personal_policy_action({
                "action": "set_limit", "target_key": "app:test",
                "settings": {"limit_seconds": 300},
            }, "admin")
            runtime._flush_personal_policy_outbox()
            self.assertTrue(queued["queued"])
            self.assertEqual(
                runtime.status()["pending_personal_policy_uploads"], 1,
            )
            restored = ServiceBackendRuntime(
                directory, ControlRegistry(),
                settings={"enabled": True, "installation_profile": "server"},
                client_factory=Client,
            )
            Client.online = True
            restored._flush_personal_policy_outbox()

            self.assertEqual(
                restored.status()["pending_personal_policy_uploads"], 0,
            )
            self.assertEqual(Client.uploads[0][0], sid)
            self.assertEqual(
                Client.uploads[0][1]["action"], "set_limit",
            )
            self.assertTrue(Client.uploads[0][2].startswith("local-pc-test-"))

            again = ServiceBackendRuntime(
                directory, ControlRegistry(),
                settings={"enabled": True, "installation_profile": "server"},
                client_factory=Client,
            )
            self.assertEqual(
                again.status()["pending_personal_policy_uploads"], 0,
            )

    def test_local_computer_limit_is_queued_for_the_mapped_person_policy(self):
        sid = "S-1-5-21-1-2-3-1001"

        class Client:
            uploads = []

            def __init__(self, *_args, **_kwargs):
                self.enabled = True
                self.configured = True
                self.device_id = "pc-test"
                self._thread = None

            def push_user_policy_action(
                self, supplied_sid, command, operation_key, actor="",
            ):
                self.uploads.append((
                    supplied_sid, command, operation_key, actor,
                ))
                return {"ok": True, "computer_block_policy": {"revision": 1}}

            def traffic_stats(self):
                return {}

        with tempfile.TemporaryDirectory() as directory:
            Client.uploads = []
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(),
                settings={"enabled": True, "installation_profile": "server"},
                client_factory=Client,
            )
            runtime.publish_desktop_state({
                "runtime": {"windows_identity": {"windows_sid": sid}},
            })

            queued = runtime.queue_personal_policy_action({
                "action": "set_computer_block", "mode": "schedule",
                "start_time": "20:11", "end_time": "20:12",
            }, "admin")
            runtime._flush_personal_policy_outbox()

            self.assertTrue(queued["queued"])
            self.assertEqual(runtime.status()["pending_personal_policy_uploads"], 0)
            self.assertEqual(Client.uploads[0][0], sid)
            self.assertEqual(
                Client.uploads[0][1]["action"], "set_computer_block",
            )
            self.assertEqual(Client.uploads[0][3], "admin")

    def test_local_profile_starts_loopback_backend_before_outbound_client(self):
        events = []

        class LocalServer:
            def __init__(self):
                self.httpd = None
                self.stopping = threading.Event()

            def start(self):
                events.append("local-server")
                self.httpd = object()
                self.stopping.wait(2)

            def stop(self):
                events.append("local-stop")
                self.stopping.set()

        class Client:
            def __init__(self, *_args, **_kwargs):
                self.enabled = True
                self.configured = True
                self.base_url = "http://127.0.0.1:8767/usage-guard"
                self.device_id = "local-device"
                self.device_token = "x" * 48
                self._thread = None

            def start(self):
                events.append("client")
                self._thread = object()

            def stop(self):
                events.append("client-stop")
                self._thread = None

            def traffic_stats(self):
                return {}

        local_server = LocalServer()
        with tempfile.TemporaryDirectory() as directory:
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(),
                settings={"installation_profile": "local"},
                client_factory=Client,
                local_server_factory=lambda _directory, _client: local_server,
            )

            runtime.start()
            self.assertEqual(events[:2], ["local-server", "client"])
            self.assertEqual(runtime.status()["installation_profile"], "local")
            runtime.stop()

        self.assertEqual(events[-2:], ["client-stop", "local-stop"])

    def test_service_authenticates_local_admin_through_its_backend_client(self):
        class Client:
            def __init__(self, *_args, **_kwargs):
                self.enabled = True
                self.configured = True
                self._thread = None

            def authenticate_user(self, username, password, email=""):
                self.credentials = (username, password, email)
                return {
                    "username": username, "email": email,
                    "is_admin": True, "must_change": False,
                    "must_set_email": False,
                    "_backend_management_session": {
                        "cookie": "ug_session=server", "csrf_token": "csrf",
                    },
                }

            def traffic_stats(self):
                return {}

        with tempfile.TemporaryDirectory() as directory:
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={},
                client_factory=Client,
            )
            response, _ = dispatch_request({
                "version": PROTOCOL_VERSION,
                "operation": "authenticate_user",
                "username": "admin",
                "password": "secret-password",
            }, backend_runtime=runtime)

            self.assertTrue(response["ok"])
            self.assertTrue(response["user"]["is_admin"])
            self.assertEqual(
                runtime.client.credentials, ("admin", "secret-password", ""),
            )
            self.assertTrue(response["user"]["_service_admin_token"])
            self.assertNotIn("_backend_management_session", response["user"])

    def test_service_preserves_the_backend_login_error_message(self):
        class Client:
            def __init__(self, *_args, **_kwargs):
                self.enabled = True
                self.configured = True
                self._thread = None

            def authenticate_user(self, *_args, **_kwargs):
                raise HTTPError(
                    "https://example.test/api/v1/auth/login", 401,
                    "Unauthorized", {}, io.BytesIO(json.dumps({
                        "error": "Identifiant ou mot de passe incorrect."
                    }).encode("utf-8")),
                )

            def traffic_stats(self):
                return {}

        with tempfile.TemporaryDirectory() as directory:
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={},
                client_factory=Client,
            )
            with self.assertRaisesRegex(
                RuntimeError, "Identifiant ou mot de passe incorrect",
            ):
                runtime.authenticate_user("admin", "incorrect-password")

    def test_service_backend_admin_operations_require_the_login_token(self):
        class Client:
            def __init__(self, *_args, **_kwargs):
                self.enabled = True
                self.configured = True
                self._thread = None
                self.created = None

            def authenticate_user(self, username, password, email=""):
                return {
                    "username": username, "email": email,
                    "is_admin": True, "must_change": False,
                    "must_set_email": False,
                    "_backend_management_session": {
                        "cookie": "ug_session=server", "csrf_token": "csrf",
                    },
                }

            def list_users(self, management_session=None):
                self.management_session = management_session
                return {"users": [{"username": "admin"}]}

            def create_user(
                self, username, password, email="", is_admin=False,
                permissions=None, role=None, device_ids=None,
                management_session=None,
            ):
                self.created = (
                    username, password, email, is_admin, dict(permissions or {}),
                )
                return {"ok": True}

            def traffic_stats(self):
                return {}

        with tempfile.TemporaryDirectory() as directory:
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={},
                client_factory=Client,
            )
            with self.assertRaises(PermissionError):
                runtime.backend_admin("invalid", "list_users")

            user = runtime.authenticate_user(
                "admin", "secret-password", "admin@example.test",
            )
            token = user["_service_admin_token"]
            self.assertEqual(
                runtime.backend_admin(token, "list_users")["users"][0]["username"],
                "admin",
            )
            self.assertEqual(
                runtime.client.management_session["cookie"], "ug_session=server",
            )
            runtime.backend_admin(token, "create_user", {
                "username": "alice", "password": "temporary-password",
                "email": "alice@example.test",
                "is_admin": True,
            })
            self.assertEqual(runtime.client.created, (
                "alice", "temporary-password", "alice@example.test",
                True, {},
            ))
            runtime.registry.bootstrap({}, {})
            remote = stamp_command({
                "action": "set_limit", "target_key": "app:test",
            }, SOURCE_BACKEND)
            runtime.registry.commit(remote, {
                "ok": True,
                "limit": {
                    "key": "app:test", "enabled": True,
                    "limit_seconds": 60, "extension_seconds": 0,
                },
            })
            local_admin = stamp_command({
                "action": "remove_limit", "target_key": "app:test",
            }, SOURCE_LOCAL_ADMIN)
            runtime.publish_desktop_state({
                "runtime": {"windows_identity": {
                    "windows_sid": "S-1-5-21-1-2-3-1001",
                }},
            })
            runtime.backend_admin(token, "commit_control", {
                "command": local_admin, "result": {"ok": True},
            })
            self.assertNotIn("app:test", runtime.registry.controls()["limits"])
            self.assertEqual(
                runtime.status()["pending_personal_policy_uploads"], 1,
            )
            create = stamp_command({
                "action": "set_computer_block", "mode": "schedule",
                "start_time": "19:30", "end_time": "19:32",
            }, SOURCE_LOCAL_ADMIN)
            runtime.backend_admin(token, "commit_control", {
                "command": create,
                "result": {"ok": True, "computer_block": {
                    "block_id": "local-short-evening", "mode": "schedule",
                    "enabled": True, "managed_by": "local",
                }},
            })
            queued_create = runtime._personal_policy_outbox[-1]["command"]
            self.assertEqual(queued_create["block_id"], "local-short-evening")
            self.assertTrue(queued_create["create_new"])
            disable = stamp_command({
                "action": "set_computer_block_enabled", "enabled": False,
            }, SOURCE_LOCAL_ADMIN)
            runtime.backend_admin(token, "commit_control", {
                "command": disable,
                "result": {"ok": True, "computer_block": {
                    "block_id": "short-evening", "mode": "schedule",
                    "enabled": False, "managed_by": "backend",
                }},
            })
            self.assertEqual(
                runtime._personal_policy_outbox[-1]["command"]["block_id"],
                "short-evening",
            )

    def test_service_backend_limited_session_can_proxy_own_notifications_only(self):
        class Client:
            def __init__(self, *_args, **_kwargs):
                self.enabled = True
                self.configured = True
                self._thread = None
                self.calls = []

            def authenticate_user(self, username, _password, email=""):
                return {
                    "username": username, "email": email,
                    "is_admin": False, "must_change": False,
                    "must_set_email": False,
                    "permissions": {
                        "view_notifications": True,
                        "manage_notifications": True,
                        "view_activity": True,
                        "view_analysis": True,
                    },
                    "_backend_management_session": {
                        "cookie": "ug_session=limited", "csrf_token": "csrf",
                    },
                }

            def session_devices(self, session):
                self.calls.append(("devices", session))
                return {"devices": [{"device_id": "pc-1"}]}

            def policy_users(self, session):
                self.calls.append(("policies", session))
                return {"users": [{
                    "username": "nicklaus", "device_ids": ["pc-1"],
                }]}

            def notification_overview(self, owner, device_id, session):
                self.calls.append(("overview", owner, device_id, session))
                return {"notification_rules": [{
                    "id": "own", "owner": owner,
                }]}

            def notification_action(self, command, device_id, session):
                self.calls.append(("action", command, device_id, session))
                return {"ok": True, "queued": True}

            def analysis_overview(self, selection, session):
                self.calls.append(("analysis", selection, session))
                return {
                    "scope": selection.get("scope"),
                    "history_page": {"next_before": "older"},
                }

            def traffic_stats(self):
                return {}

        with tempfile.TemporaryDirectory() as directory:
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={},
                client_factory=Client,
            )
            user = runtime.authenticate_user(
                "nicklaus", "secret-password", "nicklaus@example.test",
            )
            token = user["_service_backend_token"]

            self.assertNotIn("_service_admin_token", user)
            self.assertEqual(
                runtime.backend_admin(token, "session_devices")["devices"][0]["device_id"],
                "pc-1",
            )
            overview = runtime.backend_admin(token, "notification_overview", {
                "owner": "nicklaus", "device_id": "pc-1",
            })
            self.assertEqual(overview["notification_rules"][0]["id"], "own")
            queued = runtime.backend_admin(token, "notification_action", {
                "device_id": "pc-1", "command": {
                    "action": "set_notification_rule",
                    "rule": {
                        "id": "own", "owner": "nicklaus",
                        "description": "Message modifié",
                    },
                },
            })
            self.assertTrue(queued["queued"])
            self.assertEqual(
                runtime.client.calls[-1][1]["rule"]["description"],
                "Message modifié",
            )
            history = runtime.backend_admin(token, "analysis_overview", {
                "scope": "all", "device_id": "pc-1",
                "before": "opaque-cursor", "tz": "Europe/Paris",
            })
            self.assertEqual(history["history_page"]["next_before"], "older")
            self.assertEqual(
                runtime.client.calls[-1][1]["before"], "opaque-cursor",
            )

            runtime._admin_sessions[token]["permissions"][
                "manage_notifications"
            ] = False
            with self.assertRaisesRegex(
                PermissionError, "Modification de notification non autorisée",
            ):
                runtime.backend_admin(token, "notification_action", {
                    "device_id": "pc-1", "command": {
                        "action": "set_notification_rule",
                        "rule": {"id": "own", "owner": "nicklaus"},
                    },
                })
            runtime._admin_sessions[token]["permissions"][
                "view_notifications"
            ] = False
            with self.assertRaisesRegex(
                PermissionError, "Consultation des notifications non autorisée",
            ):
                runtime.backend_admin(token, "notification_overview", {
                    "owner": "nicklaus", "device_id": "pc-1",
                })
            runtime._admin_sessions[token]["permissions"][
                "view_analysis"
            ] = False
            with self.assertRaisesRegex(
                PermissionError, "Consultation de cette vue non autorisée",
            ):
                runtime.backend_admin(token, "analysis_overview", {
                    "scope": "all", "device_id": "pc-1",
                })
            with self.assertRaisesRegex(PermissionError, "administrateur"):
                runtime.backend_admin(token, "list_users")

    def test_service_backend_preserves_remote_email_error(self):
        class Client:
            def __init__(self, *_args, **_kwargs):
                self.enabled = True
                self.configured = True
                self._thread = None

            def traffic_stats(self):
                return {}

            def test_email_settings(self, _recipient, _management_session=None):
                raise HTTPError(
                    "https://example.test/email/test", 502, "Bad Gateway", {},
                    io.BytesIO(json.dumps({
                        "error": "Envoi SMTP impossible : identifiants invalides",
                    }).encode("utf-8")),
                )

        with tempfile.TemporaryDirectory() as directory:
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={},
                client_factory=Client,
            )
            runtime._admin_sessions["valid-token"] = {
                "expires_at": time.time() + 60,
                "management_session": {
                    "cookie": "ug_session=server", "csrf_token": "csrf",
                },
            }

            with self.assertRaisesRegex(
                RuntimeError, "Envoi SMTP impossible : identifiants invalides",
            ):
                runtime.backend_admin("valid-token", "test_email_settings", {
                    "recipient": "owner@example.test",
                })

    def test_service_backend_accepts_windows_utf8_bom_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "backend.json"
            path.write_text(json.dumps({
                "enabled": True,
                "base_url": "https://example.test/usage-guard",
                "device_id": "pc",
                "device_token": "x" * 40,
            }), encoding="utf-8-sig")
            runtime = ServiceBackendRuntime(directory, ControlRegistry())
            self.assertTrue(runtime.client.configured)

    def test_service_snapshot_exposes_the_single_configured_device_name(self):
        settings = {
            "enabled": True, "base_url": "https://example.test/usage-guard",
            "device_id": "pc-main", "device_token": "x" * 40,
            "display_name": "ordinateur-principal",
        }
        with tempfile.TemporaryDirectory() as directory:
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(), settings=settings,
            )
            runtime._snapshot = {"runtime": {"profile": "production"}}

            snapshot = runtime.snapshot()

            self.assertEqual(snapshot["runtime"]["device"], {
                "device_id": "pc-main",
                "display_name": "ordinateur-principal",
            })

    def test_device_rename_is_persisted_without_losing_protected_settings(self):
        settings = {
            "enabled": True, "base_url": "https://example.test/usage-guard",
            "device_id": "pc-main", "device_token": "x" * 40,
            "display_name": "ordinateur-principal",
            "installation_profile": "server",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "backend.json"
            path.write_text(json.dumps({
                **settings, "protected_future_field": "preserved",
            }), encoding="utf-8")
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(), settings=settings,
            )
            runtime.client.rename_device = lambda label, _session=None: {
                "ok": True, "device": {"label": label},
            }

            runtime.rename_device("NUC11PHKi7", {"session": "admin"})

            saved = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(saved["display_name"], "NUC11PHKi7")
            self.assertEqual(saved["device_token"], "x" * 40)
            self.assertEqual(saved["protected_future_field"], "preserved")

    def test_backend_runtime_handoff_is_durable_and_ack_waits_for_completion(self):
        settings = {
            "enabled": True, "base_url": "https://example.test/usage-guard",
            "device_id": "pc", "device_token": "x" * 40,
        }
        with tempfile.TemporaryDirectory() as directory:
            controls = ControlRegistry(Path(directory) / "controls.json")
            runtime = ServiceBackendRuntime(directory, controls, settings=settings)
            command = stamp_command({
                "action": "set_limit", "target_key": "app:test",
                "settings": {"limit_seconds": 60},
            }, SOURCE_BACKEND, command_id="41")

            deferred = runtime.accept_command(command)
            self.assertTrue(deferred["_defer_ack"])
            self.assertEqual(runtime.next_command()["service_command_id"], "41")
            self.assertIn("app:test", controls.controls()["limits"])

            restored = ServiceBackendRuntime(
                directory, controls, settings=settings
            )
            self.assertEqual(restored.next_command()["command"]["action"], "set_limit")
            result = {
                "ok": True,
                "limit": {"key": "app:test", "limit_seconds": 60},
            }
            restored.complete_command("41", result)
            self.assertIsNone(restored.next_command())
            self.assertEqual(restored.accept_command(command), result)
            self.assertEqual(
                controls.controls()["limits"]["app:test"]["managed_by"],
                "backend",
            )

    def test_catalog_commands_are_delivered_only_to_the_target_windows_sid(self):
        alice_sid = "S-1-5-21-100-200-300-1001"
        bob_sid = "S-1-5-21-100-200-300-1002"
        settings = {
            "enabled": True, "base_url": "https://example.test/usage-guard",
            "device_id": "shared-pc", "device_token": "x" * 40,
            "windows_identities": [{
                "windows_sid": alice_sid,
                "windows_username": "Alice",
                "usage_guard_username": "alice",
            }, {
                "windows_sid": bob_sid,
                "windows_username": "Bob",
                "usage_guard_username": "bob",
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(), settings=settings,
            )
            alice = stamp_command({
                "action": "delete_target", "target_key": "app:alice",
                "_usage_guard_target_username": "alice",
                "_usage_guard_target_windows_sids": [alice_sid],
            }, SOURCE_BACKEND, command_id="41")
            bob = stamp_command({
                "action": "rename_target", "target_key": "app:bob",
                "label": "Bob",
                "_usage_guard_target_username": "bob",
                "_usage_guard_target_windows_sids": [bob_sid],
            }, SOURCE_BACKEND, command_id="42")
            runtime.accept_command(alice)
            runtime.accept_command(bob)

            self.assertIsNone(runtime.next_command())
            self.assertIsNone(runtime.next_command(
                bob_sid, "alice",
            ))
            bob_pending = runtime.next_command(bob_sid, "bob")
            self.assertEqual(bob_pending["service_command_id"], "42")
            runtime.complete_command("42", {"ok": True})
            self.assertIsNone(runtime.next_command(bob_sid, "bob"))

            restored = ServiceBackendRuntime(
                directory, ControlRegistry(), settings=settings,
            )
            self.assertIsNone(restored.next_command(bob_sid, "bob"))
            alice_pending = restored.next_command(alice_sid, "alice")
            self.assertEqual(alice_pending["service_command_id"], "41")
            self.assertEqual(
                alice_pending["command"]["target_key"], "app:alice",
            )

    def test_protection_incidents_survive_disconnect_until_server_ack(self):
        class Client:
            def __init__(self, *_args, **kwargs):
                self.enabled = True
                self.configured = True
                self._thread = None
                self.status_provider = kwargs["status_provider"]
                self.status_acknowledger = kwargs["status_acknowledger"]

            def traffic_stats(self):
                return {}

        def snapshot(extension_connected):
            return {"runtime": {"protection": {"extension": {
                "connected": extension_connected,
                "last_seen_at": "2026-08-21T10:00:00+00:00",
            }}}}

        with tempfile.TemporaryDirectory() as directory:
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={},
                client_factory=Client,
            )
            runtime.publish_desktop_state(snapshot(True))
            runtime.publish_desktop_state(snapshot(False))
            pending = runtime.protection_status()["events"]
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0]["kind"], "interrupted")

            restored = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={},
                client_factory=Client,
            )
            replayed = restored.protection_status()["events"]
            self.assertEqual(replayed, pending)

            restored.acknowledge_protection_events([pending[0]["id"]])
            again = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={},
                client_factory=Client,
            )
            self.assertEqual(again.protection_status()["events"], [])

    def test_remote_complete_activity_import_is_disabled(self):
        settings = {
            "enabled": True, "base_url": "https://example.test/usage-guard",
            "device_id": "pc", "device_token": "x" * 40,
        }
        with tempfile.TemporaryDirectory() as directory:
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(), settings=settings
            )
            remote = {"days": {"2026-08-20": {"app:test": 12}}}
            self.assertFalse(hasattr(runtime, "import_activity"))
            self.assertIsNone(runtime.next_command())

    def test_backend_ipc_operations_expose_no_secret_configuration(self):
        class BackendRuntime:
            def status(self):
                return {"enabled": False, "configured": False}

            def publish_desktop_state(
                self, snapshot, activity=None, *, preserve_activity=False,
            ):
                self.snapshot = snapshot
                return self.status()

            def next_command(self):
                return None

        backend = BackendRuntime()
        response, _ = dispatch_request({
            "version": PROTOCOL_VERSION,
            "operation": "health",
        }, backend_runtime=backend)
        self.assertEqual(response["backend"], {
            "enabled": False, "configured": False,
        })
        response, _ = dispatch_request({
            "version": PROTOCOL_VERSION,
            "operation": "publish_desktop_state",
            "snapshot": {"usage": []}, "activity_unchanged": True,
        }, backend_runtime=backend)
        self.assertTrue(response["ok"])
        self.assertEqual(backend.snapshot, {"usage": []})

    def test_snapshot_publish_never_caches_a_complete_activity_archive(self):
        class Client:
            enabled = True
            configured = True
            device_id = "pc"
            device_token = "x" * 40
            _thread = None

            def __init__(self, *_args, **_kwargs):
                pass

            def traffic_stats(self):
                return {}

        with tempfile.TemporaryDirectory() as directory:
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={},
                client_factory=Client,
            )
            with self.assertRaisesRegex(ValueError, "archive"):
                runtime.publish_desktop_state(
                    {"revision": 1},
                    {"days": {"2026-08-28": {"app:test": 12}}},
                )

            response, _ = dispatch_request({
                "version": PROTOCOL_VERSION,
                "operation": "publish_desktop_state",
                "snapshot": {"revision": 2},
                "activity_unchanged": True,
            }, backend_runtime=runtime)

            self.assertTrue(response["ok"])
            self.assertEqual(runtime.snapshot()["revision"], 2)
            self.assertIsNone(runtime.activity())

    def test_incomplete_desktop_activity_is_rejected_too(self):
        class Client:
            enabled = True
            configured = True
            device_id = "pc"
            device_token = "x" * 40
            _thread = None

            def __init__(self, *_args, **_kwargs):
                pass

            def traffic_stats(self):
                return {}

        with tempfile.TemporaryDirectory() as directory:
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={},
                client_factory=Client,
            )
            with self.assertRaisesRegex(ValueError, "archive"):
                runtime.publish_desktop_state(
                    {"revision": 2}, {"open_sessions": {}},
                )
            self.assertIsNone(runtime.activity())

    def test_snapshot_only_publish_after_service_restart_keeps_activity_absent(self):
        class Client:
            enabled = True
            configured = True
            device_id = "pc"
            device_token = "x" * 40
            _thread = None

            def __init__(self, *_args, **_kwargs):
                pass

            def traffic_stats(self):
                return {}

        with tempfile.TemporaryDirectory() as directory:
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={},
                client_factory=Client,
            )
            runtime.publish_desktop_state({"revision": 1})

            self.assertIsNone(runtime.activity())

    def test_compact_activity_outbox_survives_service_restart_until_both_acks(self):
        class Client:
            enabled = True
            configured = True
            device_id = "pc"
            device_token = "x" * 40
            _thread = None

            def __init__(self, *_args, **kwargs):
                self.callbacks = kwargs

            def traffic_stats(self):
                return {}

        sid = "S-1-5-21-1-2-3-1001"
        session = {
            "record_id": "timeline-" + "a" * 64,
            "interval_id": "activity-" + "b" * 64,
            "kind": "active", "id": "active:kona", "key": "app:kona",
            "label": "Kona", "category": "Jeux",
            "category_lineage": ["Jeux", "Divertissement"],
            "windows_sid": sid,
            "started_at": "2026-08-29T23:55:00+02:00",
            "ended_at": "2026-08-30T00:05:00+02:00",
            "policy_revision": 4,
        }
        live = [{
            "live_id": "live-" + "c" * 64, "windows_sid": sid,
            "target_key": "app:kona",
            "started_at": "2026-08-30T00:10:00+02:00",
            "observed_at": "2026-08-30T00:11:00+02:00",
        }]

        with tempfile.TemporaryDirectory() as directory:
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={}, client_factory=Client,
            )
            runtime.publish_desktop_state(
                {"revision": 1}, preserve_activity=True,
                activity_export={
                    "intervals": [session], "live_intervals": live,
                    "cursor": 123, "bytes": 400,
                },
            )
            restored = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={}, client_factory=Client,
            )

            # The outbound client is wired only to bounded incremental
            # providers.  A future reintroduction of an archive provider must
            # fail this sentinel before it can reach the network.
            self.assertNotIn("activity_provider", restored.client.callbacks)
            self.assertNotIn("activity_importer", restored.client.callbacks)
            self.assertIn("interval_provider", restored.client.callbacks)
            self.assertIn("timeline_provider", restored.client.callbacks)
            self.assertIn("live_interval_provider", restored.client.callbacks)

            self.assertEqual(
                restored.pending_usage_intervals()[sid][0]["target_key"],
                "app:kona",
            )
            self.assertEqual(
                restored.pending_timeline_sessions()[sid][0]["record_id"],
                session["record_id"],
            )
            # A restarted service must not republish a stale open interval
            # until the desktop has reconnected and refreshed it.
            self.assertEqual(restored.live_activity_intervals(), [])
            restored.publish_desktop_state(
                {"revision": 2}, preserve_activity=True,
                activity_export={
                    "intervals": [session], "live_intervals": live,
                    "cursor": 123, "bytes": 400,
                },
            )
            self.assertEqual(restored.live_activity_intervals(), live)
            restored.acknowledge_usage_intervals([session["interval_id"]])
            self.assertIn(sid, restored.pending_timeline_sessions())
            restored.acknowledge_timeline_sessions([session["record_id"]])

            again = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={}, client_factory=Client,
            )
            self.assertEqual(again.pending_usage_intervals(), {})
            self.assertEqual(again.pending_timeline_sessions(), {})

    def test_other_sites_outbox_keeps_usage_but_never_queues_timeline(self):
        sid = "S-1-5-21-1-2-3-1001"
        aggregate = {
            "record_id": "timeline-" + "a" * 64,
            "interval_id": "activity-" + "a" * 64,
            "kind": "active", "id": "active:aggregate",
            "key": "site:brave.exe:other-sites", "label": "Autres sites",
            "windows_sid": sid,
            "started_at": "2026-09-03T08:00:00+02:00",
            "ended_at": "2026-09-03T08:01:00+02:00",
        }
        neighboring = {
            **aggregate,
            "record_id": "timeline-" + "b" * 64,
            "interval_id": "activity-" + "b" * 64,
            "id": "active:neighbor",
            "key": "site:brave.exe:other-sites-extra",
            "label": "Other sites extra",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "outbox.sqlite3")
            outbox = DurableActivityOutbox(path)

            self.assertEqual(outbox.add_many([aggregate, neighboring]), 2)
            db = sqlite3.connect(path)
            try:
                flags = dict(db.execute(
                    "SELECT record_id,timeline_acked || ',' || usage_acked "
                    "FROM activity_outbox"
                ).fetchall())
            finally:
                db.close()
            self.assertEqual(flags[aggregate["record_id"]], "1,0")
            self.assertEqual(flags[neighboring["record_id"]], "0,0")
            self.assertEqual(
                [item["key"] for item in outbox.pending_sessions(timeline=True)],
                [neighboring["key"]],
            )
            self.assertEqual(
                {item["key"] for item in outbox.pending_sessions(timeline=False)},
                {aggregate["key"], neighboring["key"]},
            )

            # Model a row written by an older service, then verify that the
            # startup migration repairs it without acknowledging its usage.
            db = sqlite3.connect(path)
            try:
                db.execute(
                    "UPDATE activity_outbox SET timeline_acked=0 "
                    "WHERE record_id=?", (aggregate["record_id"],),
                )
                db.commit()
            finally:
                db.close()
            restored = DurableActivityOutbox(path)
            again = DurableActivityOutbox(path)

            self.assertEqual(
                [item["key"] for item in restored.pending_sessions(timeline=True)],
                [neighboring["key"]],
            )
            self.assertEqual(
                {item["key"] for item in again.pending_sessions(timeline=False)},
                {aggregate["key"], neighboring["key"]},
            )
            db = sqlite3.connect(path)
            try:
                aggregate_flags = db.execute(
                    "SELECT timeline_acked,usage_acked,interval_id "
                    "FROM activity_outbox WHERE record_id=?",
                    (aggregate["record_id"],),
                ).fetchone()
            finally:
                db.close()
            self.assertEqual(
                aggregate_flags,
                (1, 0, aggregate["interval_id"]),
            )

    def test_runtime_defensively_omits_other_sites_timeline_rows(self):
        aggregate = {
            "record_id": "timeline-" + "c" * 64,
            "kind": "active", "id": "active:aggregate",
            "key": "site:brave.exe:other-sites", "label": "Autres sites",
            "windows_sid": "S-1-5-21-1-2-3-1001",
        }
        neighboring = {
            **aggregate,
            "record_id": "timeline-" + "d" * 64,
            "key": "site:brave.exe:other-sites-extra",
        }

        class Store:
            def pending_sessions(self, timeline=True):
                self.timeline = timeline
                return [aggregate, neighboring]

        runtime = ServiceBackendRuntime.__new__(ServiceBackendRuntime)
        runtime._lock = threading.RLock()
        runtime._activity_store = Store()

        pending = runtime.pending_timeline_sessions()

        self.assertEqual(runtime._activity_store.timeline, True)
        self.assertEqual(
            pending[aggregate["windows_sid"]][0]["record_id"],
            neighboring["record_id"],
        )

    def test_daily_aggregate_outbox_coalesces_by_day_and_survives_restart(self):
        class Client:
            enabled = True
            configured = True
            device_id = "pc"
            device_token = "x" * 40
            _thread = None

            def __init__(self, *_args, **kwargs):
                self.callbacks = kwargs

            def traffic_stats(self):
                return {}

        first = {
            "aggregate_id": "daily-v1-" + "a" * 64,
            "local_day": "2026-08-03",
            "metrics": [{
                "kind": "usage", "key": "app:kona", "seconds": 60,
            }],
        }
        corrected = {
            **first,
            "aggregate_id": "daily-v1-" + "b" * 64,
            "metrics": [{
                "kind": "usage", "key": "app:kona", "seconds": 90,
            }],
        }
        sid = "S-1-5-21-1-2-3-1001"
        snapshot = {
            "runtime": {"windows_identity": {"windows_sid": sid}},
        }
        with tempfile.TemporaryDirectory() as directory:
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={}, client_factory=Client,
            )
            runtime.publish_desktop_state(
                {**snapshot, "revision": 1}, activity_export={
                    "intervals": [], "live_intervals": [],
                    "daily_aggregates": [first], "cursor": 0, "bytes": 0,
                },
            )
            runtime.publish_desktop_state(
                {**snapshot, "revision": 2}, activity_export={
                    "intervals": [], "live_intervals": [],
                    "daily_aggregates": [corrected], "cursor": 0, "bytes": 0,
                },
            )
            restored = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={}, client_factory=Client,
            )

            pending_groups = restored.pending_daily_aggregates()
            self.assertNotIn("", pending_groups)
            pending = pending_groups[sid]
            self.assertEqual(pending, [corrected])
            self.assertIn("daily_aggregate_provider", restored.client.callbacks)
            restored.acknowledge_daily_aggregates(
                [first["aggregate_id"]], sid,
            )
            self.assertEqual(restored._activity_store.daily_count(), 1)
            restored.acknowledge_daily_aggregates([
                corrected["aggregate_id"],
            ], sid)
            self.assertEqual(restored.pending_daily_aggregates(), {})

            with self.assertRaisesRegex(ValueError, "Agrégat journalier"):
                restored._activity_store.add_daily_aggregates([{
                    **corrected, "sessions": [{"started_at": "raw"}],
                }])

    def test_daily_aggregate_outbox_validates_and_persists_other_site_metric(self):
        aggregate = {
            "aggregate_id": "daily-v1-" + "e" * 64,
            "local_day": "2026-09-03",
            "metrics": [{
                "kind": "other_site",
                "key": "site:firefox.exe:example.org",
                "seconds": 42.1236,
            }],
        }
        expected = {
            **aggregate,
            "metrics": [{
                "kind": "other_site",
                "key": "site:firefox.exe:example.org",
                "seconds": 42.124,
            }],
        }

        self.assertEqual(
            DurableActivityOutbox._validated_daily_aggregate(aggregate),
            expected,
        )
        with tempfile.TemporaryDirectory() as directory:
            outbox = DurableActivityOutbox(Path(directory, "outbox.sqlite3"))

            self.assertEqual(
                outbox.add_daily_aggregates([aggregate], windows_sid="test-sid"),
                [aggregate["aggregate_id"]],
            )
            self.assertEqual(
                outbox.pending_daily_aggregates(),
                {"TEST-SID": [expected]},
            )

    def test_identical_daily_digest_is_acknowledged_for_only_one_sid(self):
        class Client:
            enabled = True
            configured = True
            device_id = "pc"
            device_token = "x" * 40
            _thread = None

            def __init__(self, *_args, **kwargs):
                self.callbacks = kwargs

            def traffic_stats(self):
                return {}

        aggregate = {
            "aggregate_id": "daily-v1-" + "c" * 64,
            "local_day": "2026-08-03",
            "metrics": [{
                "kind": "usage", "key": "app:kona", "seconds": 60,
            }],
        }
        sid_one = "S-1-5-21-1-2-3-1001"
        sid_two = "S-1-5-21-1-2-3-1002"
        with tempfile.TemporaryDirectory() as directory:
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={},
                client_factory=Client,
            )
            for revision, sid in enumerate((sid_one, sid_two), start=1):
                runtime.publish_desktop_state({
                    "revision": revision,
                    "runtime": {"windows_identity": {"windows_sid": sid}},
                }, activity_export={
                    "intervals": [], "live_intervals": [],
                    "daily_aggregates": [aggregate],
                    "cursor": 0, "bytes": 0,
                })
            self.assertEqual(
                set(runtime.pending_daily_aggregates()), {sid_one, sid_two},
            )

            runtime.acknowledge_daily_aggregates(
                [aggregate["aggregate_id"]], sid_one,
            )

            self.assertEqual(runtime._activity_store.daily_count(), 1)
            self.assertEqual(
                set(runtime.pending_daily_aggregates()), {sid_two},
            )

    def test_activity_backlog_is_not_embedded_in_the_rewritten_broker(self):
        class Client:
            enabled = True
            configured = True
            device_id = "pc"
            device_token = "x" * 40
            _thread = None

            def __init__(self, *_args, **_kwargs):
                pass

            def traffic_stats(self):
                return {}

        sid = "S-1-5-21-1-2-3-1001"
        sessions = [{
            "record_id": "timeline-" + f"{index:064x}",
            "interval_id": "activity-" + f"{index:064x}",
            "kind": "active", "id": f"active:{index}",
            "key": "app:test", "label": "Test",
            "windows_sid": sid,
            "started_at": f"2026-08-30T08:{index % 60:02d}:00+02:00",
            "ended_at": f"2026-08-30T08:{index % 60:02d}:01+02:00",
        } for index in range(500)]

        with tempfile.TemporaryDirectory() as directory:
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={}, client_factory=Client,
            )
            runtime.publish_desktop_state(
                {"revision": 1}, activity_export={
                    "intervals": sessions, "live_intervals": [],
                    "cursor": 123, "bytes": 1,
                },
            )

            broker = json.loads(Path(
                directory, "backend-command-broker.json",
            ).read_text(encoding="utf-8"))
            self.assertNotIn("activity_outbox", broker)
            self.assertEqual(runtime._activity_store.count(), 500)
            self.assertLess(
                Path(directory, "backend-command-broker.json").stat().st_size,
                64 * 1024,
            )

    def test_activity_outbox_sqlite_read_is_bounded_by_encoded_bytes(self):
        sid = "S-1-5-21-1-2-3-1001"
        sessions = [{
            "record_id": "timeline-" + f"{index:064x}",
            "kind": "program", "id": f"program:{index}",
            "key": f"app:test-{index}", "label": "é" * 90_000,
            "windows_sid": sid,
            "started_at": f"2026-08-30T08:0{index}:00+02:00",
            "ended_at": f"2026-08-30T08:0{index}:01+02:00",
        } for index in range(3)]

        with tempfile.TemporaryDirectory() as directory:
            outbox = DurableActivityOutbox(Path(directory, "outbox.sqlite3"))
            self.assertEqual(outbox.add_many(sessions), 3)

            page = outbox.pending_sessions(
                timeline=True, max_bytes=220 * 1024,
            )
            encoded = json.dumps(
                page, ensure_ascii=False, separators=(",", ":"),
            ).encode("utf-8")

            self.assertEqual(len(page), 1)
            self.assertLessEqual(len(encoded), 220 * 1024)
            self.assertEqual(outbox.count(), 3)

            full_page = outbox.pending_sessions(timeline=True)
            full_encoded = json.dumps(
                full_page, ensure_ascii=False, separators=(",", ":"),
            ).encode("utf-8")
            self.assertEqual(len(full_page), 2)
            self.assertLessEqual(
                len(full_encoded), ACTIVITY_OUTBOX_PAGE_BYTES,
            )

    def test_legacy_broker_outbox_migrates_idempotently_to_sqlite(self):
        class Client:
            configured = True
            device_id = "pc"
            device_token = "x" * 40
            _thread = None

            def __init__(self, *_args, **_kwargs):
                pass

            def traffic_stats(self):
                return {}

        record_id = "timeline-" + "d" * 64
        session = {
            "record_id": record_id, "kind": "program",
            "id": "program:kona", "key": "app:kona", "label": "Kona",
            "windows_sid": "S-1-5-21-1-2-3-1001",
            "started_at": "2026-08-30T08:00:00+02:00",
            "ended_at": "2026-08-30T08:01:00+02:00",
        }
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory, "backend-command-broker.json")
            state.write_text(json.dumps({
                "activity_outbox": {record_id: {
                    "session": session, "timeline_acked": False,
                    "usage_acked": True,
                }},
            }), encoding="utf-8")

            first = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={}, client_factory=Client,
            )
            second = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={}, client_factory=Client,
            )

            self.assertEqual(first._activity_store.count(), 1)
            self.assertEqual(second._activity_store.count(), 1)
            self.assertEqual(
                second.pending_timeline_sessions()[session["windows_sid"]][0][
                    "record_id"
                ],
                record_id,
            )
            self.assertNotIn(
                "activity_outbox",
                json.loads(state.read_text(encoding="utf-8")),
            )

    def test_service_state_is_fsynced_before_atomic_replace(self):
        class Client:
            enabled = True
            configured = True
            device_id = "pc"
            device_token = "x" * 40
            _thread = None

            def __init__(self, *_args, **_kwargs):
                pass

            def traffic_stats(self):
                return {}

        with tempfile.TemporaryDirectory() as directory:
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={},
                client_factory=Client,
            )
            events = []
            original_replace = Path.replace

            def tracked_replace(source, target):
                events.append("replace")
                return original_replace(source, target)

            with patch(
                "service_backend.os.fsync",
                side_effect=lambda _descriptor: events.append("fsync"),
            ), patch.object(Path, "replace", tracked_replace):
                runtime._save_state()

            self.assertEqual(events, ["fsync", "replace"])

    def test_service_state_is_not_replaced_when_fsync_fails(self):
        class Client:
            enabled = True
            configured = True
            device_id = "pc"
            device_token = "x" * 40
            _thread = None

            def __init__(self, *_args, **_kwargs):
                pass

            def traffic_stats(self):
                return {}

        with tempfile.TemporaryDirectory() as directory:
            runtime = ServiceBackendRuntime(
                directory, ControlRegistry(), settings={},
                client_factory=Client,
            )
            with patch(
                "service_backend.os.fsync", side_effect=OSError("disk full"),
            ), patch.object(Path, "replace") as replace:
                with self.assertRaises(OSError):
                    runtime._save_state()
            replace.assert_not_called()

    def test_lightweight_desktop_client_payload_skips_activity_compression(self):
        requests = []
        client = DecisionServiceClient("unused", b"unused")
        client.request = lambda operation, **payload: (
            requests.append((operation, payload)) or {"backend": {}}
        )

        client.publish_desktop_state(
            {"revision": 3}, activity_unchanged=True,
        )

        self.assertEqual(requests[0][0], "publish_desktop_state")
        payload = requests[0][1]
        self.assertEqual(payload["snapshot"], {"revision": 3})
        self.assertIs(payload["activity_unchanged"], True)
        self.assertNotIn("activity", payload)
        self.assertNotIn("activity_data", payload)
        self.assertNotIn("activity_encoding", payload)

    def test_sensitive_operations_require_service_admin_token(self):
        registry = ControlRegistry()
        token = b"protected-administrative-token-value"
        response, stopping = dispatch_request({
            "version": PROTOCOL_VERSION,
            "operation": "shutdown",
        }, registry, token)
        self.assertFalse(response["ok"])
        self.assertFalse(stopping)

        import base64
        response, stopping = dispatch_request({
            "version": PROTOCOL_VERSION,
            "operation": "shutdown",
            "admin_token": base64.urlsafe_b64encode(token).decode("ascii"),
        }, registry, token)
        self.assertTrue(response["ok"])
        self.assertTrue(stopping)

    def test_external_service_manager_uses_public_protocol_and_does_not_stop_scm(self):
        class Profile:
            name = "dev"
            decision_pipe_name = r"\\.\pipe\UsageGuardDecisionDevTest"

            @staticmethod
            def local_data_directory():
                raise AssertionError("LocalAppData key must not be used")

        manager = DecisionServiceManager(
            Profile(), service_detector=lambda _profile: True
        )
        calls = []
        manager.client = type("Client", (), {
            "request": lambda *_args, **_kwargs: calls.append("request")
        })()
        manager.connected = True

        self.assertTrue(manager.external_service)
        self.assertEqual(manager.authkey, PUBLIC_SERVICE_AUTHKEY)
        manager.stop()
        self.assertEqual(calls, [])

    def test_control_registry_persists_backend_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "controls.json"
            registry = ControlRegistry(path)
            registry.bootstrap({}, {})
            remote = stamp_command({
                "action": "set_limit", "target_key": "app:test",
            }, SOURCE_BACKEND)
            registry.commit(remote, {
                "ok": True,
                "limit": {
                    "key": "app:test", "enabled": True,
                    "limit_seconds": 60, "extension_seconds": 0,
                    "managed_by": "backend",
                },
            })

            restored = ControlRegistry(path)
            local_remove = stamp_command({
                "action": "remove_limit", "target_key": "app:test",
            }, SOURCE_LOCAL_API)

            self.assertIn("app:test", restored.controls()["limits"])
            self.assertFalse(restored.authorize(local_remove)["allowed"])

    def test_replace_commit_does_not_adopt_preserved_local_computer_block(self):
        registry = ControlRegistry()
        registry.bootstrap({}, [])
        command = stamp_command({
            "action": "replace_computer_blocks",
            "blocks": [{
                "block_id": "first", "mode": "schedule",
                "start_time": "19:30", "end_time": "19:32",
            }],
        }, SOURCE_BACKEND)
        registry.reserve(command)

        controls = registry.commit(command, {
            "ok": True,
            "computer_blocks": [{
                "block_id": "first", "mode": "schedule",
                "daily_start": "19:30", "daily_end": "19:32",
                "managed_by": "backend",
            }, {
                "block_id": "second", "mode": "schedule",
                "daily_start": "22:30", "daily_end": "05:00",
                "managed_by": "local",
            }],
        })

        self.assertEqual(
            [block["block_id"] for block in controls["computer_blocks"]],
            ["first"],
        )
        self.assertEqual(
            controls["computer_blocks"][0]["managed_by"], "backend",
        )

    def test_control_registry_migrates_v1_computer_block_to_v2(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "controls.json"
            path.write_text(json.dumps({
                "version": 1, "limits": {},
                "computer_block": {
                    "mode": "schedule", "daily_start": "22:30",
                    "daily_end": "05:00", "managed_by": "backend",
                },
            }), encoding="utf-8")

            first = ControlRegistry(path).controls()["computer_blocks"]
            second = ControlRegistry(path).controls()["computer_blocks"]
            saved = json.loads(path.read_text(encoding="utf-8"))

            self.assertEqual(len(first), 1)
            self.assertEqual(first[0]["block_id"], second[0]["block_id"])
            self.assertEqual(saved["version"], 2)
            self.assertIn(first[0]["block_id"], saved["computer_blocks"])

    def test_computer_close_graces_are_distinct_per_block_id(self):
        registry = ControlRegistry()
        now = datetime(2026, 8, 24, 10, 0, tzinfo=timezone.utc)
        base = {
            "mode": "schedule",
            "started_at": "2026-08-24T09:00:00+00:00",
            "ends_at": "2026-08-24T11:00:00+00:00",
        }

        first = registry.start_computer_block_grace(
            {**base, "block_id": "first"}, 300, now,
        )
        second = registry.computer_block_grace_status(
            {**base, "block_id": "second"}, now,
        )

        self.assertTrue(first["active"])
        self.assertNotEqual(
            first["occurrence_token"], second["occurrence_token"]
        )
        self.assertFalse(second["used"])
        self.assertTrue(second["available"])

    def test_computer_close_grace_is_service_persisted_and_cannot_be_recreated(self):
        occurrence = {
            "mode": "daily_duration",
            "started_at": "2026-08-24T09:00:00+00:00",
            "ends_at": "2026-08-24T23:00:00+00:00",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "controls.json"
            registry = ControlRegistry(path)
            before = registry.computer_block_grace_status(
                occurrence, datetime(2026, 8, 24, 10, 0, tzinfo=timezone.utc)
            )
            started = registry.start_computer_block_grace(
                occurrence, 1,
                datetime(2026, 8, 24, 10, 0, tzinfo=timezone.utc),
            )
            repeated = registry.start_computer_block_grace(
                occurrence, 900,
                datetime(2026, 8, 24, 10, 1, tzinfo=timezone.utc),
            )
            restored = ControlRegistry(path).computer_block_grace_status(
                occurrence, datetime(2026, 8, 24, 10, 2, tzinfo=timezone.utc)
            )
            expired = ControlRegistry(path).computer_block_grace_status(
                occurrence, datetime(2026, 8, 24, 10, 6, tzinfo=timezone.utc)
            )
            refused = ControlRegistry(path).start_computer_block_grace(
                occurrence, 300,
                datetime(2026, 8, 24, 10, 6, tzinfo=timezone.utc),
            )
            next_occurrence = {
                **occurrence,
                "started_at": "2026-08-25T09:00:00+00:00",
                "ends_at": "2026-08-25T23:00:00+00:00",
            }
            next_status = ControlRegistry(path).computer_block_grace_status(
                next_occurrence,
                datetime(2026, 8, 25, 10, 0, tzinfo=timezone.utc),
            )

            self.assertTrue(before["available"])
            self.assertTrue(started["active"])
            self.assertEqual(started["duration_seconds"], 300)
            self.assertEqual(repeated["activated_at"], started["activated_at"])
            self.assertEqual(repeated["ends_at"], started["ends_at"])
            self.assertTrue(restored["active"])
            self.assertEqual(expired["state"], "expired")
            self.assertFalse(expired["available"])
            self.assertEqual(refused["state"], "expired")
            self.assertTrue(next_status["available"])
            self.assertFalse(next_status["used"])

    def test_computer_close_grace_requires_an_active_block_occurrence(self):
        registry = ControlRegistry()
        occurrence = {
            "mode": "schedule",
            "started_at": "2026-08-24T09:00:00+00:00",
            "ends_at": "2026-08-24T10:00:00+00:00",
        }
        with self.assertRaisesRegex(ValueError, "n’est pas actif"):
            registry.start_computer_block_grace(
                occurrence, 300,
                datetime(2026, 8, 24, 10, 1, tzinfo=timezone.utc),
            )

    def test_computer_close_grace_is_exposed_by_the_service_protocol(self):
        registry = ControlRegistry()
        response, stopping = dispatch_request({
            "version": PROTOCOL_VERSION,
            "operation": "computer_block_grace",
            "action": "status",
            "occurrence": {
                "mode": "schedule",
                "started_at": "2026-08-24T00:00:00+00:00",
                "ends_at": "2026-08-25T00:00:00+00:00",
            },
        }, registry)
        self.assertTrue(response["ok"])
        self.assertFalse(stopping)
        self.assertIn("occurrence_token", response["grace"])

    def test_authenticated_local_admin_can_take_over_backend_control(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "controls.json"
            registry = ControlRegistry(path)
            registry.bootstrap({}, {})
            remote = stamp_command({
                "action": "set_limit", "target_key": "app:test",
            }, SOURCE_BACKEND)
            registry.commit(remote, {
                "ok": True,
                "limit": {
                    "key": "app:test", "enabled": True,
                    "limit_seconds": 60, "extension_seconds": 0,
                },
            })
            local_admin = stamp_command({
                "action": "set_limit", "target_key": "app:test",
            }, SOURCE_LOCAL_ADMIN)

            self.assertTrue(registry.authorize(local_admin)["allowed"])
            registry.commit(local_admin, {
                "ok": True,
                "limit": {
                    "key": "app:test", "enabled": False,
                    "limit_seconds": 60, "extension_seconds": 0,
                },
            })

            self.assertNotIn("app:test", ControlRegistry(path).controls()["limits"])

    def test_dispatch_rejects_unknown_protocol_and_operation(self):
        response, stopping = dispatch_request({"version": 99, "operation": "health"})
        self.assertFalse(response["ok"])
        self.assertFalse(stopping)
        response, stopping = dispatch_request({
            "version": PROTOCOL_VERSION,
            "operation": "unknown",
        })
        self.assertFalse(response["ok"])
        self.assertFalse(stopping)

    @unittest.skipUnless(sys.platform == "win32", "Windows named pipe integration")
    def test_authenticated_pipe_evaluates_and_stops_cleanly(self):
        address = rf"\\.\pipe\UsageGuardDecisionTest{uuid.uuid4().hex}"
        authkey = b"usage-guard-test-authentication-key"
        host = DecisionServiceHost(
            address, authkey, allow_interactive_clients=True
        )
        thread = threading.Thread(target=host.serve_forever, daemon=True)
        thread.start()
        client = DecisionServiceClient(address, authkey)
        deadline = time.monotonic() + 3
        while True:
            try:
                health = client.health()
                break
            except (
                FileNotFoundError, ConnectionRefusedError, EOFError,
                BrokenPipeError, AuthenticationError,
            ):
                if time.monotonic() >= deadline:
                    self.fail("Le pipe de test n’a pas démarré.")
                time.sleep(0.02)
        self.assertEqual(health["service"], "usage-guard-decision")

        with self.assertRaises(AuthenticationError):
            DecisionServiceClient(address, b"incorrect-authentication-key").health()
        self.assertTrue(client.health()["ok"])

        decision = client.evaluate(
            {
                "limit_seconds": 60,
                "extension_seconds": 30,
                "block_during_validity": False,
                "blocked_after": "",
            },
            {"seconds": 45, "extension_used": False},
            datetime.fromisoformat("2026-08-20T12:00:00+02:00"),
        )
        self.assertEqual(decision["allowed"], 60)
        self.assertEqual(decision["remaining"], 15)

        client.bootstrap_controls({}, {})
        remote = stamp_command({
            "action": "set_limit", "target_key": "app:test",
        }, SOURCE_BACKEND)
        client.commit_control(remote, {
            "ok": True,
            "limit": {
                "key": "app:test", "enabled": True,
                "limit_seconds": 60, "extension_seconds": 0,
                "managed_by": "backend",
            },
        })
        local_remove = stamp_command({
            "action": "remove_limit", "target_key": "app:test",
        }, SOURCE_LOCAL_API)
        self.assertFalse(client.authorize_control(local_remove)["allowed"])

        client.request("shutdown")
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
