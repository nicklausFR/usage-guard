import unittest
import json
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend_client import BackendClient


class BackendClientTest(unittest.TestCase):
    def test_requires_https_and_long_device_token(self):
        common = {"enabled": True, "device_id": "pc", "device_token": "x" * 40}
        self.assertFalse(BackendClient(lambda: {}, lambda _: {}, {**common, "base_url": "http://example.test"}).configured)
        self.assertTrue(BackendClient(lambda: {}, lambda _: {}, {**common, "base_url": "https://example.test/usage-guard"}).configured)
        self.assertFalse(BackendClient(lambda: {}, lambda _: {}, {**common, "base_url": "https://example.test", "device_token": "short"}).configured)

    def test_request_rejects_an_invalid_backend_configuration(self):
        client = BackendClient(lambda: {}, lambda _: {}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "file:///tmp/not-a-backend",
        })
        with self.assertRaises(RuntimeError):
            client._request("GET", "/api/v1/overview")

    def test_user_methods_use_agent_endpoints(self):
        client = BackendClient(lambda: {}, lambda _: {}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        })
        calls = []
        client._request = lambda method, path, payload=None: calls.append((method, path, payload)) or {"ok": True}
        client.list_users()
        client.create_user("alice", "password-long")
        client.delete_user("alice test")
        client.update_user_access("alice test", True, {"view_activity": True})
        self.assertEqual(calls[0][:2], ("GET", "/api/v1/agent/users?device_id=pc"))
        self.assertEqual(calls[1][2]["device_id"], "pc")
        self.assertIn("alice%20test", calls[2][1])
        self.assertEqual(calls[3][0], "POST")
        self.assertEqual(calls[3][1], "/api/v1/agent/users/alice%20test/access")
        self.assertTrue(calls[3][2]["is_admin"])

    def test_email_configuration_and_manual_test_use_agent_endpoints(self):
        client = BackendClient(lambda: {}, lambda _: {}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        })
        calls = []
        client._request = lambda method, path, payload=None: calls.append((method, path, payload)) or {"ok": True}

        client.email_settings()
        client.save_email_settings({"enabled": False, "smtp_host": "smtp.example.test"})
        client.test_email_settings("test@example.test")

        self.assertEqual(calls[0][:2], ("GET", "/api/v1/agent/email/settings?device_id=pc"))
        self.assertFalse(calls[1][2]["settings"]["enabled"])
        self.assertEqual(calls[2][:2], ("POST", "/api/v1/agent/email/test"))
        self.assertEqual(calls[2][2]["recipient"], "test@example.test")

    def test_queued_notification_is_relayed_during_sync(self):
        client = BackendClient(lambda: {"usage": []}, lambda _: {}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        })
        calls = []
        client._request = lambda method, path, payload=None: calls.append((method, path, payload)) or {"commands": []}
        client.queue_email_notification(
            "Limite", "Temps écoulé", "owner@example.test"
        )

        client._sync()

        relay = next(call for call in calls if call[1] == "/api/v1/agent/email/send")
        self.assertEqual(relay[2]["title"], "Limite")
        self.assertEqual(relay[2]["message"], "Temps écoulé")
        self.assertEqual(relay[2]["recipient"], "owner@example.test")
        self.assertFalse(client._pending_email_notifications)

    def test_sync_publishes_complete_activity_store(self):
        activity = {"days": {"2026-08-13": {"app:test": 12}}, "app_limit_settings": {}}
        client = BackendClient(lambda *_: {"usage": []}, lambda _: {}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        }, activity_provider=lambda: activity)
        calls = []
        client._request = lambda method, path, payload=None: calls.append((method, path, payload)) or ({"activity": None} if method == "GET" and "activity" in path else {"commands": []})

        client._sync()

        upload = next(call for call in calls if call[0] == "POST" and call[1] == "/api/v1/agent/activity")
        self.assertEqual(upload[2]["activity"], activity)

    def test_snapshot_publish_does_not_duplicate_complete_analysis(self):
        snapshot_calls = []
        uploads = []

        def snapshot_provider(*args):
            snapshot_calls.append(args)
            return {"usage": [], "daily_stats": []}

        client = BackendClient(snapshot_provider, lambda _: {}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        })
        def request(method, path, payload=None):
            if method == "POST" and path == "/api/v1/agent/snapshot":
                uploads.append(payload)
            return {"commands": []}

        client._request = request

        client._sync()

        self.assertEqual(snapshot_calls, [()])
        self.assertNotIn("analysis", uploads[0]["snapshot"])

    def test_snapshot_is_published_when_activity_upload_fails(self):
        client = BackendClient(lambda: {"limits": [{"key": "app:test"}]}, lambda _: {}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        }, activity_provider=lambda: {"days": {}})
        calls = []

        def request(method, path, payload=None):
            calls.append((method, path, payload))
            if method == "GET" and "activity" in path:
                return {"activity": None}
            if method == "POST" and path == "/api/v1/agent/activity":
                raise HTTPError("https://example.test", 500, "server error", {}, None)
            if method == "GET" and path.startswith("/api/v1/agent/commands"):
                return {"commands": []}
            return {"ok": True}

        client._request = request
        client._sync()

        snapshot_uploads = [call for call in calls if call[0] == "POST" and call[1] == "/api/v1/agent/snapshot"]
        self.assertEqual(snapshot_uploads[0][2]["snapshot"]["limits"][0]["key"], "app:test")

    def test_sync_publishes_activity_delta_after_initial_upload(self):
        activities = [
            {"days": {"2026-08-13": {"app:test": 12}}, "app_limit_settings": {}},
            {"days": {"2026-08-13": {"app:test": 18}}, "app_limit_settings": {}},
        ]
        client = BackendClient(lambda *_: {"usage": []}, lambda _: {}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        }, activity_provider=lambda: activities[0])
        calls = []
        client._request = lambda method, path, payload=None: calls.append((method, path, payload)) or ({"activity": None} if method == "GET" and "activity" in path else {"commands": []})

        client._sync()
        client.activity_provider = lambda: activities[1]
        client._sync()

        uploads = [call for call in calls if call[0] == "POST" and call[1] == "/api/v1/agent/activity"]
        self.assertIn("activity", uploads[0][2])
        self.assertIn("activity_delta", uploads[1][2])
        self.assertNotIn("activity", uploads[1][2])

    def test_delta_conflict_falls_back_to_complete_upload(self):
        current = {"days": {"2026-08-13": {"app:test": 12}}, "app_limit_settings": {}}
        updated = {"days": {"2026-08-13": {"app:test": 18}}, "app_limit_settings": {}}
        client = BackendClient(lambda *_: {"usage": []}, lambda _: {}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        }, activity_provider=lambda: current)
        calls = []

        def request(method, path, payload=None):
            calls.append((method, path, payload))
            if method == "GET" and "activity" in path:
                return {"activity": None}
            if payload and "activity_delta" in payload:
                raise HTTPError("https://example.test", 409, "conflict", {}, None)
            return {"commands": []}

        client._request = request
        client._sync()
        client.activity_provider = lambda: updated
        client._sync()

        uploads = [call[2] for call in calls if call[0] == "POST" and call[1] == "/api/v1/agent/activity"]
        self.assertIn("activity_delta", uploads[1])
        self.assertEqual(uploads[2]["activity"], updated)

    def test_sync_still_fetches_commands_when_state_publish_fails(self):
        handled = []
        client = BackendClient(lambda *_: {"usage": []}, lambda command: handled.append(command) or {"ok": True}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        })
        calls = []

        def request(method, path, payload=None):
            calls.append((method, path, payload))
            if method == "POST" and path == "/api/v1/agent/snapshot":
                raise HTTPError("https://example.test", 500, "server error", {}, None)
            if method == "GET" and path.startswith("/api/v1/agent/commands"):
                return {"commands": [{"id": "7", "action": "set_language", "language": "fr"}]}
            return {"ok": True}

        client._request = request
        client._sync()

        self.assertEqual(handled[0]["action"], "set_language")
        self.assertIn("_remote_command_id", handled[0])
        self.assertTrue(any(call[0] == "POST" and call[1] == "/api/v1/agent/commands/7/ack" for call in calls))

    def test_upload_traffic_counts_successful_request_payloads_and_resets(self):
        client = BackendClient(lambda: {}, lambda _: {}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        })
        body = {"device_id": "pc", "snapshot": {"usage": []}}

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return b"{}"

        with patch("backend_client.urlopen", return_value=Response()):
            client._request("POST", "/api/v1/agent/snapshot", body)

        stats = client.traffic_stats()
        self.assertEqual(stats["uploaded_bytes"], len(json.dumps(body).encode("utf-8")))
        self.assertGreaterEqual(stats["upload_rate_bytes_per_minute"], 0)
        self.assertIsNotNone(stats["last_upload_at"])

        reset = client.reset_traffic_stats()
        self.assertEqual(reset["uploaded_bytes"], 0)
        self.assertIsNone(reset["last_upload_at"])
