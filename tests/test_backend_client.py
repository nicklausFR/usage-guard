import unittest
from pathlib import Path
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
