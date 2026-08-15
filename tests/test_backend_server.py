import json
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from usage_guard_backend.server import BackendServer, Store


PUBLIC_ORIGIN = "https://example.test"


class BackendServerTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        (root / "index.html").write_text("Usage Guard", encoding="utf-8")
        self.token = "t" * 48
        self.server = BackendServer(
            port=0, store=Store(root / "test.sqlite3"), device_id="pc-test",
            device_token=self.token, public_origin=PUBLIC_ORIGIN, pwa_dir=root,
        )
        self.thread = threading.Thread(target=self.server.start, daemon=True)
        self.thread.start()
        for _ in range(50):
            if self.server.httpd: break
            time.sleep(.01)
        self.base = f"http://127.0.0.1:{self.server.httpd.server_address[1]}/usage-guard"

    def tearDown(self):
        self.server.stop(); self.thread.join(timeout=2); self.temporary.cleanup()

    def test_csp_allows_dynamic_style_attributes_needed_by_charts(self):
        with urlopen(self.base + "/", timeout=2) as response:
            policy = response.headers["Content-Security-Policy"]
        self.assertIn("style-src 'self'", policy)
        self.assertIn("style-src-attr 'unsafe-inline'", policy)

    def request(self, path, method="GET", payload=None, agent=False, origin=None, cookie=None, csrf=None):
        headers = {"Accept": "application/json"}
        if agent: headers["Authorization"] = "Bearer " + self.token
        if origin: headers["Origin"] = origin
        if cookie: headers["Cookie"] = cookie
        if csrf: headers["X-CSRF-Token"] = csrf
        data = None if payload is None else json.dumps(payload).encode()
        if data: headers["Content-Type"] = "application/json"
        with urlopen(Request(self.base + path, data=data, method=method, headers=headers), timeout=2) as response:
            return response.status, json.load(response), response.headers

    def test_snapshot_command_and_acknowledgement_flow(self):
        status, _, _ = self.request("/api/v1/agent/snapshot", "POST", {"device_id":"pc-test","snapshot":{"usage":[]}}, True)
        self.assertEqual(status, 200)
        _, created, _ = self.request("/api/v1/agent/users", "POST", {"device_id":"pc-test","username":"alice","password":"temporary-strong"}, True)
        self.assertTrue(created["user"]["must_change"])
        _, login, login_headers = self.request("/api/v1/auth/login", "POST", {"username":"alice","password":"temporary-strong"}, origin=PUBLIC_ORIGIN)
        cookie = login_headers["Set-Cookie"].split(";", 1)[0]
        self.assertIn("Secure", login_headers["Set-Cookie"])
        self.assertIn("HttpOnly", login_headers["Set-Cookie"])
        self.assertTrue(login["must_change"])
        with self.assertRaises(HTTPError) as error:
            self.request("/api/v1/overview", cookie=cookie)
        self.assertEqual(error.exception.code, 403)
        with self.assertRaises(HTTPError) as error:
            self.request("/api/v1/actions", "POST", {"action":"reset_limit","target_key":"app:test"}, origin=PUBLIC_ORIGIN, cookie=cookie)
        self.assertEqual(error.exception.code, 403)
        _, changed, changed_headers = self.request("/api/v1/auth/password", "POST", {"current_password":"temporary-strong","new_password":"personal-strong-password"}, origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"])
        cookie = changed_headers["Set-Cookie"].split(";", 1)[0]
        self.assertFalse(changed["must_change"])
        status, overview, _ = self.request("/api/v1/overview", cookie=cookie)
        self.assertEqual(overview["usage"], [])
        status, queued, _ = self.request("/api/v1/actions", "POST", {"action":"reset_limit","target_key":"app:test"}, origin=PUBLIC_ORIGIN, cookie=cookie, csrf=changed["csrf_token"])
        self.assertEqual(status, 202)
        _, pending, _ = self.request("/api/v1/agent/commands?device_id=pc-test", agent=True)
        self.assertEqual(pending["commands"][0]["action"], "reset_limit")
        command_id = pending["commands"][0]["id"]
        _, second, _ = self.request("/api/v1/agent/commands?device_id=pc-test", agent=True)
        self.assertEqual(second["commands"], [])
        status, ack, _ = self.request(f"/api/v1/agent/commands/{command_id}/ack", "POST", {"device_id":"pc-test","result":{"ok":True}}, True)
        self.assertTrue(ack["ok"])

    def test_complete_activity_store_is_persisted_on_server(self):
        activity = {
            "version": 2,
            "days": {"2026-08-13": {"app:potplayermini64": 42}},
            "app_limit_settings": {"app:potplayermini64": {"enabled": True, "limit_seconds": 3600}},
            "excluded": ["app:ignored"],
        }
        status, saved, _ = self.request(
            "/api/v1/agent/activity", "POST",
            {"device_id": "pc-test", "activity": activity}, True,
        )
        self.assertEqual(status, 200)
        self.assertTrue(saved["ok"])
        _, restored, _ = self.request("/api/v1/agent/activity?device_id=pc-test", agent=True)
        self.assertEqual(restored["activity"], activity)

    def test_successful_login_queues_a_notification_when_requested(self):
        self.request(
            "/api/v1/agent/snapshot", "POST",
            {"device_id": "pc-test", "snapshot": {
                "notification_rules": [{
                    "kind": "pwa_login", "enabled": True,
                }],
            }}, True,
        )
        self.request(
            "/api/v1/agent/users", "POST",
            {"device_id": "pc-test", "username": "alice", "password": "temporary-strong"},
            True,
        )
        self.request(
            "/api/v1/auth/login", "POST",
            {"username": "alice", "password": "temporary-strong"},
            origin=PUBLIC_ORIGIN,
        )

        _, pending, _ = self.request(
            "/api/v1/agent/commands?device_id=pc-test", agent=True,
        )
        command = pending["commands"][0]
        self.assertEqual(command["action"], "notify_pwa_login")
        self.assertEqual(command["actor"], "alice")

    def test_user_administration_is_agent_only_and_last_user_is_protected(self):
        with self.assertRaises(HTTPError) as error:
            self.request("/api/v1/agent/users?device_id=pc-test")
        self.assertEqual(error.exception.code, 401)
        self.request("/api/v1/agent/users", "POST", {"device_id":"pc-test","username":"alice","password":"temporary-strong"}, True)
        _, users, _ = self.request("/api/v1/agent/users?device_id=pc-test", agent=True)
        self.assertEqual([user["username"] for user in users["users"]], ["alice"])
        with self.assertRaises(HTTPError) as error:
            self.request("/api/v1/agent/users/alice?device_id=pc-test", "DELETE", agent=True)
        self.assertEqual(error.exception.code, 400)
        self.request("/api/v1/agent/users", "POST", {"device_id":"pc-test","username":"bob","password":"temporary-strong"}, True)
        status, updated, _ = self.request(
            "/api/v1/agent/users/bob/access", "POST",
            {"device_id":"pc-test","is_admin":True,"permissions":{}}, True,
        )
        self.assertEqual(status, 200)
        self.assertTrue(updated["user"]["is_admin"])
        status, _, _ = self.request("/api/v1/agent/users/bob?device_id=pc-test", "DELETE", agent=True)
        self.assertEqual(status, 200)

    def test_admin_can_restrict_views_and_modifications(self):
        self.request("/api/v1/agent/snapshot", "POST", {"device_id":"pc-test","snapshot":{"usage":[],"limits":[]}}, True)
        self.request("/api/v1/agent/users", "POST", {"device_id":"pc-test","username":"admin","password":"temporary-strong"}, True)
        _, login, headers = self.request("/api/v1/auth/login", "POST", {"username":"admin","password":"temporary-strong"}, origin=PUBLIC_ORIGIN)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        _, changed, headers = self.request("/api/v1/auth/password", "POST", {"current_password":"temporary-strong","new_password":"personal-admin-password"}, origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"])
        admin_cookie = headers["Set-Cookie"].split(";", 1)[0]
        self.request("/api/v1/agent/users", "POST", {"device_id":"pc-test","username":"viewer","password":"temporary-viewer"}, True)
        permissions = {"view_activity": True, "view_analysis": False, "view_limits": False, "manage_activity": False, "manage_limits": False}
        self.request("/api/v1/admin/users/viewer/access", "POST", {"is_admin":False,"permissions":permissions}, origin=PUBLIC_ORIGIN, cookie=admin_cookie, csrf=changed["csrf_token"])
        _, viewer, headers = self.request("/api/v1/auth/login", "POST", {"username":"viewer","password":"temporary-viewer"}, origin=PUBLIC_ORIGIN)
        viewer_cookie = headers["Set-Cookie"].split(";", 1)[0]
        _, viewer_changed, headers = self.request("/api/v1/auth/password", "POST", {"current_password":"temporary-viewer","new_password":"personal-viewer-password"}, origin=PUBLIC_ORIGIN, cookie=viewer_cookie, csrf=viewer["csrf_token"])
        viewer_cookie = headers["Set-Cookie"].split(";", 1)[0]
        _, overview, _ = self.request("/api/v1/overview?scope=today", cookie=viewer_cookie)
        self.assertEqual(overview["limits"], [])
        with self.assertRaises(HTTPError) as error:
            self.request("/api/v1/overview?scope=all", cookie=viewer_cookie)
        self.assertEqual(error.exception.code, 403)
        with self.assertRaises(HTTPError) as error:
            self.request("/api/v1/actions", "POST", {"action":"rename_target"}, origin=PUBLIC_ORIGIN, cookie=viewer_cookie, csrf=viewer_changed["csrf_token"])
        self.assertEqual(error.exception.code, 403)

    def test_existing_oldest_user_is_promoted_admin_during_migration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.sqlite3"
            db = sqlite3.connect(path)
            db.execute("CREATE TABLE users(username TEXT PRIMARY KEY COLLATE NOCASE,salt BLOB NOT NULL,password_hash BLOB NOT NULL,must_change INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)")
            db.execute("INSERT INTO users VALUES(?,?,?,?,?,?)", ("legacy-user", b"0"*16, b"0"*32, 0, "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"))
            db.commit(); db.close()
            users = Store(path).list_users()
            self.assertTrue(users[0]["is_admin"])
            self.assertTrue(all(users[0]["permissions"].values()))

    def test_rejects_bad_agent_token_origin_and_unknown_action(self):
        with self.assertRaises(HTTPError) as error:
            self.request("/api/v1/agent/commands?device_id=pc-test")
        self.assertEqual(error.exception.code, 401)
        with self.assertRaises(HTTPError) as error:
            self.request("/api/v1/actions", "POST", {"action":"reset_limit"}, origin="https://evil.test")
        self.assertEqual(error.exception.code, 403)

    def test_refuses_a_public_listen_address(self):
        with self.assertRaises(ValueError):
            BackendServer(
                host="0.0.0.0", port=0, store=self.server.store,
                device_id="pc-test", device_token=self.token,
            )
