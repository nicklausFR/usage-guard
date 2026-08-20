import json
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import ANY, MagicMock, patch
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from usage_guard_backend.server import BackendServer, EmailLimiter, Store, json_hash, COMMAND_RETRY_SECONDS


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

    def test_email_settings_hide_password_and_send_with_starttls(self):
        settings = self.server.store.save_email_settings({
            "enabled": True,
            "smtp_host": "smtp.example.test",
            "smtp_port": 587,
            "security": "starttls",
            "username": "usage-guard",
            "password": "smtp-secret",
            "sender": "Usage Guard <guard@example.test>",
            "recipient": "owner@example.test",
        })
        self.assertNotIn("password", settings)
        self.assertTrue(settings["password_configured"])
        with self.server.store.connect() as db:
            encrypted = db.execute(
                "SELECT payload FROM email_settings WHERE id=1"
            ).fetchone()["payload"]
        self.assertTrue(encrypted.startswith("v1."))
        self.assertNotIn("smtp.example.test", encrypted)
        self.assertNotIn("owner@example.test", encrypted)
        self.assertNotIn("smtp-secret", encrypted)

        smtp = MagicMock()
        connection = smtp.return_value.__enter__.return_value
        with patch("usage_guard_backend.server.smtplib.SMTP", smtp):
            result = self.server.store.send_email_notification(
                "Préavis", "Il reste cinq minutes.", "rule@example.test"
            )

        smtp.assert_called_once_with("smtp.example.test", 587, timeout=15)
        connection.starttls.assert_called_once_with(context=ANY)
        connection.login.assert_called_once_with("usage-guard", "smtp-secret")
        sent = connection.send_message.call_args.args[0]
        self.assertEqual(sent["To"], "rule@example.test")
        self.assertIn("Préavis", sent["Subject"])
        self.assertTrue(result["ok"])

    def test_email_notifications_are_disabled_by_default(self):
        result = self.server.store.send_email_notification(
            "Test", "Message", "owner@example.test"
        )
        self.assertTrue(result["skipped"])

    def test_email_rate_limiter_caps_each_recipient(self):
        limiter = EmailLimiter(limit=2, window=600)
        self.assertTrue(limiter.allow("owner@example.test"))
        self.assertTrue(limiter.allow("OWNER@example.test"))
        self.assertFalse(limiter.allow("owner@example.test"))
        self.assertTrue(limiter.allow("other@example.test"))

    def test_device_presence_reports_only_state_transitions(self):
        self.assertTrue(self.server.store.mark_device_seen("pc-test"))
        self.assertFalse(self.server.store.mark_device_seen("pc-test"))
        with self.server.store.connect() as db:
            db.execute(
                "UPDATE device_presence SET last_seen=? WHERE device_id=?",
                ((datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat(timespec="seconds"), "pc-test"),
            )
        self.assertTrue(self.server.store.mark_device_offline_if_stale("pc-test", 60))
        self.assertFalse(self.server.store.mark_device_offline_if_stale("pc-test", 60))
        self.assertTrue(self.server.store.mark_device_seen("pc-test"))

    def test_notification_list_and_mutations_are_scoped_to_connected_user(self):
        for username in ("alice", "bob"):
            self.request(
                "/api/v1/agent/users", "POST",
                {"device_id": "pc-test", "username": username, "password": "temporary-strong"}, True,
            )
        permissions = {key: True for key in self.server.store.public_user({
            "username": "alice", "must_change": 0, "is_admin": 0, "permissions": "{}",
        })["permissions"]}
        with self.server.store.connect() as db:
            for username in ("alice", "bob"):
                db.execute(
                    "UPDATE users SET must_change=0,is_admin=0,permissions=? WHERE username=?",
                    (json.dumps(permissions), username),
                )
        self.server.store.save_snapshot("pc-test", {"notification_rules": [
            {"id": "a", "kind": "pwa_login", "owner": "alice", "enabled": True},
            {"id": "b", "kind": "pwa_login", "owner": "bob", "enabled": True},
        ]})
        raw, csrf, _ = self.server.store.create_session("alice")
        cookie = f"ug_session={raw}"

        _, overview, _ = self.request("/api/v1/overview?scope=notifications", cookie=cookie)
        self.assertEqual([rule["id"] for rule in overview["notification_rules"]], ["a"])
        with self.assertRaises(HTTPError) as error:
            self.request(
                "/api/v1/actions", "POST",
                {"action": "remove_notification_rule", "rule_id": "b"},
                origin=PUBLIC_ORIGIN, cookie=cookie, csrf=csrf,
            )
        self.assertEqual(error.exception.code, 403)
        self.request(
            "/api/v1/actions", "POST",
            {"action": "set_notification_rule", "rule": {"kind": "client_connected", "enabled": True}},
            origin=PUBLIC_ORIGIN, cookie=cookie, csrf=csrf,
        )
        _, pending, _ = self.request("/api/v1/agent/commands?device_id=pc-test", agent=True)
        created = next(command for command in pending["commands"] if command["action"] == "set_notification_rule")
        self.assertEqual(created["rule"]["owner"], "alice")

    def test_smtp_update_preserves_existing_secret_without_global_recipient(self):
        self.server.store.save_email_settings({
            "smtp_host": "smtp.example.test", "smtp_port": 587,
            "security": "starttls", "username": "guard",
            "password": "smtp-secret", "sender": "guard@example.test",
            "recipient": "legacy@example.test",
        })

        public = self.server.store.save_email_settings({
            "enabled": True, "smtp_host": "smtp2.example.test",
        })
        stored = self.server.store.email_settings(include_password=True)

        self.assertNotIn("recipient", public)
        self.assertEqual(stored["recipient"], "legacy@example.test")
        self.assertEqual(stored["password"], "smtp-secret")

    def test_notification_recipients_are_encrypted_in_server_documents(self):
        snapshot = {"notification_rules": [{
            "kind": "pwa_login", "channels": ["email"],
            "email_recipient": "owner@example.test",
        }]}
        activity = {"days": {}, "notification_rules": [{
            "kind": "limit_change", "channels": ["email"],
            "email_recipient": "admin@example.test",
        }]}

        self.server.store.save_snapshot("pc-test", snapshot)
        self.server.store.save_activity_store("pc-test", activity)
        with self.server.store.connect() as db:
            raw_snapshot = db.execute(
                "SELECT payload FROM snapshots WHERE device_id='pc-test'"
            ).fetchone()["payload"]
            raw_activity = db.execute(
                "SELECT payload FROM activity_stores WHERE device_id='pc-test'"
            ).fetchone()["payload"]

        self.assertNotIn("owner@example.test", raw_snapshot)
        self.assertNotIn("admin@example.test", raw_activity)
        self.assertEqual(
            self.server.store.snapshot("pc-test")["notification_rules"][0]["email_recipient"],
            "owner@example.test",
        )

    def test_agent_can_save_read_and_manually_test_email(self):
        payload = {
            "device_id": "pc-test",
            "settings": {
                "enabled": False,
                "smtp_host": "smtp.example.test",
                "smtp_port": 465,
                "security": "ssl",
                "sender": "guard@example.test",
                "recipient": "owner@example.test",
            },
        }
        status, saved, _ = self.request("/api/v1/agent/email/settings", "POST", payload, True)
        self.assertEqual(status, 200)
        self.assertTrue(saved["email_settings"]["enabled"])
        _, current, _ = self.request("/api/v1/agent/email/settings?device_id=pc-test", agent=True)
        self.assertNotIn("password", current["email_settings"])

        smtp = MagicMock()
        with patch("usage_guard_backend.server.smtplib.SMTP_SSL", smtp):
            status, tested, _ = self.request(
                "/api/v1/agent/email/test", "POST", {
                    "device_id": "pc-test", "recipient": "test@example.test",
                }, True
            )
        self.assertEqual(status, 200)
        self.assertTrue(tested["ok"])
        smtp.assert_called_once_with("smtp.example.test", 465, timeout=15, context=ANY)

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

    def test_today_overview_uses_live_snapshot_not_embedded_analysis(self):
        snapshot = {
            "date": "2026-08-20",
            "usage": [{"key": "app:live", "label": "Live", "seconds": 1}],
            "limits": [], "merge_candidates": [],
            "analysis": {
                "date": "2026-08-13",
                "usage": [{"key": "app:stale", "label": "Stale", "seconds": 1}],
                "limits": [], "merge_candidates": [],
            },
        }
        self.request("/api/v1/agent/snapshot", "POST", {"device_id":"pc-test","snapshot":snapshot}, True)
        self.request("/api/v1/agent/users", "POST", {"device_id":"pc-test","username":"alice","password":"temporary-strong"}, True)
        _, login, headers = self.request("/api/v1/auth/login", "POST", {"username":"alice","password":"temporary-strong"}, origin=PUBLIC_ORIGIN)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        _, changed, headers = self.request("/api/v1/auth/password", "POST", {"current_password":"temporary-strong","new_password":"personal-strong-password"}, origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"])
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        _, overview, _ = self.request("/api/v1/overview?scope=today", cookie=cookie)
        _, analysis, _ = self.request("/api/v1/overview?scope=all", cookie=cookie)

        self.assertEqual(overview["usage"][0]["key"], "app:live")
        self.assertEqual(analysis["usage"][0]["key"], "app:stale")

    def test_pending_limit_command_is_merged_until_snapshot_contains_it(self):
        self.request("/api/v1/agent/snapshot", "POST", {"device_id":"pc-test","snapshot":{"usage":[],"limits":[]}}, True)
        self.request("/api/v1/agent/users", "POST", {"device_id":"pc-test","username":"alice","password":"temporary-strong"}, True)
        _, login, headers = self.request("/api/v1/auth/login", "POST", {"username":"alice","password":"temporary-strong"}, origin=PUBLIC_ORIGIN)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        _, changed, headers = self.request("/api/v1/auth/password", "POST", {"current_password":"temporary-strong","new_password":"personal-strong-password"}, origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"])
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        command = {
            "action": "set_limit",
            "target_key": "app:test",
            "settings": {"target_key": "app:test", "limit_seconds": 600},
        }

        self.request("/api/v1/actions", "POST", command, origin=PUBLIC_ORIGIN, cookie=cookie, csrf=changed["csrf_token"])
        _, overview, _ = self.request("/api/v1/overview?scope=today", cookie=cookie)
        self.assertEqual(overview["pending_limit_commands"][0]["target_key"], "app:test")
        _, pending, _ = self.request("/api/v1/agent/commands?device_id=pc-test", agent=True)
        command_id = pending["commands"][0]["id"]
        _, delivered_overview, _ = self.request("/api/v1/overview?scope=today", cookie=cookie)
        self.assertEqual(delivered_overview["pending_limit_commands"][0]["target_key"], "app:test")
        self.request(f"/api/v1/agent/commands/{command_id}/ack", "POST", {"device_id":"pc-test","result":{"ok":True}}, True)
        _, acked_overview, _ = self.request("/api/v1/overview?scope=today", cookie=cookie)
        self.assertEqual(acked_overview["pending_limit_commands"][0]["target_key"], "app:test")
        self.request("/api/v1/agent/snapshot", "POST", {"device_id":"pc-test","snapshot":{"usage":[],"limits":[]}}, True)
        _, missing_overview, _ = self.request("/api/v1/overview?scope=today", cookie=cookie)
        self.assertEqual(missing_overview["pending_limit_commands"][0]["target_key"], "app:test")
        old = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat(timespec="seconds")
        with self.server.store.connect() as db:
            db.execute("UPDATE commands SET created_at=?, delivered_at=?, acknowledged_at=? WHERE id=?", (old, old, old, command_id))
        _, stale_overview, _ = self.request("/api/v1/overview?scope=today", cookie=cookie)
        self.assertEqual(stale_overview["pending_limit_commands"], [])

    def test_recent_pending_limit_command_survives_newer_snapshot_without_limit(self):
        self.request("/api/v1/agent/snapshot", "POST", {"device_id":"pc-test","snapshot":{"usage":[],"limits":[]}}, True)
        self.request("/api/v1/agent/users", "POST", {"device_id":"pc-test","username":"alice","password":"temporary-strong"}, True)
        _, login, headers = self.request("/api/v1/auth/login", "POST", {"username":"alice","password":"temporary-strong"}, origin=PUBLIC_ORIGIN)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        _, changed, headers = self.request("/api/v1/auth/password", "POST", {"current_password":"temporary-strong","new_password":"personal-strong-password"}, origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"])
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        self.request("/api/v1/actions", "POST", {
            "action": "set_limit",
            "target_key": "app:old",
            "settings": {"target_key": "app:old", "limit_seconds": 600},
        }, origin=PUBLIC_ORIGIN, cookie=cookie, csrf=changed["csrf_token"])
        _, pending, _ = self.request("/api/v1/agent/commands?device_id=pc-test", agent=True)
        self.assertEqual(pending["commands"][0]["target_key"], "app:old")
        self.request("/api/v1/agent/snapshot", "POST", {"device_id":"pc-test","snapshot":{"usage":[],"limits":[]}}, True)
        _, overview, _ = self.request("/api/v1/overview?scope=today", cookie=cookie)
        self.assertEqual(overview["pending_limit_commands"][0]["target_key"], "app:old")

    def test_delivered_limit_command_is_retried_when_still_missing(self):
        self.request("/api/v1/agent/snapshot", "POST", {"device_id":"pc-test","snapshot":{"usage":[],"limits":[]}}, True)
        self.request("/api/v1/agent/users", "POST", {"device_id":"pc-test","username":"alice","password":"temporary-strong"}, True)
        _, login, headers = self.request("/api/v1/auth/login", "POST", {"username":"alice","password":"temporary-strong"}, origin=PUBLIC_ORIGIN)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        _, changed, headers = self.request("/api/v1/auth/password", "POST", {"current_password":"temporary-strong","new_password":"personal-strong-password"}, origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"])
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        self.request("/api/v1/actions", "POST", {
            "action": "set_limit",
            "target_key": "app:retry",
            "settings": {"target_key": "app:retry", "limit_seconds": 600},
        }, origin=PUBLIC_ORIGIN, cookie=cookie, csrf=changed["csrf_token"])
        _, first, _ = self.request("/api/v1/agent/commands?device_id=pc-test", agent=True)
        command_id = first["commands"][0]["id"]
        _, immediate, _ = self.request("/api/v1/agent/commands?device_id=pc-test", agent=True)
        self.assertEqual(immediate["commands"], [])

        stale_delivery = (datetime.now(timezone.utc) - timedelta(seconds=COMMAND_RETRY_SECONDS + 5)).isoformat(timespec="seconds")
        recent_created = (datetime.now(timezone.utc) - timedelta(seconds=COMMAND_RETRY_SECONDS + 10)).isoformat(timespec="seconds")
        with self.server.store.connect() as db:
            db.execute(
                "UPDATE commands SET created_at=?, delivered_at=? WHERE id=?",
                (recent_created, stale_delivery, command_id),
            )

        _, retried, _ = self.request("/api/v1/agent/commands?device_id=pc-test", agent=True)
        self.assertEqual(retried["commands"][0]["id"], command_id)
        self.assertEqual(retried["commands"][0]["target_key"], "app:retry")

    def test_acknowledged_limit_command_is_retried_when_snapshot_still_misses_it(self):
        self.request("/api/v1/agent/snapshot", "POST", {"device_id":"pc-test","snapshot":{"usage":[],"limits":[]}}, True)
        command_id = self.server.store.queue("pc-test", {
            "action": "set_limit",
            "target_key": "app:missing",
            "settings": {"target_key": "app:missing", "limit_seconds": 600},
        })
        stale_delivery = (datetime.now(timezone.utc) - timedelta(seconds=COMMAND_RETRY_SECONDS + 5)).isoformat(timespec="seconds")
        with self.server.store.connect() as db:
            db.execute(
                "UPDATE commands SET delivered_at=?, acknowledged_at=?, result=? WHERE id=?",
                (stale_delivery, stale_delivery, json.dumps({"ok": True, "limit": {"key": "app:missing"}}), command_id),
            )

        _, retried, _ = self.request("/api/v1/agent/commands?device_id=pc-test", agent=True)

        self.assertEqual(retried["commands"][0]["id"], str(command_id))
        self.assertEqual(retried["commands"][0]["target_key"], "app:missing")

    def test_old_undelivered_limit_command_is_kept_until_pc_takes_it(self):
        command_id = self.server.store.queue("pc-test", {
            "action": "set_limit",
            "target_key": "app:old",
            "settings": {"target_key": "app:old", "limit_seconds": 600},
        })
        old = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat(timespec="seconds")
        with self.server.store.connect() as db:
            db.execute("UPDATE commands SET created_at=? WHERE id=?", (old, command_id))

        pending_cards = self.server.store.pending_limit_commands("pc-test", {})
        pending_commands = self.server.store.pending("pc-test")
        self.assertEqual(pending_cards[0]["id"], str(command_id))
        self.assertEqual(pending_cards[0]["target_key"], "app:old")
        self.assertEqual(pending_commands[0]["id"], str(command_id))
        self.assertEqual(pending_commands[0]["target_key"], "app:old")

    def test_superseded_limit_commands_are_not_displayed_or_retried(self):
        older_id = self.server.store.queue("pc-test", {
            "action": "set_limit",
            "target_key": "app:codex",
            "settings": {"target_key": "app:codex", "limit_seconds": 600},
        })
        newer_id = self.server.store.queue("pc-test", {
            "action": "set_limit",
            "target_key": "app:codex",
            "settings": {"target_key": "app:codex", "limit_seconds": 1200},
        })

        pending_cards = self.server.store.pending_limit_commands("pc-test", {})
        pending_commands = self.server.store.pending("pc-test")

        self.assertEqual([item["id"] for item in pending_cards], [str(newer_id)])
        self.assertEqual([item["id"] for item in pending_commands], [str(newer_id)])
        self.assertNotIn(str(older_id), [item["id"] for item in pending_cards])

    def test_remove_limit_supersedes_previous_set_limit_for_source_target(self):
        older_id = self.server.store.queue("pc-test", {
            "action": "set_limit",
            "target_key": "category:Programmation+ChatGPT",
            "settings": {"target_key": "app:codex", "limit_seconds": 600},
        })
        remove_id = self.server.store.queue("pc-test", {
            "action": "remove_limit",
            "target_key": "category:Programmation+ChatGPT",
        })

        pending_cards = self.server.store.pending_limit_commands("pc-test", {})
        pending_commands = self.server.store.pending("pc-test")

        self.assertEqual([item["id"] for item in pending_cards], [str(remove_id)])
        self.assertEqual([item["id"] for item in pending_commands], [str(remove_id)])
        self.assertNotIn(str(older_id), [item["id"] for item in pending_cards])

    def test_acknowledged_old_limit_command_is_not_retried_forever(self):
        self.request("/api/v1/agent/snapshot", "POST", {"device_id":"pc-test","snapshot":{"usage":[],"limits":[]}}, True)
        command_id = self.server.store.queue("pc-test", {
            "action": "set_limit",
            "target_key": "app:stale",
            "settings": {"target_key": "app:stale", "limit_seconds": 600},
        })
        old = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat(timespec="seconds")
        with self.server.store.connect() as db:
            db.execute(
                "UPDATE commands SET delivered_at=?, acknowledged_at=?, result=? WHERE id=?",
                (old, old, json.dumps({"ok": True, "limit": {"key": "app:stale"}}), command_id),
            )

        pending_cards = self.server.store.pending_limit_commands("pc-test", {})
        pending_commands = self.server.store.pending("pc-test")

        self.assertEqual(pending_cards, [])
        self.assertEqual(pending_commands, [])

    def test_recently_reacknowledged_old_limit_command_is_purged_by_creation_date(self):
        command_id = self.server.store.queue("pc-test", {
            "action": "set_limit",
            "target_key": "app:stale",
            "settings": {"target_key": "app:stale", "limit_seconds": 600},
        })
        old = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat(timespec="seconds")
        recent = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self.server.store.connect() as db:
            db.execute(
                "UPDATE commands SET created_at=?, delivered_at=?, acknowledged_at=?, result=? WHERE id=?",
                (old, recent, recent, json.dumps({"ok": True, "limit": {"key": "app:stale"}}), command_id),
            )

        self.server.store.purge_stale_commands()
        pending_cards = self.server.store.pending_limit_commands("pc-test", {})
        pending_commands = self.server.store.pending("pc-test")

        self.assertEqual(pending_cards, [])
        self.assertEqual(pending_commands, [])

    def test_create_new_limit_is_reflected_only_by_created_key(self):
        command = {
            "action": "set_limit",
            "target_key": "category:Jeux",
            "settings": {
                "create_new": True,
                "target_key": "category:Jeux",
                "limit_seconds": 600,
            },
        }
        snapshot_with_existing_limit = {
            "limits": [{"key": "category:Jeux", "target_key": "category:Jeux"}],
        }
        snapshot_with_created_limit = {
            "limits": [
                {"key": "category:Jeux", "target_key": "category:Jeux"},
                {"key": "category:Jeux#abcd1234", "target_key": "category:Jeux"},
            ],
        }

        self.assertFalse(
            Store._limit_command_reflected(snapshot_with_existing_limit, command)
        )
        self.assertFalse(
            Store._limit_command_reflected(
                snapshot_with_existing_limit,
                command,
                {"ok": True, "limit": {"key": "category:Jeux#abcd1234"}},
            )
        )
        self.assertTrue(
            Store._limit_command_reflected(
                snapshot_with_created_limit,
                command,
                {"ok": True, "limit": {"key": "category:Jeux#abcd1234"}},
            )
        )

    def test_computer_block_command_is_not_reflected_by_previous_block(self):
        command = {
            "action": "set_computer_block",
            "mode": "duration",
            "duration_seconds": 600,
        }
        snapshot_with_previous_block = {
            "computer_block": {
                "mode": "duration",
                "started_at": "2026-08-20T10:00:00+02:00",
                "ends_at": "2026-08-20T11:00:00+02:00",
            },
        }
        result = {
            "ok": True,
            "computer_block": {
                "mode": "duration",
                "started_at": "2026-08-20T12:00:00+02:00",
                "ends_at": "2026-08-20T12:10:00+02:00",
            },
        }
        snapshot_with_new_block = {"computer_block": dict(result["computer_block"])}

        self.assertFalse(
            Store._limit_command_reflected(snapshot_with_previous_block, command)
        )
        self.assertFalse(
            Store._limit_command_reflected(snapshot_with_previous_block, command, result)
        )
        self.assertTrue(
            Store._limit_command_reflected(snapshot_with_new_block, command, result)
        )

    def test_pending_limit_command_is_removed_when_snapshot_contains_it(self):
        self.request("/api/v1/agent/snapshot", "POST", {"device_id":"pc-test","snapshot":{"usage":[],"limits":[]}}, True)
        self.request("/api/v1/agent/users", "POST", {"device_id":"pc-test","username":"alice","password":"temporary-strong"}, True)
        _, login, headers = self.request("/api/v1/auth/login", "POST", {"username":"alice","password":"temporary-strong"}, origin=PUBLIC_ORIGIN)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        _, changed, headers = self.request("/api/v1/auth/password", "POST", {"current_password":"temporary-strong","new_password":"personal-strong-password"}, origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"])
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        command = {
            "action": "set_limit",
            "target_key": "app:test",
            "settings": {"target_key": "app:test", "limit_seconds": 600},
        }

        self.request("/api/v1/actions", "POST", command, origin=PUBLIC_ORIGIN, cookie=cookie, csrf=changed["csrf_token"])
        self.request("/api/v1/agent/commands?device_id=pc-test", agent=True)
        self.request("/api/v1/agent/snapshot", "POST", {"device_id":"pc-test","snapshot":{"usage":[],"limits":[{"key":"app:test","target_key":"app:test","label":"Test"}]}}, True)
        _, reflected_overview, _ = self.request("/api/v1/overview?scope=today", cookie=cookie)
        self.assertEqual(reflected_overview["pending_limit_commands"], [])

    def test_analysis_overview_falls_back_to_activity_store_when_snapshot_analysis_is_missing(self):
        self.request("/api/v1/agent/snapshot", "POST", {"device_id":"pc-test","snapshot":{"usage":[],"limits":[]}}, True)
        self.request("/api/v1/agent/activity", "POST", {"device_id":"pc-test","activity":{
            "version": 2,
            "days": {"2026-08-20": {"app:codex": 42}},
            "targets": {"app:codex": {"label": "Codex", "category": "Programmation"}},
            "category_parents": {},
            "category_order": ["Programmation"],
            "site_categories": [],
        }}, True)
        self.request("/api/v1/agent/users", "POST", {"device_id":"pc-test","username":"alice","password":"temporary-strong"}, True)
        _, login, headers = self.request("/api/v1/auth/login", "POST", {"username":"alice","password":"temporary-strong"}, origin=PUBLIC_ORIGIN)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        _, changed, headers = self.request("/api/v1/auth/password", "POST", {"current_password":"temporary-strong","new_password":"personal-strong-password"}, origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"])
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        _, analysis, _ = self.request("/api/v1/overview?scope=all", cookie=cookie)

        self.assertEqual(analysis["scope"], "all")
        self.assertEqual(analysis["daily_stats"][0]["usage"][0]["key"], "app:codex")
        self.assertIn("Programmation", analysis["categories"])
        self.assertEqual(analysis["merge_candidates"][0]["label"], "Codex")

    def test_analysis_overview_rebuilds_when_embedded_analysis_has_no_days(self):
        self.request("/api/v1/agent/snapshot", "POST", {"device_id":"pc-test","snapshot":{
            "usage": [], "limits": [],
            "analysis": {
                "merge_candidates": [{"key": "app:empty", "label": "Empty"}],
                "daily_stats": [],
                "usage": [],
            },
        }}, True)
        self.request("/api/v1/agent/activity", "POST", {"device_id":"pc-test","activity":{
            "version": 2,
            "days": {"2026-08-20": {"app:codex": 42}},
            "targets": {"app:codex": {"label": "Codex", "category": "Programmation"}},
            "category_parents": {},
            "category_order": ["Programmation"],
            "site_categories": [],
        }}, True)
        self.request("/api/v1/agent/users", "POST", {"device_id":"pc-test","username":"alice","password":"temporary-strong"}, True)
        _, login, headers = self.request("/api/v1/auth/login", "POST", {"username":"alice","password":"temporary-strong"}, origin=PUBLIC_ORIGIN)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        _, changed, headers = self.request("/api/v1/auth/password", "POST", {"current_password":"temporary-strong","new_password":"personal-strong-password"}, origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"])
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        _, analysis, _ = self.request("/api/v1/overview?scope=all", cookie=cookie)

        self.assertEqual(analysis["daily_stats"][0]["usage"][0]["key"], "app:codex")
        self.assertEqual(analysis["merge_candidates"][0]["label"], "Codex")

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

    def test_activity_delta_is_applied_on_server(self):
        activity = {
            "version": 2,
            "days": {"2026-08-13": {"app:test": 12}},
            "app_limit_settings": {},
        }
        updated = {
            "version": 2,
            "days": {"2026-08-13": {"app:test": 18}},
            "app_limit_settings": {},
        }
        delta = {
            "kind": "dict",
            "remove": [],
            "set": {},
            "patch": {
                "days": {
                    "kind": "dict",
                    "remove": [],
                    "set": {},
                    "patch": {
                        "2026-08-13": {
                            "kind": "dict",
                            "remove": [],
                            "set": {},
                            "patch": {
                                "app:test": {"kind": "value", "value": 18},
                            },
                        },
                    },
                },
            },
        }
        self.request(
            "/api/v1/agent/activity", "POST",
            {"device_id": "pc-test", "activity": activity}, True,
        )
        status, saved, _ = self.request(
            "/api/v1/agent/activity", "POST",
            {
                "device_id": "pc-test",
                "activity_delta": delta,
                "base_hash": json_hash(activity),
                "target_hash": json_hash(updated),
            },
            True,
        )
        self.assertEqual(status, 200)
        self.assertTrue(saved["ok"])
        _, restored, _ = self.request("/api/v1/agent/activity?device_id=pc-test", agent=True)
        self.assertEqual(restored["activity"], updated)

    def test_activity_delta_conflict_returns_409(self):
        activity = {"version": 2, "days": {}, "app_limit_settings": {}}
        self.request(
            "/api/v1/agent/activity", "POST",
            {"device_id": "pc-test", "activity": activity}, True,
        )
        with self.assertRaises(HTTPError) as error:
            self.request(
                "/api/v1/agent/activity", "POST",
                {
                    "device_id": "pc-test",
                    "activity_delta": {"kind": "dict", "remove": [], "set": {"version": 3}, "patch": {}},
                    "base_hash": "stale",
                    "target_hash": json_hash({"version": 3, "days": {}, "app_limit_settings": {}}),
                },
                True,
            )
        self.assertEqual(error.exception.code, 409)

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
        self.assertTrue(command["windows_only"])

    def test_successful_login_sends_email_directly_without_waiting_for_pc(self):
        self.server.store.save_email_settings({
            "smtp_host": "smtp.example.test", "smtp_port": 587,
            "security": "starttls", "sender": "guard@example.test",
        })
        self.request(
            "/api/v1/agent/snapshot", "POST",
            {"device_id": "pc-test", "snapshot": {
                "notification_rules": [{
                    "kind": "pwa_login", "enabled": True,
                    "channels": ["email"],
                    "email_recipient": "owner@example.test",
                }],
            }}, True,
        )
        self.request(
            "/api/v1/agent/users", "POST",
            {"device_id": "pc-test", "username": "alice", "password": "temporary-strong"},
            True,
        )
        delivered = threading.Event()
        calls = []

        def record_delivery(*args):
            calls.append(args)
            delivered.set()

        with patch.object(self.server, "_send_email_background", side_effect=record_delivery):
            self.request(
                "/api/v1/auth/login", "POST",
                {"username": "alice", "password": "temporary-strong"},
                origin=PUBLIC_ORIGIN,
            )
            self.assertTrue(delivered.wait(1))

        self.assertEqual(calls[0][2], "owner@example.test")
        _, pending, _ = self.request(
            "/api/v1/agent/commands?device_id=pc-test", agent=True,
        )
        self.assertEqual(pending["commands"], [])

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
