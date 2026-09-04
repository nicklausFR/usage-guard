import copy
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
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from usage_guard_backend.server import (
    BackendServer, EmailLimiter, Store, json_hash, interval_union_seconds,
    snapshot_with_presence, snapshot_with_device_context,
    COMMAND_RETRY_SECONDS, DocumentConflict, IdempotencyConflict,
    notification_subject_roles,
    snapshot_for_day_scope, analysis_snapshot_since,
    snapshot_with_interval_history,
    normalize_notification_rules,
    target_display_label,
    MAX_INCREMENTAL_ACTIVITY_BYTES,
)


PUBLIC_ORIGIN = "https://example.test"


class BackendServerTest(unittest.TestCase):
    def test_normalized_site_key_uses_host_as_display_label(self):
        self.assertEqual(
            target_display_label(
                "site:brave.exe:gpx.studio",
                "site:brave.exe:gpx.studio",
            ),
            "gpx.studio",
        )

    def test_analysis_delta_keeps_open_sessions_but_only_recent_events(self):
        snapshot = {
            "sessions": [
                {"started_at": "2026-08-01T09:00:00+02:00", "ended_at": "2026-08-01T10:00:00+02:00"},
                {"started_at": "2026-08-20T09:00:00+02:00", "ended_at": None},
                {"started_at": "2026-08-26T09:00:00+02:00", "ended_at": "2026-08-26T10:00:00+02:00"},
            ],
            "windows_sessions": [],
            "system_events": [
                {"type": "sleep", "at": "2026-08-01T11:00:00+02:00"},
                {"type": "resume", "at": "2026-08-26T11:00:00+02:00"},
            ],
            "daily_stats": [
                {"date": "2026-08-01", "active": 10},
                {"date": "2026-08-26", "active": 20},
            ],
            "timeline": {"start": "2026-08-01", "end": "2026-08-27"},
        }

        result = analysis_snapshot_since(snapshot, "2026-08-25")

        self.assertEqual(len(result["sessions"]), 2)
        self.assertIsNone(result["sessions"][0]["ended_at"])
        self.assertEqual(
            [item["type"] for item in result["system_events"]], ["resume"],
        )
        self.assertEqual(
            [item["date"] for item in result["daily_stats"]], ["2026-08-26"],
        )
        self.assertEqual(result["delta_since"], "2026-08-25")

    def test_analysis_delta_uses_local_midnight_not_utc_date_prefix(self):
        snapshot = {
            "sessions": [{
                "kind": "active", "key": "app:kona",
                "started_at": "2026-08-29T00:05:00+02:00",
                "ended_at": "2026-08-29T00:15:00+02:00",
            }, {
                "kind": "active", "key": "app:old",
                "started_at": "2026-08-28T23:40:00+02:00",
                "ended_at": "2026-08-28T23:50:00+02:00",
            }],
            "windows_sessions": [], "system_events": [], "daily_stats": [],
        }

        result = analysis_snapshot_since(
            snapshot, "2026-08-29", "Europe/Paris",
        )

        self.assertEqual(
            [item["key"] for item in result["sessions"]], ["app:kona"],
        )

    def test_analysis_delta_keeps_tracking_gap_crossing_local_midnight(self):
        snapshot = {
            "sessions": [], "windows_sessions": [], "daily_stats": [],
            "system_events": [{
                "type": "tracking_gap",
                "at": "2026-08-28T23:50:00+02:00",
                "ended_at": "2026-08-29T00:10:00+02:00",
            }, {
                "type": "sleep", "at": "2026-08-28T23:55:00+02:00",
            }, {
                "type": "resume", "at": "2026-08-29T00:05:00+02:00",
            }],
        }

        result = analysis_snapshot_since(
            snapshot, "2026-08-29", "Europe/Paris",
        )

        self.assertEqual(
            [item["type"] for item in result["system_events"]],
            ["tracking_gap", "resume"],
        )

    def test_day_scope_drops_historical_occurrences_only(self):
        snapshot = {
            "sessions": [
                {"started_at": "2026-08-24T23:55:00+02:00", "ended_at": "2026-08-25T00:05:00+02:00"},
                {"started_at": "2026-08-25T08:00:00+02:00", "ended_at": "2026-08-25T08:01:00+02:00"},
                {"started_at": "2026-08-23T08:00:00+02:00", "ended_at": "2026-08-23T08:01:00+02:00"},
            ],
            "daily_stats": [
                {"date": "2026-08-24", "active": 10},
                {"date": "2026-08-25", "active": 20},
            ],
            "limits": [{"target_key": "app:codex"}],
        }

        result = snapshot_for_day_scope(
            snapshot, "2026-08-25", "Europe/Paris",
        )

        self.assertEqual(len(result["sessions"]), 2)
        self.assertEqual(
            result["daily_stats"],
            [{"date": "2026-08-25", "active": 20}],
        )
        self.assertEqual(result["limits"], snapshot["limits"])
        self.assertEqual(
            result["timeline"],
            {"start": "2026-08-25", "end": "2026-08-25"},
        )

    def test_day_scope_drops_windows_sessions_from_unrelated_days(self):
        snapshot = {
            "windows_sessions": [{
                "started_at": "2026-08-24T08:00:00+02:00",
                "ended_at": "2026-08-24T09:00:00+02:00",
            }],
            "sessions": [{
                "kind": "active", "key": "app:old",
                "started_at": "2026-08-24T08:10:00+02:00",
                "ended_at": "2026-08-24T08:20:00+02:00",
            }],
        }

        result = snapshot_for_day_scope(snapshot, "2026-08-25")

        self.assertEqual(result["windows_sessions"], [])
        self.assertEqual(result["sessions"], [])

    def test_notification_subject_roles_support_exact_and_legacy_policies(self):
        self.assertEqual(
            notification_subject_roles({"subject_roles": ["limited", "admin"]}),
            {"limited", "admin"},
        )
        self.assertEqual(
            notification_subject_roles({"login_role_scope": "users"}),
            {"limited", "user"},
        )

    def test_computer_limit_notification_kinds_merge_into_shared_limit_events(self):
        rules = normalize_notification_rules([
            {
                "id": "shared", "kind": "limit_change", "owner": "nicklaus",
                "channels": ["email"], "email_recipient": "owner@example.test",
            },
            {
                "id": "legacy-change", "kind": "computer_block_change",
                "owner": "nicklaus", "channels": ["windows"],
            },
            {
                "id": "legacy-warning", "kind": "computer_block_warning",
                "owner": "nicklaus", "channels": ["windows"],
            },
        ])

        self.assertEqual(
            [rule["kind"] for rule in rules],
            ["limit_change", "limit_warning"],
        )
        self.assertEqual(rules[0]["id"], "shared")
        self.assertEqual(rules[0]["channels"], ["windows", "email"])
        self.assertEqual(
            rules[0]["label"],
            "Ajout, modification ou suppression d’une limite",
        )

    def test_snapshot_uses_one_device_name_and_current_sid_mapping(self):
        snapshot = {"runtime": {"windows_identity": {
            "windows_sid": "S-1-5-21-1-2-3-1001",
            "usage_guard_username": "old-user",
        }}, "windows_sessions": [{
            "windows_sid": "S-1-5-21-1-2-3-1001",
            "usage_guard_username": "old-user",
            "started_at": "2026-08-24T01:47:00+02:00",
        }]}

        result = snapshot_with_device_context(snapshot, {
            "device_id": "pc-main", "label": "ordinateur-principal",
            "hostname_last_seen": "NUC11PHKi7",
        }, [{
            "windows_sid": "S-1-5-21-1-2-3-1001",
            "usage_guard_username": "nicklaus",
        }])

        self.assertEqual(
            result["runtime"]["device"]["display_name"],
            "ordinateur-principal",
        )
        self.assertEqual(
            result["runtime"]["windows_identity"]["usage_guard_username"],
            "nicklaus",
        )
        self.assertEqual(
            result["windows_sessions"][0]["usage_guard_username"],
            "nicklaus",
        )

    def test_offline_presence_ends_sleep_as_tracking_unavailable(self):
        protection = {"status": {
            "service_connected": False,
            "service_last_seen_at": "2026-08-24T08:05:00+00:00",
        }}
        result = snapshot_with_presence({"system_events": [{
            "type": "sleep", "at": "2026-08-24T08:00:00+00:00",
        }], "current": {"is_counted": True, "target_key": "app:test"}},
            protection, now="2026-08-24T09:00:00+00:00")

        self.assertTrue(result["offline"])
        self.assertEqual(result["current"], {})
        self.assertEqual(result["system_events"][-1]["type"], "tracking_gap")
        self.assertEqual(
            result["system_events"][-1]["at"],
            "2026-08-24T08:05:00+00:00",
        )
        confirmed = snapshot_with_presence({"system_events": [{
            "type": "shutdown", "at": "2026-08-24T08:00:00+00:00",
        }]}, protection, now="2026-08-24T09:00:00+00:00")
        self.assertEqual(len(confirmed["system_events"]), 1)

    def test_offline_device_sessions_stop_at_their_last_real_observation(self):
        protection = {"status": {
            "service_connected": False,
            "service_last_seen_at": "2026-08-24T01:50:02+02:00",
        }}
        snapshot = {
            "windows_sessions": [{
                "started_at": "2026-08-23T13:09:56+02:00",
                "ended_at": None,
                "last_observed_at": "2026-08-23T20:55:09+02:00",
            }],
            "sessions": [{
                "kind": "active", "key": "app:test", "label": "Test",
                "started_at": "2026-08-23T20:50:00+02:00",
                "ended_at": None,
            }],
        }

        result = snapshot_with_presence(
            snapshot, protection, now="2026-08-24T13:00:00+02:00"
        )

        self.assertEqual(
            result["windows_sessions"][0]["ended_at"],
            "2026-08-23T20:55:09+02:00",
        )
        self.assertTrue(result["windows_sessions"][0]["closed_inferred"])
        self.assertEqual(
            result["sessions"][0]["ended_at"],
            "2026-08-23T20:55:09+02:00",
        )
        self.assertNotEqual(
            result["windows_sessions"][0]["ended_at"],
            "2026-08-24T13:00:00+02:00",
        )

    def test_online_device_keeps_its_current_session_open(self):
        snapshot = {"windows_sessions": [{
            "started_at": "2026-08-24T12:00:00+02:00",
            "ended_at": None,
            "last_observed_at": "2026-08-24T12:59:59+02:00",
        }]}
        protection = {"status": {
            "service_connected": True,
            "service_last_seen_at": "2026-08-24T13:00:00+02:00",
        }}

        result = snapshot_with_presence(snapshot, protection)

        self.assertIsNone(result["windows_sessions"][0]["ended_at"])
        self.assertFalse(result["offline"])

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        (root / "index.html").write_text("Usage Guard", encoding="utf-8")
        self.token = "t" * 48
        self.server = BackendServer(
            port=0, store=Store(root / "test.sqlite3"), device_id="pc-test",
            device_token=self.token, public_origin=PUBLIC_ORIGIN, pwa_dir=root,
            client_release_dir=root / "client-updates",
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

    def test_backend_restart_preserves_the_admin_device_name(self):
        self.server.store.rename_device("pc-test", "NUC11PHKi7")

        restarted = BackendServer(
            port=0, store=self.server.store, device_id="pc-test",
            device_token=self.token, public_origin=PUBLIC_ORIGIN,
            pwa_dir=Path(self.temporary.name),
        )

        device = next(
            item for item in restarted.store.list_devices()
            if item["device_id"] == "pc-test"
        )
        self.assertEqual(device["label"], "NUC11PHKi7")

    def test_admin_downloads_a_transactional_audited_database_backup(self):
        root = Path(self.temporary.name)
        (root / "service-worker.js").write_text(
            'const CACHE="usage-guard-shell-v2-008";', encoding="utf-8"
        )
        self.server.store.create_user(
            "admin", "personal-admin-password", must_change=False,
            role="admin", email="admin@example.test",
        )
        self.server.store.save_snapshot(
            "pc-test", {"usage": [{"key": "app:test", "seconds": 30}]},
        )
        _, login, login_headers = self.request(
            "/api/v1/auth/login", "POST",
            {"username": "admin", "password": "personal-admin-password"},
            origin=PUBLIC_ORIGIN,
        )
        cookie = login_headers["Set-Cookie"].split(";", 1)[0]
        request = Request(
            self.base + "/api/v1/admin/database/backup",
            data=b"{}", method="POST", headers={
                "Content-Type": "application/json",
                "Origin": PUBLIC_ORIGIN,
                "Cookie": cookie,
                "X-CSRF-Token": login["csrf_token"],
            },
        )
        with urlopen(request, timeout=3) as response:
            content = response.read()
            headers = response.headers

        self.assertEqual(headers["Content-Type"], "application/vnd.sqlite3")
        self.assertIn("usage-guard-backup-v2.008-", headers["Content-Disposition"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["Pragma"], "no-cache")
        self.assertEqual(headers["Expires"], "0")
        backup = root / "downloaded.sqlite3"
        backup.write_bytes(content)
        db = sqlite3.connect(backup)
        try:
            self.assertEqual(db.execute("PRAGMA quick_check").fetchone()[0], "ok")
            snapshot = db.execute(
                "SELECT payload FROM snapshots WHERE device_id='pc-test'"
            ).fetchone()
            audit = db.execute(
                "SELECT kind,actor,details FROM audit_events ORDER BY id DESC"
            ).fetchone()
        finally:
            db.close()
        self.assertIn('"app:test"', snapshot[0])
        self.assertEqual(audit[0], "database_backup_download")
        self.assertEqual(audit[1], "admin")
        self.assertEqual(json.loads(audit[2])["version"], "2.008")

        with self.assertRaises(HTTPError) as missing_csrf:
            self.request(
                "/api/v1/admin/database/backup", "POST", {},
                origin=PUBLIC_ORIGIN, cookie=cookie,
            )
        self.assertEqual(missing_csrf.exception.code, 403)

        self.server.store.create_user(
            "viewer", "personal-viewer-password", must_change=False,
            role="user", email="viewer@example.test",
        )
        _, viewer, viewer_headers = self.request(
            "/api/v1/auth/login", "POST",
            {"username": "viewer", "password": "personal-viewer-password"},
            origin=PUBLIC_ORIGIN,
        )
        with self.assertRaises(HTTPError) as non_admin:
            self.request(
                "/api/v1/admin/database/backup", "POST", {},
                origin=PUBLIC_ORIGIN,
                cookie=viewer_headers["Set-Cookie"].split(";", 1)[0],
                csrf=viewer["csrf_token"],
            )
        self.assertEqual(non_admin.exception.code, 403)
        with self.assertRaises(HTTPError) as agent:
            self.request(
                "/api/v1/admin/database/backup", "POST", {}, agent=True,
            )
        self.assertEqual(agent.exception.code, 403)

    def test_http_public_origin_is_allowed_only_for_explicit_loopback_mode(self):
        root = Path(self.temporary.name)
        with self.assertRaises(RuntimeError):
            BackendServer(
                port=0, store=Store(root / "remote-http.sqlite3"),
                device_id="remote", device_token="r" * 48,
                public_origin="http://127.0.0.1:8767", pwa_dir=root,
            )
        local = BackendServer(
            port=0, store=Store(root / "local.sqlite3"),
            device_id="local", device_token="l" * 48,
            public_origin="http://127.0.0.1:8767", pwa_dir=root,
            local_mode=True,
        )
        self.assertTrue(local.local_mode)

    def test_protection_schema_migration_preserves_existing_rows(self):
        path = Path(self.temporary.name) / "legacy.sqlite3"
        db = sqlite3.connect(path)
        try:
            db.execute("""
                CREATE TABLE protection_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    components TEXT NOT NULL,
                    message TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            db.execute(
                "INSERT INTO protection_events(device_id,kind,components,message,created_at) VALUES(?,?,?,?,?)",
                ("pc-test", "interrupted", '["extension"]',
                 "Ancien incident", "2026-08-20T12:00:00+00:00"),
            )
            db.commit()
        finally:
            db.close()

        migrated = Store(path)
        overview = migrated.protection_overview("pc-test")

        self.assertEqual(overview["events"][0]["message"], "Ancien incident")
        self.assertEqual(
            overview["events"][0]["occurred_at"],
            "2026-08-20T12:00:00+00:00",
        )
        with migrated.connect() as db:
            columns = {
                row["name"] for row in db.execute(
                    "PRAGMA table_info(protection_events)"
                )
            }
        self.assertTrue({"event_key", "occurred_at", "received_at"} <= columns)

    def test_command_schema_migration_adds_idempotency_and_cancellation(self):
        path = Path(self.temporary.name) / "legacy-commands.sqlite3"
        db = sqlite3.connect(path)
        try:
            db.execute("""
                CREATE TABLE commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    delivered_at TEXT,
                    acknowledged_at TEXT,
                    result TEXT
                )
            """)
            db.execute(
                "INSERT INTO commands(device_id,payload,created_at) "
                "VALUES(?,?,?)",
                (
                    "pc-test", '{"action":"reset_limit"}',
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                ),
            )
            db.commit()
        finally:
            db.close()

        migrated = Store(path)
        with migrated.connect() as db:
            columns = {
                row["name"] for row in db.execute(
                    "PRAGMA table_info(commands)"
                )
            }
            row = db.execute(
                "SELECT idempotency_key,cancelled_at FROM commands"
            ).fetchone()

        self.assertTrue({"idempotency_key", "cancelled_at"} <= columns)
        self.assertEqual(row["idempotency_key"], "")
        self.assertIsNone(row["cancelled_at"])

    def test_limit_creation_is_idempotent_until_application_is_reflected(self):
        store = self.server.store
        command = {
            "action": "set_limit", "target_key": "category:Work",
            "settings": {
                "create_new": True, "target_key": "category:Work",
                "enabled": True, "limit_seconds": 3600,
            },
            "actor": "admin",
        }

        first, reused = store.queue_idempotent(
            "pc-test", command, "intent-one-1234",
        )
        same_key, same_reused = store.queue_idempotent(
            "pc-test", command, "intent-one-1234",
        )
        duplicate_click, duplicate_reused = store.queue_idempotent(
            "pc-test", command, "intent-two-1234",
        )

        self.assertFalse(reused)
        self.assertTrue(same_reused)
        self.assertTrue(duplicate_reused)
        self.assertEqual({first, same_key, duplicate_click}, {first})

        result = {
            "ok": True,
            "limit": {
                "key": "category:Work#saved",
                "target_key": "category:Work",
            },
        }
        self.assertTrue(store.acknowledge("pc-test", first, result))
        self.assertFalse(store.command_status("pc-test", first)["applied"])
        store.save_snapshot("pc-test", {
            "limits": [{
                "key": "category:Work#saved",
                "target_key": "category:Work",
            }],
        })
        self.assertTrue(store.command_status("pc-test", first)["applied"])

        intentional_second, reused = store.queue_idempotent(
            "pc-test", command, "intent-three-1234",
        )
        self.assertFalse(reused)
        self.assertNotEqual(intentional_second, first)

    def test_undelivered_command_can_be_cancelled_but_delivered_one_cannot(self):
        store = self.server.store
        first, _ = store.queue_idempotent(
            "pc-test", {"action": "reset_limit", "target_key": "app:a"},
            "cancel-one-1234",
        )
        self.assertEqual(store.cancel_command("pc-test", first), "cancelled")
        self.assertEqual(store.pending("pc-test"), [])
        self.assertTrue(store.command_status("pc-test", first)["cancelled"])

        second, _ = store.queue_idempotent(
            "pc-test", {"action": "reset_limit", "target_key": "app:b"},
            "cancel-two-1234",
        )
        self.assertEqual(store.pending("pc-test")[0]["id"], str(second))
        self.assertEqual(store.cancel_command("pc-test", second), "delivered")

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
            "message_templates": {
                "limit_warning": {
                    "title": "Alerte · {titre}",
                    "message": "Message central : {message}",
                },
            },
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
                "Préavis", "Il reste cinq minutes.", "rule@example.test",
                kind="limit_warning",
            )

        smtp.assert_called_once_with("smtp.example.test", 587, timeout=15)
        connection.starttls.assert_called_once_with(context=ANY)
        connection.login.assert_called_once_with("usage-guard", "smtp-secret")
        sent = connection.send_message.call_args.args[0]
        self.assertEqual(sent["To"], "rule@example.test")
        self.assertIn("Alerte · Préavis", sent["Subject"])
        self.assertIn("Message central : Il reste cinq minutes.", sent.get_content())
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

    def test_three_roles_and_multi_device_assignments_are_persisted(self):
        store = self.server.store
        store.register_device("pc-portable", "Portable")
        admin = store.create_user(
            "admin", "temporary-strong", role="admin"
        )
        limited = store.create_user(
            "child", "temporary-strong", role="limited",
            device_ids=["pc-test", "pc-portable"],
            permissions={
                "manage_activity": True,
                "manage_limits": True,
                "manage_notifications": True,
            },
        )
        user = store.create_user(
            "parent", "temporary-strong", role="user",
            device_ids=["pc-test", "pc-portable"],
            permissions={"manage_limits": True, "view_limits": True},
        )

        self.assertEqual(admin["role"], "admin")
        self.assertTrue(admin["is_admin"])
        self.assertEqual(
            admin["accessible_device_ids"], ["pc-portable", "pc-test"]
        )
        self.assertEqual(limited["role"], "limited")
        self.assertEqual(limited["device_ids"], ["pc-portable", "pc-test"])
        self.assertEqual(
            limited["accessible_device_ids"], ["pc-portable", "pc-test"]
        )
        self.assertTrue(limited["permissions"]["manage_limits"])
        self.assertTrue(limited["permissions"]["manage_activity"])
        self.assertTrue(limited["permissions"]["manage_notifications"])
        self.assertEqual(user["role"], "user")
        self.assertEqual(
            user["accessible_device_ids"], ["pc-portable", "pc-test"]
        )
        self.assertTrue(user["permissions"]["manage_limits"])

        authenticated = store.authenticate("parent", "temporary-strong")
        self.assertEqual(authenticated["role"], "user")
        self.assertEqual(
            authenticated["accessible_device_ids"], ["pc-portable", "pc-test"]
        )
        self.assertEqual(Store._normalize_role("manager"), "user")

    def test_user_access_uses_an_explicit_device_scope(self):
        store = self.server.store
        store.create_user(
            "admin", "personal-admin-password", must_change=False,
            role="admin", email="admin@example.test",
        )
        store.create_user(
            "child", "personal-child-password", must_change=False,
            role="limited", device_ids=["pc-test"],
            email="child@example.test",
        )
        store.create_user(
            "parent", "personal-parent-password", must_change=False,
            role="user", permissions={"manage_limits": True}, device_ids=[],
            email="parent@example.test",
        )
        _, login, headers = self.request(
            "/api/v1/auth/login", "POST", {
                "username": "parent", "password": "personal-parent-password",
            }, origin=PUBLIC_ORIGIN,
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        self.assertEqual(login["accessible_device_ids"], [])
        with self.assertRaises(HTTPError) as error:
            self.request("/api/v1/overview", cookie=cookie)
        self.assertEqual(error.exception.code, 403)

        store.update_user_access(
            "parent", False, {"manage_limits": True}, "admin",
            role="user", device_ids=["pc-test"],
        )
        _, login, headers = self.request(
            "/api/v1/auth/login", "POST", {
                "username": "parent", "password": "personal-parent-password",
            }, origin=PUBLIC_ORIGIN,
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        self.assertEqual(login["accessible_device_ids"], ["pc-test"])
        status, _, _ = self.request("/api/v1/overview", cookie=cookie)
        self.assertEqual(status, 200)
        status, queued, _ = self.request(
            "/api/v1/actions", "POST", {
                "action": "reset_limit", "target_key": "app:test",
            }, origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"],
        )
        self.assertEqual(status, 202)
        self.assertTrue(queued["queued"])

    def test_user_access_scope_can_follow_a_person_with_multiple_computers(self):
        store = self.server.store
        store.register_device("pc-portable", "Portable")
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "child", "temporary-strong", role="limited",
            device_ids=["pc-test"],
        )
        store.create_user(
            "parent", "temporary-strong", role="user", device_ids=[],
        )

        parent = store.update_user_access(
            "parent", False, {}, "admin", role="user", device_ids=[],
            person_usernames=["child"],
        )
        self.assertEqual(parent["person_usernames"], ["child"])
        self.assertEqual(parent["accessible_person_usernames"], ["child"])
        self.assertEqual(parent["accessible_device_ids"], ["pc-test"])
        self.assertTrue(store.user_can_access_policy("parent", "child"))

        store.update_user_access(
            "child", False, {}, "admin", role="limited",
            device_ids=["pc-test", "pc-portable"],
        )
        parent = next(
            user for user in store.list_users()
            if user["username"] == "parent"
        )
        self.assertEqual(
            parent["accessible_device_ids"], ["pc-portable", "pc-test"]
        )

    def test_legacy_manager_assignment_becomes_a_direct_device_scope(self):
        path = Path(self.temporary.name) / "legacy-manager.sqlite3"
        store = Store(path)
        store.register_device("pc-family", "PC familial")
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "eva", "temporary-strong", role="limited",
            device_ids=["pc-family"],
        )
        store.create_user(
            "parent", "temporary-strong", role="user", device_ids=[],
            permissions={"manage_limits": True},
        )
        with store.connect() as db:
            db.execute(
                "CREATE TABLE manager_users ("
                "manager_username TEXT NOT NULL COLLATE NOCASE,"
                "limited_username TEXT NOT NULL COLLATE NOCASE,"
                "PRIMARY KEY(manager_username,limited_username))"
            )
            db.execute(
                "INSERT INTO manager_users(manager_username,limited_username) VALUES(?,?)",
                ("parent", "eva"),
            )
            db.execute("UPDATE users SET role='manager' WHERE username='parent'")

        migrated = Store(path)
        parent = next(
            user for user in migrated.list_users()
            if user["username"] == "parent"
        )
        self.assertEqual(parent["role"], "user")
        self.assertEqual(parent["device_ids"], ["pc-family"])
        self.assertNotIn("managed_usernames", parent)

    def test_existing_non_admin_users_are_assigned_to_current_device(self):
        path = Path(self.temporary.name) / "roles.sqlite3"
        store = Store(path)
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user("child", "temporary-strong", role="limited")
        store.create_user(
            "parent", "temporary-strong", role="user",
            permissions={"manage_limits": True},
        )

        migrated = BackendServer(
            port=0, store=store, device_id="pc-migrated",
            device_token="m" * 48, public_origin=PUBLIC_ORIGIN,
            pwa_dir=Path(self.temporary.name),
        )

        child = next(user for user in migrated.store.list_users() if user["username"] == "child")
        parent = next(user for user in migrated.store.list_users() if user["username"] == "parent")
        self.assertEqual(child["device_ids"], ["pc-migrated"])
        self.assertEqual(parent["device_ids"], ["pc-migrated"])

    def test_computer_state_rule_receives_online_and_offline_transitions(self):
        self.server.store.save_snapshot("pc-test", {
            "notification_rules": [{
                "kind": "computer_state", "enabled": True,
                "channels": ["windows"],
                "custom_title": "Ancien titre à ignorer",
                "custom_message": "Ancien message à ignorer.",
            }],
        })

        self.server._dispatch_client_presence("pc-test", True)
        self.server._dispatch_client_presence("pc-test", False)

        commands = self.server.store.pending("pc-test")
        presence = [
            command for command in commands
            if command.get("action") == "notify_client_presence"
        ]
        self.assertEqual(
            [command["connected"] for command in presence], [True, False]
        )
        self.assertEqual(presence[0]["title"], "Ordinateur allumé — Usage Guard")
        self.assertEqual(
            presence[1]["title"],
            "Ordinateur éteint ou inaccessible — Usage Guard",
        )

    def test_protection_heartbeat_also_keeps_device_presence_online(self):
        self.server.store.mark_device_seen("pc-test")
        with self.server.store.connect() as db:
            db.execute(
                "UPDATE device_presence SET online=0 WHERE device_id=?",
                ("pc-test",),
            )

        self.request(
            "/api/v1/agent/status", "POST", {
                "device_id": "pc-test",
                "status": {
                    "desktop_connected": True,
                    "extension_connected": True,
                },
            }, True,
        )

        self.assertTrue(
            self.server.store.device_presence("pc-test")["online"]
        )

    def test_protection_events_are_replayed_idempotently_and_can_be_stale(self):
        base_status = {
            "desktop_connected": True,
            "desktop_last_seen_at": "2026-08-21T10:00:00+00:00",
            "extension_connected": True,
            "extension_last_seen_at": "2026-08-21T10:00:00+00:00",
            "stale_after_seconds": 45,
        }
        _, initial, _ = self.request(
            "/api/v1/agent/status", "POST",
            {"device_id": "pc-test", "status": base_status}, True,
        )
        self.assertEqual(initial["accepted_event_ids"], [])

        incident = {
            "id": "durable-event-1", "kind": "interrupted",
            "components": ["extension"],
            "message": "Extension absente.",
            "occurred_at": "2026-08-21T10:01:00+00:00",
        }
        payload = {
            "device_id": "pc-test",
            "status": {
                **base_status, "extension_connected": False,
                "events": [incident],
            },
        }
        _, first, _ = self.request(
            "/api/v1/agent/status", "POST", payload, True,
        )
        _, replay, _ = self.request(
            "/api/v1/agent/status", "POST", payload, True,
        )
        self.assertEqual(first["accepted_event_ids"], ["durable-event-1"])
        self.assertEqual(replay["accepted_event_ids"], ["durable-event-1"])
        with self.server.store.connect() as db:
            count = db.execute(
                "SELECT COUNT(*) FROM protection_events WHERE event_key=?",
                ("durable-event-1",),
            ).fetchone()[0]
            db.execute(
                "UPDATE protection_status SET updated_at=? WHERE device_id=?",
                ((datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(
                    timespec="seconds"
                ), "pc-test"),
            )
        self.assertEqual(count, 1)

        overview = self.server.store.protection_overview("pc-test")
        self.assertTrue(overview["status"]["stale"])
        self.assertFalse(overview["status"]["healthy"])
        self.assertEqual(
            overview["events"][0]["occurred_at"],
            incident["occurred_at"],
        )
        self.assertTrue(overview["events"][0]["received_at"])

    def test_update_maintenance_suppresses_expected_protection_events(self):
        _, started, _ = self.request(
            "/api/v1/agent/maintenance", "POST", {
                "device_id": "pc-test", "version": "2.012",
                "duration_seconds": 900,
            }, True,
        )
        self.assertTrue(started["maintenance"]["active"])
        self.assertEqual(started["maintenance"]["version"], "2.012")

        incident = {
            "id": "expected-update-stop", "kind": "interrupted",
            "components": ["desktop", "extension"],
            "message": "Arrêt attendu pendant la mise à jour.",
        }
        with patch.object(self.server, "_dispatch_protection_event") as dispatch:
            _, result, _ = self.request(
                "/api/v1/agent/status", "POST", {
                    "device_id": "pc-test",
                    "status": {
                        "desktop_connected": False,
                        "extension_connected": False,
                        "events": [incident],
                    },
                }, True,
            )
        self.assertEqual(result["accepted_event_ids"], ["expected-update-stop"])
        dispatch.assert_not_called()
        self.assertTrue(self.server.store.device_maintenance("pc-test")["active"])

    def test_expired_update_maintenance_alerts_only_once(self):
        self.server.store.begin_device_maintenance("pc-test", "2.012", 900)
        with self.server.store.connect() as db:
            row = db.execute(
                "SELECT payload FROM protection_status WHERE device_id=?",
                ("pc-test",),
            ).fetchone()
            payload = json.loads(row["payload"])
            payload["maintenance_until"] = (
                datetime.now(timezone.utc) - timedelta(seconds=1)
            ).isoformat(timespec="seconds")
            db.execute(
                "UPDATE protection_status SET payload=? WHERE device_id=?",
                (json.dumps(payload), "pc-test"),
            )

        self.assertTrue(
            self.server.store.claim_expired_device_maintenance("pc-test")
        )
        self.assertFalse(
            self.server.store.claim_expired_device_maintenance("pc-test")
        )

    def test_update_reconnection_is_silent_until_protection_is_healthy(self):
        self.server.store.mark_device_seen("pc-test")
        with self.server.store.connect() as db:
            db.execute(
                "UPDATE device_presence SET online=0 WHERE device_id=?",
                ("pc-test",),
            )
        self.server.store.begin_device_maintenance("pc-test", "2.012", 900)
        with (
            patch.object(self.server, "_dispatch_client_presence") as presence,
            patch.object(self.server, "_dispatch_protection_event") as protection,
        ):
            self.server._mark_agent_seen("pc-test")
            self.assertTrue(
                self.server.store.device_maintenance("pc-test")["reconnected"]
            )
            self.request(
                "/api/v1/agent/status", "POST", {
                    "device_id": "pc-test",
                    "status": {
                        "desktop_connected": True,
                        "extension_connected": True,
                        "events": [{
                            "id": "expected-update-restore",
                            "kind": "restored",
                            "components": ["desktop", "extension"],
                            "message": "Retour attendu après mise à jour.",
                        }],
                    },
                }, True,
            )
        presence.assert_not_called()
        protection.assert_not_called()
        self.assertFalse(
            self.server.store.device_maintenance("pc-test")["active"]
        )

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
            {"action": "set_notification_rule", "rule": {"kind": "computer_state", "enabled": True}},
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

    def test_store_restart_configures_email_key_before_snapshot_migrations(self):
        self.server.store.save_snapshot("pc-test", {"notification_rules": [{
            "kind": "pwa_login", "channels": ["email"],
            "email_recipient": "owner@example.test",
        }]})

        restarted = Store(
            self.server.store.path, email_encryption_key=self.token,
        )

        self.assertEqual(
            restarted.snapshot("pc-test")["notification_rules"][0][
                "email_recipient"
            ],
            "owner@example.test",
        )

    def test_device_token_cannot_manage_smtp_and_can_only_send_its_configured_rule(self):
        for path, method, payload in (
            ("/api/v1/agent/email/settings?device_id=pc-test", "GET", None),
            ("/api/v1/agent/email/settings", "POST", {"device_id": "pc-test"}),
            ("/api/v1/agent/email/test", "POST", {"device_id": "pc-test", "recipient": "test@example.test"}),
        ):
            with self.assertRaises(HTTPError) as error:
                self.request(path, method, payload, agent=True)
            self.assertEqual(error.exception.code, 403)

        self.server.store.save_email_settings({
            "smtp_host": "smtp.example.test", "smtp_port": 465,
            "security": "ssl", "sender": "guard@example.test",
        })
        allowed_rule = {
            "id": "allowed-rule", "enabled": True, "kind": "limit_warning",
            "channels": ["email"], "email_recipient": "allowed@example.test",
        }
        self.server.store.update_device_notification_policy(
            "pc-test", "set_notification_rule", allowed_rule,
        )
        with self.server.store.connect() as db:
            raw_policy = db.execute(
                "SELECT payload FROM device_notification_policies WHERE device_id=?",
                ("pc-test",),
            ).fetchone()["payload"]
        self.assertNotIn("allowed@example.test", raw_policy)
        self.server.store.save_snapshot("pc-test", {
            "notification_rules": [allowed_rule, {
                "id": "injected", "enabled": True, "kind": "limit_warning",
                "channels": ["email"], "email_recipient": "attacker@example.test",
            }],
        })
        with self.assertRaises(HTTPError) as error:
            self.request("/api/v1/agent/email/send", "POST", {
                "device_id": "pc-test", "kind": "limit_warning",
                "recipient": "attacker@example.test", "title": "X", "message": "X",
            }, agent=True)
        self.assertEqual(error.exception.code, 403)

        smtp = MagicMock()
        with patch("usage_guard_backend.server.smtplib.SMTP_SSL", smtp):
            status, sent, _ = self.request("/api/v1/agent/email/send", "POST", {
                "device_id": "pc-test", "kind": "limit_warning",
                "recipient": "allowed@example.test", "title": "Préavis", "message": "Message",
            }, agent=True)
        self.assertEqual(status, 200)
        self.assertTrue(sent["ok"])
        smtp.assert_called_once_with("smtp.example.test", 465, timeout=15, context=ANY)

    def test_login_explains_server_side_bootstrap_when_no_admin_exists(self):
        with self.assertRaises(HTTPError) as error:
            self.request(
                "/api/v1/auth/login", "POST",
                {"username": "owner", "password": "temporary-strong"},
                origin=PUBLIC_ORIGIN,
            )

        self.assertEqual(error.exception.code, 503)
        payload = json.loads(error.exception.read().decode("utf-8"))
        self.assertIn("Aucun administrateur", payload["error"])
        self.assertIn("localement sur le serveur", payload["error"])

    def request(self, path, method="GET", payload=None, agent=False, origin=None, cookie=None, csrf=None, token=None):
        if (
            getattr(self, "seed_agent_users", True) and agent
            and method == "POST" and path == "/api/v1/agent/users"
        ):
            source = dict(payload or {})
            user = self.server.store.create_user(
                source.get("username"), source.get("password"), True,
                source.get("email", ""), source.get("is_admin", False),
                source.get("permissions", {}), source.get("role"),
                source.get("device_ids", [source.get("device_id", "pc-test")]),
            )
            return 201, {"ok": True, "user": user}, {}
        headers = {"Accept": "application/json"}
        if agent: headers["Authorization"] = "Bearer " + (token or self.token)
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

    def test_enrollment_rotation_preserves_server_data_and_rejects_old_secret(self):
        store = self.server.store
        store.create_user(
            "admin", "personal-admin-password", must_change=False,
            role="admin", email="admin@example.test",
        )
        store.create_user(
            "child", "personal-child-password", must_change=False,
            role="limited", email="child@example.test", device_ids=[],
        )
        enrollment = store.create_device_enrollment(
            "admin", "child", label="PC chambre",
        )
        first = store.consume_device_enrollment(
            enrollment["code"], hostname="CHAMBRE-PC",
        )
        device_id = first["device_id"]
        store.save_snapshot(device_id, {"limits": [{"key": "app:game"}]})
        store.save_activity_store(device_id, {"days": {"2026-08-22": {}}})

        reinstall = store.create_device_enrollment(
            "admin", "child", device_id=device_id,
        )
        second = store.consume_device_enrollment(
            reinstall["code"], hostname="CHAMBRE-PC",
        )

        self.assertFalse(store.authenticate_device(device_id, first["device_token"]))
        self.assertTrue(store.authenticate_device(device_id, second["device_token"]))
        self.assertEqual(store.snapshot(device_id)["limits"][0]["key"], "app:game")
        self.assertIn(
            "2026-08-22", store.activity_store(device_id)["activity"]["days"]
        )
        store.register_device(device_id, token="z" * 48)
        self.assertTrue(store.authenticate_device(device_id, second["device_token"]))

    def test_one_device_can_keep_multiple_limited_users(self):
        store = self.server.store
        store.create_user(
            "admin", "personal-admin-password", must_change=False,
            role="admin", email="admin@example.test",
        )
        store.create_user(
            "oldchild", "personal-old-password", must_change=False,
            role="limited", email="old@example.test", device_ids=["pc-test"],
        )
        store.create_user(
            "newchild", "personal-new-password", must_change=False,
            role="limited", email="new@example.test", device_ids=[],
        )
        store.create_user(
            "helper", "personal-helper-password", must_change=False,
            role="user", email="helper@example.test", device_ids=["pc-test"],
        )

        store.create_device_enrollment(
            "admin", "newchild", device_id="pc-test", label="NUC salon",
        )

        with store.connect() as db:
            assignments = {
                row["username"] for row in db.execute(
                    "SELECT username FROM user_devices WHERE device_id='pc-test'"
                )
            }
        self.assertEqual(assignments, {"oldchild", "newchild", "helper"})

    def test_admin_can_rename_a_device_without_changing_its_network_name(self):
        store = self.server.store
        store.create_user(
            "admin", "personal-admin-password", must_change=False,
            role="admin", email="admin@example.test",
        )
        enrollment = store.create_device_enrollment(
            "admin", device_id="pc-test",
        )
        store.consume_device_enrollment(
            enrollment["code"], hostname="NUC11PHKi7",
        )
        _, login, headers = self.request(
            "/api/v1/auth/login", "POST", {
                "username": "admin", "password": "personal-admin-password",
            }, origin=PUBLIC_ORIGIN,
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        status, result, _ = self.request(
            "/api/v1/admin/devices/pc-test/rename", "POST",
            {"label": "Ordinateur du bureau"}, origin=PUBLIC_ORIGIN,
            cookie=cookie, csrf=login["csrf_token"],
        )

        self.assertEqual(status, 200)
        self.assertEqual(result["device"]["label"], "Ordinateur du bureau")
        self.assertEqual(result["device"]["hostname_last_seen"], "NUC11PHKi7")

    def test_assigning_another_limited_user_keeps_existing_users(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "oldchild", "temporary-strong", role="limited",
            device_ids=["pc-test"],
        )
        store.create_user(
            "newchild", "temporary-strong", role="limited", device_ids=[],
        )
        store.create_user(
            "helper", "temporary-strong", role="user",
            device_ids=["pc-test"],
        )

        store.update_user_access(
            "newchild", False, {}, "admin", role="limited",
            device_ids=["pc-test"],
        )

        with store.connect() as db:
            assignments = {
                row["username"] for row in db.execute(
                    "SELECT username FROM user_devices WHERE device_id='pc-test'"
                )
            }
        self.assertEqual(assignments, {"oldchild", "newchild", "helper"})

    def test_startup_preserves_multiple_limited_assignments(self):
        path = Path(self.temporary.name) / "stale-device-assignment.sqlite3"
        store = Store(path)
        store.register_device(
            "pc-family", "ordinateur-principal", token="f" * 48,
            hostname="FAMILY-PC",
        )
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "eva", "temporary-strong", role="limited",
            device_ids=["pc-family"],
        )
        store.create_user(
            "nicklaus", "temporary-strong", role="limited", device_ids=[],
        )
        store.create_user(
            "helper", "temporary-strong", role="user",
            device_ids=["pc-family"],
        )
        enrollment = store.create_device_enrollment(
            "admin", "nicklaus", device_id="pc-family",
        )
        store.consume_device_enrollment(
            enrollment["code"], hostname="FAMILY-PC",
        )
        with store.connect() as db:
            db.execute(
                "INSERT OR IGNORE INTO user_devices(username,device_id) VALUES(?,?)",
                ("eva", "pc-family"),
            )

        migrated = Store(path)
        migrated.assign_unscoped_users("pc-family")

        with migrated.connect() as db:
            assignments = {
                row["username"] for row in db.execute(
                    "SELECT username FROM user_devices WHERE device_id='pc-family'"
                )
            }
        self.assertEqual(assignments, {"eva", "nicklaus", "helper"})

    def test_device_maps_existing_windows_sids_to_distinct_users(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        store.create_user(
            "bob", "temporary-strong", role="limited", device_ids=[],
        )
        store.create_user(
            "viewer", "temporary-strong", role="user", device_ids=[],
        )
        identities = [
            {
                "windows_sid": "S-1-5-21-100-200-300-1001",
                "windows_domain": "FAMILLE",
                "windows_username": "Alice",
                "usage_guard_username": "alice",
                "is_windows_admin": False,
            },
            {
                "windows_sid": "S-1-5-21-100-200-300-1002",
                "windows_domain": "FAMILLE",
                "windows_username": "Bob",
                "usage_guard_username": "bob",
                "is_windows_admin": True,
            },
        ]

        enrollment = store.create_device_enrollment(
            "admin", device_id="pc-test", label="PC familial",
            windows_identities=identities,
        )
        consumed = store.consume_device_enrollment(
            enrollment["code"], hostname="FAMILLE-PC",
        )

        self.assertEqual(
            {item["usage_guard_username"] for item in consumed["windows_identities"]},
            {"alice", "bob"},
        )
        self.assertEqual(
            store.user_for_windows_sid(
                "pc-test", "s-1-5-21-100-200-300-1002"
            )["usage_guard_username"],
            "bob",
        )
        self.assertTrue(
            store.user_for_windows_sid(
                "pc-test", "S-1-5-21-100-200-300-1002"
            )["is_windows_admin"]
        )
        with self.assertRaisesRegex(ValueError, "ne peut correspondre"):
            store.set_device_windows_identities(
                "pc-test", [identities[0], {
                    **identities[1], "usage_guard_username": "alice",
                }], "admin",
            )
        with self.assertRaisesRegex(ValueError, "utilisateur à limiter"):
            store.set_device_windows_identities(
                "pc-test", [{
                    **identities[0], "usage_guard_username": "viewer",
                }], "admin",
            )

    def test_device_secret_reads_only_its_own_windows_identities(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": "S-1-5-21-100-200-300-1001",
            "windows_domain": "FAMILLE",
            "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")

        status, payload, _ = self.request(
            "/api/v1/agent/windows-identities?device_id=pc-test", agent=True,
        )

        self.assertEqual(status, 200)
        self.assertEqual(
            payload["windows_identities"][0]["usage_guard_username"],
            "alice",
        )
        store.register_device("pc-other", token="o" * 48)
        with self.assertRaises(HTTPError) as error:
            self.request(
                "/api/v1/agent/windows-identities?device_id=pc-other",
                agent=True,
            )
        self.assertEqual(error.exception.code, 401)

    def test_personal_policy_revision_targets_every_mapped_device(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        store.register_device("pc-other", token="o" * 48)
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": "S-1-5-21-100-200-300-1001",
            "windows_domain": "FAMILLE", "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        store.set_device_windows_identities("pc-other", [{
            "windows_sid": "S-1-5-21-400-500-600-1001",
            "windows_domain": "PORTABLE", "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")

        first = store.save_user_policy(
            "alice", {"limits": [{"target_key": "category:Work"}]},
            "admin",
        )

        self.assertEqual(first["revision"], 1)
        self.assertEqual(first["policy"]["enforcement_mode"], "enforced")
        self.assertEqual(
            {item["device_id"] for item in first["devices"]},
            {"pc-test", "pc-other"},
        )
        self.assertTrue(all(
            item["desired_revision"] == 1
            and item["applied_revision"] == 0
            for item in first["devices"]
        ))
        applied = store.acknowledge_user_policy(
            "pc-test", "S-1-5-21-100-200-300-1001", 1, {"ok": True},
        )
        states = {item["device_id"]: item for item in applied["devices"]}
        self.assertEqual(states["pc-test"]["applied_revision"], 1)
        self.assertEqual(states["pc-other"]["applied_revision"], 0)
        rejected = store.acknowledge_user_policy(
            "pc-test", "S-1-5-21-100-200-300-1001", 1,
            {
                "ok": False, "phase": "validation", "validated": False,
                "differences": ["category_unresolved:category:Work"],
            },
        )
        rejected_states = {
            item["device_id"]: item for item in rejected["devices"]
        }
        self.assertEqual(rejected_states["pc-test"]["applied_revision"], 0)

        second = store.save_user_policy(
            "alice", {"limits": [{"target_key": "category:Work"}],
                      "notifications": []}, "admin",
        )
        self.assertEqual(second["revision"], 2)
        self.assertTrue(all(
            item["desired_revision"] == 2 for item in second["devices"]
        ))
        with self.assertRaisesRegex(ValueError, "Mode d.application"):
            store.save_user_policy(
                "alice", {"enforcement_mode": "automatic", "limits": []},
                "admin",
            )
        with self.assertRaisesRegex(ValueError, "double"):
            store.save_user_policy("alice", {"limits": [
                {"target_key": "app:test"},
                {"target_key": "app:test"},
            ]}, "admin")

    def test_personal_computer_block_is_persistent_and_targets_every_pc(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        store.register_device("pc-other", token="o" * 48)
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": "S-1-5-21-100-200-300-1001",
            "windows_username": "Alice", "usage_guard_username": "alice",
        }], "admin")
        store.set_device_windows_identities("pc-other", [{
            "windows_sid": "S-1-5-21-400-500-600-1001",
            "windows_username": "Alice", "usage_guard_username": "alice",
        }], "admin")
        command = {
            "action": "set_computer_block", "mode": "schedule",
            "start_time": "23:00", "end_time": "05:00",
            "grace_seconds": 300, "name": "  Nuit scolaire  ",
        }

        first = store.mutate_user_computer_block(
            "alice", command, "admin", "computer-operation-1",
        )
        replay = store.mutate_user_computer_block(
            "alice", command, "admin", "computer-operation-1",
        )

        self.assertEqual(first["revision"], 1)
        self.assertEqual(replay["revision"], 1)
        self.assertTrue(replay["reused"])
        self.assertEqual(replay["block"]["start_time"], "23:00")
        self.assertEqual(replay["block"]["end_time"], "05:00")
        self.assertEqual(replay["block"]["name"], "Nuit scolaire")
        states = {item["device_id"]: item for item in first["devices"]}
        self.assertEqual(set(states), {"pc-test", "pc-other"})
        self.assertTrue(all(
            item["desired_revision"] == 1
            and item["applied_revision"] == 0
            and item["command_id"]
            for item in states.values()
        ))
        self.assertEqual(
            store.pending("pc-test")[0]["name"], "Nuit scolaire",
        )
        self.assertTrue(store.acknowledge(
            "pc-test", int(states["pc-test"]["command_id"]), {"ok": True},
        ))
        refreshed = store.user_computer_block_policy("alice")
        refreshed_states = {
            item["device_id"]: item for item in refreshed["devices"]
        }
        self.assertEqual(refreshed_states["pc-test"]["applied_revision"], 1)
        self.assertEqual(refreshed_states["pc-other"]["applied_revision"], 0)

        cleared = store.mutate_user_computer_block(
            "alice", {"action": "clear_computer_block"}, "admin",
            "computer-operation-2",
        )
        self.assertEqual(cleared["revision"], 2)
        self.assertEqual(cleared["block"], {})

    def test_personal_computer_block_targets_only_checked_pc(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        store.register_device("pc-other", token="o" * 48)
        for device_id, sid in (
            ("pc-test", "S-1-5-21-100-200-300-1001"),
            ("pc-other", "S-1-5-21-400-500-600-1001"),
        ):
            store.set_device_windows_identities(device_id, [{
                "windows_sid": sid, "windows_username": "Alice",
                "usage_guard_username": "alice",
            }], "admin")

        scoped = store.mutate_user_computer_block(
            "alice", {
                "action": "set_computer_block", "mode": "schedule",
                "start_time": "23:00", "end_time": "05:00",
                "grace_seconds": 300, "device_ids": ["pc-test"],
            }, "admin", "computer-scoped-operation-1",
        )

        self.assertEqual(scoped["block"]["device_ids"], ["pc-test"])
        self.assertEqual(
            [item["device_id"] for item in scoped["devices"]], ["pc-test"],
        )
        self.assertEqual(store.pending("pc-other"), [])

    def test_warning_computer_block_requires_capability_and_survives_edit(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": "S-1-5-21-100-200-300-1001",
            "windows_username": "Alice", "usage_guard_username": "alice",
        }], "admin")
        command = {
            "action": "set_computer_block", "mode": "schedule",
            "start_time": "23:00", "end_time": "05:00",
            "enforcement_action": "warn",
        }

        with self.assertRaisesRegex(ValueError, "mode Avertir.*mise à jour"):
            store.mutate_user_computer_block(
                "alice", command, "admin", "warning-computer-old-client",
            )
        self.assertFalse(store.user_computer_block_policy("alice")["configured"])

        store.save_snapshot("pc-test", {
            "capabilities": ["limit_warning_action"],
        })
        created = store.mutate_user_computer_block(
            "alice", command, "admin", "warning-computer-create",
        )
        edited = store.mutate_user_computer_block("alice", {
            "action": "set_computer_block",
            "block_id": created["block_id"],
            "mode": "schedule", "start_time": "22:30", "end_time": "05:30",
        }, "admin", "warning-computer-edit")

        self.assertEqual(created["block"]["enforcement_action"], "warn")
        self.assertEqual(edited["block"]["enforcement_action"], "warn")
        self.assertEqual(store.pending("pc-test")[-1]["enforcement_action"], "warn")

    def test_legacy_computer_block_policy_is_migrated_to_v2_with_stable_id(self):
        store = self.server.store
        store.create_user("alice", "temporary-strong", role="limited")
        legacy = {
            "mode": "schedule", "enabled": True,
            "start_time": "22:30", "end_time": "05:00",
            "name": "Nuit",
        }
        with store.connect() as db:
            db.execute(
                "INSERT INTO user_computer_block_policies("
                "usage_guard_username,revision,payload,actor,updated_at) "
                "VALUES(?,?,?,?,?)",
                (
                    "alice", 7, json.dumps(legacy), "admin",
                    "2026-08-28T10:00:00+00:00",
                ),
            )

        first = Store(store.path).user_computer_block_policy("alice")
        second = Store(store.path).user_computer_block_policy("alice")

        self.assertEqual(first["version"], 2)
        self.assertEqual(len(first["blocks"]), 1)
        self.assertEqual(first["blocks"][0]["name"], "Nuit")
        self.assertEqual(
            first["blocks"][0]["block_id"],
            second["blocks"][0]["block_id"],
        )
        with store.connect() as db:
            payload = json.loads(db.execute(
                "SELECT payload FROM user_computer_block_policies "
                "WHERE usage_guard_username='alice'",
            ).fetchone()["payload"])
        self.assertEqual(payload["version"], 2)
        self.assertEqual(payload["blocks"][0]["block_id"], first["block"]["block_id"])

    def test_v2_computer_blocks_are_added_and_mutated_by_exact_id(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user("alice", "temporary-strong", role="limited")
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": "S-1-5-21-100-200-300-1001",
            "windows_username": "Alice", "usage_guard_username": "alice",
        }], "admin")
        store.save_snapshot("pc-test", {
            "capabilities": ["computer_blocks_v2"], "computer_blocks": [],
        })
        first = store.mutate_user_computer_block("alice", {
            "action": "set_computer_block", "mode": "schedule",
            "start_time": "22:30", "end_time": "05:00", "name": "Nuit",
        }, "admin", "computer-v2-create-1")
        first_id = first["block_id"]
        second = store.mutate_user_computer_block("alice", {
            "action": "set_computer_block", "mode": "schedule",
            "start_time": "19:30", "end_time": "19:32", "name": "Test court",
        }, "admin", "computer-v2-create-2")
        second_id = second["block_id"]

        self.assertNotEqual(first_id, second_id)
        self.assertEqual(
            {item["name"] for item in second["blocks"]},
            {"Nuit", "Test court"},
        )
        pending = store.pending("pc-test")
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["action"], "replace_computer_blocks")
        self.assertEqual(
            {item["block_id"] for item in pending[0]["blocks"]},
            {first_id, second_id},
        )
        store.save_snapshot("pc-test", {
            "capabilities": ["computer_blocks_v2"],
            "computer_blocks": second["blocks"],
        })
        self.assertEqual(store.pending("pc-test"), [])
        reflected = store.user_computer_block_policy("alice")["devices"][0]
        self.assertEqual(reflected["applied_revision"], second["revision"])

        toggled = store.mutate_user_computer_block("alice", {
            "action": "set_computer_block_enabled", "block_id": second_id,
            "enabled": False,
        }, "admin", "computer-v2-toggle-3")
        by_id = {item["block_id"]: item for item in toggled["blocks"]}
        self.assertTrue(by_id[first_id]["enabled"])
        self.assertFalse(by_id[second_id]["enabled"])

        removed = store.mutate_user_computer_block("alice", {
            "action": "clear_computer_block", "block_id": second_id,
        }, "admin", "computer-v2-remove-4")
        self.assertEqual([item["block_id"] for item in removed["blocks"]], [first_id])
        self.assertEqual(removed["block"]["name"], "Nuit")

    def test_local_computer_block_creation_accepts_provided_id_with_create_new(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user("alice", "temporary-strong", role="limited")
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": "S-1-5-21-100-200-300-1001",
            "windows_username": "Alice", "usage_guard_username": "alice",
        }], "admin")

        created = store.mutate_user_computer_block("alice", {
            "action": "set_computer_block", "block_id": "local-rule-123",
            "create_new": True, "mode": "schedule", "name": "Créée localement",
            "start_time": "19:30", "end_time": "19:32",
        }, "appareil pc-test · admin", "computer-local-create-1")

        self.assertEqual(created["block_id"], "local-rule-123")
        self.assertEqual(created["block"]["block_id"], "local-rule-123")
        self.assertNotIn("create_new", created["block"])
        self.assertNotIn("create_new", store.pending("pc-test")[0])
        with self.assertRaisesRegex(ValueError, "introuvable"):
            store.mutate_user_computer_block("alice", {
                "action": "set_computer_block", "block_id": "unknown-rule",
                "mode": "schedule", "start_time": "20:00", "end_time": "20:05",
            }, "admin", "computer-local-edit-missing-2")

    def test_multi_computer_block_requires_capability_before_commit(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user("alice", "temporary-strong", role="limited")
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": "S-1-5-21-100-200-300-1001",
            "windows_username": "Alice", "usage_guard_username": "alice",
        }], "admin")
        first = store.mutate_user_computer_block("alice", {
            "action": "set_computer_block", "mode": "schedule",
            "start_time": "22:30", "end_time": "05:00",
        }, "admin", "computer-legacy-safe-1")
        self.assertEqual(store.pending("pc-test")[0]["action"], "set_computer_block")

        with self.assertRaisesRegex(ValueError, "mis à jour"):
            store.mutate_user_computer_block("alice", {
                "action": "set_computer_block", "mode": "schedule",
                "start_time": "19:30", "end_time": "19:32",
            }, "admin", "computer-legacy-refused-2")

        unchanged = store.user_computer_block_policy("alice")
        self.assertEqual(unchanged["revision"], first["revision"])
        self.assertEqual(len(unchanged["blocks"]), 1)

    def test_disabled_singleton_keeps_legacy_definition_before_disable(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user("alice", "temporary-strong", role="limited")
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": "S-1-5-21-100-200-300-1001",
            "windows_username": "Alice", "usage_guard_username": "alice",
        }], "admin")
        created = store.mutate_user_computer_block("alice", {
            "action": "set_computer_block", "mode": "schedule",
            "start_time": "19:30", "end_time": "19:32",
            "name": "Test du soir",
        }, "admin", "computer-legacy-disable-create")

        store.mutate_user_computer_block("alice", {
            "action": "set_computer_block_enabled",
            "block_id": created["block_id"], "enabled": False,
        }, "admin", "computer-legacy-disable-toggle")
        pending = store.pending("pc-test")

        self.assertEqual(
            [item["action"] for item in pending],
            ["set_computer_block", "set_computer_block_enabled"],
        )
        self.assertEqual(pending[0]["start_time"], "19:30")
        self.assertEqual(pending[0]["end_time"], "19:32")
        self.assertEqual(pending[0]["name"], "Test du soir")
        self.assertFalse(pending[1]["enabled"])

    def test_computer_block_reflection_compares_all_persistent_fields(self):
        expected = {"version": 2, "blocks": [{
            "block_id": "daily-rule-1", "mode": "daily_duration",
            "enabled": True, "duration_seconds": 3600,
            "start_time": "17:00", "end_time": "22:00",
            "grace_seconds": 300,
            "valid_from": "", "valid_from_time": "",
            "valid_until": "", "valid_until_time": "", "name": "",
        }]}
        reflected = {"computer_blocks": [{
            "block_id": "daily-rule-1", "mode": "daily_duration",
            "enabled": True, "limit_seconds": 3600,
            "schedule_start": "17:00", "schedule_end": "22:00",
            "grace_seconds": 300,
            "valid_from": "", "valid_from_time": "",
            "valid_until": "", "valid_until_time": "", "name": "",
        }]}

        self.assertTrue(Store._computer_block_policy_reflected(
            reflected, expected,
        ))
        stale_values = {
            "limit_seconds": 7200,
            "grace_seconds": 600,
            "valid_from": "2026-08-28",
            "valid_from_time": "17:00",
            "valid_until": "2026-08-29",
            "valid_until_time": "22:00",
            "name": "Ancien nom",
        }
        for field, value in stale_values.items():
            with self.subTest(field=field):
                stale = copy.deepcopy(reflected)
                stale["computer_blocks"][0][field] = value
                self.assertFalse(Store._computer_block_policy_reflected(
                    stale, expected,
                ))
        warning_expected = copy.deepcopy(expected)
        warning_expected["blocks"][0]["enforcement_action"] = "warn"
        self.assertFalse(Store._computer_block_policy_reflected(
            reflected, warning_expected,
        ))
        warning_reflected = copy.deepcopy(reflected)
        warning_reflected["computer_blocks"][0]["enforcement_action"] = "warn"
        self.assertTrue(Store._computer_block_policy_reflected(
            warning_reflected, warning_expected,
        ))

    def test_v2_computer_block_fanout_filters_each_device_scope(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user("alice", "temporary-strong", role="limited")
        store.register_device("pc-other", token="o" * 48)
        for device_id, sid in (
            ("pc-test", "S-1-5-21-100-200-300-1001"),
            ("pc-other", "S-1-5-21-400-500-600-1001"),
        ):
            store.set_device_windows_identities(device_id, [{
                "windows_sid": sid, "windows_username": "Alice",
                "usage_guard_username": "alice",
            }], "admin")
            store.save_snapshot(device_id, {
                "capabilities": ["computer_blocks_v2"],
                "computer_blocks": [],
            })
        store.mutate_user_computer_block("alice", {
            "action": "set_computer_block", "mode": "schedule",
            "start_time": "22:30", "end_time": "05:00",
            "device_ids": ["pc-test"], "name": "Bureau",
        }, "admin", "computer-device-scope-1")
        store.mutate_user_computer_block("alice", {
            "action": "set_computer_block", "mode": "schedule",
            "start_time": "20:00", "end_time": "21:00",
            "device_ids": ["pc-other"], "name": "Portable",
        }, "admin", "computer-device-scope-2")

        pc_test = store.pending("pc-test")[-1]
        pc_other = store.pending("pc-other")[-1]
        self.assertEqual([item["name"] for item in pc_test["blocks"]], ["Bureau"])
        self.assertEqual([item["name"] for item in pc_other["blocks"]], ["Portable"])

    def test_personal_computer_block_api_returns_blocks_and_accepts_block_id(self):
        store = self.server.store
        store.create_user(
            "admin", "personal-admin-password", must_change=False, role="admin",
        )
        store.create_user(
            "alice", "personal-alice-password", must_change=False,
            role="limited",
        )
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": "S-1-5-21-100-200-300-1001",
            "windows_username": "Alice", "usage_guard_username": "alice",
        }], "admin")
        store.save_snapshot("pc-test", {
            "capabilities": ["computer_blocks_v2"], "computer_blocks": [],
        })
        _, login, headers = self.request(
            "/api/v1/auth/login", "POST", {
                "username": "admin", "password": "personal-admin-password",
            }, origin=PUBLIC_ORIGIN,
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        status, created, _ = self.request(
            "/api/v1/policies/alice/actions", "POST", {
                "action": "set_computer_block", "mode": "schedule",
                "start_time": "22:30", "end_time": "05:00",
                "name": "Nuit", "idempotency_key": "computer-api-create-1",
            }, origin=PUBLIC_ORIGIN, cookie=cookie,
            csrf=login["csrf_token"],
        )
        block_id = created["computer_block_policy"]["block_id"]
        status, toggled, _ = self.request(
            "/api/v1/policies/alice/actions", "POST", {
                "action": "set_computer_block_enabled", "block_id": block_id,
                "enabled": False, "idempotency_key": "computer-api-toggle-2",
            }, origin=PUBLIC_ORIGIN, cookie=cookie,
            csrf=login["csrf_token"],
        )

        self.assertEqual(status, 202)
        self.assertEqual(len(toggled["computer_block_policy"]["blocks"]), 1)
        self.assertEqual(
            toggled["computer_block_policy"]["blocks"][0]["block_id"], block_id,
        )
        self.assertFalse(
            toggled["computer_block_policy"]["blocks"][0]["enabled"]
        )

    def test_reflected_computer_block_marks_device_revision_applied(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user("alice", "temporary-strong", role="limited", device_ids=[])
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": "S-1-5-21-100-200-300-1001",
            "windows_username": "Alice", "usage_guard_username": "alice",
        }], "admin")
        store.mutate_user_computer_block("alice", {
            "action": "set_computer_block", "mode": "schedule",
            "start_time": "23:00", "end_time": "05:00",
        }, "admin", "computer-operation-reflected")

        self.assertEqual(len(store.pending("pc-test")), 1)
        store.save_snapshot("pc-test", {"computer_block": {
            "enabled": True, "mode": "schedule",
            "daily_start": "23:00", "daily_end": "05:00",
        }})
        self.assertEqual(store.pending("pc-test"), [])

        state = store.user_computer_block_policy("alice")["devices"][0]
        self.assertEqual(state["applied_revision"], 1)
        self.assertEqual(state["last_result"]["phase"], "reflected")

    def test_overview_reflection_marks_computer_revision_before_deleting_command(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user("alice", "temporary-strong", role="limited", device_ids=[])
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": "S-1-5-21-100-200-300-1001",
            "windows_username": "Alice", "usage_guard_username": "alice",
        }], "admin")
        store.mutate_user_computer_block("alice", {
            "action": "set_computer_block", "mode": "schedule",
            "start_time": "20:11", "end_time": "20:12",
        }, "admin", "computer-operation-overview-reflected")
        self.assertEqual(len(store.pending("pc-test")), 1)
        store.save_snapshot("pc-test", {"computer_block": {
            "enabled": True, "mode": "schedule",
            "daily_start": "20:11", "daily_end": "20:12",
        }})

        cards = store.pending_limit_commands(
            "pc-test", store.snapshot("pc-test"),
        )

        self.assertEqual(cards, [])
        state = store.user_computer_block_policy("alice")["devices"][0]
        self.assertEqual(state["applied_revision"], 1)
        self.assertEqual(state["last_result"]["phase"], "reflected")

    def test_restart_repairs_missing_ack_for_an_already_applied_block(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user("alice", "temporary-strong", role="limited", device_ids=[])
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": "S-1-5-21-100-200-300-1001",
            "windows_username": "Alice", "usage_guard_username": "alice",
        }], "admin")
        policy = store.mutate_user_computer_block("alice", {
            "action": "set_computer_block", "mode": "schedule",
            "start_time": "23:00", "end_time": "05:00",
        }, "admin", "computer-operation-lost-ack")
        command_id = int(policy["devices"][0]["command_id"])
        store.save_snapshot("pc-test", {"computer_block": {
            "enabled": True, "mode": "schedule",
            "daily_start": "23:00", "daily_end": "05:00",
        }})
        with store.connect() as db:
            db.execute("DELETE FROM commands WHERE id=?", (command_id,))

        repaired = Store(store.path, email_encryption_key="e" * 32)
        state = repaired.user_computer_block_policy("alice")["devices"][0]

        self.assertEqual(state["applied_revision"], 1)
        self.assertEqual(state["last_result"]["phase"], "reflected")

    def test_restart_adopts_an_existing_device_computer_block_once(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": "S-1-5-21-100-200-300-1001",
            "windows_username": "Alice", "usage_guard_username": "alice",
        }], "admin")
        store.save_snapshot("pc-test", {"computer_block": {
            "enabled": True, "mode": "schedule",
            "daily_start": "23:00", "daily_end": "05:00",
            "grace_seconds": 300, "actor": "admin",
        }})

        migrated = Store(store.path, email_encryption_key="e" * 32)
        policy = migrated.user_computer_block_policy("alice")
        replayed = Store(
            store.path, email_encryption_key="e" * 32
        ).user_computer_block_policy("alice")

        self.assertTrue(policy["configured"])
        self.assertEqual(policy["revision"], 1)
        self.assertEqual(policy["block"]["start_time"], "23:00")
        self.assertEqual(policy["block"]["end_time"], "05:00")
        self.assertEqual(replayed["revision"], 1)
        self.assertEqual(len(policy["devices"]), 1)

        store.register_device("pc-other", token="o" * 48)
        store.set_device_windows_identities("pc-other", [{
            "windows_sid": "S-1-5-21-400-500-600-1001",
            "windows_username": "Alice", "usage_guard_username": "alice",
        }], "admin")
        with store.connect() as db:
            db.execute(
                "INSERT INTO commands(device_id,payload,created_at,"
                "idempotency_key) VALUES(?,?,?,?)",
                (
                    "pc-other",
                    '{"action":"set_computer_block","actor":"ancien"}',
                    "2026-08-25T20:00:00+00:00",
                    "computer-policy:alice:1:pc-other",
                ),
            )
        repaired = Store(
            store.path, email_encryption_key="e" * 32
        ).user_computer_block_policy("alice")
        self.assertEqual(
            {item["device_id"] for item in repaired["devices"]},
            {"pc-test", "pc-other"},
        )
        self.assertTrue(all(
            item["desired_revision"] == 1 for item in repaired["devices"]
        ))

    def test_first_personal_policy_mutation_imports_reference_limits_once(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_domain": "FAMILLE",
            "windows_username": "Alice", "usage_guard_username": "alice",
        }], "admin")
        store.save_snapshot("pc-test", {
            "limits": [{
                "key": "app:legacy", "target_key": "app:legacy",
                "enabled": True, "limit_seconds": 600,
                "seconds": 120, "remaining": 480, "label": "Legacy",
            }],
        })
        command = {
            "action": "set_limit", "target_key": "app:new",
            "settings": {
                "create_new": True, "target_key": "app:new",
                "enabled": True, "limit_seconds": 300,
                "name": "  Travail concentré  ",
            },
        }

        first = store.mutate_user_policy(
            "alice", command, "admin", "pc-test", "operation-1",
        )
        replay = store.mutate_user_policy(
            "alice", command, "admin", "pc-test", "operation-1",
        )

        self.assertEqual(first["revision"], 1)
        self.assertEqual(replay["revision"], 1)
        limits = {item["key"]: item for item in replay["policy"]["limits"]}
        self.assertEqual(set(limits), {"app:legacy", "app:new"})
        self.assertEqual(limits["app:legacy"]["limit_seconds"], 600)
        self.assertNotIn("seconds", limits["app:legacy"])
        self.assertEqual(limits["app:new"]["operation_id"], "operation-1")
        self.assertEqual(limits["app:new"]["name"], "Travail concentré")
        self.assertEqual(limits["app:new"]["actor"], "admin")
        self.assertTrue(limits["app:new"]["updated_at"])
        self.assertEqual(limits["app:new"]["requested_by"], "admin")
        self.assertTrue(limits["app:new"]["requested_at"])
        with self.assertRaisesRegex(ValueError, "120 caractères"):
            store.mutate_user_policy(
                "alice", {
                    "action": "set_limit", "target_key": "app:long-name",
                    "settings": {
                        "create_new": True, "target_key": "app:long-name",
                        "enabled": True, "limit_seconds": 300,
                        "name": "x" * 121,
                    },
                }, "admin", "pc-test", "operation-long-name",
            )

        removed = store.mutate_user_policy(
            "alice", {
                "action": "remove_limit", "target_key": "app:legacy",
            }, "admin", "pc-test", "operation-2",
        )
        self.assertEqual(removed["revision"], 2)
        self.assertEqual(
            [item["key"] for item in removed["policy"]["limits"]],
            ["app:new"],
        )
        with self.assertRaisesRegex(ValueError, "non prise en charge"):
            store.mutate_user_policy(
                "alice", {
                    "action": "set_enforcement_mode",
                    "enforcement_mode": "shadow",
                }, "admin",
            )
        operation = store.begin_user_policy_operation(
            "alice", {
                "action": "remove_limit", "target_key": "app:new",
            }, "admin", idempotency_key="policy-operation-1",
        )
        replay = store.begin_user_policy_operation(
            "alice", {
                "action": "remove_limit", "target_key": "app:new",
            }, "admin", idempotency_key="policy-operation-1",
        )
        self.assertEqual(operation["target_revision"], 3)
        self.assertEqual(replay["id"], operation["id"])
        self.assertTrue(replay["reused"])
        self.assertFalse(operation["complete"])

        cancelled = store.cancel_user_policy_operation(
            "alice", operation["id"], "admin",
        )
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertEqual(cancelled["rollback_revision"], 4)
        self.assertEqual(
            [item["key"] for item in cancelled["policy"]["policy"]["limits"]],
            ["app:new"],
        )
        store.acknowledge_user_policy(
            "pc-test", sid, 4, {"ok": True, "phase": "applied"},
        )
        self.assertTrue(store.user_policy_operation(
            "alice", operation["id"],
        )["complete"])

    def test_warning_app_limit_requires_capability_and_survives_partial_edit(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        command = {
            "action": "set_limit", "target_key": "app:kona",
            "settings": {
                "target_key": "app:kona", "enabled": True,
                "limit_seconds": 3600, "enforcement_action": "warn",
            },
        }

        with self.assertRaisesRegex(ValueError, "mode Avertir.*mise à jour"):
            store.mutate_user_policy("alice", command, "admin")
        self.assertFalse(store.user_policy("alice")["configured"])

        store.save_snapshot("pc-test", {
            "capabilities": ["limit_warning_action"],
        })
        created = store.mutate_user_policy("alice", command, "admin")
        edited = store.mutate_user_policy("alice", {
            "action": "set_limit", "target_key": "app:kona",
            "settings": {
                "target_key": "app:kona", "enabled": True,
                "limit_seconds": 5400,
            },
        }, "admin")

        created_limit = created["policy"]["limits"][0]
        edited_limit = edited["policy"]["limits"][0]
        self.assertEqual(created_limit["enforcement_action"], "warn")
        self.assertEqual(edited_limit["enforcement_action"], "warn")
        self.assertEqual(edited_limit["limit_seconds"], 5400)
        delivered = store.policy_for_windows_sid("pc-test", sid)
        self.assertEqual(
            delivered["policy"]["limits"][0]["enforcement_action"], "warn",
        )

    def test_direct_warning_limit_command_is_refused_for_legacy_client(self):
        store = self.server.store
        command = {
            "action": "set_limit", "target_key": "app:kona",
            "settings": {
                "target_key": "app:kona", "enabled": True,
                "limit_seconds": 3600, "enforcement_action": "warn",
            },
        }

        with self.assertRaisesRegex(ValueError, "mode Avertir.*mise à jour"):
            store.queue_idempotent("pc-test", command, "warning-direct-old")

        store.save_snapshot("pc-test", {
            "capabilities": {"limit_warning_action": True},
        })
        command_id, reused = store.queue_idempotent(
            "pc-test", command, "warning-direct-new",
        )
        self.assertTrue(command_id)
        self.assertFalse(reused)

    def test_policy_api_is_scoped_by_user_device_and_windows_sid(self):
        store = self.server.store
        store.create_user(
            "admin", "personal-admin-password", must_change=False,
            role="admin", email="admin@example.test",
        )
        store.create_user(
            "alice", "personal-alice-password", must_change=False,
            role="limited", device_ids=[], email="alice@example.test",
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_domain": "FAMILLE",
            "windows_username": "Alice", "usage_guard_username": "alice",
        }], "admin")
        _, login, headers = self.request(
            "/api/v1/auth/login", "POST", {
                "username": "admin", "password": "personal-admin-password",
            }, origin=PUBLIC_ORIGIN,
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        status, saved, _ = self.request(
            "/api/v1/policies/alice", "POST", {
                "policy": {"limits": [{"target_key": "app:test"}]},
            }, origin=PUBLIC_ORIGIN, cookie=cookie,
            csrf=login["csrf_token"],
        )
        self.assertEqual(status, 200)
        self.assertEqual(saved["revision"], 1)

        status, usage, _ = self.request(
            "/api/v1/policies/alice/usage?" + urlencode({
                "start": "2026-08-24T00:00:00+02:00",
                "end": "2026-08-25T00:00:00+02:00",
            }), cookie=cookie,
        )
        self.assertEqual(status, 200)
        self.assertEqual(usage["usage_guard_username"], "alice")
        self.assertEqual(usage["seconds"], 0)

        status, policy, _ = self.request(
            "/api/v1/agent/policy?" + urlencode({
                "device_id": "pc-test", "windows_sid": sid,
            }), agent=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(policy["usage_guard_username"], "alice")
        self.assertEqual(policy["policy"]["limits"][0]["target_key"], "app:test")

        with self.assertRaises(HTTPError) as error:
            self.request(
                "/api/v1/agent/policy?" + urlencode({
                    "device_id": "pc-test",
                    "windows_sid": "S-1-5-21-100-200-300-9999",
                }), agent=True,
            )
        self.assertEqual(error.exception.code, 409)

        status, acknowledged, _ = self.request(
            "/api/v1/agent/policy/ack", "POST", {
                "device_id": "pc-test", "windows_sid": sid,
                "revision": 1, "result": {"ok": True},
            }, agent=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            acknowledged["policy"]["devices"][0]["applied_revision"], 1,
        )

    def test_policy_action_api_targets_person_not_selected_device(self):
        store = self.server.store
        store.create_user(
            "admin", "personal-admin-password", must_change=False,
            role="admin", email="admin@example.test",
        )
        store.create_user(
            "alice", "personal-alice-password", must_change=False,
            role="limited", device_ids=[], email="alice@example.test",
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_domain": "FAMILLE",
            "windows_username": "Alice", "usage_guard_username": "alice",
        }], "admin")
        store.save_snapshot("pc-test", {"limits": []})
        _, login, headers = self.request(
            "/api/v1/auth/login", "POST", {
                "username": "admin", "password": "personal-admin-password",
            }, origin=PUBLIC_ORIGIN,
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        status, payload, _ = self.request(
            "/api/v1/policies/alice/actions", "POST", {
                "action": "set_limit", "base_device_id": "pc-test",
                "idempotency_key": "person-operation-1",
                "target_key": "app:test",
                "settings": {
                    "create_new": True, "target_key": "app:test",
                    "limit_seconds": 300,
                },
            }, origin=PUBLIC_ORIGIN, cookie=cookie,
            csrf=login["csrf_token"],
        )

        self.assertEqual(status, 202)
        self.assertEqual(payload["usage_guard_username"], "alice")
        self.assertEqual(payload["revision"], 1)
        self.assertEqual(
            payload["policy"]["policy"]["limits"][0]["key"], "app:test",
        )
        self.assertEqual(
            payload["devices"][0]["device_id"], "pc-test",
        )
        status, observed, _ = self.request(
            f"/api/v1/policies/alice/operations/{payload['id']}",
            cookie=cookie,
        )
        self.assertEqual(status, 200)
        self.assertEqual(observed["target_revision"], 1)

        status, cancelled, _ = self.request(
            f"/api/v1/policies/alice/operations/{payload['id']}/cancel",
            "POST", {}, origin=PUBLIC_ORIGIN, cookie=cookie,
            csrf=login["csrf_token"],
        )
        self.assertEqual(status, 200)
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertEqual(cancelled["rollback_revision"], 2)
        self.assertEqual(cancelled["policy"]["policy"]["limits"], [])

    def test_same_account_can_modify_local_limit_remotely_but_other_account_cannot(self):
        store = self.server.store
        store.create_user(
            "admin", "personal-admin-password", must_change=False,
            role="admin", email="admin@example.test",
        )
        store.create_user(
            "alice", "personal-alice-password", must_change=False,
            role="limited", device_ids=[], email="alice@example.test",
        )
        for username in ("eva", "bob"):
            store.create_user(
                username, f"personal-{username}-password", must_change=False,
                role="user", device_ids=["pc-test"],
                email=f"{username}@example.test",
                permissions={"view_limits": True, "manage_limits": True},
            )
        store.rename_device("pc-test", "Ordi 1 : Bureau")
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": "S-1-5-21-100-200-300-1001",
            "windows_username": "Alice", "usage_guard_username": "alice",
        }], "admin")
        store.mutate_user_computer_block("alice", {
            "action": "set_computer_block", "mode": "schedule",
            "start_time": "20:11", "end_time": "20:12",
        }, "appareil Ordi 1 : Bureau · eva", "local-eva-computer-1")

        _, eva_login, eva_headers = self.request(
            "/api/v1/auth/login", "POST", {
                "username": "eva", "password": "personal-eva-password",
            }, origin=PUBLIC_ORIGIN,
        )
        eva_cookie = eva_headers["Set-Cookie"].split(";", 1)[0]
        status, changed, _ = self.request(
            "/api/v1/policies/alice/actions", "POST", {
                "action": "set_computer_block_enabled", "enabled": False,
                "idempotency_key": "remote-eva-computer-2",
            }, origin=PUBLIC_ORIGIN, cookie=eva_cookie,
            csrf=eva_login["csrf_token"],
        )
        self.assertEqual(status, 202)
        self.assertEqual(changed["computer_block_policy"]["actor"], "eva")

        _, bob_login, bob_headers = self.request(
            "/api/v1/auth/login", "POST", {
                "username": "bob", "password": "personal-bob-password",
            }, origin=PUBLIC_ORIGIN,
        )
        bob_cookie = bob_headers["Set-Cookie"].split(";", 1)[0]
        with self.assertRaises(HTTPError) as failure:
            self.request(
                "/api/v1/policies/alice/actions", "POST", {
                    "action": "set_computer_block_enabled", "enabled": True,
                    "idempotency_key": "remote-bob-computer-3",
                }, origin=PUBLIC_ORIGIN, cookie=bob_cookie,
                csrf=bob_login["csrf_token"],
            )
        self.assertEqual(failure.exception.code, 403)

    def test_personal_limit_action_sends_one_email_for_two_computers(self):
        store = self.server.store
        store.create_user(
            "admin", "personal-admin-password", must_change=False,
            role="admin", email="admin@example.test",
        )
        store.create_user(
            "alice", "personal-alice-password", must_change=False,
            role="limited", device_ids=[], email="alice@example.test",
        )
        store.register_device("pc-other", token="o" * 48)
        for device_id, sid in (
            ("pc-test", "S-1-5-21-100-200-300-1001"),
            ("pc-other", "S-1-5-21-400-500-600-1001"),
        ):
            store.set_device_windows_identities(device_id, [{
                "windows_sid": sid, "windows_username": "Alice",
                "usage_guard_username": "alice",
            }], "admin")
            store.update_device_notification_policy(
                device_id, "set_notification_rule", {
                    "id": "limit-mail-" + device_id,
                    "kind": (
                        "computer_block_change"
                        if device_id == "pc-other" else "limit_change"
                    ),
                    "owner": "alice", "enabled": True,
                    "channels": ["email"],
                    "email_recipient": "alice@example.test",
                },
            )
        store.save_email_settings({
            "smtp_host": "smtp.example.test", "smtp_port": 587,
            "security": "starttls", "sender": "guard@example.test",
        })
        _, login, headers = self.request(
            "/api/v1/auth/login", "POST", {
                "username": "admin", "password": "personal-admin-password",
            }, origin=PUBLIC_ORIGIN,
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        request = {
            "action": "set_limit", "base_device_id": "pc-test",
            "idempotency_key": "person-email-operation-1",
            "target_key": "app:codex",
            "settings": {
                "create_new": True, "target_key": "app:codex",
                "limit_seconds": 300,
            },
        }
        delivered = threading.Event()
        calls = []

        def record_delivery(*args):
            calls.append(args)
            delivered.set()

        with patch.object(
            self.server, "_send_email_background", side_effect=record_delivery,
        ):
            self.request(
                "/api/v1/policies/alice/actions", "POST", request,
                origin=PUBLIC_ORIGIN, cookie=cookie,
                csrf=login["csrf_token"],
            )
            self.assertTrue(delivered.wait(1))
            self.request(
                "/api/v1/policies/alice/actions", "POST", request,
                origin=PUBLIC_ORIGIN, cookie=cookie,
                csrf=login["csrf_token"],
            )
            time.sleep(.05)

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][2:], ("alice@example.test", "limit_change"))
        self.assertIn("codex", calls[0][1].lower())

    def test_agent_can_publish_only_its_mapped_users_local_limit(self):
        store = self.server.store
        store.rename_device("pc-test", "Ordi 1 : Bureau")
        store.create_user(
            "admin", "personal-admin-password", must_change=False,
            role="admin", email="admin@example.test",
        )
        store.create_user(
            "alice", "personal-alice-password", must_change=False,
            role="limited", device_ids=[], email="alice@example.test",
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_domain": "FAMILLE",
            "windows_username": "Alice", "usage_guard_username": "alice",
        }], "admin")
        store.save_snapshot("pc-test", {"limits": []})
        request = {
            "device_id": "pc-test", "windows_sid": sid,
            "idempotency_key": "local-pc-operation-1",
            "actor": "admin",
            "command": {
                "action": "set_limit", "target_key": "app:test",
                "settings": {
                    "create_new": True, "target_key": "app:test",
                    "limit_seconds": 300,
                },
            },
        }

        status, first, _ = self.request(
            "/api/v1/agent/policy/actions", "POST", request, agent=True,
        )
        status_replay, replay, _ = self.request(
            "/api/v1/agent/policy/actions", "POST", request, agent=True,
        )

        self.assertEqual((status, status_replay), (202, 202))
        self.assertEqual(first["usage_guard_username"], "alice")
        self.assertEqual(first["revision"], 1)
        self.assertEqual(replay["id"], first["id"])
        self.assertTrue(replay["reused"])
        saved_limit = store.user_policy("alice")["policy"]["limits"][0]
        self.assertEqual(
            saved_limit["requested_by"], "appareil Ordi 1 : Bureau · admin",
        )
        with self.assertRaises(HTTPError) as failure:
            self.request(
                "/api/v1/agent/policy/actions", "POST", {
                    **request,
                    "windows_sid": "S-1-5-21-100-200-300-9999",
                    "idempotency_key": "local-pc-operation-2",
                }, agent=True,
            )
        self.assertEqual(failure.exception.code, 409)

    def test_agent_local_computer_limit_targets_mapped_person_and_all_their_pcs(self):
        store = self.server.store
        store.rename_device("pc-test", "Ordi 1 : Bureau")
        store.create_user(
            "admin", "personal-admin-password", must_change=False,
            role="admin", email="admin@example.test",
        )
        store.create_user(
            "alice", "personal-alice-password", must_change=False,
            role="limited", device_ids=[], email="alice@example.test",
        )
        store.register_device("pc-other", token="o" * 48)
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        store.set_device_windows_identities("pc-other", [{
            "windows_sid": "S-1-5-21-400-500-600-1001",
            "windows_username": "Alice", "usage_guard_username": "alice",
        }], "admin")
        request = {
            "device_id": "pc-test", "windows_sid": sid,
            "idempotency_key": "local-computer-operation-1",
            "actor": "admin",
            "command": {
                "action": "set_computer_block", "mode": "schedule",
                "start_time": "20:11", "end_time": "20:12",
                "grace_seconds": 300,
            },
        }

        status, first, _ = self.request(
            "/api/v1/agent/policy/actions", "POST", request, agent=True,
        )
        replay_status, replay, _ = self.request(
            "/api/v1/agent/policy/actions", "POST", request, agent=True,
        )

        self.assertEqual((status, replay_status), (202, 202))
        self.assertEqual(first["usage_guard_username"], "alice")
        self.assertEqual(first["computer_block_policy"]["revision"], 1)
        self.assertTrue(replay["computer_block_policy"]["reused"])
        policy = store.user_computer_block_policy("alice")
        self.assertEqual(policy["actor"], "appareil Ordi 1 : Bureau · admin")
        self.assertEqual(
            policy["block"]["device_ids"], ["pc-other", "pc-test"],
        )
        self.assertEqual(
            {item["device_id"] for item in policy["devices"]},
            {"pc-test", "pc-other"},
        )

    def test_agent_catalog_action_fans_out_without_echoing_to_source_pc(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        store.register_device("pc-other", token="o" * 48)
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        store.set_device_windows_identities("pc-other", [{
            "windows_sid": "S-1-5-21-400-500-600-1001",
            "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        request = {
            "device_id": "pc-test", "windows_sid": sid,
            "idempotency_key": "catalog-operation-1", "actor": "admin",
            "command": {
                "action": "set_category", "target_key": "app:test",
                "category": "Travail",
            },
        }

        status, first, _ = self.request(
            "/api/v1/agent/catalog/actions", "POST", request, agent=True,
        )
        status_replay, replay, _ = self.request(
            "/api/v1/agent/catalog/actions", "POST", request, agent=True,
        )

        self.assertEqual((status, status_replay), (202, 202))
        self.assertEqual(first["source_device_id"], "pc-test")
        self.assertEqual(
            [item["device_id"] for item in first["deliveries"]],
            ["pc-other"],
        )
        self.assertTrue(replay["deliveries"][0]["reused"])
        _, pending_other, _ = self.request(
            "/api/v1/agent/commands?device_id=pc-other",
            agent=True, token="o" * 48,
        )
        self.assertEqual(len(pending_other["commands"]), 1)
        self.assertEqual(pending_other["commands"][0]["action"], "set_category")
        self.assertEqual(
            pending_other["commands"][0]["_usage_guard_target_username"],
            "alice",
        )
        self.assertEqual(
            pending_other["commands"][0]["_usage_guard_target_windows_sids"],
            ["S-1-5-21-400-500-600-1001"],
        )
        _, pending_source, _ = self.request(
            "/api/v1/agent/commands?device_id=pc-test", agent=True,
        )
        self.assertEqual(pending_source["commands"], [])

    def test_agent_delete_target_requires_limit_grants_and_other_owner_grant(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        store.register_device("pc-other", token="o" * 48)
        alice_test_sid = "S-1-5-21-100-200-300-1001"
        alice_other_sid = "S-1-5-21-400-500-600-1001"
        for device_id, sid in (
            ("pc-test", alice_test_sid), ("pc-other", alice_other_sid),
        ):
            store.set_device_windows_identities(device_id, [{
                "windows_sid": sid, "windows_username": "Alice",
                "usage_guard_username": "alice",
            }], "admin")
        store.save_user_policy("alice", {
            "enforcement_mode": "enforced", "limits": [{
                "key": "app:owned-by-admin",
                "target_key": "app:owned-by-admin",
                "limit_seconds": 300, "requested_by": "admin",
                "actor": "admin",
            }],
        }, "admin")
        self.assertEqual(
            store.target_policy_deletion_impact(
                "alice", "app:owned-by-admin", ["pc-test", "pc-other"],
            )["owners"],
            ["admin"],
        )

        def agent_payload(operation, **grants):
            return {
                "device_id": "pc-test", "windows_sid": alice_test_sid,
                "idempotency_key": operation, "actor": "alice",
                "command": {
                    "action": "delete_target",
                    "target_key": "app:owned-by-admin", **grants,
                },
            }

        with self.assertRaises(HTTPError) as missing_limit_grant:
            self.request(
                "/api/v1/agent/catalog/actions", "POST",
                agent_payload("agent-delete-denied-0001"), agent=True,
            )
        self.assertEqual(missing_limit_grant.exception.code, 403)
        with self.assertRaises(HTTPError) as missing_other_grant:
            self.request(
                "/api/v1/agent/catalog/actions", "POST",
                agent_payload(
                    "agent-delete-denied-0002",
                    _usage_guard_delete_limits_authorized=True,
                ), agent=True,
            )
        self.assertEqual(missing_other_grant.exception.code, 403)

        status, deleted, _ = self.request(
            "/api/v1/agent/catalog/actions", "POST",
            agent_payload(
                "agent-delete-allowed-0001",
                _usage_guard_delete_limits_authorized=True,
                _usage_guard_delete_other_limits_authorized=True,
            ), agent=True,
        )

        self.assertEqual(status, 202)
        self.assertEqual(deleted["source_device_id"], "pc-test")
        self.assertEqual(store.user_policy("alice")["policy"]["limits"], [])
        pending = store.pending("pc-other")
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["action"], "delete_target")
        self.assertEqual(pending[0]["_usage_guard_target_username"], "alice")
        self.assertEqual(
            pending[0]["_usage_guard_target_windows_sids"],
            [alice_other_sid],
        )
        self.assertNotIn(
            "_usage_guard_delete_limits_authorized", pending[0],
        )
        self.assertNotIn(
            "_usage_guard_delete_other_limits_authorized", pending[0],
        )

    def test_web_delete_target_requires_manage_limits_and_other_owner_right(self):
        store = self.server.store
        store.create_user(
            "admin", "personal-admin-password", must_change=False,
            role="admin", email="admin@example.test",
        )
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        store.create_user(
            "cataloger", "personal-cataloger-password", must_change=False,
            role="user", device_ids=["pc-test"],
            permissions={"manage_activity": True, "manage_limits": False},
        )
        store.create_user(
            "operator", "personal-operator-password", must_change=False,
            role="user", device_ids=["pc-test"],
            permissions={
                "manage_activity": True, "manage_limits": True,
                "manage_other_limits": False,
            },
        )
        store.save_user_policy("alice", {
            "enforcement_mode": "enforced", "limits": [{
                "key": "app:admin-rule", "target_key": "app:admin-rule",
                "limit_seconds": 300, "requested_by": "admin",
                "actor": "admin",
            }],
        }, "admin")

        def login(username, password):
            _, session, headers = self.request(
                "/api/v1/auth/login", "POST", {
                    "username": username, "password": password,
                }, origin=PUBLIC_ORIGIN,
            )
            return session, headers["Set-Cookie"].split(";", 1)[0]

        cataloger, cataloger_cookie = login(
            "cataloger", "personal-cataloger-password",
        )
        with self.assertRaises(HTTPError) as no_manage_limits:
            self.request(
                "/api/v1/catalogs/alice/actions", "POST", {
                    "action": "delete_target", "target_key": "app:no-rule",
                    "idempotency_key": "web-delete-denied-0001",
                }, origin=PUBLIC_ORIGIN, cookie=cataloger_cookie,
                csrf=cataloger["csrf_token"],
            )
        self.assertEqual(no_manage_limits.exception.code, 403)

        operator, operator_cookie = login(
            "operator", "personal-operator-password",
        )
        with self.assertRaises(HTTPError) as no_manage_other:
            self.request(
                "/api/v1/catalogs/alice/actions", "POST", {
                    "action": "delete_target",
                    "target_key": "app:admin-rule",
                    "idempotency_key": "web-delete-denied-0002",
                }, origin=PUBLIC_ORIGIN, cookie=operator_cookie,
                csrf=operator["csrf_token"],
            )
        self.assertEqual(no_manage_other.exception.code, 403)
        with self.assertRaises(HTTPError) as retired_site_delete:
            self.request(
                "/api/v1/catalogs/alice/actions", "POST", {
                    "action": "delete_site", "browser": "brave.exe",
                    "host": "example.test",
                    "idempotency_key": "web-delete-site-retired-0001",
                }, origin=PUBLIC_ORIGIN, cookie=operator_cookie,
                csrf=operator["csrf_token"],
            )
        self.assertEqual(retired_site_delete.exception.code, 400)
        with store.connect() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM commands"
            ).fetchone()[0], 0)
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_target_deletion_operations"
            ).fetchone()[0], 0)

    def test_delete_target_site_key_validation_is_strict_and_normalized(self):
        for target_key in (
            "app:", "category:", "site::example.test",
            "site:brave.exe:", "site:brave.exe:https://example.test",
        ):
            with self.subTest(target_key=target_key), self.assertRaises(
                ValueError
            ):
                self.server.store._catalog_deletion_target({
                    "action": "delete_target", "target_key": target_key,
                })
        self.assertEqual(
            self.server.store._catalog_deletion_target({
                "action": "delete_target",
                "target_key": "site:BRAVE.EXE:WWW.Example.TEST.",
            }),
            "site:brave.exe:example.test",
        )

    def test_delete_target_sanitizes_snapshot_and_legacy_fallback_without_rewrite(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        legacy = {
            "runtime": {"windows_identity": {
                "windows_sid": sid, "usage_guard_username": "alice",
            }},
            "targets": {
                "app:deleted": {"label": "Deleted"},
                "app:kept": {"label": "Kept"},
            },
            "merge_candidates": [
                {"key": "app:deleted", "label": "Deleted"},
                {"key": "app:kept", "label": "Kept"},
            ],
            "days": {"2026-08-03": {
                "app:deleted": 60, "app:kept": 30,
            }},
            "sessions": [{
                "kind": "active", "key": "app:deleted",
                "usage_guard_username": "alice",
                "started_at": "2026-08-03T08:00:00+00:00",
                "ended_at": "2026-08-03T08:01:00+00:00",
            }],
        }
        store._save_document("activity_stores", "pc-test", legacy)
        store.save_snapshot("pc-test", legacy)

        store.purge_user_target_activity(
            "alice", "app:deleted", ["pc-test"], "admin",
            "delete-fallback-legacy-0001",
        )

        compact = store.snapshot("pc-test")
        self.assertNotIn("app:deleted", compact["targets"])
        self.assertNotIn("app:deleted", compact["days"]["2026-08-03"])
        self.assertEqual(compact["sessions"], [])
        fallback = store.activity_store("pc-test")["activity"]
        self.assertNotIn("app:deleted", fallback["targets"])
        self.assertNotIn("app:deleted", fallback["days"]["2026-08-03"])
        self.assertEqual(fallback["sessions"], [])
        raw, _ = store._load_document("activity_stores", "pc-test")
        self.assertIn("app:deleted", raw["targets"])
        self.assertIn("app:deleted", raw["days"]["2026-08-03"])

        # A released compact-catalog seal never exposes the frozen legacy
        # archive; that fallback remains masked in memory without rewriting it.
        with store.connect() as db:
            db.execute(
                "UPDATE activity_target_deletion_seals SET catalog_sealed=0 "
                "WHERE device_id=? AND usage_guard_username=? AND target_key=?",
                ("pc-test", "alice", "app:deleted"),
            )
        fallback = store.activity_store("pc-test")["activity"]
        self.assertNotIn("app:deleted", fallback["targets"])

    def test_delete_site_purges_other_site_details_and_seals_replays(self):
        store = self.server.store
        store.create_user(
            "admin", "temporary-strong", role="admin", device_ids=[],
        )
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        target = "site:brave.exe:amazon.fr"
        kept = "site:brave.exe:kept.example"
        details = [
            {"browser": "brave.exe", "host": "amazon.fr", "seconds": 40},
            {"browser": "brave.exe", "host": "kept.example", "seconds": 20},
        ]
        analysis = {
            "other_sites": copy.deepcopy(details),
            "other_site_days": {"brave.exe": {"2026-08-03": {
                "amazon.fr": 40, "kept.example": 20,
            }}},
            "daily_stats": [{
                "date": "2026-08-03", "usage": [],
                "other_sites": copy.deepcopy(details),
            }],
        }
        snapshot = {
            "runtime": {"windows_identity": {
                "windows_sid": sid, "usage_guard_username": "alice",
            }},
            "targets": {
                target: {"label": "Amazon"}, kept: {"label": "Kept"},
            },
            "merge_candidates": [
                {"key": target, "label": "Amazon"},
                {"key": kept, "label": "Kept"},
            ],
            **copy.deepcopy(analysis),
            "analysis": copy.deepcopy(analysis),
        }
        store.save_snapshot("pc-test", snapshot)
        store.ingest_activity_daily_aggregates("pc-test", [{
            "aggregate_id": "aggregate-other-site-before-0001",
            "local_day": "2026-08-03", "metrics": [{
                "kind": "usage", "key": "site:brave.exe:other-sites",
                "seconds": 60,
            }, {
                "kind": "other_site", "key": target, "seconds": 40,
            }, {
                "kind": "other_site", "key": kept, "seconds": 20,
            }],
        }], sid)
        with store.connect() as db:
            db.executemany(
                "INSERT INTO activity_daily_legacy(device_id,"
                "usage_guard_username,local_day,metric_kind,metric_key,seconds) "
                "VALUES(?,?,?,?,?,?)",
                [
                    ("pc-test", "alice", "2026-08-03", "other_site", target, 40),
                    ("pc-test", "alice", "2026-08-03", "other_site", kept, 20),
                ],
            )

        store.purge_user_target_activity(
            "alice", target, ["pc-test"], "admin",
            "delete-other-site-sealed-0001",
        )

        cleaned = store.snapshot("pc-test")
        for document in (cleaned, cleaned["analysis"]):
            self.assertEqual(
                [item["host"] for item in document["other_sites"]],
                ["kept.example"],
            )
            self.assertEqual(
                [
                    item["host"]
                    for item in document["daily_stats"][0]["other_sites"]
                ],
                ["kept.example"],
            )
            self.assertEqual(
                document["other_site_days"]["brave.exe"]["2026-08-03"],
                {"kept.example": 20},
            )
        with store.connect() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_daily_legacy WHERE device_id=? "
                "AND usage_guard_username=? AND metric_kind='other_site' "
                "AND metric_key=?",
                ("pc-test", "alice", target),
            ).fetchone()[0], 0)
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_daily_aggregate_metrics AS m "
                "JOIN activity_daily_aggregate_batches AS b ON "
                "b.device_id=m.device_id AND b.aggregate_id=m.aggregate_id "
                "WHERE b.device_id=? AND b.usage_guard_username=? AND "
                "m.metric_kind='other_site' AND m.metric_key=?",
                ("pc-test", "alice", target),
            ).fetchone()[0], 0)

        # A stale correction for the sealed day may replace the batch, but
        # the deletion seal removes only the deleted domain again.
        store.ingest_activity_daily_aggregates("pc-test", [{
            "aggregate_id": "aggregate-other-site-replay-0001",
            "local_day": "2026-08-03", "metrics": [{
                "kind": "usage", "key": "site:brave.exe:other-sites",
                "seconds": 999,
            }, {
                "kind": "other_site", "key": target, "seconds": 777,
            }, {
                "kind": "other_site", "key": kept, "seconds": 222,
            }],
        }], sid)
        with store.connect() as db:
            remaining = db.execute(
                "SELECT m.metric_kind,m.metric_key,m.seconds FROM "
                "activity_daily_aggregate_metrics AS m JOIN "
                "activity_daily_aggregate_batches AS b ON "
                "b.device_id=m.device_id AND b.aggregate_id=m.aggregate_id "
                "WHERE b.device_id=? AND b.usage_guard_username=? AND "
                "b.local_day=? ORDER BY m.metric_kind,m.metric_key",
                ("pc-test", "alice", "2026-08-03"),
            ).fetchall()
        self.assertEqual(
            [(row["metric_kind"], row["metric_key"], row["seconds"])
             for row in remaining],
            [
                ("other_site", kept, 222.0),
                ("usage", "site:brave.exe:other-sites", 999.0),
            ],
        )

    def test_remote_catalog_action_targets_every_pc_of_selected_person(self):
        store = self.server.store
        store.create_user(
            "admin", "personal-admin-password", must_change=False,
            role="admin", email="admin@example.test",
        )
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        store.register_device("pc-other", token="o" * 48)
        for device_id, sid in (
            ("pc-test", "S-1-5-21-100-200-300-1001"),
            ("pc-other", "S-1-5-21-400-500-600-1001"),
        ):
            store.set_device_windows_identities(device_id, [{
                "windows_sid": sid, "windows_username": "Alice",
                "usage_guard_username": "alice",
            }], "admin")
        _, login, headers = self.request(
            "/api/v1/auth/login", "POST", {
                "username": "admin", "password": "personal-admin-password",
            }, origin=PUBLIC_ORIGIN,
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        status, queued, _ = self.request(
            "/api/v1/catalogs/alice/actions", "POST", {
                "action": "delete_target", "target_key": "app:excluded",
                "idempotency_key": "catalog-operation-remote-1",
            }, origin=PUBLIC_ORIGIN, cookie=cookie,
            csrf=login["csrf_token"],
        )

        self.assertEqual(status, 202)
        self.assertEqual(
            {item["device_id"] for item in queued["deliveries"]},
            {"pc-test", "pc-other"},
        )
        for device_id, token in (
            ("pc-test", self.token), ("pc-other", "o" * 48),
        ):
            _, pending, _ = self.request(
                f"/api/v1/agent/commands?device_id={device_id}",
                agent=True, token=token,
            )
            self.assertEqual(pending["commands"][0]["action"], "delete_target")
            self.assertEqual(
                pending["commands"][0]["target_key"], "app:excluded",
            )

        status, scoped, _ = self.request(
            "/api/v1/catalogs/alice/actions", "POST", {
                "action": "rename_target", "target_key": "app:test",
                "label": "Portable seulement",
                "device_ids": ["pc-other"],
                "idempotency_key": "catalog-operation-remote-2",
            }, origin=PUBLIC_ORIGIN, cookie=cookie,
            csrf=login["csrf_token"],
        )
        self.assertEqual(status, 202)
        self.assertEqual(
            [item["device_id"] for item in scoped["deliveries"]],
            ["pc-other"],
        )

    def test_delete_target_is_scoped_sealed_and_keeps_offline_catalog_deleted(self):
        store = self.server.store
        store.create_user(
            "admin", "personal-admin-password", must_change=False,
            role="admin", email="admin@example.test",
        )
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        store.create_user(
            "bob", "temporary-strong", role="limited", device_ids=[],
        )
        store.register_device("pc-other", token="o" * 48)
        alice_test_sid = "S-1-5-21-100-200-300-1001"
        alice_other_sid = "S-1-5-21-400-500-600-1001"
        bob_other_sid = "S-1-5-21-700-800-900-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": alice_test_sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        store.set_device_windows_identities("pc-other", [{
            "windows_sid": alice_other_sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }, {
            "windows_sid": bob_other_sid, "windows_username": "Bob",
            "usage_guard_username": "bob",
        }], "admin")

        catalog_snapshot = {
            "category_order": ["Jeux"], "categories": ["Jeux"],
            "runtime": {"windows_identity": {
                "usage_guard_username": "alice",
                "windows_sid": alice_other_sid,
            }},
            "merge_candidates": [{
                "key": "app:deleted", "label": "Deleted",
                "category": "Jeux",
            }, {
                "key": "app:kept", "label": "Kept", "category": "Jeux",
            }],
        }
        store.save_snapshot("pc-test", catalog_snapshot)
        store.save_snapshot("pc-other", catalog_snapshot)
        store.save_user_policy("alice", {
            "enforcement_mode": "enforced", "limits": [{
                "key": "app:deleted", "target_key": "app:deleted",
                "limit_seconds": 300,
            }, {
                "key": "app:kept", "target_key": "app:kept",
                "limit_seconds": 600,
            }],
        }, "admin")

        def interval(identifier, target="app:deleted"):
            return {
                "interval_id": identifier, "target_key": target,
                "category_key": "Jeux", "category_keys": ["Jeux"],
                "started_at": "2026-08-03T08:00:00+00:00",
                "ended_at": "2026-08-03T08:01:00+00:00",
                "policy_revision": 1,
            }

        store.ingest_activity_intervals(
            "pc-test", alice_test_sid, [interval("alice-test-old-0001")],
        )
        store.ingest_activity_intervals(
            "pc-other", alice_other_sid,
            [interval("alice-other-old-0001"), interval(
                "alice-other-keep-0001", "app:kept",
            )],
        )
        store.ingest_activity_intervals(
            "pc-other", bob_other_sid, [interval("bob-other-old-000001")],
        )
        store.ingest_activity_timeline_sessions(
            "pc-other", alice_other_sid, [{
                "record_id": "timeline-delete-0001", "kind": "active",
                "id": "active:deleted", "key": "app:deleted",
                "label": "Deleted", "category": "Jeux",
                "category_lineage": ["Jeux"],
                "started_at": "2026-08-03T08:00:00+00:00",
                "ended_at": "2026-08-03T08:01:00+00:00",
            }],
        )
        store.replace_live_activity_intervals("pc-other", [{
            "live_id": "live-delete-0001", "windows_sid": alice_other_sid,
            "target_key": "app:deleted", "category_key": "Jeux",
            "category_keys": ["Jeux"],
            "started_at": "2026-08-03T08:00:00+00:00",
            "observed_at": "2026-08-03T08:01:00+00:00",
            "policy_revision": 1,
        }])
        for device_id, sid, suffix in (
            ("pc-test", alice_test_sid, "test"),
            ("pc-other", alice_other_sid, "other"),
        ):
            store.ingest_activity_daily_aggregates(device_id, [{
                "aggregate_id": f"aggregate-before-{suffix}-0001",
                "local_day": "2026-08-03", "metrics": [{
                    "kind": "usage", "key": "app:deleted", "seconds": 60,
                }, {
                    "kind": "usage", "key": "app:kept", "seconds": 30,
                }],
            }], sid)
        with store.connect() as db:
            db.execute(
                "INSERT INTO activity_daily_legacy(device_id,"
                "usage_guard_username,local_day,metric_kind,metric_key,seconds) "
                "VALUES(?,?,?,?,?,?)",
                (
                    "pc-other", "alice", "2026-08-02", "active",
                    "app:deleted", 45,
                ),
            )

        _, login, headers = self.request(
            "/api/v1/auth/login", "POST", {
                "username": "admin", "password": "personal-admin-password",
            }, origin=PUBLIC_ORIGIN,
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        request_payload = {
            "action": "delete_target", "target_key": "app:deleted",
            "device_ids": ["pc-other"],
            "idempotency_key": "delete-target-sealed-0001",
        }
        status, deleted, _ = self.request(
            "/api/v1/catalogs/alice/actions", "POST", request_payload,
            origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"],
        )

        self.assertEqual(status, 202)
        self.assertEqual(deleted["deletion"]["device_ids"], ["pc-other"])
        self.assertFalse(deleted["deletion"]["reused"])
        self.assertNotIn(
            "app:deleted", store.device_catalog("pc-other")["targets"],
        )
        self.assertIn(
            "app:deleted", store.device_catalog("pc-test")["targets"],
        )
        policy = store.user_policy("alice")["policy"]
        deleted_limit = next(
            item for item in policy["limits"]
            if item["key"] == "app:deleted"
        )
        self.assertEqual(deleted_limit["device_ids"], ["pc-test"])
        with store.connect() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_intervals WHERE device_id=? "
                "AND usage_guard_username=? AND target_key=?",
                ("pc-other", "alice", "app:deleted"),
            ).fetchone()[0], 0)
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_timeline_sessions WHERE "
                "device_id=? AND usage_guard_username=? AND target_key=?",
                ("pc-other", "alice", "app:deleted"),
            ).fetchone()[0], 0)
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_live_intervals WHERE "
                "device_id=? AND usage_guard_username=? AND target_key=?",
                ("pc-other", "alice", "app:deleted"),
            ).fetchone()[0], 0)
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_daily_legacy WHERE device_id=? "
                "AND usage_guard_username=? AND metric_key=?",
                ("pc-other", "alice", "app:deleted"),
            ).fetchone()[0], 0)
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_daily_aggregate_metrics AS m "
                "JOIN activity_daily_aggregate_batches AS b ON "
                "b.device_id=m.device_id AND b.aggregate_id=m.aggregate_id "
                "WHERE b.device_id=? AND b.usage_guard_username=? AND "
                "m.metric_kind='usage' AND m.metric_key=?",
                ("pc-other", "alice", "app:deleted"),
            ).fetchone()[0], 0)
            # Same target on another PC and another person is untouched.
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_intervals WHERE target_key=? "
                "AND ((device_id=? AND usage_guard_username=?) OR "
                "(device_id=? AND usage_guard_username=?))",
                (
                    "app:deleted", "pc-test", "alice",
                    "pc-other", "bob",
                ),
            ).fetchone()[0], 2)

        # A stale offline snapshot cannot restore the catalogue before the
        # device has acknowledged the retained delete command.
        store.save_snapshot("pc-other", catalog_snapshot)
        self.assertNotIn(
            "app:deleted", store.device_catalog("pc-other")["targets"],
        )

        # Old exact and daily corrections are accepted at transport level but
        # the deletion seal removes only the deleted metric.
        store.ingest_activity_intervals(
            "pc-other", alice_other_sid, [interval("stale-replay-old-0001")],
        )
        store.ingest_activity_daily_aggregates("pc-other", [{
            "aggregate_id": "aggregate-stale-correction-0001",
            "local_day": "2026-08-03", "metrics": [{
                "kind": "usage", "key": "app:deleted", "seconds": 999,
            }, {
                "kind": "usage", "key": "app:kept", "seconds": 222,
            }],
        }], alice_other_sid)
        with store.connect() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_intervals WHERE device_id=? "
                "AND usage_guard_username=? AND target_key=?",
                ("pc-other", "alice", "app:deleted"),
            ).fetchone()[0], 0)
            stale_metrics = db.execute(
                "SELECT m.metric_key,m.seconds FROM "
                "activity_daily_aggregate_metrics AS m JOIN "
                "activity_daily_aggregate_batches AS b ON "
                "b.device_id=m.device_id AND b.aggregate_id=m.aggregate_id "
                "WHERE b.device_id=? AND b.usage_guard_username=? AND "
                "b.local_day=? ORDER BY m.metric_key",
                ("pc-other", "alice", "2026-08-03"),
            ).fetchall()
        self.assertEqual(
            [(row["metric_key"], row["seconds"]) for row in stale_metrics],
            [("app:kept", 222.0)],
        )

        # Reusing the key with a wider PC scope is rejected before any new
        # command, seal or purge can be created.
        with store.connect() as db:
            command_count = db.execute(
                "SELECT COUNT(*) FROM commands"
            ).fetchone()[0]
        widened = {**request_payload, "device_ids": ["pc-test", "pc-other"]}
        with self.assertRaises(HTTPError) as conflict:
            self.request(
                "/api/v1/catalogs/alice/actions", "POST", widened,
                origin=PUBLIC_ORIGIN, cookie=cookie,
                csrf=login["csrf_token"],
            )
        self.assertEqual(conflict.exception.code, 409)
        with store.connect() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM commands"
            ).fetchone()[0], command_count)
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_target_deletion_seals WHERE "
                "device_id=? AND usage_guard_username=? AND target_key=?",
                ("pc-test", "alice", "app:deleted"),
            ).fetchone()[0], 0)
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_intervals WHERE device_id=? "
                "AND usage_guard_username=? AND target_key=?",
                ("pc-test", "alice", "app:deleted"),
            ).fetchone()[0], 1)

        # An explicit empty correction still clears the whole old day batch.
        store.ingest_activity_daily_aggregates("pc-other", [{
            "aggregate_id": "aggregate-empty-correction-0001",
            "local_day": "2026-08-03", "metrics": [],
        }], alice_other_sid)
        with store.connect() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_daily_aggregate_metrics AS m "
                "JOIN activity_daily_aggregate_batches AS b ON "
                "b.device_id=m.device_id AND b.aggregate_id=m.aggregate_id "
                "WHERE b.device_id=? AND b.usage_guard_username=? AND "
                "b.local_day=?",
                ("pc-other", "alice", "2026-08-03"),
            ).fetchone()[0], 0)
            sealed_day = db.execute(
                "SELECT sealed_through_day FROM "
                "activity_target_deletion_seals WHERE device_id=? AND "
                "usage_guard_username=? AND target_key=?",
                ("pc-other", "alice", "app:deleted"),
            ).fetchone()[0]
        later_day = (
            datetime.fromisoformat(sealed_day) + timedelta(days=1)
        ).date().isoformat()
        store.ingest_activity_daily_aggregates("pc-other", [{
            "aggregate_id": "aggregate-after-seal-0001",
            "local_day": later_day, "metrics": [{
                "kind": "usage", "key": "app:deleted", "seconds": 12,
            }],
        }], alice_other_sid)
        with store.connect() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_daily_aggregate_metrics AS m "
                "JOIN activity_daily_aggregate_batches AS b ON "
                "b.device_id=m.device_id AND b.aggregate_id=m.aggregate_id "
                "WHERE b.device_id=? AND b.usage_guard_username=? AND "
                "b.local_day=? AND m.metric_key=?",
                ("pc-other", "alice", later_day, "app:deleted"),
            ).fetchone()[0], 1)

        cutoff = datetime.fromisoformat(deleted["deletion"]["cutoff_at"])
        future_start = cutoff + timedelta(seconds=1)
        future_end = cutoff + timedelta(seconds=11)
        future = interval("future-after-delete-0001")
        future["started_at"] = future_start.isoformat(timespec="milliseconds")
        future["ended_at"] = future_end.isoformat(timespec="milliseconds")
        store.ingest_activity_intervals(
            "pc-other", alice_other_sid, [future],
        )
        _, replayed, _ = self.request(
            "/api/v1/catalogs/alice/actions", "POST", request_payload,
            origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"],
        )
        self.assertTrue(replayed["deletion"]["reused"])
        self.assertEqual(
            replayed["deletion"]["cutoff_at"],
            deleted["deletion"]["cutoff_at"],
        )
        with store.connect() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_intervals WHERE device_id=? "
                "AND usage_guard_username=? AND target_key=?",
                ("pc-other", "alice", "app:deleted"),
            ).fetchone()[0], 1)

        # ACK alone cannot release the catalogue seal: a target-present
        # snapshot may already have been in flight when the deletion ran.
        command_id = int(deleted["deliveries"][0]["command_id"])
        self.assertTrue(store.acknowledge(
            "pc-other", command_id, {"ok": True},
        ))
        store.save_snapshot("pc-other", catalog_snapshot)
        self.assertNotIn(
            "app:deleted", store.device_catalog("pc-other")["targets"],
        )
        with store.connect() as db:
            self.assertEqual(db.execute(
                "SELECT catalog_sealed FROM activity_target_deletion_seals "
                "WHERE device_id=? AND usage_guard_username=? AND target_key=?",
                ("pc-other", "alice", "app:deleted"),
            ).fetchone()[0], 1)

        # Only a fresh rich snapshot from the correct identity confirming the
        # target absent opens the seal. A subsequent real rediscovery is new
        # catalogue state and may recreate the entry.
        confirmed_absent = copy.deepcopy(catalog_snapshot)
        confirmed_absent["merge_candidates"] = [
            item for item in confirmed_absent["merge_candidates"]
            if item["key"] != "app:deleted"
        ]
        store.save_snapshot("pc-other", confirmed_absent)
        with store.connect() as db:
            self.assertEqual(db.execute(
                "SELECT catalog_sealed FROM activity_target_deletion_seals "
                "WHERE device_id=? AND usage_guard_username=? AND target_key=?",
                ("pc-other", "alice", "app:deleted"),
            ).fetchone()[0], 0)
        store.save_snapshot("pc-other", catalog_snapshot)
        self.assertIn(
            "app:deleted", store.device_catalog("pc-other")["targets"],
        )
        self.assertTrue(any(
            item.get("key") == "app:deleted"
            for item in store.snapshot("pc-other")["merge_candidates"]
        ))
        with store.connect() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_intervals WHERE device_id=? "
                "AND usage_guard_username=? AND target_key=?",
                ("pc-other", "alice", "app:deleted"),
            ).fetchone()[0], 1)

    def test_catalog_bootstrap_uses_richest_order_and_queues_identical_union(self):
        store = self.server.store
        store.create_user(
            "admin", "personal-admin-password", must_change=False,
            role="admin", email="admin@example.test",
        )
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        store.register_device("pc-other", token="o" * 48)
        for device_id, sid in (
            ("pc-test", "S-1-5-21-100-200-300-1001"),
            ("pc-other", "S-1-5-21-400-500-600-1001"),
        ):
            store.set_device_windows_identities(device_id, [{
                "windows_sid": sid, "windows_username": "Alice",
                "usage_guard_username": "alice",
            }], "admin")
        sparse = {
            "targets": {"app:sparse": {"label": "Sparse", "category": "Jeux"}},
            "category_order": ["Jeux"], "category_parents": {},
        }
        rich = {
            "targets": {
                "app:chat": {"label": "Chat", "category": "Travail"},
                "app:code": {"label": "Code", "category": "Programmation"},
            },
            "category_order": ["Travail", "Programmation"],
            "category_parents": {},
            "target_order": ["app:chat", "app:code"],
            "dismissed_targets": {"app:chat": "awaiting_launch"},
        }
        store.save_activity_store("pc-test", sparse)
        store.save_activity_store("pc-other", rich)
        _, login, headers = self.request(
            "/api/v1/auth/login", "POST", {
                "username": "admin", "password": "personal-admin-password",
            }, origin=PUBLIC_ORIGIN,
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        status, result, _ = self.request(
            "/api/v1/catalogs/alice/bootstrap", "POST", {
                "idempotency_key": "catalog-bootstrap-test-1",
            }, origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"],
        )

        self.assertEqual(status, 202)
        self.assertEqual(result["canonical_device_id"], "pc-other")
        commands = {
            device_id: store.pending(device_id)[0]
            for device_id in ("pc-test", "pc-other")
        }
        self.assertEqual(commands["pc-test"]["action"], "replace_catalog")
        self.assertEqual(
            commands["pc-test"]["catalog"], commands["pc-other"]["catalog"],
        )
        catalog = commands["pc-test"]["catalog"]
        self.assertEqual(
            catalog["category_order"], ["Travail", "Programmation", "Jeux"],
        )
        self.assertEqual(
            set(catalog["targets"]), {"app:chat", "app:code", "app:sparse"},
        )
        self.assertEqual(
            catalog["dismissed_targets"], {"app:chat": "awaiting_launch"},
        )
        repeated_status, repeated, _ = self.request(
            "/api/v1/catalogs/alice/bootstrap", "POST", {
                "idempotency_key": "catalog-bootstrap-test-1",
            }, origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"],
        )
        self.assertEqual(repeated_status, 202)
        self.assertTrue(all(item["reused"] for item in repeated["deliveries"]))

    def test_catalog_bootstrap_score_prefers_more_complete_orders_on_equal_categories(self):
        base = Store._catalog_document({
            "targets": {
                "app:chat": {"label": "Chat", "category": "Travail"},
                "app:code": {"label": "Code", "category": "Programmation"},
            },
            "category_order": ["Travail", "Programmation"],
        })
        richer = copy.deepcopy(base)
        richer["target_order"] = ["app:code", "app:chat"]
        richer["category_parents"] = {"Programmation": "Travail"}
        richer["site_categories"] = ["Documentation"]

        canonical_device_id, merged = Store._merge_catalog_documents([
            ("pc-compact", base), ("pc-rich", richer),
        ])

        self.assertEqual(canonical_device_id, "pc-rich")
        self.assertEqual(merged["target_order"], ["app:code", "app:chat"])
        self.assertEqual(merged["category_parents"], {"Programmation": "Travail"})

        conflicting = copy.deepcopy(richer)
        conflicting["targets"]["site:brave.exe:youtube.com"] = {
            "label": "youtube.com", "category": "Brave",
        }
        preferred = Store._catalog_document({
            "targets": {"site:brave.exe:youtube.com": {
                "label": "youtube.com", "category": "Divertissement",
            }},
            "category_parents": {"Divertissement": ""},
        })
        preferred_device_id, preferred_merge = Store._merge_catalog_documents(
            [("pc-richer", conflicting), ("pc-preferred", preferred)],
            preferred_categories={"Divertissement"},
        )
        self.assertEqual(preferred_device_id, "pc-preferred")
        self.assertEqual(
            preferred_merge["targets"]["site:brave.exe:youtube.com"]["category"],
            "Divertissement",
        )

    def test_equal_catalog_scores_prefer_freshest_device_and_expose_it(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.register_device("pc-a-old", token="a" * 48)
        store.register_device("pc-z-new", token="z" * 48)
        store.create_user(
            "alice", "temporary-strong", role="limited",
            device_ids=["pc-a-old", "pc-z-new"],
        )
        store.save_snapshot("pc-a-old", {
            "targets": {"app:chatgpt": {
                "label": "ChatGPT", "category": "Ancien classement",
            }},
            "category_order": ["Ancien classement"],
        })
        store.save_snapshot("pc-z-new", {
            "targets": {"app:chatgpt": {
                "label": "ChatGPT", "category": "Programmation+ChatGPT",
            }},
            "category_order": ["Programmation+ChatGPT"],
        })
        with store.connect() as db:
            db.execute(
                "UPDATE device_catalogs SET updated_at=? WHERE device_id=?",
                ("2026-08-20T10:00:00+00:00", "pc-a-old"),
            )
            db.execute(
                "UPDATE device_catalogs SET updated_at=? WHERE device_id=?",
                ("2026-09-03T10:00:00+00:00", "pc-z-new"),
            )

        # A later activity-only snapshot must not make an unchanged, stale
        # catalogue look newer than the catalogue that was actually edited.
        store.save_snapshot("pc-a-old", {
            "targets": {"app:chatgpt": {
                "label": "ChatGPT", "category": "Ancien classement",
            }},
            "category_order": ["Ancien classement"],
            "usage": [{"key": "app:chatgpt", "seconds": 120}],
        })
        with store.connect() as db:
            old_catalog_updated_at = db.execute(
                "SELECT updated_at FROM device_catalogs WHERE device_id=?",
                ("pc-a-old",),
            ).fetchone()["updated_at"]

        canonical_device_id, catalog = store._user_canonical_catalog("alice")
        users = store.accessible_policy_users("admin", is_admin=True)
        alice = next(item for item in users if item["username"] == "alice")

        self.assertEqual(old_catalog_updated_at, "2026-08-20T10:00:00+00:00")
        self.assertEqual(canonical_device_id, "pc-z-new")
        self.assertEqual(alice["catalog_device_id"], "pc-z-new")
        self.assertEqual(
            catalog["targets"]["app:chatgpt"]["category"],
            "Programmation+ChatGPT",
        )

    def test_category_policy_reconciles_the_canonical_catalog_before_application(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        store.register_device("pc-other", token="o" * 48)
        for device_id, sid in (
            ("pc-test", "S-1-5-21-100-200-300-1001"),
            ("pc-other", "S-1-5-21-400-500-600-1001"),
        ):
            store.set_device_windows_identities(device_id, [{
                "windows_sid": sid, "windows_username": "Alice",
                "usage_guard_username": "alice",
            }], "admin")
        youtube = "site:brave.exe:youtube.com"
        store.save_activity_store("pc-test", {
            "targets": {youtube: {
                "label": "youtube.com", "category": "Divertissement",
            }},
            "category_order": ["Divertissement"],
            "category_parents": {"Divertissement": ""},
        })
        store.save_activity_store("pc-other", {
            "targets": {youtube: {
                "label": "youtube.com", "category": "Brave",
            }},
        })

        operation = store.begin_user_policy_operation(
            "alice", {
                "action": "set_limit",
                "target_key": "category:Divertissement",
                "settings": {
                    "target_key": "category:Divertissement",
                    "limit_seconds": 3 * 60 * 60,
                },
            }, "admin", idempotency_key="policy-catalog-sync-test-1",
        )

        self.assertEqual(operation["target_revision"], 1)
        self.assertEqual(
            operation["catalog_sync"]["canonical_device_id"], "pc-test",
        )
        self.assertEqual(
            [item["device_id"] for item in operation["catalog_sync"]["deliveries"]],
            ["pc-other"],
        )
        self.assertEqual(operation["catalog_sync"]["unresolved_categories"], [])
        command = store.pending("pc-other")[0]
        self.assertEqual(command["action"], "replace_catalog")
        self.assertEqual(
            command["catalog"]["targets"][youtube]["category"],
            "Divertissement",
        )

        # Catalogue commands use the protected service's deferred-ack
        # handshake and therefore have to be redelivered after the retry
        # window, just like limit commands.
        with store.connect() as db:
            db.execute(
                "UPDATE commands SET delivered_at=? WHERE id=?",
                ((datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat(
                    timespec="seconds"
                ), command["id"]),
            )
        self.assertEqual(store.pending("pc-other")[0]["id"], command["id"])

    def test_personal_limit_scope_is_filtered_for_each_selected_pc(self):
        store = self.server.store
        store.create_user(
            "admin", "personal-admin-password", must_change=False,
            role="admin", email="admin@example.test",
        )
        store.create_user(
            "alice", "personal-alice-password", must_change=False,
            role="limited", device_ids=[], email="alice@example.test",
        )
        store.register_device("pc-other", token="o" * 48)
        sid_one = "S-1-5-21-100-200-300-1001"
        sid_two = "S-1-5-21-400-500-600-1001"
        for device_id, sid in (("pc-test", sid_one), ("pc-other", sid_two)):
            store.set_device_windows_identities(device_id, [{
                "windows_sid": sid, "windows_username": "Alice",
                "usage_guard_username": "alice",
            }], "admin")
        _, login, headers = self.request(
            "/api/v1/auth/login", "POST", {
                "username": "admin", "password": "personal-admin-password",
            }, origin=PUBLIC_ORIGIN,
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        status, saved, _ = self.request(
            "/api/v1/policies/alice/actions", "POST", {
                "action": "set_limit", "base_device_id": "pc-test",
                "device_ids": ["pc-test"],
                "idempotency_key": "person-device-scope-1",
                "target_key": "app:test",
                "settings": {
                    "create_new": True, "target_key": "app:test",
                    "limit_seconds": 300,
                },
            }, origin=PUBLIC_ORIGIN, cookie=cookie,
            csrf=login["csrf_token"],
        )

        self.assertEqual(status, 202)
        self.assertEqual(
            saved["policy"]["policy"]["limits"][0]["device_ids"],
            ["pc-test"],
        )
        self.assertEqual(
            len(store.policy_for_windows_sid("pc-test", sid_one)["policy"]["limits"]),
            1,
        )
        self.assertEqual(
            store.policy_for_windows_sid("pc-other", sid_two)["policy"]["limits"],
            [],
        )
        with self.assertRaises(ValueError):
            store.selected_user_device_ids("alice", ["pc-unknown"])

    def test_policy_user_list_only_exposes_accessible_limited_people(self):
        store = self.server.store
        store.register_device("pc-other", token="o" * 48)
        store.create_user(
            "admin", "personal-admin-password", must_change=False,
            role="admin", email="admin@example.test",
        )
        store.create_user(
            "alice", "personal-alice-password", must_change=False,
            role="limited", device_ids=["pc-test"],
            email="alice@example.test",
        )
        store.create_user(
            "bob", "personal-bob-password", must_change=False,
            role="limited", device_ids=["pc-other"],
            email="bob@example.test",
        )
        store.create_user(
            "viewer", "personal-viewer-password", must_change=False,
            role="user", device_ids=["pc-test"],
            email="viewer@example.test",
        )
        store.save_user_policy("alice", {"limits": []}, "viewer")
        store.save_user_policy("bob", {"limits": []}, "admin")
        _, login, headers = self.request(
            "/api/v1/auth/login", "POST", {
                "username": "viewer", "password": "personal-viewer-password",
            }, origin=PUBLIC_ORIGIN,
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        status, payload, _ = self.request(
            "/api/v1/policies", cookie=cookie,
        )

        self.assertEqual(status, 200)
        self.assertEqual(
            [item["username"] for item in payload["users"]], ["alice"],
        )
        self.assertEqual(payload["users"][0]["revision"], 1)
        self.assertNotIn("email", payload["users"][0])

    def test_multi_device_intervals_are_idempotent_and_counted_by_union(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        store.register_device("pc-other", token="o" * 48)
        sid_one = "S-1-5-21-100-200-300-1001"
        sid_two = "S-1-5-21-400-500-600-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid_one, "windows_domain": "FAMILLE",
            "windows_username": "Alice", "usage_guard_username": "alice",
        }], "admin")
        store.set_device_windows_identities("pc-other", [{
            "windows_sid": sid_two, "windows_domain": "PORTABLE",
            "windows_username": "Alice", "usage_guard_username": "alice",
        }], "admin")
        first = [{
            "interval_id": "interval-pc1-0001",
            "target_key": "category:Internet",
            "category_key": "Programmation",
            "category_keys": ["Programmation", "Internet"],
            "started_at": "2026-08-24T07:00:00+02:00",
            "ended_at": "2026-08-24T10:00:00+02:00",
            "policy_revision": 1,
        }]
        second = [{
            "interval_id": "interval-pc2-0001",
            "target_key": "category:Internet",
            "category_key": "Programmation",
            "category_keys": ["Programmation", "Internet"],
            "started_at": "2026-08-24T09:00:00+02:00",
            "ended_at": "2026-08-24T12:00:00+02:00",
            "policy_revision": 1,
        }]

        accepted = store.ingest_activity_intervals(
            "pc-test", sid_one, first,
        )
        duplicate = store.ingest_activity_intervals(
            "pc-test", sid_one, first,
        )
        store.ingest_activity_intervals("pc-other", sid_two, second)

        self.assertEqual(accepted["accepted"], 1)
        self.assertEqual(duplicate["duplicates"], 1)
        self.assertEqual(store.user_usage_union(
            "alice", "2026-08-24T00:00:00+02:00",
            "2026-08-25T00:00:00+02:00",
            target_key="category:Internet",
        ), 5 * 60 * 60)
        self.assertEqual(store.user_usage_union(
            "alice", "2026-08-24T00:00:00+02:00",
            "2026-08-25T00:00:00+02:00",
            category_key="Internet",
        ), 5 * 60 * 60)
        store.replace_live_activity_intervals("pc-test", [{
            "live_id": "live-pc1-0001", "windows_sid": sid_one,
            "target_key": "app:editor", "category_key": "Programmation",
            "category_keys": ["Programmation", "Internet"],
            "started_at": "2026-08-24T11:00:00+02:00",
            "observed_at": "2026-08-24T13:00:00+02:00",
            "policy_revision": 1,
        }])
        store.replace_live_activity_intervals("pc-other", [{
            "live_id": "live-pc2-0001", "windows_sid": sid_two,
            "target_key": "app:browser", "category_key": "Internet",
            "category_keys": ["Internet"],
            "started_at": "2026-08-24T11:30:00+02:00",
            "observed_at": "2026-08-24T14:00:00+02:00",
            "policy_revision": 1,
        }])
        self.assertEqual(store.user_usage_union(
            "alice", "2026-08-24T00:00:00+02:00",
            "2026-08-25T00:00:00+02:00", category_key="Internet",
        ), 7 * 60 * 60)
        store.replace_live_activity_intervals("pc-other", [])
        self.assertEqual(store.user_usage_union(
            "alice", "2026-08-24T00:00:00+02:00",
            "2026-08-25T00:00:00+02:00", category_key="Internet",
        ), 6 * 60 * 60)
        breakdown = store.user_usage_breakdown(
            "alice", "2026-08-24T00:00:00+02:00",
            "2026-08-25T00:00:00+02:00",
        )
        self.assertEqual(breakdown["seconds"], 6 * 60 * 60)
        self.assertEqual(
            {item["key"]: item["seconds"] for item in breakdown["categories"]}[
                "Internet"
            ],
            6 * 60 * 60,
        )
        scoped_breakdown = store.user_usage_breakdown(
            "alice", "2026-08-24T00:00:00+02:00",
            "2026-08-25T00:00:00+02:00", device_ids=["pc-test"],
        )
        self.assertEqual(scoped_breakdown["seconds"], 5 * 60 * 60)
        self.assertEqual(store.user_usage_union(
            "alice", "2026-08-24T00:00:00+02:00",
            "2026-08-25T00:00:00+02:00", category_key="Internet",
            device_ids=["pc-test"],
        ), 5 * 60 * 60)
        changed = [{**first[0], "ended_at": "2026-08-24T11:00:00+02:00"}]
        with self.assertRaises(IdempotencyConflict):
            store.ingest_activity_intervals("pc-test", sid_one, changed)

    def test_timeline_batches_are_idempotent_without_consuming_a_quota(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        sessions = [{
            "record_id": "timeline-program-0001", "kind": "program",
            "id": "program:kona", "key": "app:kona", "label": "Kona",
            "category": "Jeux", "category_lineage": ["Jeux"],
            "started_at": "2026-08-28T22:00:00+02:00",
            "ended_at": "2026-08-29T01:00:00+02:00",
            "windows_session_id": 4, "source": "monitor",
        }, {
            "record_id": "timeline-media-0001", "kind": "multimedia",
            "id": "multimedia:potplayer", "key": "PotPlayer",
            "label": "PotPlayer", "started_at": "2026-08-28T23:00:00+02:00",
            "ended_at": "2026-08-28T23:30:00+02:00",
            "windows_session_id": 4, "source": "media_session",
        }, {
            "record_id": "timeline-windows-0001", "kind": "windows_session",
            "id": "windows:4", "key": "computer:session",
            "label": "Session Windows",
            "started_at": "2026-08-28T21:55:00+02:00",
            "ended_at": "2026-08-29T01:05:00+02:00",
            "windows_session_id": 4, "source": "shutdown",
        }, {
            "record_id": "timeline-system-0001", "kind": "system_event",
            "id": "system:sleep", "key": "computer:event", "label": "sleep",
            "started_at": "2026-08-28T23:45:00+02:00",
            "ended_at": "2026-08-28T23:45:00.001000+02:00",
            "windows_session_id": 4, "source": "power",
        }]

        accepted = store.ingest_activity_timeline_sessions(
            "pc-test", sid, sessions,
        )
        duplicate = store.ingest_activity_timeline_sessions(
            "pc-test", sid, sessions,
        )
        timeline, truncated = store.device_activity_sessions(
            "pc-test", username="alice",
        )

        self.assertEqual(accepted["accepted"], 4)
        self.assertEqual(duplicate["duplicates"], 4)
        self.assertFalse(truncated)
        self.assertEqual(
            [item["kind"] for item in timeline],
            ["windows_session", "program", "multimedia", "system_event"],
        )
        analysis = snapshot_with_interval_history(
            {"sessions": [], "windows_sessions": [], "system_events": []},
            timeline, timezone_name="Europe/Paris",
        )
        self.assertEqual(
            [item["kind"] for item in analysis["sessions"]],
            ["program", "multimedia"],
        )
        self.assertEqual(len(analysis["windows_sessions"]), 1)
        self.assertEqual(analysis["system_events"][0]["type"], "sleep")
        self.assertEqual(store.user_usage_union(
            "alice", "2026-08-28T00:00:00+02:00",
            "2026-08-30T00:00:00+02:00",
        ), 0)
        changed = [{**sessions[0], "label": "Kona modifié"}]
        with self.assertRaises(IdempotencyConflict):
            store.ingest_activity_timeline_sessions("pc-test", sid, changed)

    def test_other_sites_sentinel_is_usage_only_for_old_incremental_agents(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        sentinel = "site:brave.exe:other-sites"
        near_miss = "site:brave.exe:news:other-sites"
        common = {
            "kind": "active", "category": "Navigation Internet",
            "category_lineage": ["Navigation Internet"],
            "started_at": "2026-08-29T08:00:00+02:00",
            "ended_at": "2026-08-29T08:10:00+02:00",
            "windows_session_id": 4, "source": "extension",
        }

        result = store.ingest_activity_timeline_sessions(
            "pc-test", sid, [{
                **common, "record_id": "timeline-other-sites-old-0001",
                "id": "active:other-sites", "key": sentinel,
                "label": "Autres sites",
            }, {
                **common, "record_id": "timeline-other-sites-near-0001",
                "id": "active:near", "key": near_miss,
                "label": "news:other-sites",
            }],
        )
        store.ingest_activity_intervals("pc-test", sid, [{
            "interval_id": "activity-other-sites-old-0001",
            "target_key": sentinel,
            "category_key": "Navigation Internet",
            "category_keys": ["Navigation Internet"],
            "started_at": common["started_at"],
            "ended_at": common["ended_at"], "policy_revision": 3,
        }])
        store.ingest_activity_daily_aggregates("pc-test", [{
            "aggregate_id": "daily-other-sites-old-0001",
            "local_day": "2026-08-29", "metrics": [{
                "kind": "usage", "key": sentinel, "seconds": 600,
            }],
        }], sid)

        timeline, truncated = store.device_activity_sessions(
            "pc-test", username="alice",
        )
        history, metadata = store.device_activity_history_page(
            "pc-test", username="alice",
        )
        self.assertEqual(
            (result["accepted"], result["ignored_usage_only"]), (1, 1),
        )
        self.assertFalse(truncated)
        self.assertEqual([item["key"] for item in timeline], [near_miss])
        self.assertEqual([item["key"] for item in history], [near_miss])
        self.assertFalse(metadata["has_more"])
        self.assertEqual(store.user_usage_union(
            "alice", "2026-08-29T00:00:00+02:00",
            "2026-08-30T00:00:00+02:00", target_key=sentinel,
        ), 600)
        with store.connect() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_timeline_sessions WHERE "
                "target_key=?", (sentinel,),
            ).fetchone()[0], 0)
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_intervals WHERE target_key=?",
                (sentinel,),
            ).fetchone()[0], 1)
            self.assertEqual(db.execute(
                "SELECT seconds FROM activity_daily_aggregate_metrics "
                "WHERE metric_kind='usage' AND metric_key=?", (sentinel,),
            ).fetchone()[0], 600)

    def test_old_snapshot_and_activity_store_keep_usage_without_sentinel_timeline(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        sentinel = "site:brave.exe:other-sites"
        snapshot_session = {
            "kind": "active", "id": "active:snapshot-other-sites",
            "key": sentinel, "label": "Autres sites", "windows_sid": sid,
            "windows_identity_mapped": True,
            "started_at": "2026-08-29T08:00:00+02:00",
            "ended_at": "2026-08-29T08:01:00+02:00",
        }
        snapshot = {
            "runtime": {"windows_identity": {
                "windows_sid": sid, "usage_guard_username": "alice",
            }},
            "days": {"2026-08-29": {sentinel: 60}},
            "sessions": [snapshot_session],
            "analysis": {"sessions": [copy.deepcopy(snapshot_session)]},
        }
        store.save_snapshot("pc-test", snapshot)
        with store.connect() as db:
            snapshot_interval_id = db.execute(
                "SELECT interval_id FROM activity_intervals WHERE "
                "interval_id GLOB 'snapshot-activity-*' AND target_key=?",
                (sentinel,),
            ).fetchone()[0]
        store.ingest_activity_intervals("pc-test", sid, [{
            "interval_id": "activity-other-sites-from-snapshot-0001",
            "target_key": sentinel, "category_key": "", "category_keys": [],
            "started_at": snapshot_session["started_at"],
            "ended_at": snapshot_session["ended_at"], "policy_revision": 0,
        }])

        legacy_session = {
            **snapshot_session, "id": "active:legacy-other-sites",
            "started_at": "2026-08-29T08:01:00+02:00",
            "ended_at": "2026-08-29T08:02:00+02:00",
        }
        store.save_activity_store("pc-test", {
            "days": {"2026-08-29": {sentinel: 120}},
            "sessions": [legacy_session],
            "open_sessions": {"active": {
                **legacy_session, "ended_at": None,
            }},
        })

        compact = store.snapshot("pc-test")
        fallback = store.activity_store("pc-test")["activity"]
        timeline, truncated = store.device_activity_sessions(
            "pc-test", username="alice",
        )
        self.assertEqual(compact["sessions"], [])
        self.assertEqual(compact["analysis"]["sessions"], [])
        self.assertEqual(compact["days"]["2026-08-29"][sentinel], 60)
        self.assertEqual(fallback["sessions"], [])
        self.assertEqual(fallback["open_sessions"], {})
        self.assertEqual(fallback["days"]["2026-08-29"][sentinel], 120)
        self.assertFalse(truncated)
        self.assertEqual(timeline, [])
        self.assertEqual(store.user_usage_union(
            "alice", "2026-08-29T00:00:00+02:00",
            "2026-08-30T00:00:00+02:00", target_key=sentinel,
        ), 120)
        with store.connect() as db:
            interval_ids = {row[0] for row in db.execute(
                "SELECT interval_id FROM activity_intervals WHERE target_key=?",
                (sentinel,),
            ).fetchall()}
            self.assertNotIn(snapshot_interval_id, interval_ids)
            self.assertIn(
                "activity-other-sites-from-snapshot-0001", interval_ids,
            )
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_intervals WHERE target_key=?",
                (sentinel,),
            ).fetchone()[0], 2)
            self.assertGreater(db.execute(
                "SELECT COUNT(*) FROM activity_daily_legacy WHERE "
                "metric_kind='active' AND metric_key=?", (sentinel,),
            ).fetchone()[0], 0)

    def test_startup_purge_is_exact_and_removes_only_exact_snapshot_duplicates(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        sentinel = "site:brave.exe:other-sites"
        near_miss = "site:brave.exe:news:other-sites"
        exact_session = {
            "kind": "active", "id": "active:other-sites", "key": sentinel,
            "label": "Autres sites", "windows_sid": sid,
            "started_at": "2026-08-29T07:00:00+02:00",
            "ended_at": "2026-08-29T07:01:00+02:00",
        }
        near_session = {
            **exact_session, "id": "active:near", "key": near_miss,
            "label": "news:other-sites",
            "started_at": "2026-08-29T07:01:00+02:00",
            "ended_at": "2026-08-29T07:02:00+02:00",
        }
        snapshot_payload = {
            "days": {"2026-08-29": {sentinel: 60, near_miss: 60}},
            "sessions": [exact_session, near_session],
            "open_sessions": {
                "exact": {**exact_session, "ended_at": None},
                "near": {**near_session, "ended_at": None},
            },
            "analysis": {"sessions": [copy.deepcopy(exact_session)]},
        }
        activity_payload = {
            "days": {"2026-08-29": {sentinel: 120, near_miss: 60}},
            "sessions": [{
                **exact_session,
                "started_at": "2026-08-29T07:02:00+02:00",
                "ended_at": "2026-08-29T07:03:00+02:00",
            }, near_session],
            "open_sessions": {
                "exact": {**exact_session, "ended_at": None},
                "near": {**near_session, "ended_at": None},
            },
        }
        store.ingest_activity_daily_aggregates("pc-test", [{
            "aggregate_id": "daily-other-sites-startup-0001",
            "local_day": "2026-08-29", "metrics": [{
                "kind": "usage", "key": sentinel, "seconds": 321,
            }],
        }], sid)
        updated_at = "2026-08-30T08:00:00+00:00"
        received_at = "2026-08-30T08:05:00+00:00"
        with store.connect() as db:
            for table, payload in (
                ("snapshots", snapshot_payload),
                ("activity_stores", activity_payload),
            ):
                db.execute(
                    f"INSERT OR REPLACE INTO {table}(device_id,payload,updated_at) "
                    "VALUES(?,?,?)",
                    (
                        "pc-test", json.dumps(
                            payload, ensure_ascii=False, separators=(",", ":"),
                        ), updated_at,
                    ),
                )
            db.executemany(
                "INSERT INTO activity_timeline_sessions(device_id,record_id,"
                "windows_sid,usage_guard_username,session_kind,session_id,"
                "target_key,label,category_key,category_lineage,started_at,"
                "ended_at,windows_session_id,started_before_tracking,source,"
                "received_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        "pc-test", "legacy-exact-other-sites", sid, "alice",
                        "active", "active:other-sites", sentinel,
                        "Autres sites", "Navigation Internet", "[]",
                        "2026-08-29T07:00:00.000+02:00",
                        "2026-08-29T07:01:00.000+02:00", "4", 0,
                        "legacy", received_at,
                    ),
                    (
                        "pc-test", "legacy-near-other-sites", sid, "alice",
                        "active", "active:near", near_miss,
                        "news:other-sites", "Navigation Internet", "[]",
                        "2026-08-29T07:01:00.000+02:00",
                        "2026-08-29T07:02:00.000+02:00", "4", 0,
                        "legacy", received_at,
                    ),
                ],
            )
            interval_rows = [
                (
                    "activity-duplicate-exact-0001", "app:duplicate",
                    "Programmation", "2026-08-29T10:00:00.000+02:00",
                    "2026-08-29T10:05:00.000+02:00", 7,
                ),
                (
                    "snapshot-activity-duplicate-exact-0001", "app:duplicate",
                    "Programmation", "2026-08-29T10:00:00.000+02:00",
                    "2026-08-29T10:05:00.000+02:00", 7,
                ),
                (
                    "activity-duplicate-time-0001", "app:time-near",
                    "Programmation", "2026-08-29T10:05:00.000+02:00",
                    "2026-08-29T10:10:00.000+02:00", 7,
                ),
                (
                    "snapshot-activity-duplicate-time-0001", "app:time-near",
                    "Programmation", "2026-08-29T10:05:00.000+02:00",
                    "2026-08-29T10:10:00.001+02:00", 7,
                ),
                (
                    "activity-duplicate-category-0001", "app:category-near",
                    "Programmation", "2026-08-29T10:10:00.000+02:00",
                    "2026-08-29T10:15:00.000+02:00", 7,
                ),
                (
                    "snapshot-activity-duplicate-category-0001",
                    "app:category-near", "Programmation",
                    "2026-08-29T10:10:00.000+02:00",
                    "2026-08-29T10:15:00.000+02:00", 7,
                ),
                (
                    "legacy-activity-other-sites-0001", sentinel,
                    "Navigation Internet", "2026-08-29T07:03:00.000+02:00",
                    "2026-08-29T07:04:00.000+02:00", 2,
                ),
            ]
            db.executemany(
                "INSERT INTO activity_intervals(device_id,interval_id,"
                "windows_sid,usage_guard_username,target_key,category_key,"
                "started_at,ended_at,policy_revision,received_at) "
                "VALUES('pc-test',?,?,?,?,?,?,?,?,?)",
                [
                    (
                        interval_id, sid, "alice", target_key, category_key,
                        started_at, ended_at, revision, received_at,
                    )
                    for (
                        interval_id, target_key, category_key, started_at,
                        ended_at, revision,
                    ) in interval_rows
                ],
            )
            category_rows = []
            for interval_id, *_rest in interval_rows:
                category_rows.append(("pc-test", interval_id, "Programmation"))
            category_rows.extend([
                ("pc-test", "activity-duplicate-exact-0001", "Travail"),
                (
                    "pc-test", "snapshot-activity-duplicate-exact-0001",
                    "Travail",
                ),
                ("pc-test", "activity-duplicate-category-0001", "Travail"),
            ])
            db.executemany(
                "INSERT INTO activity_interval_categories(device_id,"
                "interval_id,category_key) VALUES(?,?,?)", category_rows,
            )

        restarted = Store(store.path)

        with restarted.connect() as db:
            timeline_keys = [row[0] for row in db.execute(
                "SELECT target_key FROM activity_timeline_sessions",
            ).fetchall()]
            interval_ids = {row[0] for row in db.execute(
                "SELECT interval_id FROM activity_intervals",
            ).fetchall()}
            stored_documents = {
                table: (
                    json.loads(row["payload"]), row["updated_at"]
                )
                for table in ("snapshots", "activity_stores")
                for row in [db.execute(
                    f"SELECT payload,updated_at FROM {table} WHERE device_id=?",
                    ("pc-test",),
                ).fetchone()]
            }
            daily_seconds = db.execute(
                "SELECT seconds FROM activity_daily_aggregate_metrics WHERE "
                "metric_kind='usage' AND metric_key=?", (sentinel,),
            ).fetchone()[0]
            retained_sentinel_intervals = db.execute(
                "SELECT COUNT(*) FROM activity_intervals WHERE target_key=?",
                (sentinel,),
            ).fetchone()[0]
            deleted_categories = db.execute(
                "SELECT COUNT(*) FROM activity_interval_categories WHERE "
                "interval_id='snapshot-activity-duplicate-exact-0001'",
            ).fetchone()[0]

        self.assertNotIn(sentinel, timeline_keys)
        self.assertIn(near_miss, timeline_keys)
        self.assertIn("activity-duplicate-exact-0001", interval_ids)
        self.assertNotIn(
            "snapshot-activity-duplicate-exact-0001", interval_ids,
        )
        self.assertTrue({
            "activity-duplicate-time-0001",
            "snapshot-activity-duplicate-time-0001",
            "activity-duplicate-category-0001",
            "snapshot-activity-duplicate-category-0001",
        } <= interval_ids)
        self.assertEqual(deleted_categories, 0)
        self.assertGreaterEqual(retained_sentinel_intervals, 1)
        self.assertEqual(daily_seconds, 321)
        for document, document_updated_at in stored_documents.values():
            self.assertEqual(document_updated_at, updated_at)
            self.assertEqual(
                [item["key"] for item in document["sessions"]], [near_miss],
            )
            self.assertEqual(
                [item["key"] for item in document["open_sessions"].values()],
                [near_miss],
            )
            self.assertIn(sentinel, document["days"]["2026-08-29"])
        self.assertEqual(
            restarted.purge_duplicate_snapshot_activity_intervals(), 0,
        )
        self.assertEqual(restarted.purge_other_sites_timeline_records(), {
            "timeline": 0, "snapshots": 0, "activity_stores": 0,
        })
        visible, truncated = restarted.device_activity_sessions(
            "pc-test", username="alice",
        )
        self.assertFalse(truncated)
        self.assertNotIn(sentinel, [item["key"] for item in visible])
        self.assertIn(near_miss, [item["key"] for item in visible])

    def test_normalized_history_pages_do_not_skip_equal_timestamps(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        sessions = [{
            "record_id": f"timeline-history-{index:04d}",
            "kind": "program", "id": "program:kona",
            "key": "app:kona", "label": "Kona", "category": "Jeux",
            "category_lineage": ["Jeux", "Divertissement"],
            # Deliberately identical: a timestamp-only cursor would lose rows.
            "started_at": "2026-06-01T10:00:00+02:00",
            "ended_at": "2026-06-01T10:01:00+02:00",
            "windows_session_id": 4, "source": "monitor",
        } for index in range(10_025)]
        for offset in range(0, len(sessions), 500):
            store.ingest_activity_timeline_sessions(
                "pc-test", sid, sessions[offset:offset + 500],
            )

        received = []
        before = ""
        pages = 0
        while True:
            page, metadata = store.device_activity_history_page(
                "pc-test", username="alice", before=before, limit=500,
            )
            pages += 1
            self.assertLessEqual(len(page), 500)
            self.assertLessEqual(
                metadata["payload_bytes"], MAX_INCREMENTAL_ACTIVITY_BYTES,
            )
            received.extend(item["record_id"] for item in page)
            if not metadata["has_more"]:
                self.assertEqual(metadata["next_before"], "")
                break
            self.assertTrue(metadata["next_before"])
            self.assertNotEqual(metadata["next_before"], before)
            before = metadata["next_before"]

        self.assertGreater(pages, 20)
        self.assertEqual(len(received), 10_025)
        self.assertEqual(set(received), {
            item["record_id"] for item in sessions
        })
        with self.assertRaisesRegex(ValueError, "Curseur d’historique"):
            store.device_activity_history_page(
                "pc-test", username="alice", before="invalide",
            )

    def test_history_page_never_emits_one_record_over_its_byte_budget(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        with self.assertRaisesRegex(ValueError, "Cible de tranche"):
            store.ingest_activity_intervals("pc-test", sid, [{
                "interval_id": "oversized-ingest-target-0001",
                "target_key": "app:" + "x" * 1025,
                "started_at": "2026-06-01T10:00:00+00:00",
                "ended_at": "2026-06-01T10:01:00+00:00",
            }])

        # Model a row written by an older/corrupt runtime before the field
        # limit existed.  The reader must fail closed even for its first row.
        with store.connect() as db:
            db.execute(
                "INSERT INTO activity_intervals(device_id,interval_id,"
                "windows_sid,usage_guard_username,target_key,category_key,"
                "started_at,ended_at,policy_revision,received_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    "pc-test", "oversized-stored-target-0001", sid, "alice",
                    "app:" + "x" * (70 * 1024), "",
                    "2026-06-01T10:00:00.000+00:00",
                    "2026-06-01T10:01:00.000+00:00", 0,
                    "2026-06-01T10:02:00.000+00:00",
                ),
            )
        with self.assertRaisesRegex(ValueError, "trop volumineux"):
            store.device_activity_history_page(
                "pc-test", username="alice", max_bytes=64 * 1024,
            )

    def test_history_page_deduplicates_active_transport_at_page_boundary(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        newer = [{
            "record_id": f"newer-program-{index:04d}",
            "kind": "program", "id": "program:kona",
            "key": "app:kona", "label": "Kona", "category": "Jeux",
            "category_lineage": ["Jeux"],
            "started_at": (
                datetime(2026, 6, 2, tzinfo=timezone.utc)
                + timedelta(seconds=index * 2)
            ).isoformat(),
            "ended_at": (
                datetime(2026, 6, 2, tzinfo=timezone.utc)
                + timedelta(seconds=index * 2 + 1)
            ).isoformat(),
            "windows_session_id": 4, "source": "monitor",
        } for index in range(499)]
        active = {
            "record_id": "timeline-active-boundary",
            "kind": "active", "id": "active:kona", "key": "app:kona",
            "label": "Kona", "category": "Jeux",
            "category_lineage": ["Jeux"],
            "started_at": "2026-06-01T10:00:00+00:00",
            "ended_at": "2026-06-01T10:01:00+00:00",
            "windows_session_id": 4, "source": "monitor",
        }
        store.ingest_activity_timeline_sessions(
            "pc-test", sid, [*newer, active],
        )
        store.ingest_activity_intervals("pc-test", sid, [{
            "interval_id": "interval-active-boundary",
            "target_key": "app:kona", "category_key": "Jeux",
            "category_keys": ["Jeux"],
            "started_at": active["started_at"],
            "ended_at": active["ended_at"], "policy_revision": 1,
        }])

        page, metadata = store.device_activity_history_page(
            "pc-test", username="alice", limit=500,
        )

        self.assertFalse(metadata["has_more"])
        self.assertEqual(len(page), 500)
        active_rows = [
            item for item in page
            if item["kind"] == "active" and item["key"] == "app:kona"
        ]
        self.assertEqual(
            [item["record_id"] for item in active_rows],
            ["timeline-active-boundary"],
        )

    def test_analysis_overview_exposes_a_bounded_backward_cursor(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited",
            device_ids=["pc-test"],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        sessions = [{
            "record_id": f"timeline-overview-{index:04d}",
            "kind": "program", "id": "program:kona",
            "key": "app:kona", "label": "Kona", "category": "Jeux",
            "category_lineage": ["Jeux"],
            "started_at": (
                datetime(2026, 6, 1, tzinfo=timezone.utc)
                + timedelta(minutes=index)
            ).isoformat(),
            "ended_at": (
                datetime(2026, 6, 1, tzinfo=timezone.utc)
                + timedelta(minutes=index, seconds=30)
            ).isoformat(),
            "windows_session_id": 4, "source": "monitor",
        } for index in range(505)]
        store.ingest_activity_timeline_sessions(
            "pc-test", sid, sessions[:500],
        )
        store.ingest_activity_timeline_sessions(
            "pc-test", sid, sessions[500:],
        )
        _, login, headers = self.request(
            "/api/v1/auth/login", "POST", {
                "username": "alice", "password": "temporary-strong",
            }, origin=PUBLIC_ORIGIN,
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        _, changed, headers = self.request(
            "/api/v1/auth/password", "POST", {
                "current_password": "temporary-strong",
                "new_password": "personal-strong-password",
            }, origin=PUBLIC_ORIGIN, cookie=cookie,
            csrf=login["csrf_token"],
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        _, first, _ = self.request(
            "/api/v1/overview?scope=all&tz=Europe%2FParis",
            cookie=cookie,
        )
        cursor = first["history_page"]["next_before"]
        self.assertTrue(first["history_page"]["has_more"])
        self.assertLessEqual(first["history_page"]["rows"], 500)
        self.assertLessEqual(
            first["history_page"]["payload_bytes"],
            MAX_INCREMENTAL_ACTIVITY_BYTES,
        )
        _, second, _ = self.request(
            "/api/v1/overview?" + urlencode({
                "scope": "all", "tz": "Europe/Paris", "before": cursor,
            }), cookie=cookie,
        )

        self.assertFalse(second["history_page"]["has_more"])
        self.assertEqual(second["history_page"]["next_before"], "")
        self.assertEqual(
            {
                item["record_id"]
                for item in first["sessions"] + second["sessions"]
            },
            {item["record_id"] for item in sessions},
        )
        self.assertTrue(changed["permissions"]["view_analysis"])

    def test_full_analysis_summary_is_independent_from_raw_history_pages(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited",
            device_ids=["pc-test"], must_change=False,
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        intervals = []
        for index in range(620):
            opened = datetime(2026, 6, 1, tzinfo=timezone.utc) + timedelta(
                hours=index * 3,
            )
            intervals.append({
                "interval_id": f"analysis-complete-{index:04d}",
                "target_key": "app:kona", "category_key": "Jeux",
                "category_keys": ["Jeux", "Divertissement"],
                "started_at": opened.isoformat(),
                "ended_at": (opened + timedelta(minutes=10)).isoformat(),
                "policy_revision": 1,
            })
        store.ingest_activity_intervals("pc-test", sid, intervals[:500])
        store.ingest_activity_intervals("pc-test", sid, intervals[500:])

        page, metadata = store.device_activity_history_page(
            "pc-test", username="alice", limit=500,
        )
        summary = store.device_activity_analysis_summary(
            "pc-test", username="alice", timezone_name="Europe/Paris",
        )
        raw_session, _csrf, _expires = store.create_session("alice")
        _, overview, _ = self.request(
            "/api/v1/overview?scope=all&tz=Europe%2FParis",
            cookie="ug_session=" + raw_session,
        )

        self.assertEqual(len(page), 500)
        self.assertTrue(metadata["has_more"])
        self.assertEqual(summary["daily_stats"][0]["date"], "2026-06-01")
        self.assertEqual(summary["analysis_coverage"]["start"], "2026-06-01")
        self.assertTrue(summary["analysis_coverage"]["complete"])
        self.assertGreater(len(summary["daily_stats"]), 70)
        self.assertEqual(overview["daily_stats"][0]["date"], "2026-06-01")
        self.assertEqual(len(overview["sessions"]), 500)
        self.assertTrue(overview["history_page"]["has_more"])

    def test_analysis_revision_detects_backfill_outside_delta_window(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited",
            device_ids=["pc-test"], must_change=False,
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        recent = {
            "aggregate_id": "daily-recent-" + "a" * 64,
            "local_day": "2026-08-30",
            "metrics": [{
                "kind": "usage", "key": "app:thunderbird", "seconds": 40,
            }],
        }
        older = {
            "aggregate_id": "daily-backfill-" + "b" * 64,
            "local_day": "2026-08-03",
            "metrics": [{
                "kind": "usage", "key": "app:thunderbird", "seconds": 60,
            }],
        }
        store.ingest_activity_daily_aggregates("pc-test", [recent], sid)
        revision_before_tail = store.activity_analysis_revision(
            "pc-test", "alice",
        )
        current_day = datetime.now(timezone.utc).date()
        tail_started = datetime.combine(
            current_day, datetime.min.time(), tzinfo=timezone.utc,
        ) + timedelta(minutes=1)
        store.ingest_activity_intervals("pc-test", sid, [{
            "interval_id": "current-tail-does-not-revise-prefix",
            "target_key": "app:tail", "category_key": "Travail",
            "category_keys": ["Travail"],
            "started_at": tail_started.isoformat(),
            "ended_at": (tail_started + timedelta(minutes=1)).isoformat(),
            "policy_revision": 1,
        }])
        self.assertEqual(
            store.activity_analysis_revision("pc-test", "alice"),
            revision_before_tail,
        )
        raw_session, _csrf, _expires = store.create_session("alice")
        cookie = "ug_session=" + raw_session
        _, initial, _ = self.request(
            "/api/v1/overview?scope=all&tz=Europe%2FParis", cookie=cookie,
        )
        initial_revision = initial["analysis_coverage"]["revision"]

        store.ingest_activity_daily_aggregates("pc-test", [older], sid)
        store.ingest_activity_intervals("pc-test", sid, [{
            "interval_id": "old-normalized-backfill",
            "target_key": "app:thunderbird", "category_key": "Travail",
            "category_keys": ["Travail"],
            "started_at": "2026-08-03T08:00:00+00:00",
            "ended_at": "2026-08-03T08:01:00+00:00",
            "policy_revision": 1,
        }])
        _, delta, _ = self.request(
            "/api/v1/overview?scope=all&since=2026-08-30"
            "&tz=Europe%2FParis", cookie=cookie,
        )
        revised = delta["analysis_coverage"]["revision"]

        self.assertTrue(initial_revision.startswith("analysis-v1-"))
        self.assertNotEqual(revised, initial_revision)
        self.assertNotIn(
            "2026-08-03",
            [item["date"] for item in delta["daily_stats"]],
        )
        self.assertIn(
            "2026-08-30",
            [item["date"] for item in delta["daily_stats"]],
        )
        self.assertEqual(delta["delta_since"], "2026-08-30")

        aggregate_replay = store.ingest_activity_daily_aggregates(
            "pc-test", [older], sid,
        )
        interval_replay = store.ingest_activity_intervals(
            "pc-test", sid, [{
                "interval_id": "old-normalized-backfill",
                "target_key": "app:thunderbird", "category_key": "Travail",
                "category_keys": ["Travail"],
                "started_at": "2026-08-03T08:00:00+00:00",
                "ended_at": "2026-08-03T08:01:00+00:00",
                "policy_revision": 1,
            }],
        )
        _, replayed, _ = self.request(
            "/api/v1/overview?scope=all&since=2026-08-30"
            "&tz=Europe%2FParis", cookie=cookie,
        )
        _, complete, _ = self.request(
            "/api/v1/overview?scope=all&tz=Europe%2FParis", cookie=cookie,
        )

        self.assertEqual(aggregate_replay["duplicates"], 1)
        self.assertEqual(interval_replay["duplicates"], 1)
        self.assertEqual(
            replayed["analysis_coverage"]["revision"], revised,
        )
        self.assertEqual(complete["daily_stats"][0]["date"], "2026-08-03")
        self.assertIn(
            "2026-08-30",
            [item["date"] for item in complete["daily_stats"]],
        )
        thunderbird_days = [
            day["date"] for day in complete["daily_stats"]
            if any(
                item["key"] == "app:thunderbird"
                for item in day.get("usage", [])
            )
        ]
        self.assertEqual(thunderbird_days, ["2026-08-03", "2026-08-30"])

    def test_legacy_daily_totals_are_normalized_for_analysis_only(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited",
            device_ids=["pc-test"],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        store.save_activity_store("pc-test", {
            "days": {"2026-08-03": {"app:codex": 3600}},
            "passive_days": {"2026-08-03": {"PotPlayer": 120}},
            "system_days": {"2026-08-03": {
                "foreground": 3600, "on": 7200,
            }},
            "other_site_days": {"brave.exe": {"2026-08-03": {
                "amazon.fr": 75,
            }}},
            "targets": {"app:codex": {
                "label": "Codex", "category": "Programmation",
            }},
        })

        summary = store.device_activity_analysis_summary(
            "pc-test", username="alice", timezone_name="Europe/Paris",
        )
        day = summary["daily_stats"][0]
        with store.connect() as db:
            marker = db.execute(
                "SELECT daily_aggregates_migrated FROM "
                "activity_store_migrations WHERE device_id='pc-test'",
            ).fetchone()
            interval_count = db.execute(
                "SELECT COUNT(*) FROM activity_intervals",
            ).fetchone()[0]

        self.assertEqual(day["date"], "2026-08-03")
        self.assertEqual(day["usage"][0]["label"], "Codex")
        self.assertEqual(day["usage"][0]["seconds"], 3600)
        self.assertEqual(day["passive"][0]["seconds"], 120)
        self.assertEqual(day["other_sites"], [{
            "browser": "brave.exe", "host": "amazon.fr", "seconds": 75.0,
        }])
        self.assertEqual(day["system"]["on"], 7200)
        self.assertEqual(marker["daily_aggregates_migrated"], 1)
        self.assertEqual(interval_count, 0)

    def test_daily_aggregate_corrections_are_bounded_and_replay_safe(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited",
            device_ids=["pc-test"],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        old = {
            "aggregate_id": "daily-v1:2026-08-03:" + "a" * 64,
            "local_day": "2026-08-03",
            "metrics": [{
                "kind": "usage", "key": "app:codex", "seconds": 60,
            }, {
                "kind": "other_site",
                "key": "site:brave.exe:amazon.fr", "seconds": 30,
            }],
        }
        corrected = {
            "aggregate_id": "daily-v1:2026-08-03:" + "b" * 64,
            "local_day": "2026-08-03",
            "metrics": [{
                "kind": "usage", "key": "app:codex", "seconds": 90,
            }, {
                "kind": "other_site",
                "key": "site:brave.exe:amazon.fr", "seconds": 45,
            }],
        }

        _, first, _ = self.request(
            "/api/v1/agent/activity/daily-aggregates", "POST", {
                "device_id": "pc-test", "schema_version": 1,
                "windows_sid": sid, "aggregates": [old],
            }, agent=True,
        )
        second = store.ingest_activity_daily_aggregates(
            "pc-test", [corrected], sid,
        )
        replay = store.ingest_activity_daily_aggregates(
            "pc-test", [old], sid,
        )
        summary = store.device_activity_analysis_summary(
            "pc-test", username="alice", timezone_name="Europe/Paris",
        )

        self.assertEqual(first["accepted_ids"], [old["aggregate_id"]])
        self.assertEqual(second["accepted_ids"], [corrected["aggregate_id"]])
        self.assertEqual(replay["duplicates"], 1)
        self.assertEqual(
            summary["daily_stats"][0]["usage"][0]["seconds"], 90,
        )
        self.assertEqual(summary["daily_stats"][0]["other_sites"], [{
            "browser": "brave.exe", "host": "amazon.fr", "seconds": 45.0,
        }])
        self.assertEqual(summary["other_sites"], [{
            "browser": "brave.exe", "host": "amazon.fr", "seconds": 45.0,
        }])
        with self.assertRaisesRegex(ValueError, "Lot d’agrégats"):
            store.ingest_activity_daily_aggregates(
                "pc-test", [old] * 32, sid,
            )

    def test_daily_aggregate_replaces_legacy_and_exact_totals_for_owner_day(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited",
            device_ids=["pc-test"],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        store.save_activity_store("pc-test", {
            "days": {"2026-08-03": {"app:codex": 100}},
            "targets": {"app:codex": {
                "label": "Codex", "category": "Programmation",
            }},
        })
        store.ingest_activity_intervals("pc-test", sid, [{
            "interval_id": "daily-authority-exact-0001",
            "target_key": "app:codex", "category_key": "Programmation",
            "category_keys": ["Programmation"],
            "started_at": "2026-08-03T12:00:00+02:00",
            "ended_at": "2026-08-03T12:02:00+02:00",
            "policy_revision": 1,
        }])
        corrected = {
            "aggregate_id": "daily-v1:2026-08-03:" + "c" * 64,
            "local_day": "2026-08-03",
            "metrics": [{
                "kind": "usage", "key": "app:codex", "seconds": 50,
            }],
        }
        store.ingest_activity_daily_aggregates(
            "pc-test", [corrected], sid,
        )

        summary = store.device_activity_analysis_summary(
            "pc-test", username="alice", timezone_name="Europe/Paris",
        )

        self.assertEqual(
            summary["daily_stats"][0]["usage"][0]["seconds"], 50,
        )

        empty_correction = {
            "aggregate_id": "daily-v1:2026-08-03:" + "d" * 64,
            "local_day": "2026-08-03", "metrics": [],
        }
        store.ingest_activity_daily_aggregates(
            "pc-test", [empty_correction], sid,
        )
        empty_summary = store.device_activity_analysis_summary(
            "pc-test", username="alice", timezone_name="Europe/Paris",
        )
        self.assertEqual(empty_summary["daily_stats"], [])

    def test_identical_daily_digest_is_not_deduplicated_across_users(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited",
            device_ids=["pc-test"],
        )
        store.create_user(
            "bob", "temporary-strong", role="limited",
            device_ids=["pc-test"],
        )
        sid_alice = "S-1-5-21-100-200-300-1001"
        sid_bob = "S-1-5-21-100-200-300-1002"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid_alice, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }, {
            "windows_sid": sid_bob, "windows_username": "Bob",
            "usage_guard_username": "bob",
        }], "admin")
        aggregate = {
            "aggregate_id": "daily-v1-" + "c" * 64,
            "local_day": "2026-08-03",
            "metrics": [{
                "kind": "usage", "key": "app:kona", "seconds": 60,
            }],
        }

        first = store.ingest_activity_daily_aggregates(
            "pc-test", [aggregate], sid_alice,
        )
        second = store.ingest_activity_daily_aggregates(
            "pc-test", [aggregate], sid_bob,
        )
        replay_alice = store.ingest_activity_daily_aggregates(
            "pc-test", [aggregate], sid_alice,
        )
        replay_bob = store.ingest_activity_daily_aggregates(
            "pc-test", [aggregate], sid_bob,
        )

        self.assertEqual(first["duplicates"], 0)
        self.assertEqual(second["duplicates"], 0)
        self.assertEqual(replay_alice["duplicates"], 1)
        self.assertEqual(replay_bob["duplicates"], 1)
        with store.connect() as db:
            batches = db.execute(
                "SELECT aggregate_id,usage_guard_username FROM "
                "activity_daily_aggregate_batches ORDER BY "
                "usage_guard_username",
            ).fetchall()
            receipts = db.execute(
                "SELECT aggregate_id FROM "
                "activity_daily_aggregate_receipts",
            ).fetchall()
        self.assertEqual(
            [row["usage_guard_username"] for row in batches],
            ["alice", "bob"],
        )
        self.assertEqual(len({row["aggregate_id"] for row in batches}), 2)
        self.assertEqual(len(receipts), 2)

    def test_compact_snapshot_tail_is_normalized_idempotently(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited",
            device_ids=["pc-test"],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        snapshot = {"analysis": {
            "sessions": [{
                "kind": "active", "id": "active:kona",
                "key": "app:kona", "label": "Kona",
                "category": "Jeux", "category_lineage": ["Jeux"],
                "windows_sid": sid, "windows_session_id": 4,
                "started_at": "2026-08-29T23:50:00+02:00",
                "ended_at": "2026-08-30T00:10:00+02:00",
            }],
        }}

        store.save_snapshot("pc-test", snapshot)
        store.save_snapshot("pc-test", snapshot)
        summary = store.device_activity_analysis_summary(
            "pc-test", username="alice", timezone_name="Europe/Paris",
        )
        with store.connect() as db:
            counts = (
                db.execute(
                    "SELECT COUNT(*) FROM activity_timeline_sessions",
                ).fetchone()[0],
                db.execute(
                    "SELECT COUNT(*) FROM activity_intervals",
                ).fetchone()[0],
            )

        self.assertEqual(counts, (1, 1))
        self.assertEqual(
            [day["date"] for day in summary["daily_stats"]],
            ["2026-08-29", "2026-08-30"],
        )
        self.assertEqual(
            [day["usage"][0]["seconds"] for day in summary["daily_stats"]],
            [600, 600],
        )

    def test_legacy_activity_store_is_migrated_locally_before_new_intervals(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited",
            device_ids=["pc-test"],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        store.save_activity_store("pc-test", {
            "version": 2,
            "targets": {
                "app:kona": {"label": "Kona", "category": "Jeux"},
                "app:chatgpt": {
                    "label": "Codex", "category": "Programation+ChatGPT",
                },
            },
            "category_parents": {"Jeux": "Divertissement"},
            "category_order": ["Programation+ChatGPT", "Divertissement", "Jeux"],
            "sessions": [{
                "id": "active:kona", "kind": "active",
                "key": "app:kona", "label": "Kona",
                "category": "Jeux",
                "category_lineage": ["Jeux", "Divertissement"],
                "started_at": "2026-08-28T23:50:00+02:00",
                "ended_at": "2026-08-29T00:10:00+02:00",
                "windows_session_id": 4,
            }, {
                # Codex is no longer running: both its closed timeline row and
                # its catalogue classification must survive the migration.
                "id": "program:codex", "kind": "program",
                "key": "app:chatgpt", "label": "Codex",
                "started_at": "2026-08-28T22:00:00+02:00",
                "ended_at": "2026-08-28T22:05:00+02:00",
                "windows_session_id": 4,
            }],
            "windows_sessions": [{
                "windows_sid": sid, "usage_guard_username": "alice",
                "windows_session_id": 4,
                "started_at": "2026-08-28T21:55:00+02:00",
                "ended_at": "2026-08-29T00:15:00+02:00",
            }],
            "system_events": [{
                "type": "sleep", "at": "2026-08-28T22:30:00+02:00",
                "windows_session_id": 4,
            }],
        })
        store.ingest_activity_intervals("pc-test", sid, [{
            "interval_id": "fresh-kona-after-migration-0001",
            "target_key": "app:kona", "category_key": "Jeux",
            "category_keys": ["Jeux", "Divertissement"],
            "started_at": "2026-08-29T00:10:00+02:00",
            "ended_at": "2026-08-29T00:20:00+02:00",
            "policy_revision": 1,
        }])

        timeline, truncated = store.device_activity_sessions(
            "pc-test", username="alice",
        )
        catalog = store.device_catalog("pc-test")

        self.assertFalse(truncated)
        self.assertEqual(
            [item["kind"] for item in timeline],
            ["windows_session", "program", "system_event", "active", "active"],
        )
        self.assertEqual(
            catalog["targets"]["app:chatgpt"]["category"],
            "Programation+ChatGPT",
        )
        self.assertEqual(store.user_usage_union(
            "alice", "2026-08-28T00:00:00+02:00",
            "2026-08-30T00:00:00+02:00", target_key="app:kona",
        ), 30 * 60)
        self.assertEqual(store.user_usage_union(
            "alice", "2026-08-28T00:00:00+02:00",
            "2026-08-30T00:00:00+02:00",
            category_key="Divertissement",
        ), 30 * 60)

    def test_legacy_activity_store_migration_is_idempotent_across_restart(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited",
            device_ids=["pc-test"],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        store.save_activity_store("pc-test", {
            "targets": {"app:kona": {"label": "Kona", "category": "Jeux"}},
            "category_order": ["Jeux"],
            "sessions": [{
                "kind": "active", "key": "app:kona", "label": "Kona",
                "windows_sid": sid, "usage_guard_username": "alice",
                "started_at": "2026-08-28T23:50:00+02:00",
                "ended_at": "2026-08-29T00:10:00+02:00",
            }],
        })
        with store.connect() as db:
            before = (
                db.execute("SELECT COUNT(*) FROM activity_intervals").fetchone()[0],
                db.execute(
                    "SELECT COUNT(*) FROM activity_timeline_sessions"
                ).fetchone()[0],
            )

        repeated = store.migrate_legacy_activity_stores("pc-test")
        restarted = Store(store.path)
        with restarted.connect() as db:
            after = (
                db.execute("SELECT COUNT(*) FROM activity_intervals").fetchone()[0],
                db.execute(
                    "SELECT COUNT(*) FROM activity_timeline_sessions"
                ).fetchone()[0],
            )
            marker = db.execute(
                "SELECT status,pending_records FROM activity_store_migrations "
                "WHERE device_id='pc-test'"
            ).fetchone()

        self.assertEqual(before, (1, 1))
        self.assertEqual(after, before)
        self.assertEqual(repeated["migrated_records"], 0)
        self.assertEqual((marker["status"], marker["pending_records"]), (
            "completed", 0,
        ))

    def test_store_startup_migrates_a_preexisting_legacy_blob(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited",
            device_ids=["pc-test"],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        legacy = {
            "targets": {
                "app:chatgpt": {
                    "label": "Codex", "category": "Programation+ChatGPT",
                },
            },
            "category_order": ["Programation+ChatGPT"],
            "sessions": [{
                "kind": "active", "key": "app:chatgpt", "label": "Codex",
                "windows_sid": sid,
                "started_at": "2026-08-29T00:00:00+02:00",
                "ended_at": "2026-08-29T00:01:00+02:00",
            }],
        }
        with store.connect() as db:
            db.execute(
                "INSERT INTO activity_stores(device_id,payload,updated_at) "
                "VALUES(?,?,?)",
                (
                    "pc-test", json.dumps(legacy, separators=(",", ":")),
                    "2026-08-30T08:00:00+00:00",
                ),
            )

        restarted = Store(store.path)

        with restarted.connect() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_intervals"
            ).fetchone()[0], 1)
            marker = db.execute(
                "SELECT status FROM activity_store_migrations "
                "WHERE device_id='pc-test'"
            ).fetchone()
        self.assertEqual(marker["status"], "completed")
        self.assertEqual(
            restarted.device_catalog("pc-test")["targets"]["app:chatgpt"][
                "category"
            ],
            "Programation+ChatGPT",
        )

    def test_legacy_activity_store_retries_records_after_identity_mapping(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited",
            device_ids=["pc-test"],
        )
        store.save_activity_store("pc-test", {
            "sessions": [{
                "kind": "active", "key": "app:kona", "label": "Kona",
                "started_at": "2026-08-29T00:00:00+02:00",
                "ended_at": "2026-08-29T00:10:00+02:00",
            }],
        })
        with store.connect() as db:
            pending = db.execute(
                "SELECT status,pending_records FROM activity_store_migrations "
                "WHERE device_id='pc-test'"
            ).fetchone()
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_intervals"
            ).fetchone()[0], 0)

        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        with store.connect() as db:
            retried = db.execute(
                "SELECT status,pending_records FROM activity_store_migrations "
                "WHERE device_id='pc-test'"
            ).fetchone()

        self.assertEqual((pending["status"], pending["pending_records"]), (
            "pending", 1,
        ))
        self.assertEqual((retried["status"], retried["pending_records"]), (
            "completed", 0,
        ))
        self.assertEqual(store.user_usage_union(
            "alice", "2026-08-29T00:00:00+02:00",
            "2026-08-30T00:00:00+02:00",
        ), 10 * 60)

    def test_timeline_http_endpoint_is_idempotent_and_conflicts_atomically(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        session = {
            "record_id": "timeline-http-idempotent-0001",
            "kind": "program", "id": "program:kona", "key": "app:kona",
            "label": "Kona", "category": "Jeux",
            "category_lineage": ["Jeux", "Divertissement"],
            "started_at": "2026-08-29T23:55:00+02:00",
            "ended_at": "2026-08-30T00:05:00+02:00",
            "windows_session_id": 4, "source": "monitor",
        }
        payload = {
            "device_id": "pc-test", "windows_sid": sid,
            "sessions": [session],
        }

        first_status, first, _ = self.request(
            "/api/v1/agent/activity/timeline", "POST", payload, agent=True,
        )
        second_status, second, _ = self.request(
            "/api/v1/agent/activity/timeline", "POST", payload, agent=True,
        )

        self.assertEqual((first_status, second_status), (200, 200))
        self.assertEqual((first["accepted"], first["duplicates"]), (1, 0))
        self.assertEqual((second["accepted"], second["duplicates"]), (0, 1))
        with store.connect() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_timeline_sessions WHERE "
                "device_id=?", ("pc-test",),
            ).fetchone()[0], 1)

        with self.assertRaises(HTTPError) as conflict:
            self.request(
                "/api/v1/agent/activity/timeline", "POST", {
                    **payload,
                    "sessions": [{**session, "label": "Kona modifié"}],
                }, agent=True,
            )
        self.assertEqual(conflict.exception.code, 409)
        with store.connect() as db:
            self.assertEqual(db.execute(
                "SELECT label FROM activity_timeline_sessions WHERE "
                "device_id=? AND record_id=?",
                ("pc-test", session["record_id"]),
            ).fetchone()[0], "Kona")

    def test_timeline_http_endpoint_rejects_more_than_500_rows_atomically(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        sessions = [{
            "record_id": f"timeline-count-{index:04d}",
            "kind": "program", "id": "program:kona", "key": "app:kona",
            "label": "Kona", "category": "Jeux",
            "category_lineage": ["Jeux"],
            "started_at": "2026-08-29T23:55:00+02:00",
            "ended_at": "2026-08-30T00:05:00+02:00",
            "windows_session_id": 4, "source": "monitor",
        } for index in range(501)]

        with self.assertRaises(HTTPError) as rejected:
            self.request(
                "/api/v1/agent/activity/timeline", "POST", {
                    "device_id": "pc-test", "windows_sid": sid,
                    "sessions": sessions,
                }, agent=True,
            )

        self.assertEqual(rejected.exception.code, 400)
        with store.connect() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_timeline_sessions",
            ).fetchone()[0], 0)

    def test_timeline_http_endpoint_rejects_more_than_512_kib_atomically(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_username": "Alice",
            "usage_guard_username": "alice",
        }], "admin")
        sessions = [{
            "record_id": f"timeline-bytes-{index:04d}",
            "kind": "program", "id": "program:kona", "key": "app:kona",
            "label": "x" * 1024, "category": "Jeux",
            "category_lineage": ["Jeux"],
            "started_at": "2026-08-29T23:55:00+02:00",
            "ended_at": "2026-08-30T00:05:00+02:00",
            "windows_session_id": 4, "source": "monitor",
        } for index in range(500)]
        encoded_sessions = json.dumps(
            sessions, ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
        self.assertGreater(
            len(encoded_sessions), MAX_INCREMENTAL_ACTIVITY_BYTES,
        )

        with self.assertRaises(HTTPError) as rejected:
            self.request(
                "/api/v1/agent/activity/timeline", "POST", {
                    "device_id": "pc-test", "windows_sid": sid,
                    "sessions": sessions,
                }, agent=True,
            )

        self.assertEqual(rejected.exception.code, 400)
        with store.connect() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM activity_timeline_sessions",
            ).fetchone()[0], 0)

    def test_interval_history_keeps_kona_on_both_sides_of_midnight(self):
        snapshot = {
            "merge_candidates": [{
                "key": "app:kona", "label": "Kona", "category": "Jeux",
            }],
            "daily_stats": [], "sessions": [], "windows_sessions": [],
        }
        sessions = [{
            "record_id": "kona-before", "kind": "active",
            "key": "app:kona", "label": "Kona",
            "started_at": "2026-08-28T23:34:09+02:00",
            "ended_at": "2026-08-29T00:00:00+02:00",
            "windows_sid": "S-1-5-21-1",
        }, {
            "record_id": "kona-after", "kind": "active",
            "key": "app:kona", "label": "Kona",
            "started_at": "2026-08-29T00:00:00+02:00",
            "ended_at": "2026-08-29T00:10:00+02:00",
            "windows_sid": "S-1-5-21-1",
        }]

        analysis = snapshot_with_interval_history(
            snapshot, sessions, timezone_name="Europe/Paris",
        )

        by_day = {
            item["date"]: item["usage"][0]["seconds"]
            for item in analysis["daily_stats"]
        }
        self.assertEqual(by_day["2026-08-28"], 1551.0)
        self.assertEqual(by_day["2026-08-29"], 600.0)
        self.assertEqual(analysis["usage"][0]["seconds"], 2151.0)
        self.assertEqual(len(analysis["sessions"]), 2)

    def test_interval_history_ignores_reversed_rows_in_daily_totals(self):
        snapshot = {
            "merge_candidates": [{
                "key": "app:kona", "label": "Kona", "category": "Jeux",
            }],
            "daily_stats": [], "sessions": [], "windows_sessions": [],
        }
        sessions = [{
            "record_id": "kona-reversed", "kind": "active",
            "key": "app:kona", "label": "Kona",
            "started_at": "2026-08-29T10:05:00+02:00",
            "ended_at": "2026-08-29T10:04:00+02:00",
        }, {
            "record_id": "kona-valid", "kind": "active",
            "key": "app:kona", "label": "Kona",
            "started_at": "2026-08-29T10:10:00+02:00",
            "ended_at": "2026-08-29T10:11:00+02:00",
        }]

        analysis = snapshot_with_interval_history(
            snapshot, sessions, timezone_name="Europe/Paris",
        )

        self.assertEqual(analysis["daily_stats"][0]["active"], 60.0)
        self.assertEqual(analysis["usage"][0]["seconds"], 60.0)
        self.assertEqual(len(analysis["sessions"]), 2)

    def test_empty_snapshot_cannot_erase_saved_codex_catalog(self):
        store = self.server.store
        store.save_snapshot("pc-test", {
            "category_order": ["Programation+ChatGPT"],
            "categories": ["Programation+ChatGPT"],
            "merge_candidates": [{
                "key": "app:chatgpt", "label": "Codex",
                "category": "Programation+ChatGPT",
            }],
        })
        store.save_snapshot("pc-test", {
            "usage": [], "sessions": [], "category_order": [],
            "categories": [], "merge_candidates": [],
        })

        catalog = store.device_catalog("pc-test")

        self.assertEqual(
            catalog["targets"]["app:chatgpt"]["category"],
            "Programation+ChatGPT",
        )
        self.assertEqual(catalog["category_order"], ["Programation+ChatGPT"])

    def test_policy_scope_chooses_rich_catalog_not_device_with_activity_blob(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.register_device("pc-empty", token="e" * 48)
        store.create_user(
            "alice", "temporary-strong", role="limited",
            device_ids=["pc-test", "pc-empty"],
        )
        store.save_snapshot("pc-test", {
            "category_order": ["Programation+ChatGPT"],
            "categories": ["Programation+ChatGPT"],
            "merge_candidates": [{
                "key": "app:chatgpt", "label": "Codex",
                "category": "Programation+ChatGPT",
            }],
        })
        store.save_activity_store("pc-empty", {
            "days": {"2026-08-29": {"app:other": 1}},
            "targets": {}, "category_order": [],
        })

        users = store.accessible_policy_users("admin", is_admin=True)
        alice = next(item for item in users if item["username"] == "alice")

        self.assertEqual(alice["catalog_device_id"], "pc-test")

    def test_person_wide_category_usage_uses_the_canonical_catalog(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        store.register_device("pc-other", token="o" * 48)
        sid_one = "S-1-5-21-100-200-300-1001"
        sid_two = "S-1-5-21-400-500-600-1001"
        for device_id, sid in (("pc-test", sid_one), ("pc-other", sid_two)):
            store.set_device_windows_identities(device_id, [{
                "windows_sid": sid, "windows_username": "Alice",
                "usage_guard_username": "alice",
            }], "admin")
        youtube = "site:brave.exe:youtube.com"
        store.save_activity_store("pc-test", {
            "targets": {youtube: {
                "label": "youtube.com", "category": "Divertissement",
            }},
            "category_order": ["Divertissement"],
            "category_parents": {"Divertissement": ""},
        })
        # This reproduces x20w before catalogue reconciliation: YouTube usage
        # is uploaded and advances, but its old local category is "Brave".
        store.save_activity_store("pc-other", {
            "targets": {youtube: {
                "label": "youtube.com", "category": "Brave",
            }},
        })
        store.ingest_activity_intervals("pc-test", sid_one, [{
            "interval_id": "youtube-nuc-0001", "target_key": youtube,
            "category_key": "Divertissement",
            "category_keys": ["Divertissement"],
            "started_at": "2026-08-29T07:00:00+02:00",
            "ended_at": "2026-08-29T08:00:00+02:00",
            "policy_revision": 38,
        }])
        store.ingest_activity_intervals("pc-other", sid_two, [{
            "interval_id": "youtube-x20w-0001", "target_key": youtube,
            "category_key": "Brave", "category_keys": ["Brave"],
            "started_at": "2026-08-29T08:00:00+02:00",
            "ended_at": "2026-08-29T10:00:00+02:00",
            "policy_revision": 38,
        }])
        start = "2026-08-29T00:00:00+02:00"
        end = "2026-08-30T00:00:00+02:00"

        self.assertEqual(store.user_usage_union(
            "alice", start, end, category_key="Divertissement",
        ), 3 * 60 * 60)
        self.assertEqual(store.user_usage_union(
            "alice", start, end, category_key="Divertissement",
            device_ids=["pc-other"],
        ), 2 * 60 * 60)
        self.assertEqual(store.user_usage_union(
            "alice", start, end, category_key="Brave",
        ), 0)
        breakdown = store.user_usage_breakdown("alice", start, end)
        categories = {
            item["key"]: item["seconds"]
            for item in breakdown["categories"]
        }
        self.assertEqual(categories["Divertissement"], 3 * 60 * 60)
        self.assertNotIn("Brave", categories)

    def test_interval_union_clips_and_merges_touching_periods(self):
        intervals = [{
            "started_at": "2026-08-24T07:00:00+02:00",
            "ended_at": "2026-08-24T10:00:00+02:00",
        }, {
            "started_at": "2026-08-24T10:00:00+02:00",
            "ended_at": "2026-08-24T12:00:00+02:00",
        }]
        self.assertEqual(interval_union_seconds(intervals), 5 * 60 * 60)
        self.assertEqual(interval_union_seconds(
            intervals, "2026-08-24T08:00:00+02:00",
            "2026-08-24T11:00:00+02:00",
        ), 3 * 60 * 60)

    def test_agent_interval_api_requires_its_own_mapped_sid(self):
        store = self.server.store
        store.create_user("admin", "temporary-strong", role="admin")
        store.create_user(
            "alice", "temporary-strong", role="limited", device_ids=[],
        )
        sid = "S-1-5-21-100-200-300-1001"
        store.set_device_windows_identities("pc-test", [{
            "windows_sid": sid, "windows_domain": "FAMILLE",
            "windows_username": "Alice", "usage_guard_username": "alice",
        }], "admin")
        interval = {
            "interval_id": "interval-api-0001",
            "target_key": "app:test",
            "started_at": "2026-08-24T08:00:00+02:00",
            "ended_at": "2026-08-24T08:01:00+02:00",
            "policy_revision": 1,
        }

        status, result, _ = self.request(
            "/api/v1/agent/activity/intervals", "POST", {
                "device_id": "pc-test", "windows_sid": sid,
                "intervals": [interval],
            }, agent=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["usage_guard_username"], "alice")
        status, merged, _ = self.request(
            "/api/v1/agent/activity/union?" + urlencode({
                "device_id": "pc-test", "windows_sid": sid,
                "start": "2026-08-24T00:00:00+02:00",
                "end": "2026-08-25T00:00:00+02:00",
                "target_key": "app:test",
            }), agent=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(merged["seconds"], 60)

        status, live, _ = self.request(
            "/api/v1/agent/activity/live", "POST", {
                "device_id": "pc-test", "live_intervals": [{
                    "live_id": "live-api-0001", "windows_sid": sid,
                    "target_key": "app:test",
                    "started_at": "2026-08-24T08:01:00+02:00",
                    "observed_at": "2026-08-24T08:03:00+02:00",
                    "policy_revision": 1,
                }],
            }, agent=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(live["active"], 1)
        status, merged, _ = self.request(
            "/api/v1/agent/activity/union?" + urlencode({
                "device_id": "pc-test", "windows_sid": sid,
                "start": "2026-08-24T00:00:00+02:00",
                "end": "2026-08-25T00:00:00+02:00",
                "target_key": "app:test",
            }), agent=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(merged["seconds"], 180)

        with self.assertRaises(HTTPError) as error:
            self.request(
                "/api/v1/agent/activity/intervals", "POST", {
                    "device_id": "pc-test",
                    "windows_sid": "S-1-5-21-100-200-300-9999",
                    "intervals": [{**interval, "interval_id": "interval-api-0002"}],
                }, agent=True,
            )
        self.assertEqual(error.exception.code, 400)

    def test_authenticated_client_update_requires_a_valid_hash(self):
        release_dir = Path(self.temporary.name) / "client-updates"
        release_dir.mkdir()
        package = release_dir / "usage-guard-client-2.000.zip"
        package.write_bytes(b"PK\x03\x04test-package")
        import hashlib
        manifest = {
            "version": "2.000", "minimum_version": "2.000",
            "mandatory": True, "filename": package.name,
            "sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
            "size": package.stat().st_size,
            "published_at": "2026-08-22T08:00:00+00:00",
        }
        (release_dir / "manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8",
        )

        _, result, _ = self.request(
            "/api/v1/agent/update?device_id=pc-test", agent=True,
        )
        self.assertTrue(result["update"]["mandatory"])
        request = Request(
            self.base + "/api/v1/agent/update/package?device_id=pc-test",
            headers={"Authorization": "Bearer " + self.token},
        )
        with urlopen(request, timeout=2) as response:
            self.assertEqual(response.read(), package.read_bytes())

        manifest["sha256"] = "0" * 64
        (release_dir / "manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8",
        )
        _, invalid, _ = self.request(
            "/api/v1/agent/update?device_id=pc-test", agent=True,
        )
        self.assertIsNone(invalid["update"])

    def test_two_devices_are_selected_explicitly_and_credentials_are_isolated(self):
        store = self.server.store
        store.create_user(
            "admin", "personal-admin-password", must_change=False,
            role="admin", email="admin@example.test",
        )
        enrollment = store.create_device_enrollment(
            "admin", device_id="pc-bedroom", label="PC chambre",
        )
        enrolled = store.consume_device_enrollment(
            enrollment["code"], hostname="BEDROOM-PC",
        )
        second_token = enrolled["device_token"]

        status, _, _ = self.request(
            "/api/v1/agent/snapshot", "POST", {
                "device_id": "pc-bedroom", "snapshot": {"marker": "bedroom"},
            }, agent=True, token=second_token,
        )
        self.assertEqual(status, 200)
        with self.assertRaises(HTTPError) as error:
            self.request(
                "/api/v1/agent/snapshot", "POST", {
                    "device_id": "pc-test", "snapshot": {"marker": "wrong"},
                }, agent=True, token=second_token,
            )
        self.assertEqual(error.exception.code, 401)

        _, login, headers = self.request(
            "/api/v1/auth/login", "POST", {
                "username": "admin", "password": "personal-admin-password",
            }, origin=PUBLIC_ORIGIN,
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        _, devices, _ = self.request("/api/v1/devices", cookie=cookie)
        self.assertEqual(
            {item["device_id"] for item in devices["devices"]},
            {"pc-test", "pc-bedroom"},
        )
        _, overview, _ = self.request(
            "/api/v1/overview?device_id=pc-bedroom", cookie=cookie,
        )
        self.assertEqual(overview["marker"], "bedroom")
        status, _, _ = self.request(
            "/api/v1/actions", "POST", {
                "device_id": "pc-bedroom", "action": "reset_limit",
                "target_key": "app:test",
            }, origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"],
        )
        self.assertEqual(status, 202)
        pending = store.pending("pc-bedroom")
        self.assertEqual(pending[0]["action"], "reset_limit")

    def test_remote_action_status_and_cancel_are_scoped_to_the_selected_device(self):
        store = self.server.store
        store.create_user(
            "admin", "personal-admin-password", must_change=False,
            role="admin", email="admin@example.test",
        )
        _, login, headers = self.request(
            "/api/v1/auth/login", "POST", {
                "username": "admin", "password": "personal-admin-password",
            }, origin=PUBLIC_ORIGIN,
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        command = {
            "device_id": "pc-test", "action": "set_limit",
            "target_key": "app:test", "idempotency_key": "route-one-1234",
            "settings": {
                "create_new": True, "target_key": "app:test",
                "enabled": True, "limit_seconds": 600,
            },
        }
        status, queued, _ = self.request(
            "/api/v1/actions", "POST", command,
            origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"],
        )
        self.assertEqual(status, 202)
        status, duplicate, _ = self.request(
            "/api/v1/actions", "POST", {
                **command, "idempotency_key": "route-two-1234",
            }, origin=PUBLIC_ORIGIN, cookie=cookie,
            csrf=login["csrf_token"],
        )
        self.assertEqual(status, 202)
        self.assertTrue(duplicate["reused"])
        self.assertEqual(duplicate["id"], queued["id"])

        status, operation, _ = self.request(
            f"/api/v1/actions/{queued['id']}?device_id=pc-test",
            cookie=cookie,
        )
        self.assertEqual(status, 200)
        self.assertFalse(operation["delivered"])
        self.assertFalse(operation["applied"])

        status, cancelled, _ = self.request(
            f"/api/v1/actions/{queued['id']}/cancel", "POST",
            {"device_id": "pc-test"}, origin=PUBLIC_ORIGIN,
            cookie=cookie, csrf=login["csrf_token"],
        )
        self.assertEqual(status, 200)
        self.assertTrue(cancelled["cancelled"])
        self.assertEqual(store.pending("pc-test"), [])

    def test_missing_email_is_requested_and_saved_during_first_login(self):
        self.request(
            "/api/v1/agent/users", "POST", {
                "device_id": "pc-test", "username": "alice",
                "password": "temporary-strong",
            }, True,
        )
        _, login, headers = self.request(
            "/api/v1/auth/login", "POST", {
                "username": "alice", "password": "temporary-strong",
            }, origin=PUBLIC_ORIGIN,
        )
        self.assertTrue(login["must_set_email"])
        self.assertEqual(login["email"], "")
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        _, changed, headers = self.request(
            "/api/v1/auth/password", "POST", {
                "current_password": "temporary-strong",
                "new_password": "personal-strong-password",
            }, origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"],
        )
        self.assertTrue(changed["must_set_email"])
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        _, profile, _ = self.request(
            "/api/v1/auth/email", "POST", {
                "email": "alice@example.test",
            }, origin=PUBLIC_ORIGIN, cookie=cookie, csrf=changed["csrf_token"],
        )
        self.assertFalse(profile["must_set_email"])
        self.assertEqual(profile["email"], "alice@example.test")

    def test_login_can_fill_a_missing_email_for_the_local_admin_flow(self):
        self.server.store.create_user(
            "admin", "personal-admin-password", must_change=False,
        )
        _, login, _ = self.request(
            "/api/v1/auth/login", "POST", {
                "username": "admin", "password": "personal-admin-password",
                "email": "admin@example.test",
            }, origin=PUBLIC_ORIGIN,
        )
        self.assertEqual(login["email"], "admin@example.test")
        self.assertFalse(login["must_set_email"])

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

    def test_warning_limit_is_reflected_only_with_the_same_action(self):
        command = {
            "action": "set_limit", "target_key": "app:kona",
            "settings": {
                "target_key": "app:kona", "limit_seconds": 600,
                "enforcement_action": "warn",
            },
        }
        blocked_snapshot = {
            "limits": [{
                "key": "app:kona", "target_key": "app:kona",
                "enforcement_action": "block",
            }],
        }
        warning_snapshot = {
            "limits": [{
                "key": "app:kona", "target_key": "app:kona",
                "enforcement_action": "warn",
            }],
        }

        self.assertFalse(Store._limit_command_reflected(
            blocked_snapshot, command,
        ))
        self.assertFalse(Store._limit_command_effect_present(
            blocked_snapshot, command,
        ))
        self.assertTrue(Store._limit_command_reflected(
            warning_snapshot, command,
        ))
        self.assertTrue(Store._limit_command_effect_present(
            warning_snapshot, command,
        ))

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

    def test_analysis_overview_never_reads_legacy_activity_blob(self):
        self.request("/api/v1/agent/snapshot", "POST", {"device_id":"pc-test","snapshot":{"usage":[],"limits":[]}}, True)
        self.server.store.save_activity_store("pc-test", {
            "version": 2,
            "days": {"2026-08-20": {"app:codex": 42}},
            "targets": {"app:codex": {"label": "Codex", "category": "Programmation"}},
            "category_parents": {},
            "category_order": ["Programmation"],
            "target_order": ["app:codex"],
            "navigation_position": {
                "destination": "Programmation", "before": False,
            },
            "unclassified_position": {
                "destination": "Programmation", "before": True,
            },
            "site_categories": [],
        })
        self.request("/api/v1/agent/users", "POST", {"device_id":"pc-test","username":"alice","password":"temporary-strong"}, True)
        _, login, headers = self.request("/api/v1/auth/login", "POST", {"username":"alice","password":"temporary-strong"}, origin=PUBLIC_ORIGIN)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        _, changed, headers = self.request("/api/v1/auth/password", "POST", {"current_password":"temporary-strong","new_password":"personal-strong-password"}, origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"])
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        with patch.object(
            self.server.store, "activity_store",
            side_effect=AssertionError("legacy archive must not be read"),
        ):
            _, analysis, _ = self.request(
                "/api/v1/overview?scope=all", cookie=cookie,
            )

        self.assertEqual(analysis["scope"], "all")
        self.assertEqual(analysis["usage"], [])
        self.assertEqual(analysis["daily_stats"], [])
        self.assertEqual(
            analysis["analysis_coverage"]["source"],
            "normalized-server-aggregates",
        )

    def test_today_overview_never_reads_legacy_blob_when_snapshot_is_missing(self):
        kona_before_midnight = {
            "kind": "active", "key": "app:kona", "label": "Kona",
            "started_at": "2026-08-28T22:09:55+02:00",
            "ended_at": "2026-08-28T22:35:46+02:00",
        }
        kona_after_midnight = {
            "kind": "active", "key": "app:kona", "label": "Kona",
            "started_at": "2026-08-29T00:05:00+02:00",
            "ended_at": "2026-08-29T00:15:00+02:00",
        }
        windows_session = {
            "started_at": "2026-08-28T07:11:08+02:00",
            "ended_at": "2026-08-29T01:33:35+02:00",
        }
        self.server.store.save_activity_store("pc-test", {
            "version": 2,
            "days": {
                "2026-08-28": {"app:kona": 1551},
                "2026-08-29": {"app:kona": 600},
            },
            "targets": {"app:kona": {"label": "Kona"}},
            "sessions": [kona_before_midnight, kona_after_midnight],
            "windows_sessions": [windows_session],
        })
        self.request("/api/v1/agent/users", "POST", {
            "device_id": "pc-test", "username": "alice",
            "password": "temporary-strong",
        }, True)
        _, login, headers = self.request(
            "/api/v1/auth/login", "POST",
            {"username": "alice", "password": "temporary-strong"},
            origin=PUBLIC_ORIGIN,
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        _, _, headers = self.request(
            "/api/v1/auth/password", "POST",
            {
                "current_password": "temporary-strong",
                "new_password": "personal-strong-password",
            },
            origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"],
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        with patch.object(
            self.server.store, "activity_store",
            side_effect=AssertionError("legacy archive must not be read"),
        ):
            _, overview, _ = self.request(
                "/api/v1/overview?scope=today&day=2026-08-29&tz=Europe%2FParis",
                cookie=cookie,
            )

        self.assertEqual(overview["error"], "Aucune donnée reçue")
        self.assertNotIn("sessions", overview)

    def test_analysis_overview_keeps_bounded_snapshot_instead_of_legacy_blob(self):
        self.request("/api/v1/agent/snapshot", "POST", {
            "device_id": "pc-test",
            "snapshot": {"analysis": {
                "scope": "all",
                "daily_stats": [{"date": "2026-08-22", "usage": []}],
                "timeline": {"start": "2026-08-22", "end": "2026-08-27"},
            }},
        }, True)
        self.server.store.save_activity_store("pc-test", {
            "version": 2,
            "days": {
                "2026-08-03": {"app:codex": 42},
                "2026-08-27": {"app:codex": 21},
            },
            "targets": {
                "app:codex": {"label": "Codex", "category": "Programmation"},
            },
            "category_parents": {},
            "category_order": ["Programmation"],
            "target_order": ["app:codex"],
            "site_categories": [],
        })
        self.request("/api/v1/agent/users", "POST", {
            "device_id": "pc-test", "username": "alice",
            "password": "temporary-strong",
        }, True)
        _, login, headers = self.request(
            "/api/v1/auth/login", "POST",
            {"username": "alice", "password": "temporary-strong"},
            origin=PUBLIC_ORIGIN,
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        _, changed, headers = self.request(
            "/api/v1/auth/password", "POST",
            {
                "current_password": "temporary-strong",
                "new_password": "personal-strong-password",
            },
            origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"],
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        with patch.object(
            self.server.store, "activity_store",
            side_effect=AssertionError("legacy archive must not be read"),
        ):
            _, analysis, _ = self.request(
                "/api/v1/overview?scope=all", cookie=cookie,
            )

        self.assertEqual(analysis["timeline"]["start"], "2026-08-22")
        self.assertEqual(
            [item["date"] for item in analysis["daily_stats"]],
            ["2026-08-22"],
        )

    def test_today_and_session_overviews_never_merge_legacy_blob(self):
        old_activity_session = {
            "kind": "active", "key": "app:old", "label": "Old",
            "started_at": "2026-08-19T10:00:00+02:00",
            "ended_at": "2026-08-19T10:00:10+02:00",
        }
        activity_session = {
            "kind": "active", "key": "app:codex", "label": "Codex",
            "started_at": "2026-08-20T10:00:00+02:00",
            "ended_at": "2026-08-20T10:00:42+02:00",
        }
        live_session = {
            "kind": "active", "key": "app:chatgpt", "label": "ChatGPT",
            "started_at": "2026-08-20T11:00:00+02:00",
            "ended_at": None,
        }
        self.server.store.save_activity_store("pc-test", {
            "version": 2,
            "days": {
                "2026-08-19": {"app:old": 10},
                "2026-08-20": {"app:codex": 42},
            },
            "targets": {
                "app:old": {"label": "Old"},
                "app:codex": {"label": "Codex"},
            },
            "sessions": [old_activity_session, activity_session],
        })
        self.request("/api/v1/agent/snapshot", "POST", {
            "device_id": "pc-test",
            "snapshot": {
                "usage": [{"key": "app:chatgpt", "seconds": 60}],
                "limits": [], "sessions": [live_session],
                "daily_stats": [{
                    "date": "2026-08-20", "active": 60,
                    "usage": [{"key": "app:chatgpt", "seconds": 60}],
                }],
            },
        }, True)
        self.request("/api/v1/agent/users", "POST", {
            "device_id": "pc-test", "username": "alice",
            "password": "temporary-strong",
        }, True)
        _, login, headers = self.request(
            "/api/v1/auth/login", "POST",
            {"username": "alice", "password": "temporary-strong"},
            origin=PUBLIC_ORIGIN,
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        _, _, headers = self.request(
            "/api/v1/auth/password", "POST",
            {"current_password": "temporary-strong", "new_password": "personal-strong-password"},
            origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"],
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        with patch.object(
            self.server.store, "activity_store",
            side_effect=AssertionError("legacy archive must not be read"),
        ):
            for scope in ("today", "session"):
                _, overview, _ = self.request(
                    f"/api/v1/overview?scope={scope}&day=2026-08-20&tz=Europe%2FParis",
                    cookie=cookie,
                )
                self.assertEqual(overview["sessions"], [live_session])
                self.assertEqual(len(overview["daily_stats"]), 1)
                self.assertEqual(overview["daily_stats"][0]["active"], 60)

    def test_day_scope_keeps_the_complete_windows_session_across_midnight(self):
        from usage_guard_backend.server import (
            analysis_snapshot_from_activity, snapshot_for_day_scope,
            snapshot_with_activity_history,
        )

        kona_before_midnight = {
            "kind": "active", "key": "app:kona", "label": "Kona",
            "started_at": "2026-08-28T22:09:55+02:00",
            "ended_at": "2026-08-28T22:35:46+02:00",
        }
        kona_after_midnight = {
            "kind": "active", "key": "app:kona", "label": "Kona",
            "started_at": "2026-08-29T00:05:00+02:00",
            "ended_at": "2026-08-29T00:15:00+02:00",
        }
        windows_session = {
            "started_at": "2026-08-28T07:11:08+02:00",
            "ended_at": "2026-08-29T01:33:35+02:00",
        }
        activity = {
            "days": {
                "2026-08-28": {"app:kona": 1551},
                "2026-08-29": {"app:kona": 600},
            },
            "targets": {"app:kona": {"label": "Kona"}},
            "sessions": [kona_before_midnight],
            "windows_sessions": [windows_session],
        }
        merged = snapshot_with_activity_history(
            # The fresh compact snapshot starts after a client restart and
            # therefore knows only the post-midnight interval.
            {"sessions": [kona_after_midnight]},
            activity,
        )

        scoped_before = snapshot_for_day_scope(
            merged, "2026-08-28", "Europe/Paris",
        )
        scoped_after = snapshot_for_day_scope(
            merged, "2026-08-29", "Europe/Paris",
        )

        expected = [kona_before_midnight, kona_after_midnight]
        self.assertEqual(scoped_before["sessions"], expected)
        self.assertEqual(scoped_after["sessions"], expected)
        self.assertEqual(scoped_before["windows_sessions"], [windows_session])
        self.assertEqual(scoped_after["windows_sessions"], [windows_session])
        analysis = analysis_snapshot_from_activity(activity)
        self.assertEqual(
            [day["usage"][0]["seconds"] for day in analysis["daily_stats"]],
            [1551.0, 600.0],
        )
        self.assertEqual(analysis["usage"][0]["seconds"], 2151.0)

    def test_analysis_fallback_keeps_power_and_timeline_events(self):
        from usage_guard_backend.server import analysis_snapshot_from_activity

        activity = {
            "sessions": [{"kind": "active", "started_at": "2026-08-21T10:00:00+02:00", "ended_at": "2026-08-21T10:01:00+02:00"}],
            "windows_sessions": [{"started_at": "2026-08-21T09:00:00+02:00", "ended_at": None}],
            "system_events": [{"type": "sleep", "at": "2026-08-21T12:00:00+02:00"}],
        }

        analysis = analysis_snapshot_from_activity(activity)

        self.assertEqual(analysis["sessions"], activity["sessions"])
        self.assertEqual(analysis["windows_sessions"], activity["windows_sessions"])
        self.assertEqual(analysis["system_events"], activity["system_events"])

    def test_live_other_sites_complete_the_current_server_analysis_day(self):
        from usage_guard_backend.server import analysis_with_live_other_sites

        summary = {
            "daily_stats": [{
                "date": "2026-09-03",
                "usage": [{
                    "key": "site:brave.exe:other-sites", "seconds": 90,
                }],
                "active": 90, "passive": [], "system": {},
                "other_sites": [],
            }],
            "other_sites": [],
        }
        live = {
            "date": "2026-09-03",
            "other_sites": [
                {"browser": "brave.exe", "host": "amazon.fr", "seconds": 55},
                {"browser": "brave.exe", "host": "just4camper.fr", "seconds": 35},
            ],
        }

        merged = analysis_with_live_other_sites(summary, live)

        self.assertEqual(merged["daily_stats"][0]["usage"], summary["daily_stats"][0]["usage"])
        self.assertEqual(merged["daily_stats"][0]["other_sites"], live["other_sites"])
        self.assertEqual(merged["other_sites"], live["other_sites"])

    def test_analysis_snapshot_includes_open_sessions_after_midnight(self):
        from usage_guard_backend.server import analysis_snapshot_from_activity

        activity = {
            "sessions": [],
            "open_sessions": {
                "program:codex": {
                    "id": "program:codex", "kind": "program",
                    "key": "app:codex", "label": "Codex",
                    "started_at": "2026-08-24T23:55:00+02:00",
                },
            },
        }

        analysis = analysis_snapshot_from_activity(activity)

        self.assertEqual(len(analysis["sessions"]), 1)
        self.assertEqual(analysis["sessions"][0]["key"], "app:codex")
        self.assertIsNone(analysis["sessions"][0]["ended_at"])

    def test_analysis_snapshot_never_turns_category_scope_into_a_category(self):
        from usage_guard_backend.server import analysis_snapshot_from_activity

        activity = {
            "category_parents": {"Jeux": "Divertissement"},
            "site_categories": ["Actualité"],
            "targets": {
                "app:game": {"label": "Jeu", "category": "Jeux"},
                "site:brave.exe:bbc.com": {
                    "label": "bbc.com", "category": "__root__",
                    "site_category": "Actualité",
                },
                "site:brave.exe:docs.test": {
                    "label": "docs.test", "category": "Programmation",
                    "category_scope": "site",
                },
            },
        }

        analysis = analysis_snapshot_from_activity(activity)

        self.assertNotIn("site", analysis["categories"])
        self.assertNotIn("Actualité", analysis["top_level_categories"])
        self.assertIn("Programmation", analysis["top_level_categories"])
        self.assertEqual(analysis["site_categories"], ["Actualité"])

    def test_analysis_snapshot_marks_manual_catalog_targets_as_planned(self):
        from usage_guard_backend.server import analysis_snapshot_from_activity

        analysis = analysis_snapshot_from_activity({
            "targets": {
                "app:future": {"label": "Future", "manual": True},
                "app:used": {"label": "Used"},
            },
        })
        candidates = {
            item["key"]: item for item in analysis["merge_candidates"]
        }

        self.assertTrue(candidates["app:future"]["planned"])
        self.assertFalse(candidates["app:used"]["planned"])

    def test_empty_embedded_analysis_never_rebuilds_from_legacy_blob(self):
        self.request("/api/v1/agent/snapshot", "POST", {"device_id":"pc-test","snapshot":{
            "usage": [], "limits": [],
            "analysis": {
                "merge_candidates": [{"key": "app:empty", "label": "Empty"}],
                "daily_stats": [],
                "usage": [],
            },
        }}, True)
        self.server.store.save_activity_store("pc-test", {
            "version": 2,
            "days": {"2026-08-20": {"app:codex": 42}},
            "targets": {"app:codex": {"label": "Codex", "category": "Programmation"}},
            "category_parents": {},
            "category_order": ["Programmation"],
            "site_categories": [],
        })
        self.request("/api/v1/agent/users", "POST", {"device_id":"pc-test","username":"alice","password":"temporary-strong"}, True)
        _, login, headers = self.request("/api/v1/auth/login", "POST", {"username":"alice","password":"temporary-strong"}, origin=PUBLIC_ORIGIN)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        _, changed, headers = self.request("/api/v1/auth/password", "POST", {"current_password":"temporary-strong","new_password":"personal-strong-password"}, origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"])
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        with patch.object(
            self.server.store, "activity_store",
            side_effect=AssertionError("legacy archive must not be read"),
        ):
            _, analysis, _ = self.request(
                "/api/v1/overview?scope=all", cookie=cookie,
            )

        self.assertEqual(analysis["daily_stats"], [])
        self.assertEqual(analysis["merge_candidates"][0]["label"], "Empty")

    def test_legacy_activity_transport_is_gone_without_persisting_a_body(self):
        activity = {
            "version": 2,
            "days": {"2026-08-13": {"app:potplayermini64": 42}},
            "app_limit_settings": {"app:potplayermini64": {"enabled": True, "limit_seconds": 3600}},
            "excluded": ["app:ignored"],
        }
        with self.assertRaises(HTTPError) as get_error:
            self.request(
                "/api/v1/agent/activity?device_id=pc-test", agent=True,
            )
        with self.assertRaises(HTTPError) as post_error:
            self.request(
                "/api/v1/agent/activity", "POST",
                {"device_id": "pc-test", "activity": activity}, True,
            )

        self.assertEqual(get_error.exception.code, 410)
        self.assertEqual(post_error.exception.code, 410)
        self.assertIsNone(self.server.store.activity_store("pc-test"))

    def test_legacy_live_only_activity_upload_preserves_catalog_and_history(self):
        activity = {
            "version": 2,
            "days": {"2026-08-29": {"app:codex": 3600}},
            "targets": {"app:codex": {
                "label": "Codex", "category": "Programmation",
            }},
            "category_order": ["Programmation"],
            "sessions": [{
                "id": "closed", "started_at": "2026-08-29T08:00:00+00:00",
                "ended_at": "2026-08-29T09:00:00+00:00",
            }],
            "open_sessions": {"active": {
                "id": "active", "started_at": "2026-08-29T09:00:00+00:00",
            }},
        }
        self.server.store.save_activity_store(
            "pc-test", activity, complete=True,
        )
        partial_merged = self.server.store.save_activity_store(
            "pc-test", {"open_sessions": {}}, complete=None,
        )
        restored = self.server.store.activity_store("pc-test")["activity"]

        self.assertTrue(partial_merged)
        self.assertEqual(restored["days"], activity["days"])
        self.assertEqual(restored["targets"], activity["targets"])
        self.assertEqual(
            restored["category_order"], ["Programmation"],
        )
        self.assertEqual(restored["sessions"], activity["sessions"])
        self.assertEqual(restored["open_sessions"], {})

    def test_legacy_delta_cannot_reduce_rich_activity_to_live_only_state(self):
        activity = {
            "version": 2,
            "days": {"2026-08-29": {"app:codex": 3600}},
            "targets": {"app:codex": {
                "label": "Codex", "category": "Programmation",
            }},
            "category_order": ["Programmation"],
            "open_sessions": {"active": {"started_at": "2026-08-29T09:00:00+00:00"}},
        }
        reduced = {"open_sessions": {}}
        self.server.store.save_activity_store(
            "pc-test", activity, complete=True,
        )

        with self.assertRaises(DocumentConflict):
            self.server.store.patch_activity_store(
                "pc-test", {
                    "kind": "dict",
                    "remove": [
                        "version", "days", "targets", "category_order",
                    ],
                    "set": {"open_sessions": {}}, "patch": {},
                },
                json_hash(activity), json_hash(reduced), complete=None,
            )
        self.assertEqual(
            self.server.store.activity_store("pc-test")["activity"], activity,
        )

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
        self.server.store.save_activity_store("pc-test", activity)
        self.server.store.patch_activity_store(
            "pc-test", delta, json_hash(activity), json_hash(updated),
        )
        restored = self.server.store.activity_store("pc-test")["activity"]
        self.assertEqual(restored, updated)

    def test_activity_delta_conflict_returns_409(self):
        activity = {"version": 2, "days": {}, "app_limit_settings": {}}
        self.server.store.save_activity_store("pc-test", activity)
        with self.assertRaises(DocumentConflict):
            self.server.store.patch_activity_store(
                "pc-test", {
                    "kind": "dict", "remove": [],
                    "set": {"version": 3}, "patch": {},
                }, "stale", json_hash({
                    "version": 3, "days": {}, "app_limit_settings": {},
                }),
            )

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

    def test_access_change_notification_names_role_rights_and_computers(self):
        self.server.store.update_device_notification_policy(
            "pc-test", "set_notification_rule", {
                "id": "access-rule", "kind": "access_change",
                "enabled": True, "channels": ["windows"],
            },
        )
        before = {
            "username": "nicklaus", "role": "limited",
            "permissions": {key: False for key in (
                "view_activity", "view_analysis", "view_limits",
                "view_notifications", "manage_activity", "manage_limits",
                "manage_notifications",
            )},
            "accessible_device_ids": ["pc-test"],
        }
        after = {
            **before, "role": "user",
            "permissions": {**before["permissions"], "view_limits": True,
                            "manage_notifications": True},
            "accessible_device_ids": [],
        }

        queued = self.server._dispatch_access_change(before, after, "admin")
        command = self.server.store.pending("pc-test")[0]

        self.assertTrue(queued)
        self.assertEqual(command["action"], "notify_access_change")
        self.assertIn("nicklaus", command["title"])
        self.assertIn("Utilisateur à limiter → Utilisateur", command["message"])
        self.assertIn("voir les limitations", command["message"])
        self.assertIn("créer et modifier les notifications", command["message"])
        self.assertIn("Ordinateurs retirés : pc-test", command["message"])

    def test_access_change_without_effective_difference_is_not_queued(self):
        user = {
            "username": "nicklaus", "role": "limited",
            "permissions": {"view_activity": True},
            "accessible_device_ids": ["pc-test"],
        }
        self.assertFalse(
            self.server._dispatch_access_change(user, dict(user), "admin")
        )
        self.assertEqual(self.server.store.pending("pc-test"), [])

    def test_admin_access_endpoint_dispatches_the_configured_change_event(self):
        self.server.store.create_user(
            "admin", "personal-admin-password", must_change=False,
            email="admin@example.test", role="admin",
        )
        self.server.store.create_user(
            "viewer", "personal-viewer-password", must_change=False,
            email="viewer@example.test", role="limited",
            device_ids=["pc-test"],
        )
        self.server.store.update_device_notification_policy(
            "pc-test", "set_notification_rule", {
                "id": "access-rule", "kind": "access_change",
                "enabled": True, "channels": ["windows"],
            },
        )
        _, login, headers = self.request(
            "/api/v1/auth/login", "POST",
            {"username": "admin", "password": "personal-admin-password"},
            origin=PUBLIC_ORIGIN,
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        self.request(
            "/api/v1/admin/users/viewer/access", "POST", {
                "role": "user", "is_admin": False,
                "permissions": {"manage_limits": True},
                "device_ids": ["pc-test"],
            }, origin=PUBLIC_ORIGIN, cookie=cookie,
            csrf=login["csrf_token"],
        )

        command = self.server.store.pending("pc-test")[0]
        self.assertEqual(command["action"], "notify_access_change")
        self.assertIn("admin", command["title"])
        self.assertIn("créer et modifier les limitations", command["message"])

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
        self.assertEqual(calls[0][3], "pwa_login")
        _, pending, _ = self.request(
            "/api/v1/agent/commands?device_id=pc-test", agent=True,
        )
        self.assertEqual(pending["commands"], [])

    def test_login_notification_filters_roles_and_excludes_rule_owner(self):
        self.request(
            "/api/v1/agent/snapshot", "POST",
            {"device_id": "pc-test", "snapshot": {
                "notification_rules": [{
                    "kind": "pwa_login", "enabled": True,
                    "owner": "owner", "login_role_scope": "users",
                }],
            }}, True,
        )
        self.request(
            "/api/v1/agent/users", "POST",
            {"device_id": "pc-test", "username": "owner", "password": "temporary-strong"},
            True,
        )
        self.request(
            "/api/v1/agent/users", "POST",
            {"device_id": "pc-test", "username": "alice", "password": "temporary-strong"},
            True,
        )
        self.request(
            "/api/v1/auth/login", "POST",
            {"username": "owner", "password": "temporary-strong"},
            origin=PUBLIC_ORIGIN,
        )
        self.request(
            "/api/v1/auth/login", "POST",
            {"username": "alice", "password": "temporary-strong"},
            origin=PUBLIC_ORIGIN,
        )

        _, pending, _ = self.request(
            "/api/v1/agent/commands?device_id=pc-test", agent=True,
        )
        self.assertEqual(len(pending["commands"]), 1)
        self.assertEqual(pending["commands"][0]["actor"], "alice")
        self.assertFalse(pending["commands"][0]["actor_is_admin"])

    def test_admin_login_matches_admin_notification_scope(self):
        self.request(
            "/api/v1/agent/snapshot", "POST",
            {"device_id": "pc-test", "snapshot": {
                "notification_rules": [{
                    "kind": "pwa_login", "enabled": True,
                    "owner": "owner", "login_role_scope": "admins",
                }],
            }}, True,
        )
        self.request(
            "/api/v1/agent/users", "POST",
            {"device_id": "pc-test", "username": "owner", "password": "temporary-strong"},
            True,
        )
        self.request(
            "/api/v1/agent/users", "POST",
            {
                "device_id": "pc-test", "username": "second-admin",
                "password": "temporary-strong", "is_admin": True,
            }, True,
        )
        self.request(
            "/api/v1/auth/login", "POST",
            {"username": "second-admin", "password": "temporary-strong"},
            origin=PUBLIC_ORIGIN,
        )

        _, pending, _ = self.request(
            "/api/v1/agent/commands?device_id=pc-test", agent=True,
        )
        self.assertEqual(pending["commands"][0]["actor"], "second-admin")
        self.assertTrue(pending["commands"][0]["actor_is_admin"])

    def test_device_token_cannot_read_create_promote_or_delete_users(self):
        self.seed_agent_users = False
        for path, method, payload in (
            ("/api/v1/agent/users?device_id=pc-test", "GET", None),
            ("/api/v1/agent/users", "POST", {"device_id": "pc-test", "username": "root", "password": "temporary-strong", "is_admin": True}),
            ("/api/v1/agent/users/alice/access", "POST", {"device_id": "pc-test", "is_admin": True}),
            ("/api/v1/agent/users/alice?device_id=pc-test", "DELETE", None),
        ):
            with self.assertRaises(HTTPError) as error:
                self.request(path, method, payload, agent=True)
            self.assertEqual(error.exception.code, 403)
        self.assertEqual(self.server.store.list_users(), [])

    def test_admin_session_can_manage_users_without_reusing_device_secret(self):
        self.server.store.create_user(
            "admin", "personal-admin-password", must_change=False,
            role="admin", email="admin@example.test",
        )
        _, login, headers = self.request(
            "/api/v1/auth/login", "POST", {
                "username": "admin", "password": "personal-admin-password",
            }, origin=PUBLIC_ORIGIN,
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        status, created, _ = self.request(
            "/api/v1/admin/users", "POST", {
                "username": "child", "password": "temporary-strong",
                "role": "limited", "device_ids": ["pc-test"],
            }, origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"],
        )
        self.assertEqual(status, 201)
        self.assertFalse(created["user"]["is_admin"])
        status, _, _ = self.request(
            "/api/v1/admin/users/child", "DELETE",
            origin=PUBLIC_ORIGIN, cookie=cookie, csrf=login["csrf_token"],
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [user["username"] for user in self.server.store.list_users()],
            ["admin"],
        )

    def test_admin_can_restrict_views_and_modifications(self):
        self.request("/api/v1/agent/snapshot", "POST", {"device_id":"pc-test","snapshot":{"usage":[],"merge_candidates":[{"key":"app:unused","label":"Unused"}],"sessions":[{"started_at":"2026-08-20T10:00:00+02:00"}],"limits":[{"key":"app:test","target_key":"app:test","label":"Test"}]}}, True)
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
        _, catalog, _ = self.request("/api/v1/overview?scope=catalog", cookie=viewer_cookie)
        self.assertEqual(catalog["scope"], "catalog")
        self.assertIn("usage", catalog)
        self.assertEqual(catalog["merge_candidates"][0]["key"], "app:unused")
        self.assertNotIn("sessions", catalog)
        self.assertNotIn("daily_stats", catalog)
        self.assertNotIn("limits", catalog)
        self.assertNotIn("notification_rules", catalog)
        permissions["view_limits"] = True
        self.request("/api/v1/admin/users/viewer/access", "POST", {"is_admin":False,"permissions":permissions}, origin=PUBLIC_ORIGIN, cookie=admin_cookie, csrf=changed["csrf_token"])
        _, viewer, headers = self.request("/api/v1/auth/login", "POST", {"username":"viewer","password":"personal-viewer-password"}, origin=PUBLIC_ORIGIN)
        viewer_cookie = headers["Set-Cookie"].split(";", 1)[0]
        _, limits, _ = self.request("/api/v1/overview?scope=limits", cookie=viewer_cookie)
        self.assertEqual(limits["limits"][0]["key"], "app:test")
        with self.assertRaises(HTTPError) as error:
            self.request("/api/v1/overview?scope=all", cookie=viewer_cookie)
        self.assertEqual(error.exception.code, 403)
        with self.assertRaises(HTTPError) as error:
            self.request("/api/v1/actions", "POST", {"action":"rename_target"}, origin=PUBLIC_ORIGIN, cookie=viewer_cookie, csrf=viewer_changed["csrf_token"])
        self.assertEqual(error.exception.code, 403)

    def test_limited_user_can_classify_activity_and_manage_notifications(self):
        self.request(
            "/api/v1/agent/users", "POST", {
                "device_id": "pc-test", "username": "admin",
                "password": "temporary-admin", "role": "admin",
            }, True,
        )
        self.request(
            "/api/v1/agent/users", "POST", {
                "device_id": "pc-test", "username": "limited-user",
                "password": "temporary-limited", "role": "limited",
                "permissions": {
                    "manage_activity": True,
                    "manage_limits": True,
                    "manage_notifications": True,
                },
            }, True,
        )
        _, login, headers = self.request(
            "/api/v1/auth/login", "POST", {
                "username": "limited-user",
                "password": "temporary-limited",
            }, origin=PUBLIC_ORIGIN,
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        _, changed, headers = self.request(
            "/api/v1/auth/password", "POST", {
                "current_password": "temporary-limited",
                "new_password": "personal-limited-password",
            }, origin=PUBLIC_ORIGIN, cookie=cookie,
            csrf=login["csrf_token"],
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        self.assertTrue(changed["permissions"]["manage_activity"])
        self.assertTrue(changed["permissions"]["manage_notifications"])
        self.assertTrue(changed["permissions"]["manage_limits"])

        status, _, _ = self.request(
            "/api/v1/actions", "POST", {
                "action": "set_category", "target_key": "app:test",
                "category": "Travail",
            }, origin=PUBLIC_ORIGIN, cookie=cookie,
            csrf=changed["csrf_token"],
        )
        self.assertEqual(status, 202)
        status, _, _ = self.request(
            "/api/v1/actions", "POST", {
                "action": "set_notification_rule",
                "rule": {"id": "limited-rule", "kind": "usage_threshold"},
            }, origin=PUBLIC_ORIGIN, cookie=cookie,
            csrf=changed["csrf_token"],
        )
        self.assertEqual(status, 202)
        status, _, _ = self.request(
            "/api/v1/actions", "POST", {
                "action": "set_notification_rule",
                "rule": {
                    "id": "limited-rule", "kind": "usage_threshold",
                    "description": "Notification modifiée", "enabled": False,
                },
            }, origin=PUBLIC_ORIGIN, cookie=cookie,
            csrf=changed["csrf_token"],
        )
        self.assertEqual(status, 202)
        saved_rule = next(
            rule for rule in self.server.store.device_notification_rules(
                "pc-test",
            )
            if rule["id"] == "limited-rule"
        )
        self.assertEqual(saved_rule["description"], "Notification modifiée")
        self.assertFalse(saved_rule["enabled"])
        status, _, _ = self.request(
            "/api/v1/actions", "POST", {
                "action": "set_limit", "target_key": "app:test",
                "limit_seconds": 3600,
            }, origin=PUBLIC_ORIGIN, cookie=cookie,
            csrf=changed["csrf_token"],
        )
        self.assertEqual(status, 202)

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
            self.assertEqual(users[0]["email"], "")
            self.assertTrue(users[0]["must_set_email"])

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
