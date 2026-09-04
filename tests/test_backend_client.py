import unittest
import json
import threading
import time
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from command_policy import COMMAND_SOURCE_FIELD, SOURCE_BACKEND

from backend_client import (
    BackendClient, _bounded_json_batches, _json_hash, activity_intervals_by_sid,
    live_activity_intervals,
)


class BackendClientTest(unittest.TestCase):
    def test_compact_batches_are_bounded_by_count_and_encoded_bytes(self):
        records = [
            {"record_id": f"timeline-{index:064x}", "label": "x" * 2000}
            for index in range(600)
        ]

        batches = list(_bounded_json_batches(records))

        self.assertGreater(len(batches), 2)
        self.assertTrue(all(len(batch) <= 500 for batch in batches))
        self.assertTrue(all(
            len(json.dumps(
                batch, ensure_ascii=False, separators=(",", ":"),
            ).encode("utf-8")) <= 512 * 1024
            for batch in batches
        ))

    def test_closed_mapped_active_sessions_become_stable_intervals(self):
        session = {
            "id": "active:app:test", "kind": "active",
            "key": "app:test", "category": "Programmation",
            "category_lineage": ["Programmation", "Travail"],
            "started_at": "2026-08-24T08:00:00+02:00",
            "ended_at": "2026-08-24T08:01:00+02:00",
            "windows_sid": "S-1-5-21-1-2-3-1001",
            "windows_identity_mapped": True,
            "windows_session_id": 2, "policy_revision": 3,
        }
        groups = activity_intervals_by_sid({
            "sessions": [
                session,
                {**session, "id": "active:app:open", "ended_at": None},
                {**session, "id": "active:app:unknown",
                 "windows_identity_mapped": False},
                {**session, "id": "program:app:test", "kind": "program"},
            ],
        })

        self.assertEqual(list(groups), ["S-1-5-21-1-2-3-1001"])
        self.assertEqual(len(groups["S-1-5-21-1-2-3-1001"]), 1)
        interval = groups["S-1-5-21-1-2-3-1001"][0]
        self.assertTrue(interval["interval_id"].startswith("activity-"))
        self.assertEqual(interval["category_key"], "Programmation")
        self.assertEqual(
            interval["category_keys"], ["Programmation", "Travail"]
        )
        self.assertEqual(interval["policy_revision"], 3)

    def test_legacy_activity_provider_is_never_scanned_or_uploaded(self):
        activity = {"days": {}, "sessions": [{
            "id": "active:app:test", "kind": "active",
            "key": "app:test", "category": "Travail",
            "started_at": "2026-08-24T08:00:00+02:00",
            "ended_at": "2026-08-24T08:01:00+02:00",
            "windows_sid": "S-1-5-21-1-2-3-1001",
            "windows_identity_mapped": True, "policy_revision": 1,
        }]}
        client = BackendClient(
            lambda: {"error": "not ready"}, lambda _: {}, {
                "enabled": True,
                "base_url": "https://example.test/usage-guard",
                "device_id": "pc-test", "device_token": "x" * 40,
            },
        )
        calls = []
        client._request = lambda method, path, payload=None: (
            calls.append((method, path, payload)) or {"ok": True}
        )

        client._publish_state()
        client._publish_state()

        uploads = [
            call for call in calls
            if call[1] == "/api/v1/agent/activity/intervals"
        ]
        self.assertEqual(uploads, [])

    def test_compact_outbox_uploads_usage_and_timeline_without_activity_store(self):
        sid = "S-1-5-21-1-2-3-1001"
        session = {
            "record_id": "timeline-" + "a" * 64,
            "interval_id": "activity-" + "b" * 64,
            "id": "active:app:test", "kind": "active",
            "target_key": "app:test", "category_key": "Programmation",
            "category_keys": ["Programmation"],
            "started_at": "2026-08-29T23:55:00+02:00",
            "ended_at": "2026-08-30T00:05:00+02:00",
            "windows_sid": sid, "policy_revision": 4,
        }
        pending_usage = {session["interval_id"]}
        pending_timeline = {session["record_id"]}
        uploads = []
        settings = {
            "enabled": True,
            "base_url": "https://example.test/usage-guard",
            "device_id": "pc-test", "device_token": "x" * 40,
        }
        client = BackendClient(
            lambda: {"usage": []}, lambda _: {}, settings,
            interval_provider=lambda: ({sid: [session]} if pending_usage else {}),
            interval_acknowledger=lambda ids: pending_usage.difference_update(ids),
            timeline_provider=lambda: ({sid: [session]} if pending_timeline else {}),
            timeline_acknowledger=lambda ids: pending_timeline.difference_update(ids),
            live_interval_provider=lambda: [],
        )

        def request(method, path, payload=None):
            uploads.append((method, path, payload))
            return {"commands": []} if path.startswith(
                "/api/v1/agent/commands"
            ) else {"ok": True}

        client._request = request
        client._sync()
        client._sync()

        self.assertEqual(sum(
            call[1] == "/api/v1/agent/activity/intervals" for call in uploads
        ), 1)
        self.assertEqual(sum(
            call[1] == "/api/v1/agent/activity/timeline" for call in uploads
        ), 1)
        self.assertFalse(any(
            call[1] == "/api/v1/agent/activity" for call in uploads
        ))

    def test_daily_aggregate_provider_is_acked_without_raw_history(self):
        aggregate = {
            "aggregate_id": "daily-v1-" + "a" * 64,
            "local_day": "2026-08-03",
            "metrics": [{
                "kind": "usage", "key": "app:kona", "seconds": 3600.0,
            }],
        }
        pending = {aggregate["aggregate_id"]}
        calls = []
        client = BackendClient(
            lambda: {"usage": []}, lambda _: {}, {
                "enabled": True,
                "base_url": "https://example.test/usage-guard",
                "device_id": "pc-test", "device_token": "x" * 40,
            },
            daily_aggregate_provider=lambda: (
                {"": [aggregate]} if pending else {}
            ),
            daily_aggregate_acknowledger=(
                lambda ids, _sid: pending.difference_update(ids)
            ),
        )

        def request(method, path, payload=None):
            calls.append((method, path, payload))
            if path == "/api/v1/agent/activity/daily-aggregates":
                self.assertNotIn("sessions", json.dumps(payload))
                return {"accepted_ids": [aggregate["aggregate_id"]]}
            return {"ok": True}

        client._request = request
        client._publish_compact_activity()
        client._publish_compact_activity()

        uploads = [
            call for call in calls
            if call[1] == "/api/v1/agent/activity/daily-aggregates"
        ]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(uploads[0][2]["schema_version"], 1)
        self.assertEqual(pending, set())

    def test_old_server_404_retries_after_backoff_and_drains_without_restart(self):
        sid = "S-1-5-21-1-2-3-1001"
        session = {
            "record_id": "timeline-" + "a" * 64,
            "kind": "program", "id": "program:kona", "key": "app:kona",
            "label": "Kona", "category": "Jeux",
            "category_lineage": ["Jeux"],
            "started_at": "2026-08-30T00:00:00+02:00",
            "ended_at": "2026-08-30T00:05:00+02:00",
        }
        acked = []
        client = BackendClient(
            lambda: {"usage": []}, lambda _: {}, {
                "enabled": True, "base_url": "https://example.test/usage-guard",
                "device_id": "pc-test", "device_token": "x" * 40,
            },
            timeline_provider=lambda: {sid: [session]},
            timeline_acknowledger=lambda ids: acked.extend(ids),
        )
        calls = []
        server_available = False

        def request(method, path, payload=None):
            calls.append((method, path, payload))
            if (
                path == "/api/v1/agent/activity/timeline"
                and not server_available
            ):
                raise HTTPError(path, 404, "old server", {}, None)
            return {"commands": []} if path.startswith(
                "/api/v1/agent/commands"
            ) else {"ok": True}

        client._request = request
        with patch("backend_client.time.monotonic", return_value=100):
            client._sync()
            client._sync()

        self.assertEqual(sum(
            call[1] == "/api/v1/agent/activity/timeline" for call in calls
        ), 1)
        self.assertEqual(acked, [])
        server_available = True
        with patch("backend_client.time.monotonic", return_value=399):
            client._sync()
        self.assertEqual(sum(
            call[1] == "/api/v1/agent/activity/timeline" for call in calls
        ), 1)
        with patch("backend_client.time.monotonic", return_value=400):
            client._sync()
        self.assertEqual(sum(
            call[1] == "/api/v1/agent/activity/timeline" for call in calls
        ), 2)
        self.assertEqual(acked, [session["record_id"]])

    def test_non_positive_or_naive_closed_intervals_are_not_uploaded(self):
        session = {
            "id": "active:app:test", "kind": "active", "key": "app:test",
            "started_at": "2026-08-24T08:01:00+02:00",
            "ended_at": "2026-08-24T08:01:00+02:00",
            "windows_sid": "S-1-5-21-1-2-3-1001",
            "windows_identity_mapped": True, "policy_revision": 1,
        }

        groups = activity_intervals_by_sid({"sessions": [
            session,
            {**session, "id": "negative",
             "ended_at": "2026-08-24T08:00:00+02:00"},
            {**session, "id": "naive", "started_at": "2026-08-24T08:00:00",
             "ended_at": "2026-08-24T08:01:00"},
            {**session, "id": "invalid", "started_at": "not-a-date"},
        ]})

        self.assertEqual(groups, {})

    def test_open_mapped_activity_becomes_a_bounded_live_interval(self):
        intervals = live_activity_intervals({"sessions": [{
            "id": "active:app:test", "kind": "active", "key": "app:test",
            "category": "Programmation",
            "category_lineage": ["Programmation", "Travail"],
            "started_at": "2026-08-24T08:00:00+02:00", "ended_at": None,
            "windows_sid": "S-1-5-21-1-2-3-1001",
            "windows_identity_mapped": True, "windows_session_id": 2,
            "policy_revision": 3,
        }]}, observed_at="2026-08-24T08:02:00+02:00")

        self.assertEqual(len(intervals), 1)
        self.assertTrue(intervals[0]["live_id"].startswith("live-"))
        self.assertEqual(
            intervals[0]["observed_at"], "2026-08-24T08:02:00+02:00"
        )
        self.assertEqual(intervals[0]["category_keys"], [
            "Programmation", "Travail",
        ])

    def test_open_session_store_is_used_for_live_activity(self):
        session = {
            "id": "active:app:test", "kind": "active", "key": "app:test",
            "started_at": "2026-08-24T08:00:00+02:00", "ended_at": None,
            "windows_sid": "S-1-5-21-1-2-3-1001",
            "windows_identity_mapped": True, "policy_revision": 1,
        }

        intervals = live_activity_intervals({
            "sessions": [], "open_sessions": {"active:app:test": session},
        }, observed_at="2026-08-24T08:02:00+02:00")

        self.assertEqual(len(intervals), 1)
        self.assertEqual(intervals[0]["target_key"], "app:test")

    def test_local_admin_authentication_uses_public_backend_origin(self):
        client = BackendClient(lambda: {}, lambda _: {}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        })

        class Response:
            headers = {"Set-Cookie": "ug_session=server-session; Secure; HttpOnly"}
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return json.dumps({
                    "username": "admin", "is_admin": True,
                    "csrf_token": "server-csrf",
                }).encode("utf-8")

        with patch("backend_client.urlopen", return_value=Response()) as opened:
            user = client.authenticate_user(
                "admin", "secret-password", "admin@example.test",
            )

        request = opened.call_args.args[0]
        self.assertEqual(request.full_url, "https://example.test/usage-guard/api/v1/auth/login")
        self.assertEqual(request.get_header("Origin"), "https://example.test")
        self.assertIsNone(request.get_header("Authorization"))
        self.assertEqual(
            json.loads(request.data.decode("utf-8"))["email"],
            "admin@example.test",
        )
        self.assertTrue(user["is_admin"])
        self.assertEqual(
            user["_backend_management_session"]["cookie"],
            "ug_session=server-session",
        )

    def test_requires_https_and_long_device_token(self):
        common = {"enabled": True, "device_id": "pc", "device_token": "x" * 40}
        self.assertFalse(BackendClient(lambda: {}, lambda _: {}, {**common, "base_url": "http://example.test"}).configured)
        self.assertTrue(BackendClient(lambda: {}, lambda _: {}, {**common, "base_url": "http://127.0.0.1:8767/usage-guard"}).configured)
        self.assertTrue(BackendClient(lambda: {}, lambda _: {}, {**common, "base_url": "https://example.test/usage-guard"}).configured)
        self.assertFalse(BackendClient(lambda: {}, lambda _: {}, {**common, "base_url": "https://example.test", "device_token": "short"}).configured)

    def test_request_rejects_an_invalid_backend_configuration(self):
        client = BackendClient(lambda: {}, lambda _: {}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "file:///tmp/not-a-backend",
        })
        with self.assertRaises(RuntimeError):
            client._request("GET", "/api/v1/overview")

    def test_personal_policy_transport_is_scoped_to_this_device_and_sid(self):
        client = BackendClient(lambda: {}, lambda _: {}, {
            "enabled": True, "device_id": "pc-test",
            "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        })
        calls = []
        client._request = lambda method, path, payload=None: (
            calls.append((method, path, payload))
            or ({"revision": 3} if method == "GET" else {
                "policy": {"revision": 3}
            })
        )

        fetched = client.user_policy("s-1-5-21-1-2-3-1001")
        acknowledged = client.acknowledge_user_policy(
            "s-1-5-21-1-2-3-1001", 3, {"ok": True},
        )
        pushed = client.push_user_policy_action(
            "s-1-5-21-1-2-3-1001",
            {"action": "remove_limit", "target_key": "app:test"},
            "local-operation-1", "admin",
        )

        self.assertEqual(fetched["revision"], 3)
        self.assertIn("device_id=pc-test", calls[0][1])
        self.assertIn("windows_sid=S-1-5-21-1-2-3-1001", calls[0][1])
        self.assertEqual(calls[1][1], "/api/v1/agent/policy/ack")
        self.assertEqual(calls[1][2]["device_id"], "pc-test")
        self.assertEqual(calls[1][2]["revision"], 3)
        self.assertEqual(acknowledged["revision"], 3)
        self.assertEqual(calls[2][1], "/api/v1/agent/policy/actions")
        self.assertEqual(calls[2][2]["device_id"], "pc-test")
        self.assertEqual(
            calls[2][2]["windows_sid"], "S-1-5-21-1-2-3-1001",
        )
        self.assertEqual(calls[2][2]["idempotency_key"], "local-operation-1")
        self.assertTrue(pushed["policy"])

    def test_activity_interval_transport_includes_device_and_sid(self):
        client = BackendClient(lambda: {}, lambda _: {}, {
            "enabled": True, "base_url": "https://example.test/usage-guard",
            "device_id": "pc-test", "device_token": "x" * 40,
        })
        calls = []
        client._request = lambda method, path, payload=None: (
            calls.append((method, path, payload)) or {
                "ok": True, "accepted": 1, "duplicates": 0,
            }
        )
        intervals = [{
            "interval_id": "interval-0001", "target_key": "app:test",
            "started_at": "2026-08-24T08:00:00+02:00",
            "ended_at": "2026-08-24T08:01:00+02:00",
            "policy_revision": 1,
        }]

        result = client.upload_activity_intervals(
            "s-1-5-21-1-2-3-1001", intervals,
        )

        self.assertEqual(result["accepted"], 1)
        self.assertEqual(calls[0][0:2], (
            "POST", "/api/v1/agent/activity/intervals",
        ))
        self.assertEqual(calls[0][2]["device_id"], "pc-test")
        self.assertEqual(
            calls[0][2]["windows_sid"], "S-1-5-21-1-2-3-1001",
        )

    def test_daily_aggregate_transport_is_compact_and_versioned(self):
        client = BackendClient(lambda: {}, lambda _: {}, {
            "enabled": True, "base_url": "https://example.test/usage-guard",
            "device_id": "pc-test", "device_token": "x" * 40,
        })
        calls = []
        client._request = lambda method, path, payload=None: (
            calls.append((method, path, payload)) or {
                "ok": True, "accepted_ids": ["daily-v1:2026-08-03:test"],
            }
        )
        aggregates = [{
            "aggregate_id": "daily-v1:2026-08-03:test",
            "local_day": "2026-08-03",
            "metrics": [{
                "kind": "usage", "key": "app:codex", "seconds": 60,
            }],
        }]

        result = client.upload_activity_daily_aggregates(
            aggregates, "s-1-5-21-1-2-3-1001",
        )

        self.assertEqual(result["accepted_ids"], [aggregates[0]["aggregate_id"]])
        self.assertEqual(calls[0][0:2], (
            "POST", "/api/v1/agent/activity/daily-aggregates",
        ))
        self.assertEqual(calls[0][2]["schema_version"], 1)
        self.assertEqual(calls[0][2]["aggregates"], aggregates)
        self.assertNotIn("activity", calls[0][2])

    def test_union_query_is_scoped_to_device_sid_and_target(self):
        client = BackendClient(lambda: {}, lambda _: {}, {
            "enabled": True, "base_url": "https://example.test/usage-guard",
            "device_id": "pc-test", "device_token": "x" * 40,
        })
        calls = []
        client._request = lambda method, path, payload=None: (
            calls.append((method, path, payload)) or {"seconds": 300}
        )

        result = client.user_usage_union(
            "s-1-5-21-1-2-3-1001",
            "2026-08-24T00:00:00+02:00",
            "2026-08-25T00:00:00+02:00",
            target_key="category:Internet",
        )

        self.assertEqual(result["seconds"], 300)
        self.assertEqual(calls[0][0], "GET")
        self.assertIn("device_id=pc-test", calls[0][1])
        self.assertIn("windows_sid=S-1-5-21-1-2-3-1001", calls[0][1])
        self.assertIn("target_key=category%3AInternet", calls[0][1])

    def test_user_methods_use_admin_session_endpoints_without_device_token(self):
        client = BackendClient(lambda: {}, lambda _: {}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        })
        calls = []
        client._management_request = lambda session, method, path, payload=None: calls.append((session, method, path, payload)) or {"ok": True}
        management = {"cookie": "ug_session=x", "csrf_token": "csrf"}
        client.list_users(management)
        client.create_user(
            "alice", "password-long", "alice@example.test", True,
            {"view_activity": True}, management_session=management,
        )
        client.delete_user("alice test", management)
        client.update_user_access("alice test", True, {"view_activity": True}, management_session=management)
        client.rename_device("ordinateur-principal", management)
        self.assertEqual(calls[0][1:3], ("GET", "/api/v1/admin/users"))
        self.assertNotIn("device_id", calls[1][3])
        self.assertEqual(calls[1][3]["email"], "alice@example.test")
        self.assertTrue(calls[1][3]["is_admin"])
        self.assertIn("alice%20test", calls[2][2])
        self.assertEqual(calls[3][1], "POST")
        self.assertEqual(calls[3][2], "/api/v1/admin/users/alice%20test/access")
        self.assertTrue(calls[3][3]["is_admin"])
        self.assertEqual(calls[4][1], "POST")
        self.assertEqual(calls[4][2], "/api/v1/admin/devices/pc/rename")
        self.assertEqual(calls[4][3]["label"], "ordinateur-principal")

    def test_notification_management_uses_the_authenticated_multi_pc_scope(self):
        client = BackendClient(lambda: {}, lambda _: {}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        })
        calls = []
        client._management_request = (
            lambda session, method, path, payload=None:
            calls.append((session, method, path, payload)) or {"ok": True}
        )
        management = {"cookie": "ug_session=x", "csrf_token": "csrf"}

        client.session_devices(management)
        client.policy_users(management)
        client.notification_overview("admin local", "pc-2", management)
        client.notification_action({
            "action": "set_notification_rule",
            "rule": {
                "id": "admin-rule", "owner": "admin local",
                "description": "Message modifié",
            },
        }, "pc-2", management)

        self.assertEqual(calls[0][1:3], ("GET", "/api/v1/devices"))
        self.assertEqual(calls[1][1:3], ("GET", "/api/v1/policies"))
        self.assertEqual(calls[2][1], "GET")
        self.assertIn("scope=notifications", calls[2][2])
        self.assertIn("owner=admin+local", calls[2][2])
        self.assertIn("device_id=pc-2", calls[2][2])
        self.assertEqual(calls[3][1:3], ("POST", "/api/v1/actions"))
        self.assertEqual(calls[3][3]["device_id"], "pc-2")
        self.assertEqual(
            calls[3][3]["rule"]["description"], "Message modifié",
        )

    def test_policy_catalog_and_device_management_share_the_authenticated_scope(self):
        client = BackendClient(lambda: {}, lambda _: {}, {
            "enabled": True, "device_id": "pc-1", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        })
        calls = []
        client._management_request = (
            lambda session, method, path, payload=None:
            calls.append((session, method, path, payload)) or {"ok": True}
        )
        management = {"cookie": "ug_session=x", "csrf_token": "csrf"}

        client.policy_overview("nick laus", management)
        client.policy_usage("nick laus", {
            "start": "2026-08-30T00:00:00+02:00",
            "end": "2026-08-30T12:00:00+02:00",
            "device_ids": ["pc-1", "x20W"],
        }, management)
        client.policy_action("nick laus", {
            "action": "set_limit", "device_ids": ["pc-1", "x20W"],
        }, management)
        client.cancel_policy_operation("nick laus", "operation/1", management)
        client.catalog_action("nick laus", {
            "action": "rename_target", "device_ids": ["pc-1", "x20W"],
        }, management)
        client.device_action({"action": "reset_limit"}, "x20W", management)
        client.device_action_status("command/1", "x20W", management)
        client.cancel_device_action("command/1", "x20W", management)
        client.create_device_enrollment({
            "username": "nick laus", "display_name": "Portable",
        }, management)
        client.rename_managed_device("x20/W", "x20W salon", management)

        self.assertEqual(calls[0][1:3], (
            "GET", "/api/v1/policies/nick%20laus",
        ))
        self.assertEqual(calls[1][1], "GET")
        self.assertIn("/api/v1/policies/nick%20laus/usage?", calls[1][2])
        self.assertEqual(calls[1][2].count("device_id="), 2)
        self.assertIn("device_id=x20W", calls[1][2])
        self.assertEqual(calls[2][1:3], (
            "POST", "/api/v1/policies/nick%20laus/actions",
        ))
        self.assertEqual(
            calls[3][2],
            "/api/v1/policies/nick%20laus/operations/operation%2F1/cancel",
        )
        self.assertEqual(calls[4][2], "/api/v1/catalogs/nick%20laus/actions")
        self.assertEqual(calls[5][3]["device_id"], "x20W")
        self.assertEqual(
            calls[6][2], "/api/v1/actions/command%2F1?device_id=x20W",
        )
        self.assertEqual(calls[7][3], {"device_id": "x20W"})
        self.assertEqual(calls[8][2], "/api/v1/admin/device-enrollments")
        self.assertEqual(calls[9][2], "/api/v1/admin/devices/x20%2FW/rename")

    def test_analysis_overview_forwards_the_bounded_history_cursor(self):
        client = BackendClient(lambda: {}, lambda _: {}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        })
        calls = []
        client._management_request = (
            lambda session, method, path, payload=None:
            calls.append((session, method, path, payload)) or {"ok": True}
        )
        management = {"cookie": "ug_session=x", "csrf_token": "csrf"}

        client.analysis_overview({
            "scope": "all", "device_id": "pc-2",
            "since": "2026-08-01", "before": "opaque/cursor",
            "tz": "Europe/Paris", "ignored": "must-not-leak",
        }, management)

        self.assertEqual(calls[0][0:2], (management, "GET"))
        self.assertIn("scope=all", calls[0][2])
        self.assertIn("device_id=pc-2", calls[0][2])
        self.assertIn("before=opaque%2Fcursor", calls[0][2])
        self.assertIn("tz=Europe%2FParis", calls[0][2])
        self.assertNotIn("ignored", calls[0][2])

    def test_windows_identity_refresh_updates_the_single_device_name(self):
        client = BackendClient(lambda: {}, lambda _: {}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
            "display_name": "ancien-nom",
        })
        client._request = lambda *_args, **_kwargs: {
            "device": {"device_id": "pc", "display_name": "ordinateur-principal"},
            "windows_identities": [{
                "windows_sid": "S-1-5-21-1-2-3-1001",
                "usage_guard_username": "nicklaus",
            }],
        }

        identities = client.windows_identities()

        self.assertEqual(identities[0]["usage_guard_username"], "nicklaus")
        self.assertEqual(client.display_name, "ordinateur-principal")

    def test_update_maintenance_is_declared_with_the_device_secret(self):
        client = BackendClient(lambda: {}, lambda _: {}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        })
        calls = []
        client._request = lambda method, path, payload=None: (
            calls.append((method, path, payload)) or {"ok": True}
        )

        client.begin_update_maintenance("2.012", 900)

        self.assertEqual(calls[0][0:2], ("POST", "/api/v1/agent/maintenance"))
        self.assertEqual(calls[0][2]["device_id"], "pc")
        self.assertEqual(calls[0][2]["version"], "2.012")
        self.assertEqual(calls[0][2]["duration_seconds"], 900)

    def test_email_configuration_and_manual_test_require_admin_session(self):
        client = BackendClient(lambda: {}, lambda _: {}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        })
        calls = []
        client._management_request = lambda session, method, path, payload=None: calls.append((session, method, path, payload)) or {"ok": True}
        management = {"cookie": "ug_session=x", "csrf_token": "csrf"}

        client.email_settings(management)
        client.save_email_settings({"enabled": False, "smtp_host": "smtp.example.test"}, management)
        client.test_email_settings("test@example.test", management)

        self.assertEqual(calls[0][1:3], ("GET", "/api/v1/email/settings"))
        self.assertFalse(calls[1][3]["enabled"])
        self.assertEqual(calls[2][1:3], ("POST", "/api/v1/email/test"))
        self.assertEqual(calls[2][3]["recipient"], "test@example.test")

    def test_queued_notification_is_relayed_during_sync(self):
        client = BackendClient(lambda: {"usage": []}, lambda _: {}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        })
        calls = []
        client._request = lambda method, path, payload=None: calls.append((method, path, payload)) or {"commands": []}
        client.queue_email_notification(
            "Limite", "Temps écoulé", "owner@example.test", "limit_reached"
        )

        client._sync()

        relay = next(call for call in calls if call[1] == "/api/v1/agent/email/send")
        self.assertEqual(relay[2]["title"], "Limite")
        self.assertEqual(relay[2]["message"], "Temps écoulé")
        self.assertEqual(relay[2]["recipient"], "owner@example.test")
        self.assertEqual(relay[2]["kind"], "limit_reached")
        self.assertFalse(client._pending_email_notifications)

    def test_sync_never_publishes_complete_activity_store(self):
        activity = {"days": {"2026-08-13": {"app:test": 12}}, "app_limit_settings": {}}
        client = BackendClient(lambda *_: {"usage": []}, lambda _: {}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        })
        calls = []
        client._request = lambda method, path, payload=None: calls.append((method, path, payload)) or ({"activity": None} if method == "GET" and "activity" in path else {"commands": []})

        client._sync()

        self.assertFalse(any(
            call[0] == "POST" and call[1] == "/api/v1/agent/activity"
            for call in calls
        ))

    def test_incomplete_activity_provider_never_uploads_destructive_store(self):
        client = BackendClient(lambda: {"usage": []}, lambda _: {}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        })
        calls = []
        client._request = lambda method, path, payload=None: (
            calls.append((method, path, payload)) or {"commands": []}
        )

        client._sync()

        self.assertFalse(any(
            method == "POST" and path == "/api/v1/agent/activity"
            for method, path, _payload in calls
        ))
        self.assertTrue(any(
            method == "POST" and path == "/api/v1/agent/snapshot"
            for method, path, _payload in calls
        ))

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
        })
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

    def test_sync_never_publishes_legacy_activity_delta(self):
        activities = [
            {"days": {"2026-08-13": {"app:test": 12}}, "app_limit_settings": {}},
            {"days": {"2026-08-13": {"app:test": 18}}, "app_limit_settings": {}},
        ]
        client = BackendClient(lambda *_: {"usage": []}, lambda _: {}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        })
        calls = []
        client._request = lambda method, path, payload=None: calls.append((method, path, payload)) or ({"activity": None} if method == "GET" and "activity" in path else {"commands": []})

        client._sync()
        client._sync()

        uploads = [call for call in calls if call[0] == "POST" and call[1] == "/api/v1/agent/activity"]
        self.assertEqual(uploads, [])

    def test_legacy_activity_provider_never_fetches_remote_document(self):
        current = {"days": {"2026-08-13": {"app:test": 12}}, "app_limit_settings": {}}
        updated = {"days": {"2026-08-13": {"app:test": 18}}, "app_limit_settings": {}}
        client = BackendClient(lambda *_: {"usage": []}, lambda _: {}, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        })
        calls = []

        conflict_count = 0

        def request(method, path, payload=None):
            nonlocal conflict_count
            calls.append((method, path, payload))
            if method == "GET" and "activity" in path:
                raise AssertionError("legacy activity endpoint used")
            if payload and "activity_delta" in payload:
                conflict_count += 1
                if conflict_count == 1:
                    raise HTTPError("https://example.test", 409, "conflict", {}, None)
            return {"commands": []}

        client._request = request
        client._sync()
        client._sync()

        uploads = [call[2] for call in calls if call[0] == "POST" and call[1] == "/api/v1/agent/activity"]
        self.assertEqual(uploads, [])

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
        self.assertEqual(handled[0][COMMAND_SOURCE_FIELD], SOURCE_BACKEND)
        self.assertTrue(any(call[0] == "POST" and call[1] == "/api/v1/agent/commands/7/ack" for call in calls))

    def test_sync_reports_protection_and_acknowledges_durable_events(self):
        acknowledged = []
        status = {
            "desktop_connected": False,
            "events": [{"id": "event-1", "kind": "interrupted"}],
        }
        client = BackendClient(
            lambda: {"usage": []}, lambda _: {}, {
                "enabled": True, "device_id": "pc",
                "device_token": "x" * 40,
                "base_url": "https://example.test/usage-guard",
            }, status_provider=lambda: status,
            status_acknowledger=acknowledged.extend,
        )
        calls = []

        def request(method, path, payload=None):
            calls.append((method, path, payload))
            if path == "/api/v1/agent/status":
                return {"accepted_event_ids": ["event-1"]}
            return {"commands": []}

        client._request = request
        client._publish_status()

        report = next(call for call in calls if call[1] == "/api/v1/agent/status")
        self.assertEqual(report[2]["status"], status)
        self.assertEqual(acknowledged, ["event-1"])

    def test_missing_status_endpoint_keeps_old_backend_compatible(self):
        client = BackendClient(
            lambda: {"usage": []}, lambda _: {}, {
                "enabled": True, "device_id": "pc",
                "device_token": "x" * 40,
                "base_url": "https://example.test/usage-guard",
            }, status_provider=lambda: {"desktop_connected": True},
        )

        def request(method, path, payload=None):
            if path == "/api/v1/agent/status":
                raise HTTPError(path, 404, "missing", {}, None)
            return {"commands": []}

        client._request = request
        client._publish_status()

    def test_heartbeat_runs_independently_from_slow_state_sync(self):
        statuses = []
        sync_started = threading.Event()
        release_sync = threading.Event()
        client = BackendClient(
            lambda: {}, lambda _: {}, {
                "enabled": True, "device_id": "pc",
                "device_token": "x" * 40,
                "base_url": "https://example.test/usage-guard",
            }, status_provider=lambda: {"desktop_connected": True},
        )
        client.heartbeat_seconds = 0.01

        def slow_sync():
            sync_started.set()
            release_sync.wait(1)

        def request(method, path, payload=None):
            if path == "/api/v1/agent/status":
                statuses.append(payload)
                return {"accepted_event_ids": []}
            return {"commands": []}

        client._sync = slow_sync
        client._request = request
        client.start()
        self.assertTrue(sync_started.wait(1))
        deadline = time.time() + 1
        while len(statuses) < 2 and time.time() < deadline:
            time.sleep(0.01)
        release_sync.set()
        client.stop()

        self.assertGreaterEqual(len(statuses), 2)

    def test_deferred_command_is_not_acknowledged(self):
        client = BackendClient(lambda: {"usage": []}, lambda _command: {
            "ok": False, "_defer_ack": True,
        }, {
            "enabled": True, "device_id": "pc", "device_token": "x" * 40,
            "base_url": "https://example.test/usage-guard",
        })
        calls = []

        def request(method, path, payload=None):
            calls.append((method, path, payload))
            if method == "GET" and path.startswith("/api/v1/agent/commands"):
                return {"commands": [{"id": "8", "action": "set_language", "language": "fr"}]}
            return {"ok": True}

        client._request = request
        client._sync()

        self.assertFalse(any("/commands/8/ack" in call[1] for call in calls))

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
