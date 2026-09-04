import sys
import tempfile
import unittest
from datetime import date, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from activity import ActiveContext, ActivityProbe, _host_url_from_title
from command_policy import (
    SERVICE_ADMIN_TOKEN_FIELD, SOURCE_BACKEND, SOURCE_LOCAL_ADMIN,
    SOURCE_LOCAL_API, stamp_command,
)
from guard import MonitoringService
import runtime_profile
from usage_guard import AppUsageStore


class MonitoringServiceSnapshotTest(unittest.TestCase):
    def test_sid_mapping_recovers_without_losing_outage_closures(self):
        sid = "S-1-5-21-1-2-3-1001"

        class Decision:
            calls = 0

            def resolve_windows_identity(self, supplied_sid):
                self.calls += 1
                self.supplied_sid = supplied_sid
                if self.calls == 1:
                    raise OSError("service starting")
                return {
                    "windows_sid": supplied_sid,
                    "usage_guard_username": "alice",
                    "mapped": True,
                    "mapping_status": "mapped",
                }

        with tempfile.TemporaryDirectory() as directory:
            service = MonitoringService.__new__(MonitoringService)
            service.usage = AppUsageStore(Path(directory) / "activity.json")
            service._decision_service = Decision()
            service._windows_identity = {
                "windows_sid": sid,
                "mapped": False,
                "mapping_status": "service_unavailable",
            }
            service._windows_identity_checked_at = 0.0
            service.usage.record_windows_session(
                "2026-08-30T08:00:00+02:00",
                identity=service._windows_identity,
            )

            with patch(
                "guard.time.monotonic", side_effect=[100.0, 102.0, 106.0],
            ):
                unavailable = service._refresh_windows_identity(force=True)
                service.usage.record_system_event(
                    "tracking_gap", at="2026-08-30T08:00:30+02:00",
                    ended_at="2026-08-30T08:00:45+02:00",
                )
                service.usage.update_sessions({
                    "active:kona": {
                        "kind": "active", "key": "app:kona", "label": "Kona",
                    },
                }, at="2026-08-30T08:01:00+02:00")
                service.usage.update_sessions(
                    {}, at="2026-08-30T08:02:00+02:00",
                )
                throttled = service._refresh_windows_identity()
                recovered = service._refresh_windows_identity()

            self.assertFalse(unavailable["mapped"])
            self.assertFalse(throttled["mapped"])
            self.assertTrue(recovered["mapped"])
            self.assertEqual(service._decision_service.calls, 2)
            self.assertEqual(service._decision_service.supplied_sid, sid)
            self.assertEqual(
                service.usage._active_windows_identity["usage_guard_username"],
                "alice",
            )
            current_windows_session = next(
                item for item in service.usage.windows_sessions()
                if not item.get("ended_at")
            )
            self.assertTrue(current_windows_session["windows_identity_mapped"])
            self.assertEqual(
                current_windows_session["usage_guard_username"], "alice",
            )
            pending = service.usage.pending_backend_activity_intervals()
            self.assertEqual(len(pending["intervals"]), 2)
            self.assertEqual(
                {item["kind"] for item in pending["intervals"]},
                {"active", "system_event"},
            )
            self.assertTrue(all(
                item["windows_sid"] == sid for item in pending["intervals"]
            ))
            gap = next(
                item for item in pending["intervals"]
                if item["kind"] == "system_event"
            )
            self.assertEqual(
                gap["ended_at"], "2026-08-30T08:00:45+02:00",
            )
            self.assertLessEqual(pending["bytes"], 512 * 1024)

    def test_long_modern_standby_starts_a_new_logical_session(self):
        with tempfile.TemporaryDirectory() as directory:
            service = MonitoringService.__new__(MonitoringService)
            service.usage = AppUsageStore(Path(directory) / "activity.json")
            service._windows_identity = {"windows_username": "alice"}
            events = []
            service.observation_journal = SimpleNamespace(
                event=lambda name, details: events.append((name, details))
            )
            service.usage.record_windows_session(
                "2026-08-25T21:51:42+02:00",
                observed_at="2026-08-25T23:25:00+02:00",
            )
            service.usage.update_sessions({"program:test": {
                "kind": "program", "key": "app:test", "label": "Test",
            }}, at="2026-08-25T22:00:00+02:00")

            changed = service._start_logical_session_after_sleep(
                datetime.fromisoformat("2026-08-25T23:26:23+02:00"),
                datetime.fromisoformat("2026-08-26T07:01:37+02:00"),
            )

            self.assertTrue(changed)
            self.assertEqual(service._tracking_started_at, "2026-08-26T07:01:37+02:00")
            self.assertEqual(service.usage.windows_sessions()[0]["source"], "extended-modern-standby")
            self.assertEqual(service.usage.data["sessions"][-1]["ended_at"], "2026-08-25T23:26:23+02:00")
            self.assertEqual(events[0][0], "logical_session_resume")

    def test_remote_command_can_add_an_unused_catalog_application(self):
        with tempfile.TemporaryDirectory() as directory:
            service = MonitoringService.__new__(MonitoringService)
            service.usage = AppUsageStore(Path(directory) / "activity.json")

            result = service._apply_remote_command_once({
                "action": "add_catalog_item",
                "kind": "application",
                "identifier": "FutureTool.exe",
            })

            self.assertTrue(result["ok"])
            self.assertEqual(result["item"]["key"], "app:futuretool")
            self.assertEqual(service.usage.data["days"], {})

    def test_remote_command_dismisses_program_without_deleting_history(self):
        with tempfile.TemporaryDirectory() as directory:
            service = MonitoringService.__new__(MonitoringService)
            service.usage = AppUsageStore(Path(directory) / "activity.json")
            service.usage.data["days"] = {"2026-08-28": {"app:test": 12}}
            service.usage.data["targets"] = {"app:test": {"label": "Test"}}

            result = service._apply_remote_command_once({
                "action": "dismiss_target", "target_key": "app:test",
            })

            self.assertTrue(result["ok"])
            self.assertTrue(service.usage.is_target_dismissed("app:test"))
            self.assertEqual(
                service.usage.data["days"], {"2026-08-28": {"app:test": 12}},
            )

    def test_remote_permanent_delete_reloads_live_limiter(self):
        with tempfile.TemporaryDirectory() as directory:
            service = MonitoringService.__new__(MonitoringService)
            service.usage = AppUsageStore(Path(directory) / "activity.json")
            service.usage.data["days"] = {
                "2026-08-28": {"app:test": 12},
            }
            service.usage.data["app_limit_settings"] = {
                "app:test#copy": {
                    "target_key": "app:test", "limit_seconds": 300,
                },
            }
            reloaded = []
            service.app_limiter = SimpleNamespace(
                reload_after_target_deleted=reloaded.append,
            )

            result = service._apply_remote_command_once({
                "action": "delete_target", "target_key": "app:test",
            })

            self.assertTrue(result["ok"])
            self.assertEqual(result["removed_limits"], ["app:test#copy"])
            self.assertEqual(reloaded, ["app:test"])
            self.assertNotIn(
                "app:test", service.usage.data["days"]["2026-08-28"],
            )

    def test_remote_command_can_replace_catalog_without_replacing_usage(self):
        with tempfile.TemporaryDirectory() as directory:
            service = MonitoringService.__new__(MonitoringService)
            service.usage = AppUsageStore(Path(directory) / "activity.json")
            service.usage.data["days"] = {"2026-08-28": {"app:test": 12}}
            catalog = service.usage.catalog_document()
            catalog["targets"] = {
                "app:test": {"label": "Test", "category": "Travail"},
            }
            catalog["category_order"] = ["Travail"]

            result = service._apply_remote_command_once({
                "action": "replace_catalog", "catalog": catalog,
            })

            self.assertTrue(result["ok"])
            self.assertEqual(service.usage.data["category_order"], ["Travail"])
            self.assertEqual(
                service.usage.data["days"],
                {"2026-08-28": {"app:test": 12}},
            )

    def test_service_control_restore_materializes_remote_schedule_and_keeps_local_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            service = MonitoringService.__new__(MonitoringService)
            service.usage = AppUsageStore(Path(directory) / "activity.json")
            local = service.usage.set_computer_block(
                "schedule", "administrateur local",
                start_time="22:30", end_time="05:00",
                now=datetime.fromisoformat("2026-08-28T18:00:00+02:00"),
                managed_by="local",
            )
            refreshed = []
            service.app_limiter = SimpleNamespace(
                policies={},
                remove_limit=lambda *_args, **_kwargs: None,
                apply_settings=lambda *_args, **_kwargs: None,
                refresh_computer_block=lambda: refreshed.append(True),
            )
            service._decision_service = SimpleNamespace(
                external_service=True,
                bootstrap_controls=lambda _limits, _blocks: {
                    "limits": {},
                    "computer_blocks": [{
                        "block_id": "remote-short",
                        "mode": "schedule", "enabled": False,
                        "start_time": "19:30", "end_time": "19:32",
                        "name": "Pause du soir",
                    }],
                },
            )

            service._restore_service_controls()

            restored = {
                block["block_id"]: block
                for block in service.usage.computer_blocks()
            }
            self.assertEqual(len(service.usage.computer_blocks()), 2)
            self.assertEqual(set(restored), {
                local["block_id"], "remote-short",
            })
            self.assertEqual(restored[local["block_id"]]["managed_by"], "local")
            self.assertEqual(restored["remote-short"]["managed_by"], "backend")
            self.assertEqual(restored["remote-short"]["daily_start"], "19:30")
            self.assertEqual(restored["remote-short"]["daily_end"], "19:32")
            self.assertFalse(restored["remote-short"]["enabled"])
            self.assertEqual(restored["remote-short"]["name"], "Pause du soir")
            self.assertEqual(refreshed, [True])

    def test_personal_policy_cache_is_read_for_the_current_mapped_sid(self):
        sid = "S-1-5-21-1-2-3-1001"
        calls = []
        service = MonitoringService.__new__(MonitoringService)
        service._windows_identity = {
            "windows_sid": sid, "mapped": True,
            "usage_guard_username": "alice",
        }
        service._decision_service = SimpleNamespace(
            user_policy=lambda supplied_sid: calls.append(supplied_sid) or {
                "windows_sid": supplied_sid,
                "usage_guard_username": "alice",
                "configured": True,
                "revision": 3,
                "policy": {"limits": []},
                "policy_status": "cached",
            }
        )
        service._personal_policy = {
            "configured": False, "revision": 0,
            "policy_status": "unavailable",
        }
        service._personal_policy_checked_at = 0.0

        policy = service._refresh_personal_policy(force=True)

        self.assertEqual(calls, [sid])
        self.assertEqual(policy["revision"], 3)
        self.assertEqual(policy["usage_guard_username"], "alice")

    def test_personal_policy_comparison_only_validates_before_application(self):
        sid = "S-1-5-21-1-2-3-1001"
        acknowledgements = []
        local = {
            "enabled": True, "target_key": "app:test",
            "limit_seconds": 300,
        }
        service = MonitoringService.__new__(MonitoringService)
        service._windows_identity = {"windows_sid": sid, "mapped": True}
        service._decision_service = SimpleNamespace(
            acknowledge_user_policy=lambda *args: acknowledgements.append(args)
        )
        service.app_limiter = SimpleNamespace(
            policies={"app:test": dict(local)}
        )
        service._personal_policy = {
            "configured": True, "revision": 4,
            "policy": {"limits": [{"key": "app:test", **local}]},
        }
        service._personal_policy_compared_revision = 0
        service._personal_policy_comparison = {
            "validated": False, "matches": False, "differences": [],
        }

        comparison = service._compare_personal_policy_if_needed()

        self.assertTrue(comparison["validated"])
        self.assertTrue(comparison["matches"])
        self.assertEqual(service.app_limiter.policies["app:test"], local)
        self.assertEqual(acknowledgements, [])

    def test_category_policy_waits_until_the_local_catalog_can_resolve_it(self):
        local = {
            "enabled": True, "target_key": "category:Divertissement",
            "limit_seconds": 3 * 60 * 60,
        }
        categories = []
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(categories=lambda: list(categories))
        service.app_limiter = SimpleNamespace(
            policies={"category:Divertissement": dict(local)},
        )
        service._personal_policy = {
            "configured": True, "revision": 38,
            "policy": {"limits": [{
                "key": "category:Divertissement", **local,
            }]},
        }
        service._personal_policy_compared_revision = 0
        service._personal_policy_comparison = {
            "validated": False, "matches": False, "differences": [],
        }

        unresolved = service._compare_personal_policy_if_needed()

        self.assertFalse(unresolved["validated"])
        self.assertIn(
            "category_unresolved:category:Divertissement",
            unresolved["differences"],
        )

        # A failed comparison for a revision must not be cached forever: the
        # catalogue command can arrive independently a few seconds later.
        categories.append("Divertissement")
        resolved = service._compare_personal_policy_if_needed()

        self.assertTrue(resolved["validated"])
        self.assertTrue(resolved["matches"])

        categories.clear()
        removed_again = service._compare_personal_policy_if_needed()
        self.assertFalse(removed_again["validated"])

    def test_legacy_shadow_policy_is_applied_automatically_and_acknowledged(self):
        sid = "S-1-5-21-1-2-3-1001"
        applied = []
        usage_updates = []
        acknowledgements = []
        service = MonitoringService.__new__(MonitoringService)
        service._windows_identity = {"windows_sid": sid, "mapped": True}
        service._personal_policy = {
            "configured": True, "revision": 5,
            "usage_guard_username": "alice",
            "policy": {
                "enforcement_mode": "shadow",
                "limits": [{"key": "app:test", "enabled": False}],
            },
        }
        service._personal_usage = {
            "usage_guard_username": "alice", "policy_revision": 5,
            "measured_at": "2026-08-24T08:00:00+02:00", "totals": {},
        }
        service._personal_policy_comparison = {
            "validated": True, "matches": False,
            "enforcement_mode": "enforced",
            "differences": ["different:app:test"],
        }
        service._personal_policy_applied_revision = 0
        service.usage = SimpleNamespace(data={"personal_policy_overlay": {}})
        service.app_limiter = SimpleNamespace(
            activate_personal_policy=lambda *args: applied.append(args),
            set_personal_usage=lambda state: usage_updates.append(state),
            clear_personal_usage=lambda: None,
        )
        service._decision_service = SimpleNamespace(
            acknowledge_user_policy=lambda *args: acknowledgements.append(args)
        )

        self.assertTrue(service._apply_personal_policy_if_needed())
        self.assertEqual(applied[0][0:2], ("alice", 5))
        self.assertEqual(usage_updates[0]["policy_revision"], 5)
        self.assertEqual(acknowledgements[0][0:2], (sid, 5))
        self.assertTrue(acknowledgements[0][2]["ok"])
        self.assertEqual(acknowledgements[0][2]["phase"], "applied")
        self.assertTrue(acknowledgements[0][2]["matches"])

    def test_service_outage_keeps_the_last_persisted_enforced_policy(self):
        restored = []
        service = MonitoringService.__new__(MonitoringService)
        service._windows_identity = {
            "windows_sid": "S-1-5-21-1-2-3-1001",
            "mapped": False, "mapping_status": "service_unavailable",
        }
        service._personal_policy = {
            "configured": False, "policy_status": "unavailable",
        }
        service.usage = SimpleNamespace(data={
            "personal_policy_overlay": {
                "active": True, "owner": "alice", "revision": 5,
                "local_settings": {},
            },
        })
        service.app_limiter = SimpleNamespace(
            deactivate_personal_policy=lambda: restored.append(True),
            clear_personal_usage=lambda: None,
        )

        self.assertTrue(service._apply_personal_policy_if_needed())
        self.assertEqual(restored, [])

    def test_local_admin_limit_removal_is_committed_to_external_service(self):
        removed = []
        committed = []
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(data={
            "notification_rules": [], "computer_block": {},
        })
        service.notification_requested = SimpleNamespace(emit=lambda *_args: None)
        service.app_limiter = SimpleNamespace(
            policies={"app:test": {"managed_by": "backend"}},
            label_for_key=lambda _key: "Test",
            remove_limit=lambda key, **_kwargs: removed.append(key),
        )
        service._decision_service = SimpleNamespace(
            external_service=True,
            authorize_control=lambda _command: {"allowed": True, "error": ""},
            backend_admin=lambda token, action, payload: committed.append(
                (token, action, payload)
            ),
        )
        previous = runtime_profile.current_profile()
        runtime_profile._set_active_profile_for_tests(
            runtime_profile.profile_named("production")
        )
        try:
            command = stamp_command({
                "action": "remove_limit", "target_key": "app:test",
            }, SOURCE_LOCAL_ADMIN)
            command[SERVICE_ADMIN_TOKEN_FIELD] = "service-session-token"
            result = service._apply_remote_command(command)
        finally:
            runtime_profile._set_active_profile_for_tests(previous)

        self.assertTrue(result["ok"])
        self.assertEqual(removed, ["app:test"])
        self.assertEqual(committed[0][0:2], (
            "service-session-token", "commit_control",
        ))
        self.assertNotIn(
            SERVICE_ADMIN_TOKEN_FIELD, committed[0][2]["command"],
        )

    def test_power_events_close_activity_and_survive_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            emitted = []
            service = MonitoringService.__new__(MonitoringService)
            service.usage = AppUsageStore(Path(directory) / "activity.json")
            service.usage.set_notification_rule({
                "kind": "computer_state", "enabled": True,
            })
            service.notification_requested = SimpleNamespace(
                emit=lambda *args: emitted.append(args)
            )
            service.email_notification_requested = SimpleNamespace(
                emit=lambda *_args: None
            )
            service.usage.record_windows_session("2026-08-21T08:00:00+02:00")
            service._suspended = False
            service._shutdown_recorded = False
            service._program_sessions = {"program:test": {"kind": "program"}}
            service._program_inventory_initialized = True
            service._web_inventory_initialized = True
            service._last_program_inventory = 1.0

            service.record_runtime_event("sleep")
            service.record_runtime_event("resume")

            self.assertEqual(
                [event["type"] for event in service.usage.system_events()],
                ["sleep", "resume"],
            )
            self.assertFalse(service._suspended)
            self.assertFalse(service._program_inventory_initialized)
            self.assertFalse(service._web_inventory_initialized)
            self.assertEqual(len(emitted), 2)
            self.assertIn("mis en veille", emitted[0][0])
            self.assertIn("sorti de veille", emitted[1][0])

    def test_automatic_screen_timeout_does_not_split_windows_session(self):
        with tempfile.TemporaryDirectory() as directory:
            emitted = []
            service = MonitoringService.__new__(MonitoringService)
            service.usage = AppUsageStore(Path(directory) / "activity.json")
            service.usage.set_notification_rule({
                "kind": "computer_state", "enabled": True,
            })
            service.notification_requested = SimpleNamespace(
                emit=lambda *args: emitted.append(args)
            )
            service.email_notification_requested = SimpleNamespace(
                emit=lambda *_args: None
            )
            service._suspended = False
            service._shutdown_recorded = False
            service._program_sessions = {}
            service._program_inventory_initialized = True
            service._web_inventory_initialized = True
            service._last_program_inventory = 1.0
            started = "2026-08-26T07:01:37+02:00"
            service.usage.record_windows_session(started)
            service._verified_standby_interval = lambda sleep, resume: (
                sleep, resume, "12",
            )

            service.record_runtime_event("sleep")
            service.record_runtime_event("resume")

            sessions = service.usage.windows_sessions()
            self.assertEqual(len(sessions), 1)
            self.assertEqual(sessions[0]["started_at"], started)
            self.assertIsNone(sessions[0]["ended_at"])
            self.assertEqual(emitted, [])

    def test_dev_service_can_reject_local_mutation_missing_from_desktop_state(self):
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(data={"notification_rules": []})
        service.app_limiter = SimpleNamespace(policies={})
        service._decision_service = SimpleNamespace(
            authorize_control=lambda _command: {
                "allowed": False,
                "error": "Règle distante conservée par le service.",
            }
        )
        previous = runtime_profile.current_profile()
        runtime_profile._set_active_profile_for_tests(runtime_profile.profile_named("dev"))
        try:
            result = service._apply_remote_command(stamp_command({
                "action": "remove_limit", "target_key": "app:test",
            }, SOURCE_LOCAL_API))
        finally:
            runtime_profile._set_active_profile_for_tests(previous)

        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "managed_remotely")
        self.assertIn("conservée par le service", result["error"])

    def test_dev_rejects_local_mutation_of_backend_managed_limit(self):
        removed = []
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(data={"notification_rules": []})
        service.notification_requested = SimpleNamespace(emit=lambda *_args: None)
        service.app_limiter = SimpleNamespace(
            policies={"app:test": {"managed_by": "backend"}},
            label_for_key=lambda _key: "Test",
            remove_limit=lambda key, **_kwargs: removed.append(key),
        )
        previous = runtime_profile.current_profile()
        runtime_profile._set_active_profile_for_tests(runtime_profile.profile_named("dev"))
        try:
            local = service._apply_remote_command(stamp_command({
                "action": "remove_limit", "target_key": "app:test",
            }, SOURCE_LOCAL_API))
            remote = service._apply_remote_command(stamp_command({
                "action": "remove_limit", "target_key": "app:test",
            }, SOURCE_BACKEND))
        finally:
            runtime_profile._set_active_profile_for_tests(previous)

        self.assertFalse(local["ok"])
        self.assertEqual(local["code"], "managed_remotely")
        self.assertTrue(remote["ok"])
        self.assertEqual(removed, ["app:test"])

    def test_notification_rules_dispatch_independent_windows_and_email_channels(self):
        windows = []
        emails = []
        service = MonitoringService.__new__(MonitoringService)
        service.notification_requested = SimpleNamespace(
            emit=lambda *args: windows.append(args)
        )
        service.email_notification_requested = SimpleNamespace(
            emit=lambda *args: emails.append(args)
        )
        rules = [
            {"enabled": True, "channels": ["email"],
             "kind": "limit_change",
             "email_recipient": "mail-only@example.test"},
            {"enabled": True, "channels": ["windows", "email"],
             "kind": "limit_change",
             "email_recipient": "both@example.test"},
        ]

        service._dispatch_notification_rules(rules, "Titre", "Message", 42)

        self.assertEqual(windows, [("Titre", "Message", 42)])
        self.assertEqual({item[3] for item in emails}, {
            "mail-only@example.test", "both@example.test",
        })
        self.assertIn(
            ("limit_change", "Titre", "Message", "mail-only@example.test"),
            emails,
        )
        self.assertIn(
            ("limit_change", "Titre", "Message", "both@example.test"),
            emails,
        )

    def test_custom_notification_message_is_used_for_each_channel(self):
        windows, emails = [], []
        service = MonitoringService.__new__(MonitoringService)
        service.notification_requested = SimpleNamespace(
            emit=lambda *args: windows.append(args)
        )
        service.email_notification_requested = SimpleNamespace(
            emit=lambda *args: emails.append(args)
        )
        service._dispatch_notification_rules([{
            "enabled": True, "kind": "pwa_login",
            "channels": ["windows", "email"],
            "email_recipient": "owner@example.test",
            "description": "Message personnalisé",
        }], "Titre", "Message automatique", 0)

        self.assertEqual(windows[0][1], "Message personnalisé")
        self.assertEqual(emails[0][2], "Message personnalisé")

    def test_access_change_command_uses_only_the_configured_rule_channels(self):
        windows, emails = [], []
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(data={"computer_block": {}, "notification_rules": [{
            "kind": "access_change", "enabled": True,
            "channels": ["windows", "email"],
            "email_recipient": "owner@example.test",
        }]})
        service.app_limiter = SimpleNamespace(policies={})
        service.notification_requested = SimpleNamespace(
            emit=lambda *args: windows.append(args)
        )
        service.email_notification_requested = SimpleNamespace(
            emit=lambda *args: emails.append(args)
        )

        result = service._apply_remote_command({
            "action": "notify_access_change",
            "title": "Droits de nicklaus modifiés",
            "message": "Droits ajoutés : voir les limitations.",
        })

        self.assertTrue(result["ok"])
        self.assertEqual(windows[0][0], "Droits de nicklaus modifiés")
        self.assertEqual(emails[0][0], "access_change")
        self.assertEqual(emails[0][3], "owner@example.test")

    def test_global_limit_warning_can_be_created_without_a_specific_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            service = MonitoringService.__new__(MonitoringService)
            service.usage = AppUsageStore(Path(directory) / "activity.json")
            service.app_limiter = SimpleNamespace(policies={})

            result = service._apply_remote_command({
                "action": "set_notification_rule",
                "rule": {
                    "kind": "limit_warning", "warning_seconds": 900,
                    "enabled": True,
                },
            })

            self.assertTrue(result["ok"])
            self.assertEqual(result["rule"]["target_key"], "")
            self.assertEqual(result["rule"]["warning_seconds"], 900)

    def test_computer_block_notifications_name_the_actor(self):
        with tempfile.TemporaryDirectory() as directory:
            emitted = []
            service = MonitoringService.__new__(MonitoringService)
            service.usage = AppUsageStore(Path(directory) / "activity.json")
            service.usage.set_notification_rule({
                "kind": "computer_block_change", "enabled": True,
            })
            service.notification_requested = SimpleNamespace(
                emit=lambda *args: emitted.append(args)
            )
            service.app_limiter = SimpleNamespace(
                refresh_computer_block=lambda: None,
            )

            applied = service._apply_remote_command({
                "action": "set_computer_block", "mode": "duration",
                "duration_seconds": 3600, "delay_seconds": 600,
                "actor": "alice", "name": "  Temps calme  ",
            })
            service._apply_remote_command({
                "action": "clear_computer_block", "actor": "bob",
            })

            self.assertEqual(
                emitted[0][0],
                "Limitation planifiée par alice — Usage Guard",
            )
            self.assertEqual(applied["computer_block"]["name"], "Temps calme")
            self.assertIn("alice a planifié", emitted[0][1])
            self.assertEqual(
                emitted[1][0],
                "Limitation levée par bob — Usage Guard",
            )
            self.assertIn("bob a levé", emitted[1][1])

    def test_limit_toggle_notifies_with_actor_only_when_configured(self):
        emitted = []
        policies = {"app:test": {
            "enabled": True, "limit_seconds": 60,
            "extension_seconds": 15, "warning_seconds": 5,
        }}
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(data={"notification_rules": []})
        service.notification_requested = SimpleNamespace(
            emit=lambda *args: emitted.append(args)
        )

        def apply_settings(target_key, settings, **_kwargs):
            policies[target_key] = dict(settings)
            return policies[target_key]

        service.app_limiter = SimpleNamespace(
            policies=policies,
            apply_settings=apply_settings,
            label_for_key=lambda _key: "Test",
        )

        service._apply_remote_command({
            "action": "set_limit", "target_key": "app:test",
            "settings": {**policies["app:test"], "enabled": False},
        })
        self.assertEqual(emitted, [])

        service.usage.data["notification_rules"].append({
            "kind": "limit_change", "enabled": True,
        })
        service._apply_remote_command({
            "action": "set_limit", "target_key": "app:test", "actor": "alice",
            "settings": {**policies["app:test"], "enabled": True},
        })
        service._apply_remote_command({
            "action": "set_limit", "target_key": "app:test",
            "settings": {**policies["app:test"], "enabled": False},
        })

        self.assertEqual(len(emitted), 2)
        self.assertEqual(emitted[0][0], "Limite activée par alice — Usage Guard")
        self.assertIn("alice a activé", emitted[0][1])
        self.assertTrue(emitted[1][0].startswith("Limite désactivée par Utilisateur local"))
        self.assertIn("Utilisateur local (", emitted[1][1])
        self.assertIn("a désactivé", emitted[1][1])

    def test_limit_create_update_and_delete_titles_show_the_remote_actor(self):
        emitted = []
        policies = {}
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(data={"notification_rules": [{
            "kind": "limit_change", "enabled": True, "target_key": "",
        }]})
        service.notification_requested = SimpleNamespace(
            emit=lambda *args: emitted.append(args)
        )

        def apply_settings(target_key, settings, **_kwargs):
            policies[target_key] = dict(settings)
            return policies[target_key]

        service.app_limiter = SimpleNamespace(
            policies=policies,
            apply_settings=apply_settings,
            remove_limit=lambda target_key, **_kwargs: policies.pop(target_key),
            label_for_key=lambda _key: "Test",
        )
        settings = {
            "enabled": True, "limit_seconds": 60,
            "extension_seconds": 15, "warning_seconds": 5,
        }

        service._apply_remote_command({
            "action": "set_limit", "target_key": "app:test",
            "settings": {**settings, "enabled": False}, "actor": "alice",
        })
        self.assertTrue(policies["app:test"]["enabled"])
        service._apply_remote_command({
            "action": "set_limit", "target_key": "app:test",
            "settings": {**settings, "limit_seconds": 120}, "actor": "bob",
        })
        service._apply_remote_command({
            "action": "remove_limit", "target_key": "app:test", "actor": "charlie",
        })

        self.assertEqual([item[0] for item in emitted], [
            "Limite créée par alice — Usage Guard",
            "Limite modifiée par bob — Usage Guard",
            "Limite supprimée par charlie — Usage Guard",
        ])

    def test_creating_a_second_limit_on_same_category_does_not_replace_first(self):
        policies = {}
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(data={"notification_rules": []})
        service.notification_requested = SimpleNamespace(emit=lambda *args: None)

        def apply_settings(target_key, settings, **_kwargs):
            policies[target_key] = dict(settings)
            return policies[target_key]

        service.app_limiter = SimpleNamespace(
            policies=policies,
            apply_settings=apply_settings,
            label_for_key=lambda _key: "Catégorie · Jeux",
        )
        settings = {
            "enabled": True, "create_new": True, "target_key": "category:Jeux",
            "limit_seconds": 3600, "extension_seconds": 900,
            "warning_seconds": 300,
        }

        service._apply_remote_command({
            "action": "set_limit", "target_key": "category:Jeux",
            "settings": settings,
        })
        service._apply_remote_command({
            "action": "set_limit", "target_key": "category:Jeux",
            "settings": {**settings, "limit_seconds": 600},
        })

        self.assertEqual(len(policies), 2)
        self.assertIn("category:Jeux", policies)
        duplicate_keys = [key for key in policies if key.startswith("category:Jeux#")]
        self.assertEqual(len(duplicate_keys), 1)
        self.assertEqual(policies["category:Jeux"]["limit_seconds"], 3600)
        self.assertEqual(policies[duplicate_keys[0]]["target_key"], "category:Jeux")
        self.assertEqual(policies[duplicate_keys[0]]["limit_seconds"], 600)

    def test_remote_create_new_limit_is_idempotent_for_same_command(self):
        with tempfile.TemporaryDirectory() as directory:
            policies = {}
            service = MonitoringService.__new__(MonitoringService)
            service.usage = AppUsageStore(Path(directory) / "activity.json")
            service.notification_requested = SimpleNamespace(emit=lambda *args: None)

            def apply_settings(target_key, settings, **_kwargs):
                policies[target_key] = dict(settings)
                return policies[target_key]

            service.app_limiter = SimpleNamespace(
                policies=policies,
                apply_settings=apply_settings,
                label_for_key=lambda _key: "Catégorie · Jeux",
            )
            command = {
                "_remote_command_id": "42",
                "action": "set_limit",
                "target_key": "category:Jeux",
                "settings": {
                    "enabled": True, "create_new": True,
                    "target_key": "category:Jeux",
                    "limit_seconds": 3600, "extension_seconds": 900,
                    "warning_seconds": 300,
                },
            }

            first = service._apply_remote_command(dict(command))
            second = service._apply_remote_command(dict(command))

            self.assertTrue(first["ok"])
            self.assertEqual(first, second)
            self.assertEqual(list(policies), ["category:Jeux"])
            self.assertEqual(
                service.usage.data["remote_command_results"]["42"]["limit"]["key"],
                "category:Jeux",
            )

    def test_cached_remote_limit_command_is_reapplied_when_local_limit_is_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            policies = {}
            service = MonitoringService.__new__(MonitoringService)
            service.usage = AppUsageStore(Path(directory) / "activity.json")
            service.notification_requested = SimpleNamespace(emit=lambda *args: None)

            def apply_settings(target_key, settings, **_kwargs):
                policies[target_key] = dict(settings)
                return policies[target_key]

            service.app_limiter = SimpleNamespace(
                policies=policies,
                apply_settings=apply_settings,
                label_for_key=lambda _key: "Codex",
            )
            service.usage.data["remote_command_results"]["42"] = {
                "ok": True,
                "limit": {
                    "key": "app:codex",
                    "target_key": "app:codex",
                    "limit_seconds": 600,
                },
            }

            result = service._apply_remote_command({
                "_remote_command_id": "42",
                "action": "set_limit",
                "target_key": "app:codex",
                "settings": {"target_key": "app:codex", "limit_seconds": 600},
            })

            self.assertTrue(result["ok"])
            self.assertIn("app:codex", policies)
            self.assertEqual(policies["app:codex"]["limit_seconds"], 600)

    def test_pwa_login_notification_names_the_connected_user(self):
        emitted = []
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(data={"notification_rules": [{
            "kind": "pwa_login", "enabled": True,
        }]})
        service.notification_requested = SimpleNamespace(
            emit=lambda *args: emitted.append(args)
        )

        service._notify_pwa_login("alice", "192.0.2.10")

        self.assertEqual(len(emitted), 1)
        self.assertIn("alice", emitted[0][0])
        self.assertIn("192.0.2.10", emitted[0][1])

    def test_computer_block_admin_login_uses_protected_session_and_notifies(self):
        commands = []
        notifications = []
        service = MonitoringService.__new__(MonitoringService)
        service._decision_service = SimpleNamespace(
            authenticate_user=lambda username, password: {
                "username": username, "is_admin": True,
                "must_change": False, "must_set_email": False,
                "_service_admin_token": "protected-session-token",
            }
        )
        service._apply_remote_command = lambda command: (
            commands.append(command) or {"ok": True}
        )
        service._notify_limit_override_login = notifications.append
        active = {
            "block_id": "short-evening", "enabled": True,
            "mode": "schedule", "daily_start": "19:30",
            "daily_end": "19:32", "valid_from": "",
            "valid_from_time": "", "valid_until": "",
            "valid_until_time": "", "active": True, "pending": False,
            "started_at": "2026-08-28T19:30:00+02:00",
            "ends_at": "2026-08-28T19:32:00+02:00",
        }
        service.app_limiter = SimpleNamespace(
            displayed_computer_block=lambda: {
                key: active[key]
                for key in ("block_id", "mode", "started_at", "ends_at")
            },
            computer_block_status=lambda **_kwargs: dict(active),
        )

        result = service.unlock_computer_block_with_login("admin", "secret")

        self.assertTrue(result["ok"])
        self.assertEqual(commands[0]["action"], "set_computer_block_enabled")
        self.assertFalse(commands[0]["enabled"])
        self.assertEqual(commands[0]["block_id"], "short-evening")
        self.assertEqual(commands[0]["actor"], "admin")
        self.assertEqual(
            commands[0][SERVICE_ADMIN_TOKEN_FIELD], "protected-session-token",
        )
        self.assertEqual(notifications, ["admin"])

    def test_exact_computer_block_disable_keeps_other_rules_and_does_not_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            service = MonitoringService.__new__(MonitoringService)
            service.usage = AppUsageStore(Path(directory) / "activity.json")
            now = datetime.fromisoformat("2026-08-28T18:00:00+02:00")
            night = service.usage.set_computer_block(
                "schedule", "admin", start_time="22:30", end_time="05:00",
                now=now, managed_by="backend",
            )
            short = service.usage.set_computer_block(
                "schedule", "admin", start_time="19:30", end_time="19:32",
                now=now, managed_by="backend",
            )
            refreshed = []
            service.app_limiter = SimpleNamespace(
                refresh_computer_block=lambda: refreshed.append(True),
            )
            service.notification_requested = SimpleNamespace(
                emit=lambda *_args: None,
            )

            result = service._apply_remote_command_once(stamp_command({
                "action": "set_computer_block_enabled",
                "block_id": short["block_id"], "enabled": False,
                "actor": "admin",
            }, SOURCE_LOCAL_ADMIN))

            remaining = {
                block["block_id"]: block
                for block in service.usage.computer_blocks()
            }
            self.assertTrue(result["ok"])
            self.assertEqual(len(remaining), 2)
            self.assertTrue(remaining[night["block_id"]]["enabled"])
            self.assertFalse(remaining[short["block_id"]]["enabled"])
            self.assertEqual(result["computer_block"]["block_id"], short["block_id"])
            self.assertEqual(refreshed, [True])

    def test_computer_block_admin_login_refuses_a_stale_displayed_occurrence(self):
        service = MonitoringService.__new__(MonitoringService)
        service._decision_service = SimpleNamespace(
            authenticate_user=lambda *_args: {
                "username": "admin", "is_admin": True,
                "must_change": False, "must_set_email": False,
                "_service_admin_token": "protected-session-token",
            }
        )
        service.app_limiter = SimpleNamespace(
            displayed_computer_block=lambda: {
                "block_id": "short-evening", "mode": "schedule",
                "started_at": "2026-08-28T19:30:00+02:00",
                "ends_at": "2026-08-28T19:32:00+02:00",
            },
            computer_block_status=lambda **_kwargs: {
                "block_id": "short-evening", "enabled": True,
                "mode": "schedule", "daily_start": "19:30",
                "daily_end": "19:32", "active": False, "pending": True,
                "started_at": "2026-08-29T19:30:00+02:00",
                "ends_at": "2026-08-29T19:32:00+02:00",
            },
        )
        service._apply_remote_command = lambda _command: self.fail(
            "Une occurrence remplacée ne doit pas être désactivée"
        )

        result = service.unlock_computer_block_with_login("admin", "secret")

        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "computer_block_changed")

    def test_computer_block_login_rejects_non_admin_without_mutation(self):
        service = MonitoringService.__new__(MonitoringService)
        service._decision_service = SimpleNamespace(
            authenticate_user=lambda *_args: {
                "username": "viewer", "is_admin": False,
                "must_change": False, "must_set_email": False,
            }
        )
        service._apply_remote_command = lambda _command: self.fail(
            "Une limite ne doit pas être levée par un non-administrateur"
        )

        result = service.unlock_computer_block_with_login("viewer", "secret")

        self.assertFalse(result["ok"])
        self.assertIn("administrateur", result["error"])

    def test_limit_override_login_has_its_own_notification_kind(self):
        windows = []
        emails = []
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(data={"notification_rules": [{
            "kind": "limit_override_login", "enabled": True,
            "channels": ["windows", "email"],
            "email_recipient": "owner@example.test",
        }]})
        service.notification_requested = SimpleNamespace(
            emit=lambda *args: windows.append(args)
        )
        service.email_notification_requested = SimpleNamespace(
            emit=lambda *args: emails.append(args)
        )

        service._notify_limit_override_login("admin")

        self.assertEqual(len(windows), 1)
        self.assertEqual(emails[0][0], "limit_override_login")
        self.assertIn("admin", windows[0][1])

    def test_pwa_login_notification_can_be_sent_by_email_only(self):
        emails = []
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(data={"notification_rules": [{
            "kind": "pwa_login", "enabled": True,
            "channels": ["email"],
            "email_recipient": "owner@example.test",
        }]})
        service.notification_requested = SimpleNamespace(
            emit=lambda *_args: self.fail("Notification Windows inattendue")
        )
        service.email_notification_requested = SimpleNamespace(
            emit=lambda *args: emails.append(args)
        )

        service._notify_pwa_login("alice", "192.0.2.10")

        self.assertEqual(len(emails), 1)
        self.assertEqual(emails[0][0], "pwa_login")
        self.assertEqual(emails[0][3], "owner@example.test")
        self.assertIn("alice", emails[0][1])

    def test_pwa_login_windows_only_does_not_repeat_server_email(self):
        windows = []
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(data={"notification_rules": [{
            "kind": "pwa_login", "enabled": True,
            "channels": ["windows", "email"],
            "email_recipient": "owner@example.test",
        }]})
        service.notification_requested = SimpleNamespace(
            emit=lambda *args: windows.append(args)
        )
        service.email_notification_requested = SimpleNamespace(
            emit=lambda *_args: self.fail("E-mail déjà envoyé par le serveur")
        )

        service._notify_pwa_login("alice", "192.0.2.10", windows_only=True)

        self.assertEqual(len(windows), 1)

    def test_pwa_login_notification_filters_role_and_own_login(self):
        windows = []
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(data={"notification_rules": [{
            "kind": "pwa_login", "enabled": True,
            "owner": "admin", "login_role_scope": "users",
        }]})
        service.notification_requested = SimpleNamespace(
            emit=lambda *args: windows.append(args)
        )
        service.email_notification_requested = SimpleNamespace(
            emit=lambda *_args: None
        )

        service._notify_pwa_login("other-admin", actor_is_admin=True)
        service._notify_pwa_login("admin", actor_is_admin=False)
        self.assertEqual(windows, [])

        service._notify_pwa_login("nicklaus", actor_is_admin=False)
        self.assertEqual(len(windows), 1)

    def test_pwa_login_notification_distinguishes_limited_and_regular_users(self):
        windows = []
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(data={"notification_rules": [{
            "kind": "pwa_login", "enabled": True,
            "subject_roles": ["limited"],
        }]})
        service.notification_requested = SimpleNamespace(
            emit=lambda *args: windows.append(args)
        )
        service.email_notification_requested = SimpleNamespace(
            emit=lambda *_args: None
        )

        service._notify_pwa_login("regular", actor_role="user")
        self.assertEqual(windows, [])
        service._notify_pwa_login("limited", actor_role="limited")
        self.assertEqual(len(windows), 1)

    def test_local_notification_creation_records_its_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            service = MonitoringService.__new__(MonitoringService)
            service.usage = AppUsageStore(Path(directory) / "activity.json")

            result = service._apply_remote_command_once({
                "action": "set_notification_rule", "actor": "admin",
                "rule": {"kind": "pwa_login", "login_role_scope": "admins"},
            })

            self.assertTrue(result["ok"])
            self.assertEqual(result["rule"]["owner"], "admin")

    def test_custom_threshold_notifies_once_until_usage_drops_below_it(self):
        emitted = []
        status = {"seconds": 80, "allowed": 100, "extension_used": False}
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(data={"notification_rules": [{
            "id": "threshold", "kind": "usage_threshold", "enabled": True,
            "target_key": "app:test", "threshold_percent": 80,
            "label": "Seuil test",
        }]})
        service.app_limiter = SimpleNamespace(
            policies={"app:test": {}},
            current_status=lambda _key: dict(status),
            label_for_key=lambda _key: "Test",
        )
        service.notification_requested = SimpleNamespace(
            emit=lambda *args: emitted.append(args)
        )
        service._notification_thresholds_shown = set()

        service._check_notification_thresholds()
        service._check_notification_thresholds()
        self.assertEqual(len(emitted), 1)
        self.assertIn("80 %", emitted[0][1])

        status["seconds"] = 10
        service._check_notification_thresholds()
        status["seconds"] = 80
        service._check_notification_thresholds()
        self.assertEqual(len(emitted), 2)

    def test_duration_threshold_counts_a_site_subcategory(self):
        with tempfile.TemporaryDirectory() as directory:
            emitted = []
            store = AppUsageStore(Path(directory) / "activity.json")
            key = "site:brave.exe:example.test"
            store.data["targets"][key] = {
                "label": "example.test", "category": "Internet",
                "site_category": "Actualité",
            }
            store.data["site_categories"] = ["Actualité"]
            store.data["days"][date.today().isoformat()] = {key: 120}
            store.set_notification_rule({
                "kind": "usage_threshold", "threshold_mode": "duration",
                "target_key": "category:Actualité", "duration_seconds": 60,
            })
            service = MonitoringService.__new__(MonitoringService)
            service.usage = store
            service.app_limiter = SimpleNamespace(
                label_for_key=lambda target: target,
                _format_duration=lambda seconds: f"{seconds} s",
            )
            service.notification_requested = SimpleNamespace(
                emit=lambda *args: emitted.append(args)
            )
            service._notification_thresholds_shown = set()

            service._check_notification_thresholds()
            service._check_notification_thresholds()

            self.assertEqual(len(emitted), 1)
            self.assertIn("Actualité", emitted[0][1])

    def test_hour_threshold_waits_for_the_selected_activity(self):
        with tempfile.TemporaryDirectory() as directory:
            emitted = []
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["targets"]["app:test"] = {"label": "Test"}
            store.set_notification_rule({
                "kind": "usage_threshold", "threshold_mode": "time",
                "target_key": "app:test", "after_time": "00:00",
            })
            service = MonitoringService.__new__(MonitoringService)
            service.usage = store
            service.current_context = ActiveContext(app_name="Other.exe")
            service.app_limiter = SimpleNamespace(
                label_for_key=lambda _target: "Test",
            )
            service.notification_requested = SimpleNamespace(
                emit=lambda *args: emitted.append(args)
            )
            service._notification_thresholds_shown = set()

            service._check_notification_thresholds()
            self.assertEqual(emitted, [])

            service.current_context = ActiveContext(app_name="Test.exe")
            service._check_notification_thresholds()
            self.assertEqual(len(emitted), 1)
            self.assertIn("Test", emitted[0][1])

    def test_startup_reminder_is_notification_only(self):
        emitted = []
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(data={"notification_rules": [{
            "kind": "startup_reminder", "enabled": True,
            "weekdays": list(range(7)), "label": "Repos",
            "description": "Ne pas utiliser l’ordinateur aujourd’hui.",
        }]})
        service.notification_requested = SimpleNamespace(
            emit=lambda *args: emitted.append(args)
        )

        service._notify_startup_rules()

        self.assertEqual(emitted, [(
            "Repos", "Ne pas utiliser l’ordinateur aujourd’hui.", 0,
        )])

    def test_foreground_application_remains_active_until_afk_threshold(self):
        reading = ActiveContext(
            app_name="ChatGPT.exe", has_recent_input=False,
            idle_seconds=90, is_afk=False,
        )
        away = ActiveContext(
            app_name="ChatGPT.exe", has_recent_input=False,
            idle_seconds=121, is_afk=True,
        )

        self.assertTrue(MonitoringService.is_activity_countable(reading))
        self.assertFalse(MonitoringService.is_activity_countable(away))

    def test_foreground_chrome_pwa_is_inactive_after_afk_threshold(self):
        away = ActiveContext(
            app_name="chrome.exe", window_title="Codex",
            idle_seconds=3600, is_afk=True,
        )

        self.assertFalse(MonitoringService.is_activity_countable(away))

    def test_unclassified_site_keeps_its_host_in_timeline_sessions(self):
        target = SimpleNamespace(
            key="site:brave.exe:other-sites",
            label="Autres sites",
            detail_host="example.com",
        )

        self.assertEqual(
            MonitoringService._session_identity(target),
            ("site:brave.exe:example.com", "example.com"),
        )

    def test_private_browser_title_does_not_expose_a_site(self):
        self.assertEqual(
            _host_url_from_title("example.com - Fenêtre privée - Brave"),
            "",
        )

    def test_private_browser_window_discards_a_stale_regular_url(self):
        probe = ActivityProbe.__new__(ActivityProbe)
        probe._fallback = SimpleNamespace(current=lambda: ActiveContext(
            app_name="brave.exe",
            window_title="Nouvel onglet - Fenêtre privée - Brave",
            is_afk=False,
        ))
        probe._current_bridge_tab = lambda: SimpleNamespace(
            url="https://example.test", title="Example",
            audible=False, generic=False,
        )
        probe.aw = SimpleNamespace(current=lambda: ActiveContext(
            app_name="brave.exe", url="https://example.test",
        ))
        probe._media = SimpleNamespace(
            is_playing_for=lambda *_args: False,
            playing_sources=lambda: [],
        )
        probe._last_browser_url = "https://previous.test"
        probe._last_non_guard_context = None

        result = probe.current()

        self.assertTrue(result.generic_web)
        self.assertEqual(result.url, "")
        self.assertEqual(probe._last_browser_url, "https://previous.test")

    def test_context_keeps_windows_afk_state_instead_of_three_second_input_flag(self):
        probe = ActivityProbe.__new__(ActivityProbe)
        probe._through_usage_guard = lambda context, fallback: context
        probe._media = SimpleNamespace(is_playing_for=lambda app, url: False)
        probe._background_media = lambda context: []
        probe._remember_non_guard_context = lambda context, fallback: None
        context = ActiveContext(app_name="ChatGPT.exe")
        fallback = ActiveContext(
            app_name="ChatGPT.exe", has_recent_input=False,
            idle_seconds=90, is_afk=False,
        )

        result = probe._finish_context(context, fallback)

        self.assertFalse(result.has_recent_input)
        self.assertFalse(result.is_afk)

    def test_session_snapshot_includes_all_other_sites_seen_today(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            previous_day = date.today() - timedelta(days=1)
            started_at = datetime.combine(
                previous_day, datetime.min.time()
            ).astimezone()
            key = "site:brave.exe:other-sites"
            store.data["targets"][key] = {
                "label": "Autres sites",
                "category": "Internet",
            }
            store.data["other_site_days"] = {
                "brave.exe": {
                    previous_day.isoformat(): {"carto.com": 600.0},
                    date.today().isoformat(): {"earlier.example": 15.0},
                }
            }
            store.data["sessions"] = [{
                    "kind": "active",
                    "key": key,
                    "label": "Autres sites",
                    "started_at": started_at.isoformat(),
                    "ended_at": (started_at + timedelta(seconds=600)).isoformat(),
                }, {
                    "kind": "active",
                    "key": "site:brave.exe:example.com",
                    "label": "example.com",
                    "started_at": started_at.isoformat(),
                    "ended_at": (started_at + timedelta(seconds=42)).isoformat(),
                }]
            store._recent_closed_sessions.extend(store.data["sessions"])

            service = MonitoringService.__new__(MonitoringService)
            service.usage = store
            service.app_limiter = SimpleNamespace(
                policies={}, computer_block_status=lambda: {"active": False}
            )
            service.current_context = ActiveContext(
                app_name="brave.exe",
                url="https://www.example.com/path?token=secret#details",
            )
            service._tracking_started_at = started_at.isoformat()
            service._program_inventory_initialized = True
            service._web_inventory_initialized = True

            snapshot = service.remote_snapshot({"scope": "session"})

            self.assertEqual(
                snapshot["other_sites"],
                [
                    {"browser": "brave.exe", "host": "example.com", "seconds": 42.0},
                    {"browser": "brave.exe", "host": "earlier.example", "seconds": 15.0},
                ],
            )
            self.assertNotIn("carto.com", {item["host"] for item in snapshot["other_sites"]})
            usage = {item["key"]: item["seconds"] for item in snapshot["usage"]}
            self.assertEqual(usage[key], 642.0)
            self.assertNotIn("site:brave.exe:example.com", usage)
            self.assertEqual(
                [item["key"] for item in snapshot["sessions"]],
                ["site:brave.exe:example.com"],
            )
            self.assertEqual(snapshot["current"]["site_host"], "example.com")
            self.assertEqual(snapshot["current"]["site_url"], "example.com/path")
            self.assertEqual(
                snapshot["current"]["url"],
                "https://www.example.com/path?token=secret#details",
            )
            self.assertEqual(
                snapshot["current"]["target_key"], "site:brave.exe:other-sites"
            )
            self.assertIn("computer_blocks_v2", snapshot["capabilities"])
            self.assertIn("limit_warning_action", snapshot["capabilities"])
            self.assertEqual(len(snapshot["computer_blocks"]), 1)

    def test_chrome_pwa_inventory_fuses_program_and_active_target(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.update_sessions({"program:chrome.exe": {
                "kind": "program", "key": "app:chrome", "label": "chrome",
                "source": "windows",
            }}, at="2026-08-15T06:05:43+02:00")

            service = MonitoringService.__new__(MonitoringService)
            service.usage = store
            service._tracking_started_at = "2026-08-15T06:00:00+02:00"
            observed = service._resolved_program_sessions({
                "chrome.exe": {
                    "executable": "chrome.exe",
                    "window_titles": ["ChatGPT"],
                }
            })
            store.update_sessions(observed, at="2026-08-15T15:10:00+02:00")

            session = store.data["open_sessions"]["program:chrome.exe"]
            self.assertEqual(session["key"], "app:chatgpt")
            self.assertEqual(session["label"], "ChatGPT")
            self.assertEqual(session["started_at"], "2026-08-15T06:05:43+02:00")

    def test_program_inventory_reveals_dismissed_program_only_after_relaunch(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.update_sessions({"program:test.exe": {
                "kind": "program", "key": "app:test", "label": "Test",
            }}, at="2026-08-28T10:00:00+02:00")
            store.dismiss_target("app:test")
            service = MonitoringService.__new__(MonitoringService)
            service.usage = store
            service._tracking_started_at = "2026-08-28T09:00:00+02:00"
            running = {
                "test.exe": {
                    "executable": "test.exe", "window_titles": ["Test"],
                },
            }

            service._resolved_program_sessions(running)
            self.assertTrue(store.is_target_dismissed("app:test"))
            service._resolved_program_sessions({})
            self.assertTrue(store.is_target_dismissed("app:test"))
            service._resolved_program_sessions(running)
            self.assertFalse(store.is_target_dismissed("app:test"))



if __name__ == "__main__":
    unittest.main()
