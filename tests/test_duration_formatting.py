import os
import sys
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app_limiter import AppLimiter, ComputerBlockOverlay
from activity import ActiveContext
from PySide6.QtWidgets import QApplication, QLabel, QProgressBar
from usage_guard import AppUsageStore

from gui import (
    TrayProgressCard,
    _compact_duration,
    _countdown_color,
    _format_seconds,
    _temporal_overlaps_today,
    _today_temporal_bounds,
)


class DurationFormattingTest(unittest.TestCase):
    def test_tray_countdowns_share_the_progress_palette(self):
        self.assertEqual(_countdown_color(90, 100), "#58d69a")
        self.assertEqual(_countdown_color(10, 100), "#f59e0b")
        self.assertEqual(_countdown_color(90, 100, warning=True), "#f59e0b")
        self.assertEqual(_countdown_color(0, 100), "#ef6b73")

    def test_real_computer_overlay_keeps_its_controller_and_can_be_shown(self):
        app = QApplication.instance() or QApplication([])
        controller = SimpleNamespace(
            start_computer_close_grace=lambda: None,
            shutdown_computer=lambda: None,
            restart_computer=lambda: None,
            clear_computer_block=lambda: None,
            admin_unlock_handler=None,
        )
        overlay = ComputerBlockOverlay(controller)

        with patch("app_limiter.sys.platform", "test"):
            overlay.show_block(
                (datetime.now().astimezone() + timedelta(minutes=2)).isoformat()
            )

        self.assertIs(overlay.controller, controller)
        self.assertTrue(overlay.isVisible())
        overlay.hide()
        overlay.deleteLater()
        self.assertIsNotNone(app)

    def test_video_site_limit_counts_playback_but_not_a_paused_foreground_tab(self):
        app = QApplication.instance() or QApplication([])
        with tempfile.TemporaryDirectory() as directory:
            usage = AppUsageStore(Path(directory) / "activity.json")
            context = ActiveContext(
                app_name="brave.exe",
                window_title="YouTube - Brave",
                window_handle=123,
                url="https://www.youtube.com/watch?v=test",
            )
            target = usage.target_for_context(context)
            usage.remember_target(target)
            usage.set_app_limit_settings(target.key, {
                "enabled": True,
                "limit_seconds": 60,
                "extension_seconds": 0,
                "warning_seconds": 5,
            })

            limiter = AppLimiter(usage)
            limiter.observe(context, 1.0, True, {})

            self.assertEqual(
                usage.app_limit_state_for_day(target.key)["seconds"], 0.0
            )
            context.browser_media_playing = True
            limiter.observe(context, 1.0, True, {})

            self.assertEqual(
                usage.app_limit_state_for_day(target.key)["seconds"], 1.0
            )
            limiter.follow_timer.stop()
        self.assertIsNotNone(app)

    def test_direct_browser_limit_preserves_warning_action(self):
        limiter = AppLimiter.__new__(AppLimiter)
        target_key = "site:brave.exe:example.com"
        limiter.usage = SimpleNamespace(
            data={
                "targets": {target_key: {"label": "example.com"}},
                "browser_categories": {},
            },
            category_lineage=lambda _category: [],
        )
        limiter.policies = {target_key: {
            "enabled": True,
            "target_key": target_key,
            "limit_seconds": 60,
            "extension_seconds": 0,
            "extension_unit": "seconds",
            "warning_seconds": 5,
            "enforcement_action": "warn",
        }}
        limiter.current_status = lambda _key: {
            "schedule_active": True,
            "allowed": 60,
            "remaining": 0,
        }

        state = limiter.web_limit_for_url("https://example.com/watch")

        self.assertEqual(state["enforcement_action"], "warn")

    def test_direct_browser_limit_prioritizes_block_over_overlapping_warning(self):
        limiter = AppLimiter.__new__(AppLimiter)
        site_key = "site:brave.exe:example.com"
        category_key = "category:Divertissement"
        limiter.usage = SimpleNamespace(
            data={
                "targets": {
                    site_key: {
                        "label": "example.com",
                        "category": "Divertissement",
                    },
                },
                "browser_categories": {},
            },
            category_lineage=lambda category: [category],
        )
        common = {
            "enabled": True,
            "limit_seconds": 60,
            "extension_seconds": 0,
            "extension_unit": "seconds",
            "warning_seconds": 5,
        }
        limiter.policies = {
            site_key: {
                **common, "target_key": site_key,
                "enforcement_action": "warn",
            },
            category_key: {
                **common, "target_key": category_key,
                "enforcement_action": "block",
            },
        }
        limiter.current_status = lambda key: {
            "schedule_active": True,
            "allowed": 60,
            "remaining": 0 if key == site_key else 30,
        }

        state = limiter.web_limit_for_url("https://example.com/watch")

        self.assertEqual(state["target_key"], category_key)
        self.assertEqual(state["enforcement_action"], "block")

    def test_block_target_is_a_noop_for_warning_policy(self):
        limiter = AppLimiter.__new__(AppLimiter)
        limiter.target_key = "app:test"
        limiter.policies = {
            "app:test": {"enforcement_action": "warn"},
        }
        limiter._valid_target = lambda: True
        limiter.blocked = False

        limiter.block_target()

        self.assertFalse(limiter.blocked)

    def test_computer_warning_uses_configured_email_and_one_windows_fallback(self):
        limiter = AppLimiter.__new__(AppLimiter)
        status = {
            "block_id": "warning-computer",
            "started_at": "2026-08-30T12:00:00+02:00",
            "ends_at": "2026-08-30T13:00:00+02:00",
            "active": True,
            "pending": False,
            "enforcement_action": "warn",
            "actor": "admin",
        }
        windows = []
        configured = []
        limiter._stored_computer_blocks = lambda: []
        limiter.computer_block_statuses = lambda _now: [dict(status)]
        limiter._effective_computer_block = lambda statuses: (
            dict(statuses[0]) if statuses else {}
        )
        limiter._set_effective_computer_block_mirror = lambda _status: None
        limiter._computer_block_warning_shown = set()
        limiter._notification_rules = lambda kind, target: ([{
            "kind": kind,
            "target_key": target,
            "channels": ["email"],
            "email_recipient": "parent@example.test",
        }] if kind == "limit_reached" else [])
        limiter.notification_requested = SimpleNamespace(
            emit=lambda *args: windows.append(args),
        )
        limiter._emit_notification = lambda *args, **kwargs: configured.append(
            (args, kwargs)
        )
        limiter.computer_overlay = SimpleNamespace(hide=lambda: None)

        now = datetime.fromisoformat("2026-08-30T12:30:00+02:00")
        limiter.refresh_computer_block(now)
        limiter.refresh_computer_block(now)

        self.assertEqual(len(windows), 1)
        self.assertEqual(len(configured), 1)
        self.assertEqual(configured[0][0][:2], ("limit_reached", "computer:all"))

    def test_joker_notification_is_emitted_once_after_normal_limit(self):
        emitted = []
        limiter = AppLimiter.__new__(AppLimiter)
        policy = {
            "enabled": True, "block_during_validity": False,
            "limit_seconds": 60, "extension_seconds": 15,
        }
        state = {"seconds": 60, "extension_used": True}
        limiter.policies = {"app:test": policy}
        limiter.usage = SimpleNamespace(
            data={"notification_rules": [{
                "kind": "limit_extension", "enabled": True,
                "channels": ["windows"],
            }]},
            app_limit_state_for_day=lambda _key: dict(state),
            add_app_limit_seconds=lambda *_args: {
                "seconds": 61, "extension_used": True,
            },
        )
        limiter.current_status = lambda _key: {
            "schedule_active": True, "time_blocked": False,
        }
        limiter.notification_requested = SimpleNamespace(
            emit=lambda *args: emitted.append(args)
        )
        limiter._notified_handles = {("app:test", 42)}
        limiter._warning_shown = set()
        limiter._playing_seen_at = {}
        limiter.block_target = lambda: None

        limiter._consume_limit("app:test", "Test", 10, 42, 1)
        limiter._consume_limit("app:test", "Test", 10, 42, 1)

        self.assertEqual(len(emitted), 1)
        self.assertIn("joker utilisé", emitted[0][0])
        self.assertIn("15 s", emitted[0][1])

    def test_limiter_notification_can_use_email_without_windows(self):
        windows = []
        emails = []
        limiter = AppLimiter.__new__(AppLimiter)
        limiter.usage = SimpleNamespace(data={"notification_rules": [{
            "kind": "limit_warning", "enabled": True,
            "channels": ["email"], "email_recipient": "owner@example.test",
        }]})
        limiter.notification_requested = SimpleNamespace(
            emit=lambda *args: windows.append(args)
        )
        limiter.email_notification_requested = SimpleNamespace(
            emit=lambda *args: emails.append(args)
        )

        limiter._emit_notification(
            "limit_warning", "app:test", "Préavis", "Cinq minutes", 7
        )

        self.assertEqual(windows, [])
        self.assertEqual(
            emails, [(
                "limit_warning", "Préavis", "Cinq minutes",
                "owner@example.test",
            )]
        )

    def test_seconds_are_kept_when_hours_are_present(self):
        expected = "1 h 01 min 01 s"
        self.assertEqual(_compact_duration(3661), expected)
        self.assertEqual(_format_seconds(3661), expected)
        self.assertEqual(AppLimiter._format_duration(3661), expected)

    def test_seconds_are_kept_when_minutes_are_present(self):
        expected = "2 min 05 s"
        self.assertEqual(_compact_duration(125), expected)
        self.assertEqual(_format_seconds(125), expected)
        self.assertEqual(AppLimiter._format_duration(125), expected)

    def test_extension_uses_the_unit_selected_in_the_interface(self):
        self.assertEqual(
            AppLimiter._format_configured_duration(900, "minutes"), "15 min"
        )
        self.assertEqual(
            AppLimiter._format_configured_duration(5400, "hours"), "1.5 h"
        )
        self.assertEqual(
            AppLimiter._format_configured_duration(15, "seconds"), "15 s"
        )

    def test_already_exceeded_limit_notifies_before_immediate_block(self):
        emitted = []
        blocked = []
        limiter = AppLimiter.__new__(AppLimiter)
        limiter.policies = {"app:test": {
            "enabled": True, "block_during_validity": False,
            "limit_seconds": 60, "extension_seconds": 15,
        }}
        limiter.usage = SimpleNamespace(
            data={"notification_rules": [{
                "kind": "limit_reached", "enabled": True, "target_key": "",
            }]},
            app_limit_state_for_day=lambda _key: {
                "seconds": 90, "extension_used": False,
            },
        )
        limiter.current_status = lambda _key: {
            "schedule_active": True, "time_blocked": False,
        }
        limiter.notification_requested = SimpleNamespace(
            emit=lambda *args: emitted.append(args)
        )
        limiter._notified_handles = {("app:test", 42)}
        limiter._warning_shown = set()
        limiter._playing_seen_at = {}
        limiter.block_target = lambda: blocked.append(True)

        limiter._consume_limit("app:test", "Test", 10, 42, 1)

        self.assertEqual(len(blocked), 1)
        self.assertEqual(len(emitted), 1)
        self.assertEqual(emitted[0][0], "Test — limite atteinte")
        self.assertIn("durée autorisée est atteinte", emitted[0][1])

    def test_computer_warning_is_immediate_inside_configured_notice(self):
        now = datetime.now().astimezone()
        status = {
            "pending": True,
            "started_at": (now + timedelta(minutes=5)).isoformat(),
        }
        limiter = AppLimiter.__new__(AppLimiter)
        limiter.usage = SimpleNamespace(data={"notification_rules": []})
        self.assertFalse(limiter.computer_block_warning_due(status, now))

        limiter.usage.data["notification_rules"] = [{
            "kind": "computer_block_warning", "enabled": True,
            "warning_seconds": 15 * 60,
        }]
        self.assertTrue(limiter.computer_block_warning_due(status, now))

    def test_recurring_computer_block_respects_validity_and_daily_hours(self):
        limiter = AppLimiter.__new__(AppLimiter)
        limiter.usage = SimpleNamespace(data={"computer_block": {
            "enabled": True, "mode": "schedule",
            "daily_start": "18:00", "daily_end": "20:00",
            "valid_from": "2026-08-20", "valid_from_time": "18:30",
            "valid_until": "2026-08-25", "valid_until_time": "19:30",
        }})
        before = limiter.computer_block_status(
            datetime.fromisoformat("2026-08-19T19:00:00+02:00")
        )
        during = limiter.computer_block_status(
            datetime.fromisoformat("2026-08-22T19:00:00+02:00")
        )
        after = limiter.computer_block_status(
            datetime.fromisoformat("2026-08-26T19:00:00+02:00")
        )
        self.assertTrue(before["pending"])
        self.assertTrue(during["active"])
        self.assertFalse(after["active"])
        self.assertFalse(after["pending"])

    def test_recurring_computer_block_crosses_midnight(self):
        limiter = AppLimiter.__new__(AppLimiter)
        limiter.usage = SimpleNamespace(data={"computer_block": {
            "enabled": True, "mode": "schedule",
            "daily_start": "23:00", "daily_end": "02:00",
            "valid_from": "", "valid_from_time": "",
            "valid_until": "", "valid_until_time": "",
        }})

        before_midnight = limiter.computer_block_status(
            datetime.fromisoformat("2026-08-15T23:30:00+02:00")
        )
        after_midnight = limiter.computer_block_status(
            datetime.fromisoformat("2026-08-16T01:30:00+02:00")
        )
        outside = limiter.computer_block_status(
            datetime.fromisoformat("2026-08-16T12:00:00+02:00")
        )

        self.assertTrue(before_midnight["active"])
        self.assertTrue(after_midnight["active"])
        self.assertEqual(after_midnight["daily_start"], "23:00")
        self.assertEqual(after_midnight["daily_end"], "02:00")
        self.assertFalse(outside["active"])
        self.assertTrue(outside["pending"])

    def test_multiple_computer_blocks_keep_short_and_overnight_rules(self):
        now = datetime.fromisoformat("2026-08-28T19:31:00+02:00")
        with tempfile.TemporaryDirectory() as directory:
            usage = AppUsageStore(Path(directory) / "activity.json")
            short = usage.set_computer_block(
                "schedule", "admin",
                start_time="19:30", end_time="19:32", now=now,
            )
            night = usage.set_computer_block(
                "schedule", "admin",
                start_time="22:30", end_time="05:00", now=now,
            )
            limiter = AppLimiter.__new__(AppLimiter)
            limiter.usage = usage

            statuses = {
                item["block_id"]: item
                for item in limiter.computer_block_statuses(now)
            }

            self.assertTrue(statuses[short["block_id"]]["active"])
            self.assertTrue(statuses[night["block_id"]]["pending"])
            self.assertEqual(
                limiter.computer_block_status(now)["block_id"],
                short["block_id"],
            )
            self.assertEqual(
                limiter.computer_block_status(
                    datetime.fromisoformat("2026-08-28T23:00:00+02:00")
                )["block_id"],
                night["block_id"],
            )

    def test_clearing_one_overlapping_block_keeps_the_other_enforced(self):
        now = datetime.now().astimezone()
        with tempfile.TemporaryDirectory() as directory:
            usage = AppUsageStore(Path(directory) / "activity.json")
            first = usage.set_computer_block(
                "duration", "admin", duration_seconds=600, now=now,
            )
            second = usage.set_computer_block(
                "duration", "admin", duration_seconds=1200, now=now,
            )
            shown = []
            limiter = AppLimiter.__new__(AppLimiter)
            limiter.usage = usage
            limiter._decision_mirror = None
            limiter._computer_block_warning_shown = set()
            limiter._displayed_computer_block = {}
            limiter.computer_overlay = SimpleNamespace(
                hide=lambda: None,
                show_block=lambda *_args, **_kwargs: shown.append(
                    limiter.displayed_computer_block()
                ),
            )
            limiter.computer_grace_window = SimpleNamespace(
                hide=lambda: None, show_countdown=lambda *_args: None,
            )

            limiter.refresh_computer_block(now)
            self.assertEqual(
                limiter.displayed_computer_block()["block_id"],
                first["block_id"],
            )
            self.assertTrue(limiter.clear_computer_block())

            self.assertEqual(
                [item["block_id"] for item in usage.computer_blocks()],
                [second["block_id"]],
            )
            self.assertEqual(
                limiter.displayed_computer_block()["block_id"],
                second["block_id"],
            )
            self.assertGreaterEqual(len(shown), 2)

    def test_grace_for_one_overlapping_rule_does_not_unblock_the_other(self):
        now = datetime.fromisoformat("2026-08-28T19:50:00+02:00")
        with tempfile.TemporaryDirectory() as directory:
            usage = AppUsageStore(Path(directory) / "activity.json")
            blocks = []
            for start, end in (
                ("19:30", "20:00"), ("19:45", "20:15"),
            ):
                blocks.append(usage.set_computer_block(
                    "schedule", "admin",
                    start_time=start, end_time=end, now=now,
                ))
            first_id, second_id = [item["block_id"] for item in blocks]
            limiter = AppLimiter.__new__(AppLimiter)
            limiter.usage = usage
            limiter._decision_mirror = SimpleNamespace(
                computer_block_grace=lambda occurrence, start=False: {
                    "active": occurrence["block_id"] == first_id,
                    "available": occurrence["block_id"] != first_id,
                    "used": occurrence["block_id"] == first_id,
                    "ends_at": "2026-08-28T19:55:00+02:00",
                }
            )
            limiter._computer_block_warning_shown = set()
            limiter._displayed_computer_block = {}
            limiter.computer_overlay = SimpleNamespace(
                hide=lambda: None, show_block=lambda *_args, **_kwargs: None,
            )
            limiter.computer_grace_window = SimpleNamespace(
                hide=lambda: None, show_countdown=lambda *_args: None,
            )

            limiter.refresh_computer_block(now)

            self.assertEqual(
                limiter.displayed_computer_block()["block_id"], second_id
            )

    def test_active_recurring_computer_block_restores_the_overlay(self):
        calls = []
        limiter = AppLimiter.__new__(AppLimiter)
        limiter.usage = SimpleNamespace(data={"computer_block": {
            "enabled": True, "mode": "schedule",
            "managed_by": "backend",
            "daily_start": "17:35", "daily_end": "17:40",
            "valid_from": "", "valid_from_time": "",
            "valid_until": "", "valid_until_time": "",
        }})
        limiter._decision_mirror = SimpleNamespace(
            computer_block_grace=lambda *_args, **_kwargs: {
                "state": "available", "available": True,
                "active": False, "used": False,
            }
        )
        limiter._decision_core_enabled = lambda: True
        limiter.computer_overlay = SimpleNamespace(
            show_block=lambda ends_at, **options: calls.append(
                ("show", ends_at, options)
            ),
            hide=lambda: calls.append(("hide",)),
        )
        limiter.computer_grace_window = SimpleNamespace(
            hide=lambda: calls.append(("hide-grace",))
        )
        limiter._computer_block_warning_shown = set()

        status = limiter.refresh_computer_block(
            datetime.fromisoformat("2026-08-28T17:37:00+02:00")
        )

        self.assertTrue(status["active"])
        shown = next(call for call in calls if call[0] == "show")
        self.assertEqual(shown[1], "2026-08-28T17:40:00+02:00")
        self.assertTrue(shown[2]["grace_available"])
        self.assertFalse(shown[2]["can_cancel"])
        source = (Path(__file__).parents[1] / "app_limiter.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("~Qt.WindowState.WindowMinimized", source)
        self.assertIn("user32.SetWindowPos", source)

    def test_daily_duration_computer_block_activates_after_quota(self):
        limiter = AppLimiter.__new__(AppLimiter)
        usage = SimpleNamespace(data={"computer_block": {
            "enabled": True, "mode": "daily_duration",
            "limit_seconds": 3600,
            "valid_from": "", "valid_from_time": "",
            "valid_until": "", "valid_until_time": "",
            "schedule_start": "", "schedule_end": "",
        }})
        usage.system_usage_for_day = lambda _day: {"on": usage.on_seconds}
        limiter.usage = usage

        now = datetime.fromisoformat("2026-08-20T12:00:00+02:00")
        usage.on_seconds = 3599
        before = limiter.computer_block_status(now)
        usage.on_seconds = 3600
        after = limiter.computer_block_status(now)

        self.assertFalse(before["active"])
        self.assertTrue(before["pending"])
        self.assertTrue(after["active"])
        self.assertEqual(after["allowed"], 3600)

    def test_daily_computer_block_occurrence_is_stable_across_refreshes(self):
        limiter = AppLimiter.__new__(AppLimiter)
        limiter.usage = SimpleNamespace(
            data={"computer_block": {
                "enabled": True, "mode": "daily_duration",
                "limit_seconds": 60,
                "valid_from": "", "valid_from_time": "",
                "valid_until": "", "valid_until_time": "",
                "schedule_start": "", "schedule_end": "",
            }},
            system_usage_for_day=lambda _day: {"on": 60},
        )

        first = limiter.computer_block_status(
            datetime.fromisoformat("2026-08-24T12:00:00+02:00")
        )
        refreshed = limiter.computer_block_status(
            datetime.fromisoformat("2026-08-24T12:01:00+02:00")
        )

        self.assertTrue(first["active"])
        self.assertEqual(first["started_at"], refreshed["started_at"])
        self.assertEqual(first["ends_at"], refreshed["ends_at"])
        self.assertIn("T00:00:00", first["started_at"])

    def test_computer_close_grace_starts_only_after_explicit_action(self):
        calls = []
        grace_started = {"value": False}

        def computer_block_grace(occurrence, start=False):
            calls.append((dict(occurrence), start))
            grace_started["value"] = grace_started["value"] or start
            return {
                "state": "active" if grace_started["value"] else "available",
                "available": not grace_started["value"],
                "active": grace_started["value"],
                "used": grace_started["value"],
                "ends_at": "2026-08-24T12:05:00+02:00",
            }

        service = SimpleNamespace(computer_block_grace=computer_block_grace)
        limiter = AppLimiter.__new__(AppLimiter)
        limiter._decision_mirror = service
        limiter.usage = SimpleNamespace(data={"computer_block": {
            "block_id": "daily",
            "enabled": True, "mode": "daily_duration",
            "limit_seconds": 60,
            "valid_from": "", "valid_from_time": "",
            "valid_until": "", "valid_until_time": "",
            "schedule_start": "", "schedule_end": "",
        }}, system_usage_for_day=lambda _day: {"on": 61})
        limiter.computer_overlay = SimpleNamespace(
            hide=lambda: None, show_block=lambda *_args, **_kwargs: None,
        )
        limiter.computer_grace_window = SimpleNamespace(
            hide=lambda: None,
            show_countdown=lambda ends_at, *_args: calls.append(
                ("countdown", ends_at)
            ),
        )
        limiter._computer_block_warning_shown = set()
        limiter._displayed_computer_block = {}

        status = limiter.computer_block_status(
            datetime.fromisoformat("2026-08-24T12:00:00+02:00")
        )
        available = limiter._computer_close_grace(status)

        self.assertTrue(available["available"])
        self.assertEqual(calls[-1][1], False)
        limiter._displayed_computer_block = limiter._computer_block_occurrence(status)
        limiter.computer_block_status = lambda _now=None, block_id=None: dict(status)
        self.assertTrue(limiter.start_computer_close_grace())
        self.assertTrue(any(call[1] is True for call in calls if isinstance(call[0], dict)))
        self.assertIn(("countdown", "2026-08-24T12:05:00+02:00"), calls)

    def test_shutdown_and_restart_do_not_force_close_applications(self):
        calls = []
        limiter = AppLimiter.__new__(AppLimiter)
        limiter.computer_overlay = SimpleNamespace(hide=lambda: calls.append("hide-block"))
        limiter.computer_grace_window = SimpleNamespace(hide=lambda: calls.append("hide-grace"))
        limiter._power_launcher = lambda operation: calls.append(operation)

        self.assertTrue(limiter.shutdown_computer())
        self.assertTrue(limiter.restart_computer())

        self.assertIn("shutdown", calls)
        self.assertIn("restart", calls)
        source = (Path(__file__).parents[1] / "app_limiter.py").read_text(encoding="utf-8")
        self.assertIn('["shutdown.exe", argument, "/t", "0"]', source)
        self.assertNotIn('["shutdown.exe", argument, "/f"', source)

    def test_active_close_grace_hides_block_and_expired_grace_reblocks(self):
        now = datetime.fromisoformat("2026-08-24T12:00:00+02:00")
        block = {
            "enabled": True, "mode": "duration",
            "started_at": "2026-08-24T11:00:00+02:00",
            "ends_at": "2026-08-24T13:00:00+02:00",
        }
        calls = []
        grace = {"active": True, "available": False, "used": True,
                 "ends_at": "2026-08-24T12:05:00+02:00"}
        limiter = AppLimiter.__new__(AppLimiter)
        limiter.usage = SimpleNamespace(data={"computer_block": block})
        limiter._decision_mirror = SimpleNamespace(
            computer_block_grace=lambda *_args, **_kwargs: dict(grace)
        )
        limiter.computer_overlay = SimpleNamespace(
            hide=lambda: calls.append("hide-block"),
            show_block=lambda *args, **kwargs: calls.append(("block", args, kwargs)),
        )
        limiter.computer_grace_window = SimpleNamespace(
            hide=lambda: calls.append("hide-grace"),
            show_countdown=lambda ends_at, supplied_now=None: calls.append(
                ("countdown", ends_at, supplied_now)
            ),
        )
        limiter._computer_block_warning_shown = set()

        active = limiter.refresh_computer_block(now)

        self.assertTrue(active["close_grace"]["active"])
        self.assertIn("hide-block", calls)
        self.assertIn(("countdown", grace["ends_at"], now), calls)

        calls.clear()
        grace.update({"active": False, "state": "expired"})
        expired = limiter.refresh_computer_block(now)

        self.assertFalse(expired["close_grace"]["active"])
        shown = next(call for call in calls if isinstance(call, tuple) and call[0] == "block")
        self.assertFalse(shown[2]["grace_available"])

    def test_computer_block_snapshot_exposes_service_grace_state(self):
        limiter = AppLimiter.__new__(AppLimiter)
        limiter.computer_block_status = lambda _now=None: {
            "active": True, "mode": "schedule",
            "started_at": "2026-08-24T12:00:00+02:00",
            "ends_at": "2026-08-24T13:00:00+02:00",
        }
        limiter._decision_mirror = SimpleNamespace(
            computer_block_grace=lambda *_args, **_kwargs: {
                "state": "active", "active": True,
                "available": False, "used": True,
                "remaining_seconds": 180,
            }
        )

        snapshot = limiter.computer_block_snapshot()

        self.assertEqual(snapshot["close_grace"]["state"], "active")
        self.assertEqual(snapshot["close_grace"]["remaining_seconds"], 180)

    def test_application_schedule_crosses_midnight(self):
        policy = {"schedule_start": "23:00", "schedule_end": "02:00"}
        self.assertTrue(AppLimiter._schedule_status(
            policy, datetime.fromisoformat("2026-08-15T23:30:00+02:00")
        )["active"])
        self.assertTrue(AppLimiter._schedule_status(
            policy, datetime.fromisoformat("2026-08-16T01:30:00+02:00")
        )["active"])
        self.assertFalse(AppLimiter._schedule_status(
            policy, datetime.fromisoformat("2026-08-16T12:00:00+02:00")
        )["active"])

    def test_recurring_computer_block_is_kept_until_final_validity_end(self):
        block = {
            "enabled": True, "mode": "schedule",
            "daily_start": "18:00", "daily_end": "20:00",
            "valid_from": "2026-08-15", "valid_from_time": "18:00",
            "valid_until": "2026-08-15", "valid_until_time": "21:00",
        }
        usage = SimpleNamespace(data={"computer_block": block})
        usage.clear_computer_block = lambda: usage.data.update(computer_block={})
        limiter = AppLimiter.__new__(AppLimiter)
        limiter.usage = usage
        limiter.computer_overlay = SimpleNamespace(
            show_block=lambda _ends_at: None, hide=lambda: None,
        )
        limiter._computer_block_warning_shown = set()

        status = limiter.refresh_computer_block(
            datetime.fromisoformat("2026-08-15T20:30:00+02:00")
        )

        self.assertFalse(status["active"])
        self.assertFalse(status["pending"])
        self.assertEqual(usage.data["computer_block"], block)

        limiter.refresh_computer_block(
            datetime.fromisoformat("2026-08-15T21:00:00+02:00")
        )
        self.assertEqual(usage.data["computer_block"], {})

    def test_multiple_warning_rules_are_kept_for_the_same_target(self):
        limiter = AppLimiter.__new__(AppLimiter)
        limiter.usage = SimpleNamespace(data={"notification_rules": [
            {"id": "fifteen", "kind": "limit_warning", "enabled": True,
             "target_key": "", "warning_seconds": 900},
            {"id": "five", "kind": "limit_warning", "enabled": True,
             "target_key": "", "warning_seconds": 300},
        ]})
        self.assertEqual(limiter._warning_rules("computer:all"), [
            ("fifteen", 900), ("five", 300),
        ])
        self.assertEqual(limiter.computer_block_warning_seconds(), 900)


    def test_period_block_has_no_allowed_usage_while_active(self):
        limiter = AppLimiter.__new__(AppLimiter)
        limiter.policies = {"app:test": {
            "enabled": True,
            "block_during_validity": True,
            "limit_seconds": 3600,
            "extension_seconds": 0,
            "valid_from": "2026-08-15", "valid_from_time": "10:00",
            "valid_until": "2026-08-15", "valid_until_time": "20:00",
            "schedule_date": "", "schedule_start": "", "schedule_end": "",
            "blocked_after": "",
        }}
        limiter.usage = SimpleNamespace(
            app_limit_state_for_day=lambda _key: {"seconds": 0, "extension_used": False}
        )

        with patch("app_limiter.datetime") as clock:
            clock.now.return_value = datetime.fromisoformat("2026-08-15T12:00:00+02:00")
            clock.combine.side_effect = datetime.combine
            clock.strptime.side_effect = datetime.strptime
            status = limiter.current_status("app:test")

        self.assertEqual(status["allowed"], 0)
        self.assertEqual(status["remaining"], 0)


class TrayProgressCardTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_no_progress_bar_is_kept_when_no_limit_is_active(self):
        policies = {"app:test": {"enabled": True}}
        limiter = SimpleNamespace(
            policies=policies,
            current_status=lambda _key: {
                "seconds": 30, "allowed": 60, "remaining": 30,
            },
            label_for_key=lambda _key: "Test",
        )
        usage = SimpleNamespace(
            usage_for_day=lambda: {}, presentation=lambda _usage: [],
        )
        card = TrayProgressCard(SimpleNamespace(app_limiter=limiter, usage=usage))

        labels = [label.text() for label in card.findChildren(QLabel)]
        self.assertIn("Limitations aujourd’hui", labels)
        self.assertNotIn("Usage Guard · aujourd’hui", labels)
        self.assertFalse(any(text.startswith("Temps actif") for text in labels))

        card.refresh()
        self.assertEqual(len(card.findChildren(QProgressBar)), 1)

        policies["app:test"]["enabled"] = False
        card.refresh()

        self.assertTrue(card.rows_widget.isHidden())
        self.assertFalse(card.empty_state.isHidden())
        self.assertEqual(card.findChildren(QProgressBar), [])

    def test_pending_daily_computer_limit_has_no_fake_progress_bar(self):
        today = datetime.now().astimezone().date().isoformat()
        limiter = SimpleNamespace(
            policies={},
            computer_block_status=lambda: {
                "enabled": True, "mode": "schedule",
                "active": False, "pending": True,
                "started_at": f"{today}T14:00:00+02:00",
                "ends_at": f"{today}T18:00:00+02:00",
            },
        )
        usage = SimpleNamespace(
            usage_for_day=lambda: {}, presentation=lambda _usage: [],
        )
        card = TrayProgressCard(SimpleNamespace(app_limiter=limiter, usage=usage))

        card.refresh()

        self.assertTrue(card.empty_state.isHidden())
        self.assertFalse(card.rows_widget.isHidden())
        self.assertEqual(card.findChildren(QProgressBar), [])
        labels = [label.text() for label in card.findChildren(QLabel)]
        self.assertIn("Tout l’ordinateur", labels)
        self.assertTrue(any("14:00" in text and "18:00" in text for text in labels))
        self.assertTrue(any(label.objectName() == "limitRemaining" for label in card.findChildren(QLabel)))

    def test_active_computer_limit_is_orange_immediately(self):
        now = datetime.now().astimezone()
        limiter = SimpleNamespace(
            policies={},
            computer_block_status=lambda: {
                "enabled": True, "mode": "absolute_range",
                "active": True, "pending": False,
                "started_at": (now - timedelta(seconds=15)).isoformat(),
                "ends_at": (now + timedelta(seconds=45)).isoformat(),
            },
        )
        card = TrayProgressCard(SimpleNamespace(app_limiter=limiter))

        card.refresh()

        remaining = next(
            label for label in card.findChildren(QLabel)
            if label.objectName() == "limitRemaining"
        )
        self.assertIn("#f59e0b", remaining.styleSheet())

    def test_pending_computer_limit_uses_the_configured_warning_window(self):
        now = datetime.now().astimezone()
        status = {
            "enabled": True, "mode": "schedule",
            "active": False, "pending": True,
            "started_at": (now + timedelta(seconds=169)).isoformat(),
            "ends_at": (now + timedelta(seconds=289)).isoformat(),
            "daily_start": (now + timedelta(seconds=169)).strftime("%H:%M"),
            "daily_end": (now + timedelta(seconds=289)).strftime("%H:%M"),
        }
        limiter = SimpleNamespace(
            policies={},
            computer_block_status=lambda: dict(status),
            computer_block_warning_due=lambda block, supplied_now: (
                block["pending"]
                and (
                    datetime.fromisoformat(block["started_at"]) - supplied_now
                ).total_seconds() <= 300
            ),
        )
        card = TrayProgressCard(SimpleNamespace(app_limiter=limiter))

        card.refresh()

        remaining = next(
            label for label in card.findChildren(QLabel)
            if label.objectName() == "limitRemaining"
        )
        self.assertIn("#f59e0b", remaining.styleSheet())

    def test_tomorrows_computer_limit_is_not_listed_as_today(self):
        tomorrow = (datetime.now().astimezone() + timedelta(days=1)).date().isoformat()
        limiter = SimpleNamespace(
            policies={},
            computer_block_status=lambda: {
                "enabled": True, "mode": "absolute_range",
                "active": False, "pending": True,
                "started_at": f"{tomorrow}T22:00:00+02:00",
                "ends_at": f"{tomorrow}T23:00:00+02:00",
            },
        )
        card = TrayProgressCard(SimpleNamespace(app_limiter=limiter))

        card.refresh()

        self.assertFalse(card.empty_state.isHidden())
        self.assertTrue(card.rows_widget.isHidden())
        self.assertNotIn(
            "Tout l’ordinateur",
            [label.text() for label in card.findChildren(QLabel)],
        )

    def test_configured_computer_limit_stays_visible_outside_its_time_range(self):
        limiter = SimpleNamespace(
            policies={},
            computer_block_status=lambda: {
                "enabled": True, "mode": "schedule",
                "active": False, "pending": False,
                "daily_start": "14:00", "daily_end": "18:00",
            },
        )
        usage = SimpleNamespace(
            usage_for_day=lambda: {}, presentation=lambda _usage: [],
        )
        card = TrayProgressCard(SimpleNamespace(app_limiter=limiter, usage=usage))

        card.refresh()

        self.assertTrue(card.empty_state.isHidden())
        self.assertEqual(card.findChildren(QProgressBar), [])
        labels = [label.text() for label in card.findChildren(QLabel)]
        self.assertTrue(any("14:00" in text and "18:00" in text for text in labels))

    def test_configured_application_hourly_limit_stays_visible_outside_time_range(self):
        limiter = SimpleNamespace(
            policies={"app:test": {
                "enabled": True,
                "limit_seconds": 3600,
                "extension_seconds": 900,
                "warning_seconds": 300,
                "schedule_start": "14:00",
                "schedule_end": "18:00",
            }},
            current_status=lambda _key: {
                "seconds": 0, "allowed": 3600, "remaining": 3600,
                "schedule_active": False, "schedule_pending": False,
            },
            label_for_key=lambda _key: "Application test",
            computer_block_status=lambda: {},
        )
        usage = SimpleNamespace(
            usage_for_day=lambda: {}, presentation=lambda _usage: [],
        )
        card = TrayProgressCard(SimpleNamespace(app_limiter=limiter, usage=usage))

        card.refresh()

        self.assertTrue(card.empty_state.isHidden())
        labels = [label.text() for label in card.findChildren(QLabel)]
        self.assertIn("Application test", labels)
        self.assertTrue(any("14:00" in text and "18:00" in text for text in labels))
        self.assertEqual(card.findChildren(QProgressBar), [])

    def test_temporal_application_limit_uses_the_same_progress_layout(self):
        today = datetime.now().astimezone().date()
        limiter = SimpleNamespace(
            policies={"app:test": {
                "enabled": True, "block_during_validity": True,
                "valid_from": today.isoformat(), "valid_from_time": "00:00",
                "valid_until": today.isoformat(), "valid_until_time": "23:59",
            }},
            current_status=lambda _key: {
                "seconds": 0, "allowed": 0, "remaining": 0,
                "schedule_active": True, "schedule_pending": False,
            },
            label_for_key=lambda _key: "Application test",
            computer_block_status=lambda: {},
        )
        usage = SimpleNamespace(
            usage_for_day=lambda: {}, presentation=lambda _usage: [],
        )
        card = TrayProgressCard(SimpleNamespace(app_limiter=limiter, usage=usage))

        card.refresh()

        labels = [label.text() for label in card.findChildren(QLabel)]
        self.assertIn("Application test", labels)
        self.assertTrue(any(today.strftime("%d/%m/%Y") in text for text in labels))
        self.assertEqual(len(card.findChildren(QProgressBar)), 1)

    def test_multiday_temporal_limit_is_bounded_to_today_in_the_tray(self):
        now = datetime.fromisoformat("2026-08-28T18:55:00+02:00")
        policy = {
            "block_during_validity": True,
            "valid_from": "2026-08-28", "valid_from_time": "00:00",
            "valid_until": "2026-08-31", "valid_until_time": "23:59",
        }

        starts_at, ends_at = _today_temporal_bounds(
            policy, now, active=True,
        )

        self.assertEqual(starts_at.isoformat(), "2026-08-28T00:00:00+02:00")
        self.assertEqual(ends_at.isoformat(), "2026-08-29T00:00:00+02:00")
        self.assertEqual((ends_at - now).total_seconds(), 5 * 3600 + 5 * 60)

    def test_future_temporal_limit_does_not_overlap_today(self):
        now = datetime.fromisoformat("2026-08-28T18:55:00+02:00")
        policy = {
            "block_during_validity": True,
            "valid_from": "2026-08-31", "valid_from_time": "00:00",
            "valid_until": "2026-08-31", "valid_until_time": "23:59",
        }

        self.assertFalse(_temporal_overlaps_today(policy, now))

    def test_cross_midnight_temporal_occurrence_overlaps_today(self):
        now = datetime.fromisoformat("2026-08-28T01:00:00+02:00")
        policy = {
            "block_during_validity": True,
            "valid_from": "2026-08-27", "valid_from_time": "00:00",
            "valid_until": "2026-08-31", "valid_until_time": "23:59",
            "schedule_start": "23:00", "schedule_end": "02:00",
        }

        self.assertTrue(_temporal_overlaps_today(policy, now))

    def test_future_pending_temporal_limit_is_absent_from_today_card(self):
        future = datetime.now().astimezone().date() + timedelta(days=3)
        limiter = SimpleNamespace(
            policies={"category:test": {
                "enabled": True, "block_during_validity": True,
                "valid_from": future.isoformat(), "valid_from_time": "00:00",
                "valid_until": future.isoformat(), "valid_until_time": "23:59",
            }},
            current_status=lambda _key: {
                "seconds": 0, "allowed": 0, "remaining": 0,
                "schedule_active": False, "schedule_pending": True,
            },
            label_for_key=lambda _key: "Catégorie future",
            computer_block_status=lambda: {},
        )
        card = TrayProgressCard(SimpleNamespace(app_limiter=limiter))

        card.refresh()

        labels = [label.text() for label in card.findChildren(QLabel)]
        self.assertNotIn("Catégorie future", labels)
        self.assertFalse(card.empty_state.isHidden())

    def test_multiday_temporal_card_does_not_display_global_end_date(self):
        today = datetime.now().astimezone().date()
        tomorrow = today + timedelta(days=1)
        global_end = today + timedelta(days=3)
        limiter = SimpleNamespace(
            policies={"category:test": {
                "enabled": True, "block_during_validity": True,
                "valid_from": today.isoformat(), "valid_from_time": "00:00",
                "valid_until": global_end.isoformat(), "valid_until_time": "23:59",
            }},
            current_status=lambda _key: {
                "seconds": 0, "allowed": 0, "remaining": 0,
                "schedule_active": True, "schedule_pending": False,
            },
            label_for_key=lambda _key: "Catégorie test",
            computer_block_status=lambda: {},
        )
        card = TrayProgressCard(SimpleNamespace(app_limiter=limiter))

        card.refresh()

        details = [
            label.text() for label in card.findChildren(QLabel)
            if label.objectName() == "limitTime"
        ]
        self.assertTrue(any(
            tomorrow.strftime("%d/%m/%Y 00:00") in text for text in details
        ))
        self.assertFalse(any(
            global_end.strftime("%d/%m/%Y") in text for text in details
        ))

    def test_scheduled_temporal_limit_uses_the_current_occurrence_end(self):
        now = datetime.fromisoformat("2026-08-28T18:55:00+02:00")
        policy = {
            "block_during_validity": True,
            "valid_from": "2026-08-28", "valid_from_time": "00:00",
            "valid_until": "2026-08-31", "valid_until_time": "23:59",
            "schedule_start": "18:00", "schedule_end": "20:00",
        }

        starts_at, ends_at = _today_temporal_bounds(
            policy, now, active=True,
        )

        self.assertEqual(starts_at.isoformat(), "2026-08-28T18:00:00+02:00")
        self.assertEqual(ends_at.isoformat(), "2026-08-28T20:00:00+02:00")
        self.assertEqual((ends_at - now).total_seconds(), 65 * 60)

    def test_tray_icon_blinks_for_low_duration_limits_only(self):
        script = (Path(__file__).parents[1] / "gui.py").read_text(encoding="utf-8")

        self.assertIn("def has_duration_limit_alert", script)
        self.assertIn('item.get("block_during_validity")', script)
        self.assertIn("remaining / allowed <= .1", script)
        self.assertIn("icon._alert_icon", script)
        self.assertIn("blink_timer.start()", script)


if __name__ == "__main__":
    unittest.main()
