import os
import sys
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app_limiter import AppLimiter
from PySide6.QtWidgets import QApplication, QLabel, QProgressBar

from gui import TrayProgressCard, _compact_duration, _format_seconds


class DurationFormattingTest(unittest.TestCase):
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
            emails, [("Préavis", "Cinq minutes", "owner@example.test")]
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
                "kind": "limit_warning", "enabled": True, "target_key": "",
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
        self.assertIn("limite atteinte", emitted[0][0])

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
        limiter = SimpleNamespace(
            policies={},
            computer_block_status=lambda: {
                "enabled": True, "mode": "schedule",
                "active": False, "pending": True,
                "started_at": "2026-08-15T14:00:00+02:00",
                "ends_at": "2026-08-15T18:00:00+02:00",
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
        limiter = SimpleNamespace(
            policies={"app:test": {
                "enabled": True, "block_during_validity": True,
                "valid_from": "2026-08-16", "valid_from_time": "10:00",
                "valid_until": "2026-08-16", "valid_until_time": "12:00",
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
        self.assertTrue(any("16/08/2026 10:00" in text for text in labels))
        self.assertEqual(len(card.findChildren(QProgressBar)), 1)

    def test_tray_icon_blinks_for_low_duration_limits_only(self):
        script = (Path(__file__).parents[1] / "gui.py").read_text(encoding="utf-8")

        self.assertIn("def has_duration_limit_alert", script)
        self.assertIn('item.get("block_during_validity")', script)
        self.assertIn("remaining / allowed <= .1", script)
        self.assertIn("icon._alert_icon", script)
        self.assertIn("blink_timer.start()", script)


if __name__ == "__main__":
    unittest.main()
