import os
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app_limiter import AppLimiter
from PySide6.QtWidgets import QApplication, QLabel, QProgressBar

from gui import TrayProgressCard, _compact_duration, _format_seconds


class DurationFormattingTest(unittest.TestCase):
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

    def test_pending_computer_limit_is_shown_without_progress_bar(self):
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
        self.assertTrue(any("hors plage" in text for text in labels))


if __name__ == "__main__":
    unittest.main()
