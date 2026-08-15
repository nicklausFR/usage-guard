import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from observation_journal import ObservationJournal, rebuild_active_seconds


class ObservationJournalTest(unittest.TestCase):
    def test_records_transitions_and_periodic_heartbeats_only(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = ObservationJournal(directory, heartbeat_seconds=60)
            start = datetime.fromisoformat("2026-08-14T10:00:00+02:00")
            state = {
                "target_key": "app:chatgpt",
                "has_recent_input": True,
                "idle_seconds": 0,
            }

            self.assertTrue(journal.record(state, start))
            self.assertFalse(journal.record({**state, "idle_seconds": 5}, start + timedelta(seconds=5)))
            self.assertTrue(journal.record({**state, "idle_seconds": 61}, start + timedelta(seconds=61)))
            self.assertTrue(journal.record(
                {**state, "has_recent_input": False, "idle_seconds": 62},
                start + timedelta(seconds=62),
            ))

            lines = [
                json.loads(line)
                for line in (Path(directory) / "2026-08-14.jsonl").read_text(
                    encoding="utf-8"
                ).splitlines()
            ]
            self.assertEqual([line["type"] for line in lines], [
                "state_change", "heartbeat", "state_change"
            ])
            self.assertEqual(lines[-1]["state"]["target_key"], "app:chatgpt")

    def test_disabled_journal_does_not_create_a_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "observations"
            journal = ObservationJournal(path, enabled=False)

            self.assertFalse(journal.record({"target_key": "app:test"}))
            self.assertFalse(path.exists())

    def test_rebuilds_active_time_without_counting_restart_gaps(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = ObservationJournal(directory, heartbeat_seconds=60)
            start = datetime.fromisoformat("2026-08-14T10:00:00+02:00")
            journal.event("service_start", at=start)
            journal.record({
                "target_key": "app:chatgpt", "counted_active": True
            }, at=start)
            journal.record({
                "target_key": "app:code", "counted_active": True
            }, at=start + timedelta(seconds=30))
            journal.event("service_stop", at=start + timedelta(seconds=50))
            journal.event("service_start", at=start + timedelta(hours=2))
            journal.record({
                "target_key": "app:chatgpt", "counted_active": False
            }, at=start + timedelta(hours=2))

            totals = rebuild_active_seconds(directory)

            self.assertEqual(totals, {"app:chatgpt": 30.0, "app:code": 20.0})


if __name__ == "__main__":
    unittest.main()
