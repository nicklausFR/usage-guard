import sys
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from service_backend_bridge import ServiceBackendBridge, _validate_activity_export


class ServiceBackendBridgeTest(unittest.TestCase):
    def test_activity_export_accepts_other_site_daily_metric(self):
        activity_export = {
            "intervals": [], "live_intervals": [],
            "daily_aggregates": [{
                "aggregate_id": "daily-v1-" + "e" * 64,
                "local_day": "2026-09-03",
                "metrics": [{
                    "kind": "other_site",
                    "key": "site:firefox.exe:example.org",
                    "seconds": 42.5,
                }],
            }],
            "cursor": 0, "bytes": 0,
        }

        self.assertIs(_validate_activity_export(activity_export), activity_export)

    def test_daily_aggregates_are_persisted_before_desktop_ack(self):
        calls = []
        aggregate = {
            "aggregate_id": "daily-v1-" + "a" * 64,
            "local_day": "2026-08-03",
            "metrics": [{
                "kind": "usage", "key": "app:kona", "seconds": 60,
            }],
        }

        class Decision:
            external_service = True

            def publish_desktop_state(self, *_args, **kwargs):
                calls.append(("persist", kwargs["activity_export"]))

            def next_backend_command(self):
                return None

        class Desktop:
            def request_remote_snapshot(self, timeout=5):
                return {"usage": []}

            def request_activity_export(self, timeout=5):
                return {
                    "intervals": [], "live_intervals": [],
                    "daily_aggregates": [aggregate],
                    "cursor": 0, "bytes": 0,
                }

            def acknowledge_activity_export(
                self, cursor, aggregate_ids=None, timeout=5,
            ):
                calls.append(("ack", cursor, aggregate_ids))

        ServiceBackendBridge(Decision(), Desktop()).sync_once()

        self.assertEqual([item[0] for item in calls], ["persist", "ack"])
        self.assertEqual(calls[1][2], [aggregate["aggregate_id"]])

    def test_oversized_activity_export_is_rejected_before_service_ipc(self):
        calls = []

        class Decision:
            external_service = True

            def publish_desktop_state(self, *args, **kwargs):
                calls.append((args, kwargs))

            def next_backend_command(self):
                return None

        class Desktop:
            def request_remote_snapshot(self, timeout=5):
                return {"usage": []}

            def request_activity_export(self, timeout=5):
                return {
                    "intervals": [{"record_id": str(index)} for index in range(501)],
                    "live_intervals": [], "cursor": 1, "bytes": 1,
                }

        with self.assertRaisesRegex(RuntimeError, "item limit"):
            ServiceBackendBridge(Decision(), Desktop()).sync_once()
        self.assertEqual(calls, [])

    def test_activity_export_rejects_unknown_archive_shaped_fields(self):
        class Decision:
            external_service = True

            def next_backend_command(self):
                return None

        class Desktop:
            def request_remote_snapshot(self, timeout=5):
                return {"usage": []}

            def request_activity_export(self, timeout=5):
                return {
                    "intervals": [], "live_intervals": [], "cursor": 0,
                    "activity": {"days": {"2026-08-30": {}}},
                }

        with self.assertRaisesRegex(RuntimeError, "invalid"):
            ServiceBackendBridge(Decision(), Desktop()).sync_once()

    def test_background_failure_is_logged_instead_of_hidden(self):
        messages = []

        class Decision:
            external_service = True

        class Desktop:
            pass

        bridge = ServiceBackendBridge(
            Decision(), Desktop(), interval_seconds=0.2,
            logger=messages.append,
        )
        bridge.sync_once = lambda: (_ for _ in ()).throw(
            RuntimeError("ipc too large")
        )

        bridge.start()
        time.sleep(0.25)
        bridge.stop()

        self.assertEqual(len(messages), 1)
        self.assertIn("RuntimeError: ipc too large", messages[0])

    def test_sync_publishes_state_then_applies_and_completes_command(self):
        calls = []

        class Decision:
            external_service = True

            def publish_desktop_state(
                self, snapshot, activity=None, *, activity_unchanged=False,
                activity_export=None,
            ):
                calls.append((
                    "publish", snapshot, activity, activity_unchanged,
                    activity_export,
                ))

            def next_backend_command(self):
                return {
                    "service_command_id": "9",
                    "command": {"action": "set_language", "language": "fr"},
                }

            def complete_backend_command(self, command_id, result):
                calls.append(("complete", command_id, result))

        class Desktop:
            def request_remote_snapshot(self, timeout=5):
                return {"usage": []}

            def request_activity_store(self, timeout=5):
                return {"days": {}}

            def request_activity_export(self, timeout=5):
                return {"intervals": [], "live_intervals": [], "cursor": 0}

            def acknowledge_activity_export(self, cursor, timeout=5):
                calls.append(("export-ack", cursor))

            def request_remote_command(self, command, timeout=5):
                calls.append(("apply", command))
                return {"ok": True}

        ServiceBackendBridge(Decision(), Desktop()).sync_once()

        self.assertEqual([call[0] for call in calls], [
            "publish", "export-ack", "apply", "complete",
        ])

    def test_command_poll_is_scoped_to_the_snapshot_windows_identity(self):
        calls = []
        sid = "S-1-5-21-100-200-300-1001"

        class Decision:
            external_service = True

            def publish_desktop_state(self, *_args, **_kwargs):
                pass

            def next_backend_command(self, **identity):
                calls.append(identity)
                return None

        class Desktop:
            def request_remote_snapshot(self, timeout=5):
                return {"runtime": {"windows_identity": {
                    "windows_sid": sid,
                    "usage_guard_username": "alice",
                }}}

            def request_activity_export(self, timeout=5):
                return {
                    "intervals": [], "live_intervals": [],
                    "daily_aggregates": [], "cursor": 0, "bytes": 0,
                }

            def acknowledge_activity_export(self, cursor, timeout=5):
                pass

        ServiceBackendBridge(Decision(), Desktop()).sync_once()

        self.assertEqual(calls, [{
            "windows_sid": sid, "usage_guard_username": "alice",
        }])

    def test_bridge_never_requests_or_serializes_complete_activity_store(self):
        calls = []
        class Decision:
            external_service = True
            command_polls = 0

            def publish_desktop_state(
                self, snapshot, activity=None, *, activity_unchanged=False,
                activity_export=None,
            ):
                calls.append((
                    "publish", snapshot["revision"], activity,
                    activity_unchanged, activity_export,
                ))

            def next_backend_command(self):
                self.command_polls += 1
                return None

        class Desktop:
            revision = 0
            activity_requests = 0

            def request_remote_snapshot(self, timeout=5):
                self.revision += 1
                return {"revision": self.revision}

            def request_activity_store(self, timeout=5):
                self.activity_requests += 1
                raise AssertionError(
                    "a potentially 500 MB archive must not cross desktop IPC"
                )

            def request_activity_export(self, timeout=5):
                return {"intervals": [], "live_intervals": [], "cursor": 0}

            def acknowledge_activity_export(self, cursor, timeout=5):
                pass

        desktop = Desktop()
        decision = Decision()
        bridge = ServiceBackendBridge(
            decision, desktop, interval_seconds=2,
            activity_interval_seconds=60,
        )

        bridge.sync_once()
        bridge.sync_once()
        bridge.sync_once()
        bridge.sync_once()

        self.assertEqual(desktop.activity_requests, 0)
        self.assertEqual(decision.command_polls, 4)
        self.assertEqual([call[1] for call in calls], [1, 2, 3, 4])
        self.assertTrue(all(call[2] is None for call in calls))
        self.assertTrue(all(call[3] for call in calls))

    def test_failed_full_activity_publication_is_retried_next_cycle(self):
        class Decision:
            external_service = True
            attempts = 0

            def publish_desktop_state(
                self, snapshot, activity=None, *, activity_unchanged=False,
                activity_export=None,
            ):
                self.attempts += 1
                if self.attempts == 1:
                    raise RuntimeError("service unavailable")

            def next_backend_command(self):
                return None

        class Desktop:
            activity_requests = 0

            def request_remote_snapshot(self, timeout=5):
                return {"usage": []}

            def request_activity_store(self, timeout=5):
                self.activity_requests += 1
                return {"days": {}}

            def request_activity_export(self, timeout=5):
                return {"intervals": [], "live_intervals": [], "cursor": 0}

            def acknowledge_activity_export(self, cursor, timeout=5):
                pass

        decision = Decision()
        desktop = Desktop()
        bridge = ServiceBackendBridge(
            decision, desktop, activity_interval_seconds=60,
            clock=lambda: 100.0,
        )

        with self.assertRaisesRegex(RuntimeError, "service unavailable"):
            bridge.sync_once()
        bridge.sync_once()

        self.assertEqual(decision.attempts, 2)
        self.assertEqual(desktop.activity_requests, 0)

    def test_restart_snapshot_publish_does_not_touch_activity_archive(self):
        calls = []

        class Decision:
            external_service = True

            def publish_desktop_state(self, *args, **kwargs):
                calls.append((args, kwargs))

            def next_backend_command(self):
                return None

        class Desktop:
            activity_requests = 0

            def request_remote_snapshot(self, timeout=5):
                return {"revision": self.activity_requests + 1}

            def request_activity_store(self, timeout=5):
                self.activity_requests += 1
                raise AssertionError("complete activity requested after restart")

            def request_activity_export(self, timeout=5):
                return {"intervals": [], "live_intervals": [], "cursor": 0}

            def acknowledge_activity_export(self, cursor, timeout=5):
                pass

        desktop = Desktop()
        bridge = ServiceBackendBridge(
            Decision(), desktop, activity_interval_seconds=60,
            clock=lambda: 100.0,
        )

        bridge.sync_once()
        bridge.sync_once()

        self.assertEqual(desktop.activity_requests, 0)
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(call[1]["activity_unchanged"] for call in calls))


if __name__ == "__main__":
    unittest.main()
