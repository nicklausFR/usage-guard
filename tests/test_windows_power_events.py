import sys
import unittest
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from windows_power_events import (
    PBT_APMRESUMEAUTOMATIC,
    PBT_APMRESUMESUSPEND,
    PBT_APMSUSPEND,
    WM_ENDSESSION,
    WM_POWERBROADCAST,
    WM_QUERYENDSESSION,
    WindowsPowerEventFilter,
    WindowsShellEventFilter,
    inferred_sleep_seconds,
    modern_standby_is_session_boundary,
    modern_standby_intervals_from_xml,
)


class WindowsPowerEventFilterTest(unittest.TestCase):
    def test_awake_clock_distinguishes_modern_standby_from_process_stall(self):
        self.assertEqual(inferred_sleep_seconds(8 * 3600, 3), 8 * 3600 - 3)
        self.assertEqual(inferred_sleep_seconds(30, 30), 0)
        self.assertEqual(inferred_sleep_seconds(30, 25), 0)

    def test_kernel_power_xml_pairs_only_matching_boot_intervals(self):
        xml = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>507</EventID><TimeCreated SystemTime='2026-08-26T05:01:37Z'/></System><EventData><Data Name='BootId'>695</Data></EventData></Event><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>506</EventID><TimeCreated SystemTime='2026-08-25T21:26:23Z'/></System><EventData><Data Name='BootId'>695</Data></EventData></Event>"""

        intervals = modern_standby_intervals_from_xml(xml)

        self.assertEqual(len(intervals), 1)
        self.assertEqual(intervals[0][0], datetime.fromisoformat("2026-08-25T21:26:23+00:00"))
        self.assertEqual(intervals[0][1], datetime.fromisoformat("2026-08-26T05:01:37+00:00"))

    def test_kernel_power_reason_distinguishes_screen_timeout_from_session_boundary(self):
        xml = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>506</EventID><TimeCreated SystemTime='2026-08-26T05:12:13Z'/></System><EventData><Data Name='Reason'>12</Data><Data Name='BootId'>695</Data></EventData></Event><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>507</EventID><TimeCreated SystemTime='2026-08-26T05:20:10Z'/></System><EventData><Data Name='BootId'>695</Data></EventData></Event>"""

        interval = modern_standby_intervals_from_xml(
            xml, include_reason=True,
        )[0]

        self.assertEqual(interval[2], "12")
        self.assertFalse(modern_standby_is_session_boundary(*interval))
        self.assertTrue(modern_standby_is_session_boundary(
            interval[0], interval[0].replace(hour=10), interval[2],
        ))
        self.assertTrue(modern_standby_is_session_boundary(
            interval[0], interval[1], "11",
        ))

    def test_explorer_restart_is_the_only_shell_reregistration_trigger(self):
        events = []
        listener = WindowsShellEventFilter(
            lambda: events.append("tray"), taskbar_created_message=49152,
        )

        self.assertFalse(listener.dispatch_message(123))
        self.assertTrue(listener.dispatch_message(49152))
        self.assertEqual(events, ["tray"])

    def test_sleep_and_duplicate_resume_broadcasts_are_normalized(self):
        events = []
        listener = WindowsPowerEventFilter(events.append)

        listener.dispatch_message(WM_POWERBROADCAST, PBT_APMSUSPEND)
        listener.dispatch_message(WM_POWERBROADCAST, PBT_APMRESUMEAUTOMATIC)
        listener.dispatch_message(WM_POWERBROADCAST, PBT_APMRESUMESUSPEND)

        self.assertEqual(events, ["sleep", "resume"])

    def test_shutdown_is_flushed_on_query_without_duplication(self):
        events = []
        listener = WindowsPowerEventFilter(events.append)

        listener.dispatch_message(WM_QUERYENDSESSION)
        listener.dispatch_message(WM_ENDSESSION, 1)

        self.assertEqual(events, ["shutdown"])

    def test_cancelled_shutdown_is_reported(self):
        events = []
        listener = WindowsPowerEventFilter(events.append)

        listener.dispatch_message(WM_QUERYENDSESSION)
        listener.dispatch_message(WM_ENDSESSION, 0)

        self.assertEqual(events, ["shutdown", "shutdown_cancelled"])


if __name__ == "__main__":
    unittest.main()
