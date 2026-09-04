"""Translate Windows power/session messages into durable Usage Guard events."""

from __future__ import annotations

import ctypes
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from ctypes import wintypes
from datetime import datetime, timezone

from PySide6.QtCore import QAbstractNativeEventFilter


WM_QUERYENDSESSION = 0x0011
WM_ENDSESSION = 0x0016
WM_POWERBROADCAST = 0x0218
PBT_APMSUSPEND = 0x0004
PBT_APMRESUMESUSPEND = 0x0007
PBT_APMRESUMEAUTOMATIC = 0x0012
MODERN_STANDBY_IDLE_TIMEOUT_REASON = "12"
DEFAULT_IDLE_STANDBY_SESSION_BOUNDARY_SECONDS = 4 * 3600


def awake_monotonic_seconds():
    """Return a monotonic clock which does not advance during system sleep."""
    if sys.platform == "win32":
        try:
            value = ctypes.c_ulonglong()
            if ctypes.windll.kernel32.QueryUnbiasedInterruptTime(ctypes.byref(value)):
                return value.value / 10_000_000.0
        except (AttributeError, OSError):
            pass
    return time.monotonic()


def inferred_sleep_seconds(elapsed_seconds, awake_elapsed_seconds, threshold=10.0):
    """Separate real sleep from an ordinary stalled monitoring process."""
    sleeping = max(0.0, float(elapsed_seconds) - float(awake_elapsed_seconds))
    return sleeping if sleeping >= float(threshold) else 0.0


def modern_standby_intervals_from_xml(xml_text, include_reason=False):
    """Return paired Kernel-Power 506/507 intervals from wevtutil XML."""
    if not str(xml_text or "").strip():
        return []
    try:
        root = ET.fromstring(f"<Events>{xml_text}</Events>")
    except ET.ParseError:
        return []
    namespace = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    events = []
    for event in root.findall("e:Event", namespace):
        event_id = event.findtext("e:System/e:EventID", namespaces=namespace)
        created = event.find("e:System/e:TimeCreated", namespace)
        if event_id not in {"506", "507"} or created is None:
            continue
        timestamp = str(created.get("SystemTime") or "").replace("Z", "+00:00")
        try:
            at = datetime.fromisoformat(timestamp)
        except ValueError:
            continue
        boot_id = ""
        reason = ""
        for value in event.findall("e:EventData/e:Data", namespace):
            if value.get("Name") == "BootId":
                boot_id = str(value.text or "")
            elif value.get("Name") == "Reason":
                reason = str(value.text or "")
        events.append((at, int(event_id), boot_id, reason))
    intervals, opened = [], {}
    for at, event_id, boot_id, reason in sorted(events):
        key = boot_id or "unknown"
        if event_id == 506:
            opened[key] = (at, reason)
        elif key in opened and at > opened[key][0]:
            start, start_reason = opened.pop(key)
            intervals.append(
                (start, at, start_reason) if include_reason else (start, at)
            )
    return intervals


def modern_standby_intervals_since(
    since, minimum_seconds=1, runner=None, include_reason=False,
):
    """Read verified Modern Standby intervals in the current boot history."""
    if sys.platform != "win32":
        return []
    command = [
        "wevtutil.exe", "qe", "System",
        "/q:*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and (EventID=506 or EventID=507)]]",
        "/rd:true", "/f:xml", "/c:256",
    ]
    try:
        completed = (runner or subprocess.run)(
            command, capture_output=True, text=True, timeout=5, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if getattr(completed, "returncode", 1) != 0:
        return []
    boundary = since if since.tzinfo else since.replace(tzinfo=timezone.utc)
    result = []
    for interval in modern_standby_intervals_from_xml(
        completed.stdout, include_reason=include_reason,
    ):
        start, end = interval[:2]
        if (
            end < boundary.astimezone(timezone.utc)
            or (end - start).total_seconds() < float(minimum_seconds)
        ):
            continue
        localized = (start.astimezone(), end.astimezone())
        result.append(localized + interval[2:] if include_reason else localized)
    return result


def modern_standby_is_session_boundary(
    start, end, reason="",
    idle_threshold_seconds=DEFAULT_IDLE_STANDBY_SESSION_BOUNDARY_SECONDS,
):
    """Return whether one verified standby should split the user session.

    On Modern Standby PCs, the ordinary automatic screen timeout is reported
    as Kernel-Power 506/507 too (reason 12). Short display-idle cycles must
    stop activity accounting without fabricating a new Windows session.
    A long overnight idle interval remains a real logical boundary, while
    explicit/non-idle standby reasons remain boundaries immediately.
    """
    duration = max(0.0, (end - start).total_seconds())
    if str(reason or "") == MODERN_STANDBY_IDLE_TIMEOUT_REASON:
        return duration >= max(1.0, float(idle_threshold_seconds))
    return duration >= 1.0


def latest_extended_modern_standby(since, minimum_seconds=1, runner=None):
    """Backward-compatible helper returning the most recent verified sleep."""
    intervals = modern_standby_intervals_since(since, minimum_seconds, runner)
    return max(intervals, key=lambda item: item[1], default=None)


class WindowsPowerEventFilter(QAbstractNativeEventFilter):
    """Receive native broadcasts on Qt's GUI thread."""

    def __init__(self, callback):
        super().__init__()
        self.callback = callback
        self._last_resume = 0.0
        self._shutdown_reported = False

    def dispatch_message(self, message, wparam=0, lparam=0):
        """Dispatch a decoded message; kept separate for deterministic tests."""
        if message == WM_POWERBROADCAST:
            if wparam == PBT_APMSUSPEND:
                self.callback("sleep")
                return True
            if wparam in {PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMESUSPEND}:
                now = time.monotonic()
                if now - self._last_resume > 2:
                    self._last_resume = now
                    self.callback("resume")
                return True
        if message in {WM_QUERYENDSESSION, WM_ENDSESSION}:
            # WM_QUERYENDSESSION gives us time to flush before Windows stops
            # the GUI. WM_ENDSESSION can follow and must not duplicate it.
            if not self._shutdown_reported and (
                message == WM_QUERYENDSESSION or bool(wparam)
            ):
                self._shutdown_reported = True
                self.callback("shutdown")
            elif message == WM_ENDSESSION and not bool(wparam) and self._shutdown_reported:
                self._shutdown_reported = False
                self.callback("shutdown_cancelled")
            return True
        return False

    def nativeEventFilter(self, _event_type, message):
        try:
            native = wintypes.MSG.from_address(int(message))
            self.dispatch_message(native.message, native.wParam, native.lParam)
        except (TypeError, ValueError, OSError):
            # A malformed/native message must never destabilize monitoring.
            pass
        return False, 0


class WindowsShellEventFilter(QAbstractNativeEventFilter):
    """Recreate shell-owned UI only when Explorer broadcasts its restart."""

    def __init__(self, callback, taskbar_created_message=None):
        super().__init__()
        self.callback = callback
        self.taskbar_created_message = int(
            taskbar_created_message
            if taskbar_created_message is not None
            else self._register_taskbar_created()
        )

    @staticmethod
    def _register_taskbar_created():
        if sys.platform != "win32":
            return 0
        try:
            return ctypes.windll.user32.RegisterWindowMessageW(
                "TaskbarCreated"
            )
        except (AttributeError, OSError):
            return 0

    def dispatch_message(self, message):
        if (
            self.taskbar_created_message
            and int(message) == self.taskbar_created_message
        ):
            self.callback()
            return True
        return False

    def nativeEventFilter(self, _event_type, message):
        try:
            native = wintypes.MSG.from_address(int(message))
            self.dispatch_message(native.message)
        except (TypeError, ValueError, OSError):
            pass
        return False, 0
