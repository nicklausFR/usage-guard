import platform
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import urlopen

from usage_guard import config


@dataclass
class ActiveContext:
    app_name: str = ""
    window_title: str = ""
    url: str = ""
    is_afk: bool = False
    idle_seconds: float = 0.0
    source: str = "fallback"


class ActivityProbe:
    def __init__(self):
        self.aw = ActivityWatchProbe()
        self._fallback = WindowsActivityProbe()

    def current(self) -> ActiveContext:
        if getattr(config, "ACTIVITYWATCH_ENABLED", True):
            context = self.aw.current()
            if context is not None:
                return context
        return self._fallback.current()


class ActivityWatchProbe:
    def __init__(self):
        self.base_url = str(getattr(config, "ACTIVITYWATCH_BASE_URL", "http://localhost:5600")).rstrip("/")
        self.timeout = float(getattr(config, "ACTIVITYWATCH_TIMEOUT_SECONDS", 0.25))

    def current(self):
        try:
            buckets = self._get_json("/api/0/buckets/")
        except (OSError, URLError, TimeoutError, ValueError):
            return None

        window_event = self._latest_event_for_type(buckets, "currentwindow")
        afk_event = self._latest_event_for_type(buckets, "afkstatus")
        web_event = self._latest_event_for_type(buckets, "web.tab.current")

        if window_event is None and web_event is None and afk_event is None:
            return None

        window_data = (window_event or {}).get("data", {})
        afk_data = (afk_event or {}).get("data", {})
        web_data = (web_event or {}).get("data", {})
        status = str(afk_data.get("status", "")).lower()
        is_afk = status == "afk"

        return ActiveContext(
            app_name=str(window_data.get("app", "")),
            window_title=str(web_data.get("title") or window_data.get("title", "")),
            url=str(web_data.get("url") or window_data.get("url", "")),
            is_afk=is_afk,
            idle_seconds=0.0,
            source="activitywatch",
        )

    def _latest_event_for_type(self, buckets, event_type):
        candidates = [
            bucket_id
            for bucket_id, bucket in buckets.items()
            if bucket.get("type") == event_type
        ]
        latest = None
        for bucket_id in candidates:
            events = self._events(bucket_id)
            if not events:
                continue
            event = max(events, key=lambda item: _event_timestamp(item))
            if latest is None or _event_timestamp(event) > _event_timestamp(latest):
                latest = event
        return latest

    def _events(self, bucket_id):
        query = urlencode({"limit": 1})
        try:
            events = self._get_json(f"/api/0/buckets/{bucket_id}/events?{query}")
        except (OSError, URLError, TimeoutError, ValueError):
            return []
        return events if isinstance(events, list) else []

    def _get_json(self, path):
        with urlopen(f"{self.base_url}{path}", timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))


class WindowsActivityProbe:
    def current(self) -> ActiveContext:
        if platform.system() == "Windows":
            return self._windows_current()
        return ActiveContext(is_afk=True)

    def _windows_current(self) -> ActiveContext:
        try:
            import ctypes
            from ctypes import wintypes

            user32 = ctypes.WinDLL("user32", use_last_error=True)
            psapi = ctypes.WinDLL("psapi", use_last_error=True)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            idle_seconds = self._windows_idle_seconds(ctypes, wintypes, user32)

            hwnd = user32.GetForegroundWindow()
            if not hwnd:
                return ActiveContext(is_afk=True, idle_seconds=idle_seconds, source="fallback")

            length = user32.GetWindowTextLengthW(hwnd)
            buffer = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buffer, length + 1)
            title = buffer.value

            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))

            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            PROCESS_VM_READ = 0x0010
            handle = kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                False,
                pid.value,
            )
            if not handle:
                return ActiveContext(
                    window_title=title,
                    is_afk=self._is_afk(idle_seconds),
                    idle_seconds=idle_seconds,
                    source="fallback",
                )

            path_buffer = ctypes.create_unicode_buffer(1024)
            psapi.GetModuleFileNameExW(handle, None, path_buffer, 1024)
            kernel32.CloseHandle(handle)
            app_name = path_buffer.value.rsplit("\\", 1)[-1]
            return ActiveContext(
                app_name=app_name,
                window_title=title,
                is_afk=self._is_afk(idle_seconds),
                idle_seconds=idle_seconds,
                source="fallback",
            )
        except Exception:
            return ActiveContext(is_afk=True, source="fallback")

    def _windows_idle_seconds(self, ctypes, wintypes, user32):
        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.UINT),
                ("dwTime", wintypes.DWORD),
            ]

        info = LASTINPUTINFO()
        info.cbSize = ctypes.sizeof(LASTINPUTINFO)
        if not user32.GetLastInputInfo(ctypes.byref(info)):
            return 0.0
        tick_count = ctypes.windll.kernel32.GetTickCount64()
        return max(0.0, (tick_count - info.dwTime) / 1000.0)

    def _is_afk(self, idle_seconds):
        return idle_seconds >= float(getattr(config, "AFK_AFTER_SECONDS", 120))


def _event_timestamp(event):
    value = str(event.get("timestamp", ""))
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
