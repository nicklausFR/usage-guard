import platform
import json
import time
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
    has_recent_input: bool = False
    is_video_playing: bool = False
    idle_seconds: float = 0.0
    source: str = "fallback"


class ActivityProbe:
    def __init__(self):
        self.aw = ActivityWatchProbe()
        self._fallback = WindowsActivityProbe()
        self._media = WindowsMediaProbe()

    def current(self) -> ActiveContext:
        # GetLastInputInfo is the source of truth for physical keyboard/mouse
        # activity. ActivityWatch's AFK threshold is independent and can leave
        # a long tail after the user stops interacting.
        fallback_context = self._fallback.current()
        if getattr(config, "ACTIVITYWATCH_ENABLED", True):
            context = self.aw.current()
            if context is not None:
                # The native foreground-window query is sampled in the same
                # tick. Use it for attribution so a delayed ActivityWatch
                # event cannot charge the application that was focused just
                # before an Alt+Tab. Keep the browser URL only when it refers
                # to that same foreground application.
                if (
                    not _application_names_match(context.app_name, fallback_context.app_name)
                    and not _is_configured_browser(fallback_context.app_name)
                ):
                    context.url = ""
                context.app_name = fallback_context.app_name or context.app_name
                context.window_title = fallback_context.window_title or context.window_title
                context.has_recent_input = fallback_context.has_recent_input
                context.idle_seconds = fallback_context.idle_seconds
                context.is_afk = not context.has_recent_input
                context.is_video_playing = (
                    not context.has_recent_input
                    and self._media.is_playing_for(context.app_name, context.url)
                )
                return context
        fallback_context.is_video_playing = (
            not fallback_context.has_recent_input
            and self._media.is_playing_for(fallback_context.app_name, fallback_context.url)
        )
        return fallback_context


class ActivityWatchProbe:
    def __init__(self):
        self.base_url = str(getattr(config, "ACTIVITYWATCH_BASE_URL", "http://localhost:5600")).rstrip("/")
        self.timeout = float(getattr(config, "ACTIVITYWATCH_TIMEOUT_SECONDS", 0.1))

    def current(self):
        try:
            buckets = self._get_json("/api/0/buckets/")
        except (OSError, URLError, TimeoutError, ValueError):
            return None

        window_event = self._latest_event_for_type(buckets, "currentwindow")
        web_event = self._latest_event_for_type(buckets, "web.tab.current")

        if window_event is None and web_event is None:
            return None

        window_data = (window_event or {}).get("data", {})
        web_data = (web_event or {}).get("data", {})

        return ActiveContext(
            app_name=str(window_data.get("app", "")),
            window_title=str(web_data.get("title") or window_data.get("title", "")),
            url=str(web_data.get("url") or window_data.get("url", "")),
            is_afk=False,
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
                    has_recent_input=self._has_recent_input(idle_seconds),
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
                has_recent_input=self._has_recent_input(idle_seconds),
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

    def _has_recent_input(self, idle_seconds):
        return idle_seconds <= float(getattr(config, "RECENT_INPUT_SECONDS", 3))


class WindowsMediaProbe:
    """Checks Windows media sessions without using the audio level as a signal."""

    def __init__(self):
        self._available = platform.system() == "Windows"
        self._last_check = 0.0
        self._last_key = None
        self._last_result = False

    def is_playing_for(self, app_name, url=""):
        if not self._available or not app_name or not _is_video_context(app_name, url):
            return False
        key = (app_name.lower(), url.lower())
        now = time.monotonic()
        if key == self._last_key and now - self._last_check < 3:
            return self._last_result
        self._last_key = key
        self._last_check = now
        self._last_result = False
        try:
            import asyncio
            from winrt.windows.media.control import (
                GlobalSystemMediaTransportControlsSessionPlaybackStatus,
                GlobalSystemMediaTransportControlsSessionManager,
            )

            async def get_sessions():
                manager = await GlobalSystemMediaTransportControlsSessionManager.request_async()
                return manager.get_sessions()

            for session in asyncio.run(get_sessions()):
                playback = session.get_playback_info()
                if (
                    playback.playback_status
                    == GlobalSystemMediaTransportControlsSessionPlaybackStatus.PLAYING
                    and _same_application(app_name, session.source_app_user_model_id)
                ):
                    self._last_result = True
                    return True
        except Exception:
            # A missing media API/session never makes audio playback count.
            return False
        return False


def _same_application(app_name, source_app_user_model_id):
    executable = app_name.rsplit("\\", 1)[-1].rsplit(".", 1)[0].lower()
    source = str(source_app_user_model_id or "").lower()
    return bool(executable and executable in source)


def _application_names_match(first, second):
    def normalized(value):
        return str(value or "").rsplit("\\", 1)[-1].rsplit(".", 1)[0].lower()

    return bool(normalized(first) and normalized(first) == normalized(second))


def _is_configured_browser(app_name):
    executable = str(app_name or "").rsplit("\\", 1)[-1].lower()
    return executable in {
        str(value).lower() for value in getattr(config, "BROWSER_APPS", ["brave.exe"])
    }


def _is_video_context(app_name, url):
    """Avoid treating a music/podcast session as screen time.

    Windows does not label GSMTC sessions as audio or video. We therefore only
    accept a configured video-player executable, or a browser tab on a known
    video host. Both lists are user-configurable for apps/sites not covered by
    the defaults.
    """
    executable = app_name.rsplit("\\", 1)[-1].lower()
    video_apps = {
        str(value).lower()
        for value in getattr(config, "VIDEO_PLAYER_APPS", [])
    }
    if executable in video_apps:
        return True

    address = str(url).lower()
    return any(
        pattern.lower() in address
        for pattern in getattr(config, "VIDEO_URL_PATTERNS", [])
    )


def _event_timestamp(event):
    value = str(event.get("timestamp", ""))
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
