import platform
import json
import re
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.parse import parse_qs, urlparse
from urllib.request import urlopen

from browser_bridge import browser_bridge
from usage_guard import config


@dataclass
class ActiveContext:
    app_name: str = ""
    window_title: str = ""
    window_handle: int = 0
    url: str = ""
    is_afk: bool = False
    has_recent_input: bool = False
    is_video_playing: bool = False
    background_media: list[str] = None
    browser_media_playing: bool = False
    idle_seconds: float = 0.0
    source: str = "fallback"


class ActivityProbe:
    def __init__(self):
        self.aw = ActivityWatchProbe()
        self._fallback = WindowsActivityProbe()
        self._media = WindowsMediaProbe()
        self._last_browser_url = ""
        self._last_non_guard_context = None

    def current(self) -> ActiveContext:
        # GetLastInputInfo is the source of truth for physical keyboard/mouse
        # activity. ActivityWatch's AFK threshold is independent and can leave
        # a long tail after the user stops interacting.
        fallback_context = self._fallback.current()
        bridge_tab = self._current_bridge_tab()
        if bridge_tab is not None:
            self._last_browser_url = bridge_tab.url
        bridge_context = self._browser_bridge_context(fallback_context)
        if bridge_context is not None:
            return self._finish_context(bridge_context, fallback_context)
        if getattr(config, "ACTIVITYWATCH_ENABLED", True):
            context = self.aw.current()
            if context is not None:
                if context.url:
                    self._last_browser_url = context.url
                shelf_source_url = _shelf_source_url(context.url)
                if (
                    not shelf_source_url
                    and _is_shelf_popup_app(fallback_context.app_name)
                    and context.browser_media_playing
                    and _is_video_context(_default_browser_app(), context.url)
                ):
                    # Depending on the Shelf version, ActivityWatch may
                    # already expose the YouTube URL instead of the extension
                    # URL.  The native popup is still explorer.exe in both
                    # cases, so retain that video page for attribution.
                    shelf_source_url = context.url
                # The native foreground-window query is sampled in the same
                # tick. Use it for attribution so a delayed ActivityWatch
                # event cannot charge the application that was focused just
                # before an Alt+Tab. Keep the browser URL only when it refers
                # to that same foreground application.  YouTube Shelf is an
                # exception: its popup is owned by explorer.exe, while the
                # extension event carries the actual video URL in sourceUrl.
                if (
                    not _application_names_match(context.app_name, fallback_context.app_name)
                    and not _is_configured_browser(fallback_context.app_name)
                    and not shelf_source_url
                ):
                    context.url = ""
                context.app_name = fallback_context.app_name or context.app_name
                context.window_title = fallback_context.window_title or context.window_title
                context.window_handle = fallback_context.window_handle
                if shelf_source_url:
                    # Attribute Shelf's standalone player to the configured
                    # browser and the real YouTube page, rather than to the
                    # Explorer-hosted popup or the extension URL.
                    context.app_name = _default_browser_app()
                    context.url = shelf_source_url
                elif (
                    _is_configured_browser(context.app_name)
                    and _is_youtube_title(context.window_title)
                    and not _is_youtube_url(context.url)
                ):
                    # ActivityWatch can retain the URL of the tab that opened
                    # Shelf while the native window already has the video's
                    # YouTube title. Never charge that stale URL to its old
                    # website: the player belongs to YouTube.
                    context.url = "https://www.youtube.com/"
                elif (
                    _is_configured_browser(context.app_name)
                    and _is_youtube_url(context.url)
                    and _is_regular_browser_tab(context.window_title)
                    and not _is_youtube_title(context.window_title)
                ):
                    # Conversely, a regular Brave tab with a non-YouTube
                    # native title must not inherit the Shelf video's stale
                    # URL. Recover the visible host when its title exposes
                    # one; otherwise leave the browser unattributed rather
                    # than charging the time to YouTube.
                    context.url = _host_url_from_title(context.window_title)
                elif _is_configured_browser(context.app_name) and not context.url:
                    # ActivityWatch can briefly omit a page URL after a
                    # navigation. Use an unambiguous host exposed by the
                    # native tab title so that a known site is not lost.
                    context.url = _host_url_from_title(context.window_title)
                return self._finish_context(context, fallback_context)
        return self._finish_context(fallback_context, fallback_context)

    def running_applications(self):
        """Return visible desktop applications, including those already open."""
        return self._fallback.running_applications()

    def _browser_bridge_context(self, fallback_context):
        tab = self._current_bridge_tab()
        if tab is None:
            return None
        if _is_configured_browser(fallback_context.app_name):
            app_name = fallback_context.app_name
        elif _is_shelf_popup_app(fallback_context.app_name) and _is_video_context(
            _default_browser_app(), tab.url
        ):
            app_name = _default_browser_app()
        else:
            return None
        return ActiveContext(
            app_name=app_name,
            window_title=fallback_context.window_title or tab.title,
            window_handle=fallback_context.window_handle,
            url=tab.url,
            browser_media_playing=tab.audible,
            source="browser-extension",
        )

    @staticmethod
    def _current_bridge_tab():
        if not bool(getattr(config, "BROWSER_BRIDGE_ENABLED", True)):
            return None
        return browser_bridge.current(
            float(getattr(config, "BROWSER_BRIDGE_STALE_SECONDS", 90))
        )

    def _finish_context(self, context, fallback_context):
        context = self._through_usage_guard(context, fallback_context)
        if _is_system_popup_title(context.window_title):
            # Windows can briefly report the system-tray overflow popup as a
            # Brave window after minimizing Shelf. It is not the player, so
            # let Brave's media session be accounted as background playback.
            context.app_name = "explorer.exe"
        context.has_recent_input = fallback_context.has_recent_input
        context.idle_seconds = fallback_context.idle_seconds
        # Keep Windows' real AFK state (120 s by default). ``has_recent_input``
        # is intentionally much shorter and must not turn reading/thinking
        # time into AFK time after only a few seconds.
        context.is_afk = fallback_context.is_afk
        context.is_video_playing = (
            not context.has_recent_input
            and (
                _is_foreground_browser_video(context)
                or (
                    _is_configured_browser(context.app_name)
                    and context.browser_media_playing
                )
                or self._media.is_playing_for(context.app_name, context.url)
            )
        )
        context.background_media = self._background_media(context)
        self._remember_non_guard_context(context, fallback_context)
        return context

    def _through_usage_guard(self, context, foreground_context):
        """Keep Usage Guard out of attribution without changing media rules."""
        if not (
            _is_usage_guard_window(foreground_context)
            and self._last_non_guard_context is not None
        ):
            return context
        previous = self._last_non_guard_context
        # Do not keep a stale video context after its own window has been
        # minimized. In that case the normal background-media path must decide
        # whether the playback is passive.
        if _is_minimized_window(previous.window_handle):
            return context
        context.app_name = previous.app_name
        context.window_title = previous.window_title
        context.url = previous.url
        return context

    def _remember_non_guard_context(self, context, foreground_context):
        if not _is_usage_guard_window(foreground_context):
            self._last_non_guard_context = replace(context)

    def _background_media(self, context):
        labels = []
        for source in self._media.playing_sources():
            if _same_application(context.app_name, source):
                continue
            label = _media_label(source, context.url or self._last_browser_url)
            if label != "Brave":
                labels.append(label)
        if context.browser_media_playing and not _is_configured_browser(context.app_name):
            labels.append(_browser_media_label(self._last_browser_url))
        return list(dict.fromkeys(labels))

    def media_sources(self):
        """Raw Windows media-session sources, used only by debug logging."""
        return self._media.playing_sources()

    def media_session_states(self):
        """Return every Windows media session and whether it is PLAYING."""
        return self._media.session_states()


class ActivityWatchProbe:
    def __init__(self):
        configured = str(getattr(config, "ACTIVITYWATCH_BASE_URL", "http://localhost:5600")).rstrip("/")
        parsed = urlparse(configured)
        self.base_url = (
            configured
            if parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "::1", "localhost"}
            else "http://localhost:5600"
        )
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
            browser_media_playing=bool(web_data.get("audible", False)),
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
        with urlopen(f"{self.base_url}{path}", timeout=self.timeout) as response:  # nosec B310
            return json.loads(response.read().decode("utf-8"))


class WindowsActivityProbe:
    def current(self) -> ActiveContext:
        if platform.system() == "Windows":
            return self._windows_current()
        return ActiveContext(is_afk=True)

    def running_applications(self):
        """Return one entry per executable owning a visible titled window."""
        if platform.system() != "Windows":
            return {}
        try:
            import ctypes
            from ctypes import wintypes

            user32 = ctypes.WinDLL("user32", use_last_error=True)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            applications = {}
            ignored_hosts = {
                "applicationframehost.exe",
                "lockapp.exe",
                "searchhost.exe",
                "shellexperiencehost.exe",
                "startmenuexperiencehost.exe",
                "textinputhost.exe",
            }
            callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

            def inspect_window(hwnd, _):
                if not user32.IsWindowVisible(hwnd):
                    return True
                length = user32.GetWindowTextLengthW(hwnd)
                if length <= 0:
                    return True
                title_buffer = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, title_buffer, length + 1)
                pid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                handle = kernel32.OpenProcess(0x1000, False, pid.value)
                if not handle:
                    return True
                try:
                    path_buffer = ctypes.create_unicode_buffer(1024)
                    size = wintypes.DWORD(len(path_buffer))
                    if not kernel32.QueryFullProcessImageNameW(
                        handle, 0, path_buffer, ctypes.byref(size)
                    ):
                        return True
                    executable = Path(path_buffer.value).name
                    if executable.casefold() == "usage-guard.exe" or executable.casefold() in ignored_hosts:
                        return True
                    key = executable.casefold()
                    applications.setdefault(
                        key,
                        {"executable": executable, "label": Path(executable).stem},
                    )
                finally:
                    kernel32.CloseHandle(handle)
                return True

            user32.EnumWindows(callback_type(inspect_window), 0)
            return applications
        except Exception:
            # None means that collection failed; callers retain the last good
            # inventory instead of incorrectly closing every open program.
            return None

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
                    window_handle=int(hwnd),
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
                window_handle=int(hwnd),
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
        self._last_sessions = {}
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="media-probe")
        self._pending_query = None

    def is_playing_for(self, app_name, url=""):
        if not self._available or not app_name:
            return False
        if not (_is_video_context(app_name, url) or _is_configured_browser(app_name)):
            return False
        return any(_same_application(app_name, source) for source in self.playing_sources())

    def playing_sources(self):
        return [
            source for source, is_playing in self.session_states().items()
            if is_playing
        ]

    def session_states(self):
        if not self._available:
            return {}

        # The WinRT request can occasionally stall.  It must never run on the
        # Qt GUI thread, otherwise tray clicks, menus, and Ctrl+C stop being
        # processed while Windows is resolving media sessions.
        if self._pending_query is not None and self._pending_query.done():
            try:
                self._last_sessions = self._pending_query.result()
            except Exception:
                self._last_sessions = {}
            self._pending_query = None

        now = time.monotonic()
        if now - self._last_check < 3:
            return dict(self._last_sessions)
        self._last_check = now

        if self._pending_query is None:
            self._pending_query = self._executor.submit(self._query_sessions)
        return dict(self._last_sessions)

    @staticmethod
    def _query_sessions():
        try:
            import asyncio
            from winrt.windows.media.control import (
                GlobalSystemMediaTransportControlsSessionPlaybackStatus,
                GlobalSystemMediaTransportControlsSessionManager,
            )

            async def get_sessions():
                manager = await GlobalSystemMediaTransportControlsSessionManager.request_async()
                return manager.get_sessions()

            sessions = {}
            for session in asyncio.run(get_sessions()):
                sessions[str(session.source_app_user_model_id)] = (
                    session.get_playback_info().playback_status
                    == GlobalSystemMediaTransportControlsSessionPlaybackStatus.PLAYING
                )
            return sessions
        except Exception:
            return {}


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


def _is_foreground_browser_video(context):
    is_video = _is_video_context(context.app_name, context.url) or _is_video_title(
        context.window_title
    )
    return (
        _is_configured_browser(context.app_name) and is_video
    ) or _is_shelf_video_window(context)


def _is_shelf_video_window(context):
    """Identify YouTube Shelf's foreground popup, reported as explorer.exe."""
    return bool(_shelf_source_url(context.url))


def _is_shelf_popup_app(app_name):
    """YouTube Shelf hosts its standalone player window in Explorer."""
    return str(app_name or "").rsplit("\\", 1)[-1].lower() == "explorer.exe"


def _is_usage_guard_window(context):
    """Recognize the control window in packaged and development builds."""
    executable = str(context.app_name or "").rsplit("\\", 1)[-1].lower()
    title = str(context.window_title or "").strip().casefold()
    return executable == "usage-guard.exe" or title in {"usage guard", "usage monitor"}


def _is_minimized_window(window_handle):
    """Check the exact native window that was previously in the foreground."""
    if platform.system() != "Windows" or not window_handle:
        return False
    try:
        import ctypes

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        return bool(user32.IsIconic(int(window_handle)))
    except Exception:
        return False


def _shelf_source_url(url):
    """Return the video URL embedded in a YouTube Shelf extension URL."""
    try:
        parsed_url = urlparse(str(url))
        if parsed_url.scheme != "chrome-extension":
            return ""
        query = parse_qs(parsed_url.query)
        source_url = query.get("sourceUrl", [""])[0]
    except ValueError:
        return ""
    return source_url if _is_video_context(_default_browser_app(), source_url) else ""


def _default_browser_app():
    browsers = [
        str(value).lower()
        for value in getattr(config, "BROWSER_APPS", ["brave.exe"])
        if str(value).strip()
    ]
    return browsers[0] if browsers else "brave.exe"


def _media_label(source, current_url):
    source_lower = str(source).lower()
    if "brave" in source_lower or "chrome" in source_lower:
        if "youtube.com" in str(current_url).lower():
            return "YouTube"
        return "Brave" if "brave" in source_lower else "Chrome"
    if "potplayer" in source_lower:
        return "PotPlayer"
    if "vlc" in source_lower:
        return "VLC"
    if "spotify" in source_lower:
        return "Spotify"
    return "Média"


def _browser_media_label(url):
    try:
        parsed_url = urlparse(str(url))
        # YouTube Shelf exposes the video page through its sourceUrl query
        # parameter. Use that page for the display label, not the extension ID.
        source_url = parse_qs(parsed_url.query).get("sourceUrl", [str(url)])[0]
    except ValueError:
        source_url = str(url)
    host = (urlparse(source_url).hostname or "").lower().removeprefix("www.")
    if "youtube.com" in host or "youtu.be" in host:
        return "YouTube"
    return host or "Navigateur"


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


def _is_video_title(title):
    """Recognize a video page while ActivityWatch's URL is catching up."""
    title_lower = str(title or "").lower()
    for pattern in getattr(config, "VIDEO_URL_PATTERNS", []):
        service = str(pattern).lower().split(".", 1)[0]
        if service and service in title_lower:
            return True
    return False


def _is_youtube_title(title):
    return "youtube" in str(title or "").casefold()


def _is_youtube_url(url):
    try:
        host = (urlparse(str(url)).hostname or "").casefold().removeprefix("www.")
    except ValueError:
        return False
    return host == "youtube.com" or host.endswith(".youtube.com") or host == "youtu.be"


def _is_system_popup_title(title):
    value = str(title or "").casefold()
    return (
        "barre d’état système" in value
        or "system tray" in value
        or "notification overflow" in value
    )


def _is_regular_browser_tab(title):
    title_lower = str(title or "").casefold().strip()
    return title_lower.endswith((" - brave", " – brave"))


def _host_url_from_title(title):
    title_text = str(title or "")
    match = re.search(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", title_text, re.I)
    if not match and re.search(r"\bbbc\b", title_text, re.I):
        return "https://www.bbc.com/"
    return f"https://{match.group(0)}" if match else ""


def _event_timestamp(event):
    value = str(event.get("timestamp", ""))
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
