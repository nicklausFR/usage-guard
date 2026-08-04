import time
from datetime import date
from pathlib import Path

from PySide6.QtCore import QObject, QTimer, Signal

from activity import ActiveContext, ActivityProbe
from usage_guard import AppUsageStore, config, debug_log


class MonitoringService(QObject):
    state_changed = Signal()

    def __init__(self):
        super().__init__()
        self.usage = AppUsageStore()
        self.probe = ActivityProbe()
        self.current_context = ActiveContext()
        self._last_tick = time.monotonic()
        self._last_save = self._last_tick
        self._current_day = date.today()
        self._last_debug_snapshot = None
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.setInterval(int(getattr(config, "POLL_INTERVAL_MS", 1000)))

    def start(self):
        self._last_tick = time.monotonic()
        self.timer.start()
        self.tick()

    def stop(self):
        self.timer.stop()
        self.usage.save(force=True)

    def tick(self):
        now = time.monotonic()
        # A long gap means sleep/resume or a stalled process; do not attribute it
        # to whichever window happens to be focused after the gap.
        elapsed = min(max(0.0, now - self._last_tick), 5.0)
        self._last_tick = now
        self.current_context = self.probe.current()

        today = date.today()
        if today != self._current_day:
            self.usage.save(force=True)
            self._current_day = today

        foreground = self.is_activity_countable(self.current_context)
        # Passive time is media playing outside the foreground application.
        # It remains passive while the user works in another window.
        background_media = (
            []
            if self.current_context.is_video_playing
            else self.current_context.background_media or []
        )
        passive = bool(background_media)
        debug_snapshot = (
            str(self.current_context.source),
            str(self.current_context.app_name),
            str(self.current_context.window_title),
            str(self.current_context.url),
            self.current_context.has_recent_input,
            self.current_context.browser_media_playing,
            self.current_context.is_video_playing,
            foreground,
            tuple(background_media),
            tuple(self.probe.media_sources()),
        )
        if debug_snapshot != self._last_debug_snapshot:
            debug_log(
                "source={!r}; app={!r}; title={!r}; url={!r}; recent_input={}; audible={}; "
                "video_playing={}; foreground_counted={}; "
                "background_media={!r}; windows_media_sources={!r}; passive={}".format(
                    self.current_context.source,
                    self.current_context.app_name,
                    self.current_context.window_title,
                    self.current_context.url,
                    self.current_context.has_recent_input,
                    self.current_context.browser_media_playing,
                    self.current_context.is_video_playing,
                    foreground,
                    background_media,
                    self.probe.media_sources(),
                    passive,
                )
            )
            self._last_debug_snapshot = debug_snapshot
        self.usage.add_system_seconds(elapsed, foreground, passive, today)

        if foreground:
            self.usage.add_seconds(
                self.usage.target_for_context(self.current_context), elapsed, today
            )
        for media_name in background_media:
            self.usage.add_passive_seconds(media_name, elapsed, today)

        if now - self._last_save >= 10:
            self.usage.save()
            self._last_save = now
        self.state_changed.emit()

    @staticmethod
    def is_activity_countable(context):
        return bool(
            context.app_name
            and (
                context.has_recent_input
                or context.is_video_playing
                or _is_chrome_web_app(context)
            )
        )


def _is_chrome_web_app(context):
    """Chrome PWAs are standalone foreground applications, not browser tabs."""
    executable = Path(str(context.app_name)).name.lower()
    title = str(context.window_title or "").strip()
    browser_suffixes = (" - Google Chrome", " – Google Chrome", " - Chrome", " – Chrome")
    return executable == "chrome.exe" and bool(title) and not title.endswith(browser_suffixes)


# Kept as an import-compatible alias for integrations using the old name.
UsageGuardService = MonitoringService
