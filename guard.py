import time
from datetime import date

from PySide6.QtCore import QObject, QTimer, Signal

from activity import ActiveContext, ActivityProbe
from usage_guard import AppUsageStore, config


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

        if self.is_activity_countable(self.current_context):
            self.usage.add_seconds(
                self.usage.target_for_context(self.current_context), elapsed, today
            )

        if now - self._last_save >= 10:
            self.usage.save()
            self._last_save = now
        self.state_changed.emit()

    @staticmethod
    def is_activity_countable(context):
        return bool(context.app_name and (context.has_recent_input or context.is_video_playing))


# Kept as an import-compatible alias for integrations using the old name.
UsageGuardService = MonitoringService
