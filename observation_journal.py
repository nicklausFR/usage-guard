"""Append-only raw observations used to audit and rebuild usage decisions."""

import json
from collections import defaultdict
from datetime import date, datetime, timedelta
from pathlib import Path


class ObservationJournal:
    """Persist state transitions without changing the existing usage counters.

    Files are rotated daily, making the experiment cheap to inspect, retain and
    remove.  Repeated samples are suppressed; a heartbeat is written only when
    the state did not change for the configured interval.
    """

    def __init__(self, directory, enabled=True, heartbeat_seconds=60, retention_days=7):
        self.directory = Path(directory)
        self.enabled = bool(enabled)
        self.heartbeat_seconds = max(1, int(heartbeat_seconds))
        self.retention_days = max(1, int(retention_days))
        self._last_signature = None
        self._last_written_at = None
        if self.enabled:
            self.directory.mkdir(parents=True, exist_ok=True)
            self._purge_expired()

    @staticmethod
    def _signature(state):
        # Idle time changes every second but the meaningful thresholds are
        # already represented by ``has_recent_input`` and ``is_afk``.  Ignore
        # the raw counter when deciding whether a new transition occurred.
        stable = dict(state)
        stable.pop("idle_seconds", None)
        return json.dumps(stable, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def record(self, state, at=None, force=False):
        if not self.enabled:
            return False
        at = at or datetime.now().astimezone()
        signature = self._signature(state)
        changed = signature != self._last_signature
        heartbeat_due = (
            self._last_written_at is None
            or (at - self._last_written_at).total_seconds() >= self.heartbeat_seconds
        )
        if not force and not changed and not heartbeat_due:
            return False
        self._append({
            "at": at.isoformat(timespec="milliseconds"),
            "type": "state_change" if changed else "heartbeat",
            "state": state,
        }, at.date())
        self._last_signature = signature
        self._last_written_at = at
        return True

    def event(self, event_type, details=None, at=None):
        if not self.enabled:
            return False
        at = at or datetime.now().astimezone()
        self._append({
            "at": at.isoformat(timespec="milliseconds"),
            "type": str(event_type),
            "details": dict(details or {}),
        }, at.date())
        return True

    def _append(self, payload, day):
        path = self.directory / f"{day.isoformat()}.jsonl"
        with path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")

    def _purge_expired(self):
        cutoff = date.today() - timedelta(days=self.retention_days - 1)
        for path in self.directory.glob("*.jsonl"):
            try:
                file_day = date.fromisoformat(path.stem)
            except ValueError:
                continue
            if file_day < cutoff:
                try:
                    path.unlink()
                except OSError:
                    pass


def rebuild_active_seconds(directory):
    """Recalculate counted foreground time from completed journal intervals."""
    totals = defaultdict(float)
    previous_at = None
    previous_state = None
    for path in sorted(Path(directory).glob("*.jsonl")):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            try:
                event = json.loads(line)
                at = datetime.fromisoformat(event["at"])
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                continue
            event_type = event.get("type")
            # A fresh process start marks an unknown gap after a crash or
            # shutdown. Never charge that gap to the last observed target.
            if event_type == "service_start":
                previous_at = None
                previous_state = None
                continue
            if previous_at is not None and previous_state is not None and at >= previous_at:
                if previous_state.get("counted_active"):
                    target_key = str(previous_state.get("target_key", ""))
                    if target_key:
                        totals[target_key] += (at - previous_at).total_seconds()
            if event_type in {"state_change", "heartbeat"}:
                previous_at = at
                previous_state = dict(event.get("state") or {})
            elif event_type == "service_stop":
                previous_at = None
                previous_state = None
    return dict(totals)
