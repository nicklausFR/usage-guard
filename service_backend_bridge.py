"""Desktop-to-service state and command bridge for the DEV runtime."""

from __future__ import annotations

import json
import threading
import time

MAX_COMPACT_SNAPSHOT_BYTES = 4 * 1024 * 1024
MAX_COMPACT_ACTIVITY_EXPORT_BYTES = 640 * 1024


def _validate_activity_export(export):
    if not isinstance(export, dict) or set(export) - {
        "intervals", "live_intervals", "daily_aggregates", "cursor", "bytes",
    }:
        raise RuntimeError("desktop compact activity export is invalid")
    intervals = export.get("intervals", [])
    live_intervals = export.get("live_intervals", [])
    daily_aggregates = export.get("daily_aggregates", [])
    if (
        not isinstance(intervals, list) or len(intervals) > 500
        or not isinstance(live_intervals, list) or len(live_intervals) > 256
        or not isinstance(daily_aggregates, list) or len(daily_aggregates) > 31
    ):
        raise RuntimeError("desktop compact activity export exceeds item limit")
    metric_count = 0
    for source in daily_aggregates:
        aggregate = dict(source or {})
        if set(aggregate) != {"aggregate_id", "local_day", "metrics"}:
            raise RuntimeError("desktop daily aggregate is invalid")
        metrics = aggregate.get("metrics")
        if not isinstance(metrics, list):
            raise RuntimeError("desktop daily aggregate is invalid")
        metric_count += len(metrics)
        for source_metric in metrics:
            metric = dict(source_metric or {})
            if set(metric) != {"kind", "key", "seconds"} or metric.get(
                "kind"
            ) not in {"usage", "passive", "system", "other_site"}:
                raise RuntimeError("desktop daily aggregate is invalid")
    if metric_count > 500:
        raise RuntimeError("desktop compact activity export exceeds item limit")
    try:
        cursor = int(export.get("cursor") or 0)
        exported_bytes = int(export.get("bytes") or 0)
    except (TypeError, ValueError) as error:
        raise RuntimeError("desktop compact activity export cursor is invalid") from error
    if cursor < 0 or exported_bytes < 0:
        raise RuntimeError("desktop compact activity export cursor is invalid")
    encoded_size = len(json.dumps(
        export, ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8"))
    if encoded_size > MAX_COMPACT_ACTIVITY_EXPORT_BYTES:
        raise RuntimeError("desktop compact activity export exceeds byte limit")
    return export


class ServiceBackendBridge:
    def __init__(
        self, decision_service, desktop_service, interval_seconds=2,
        activity_interval_seconds=60, logger=None, clock=None,
    ):
        self.decision_service = decision_service
        self.desktop_service = desktop_service
        self.interval_seconds = max(0.2, float(interval_seconds))
        # Kept as an accepted argument for installer/API compatibility.  The
        # bridge no longer requests the complete activity store: closed/live
        # records travel through the bounded durable desktop outbox.
        self.activity_interval_seconds = max(
            self.interval_seconds, float(activity_interval_seconds)
        )
        self.logger = logger or (lambda _message: None)
        self._clock = clock or time.monotonic
        self._stop = threading.Event()
        self._thread = None
        self._last_error = ""

    def start(self):
        if self._thread is not None or not self.decision_service.external_service:
            return
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="usage-guard-service-backend-bridge"
        )
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=4)
            self._thread = None

    def sync_once(self):
        snapshot = self.desktop_service.request_remote_snapshot(timeout=5)
        if "error" not in snapshot:
            if len(json.dumps(
                snapshot, ensure_ascii=False, separators=(",", ":"),
            ).encode("utf-8")) > MAX_COMPACT_SNAPSHOT_BYTES:
                raise RuntimeError("desktop compact snapshot exceeds byte limit")
            activity_export = _validate_activity_export(
                self.desktop_service.request_activity_export(timeout=5)
            )
            self.decision_service.publish_desktop_state(
                snapshot, activity_unchanged=True,
                activity_export=activity_export,
            )
            # The service persists the generic outbox before returning.  Only
            # then may the desktop advance/truncate its JSONL cursor.
            aggregate_ids = [
                item.get("aggregate_id")
                for item in activity_export.get("daily_aggregates", [])
            ]
            if aggregate_ids:
                self.desktop_service.acknowledge_activity_export(
                    activity_export.get("cursor", 0), aggregate_ids,
                    timeout=5,
                )
            else:
                self.desktop_service.acknowledge_activity_export(
                    activity_export.get("cursor", 0), timeout=5,
                )
        identity = dict(
            dict(snapshot.get("runtime") or {}).get("windows_identity") or {}
        ) if isinstance(snapshot, dict) else {}
        try:
            pending = self.decision_service.next_backend_command(
                windows_sid=identity.get("windows_sid", ""),
                usage_guard_username=identity.get(
                    "usage_guard_username", ""
                ),
            )
        except TypeError:
            # Compatibility for development/test adapters implementing the
            # pre-scope interface. Production mirrors always accept identity.
            pending = self.decision_service.next_backend_command()
        if pending:
            result = self.desktop_service.request_remote_command(
                pending["command"], timeout=10
            )
            self.decision_service.complete_backend_command(
                pending["service_command_id"], result
            )

    def _run(self):
        while not self._stop.is_set():
            try:
                self.sync_once()
                self._last_error = ""
            except Exception as error:
                detail = f"{type(error).__name__}: {error}"
                if detail != self._last_error:
                    self.logger(f"service backend bridge failed: {detail}")
                    self._last_error = detail
            self._stop.wait(self.interval_seconds)
