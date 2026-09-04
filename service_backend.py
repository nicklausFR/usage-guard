"""Backend ownership and durable command hand-off for the Windows service."""

from __future__ import annotations

import copy
import json
import math
import os
import secrets
import sqlite3
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

from activity_keys import is_other_sites_aggregate_key
from backend_client import BackendClient
from client_update import ClientUpdateManager
from command_policy import (
    SOURCE_LOCAL_ADMIN, command_source, is_catalog_mutation,
    is_control_mutation,
)


def _clone(value):
    return json.loads(json.dumps(value, ensure_ascii=False))


def _command_order(value):
    text = str(value)
    return (0, int(text)) if text.isdigit() else (1, text)


DESKTOP_STALE_SECONDS = 15
ACTIVITY_OUTBOX_PAGE_BYTES = 512 * 1024
DAILY_AGGREGATE_MAX_DAYS = 31
DAILY_AGGREGATE_MAX_METRICS = 500


class DurableActivityOutbox:
    """Transactional pending-only activity queue, never a history archive.

    The previous broker embedded every pending row in one JSON document and
    rewrote that entire document after each desktop heartbeat and backend ACK.
    SQLite changes only the affected pages, reuses pages after deletion, and
    gives each insert/ACK a durable transaction without ever serializing the
    local activity archive or the complete offline backlog into IPC memory.
    """

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA auto_vacuum=INCREMENTAL")
            db.execute(
                "CREATE TABLE IF NOT EXISTS activity_outbox ("
                "sequence INTEGER PRIMARY KEY AUTOINCREMENT,"
                "record_id TEXT NOT NULL UNIQUE,"
                "interval_id TEXT NOT NULL DEFAULT '',"
                "session TEXT NOT NULL,"
                "timeline_acked INTEGER NOT NULL DEFAULT 0,"
                "usage_acked INTEGER NOT NULL DEFAULT 0)"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS activity_outbox_interval "
                "ON activity_outbox(interval_id)"
            )
            self._migrate_other_sites_timeline_rows(db)
            db.execute(
                "CREATE TABLE IF NOT EXISTS daily_aggregate_outbox ("
                "sequence INTEGER PRIMARY KEY AUTOINCREMENT,"
                "windows_sid TEXT NOT NULL DEFAULT '',"
                "local_day TEXT NOT NULL,"
                "aggregate_id TEXT NOT NULL,"
                "aggregate TEXT NOT NULL,"
                "UNIQUE(windows_sid,local_day))"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS daily_aggregate_outbox_order "
                "ON daily_aggregate_outbox(sequence)"
            )

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        try:
            db.execute("PRAGMA busy_timeout=15000")
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def _encoded(session):
        return json.dumps(
            dict(session or {}), ensure_ascii=False, sort_keys=True,
            separators=(",", ":"),
        )

    @staticmethod
    def _migrate_other_sites_timeline_rows(db):
        """Acknowledge legacy aggregate sentinels for the timeline only."""
        sequences = []
        for sequence, encoded in db.execute(
            "SELECT sequence,session FROM activity_outbox "
            "WHERE timeline_acked=0"
        ).fetchall():
            try:
                session = json.loads(encoded)
            except (TypeError, ValueError):
                continue
            if (
                isinstance(session, dict)
                and is_other_sites_aggregate_key(session.get("key"))
            ):
                sequences.append((int(sequence),))
        if sequences:
            db.executemany(
                "UPDATE activity_outbox SET timeline_acked=1 "
                "WHERE sequence=?", sequences,
            )
        db.execute(
            "DELETE FROM activity_outbox WHERE timeline_acked=1 "
            "AND usage_acked=1"
        )

    def add(self, session, *, timeline_acked=False, usage_acked=None):
        return bool(self._add_entries([(
            session, timeline_acked, usage_acked,
        )]))

    def add_many(self, sessions):
        return self._add_entries([
            (session, False, None) for session in sessions or []
        ])

    def _add_entries(self, entries):
        added = 0
        with self._connect() as db:
            for raw_session, timeline_acked, usage_acked in entries:
                session = dict(raw_session or {})
                record_id = str(session.get("record_id") or "").strip()
                if not record_id.startswith("timeline-"):
                    raise ValueError("Identifiant de session exportée invalide.")
                interval_id = str(session.get("interval_id") or "").strip()
                if usage_acked is None:
                    usage_acked = not bool(interval_id)
                timeline_acked = (
                    bool(timeline_acked)
                    or is_other_sites_aggregate_key(session.get("key"))
                )
                encoded = self._encoded(session)
                if len(encoded.encode("utf-8")) + 2 > ACTIVITY_OUTBOX_PAGE_BYTES:
                    raise ValueError("Session exportée trop volumineuse.")
                existing = db.execute(
                    "SELECT session FROM activity_outbox WHERE record_id=?",
                    (record_id,),
                ).fetchone()
                if existing:
                    if str(existing[0]) != encoded:
                        raise ValueError("Session exportée non idempotente.")
                    if is_other_sites_aggregate_key(session.get("key")):
                        db.execute(
                            "UPDATE activity_outbox SET timeline_acked=1 "
                            "WHERE record_id=?", (record_id,),
                        )
                    continue
                db.execute(
                    "INSERT INTO activity_outbox(record_id,interval_id,session,"
                    "timeline_acked,usage_acked) VALUES(?,?,?,?,?)",
                    (
                        record_id, interval_id, encoded,
                        int(bool(timeline_acked)), int(bool(usage_acked)),
                    ),
                )
                added += 1
            db.execute(
                "DELETE FROM activity_outbox WHERE timeline_acked=1 "
                "AND usage_acked=1"
            )
        return added

    def add_legacy_entries(self, entries):
        """Import the old broker field transactionally; safe to replay."""
        prepared = []
        for record_id, source in dict(entries or {}).items():
            source = dict(source or {})
            session = dict(source.get("session") or {})
            session.setdefault("record_id", str(record_id))
            prepared.append((
                session,
                bool(source.get("timeline_acked")),
                bool(source.get(
                    "usage_acked", session.get("kind") != "active",
                )),
            ))
        return self._add_entries(prepared)

    def pending_sessions(
        self, timeline=True, limit=500,
        max_bytes=ACTIVITY_OUTBOX_PAGE_BYTES,
    ):
        condition = "timeline_acked=0" if timeline else (
            "usage_acked=0 AND interval_id<>''"
        )
        limit = max(1, min(500, int(limit)))
        max_bytes = max(1024, min(
            ACTIVITY_OUTBOX_PAGE_BYTES, int(max_bytes),
        ))
        with self._connect() as db:
            # Read lengths first so SQLite never materializes a page of large
            # JSON records before the byte budget has been applied.
            candidates = db.execute(
                "SELECT sequence,LENGTH(CAST(session AS BLOB)) "
                "FROM activity_outbox WHERE " + condition
                + " ORDER BY sequence LIMIT ?", (limit,),
            ).fetchall()
            sequences, used = [], 2  # JSON list brackets.
            for sequence, encoded_size in candidates:
                encoded_size = int(encoded_size or 0) + (1 if sequences else 0)
                if encoded_size + 2 > max_bytes:
                    if not sequences:
                        raise ValueError("Session exportée trop volumineuse.")
                    break
                if used + encoded_size > max_bytes:
                    break
                sequences.append(int(sequence))
                used += encoded_size
            if not sequences:
                return []
            placeholders = ",".join("?" for _ in sequences)
            rows = db.execute(
                "SELECT session FROM activity_outbox WHERE sequence IN ("
                + placeholders + ") ORDER BY sequence", sequences,
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def acknowledge_timeline(self, record_ids):
        values = list(dict.fromkeys(str(value) for value in record_ids or []))
        if not values:
            return
        with self._connect() as db:
            db.executemany(
                "UPDATE activity_outbox SET timeline_acked=1 "
                "WHERE record_id=?", ((value,) for value in values),
            )
            db.execute(
                "DELETE FROM activity_outbox WHERE timeline_acked=1 "
                "AND usage_acked=1"
            )

    def acknowledge_usage(self, interval_ids):
        values = list(dict.fromkeys(str(value) for value in interval_ids or []))
        if not values:
            return
        with self._connect() as db:
            db.executemany(
                "UPDATE activity_outbox SET usage_acked=1 "
                "WHERE interval_id=?", ((value,) for value in values),
            )
            db.execute(
                "DELETE FROM activity_outbox WHERE timeline_acked=1 "
                "AND usage_acked=1"
            )

    def count(self):
        with self._connect() as db:
            return int(db.execute(
                "SELECT COUNT(*) FROM activity_outbox"
            ).fetchone()[0])

    @staticmethod
    def _validated_daily_aggregate(source):
        aggregate = dict(source or {})
        if set(aggregate) != {"aggregate_id", "local_day", "metrics"}:
            raise ValueError("Agrégat journalier invalide.")
        aggregate_id = str(aggregate.get("aggregate_id") or "").strip()
        if (
            not 8 <= len(aggregate_id) <= 128
            or any(character not in (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                "0123456789._:-"
            ) for character in aggregate_id)
        ):
            raise ValueError("Identifiant d’agrégat journalier invalide.")
        local_day = str(aggregate.get("local_day") or "").strip()
        try:
            datetime.strptime(local_day, "%Y-%m-%d")
        except ValueError as error:
            raise ValueError("Date d’agrégat journalier invalide.") from error
        metrics = aggregate.get("metrics")
        if not isinstance(metrics, list):
            raise ValueError("Métriques journalières invalides.")
        seen = set()
        normalized = []
        for source_metric in metrics:
            metric = dict(source_metric or {})
            if set(metric) != {"kind", "key", "seconds"}:
                raise ValueError("Métrique journalière invalide.")
            kind = str(metric.get("kind") or "").strip()
            key = str(metric.get("key") or "").strip()
            try:
                seconds = float(metric.get("seconds") or 0)
            except (TypeError, ValueError) as error:
                raise ValueError("Métrique journalière invalide.") from error
            identity = (kind, key)
            if (
                kind not in {"usage", "passive", "system", "other_site"}
                or not key or len(key) > 1024
                or any(ord(character) < 32 for character in key)
                or not math.isfinite(seconds) or seconds < 0
                or identity in seen
            ):
                raise ValueError("Métrique journalière invalide.")
            seen.add(identity)
            normalized.append({
                "kind": kind, "key": key, "seconds": round(seconds, 3),
            })
        normalized.sort(key=lambda item: (item["kind"], item["key"]))
        return {
            "aggregate_id": aggregate_id, "local_day": local_day,
            "metrics": normalized,
        }

    def add_daily_aggregates(self, aggregates, windows_sid=""):
        """Coalesce pending summaries by owner/day; raw history is rejected."""
        sources = list(aggregates or [])
        if len(sources) > DAILY_AGGREGATE_MAX_DAYS:
            raise ValueError("Lot d’agrégats journaliers trop volumineux.")
        normalized = [self._validated_daily_aggregate(item) for item in sources]
        if sum(len(item["metrics"]) for item in normalized) > DAILY_AGGREGATE_MAX_METRICS:
            raise ValueError("Lot d’agrégats journaliers trop volumineux.")
        encoded_batch = json.dumps(
            normalized, ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded_batch) > ACTIVITY_OUTBOX_PAGE_BYTES:
            raise ValueError("Lot d’agrégats journaliers trop volumineux.")
        sid = str(windows_sid or "").strip().upper()
        with self._connect() as db:
            for aggregate in normalized:
                encoded = self._encoded(aggregate)
                existing = db.execute(
                    "SELECT aggregate_id,aggregate FROM daily_aggregate_outbox "
                    "WHERE windows_sid=? AND local_day=?",
                    (sid, aggregate["local_day"]),
                ).fetchone()
                if existing and str(existing[0]) == aggregate["aggregate_id"]:
                    if str(existing[1]) != encoded:
                        raise ValueError("Agrégat journalier non idempotent.")
                    continue
                db.execute(
                    "INSERT INTO daily_aggregate_outbox(windows_sid,local_day,"
                    "aggregate_id,aggregate) VALUES(?,?,?,?) "
                    "ON CONFLICT(windows_sid,local_day) DO UPDATE SET "
                    "aggregate_id=excluded.aggregate_id,"
                    "aggregate=excluded.aggregate",
                    (sid, aggregate["local_day"], aggregate["aggregate_id"], encoded),
                )
        return [item["aggregate_id"] for item in normalized]

    def pending_daily_aggregates(
        self, max_days=DAILY_AGGREGATE_MAX_DAYS,
        max_metrics=DAILY_AGGREGATE_MAX_METRICS,
        max_bytes=ACTIVITY_OUTBOX_PAGE_BYTES,
    ):
        max_days = max(1, min(DAILY_AGGREGATE_MAX_DAYS, int(max_days)))
        max_metrics = max(1, min(DAILY_AGGREGATE_MAX_METRICS, int(max_metrics)))
        max_bytes = max(1024, min(ACTIVITY_OUTBOX_PAGE_BYTES, int(max_bytes)))
        with self._connect() as db:
            rows = db.execute(
                "SELECT windows_sid,aggregate FROM daily_aggregate_outbox "
                "ORDER BY sequence LIMIT ?", (max_days,),
            ).fetchall()
        groups, count, used = {}, 0, 2
        for sid, encoded in rows:
            aggregate = json.loads(encoded)
            metrics = list(aggregate.get("metrics") or [])
            size = len(str(encoded).encode("utf-8")) + (1 if count else 0)
            if len(metrics) > max_metrics or size + 2 > max_bytes:
                if not count:
                    raise ValueError("Agrégat journalier trop volumineux.")
                break
            if count and (
                sum(len(item["metrics"]) for values in groups.values() for item in values)
                + len(metrics) > max_metrics
                or used + size > max_bytes
            ):
                break
            groups.setdefault(str(sid), []).append(aggregate)
            count += 1
            used += size
        return groups

    def acknowledge_daily_aggregates(self, aggregate_ids, windows_sid=""):
        """ACK one owner's rows without consuming another SID's same digest."""
        values = list(dict.fromkeys(
            str(value) for value in aggregate_ids or [] if str(value)
        ))
        if not values:
            return
        sid = str(windows_sid or "").strip().upper()
        with self._connect() as db:
            db.executemany(
                "DELETE FROM daily_aggregate_outbox WHERE windows_sid=? "
                "AND aggregate_id=?",
                ((sid, value) for value in values),
            )

    def daily_count(self):
        with self._connect() as db:
            return int(db.execute(
                "SELECT COUNT(*) FROM daily_aggregate_outbox"
            ).fetchone()[0])


def _backend_error_message(error):
    if isinstance(error, HTTPError):
        try:
            payload = json.loads(error.read().decode("utf-8"))
            message = str(payload.get("error") or "").strip()
            if message:
                return message
        except (AttributeError, UnicodeDecodeError, ValueError):
            pass
    if isinstance(error, URLError):
        reason = str(getattr(error, "reason", "") or "").strip()
        return f"Backend inaccessible : {reason}" if reason else "Backend inaccessible."
    return str(error).strip() or "Communication avec le backend impossible."


class ServiceBackendRuntime:
    """Own outbound HTTPS while the desktop only supplies state and execution."""

    def __init__(
        self, directory, registry, settings=None, client_factory=BackendClient,
        logger=None, local_server_factory=None,
    ):
        self.directory = Path(directory)
        self.registry = registry
        self.logger = logger or (lambda _message: None)
        self.state_path = self.directory / "backend-command-broker.json"
        self.settings_path = self.directory / "backend.json"
        self._lock = threading.RLock()
        self._snapshot = None
        self._desktop_updated_at = ""
        self._desktop_seen_monotonic = 0.0
        self._pending = {}
        self._completed = {}
        self._protection_events = {}
        self._last_protection_healthy = None
        self._admin_sessions = {}
        self._windows_identities = []
        self._windows_identities_loaded_at = 0.0
        self._personal_policies = {}
        self._personal_usage = {}
        self._personal_policy_outbox = []
        # Populated only while migrating a broker written by an older build.
        self._activity_outbox = {}
        self._activity_live_intervals = []
        self._local_server_factory = local_server_factory
        self._local_server = None
        self._local_server_thread = None
        self._policy_stop = threading.Event()
        self._policy_wakeup = threading.Event()
        self._policy_thread = None
        self._load_state()
        self._activity_store = DurableActivityOutbox(
            self.directory / "backend-activity-outbox.sqlite3"
        )
        if self._activity_outbox:
            self._activity_store.add_legacy_entries(self._activity_outbox)
            self._activity_outbox = {}
            # Publish the migrated state only after SQLite committed. A crash
            # before this rewrite simply replays idempotent imports.
            self._save_state()
        resolved = dict(settings) if settings is not None else self._load_settings()
        resolved.setdefault(
            "activity_cursor_path",
            str(self.directory / "backend-activity-cursor.json"),
        )
        self.settings = dict(resolved)
        configured_identities = resolved.get("windows_identities")
        if isinstance(configured_identities, list) and configured_identities:
            self._windows_identities = self._normalize_windows_identities(
                configured_identities
            )
        self.installation_profile = str(
            resolved.get("installation_profile") or "server"
        ).strip().lower()
        if self.installation_profile not in {"local", "server"}:
            raise ValueError("Profil d’installation backend invalide.")
        self.client = client_factory(
            self.snapshot, self.accept_command, resolved,
            interval_provider=self.pending_usage_intervals,
            interval_acknowledger=self.acknowledge_usage_intervals,
            timeline_provider=self.pending_timeline_sessions,
            timeline_acknowledger=self.acknowledge_timeline_sessions,
            live_interval_provider=self.live_activity_intervals,
            daily_aggregate_provider=self.pending_daily_aggregates,
            daily_aggregate_acknowledger=self.acknowledge_daily_aggregates,
            status_provider=self.protection_status,
            status_acknowledger=self.acknowledge_protection_events,
            logger=self.logger,
        )
        self.update_manager = ClientUpdateManager(self.directory, self.client)
        self.started = False

    def _load_settings(self):
        try:
            saved = json.loads(self.settings_path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError, TypeError):
            saved = {}
        return {
            "installation_profile": str(
                saved.get("installation_profile") or "server"
            ).strip().lower(),
            "display_name": str(saved.get("display_name") or "").strip(),
            "enabled": bool(saved.get("enabled", False)),
            "base_url": str(saved.get("base_url", "")).rstrip("/"),
            "device_id": str(saved.get("device_id", "")).strip(),
            "device_token": str(saved.get("device_token", "")).strip(),
            "poll_seconds": max(5, int(saved.get("poll_seconds", 15))),
            "windows_identities": list(saved.get("windows_identities") or []),
        }

    def _save_settings(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        try:
            saved = json.loads(
                self.settings_path.read_text(encoding="utf-8-sig")
            )
        except (OSError, ValueError, TypeError):
            saved = {}
        if not isinstance(saved, dict):
            saved = {}
        saved.update(self.settings)
        temporary = self.settings_path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(saved, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )
        temporary.replace(self.settings_path)

    def _load_state(self):
        try:
            saved = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            saved = {}
        if isinstance(saved.get("pending"), dict):
            self._pending = saved["pending"]
        if isinstance(saved.get("completed"), dict):
            self._completed = saved["completed"]
        if isinstance(saved.get("protection_events"), dict):
            self._protection_events = saved["protection_events"]
        if isinstance(saved.get("windows_identities"), list):
            self._windows_identities = self._normalize_windows_identities(
                saved["windows_identities"]
            )
        if isinstance(saved.get("personal_policies"), dict):
            self._personal_policies = {
                str(sid).strip().upper(): dict(entry)
                for sid, entry in saved["personal_policies"].items()
                if str(sid).strip().upper().startswith("S-1-")
                and isinstance(entry, dict)
            }
        if isinstance(saved.get("personal_usage"), dict):
            self._personal_usage = {
                str(sid).strip().upper(): dict(entry)
                for sid, entry in saved["personal_usage"].items()
                if str(sid).strip().upper().startswith("S-1-")
                and isinstance(entry, dict)
            }
        if isinstance(saved.get("personal_policy_outbox"), list):
            self._personal_policy_outbox = [
                dict(entry) for entry in saved["personal_policy_outbox"]
                if isinstance(entry, dict)
                and str(entry.get("windows_sid") or "").strip().upper().startswith("S-1-")
                and isinstance(entry.get("command"), dict)
                and str(entry.get("idempotency_key") or "").strip()
            ]
        if isinstance(saved.get("activity_outbox"), dict):
            self._activity_outbox = {
                str(record_id): dict(entry)
                for record_id, entry in saved["activity_outbox"].items()
                if str(record_id).startswith("timeline-")
                and isinstance(entry, dict)
                and isinstance(entry.get("session"), dict)
            }
        if isinstance(saved.get("activity_live_intervals"), list):
            self._activity_live_intervals = [
                dict(item) for item in saved["activity_live_intervals"][:256]
                if isinstance(item, dict)
            ]

    def _save_state(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_suffix(".tmp")
        encoded = json.dumps({
            "pending": self._pending,
            "completed": self._completed,
            "protection_events": self._protection_events,
            "windows_identities": self._windows_identities,
            "personal_policies": self._personal_policies,
            "personal_usage": self._personal_usage,
            "personal_policy_outbox": self._personal_policy_outbox,
            "activity_live_intervals": self._activity_live_intervals,
        }, ensure_ascii=False, sort_keys=True)
        # publish_desktop_state returns an ACK boundary to the desktop.  The
        # broker must therefore reach stable storage before its source JSONL
        # may be compacted; write_text alone can still be sitting in the OS
        # cache when it returns.
        with temporary.open("w", encoding="utf-8") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(self.state_path)

    @staticmethod
    def _normalize_windows_identities(identities):
        normalized = []
        seen = set()
        for source in identities or []:
            if not isinstance(source, dict):
                continue
            sid = str(source.get("windows_sid") or "").strip().upper()
            username = str(source.get("usage_guard_username") or "").strip()
            if not sid.startswith("S-1-") or not username or sid in seen:
                continue
            seen.add(sid)
            normalized.append({
                "windows_sid": sid,
                "windows_domain": str(source.get("windows_domain") or ""),
                "windows_username": str(source.get("windows_username") or ""),
                "is_windows_admin": bool(source.get("is_windows_admin", False)),
                "usage_guard_username": username,
            })
        return normalized

    def resolve_windows_identity(self, windows_sid):
        """Resolve one SID without exposing mappings for another device/user."""
        sid = str(windows_sid or "").strip().upper()
        if not sid.startswith("S-1-"):
            raise ValueError("SID Windows invalide.")
        refresh_failed = False
        with self._lock:
            should_refresh = (
                time.monotonic() - self._windows_identities_loaded_at >= 60
            )
        if should_refresh and self.client.configured:
            try:
                refreshed = self._normalize_windows_identities(
                    self.client.windows_identities()
                )
                with self._lock:
                    self._windows_identities = refreshed
                    self._windows_identities_loaded_at = time.monotonic()
                    self._save_state()
            except Exception as error:
                refresh_failed = True
                self.logger(
                    "windows identity refresh failed: "
                    f"{type(error).__name__}"
                )
        with self._lock:
            mapping = next((
                dict(item) for item in self._windows_identities
                if item.get("windows_sid") == sid
            ), None)
        if mapping:
            return {
                **mapping,
                "mapped": True,
                "mapping_status": "cached" if refresh_failed else "mapped",
            }
        return {
            "windows_sid": sid,
            "usage_guard_username": "",
            "mapped": False,
            "mapping_status": (
                "backend_unavailable"
                if refresh_failed or not self.client.configured
                else "unmapped"
            ),
        }

    @staticmethod
    def _normalize_personal_policy(source, windows_sid, username):
        source = dict(source or {})
        sid = str(source.get("windows_sid") or windows_sid or "").strip().upper()
        owner = str(source.get("usage_guard_username") or "").strip()
        if sid != windows_sid or owner.casefold() != username.casefold():
            raise ValueError("Politique reçue pour une autre session Windows.")
        try:
            revision = int(source.get("revision") or 0)
        except (TypeError, ValueError) as error:
            raise ValueError("Révision de politique invalide.") from error
        configured = bool(source.get("configured"))
        policy = source.get("policy")
        if revision < 0 or (configured and (revision < 1 or not isinstance(policy, dict))):
            raise ValueError("Politique utilisateur invalide.")
        if not configured and (revision != 0 or policy is not None):
            raise ValueError("Politique utilisateur non configurée incohérente.")
        return {
            "device_id": str(source.get("device_id") or ""),
            "windows_sid": sid,
            "usage_guard_username": owner,
            "configured": configured,
            "revision": revision,
            "policy": _clone(policy) if isinstance(policy, dict) else None,
            "actor": str(source.get("actor") or ""),
            "created_at": str(source.get("created_at") or ""),
        }

    def user_policy(self, windows_sid):
        """Return this SID's validated policy, retaining current and previous copies."""
        sid = str(windows_sid or "").strip().upper()
        identity = self.resolve_windows_identity(sid)
        if not identity.get("mapped"):
            raise PermissionError("Cette session Windows n’est pas associée.")
        username = str(identity.get("usage_guard_username") or "")
        with self._lock:
            cached_entry = dict(self._personal_policies.get(sid) or {})
            cached = cached_entry.get("current")
        if self.client.configured:
            try:
                fetched = self._normalize_personal_policy(
                    self.client.user_policy(sid), sid, username,
                )
                with self._lock:
                    entry = dict(self._personal_policies.get(sid) or {})
                    current = entry.get("current")
                    if current != fetched:
                        if isinstance(current, dict):
                            entry["previous"] = current
                        entry["current"] = fetched
                    entry["cached_at"] = datetime.now(timezone.utc).isoformat(
                        timespec="seconds"
                    )
                    self._personal_policies[sid] = entry
                    self._save_state()
                return {**_clone(fetched), "policy_status": "current"}
            except Exception as error:
                self.logger(
                    "personal policy refresh failed: "
                    f"{type(error).__name__}"
                )
        if isinstance(cached, dict):
            validated = self._normalize_personal_policy(
                cached, sid, username,
            )
            return {**validated, "policy_status": "cached"}
        raise RuntimeError("Aucune politique validée n’est disponible pour cette session.")

    def cached_user_policy(self, windows_sid):
        """Expose only the protected local cache to an interactive session."""
        sid = str(windows_sid or "").strip().upper()
        if not sid.startswith("S-1-"):
            raise ValueError("SID Windows invalide.")
        with self._lock:
            mapping = next((
                dict(item) for item in self._windows_identities
                if item.get("windows_sid") == sid
            ), None)
            cached = dict(
                (self._personal_policies.get(sid) or {}).get("current") or {}
            )
        if not mapping:
            raise PermissionError("Cette session Windows n’est pas associée.")
        if not cached:
            raise RuntimeError(
                "Aucune politique validée n’est disponible pour cette session."
            )
        validated = self._normalize_personal_policy(
            cached, sid, mapping["usage_guard_username"],
        )
        return {**validated, "policy_status": "cached"}

    def refresh_personal_usage(self, windows_sid, policy_state=None):
        """Cache today's server-unioned usage for every limit in one SID policy."""
        sid = str(windows_sid or "").strip().upper()
        identity = self.resolve_windows_identity(sid)
        if not identity.get("mapped"):
            raise PermissionError("Cette session Windows n’est pas associée.")
        policy_state = dict(policy_state or self.user_policy(sid))
        document = policy_state.get("policy")
        limits = document.get("limits") if isinstance(document, dict) else None
        if not policy_state.get("configured") or not isinstance(limits, list):
            raise RuntimeError("Aucune politique personnelle configurée.")
        now = datetime.now().astimezone()
        period_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        totals = {}
        for source in limits:
            source = dict(source or {})
            if not source.get("enabled", True):
                continue
            key = str(source.get("key") or source.get("target_key") or "").strip()
            measured = str(source.get("target_key") or key).strip()
            if not key.startswith(("app:", "site:", "category:")):
                raise ValueError("Cible de politique non prise en charge.")
            if measured.startswith("category:"):
                result = self.client.user_usage_union(
                    sid, period_start.isoformat(), now.isoformat(),
                    category_key=measured.removeprefix("category:"),
                )
            elif measured.startswith(("app:", "site:")):
                result = self.client.user_usage_union(
                    sid, period_start.isoformat(), now.isoformat(),
                    target_key=measured,
                )
            else:
                raise ValueError("Cible de politique non prise en charge.")
            owner = str(result.get("usage_guard_username") or "")
            if owner.casefold() != str(
                identity.get("usage_guard_username") or ""
            ).casefold():
                raise ValueError("Consommation reçue pour une autre personne.")
            seconds = float(result.get("seconds") or 0.0)
            if seconds < 0 or not math.isfinite(seconds):
                raise ValueError("Consommation personnelle invalide.")
            totals[key] = {
                "target_key": measured, "seconds": round(seconds, 3),
            }
        usage = {
            "windows_sid": sid,
            "usage_guard_username": identity["usage_guard_username"],
            "policy_revision": int(policy_state.get("revision") or 0),
            "period_start": period_start.isoformat(timespec="seconds"),
            "measured_at": now.isoformat(timespec="seconds"),
            "totals": totals,
        }
        with self._lock:
            self._personal_usage[sid] = usage
            self._save_state()
        return {**_clone(usage), "usage_status": "current"}

    def cached_personal_usage(self, windows_sid):
        """Expose only this mapped SID's last protected union snapshot."""
        sid = str(windows_sid or "").strip().upper()
        with self._lock:
            mapping = next((
                dict(item) for item in self._windows_identities
                if item.get("windows_sid") == sid
            ), None)
            cached = dict(self._personal_usage.get(sid) or {})
        if not mapping:
            raise PermissionError("Cette session Windows n’est pas associée.")
        if not cached or str(cached.get("usage_guard_username") or "").casefold() != str(
            mapping.get("usage_guard_username") or ""
        ).casefold():
            raise RuntimeError(
                "Aucune consommation fusionnée n’est disponible pour cette session."
            )
        return {**_clone(cached), "usage_status": "cached"}

    def acknowledge_user_policy(self, windows_sid, revision, result):
        """Persist actual local application before reporting it to the backend."""
        sid = str(windows_sid or "").strip().upper()
        if not isinstance(result, dict):
            raise ValueError("Résultat d’application de politique invalide.")
        try:
            revision = int(revision)
        except (TypeError, ValueError) as error:
            raise ValueError("Révision de politique invalide.") from error
        with self._lock:
            entry = dict(self._personal_policies.get(sid) or {})
            current = dict(entry.get("current") or {})
            if revision < 1 or revision != int(current.get("revision") or 0):
                raise ValueError("Révision de politique absente du cache protégé.")
            entry["local_applied_revision"] = revision if result.get("ok") else int(
                entry.get("local_applied_revision") or 0
            )
            entry["last_result"] = _clone(result)
            entry["ack_pending"] = True
            entry["pending_ack"] = {
                "revision": revision, "result": _clone(result),
            }
            self._personal_policies[sid] = entry
            self._save_state()
        if self.client.configured:
            try:
                acknowledged = self.client.acknowledge_user_policy(
                    sid, revision, result,
                )
                with self._lock:
                    entry = dict(self._personal_policies.get(sid) or {})
                    entry["ack_pending"] = False
                    entry.pop("pending_ack", None)
                    self._personal_policies[sid] = entry
                    self._save_state()
                return acknowledged
            except Exception as error:
                self.logger(
                    "personal policy acknowledgement failed: "
                    f"{type(error).__name__}"
                )
        return {
            "windows_sid": sid,
            "revision": revision,
            "ack_pending": True,
        }

    def _flush_personal_policy_ack(self, windows_sid):
        sid = str(windows_sid or "").strip().upper()
        with self._lock:
            entry = dict(self._personal_policies.get(sid) or {})
            pending = dict(entry.get("pending_ack") or {})
        if not pending or not self.client.configured:
            return
        self.client.acknowledge_user_policy(
            sid, pending.get("revision"), pending.get("result"),
        )
        with self._lock:
            entry = dict(self._personal_policies.get(sid) or {})
            if entry.get("pending_ack") == pending:
                entry["ack_pending"] = False
                entry.pop("pending_ack", None)
                self._personal_policies[sid] = entry
                self._save_state()

    def queue_personal_policy_action(self, command, actor=""):
        """Persist a local person-limit mutation before background upload."""
        if self.installation_profile != "server":
            return {"queued": False, "reason": "local_profile"}
        command = dict(command or {})
        if command.get("action") not in {
            "set_limit", "remove_limit", "set_computer_block",
            "set_computer_block_enabled", "clear_computer_block",
        }:
            return {"queued": False, "reason": "not_personal_policy"}
        with self._lock:
            runtime = dict((self._snapshot or {}).get("runtime") or {})
            identity = dict(runtime.get("windows_identity") or {})
            sid = str(identity.get("windows_sid") or "").strip().upper()
            if not sid.startswith("S-1-"):
                raise ValueError(
                    "La session Windows courante n’est pas associée à la politique personnelle."
                )
            operation_key = (
                "local-" + str(getattr(self.client, "device_id", "") or "device")
                + "-" + secrets.token_hex(16)
            )
            clean_command = _clone(command)
            clean_command.pop("_service_admin_token", None)
            entry = {
                "kind": "policy",
                "windows_sid": sid,
                "command": clean_command,
                "actor": str(actor or "administrateur local").strip(),
                "idempotency_key": operation_key,
                "queued_at": datetime.now(timezone.utc).isoformat(
                    timespec="seconds"
                ),
            }
            self._personal_policy_outbox.append(entry)
            self._save_state()
        self._policy_wakeup.set()
        return {
            "queued": True,
            "idempotency_key": operation_key,
            "pending": len(self._personal_policy_outbox),
        }

    def queue_user_catalog_action(self, command, actor=""):
        """Persist a local classification change before sharing it to other PCs."""
        if self.installation_profile != "server":
            return {"queued": False, "reason": "local_profile"}
        command = dict(command or {})
        if not is_catalog_mutation(command):
            return {"queued": False, "reason": "not_catalog"}
        with self._lock:
            runtime = dict((self._snapshot or {}).get("runtime") or {})
            identity = dict(runtime.get("windows_identity") or {})
            sid = str(identity.get("windows_sid") or "").strip().upper()
            if not sid.startswith("S-1-"):
                raise ValueError(
                    "La session Windows courante n’est pas associée au classement partagé."
                )
            operation_key = (
                "catalog-" + str(getattr(self.client, "device_id", "") or "device")
                + "-" + secrets.token_hex(16)
            )
            clean_command = _clone(command)
            clean_command.pop("_service_admin_token", None)
            self._personal_policy_outbox.append({
                "kind": "catalog",
                "windows_sid": sid,
                "command": clean_command,
                "actor": str(actor or "utilisateur local").strip(),
                "idempotency_key": operation_key,
                "queued_at": datetime.now(timezone.utc).isoformat(
                    timespec="seconds"
                ),
            })
            self._save_state()
        self._policy_wakeup.set()
        return {
            "queued": True,
            "idempotency_key": operation_key,
            "pending": len(self._personal_policy_outbox),
        }

    def _flush_personal_policy_outbox(self):
        """Replay queued mutations in order; server idempotency makes retries safe."""
        if not self.client.configured or self.installation_profile != "server":
            return
        while True:
            with self._lock:
                if not self._personal_policy_outbox:
                    return
                entry = _clone(self._personal_policy_outbox[0])
            try:
                if entry.get("kind", "policy") == "catalog":
                    self.client.push_user_catalog_action(
                        entry["windows_sid"], entry["command"],
                        entry["idempotency_key"], entry.get("actor", ""),
                    )
                else:
                    self.client.push_user_policy_action(
                        entry["windows_sid"], entry["command"],
                        entry["idempotency_key"], entry.get("actor", ""),
                    )
            except Exception as error:
                self.logger(
                    "personal policy upload failed: "
                    f"{type(error).__name__}"
                )
                return
            with self._lock:
                if (
                    self._personal_policy_outbox
                    and self._personal_policy_outbox[0].get("idempotency_key")
                    == entry["idempotency_key"]
                ):
                    self._personal_policy_outbox.pop(0)
                    self._save_state()

    def sync_personal_policies(self):
        """Refresh every mapped SID and replay durable acknowledgements."""
        if not self.client.configured:
            return
        self._flush_personal_policy_outbox()
        try:
            identities = self._normalize_windows_identities(
                self.client.windows_identities()
            )
            with self._lock:
                self._windows_identities = identities
                self._windows_identities_loaded_at = time.monotonic()
                self._save_state()
        except Exception as error:
            self.logger(
                "windows identity refresh failed before policies: "
                f"{type(error).__name__}"
            )
            with self._lock:
                identities = list(self._windows_identities)
        for identity in identities:
            sid = identity["windows_sid"]
            try:
                self._flush_personal_policy_ack(sid)
                policy = self.user_policy(sid)
                if policy.get("configured"):
                    self.refresh_personal_usage(sid, policy)
            except Exception as error:
                self.logger(
                    "personal policy sync failed: "
                    f"{type(error).__name__}"
                )

    def _run_personal_policy_sync(self):
        while not self._policy_stop.is_set():
            self.sync_personal_policies()
            self._policy_wakeup.wait(max(
                5, int(getattr(self.client, "poll_seconds", 15))
            ))
            self._policy_wakeup.clear()

    def start(self):
        if self.installation_profile == "local":
            self._start_local_backend()
        try:
            self.client.start()
            self.update_manager.start()
            self._policy_stop.clear()
            self._policy_wakeup.clear()
            if self.client.configured and self._policy_thread is None:
                self._policy_thread = threading.Thread(
                    target=self._run_personal_policy_sync, daemon=True,
                    name="usage-guard-personal-policy-sync",
                )
                self._policy_thread.start()
            self.started = self.client._thread is not None
        except Exception:
            self._stop_local_backend()
            raise

    def stop(self):
        self._policy_stop.set()
        self._policy_wakeup.set()
        if self._policy_thread is not None:
            self._policy_thread.join(timeout=3)
            self._policy_thread = None
        self.update_manager.stop()
        self.client.stop()
        self._stop_local_backend()
        self.started = False

    def _build_local_backend(self):
        if self._local_server_factory is not None:
            return self._local_server_factory(self.directory, self.client)
        from usage_guard_backend.server import BackendServer, Store

        parsed = urlparse(self.client.base_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost"}
            or parsed.path.rstrip("/") != "/usage-guard"
        ):
            raise ValueError(
                "Le backend local doit utiliser http://127.0.0.1:<port>/usage-guard."
            )
        bundle_root = Path(
            getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)
        )
        pwa_dir = bundle_root / "usage_guard_backend" / "pwa"
        origin = f"{parsed.scheme}://{parsed.netloc}"
        return BackendServer(
            host="127.0.0.1", port=parsed.port or 8767,
            store=Store(self.directory / "backend.sqlite3"),
            device_id=self.client.device_id,
            device_token=self.client.device_token,
            public_origin=origin, pwa_dir=pwa_dir,
            client_release_dir=self.directory / "client_updates",
            local_mode=True,
        )

    def _start_local_backend(self):
        if self._local_server is not None:
            return
        server = self._build_local_backend()
        thread = threading.Thread(
            target=server.start, daemon=True,
            name="usage-guard-local-backend",
        )
        self._local_server, self._local_server_thread = server, thread
        thread.start()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if getattr(server, "httpd", None) is not None:
                return
            if not thread.is_alive():
                break
            time.sleep(0.05)
        self._stop_local_backend()
        raise RuntimeError("Le backend SQLite local n’a pas démarré.")

    def _stop_local_backend(self):
        server = self._local_server
        thread = self._local_server_thread
        self._local_server = None
        self._local_server_thread = None
        if server is not None:
            server.stop()
        if thread is not None:
            thread.join(timeout=3)

    def publish_desktop_state(
        self, snapshot, activity=None, *, preserve_activity=False,
        activity_export=None,
    ):
        if activity is not None:
            raise ValueError(
                "Le transfert de l’archive d’activité complète est désactivé."
            )
        with self._lock:
            self._snapshot = _clone(snapshot) if isinstance(snapshot, dict) else None
            if activity_export is not None:
                self._store_activity_export_locked(activity_export)
            self._desktop_updated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            self._desktop_seen_monotonic = time.monotonic()
            self._queue_protection_transition_locked(
                self._protection_status_locked()
            )
        return self.status()

    def _store_activity_export_locked(self, export):
        if not isinstance(export, dict):
            raise ValueError("Export d’activité compact invalide.")
        sessions = export.get("intervals", [])
        live = export.get("live_intervals", [])
        daily = export.get("daily_aggregates", [])
        if (
            not isinstance(sessions, list) or len(sessions) > 500
            or not isinstance(live, list) or len(live) > 256
            or not isinstance(daily, list) or len(daily) > 31
        ):
            raise ValueError("Lot d’activité compact trop volumineux.")
        encoded_size = len(json.dumps(
            export, ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8"))
        if encoded_size > 640 * 1024:
            raise ValueError("Export d’activité compact trop volumineux.")
        self._activity_store.add_many(sessions)
        runtime = dict((self._snapshot or {}).get("runtime") or {})
        identity = dict(runtime.get("windows_identity") or {})
        daily_sid = str(identity.get("windows_sid") or "").strip().upper()
        if not daily_sid.startswith("S-1-"):
            daily_sid = ""
        self._activity_store.add_daily_aggregates(daily, daily_sid)
        self._activity_live_intervals = [dict(item) for item in live]
        # The live window is strictly bounded; durable closed rows live in the
        # transactional outbox and never inflate this broker document.
        self._save_state()

    def pending_timeline_sessions(self):
        fields = (
            "record_id", "kind", "id", "key", "label", "category",
            "category_lineage", "started_at", "ended_at",
            "windows_session_id", "started_before_tracking", "source",
        )
        with self._lock:
            groups = {}
            for source in self._activity_store.pending_sessions(timeline=True):
                if is_other_sites_aggregate_key(source.get("key")):
                    continue
                session = {
                    field: copy.deepcopy(source.get(field)) for field in fields
                }
                groups.setdefault(str(source.get("windows_sid") or ""), []).append(
                    session
                )
            return groups

    def acknowledge_timeline_sessions(self, record_ids):
        with self._lock:
            self._activity_store.acknowledge_timeline(record_ids)

    def pending_usage_intervals(self):
        with self._lock:
            groups = {}
            for session in self._activity_store.pending_sessions(timeline=False):
                groups.setdefault(str(session.get("windows_sid") or ""), []).append({
                    "interval_id": str(session.get("interval_id") or ""),
                    "target_key": str(session.get("key") or ""),
                    "category_key": str(session.get("category") or ""),
                    "category_keys": list(session.get("category_lineage") or []),
                    "started_at": str(session.get("started_at") or ""),
                    "ended_at": str(session.get("ended_at") or ""),
                    "policy_revision": int(session.get("policy_revision") or 0),
                })
            return groups

    def acknowledge_usage_intervals(self, interval_ids):
        with self._lock:
            self._activity_store.acknowledge_usage(interval_ids)

    def pending_daily_aggregates(self):
        with self._lock:
            return self._activity_store.pending_daily_aggregates()

    def acknowledge_daily_aggregates(
        self, aggregate_ids, windows_sid="",
    ):
        with self._lock:
            self._activity_store.acknowledge_daily_aggregates(
                aggregate_ids, windows_sid,
            )

    def live_activity_intervals(self):
        with self._lock:
            if not self._protection_status_locked()["desktop_connected"]:
                return []
            return _clone(self._activity_live_intervals)

    def _protection_status_locked(self):
        desktop_connected = bool(self._desktop_seen_monotonic) and (
            time.monotonic() - self._desktop_seen_monotonic
            <= DESKTOP_STALE_SECONDS
        )
        runtime = dict((self._snapshot or {}).get("runtime") or {})
        protection = dict(runtime.get("protection") or {})
        extension = dict(protection.get("extension") or {})
        return {
            "service_connected": True,
            "desktop_connected": desktop_connected,
            "desktop_last_seen_at": self._desktop_updated_at,
            "extension_connected": (
                desktop_connected and bool(extension.get("connected"))
            ),
            "extension_last_seen_at": str(
                extension.get("last_seen_at") or ""
            ),
            "stale_after_seconds": 45,
        }

    def _queue_protection_transition_locked(self, status):
        healthy = bool(
            status.get("desktop_connected")
            and status.get("extension_connected")
        )
        previous = self._last_protection_healthy
        self._last_protection_healthy = healthy
        if previous is None or previous == healthy:
            return
        missing = [
            component for component, connected in (
                ("desktop", status.get("desktop_connected")),
                ("extension", status.get("extension_connected")),
            ) if not connected
        ]
        kind = "restored" if healthy else "interrupted"
        labels = {"desktop": "systray", "extension": "extension navigateur"}
        message = (
            "Le systray et l’extension communiquent de nouveau avec le service protégé."
            if healthy else
            "Signal de protection perdu : "
            + ", ".join(labels[item] for item in missing)
            + ". Un arrêt ou un contournement est possible."
        )
        event_id = secrets.token_hex(16)
        self._protection_events[event_id] = {
            "id": event_id, "kind": kind,
            "components": ["desktop", "extension"] if healthy else missing,
            "message": message,
            "occurred_at": datetime.now(timezone.utc).isoformat(
                timespec="seconds"
            ),
        }
        self._save_state()

    def protection_status(self):
        """Return current and durable pending protection observations."""
        with self._lock:
            status = self._protection_status_locked()
            self._queue_protection_transition_locked(status)
            return {
                **status,
                "events": [
                    _clone(event)
                    for event in self._protection_events.values()
                ],
            }

    def acknowledge_protection_events(self, event_ids):
        with self._lock:
            changed = False
            for event_id in event_ids or []:
                changed = self._protection_events.pop(str(event_id), None) is not None or changed
            if changed:
                self._save_state()

    def snapshot(self):
        with self._lock:
            if self._snapshot is None:
                return {"error": "desktop state unavailable"}
            snapshot = _clone(self._snapshot)
            runtime = dict(snapshot.get("runtime") or {})
            runtime["device"] = {
                "device_id": str(self.settings.get("device_id") or ""),
                "display_name": str(
                    getattr(self.client, "display_name", "")
                    or self.settings.get("display_name") or ""
                ),
            }
            snapshot["runtime"] = runtime
            return snapshot

    def activity(self):
        """Retired compatibility accessor; complete archives are never cached."""
        return None

    def accept_command(self, command):
        command_id = str(command.get("_remote_command_id") or "")
        if not command_id:
            return {"ok": False, "error": "missing remote command id"}
        with self._lock:
            completed = self._completed.get(command_id)
            if isinstance(completed, dict):
                return _clone(completed.get("result", {}))
            if command_id not in self._pending:
                if is_control_mutation(command):
                    self.registry.reserve(command)
                self._pending[command_id] = {
                    "command": _clone(command),
                    "received_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                }
                self._save_state()
        return {"ok": False, "_defer_ack": True}

    def authenticate_user(self, username, password, email=""):
        """Validate a local PWA login with the authoritative HTTPS backend."""
        try:
            user = self.client.authenticate_user(username, password, email)
        except (HTTPError, URLError) as error:
            raise RuntimeError(_backend_error_message(error)) from error
        management_session = user.pop("_backend_management_session", None)
        if (
            not user.get("must_change") and not user.get("must_set_email")
            and management_session
        ):
            token = secrets.token_urlsafe(48)
            with self._lock:
                now = time.time()
                self._admin_sessions = {
                    key: value for key, value in self._admin_sessions.items()
                    if float(value.get("expires_at", 0)) > now
                }
                self._admin_sessions[token] = {
                    "expires_at": now + 8 * 60 * 60,
                    "management_session": dict(management_session or {}),
                    "username": str(user.get("username") or ""),
                    "is_admin": bool(user.get("is_admin")),
                    "permissions": dict(user.get("permissions") or {}),
                }
            user = {**user, "_service_backend_token": token}
            if user.get("is_admin"):
                user["_service_admin_token"] = token
        return user

    def authenticate_windows_session(self, windows_sid):
        """Authenticate one non-admin local user from the protected SID map."""
        if self.installation_profile != "local":
            raise PermissionError(
                "La connexion par session Windows est réservée au profil local."
            )
        sid = str(windows_sid or "").strip().upper()
        if not sid.startswith("S-1-"):
            raise ValueError("SID Windows invalide.")
        server = self._local_server
        store = getattr(server, "store", None)
        if store is None:
            raise RuntimeError("Le backend local n’est pas disponible.")
        mapping = store.user_for_windows_sid(self.client.device_id, sid)
        if not mapping:
            raise PermissionError("Cette session Windows n’est pas associée.")
        username = str(mapping.get("usage_guard_username") or "")
        user = next((
            item for item in store.list_users()
            if str(item.get("username") or "").casefold()
            == username.casefold()
        ), None)
        if not user:
            raise PermissionError("Utilisateur Usage Guard associé introuvable.")
        if user.get("is_admin") or str(user.get("role") or "") == "admin":
            raise PermissionError(
                "Un administrateur doit saisir son mot de passe Usage Guard."
            )
        return {
            "username": username,
            "email": str(user.get("email") or ""),
            "is_admin": False,
            "role": str(user.get("role") or "limited"),
            "permissions": dict(user.get("permissions") or {}),
            "must_change": False,
            "must_set_email": False,
            "authentication": "windows_session",
        }

    def backend_admin(self, token, action, payload=None):
        """Run a backend-management operation after a verified admin login."""
        with self._lock:
            session = self._admin_sessions.get(str(token or ""), {})
            expires_at = float(session.get("expires_at", 0))
            if expires_at <= time.time():
                self._admin_sessions.pop(str(token or ""), None)
                raise PermissionError("Session administrateur expirée.")
            management_session = dict(session.get("management_session") or {})
        payload = dict(payload or {})
        user_actions = {
            "session_devices", "policy_users", "notification_overview",
            "notification_action", "analysis_overview", "policy_overview",
            "policy_usage", "policy_action", "cancel_policy_operation",
            "catalog_action", "device_action", "device_action_status",
            "cancel_device_action",
        }
        if session.get("is_admin") is False:
            if action not in user_actions:
                raise PermissionError("Droits administrateur requis.")
            permissions = dict(session.get("permissions") or {})
            required_permission = {
                "notification_overview": "view_notifications",
                "notification_action": "manage_notifications",
                "analysis_overview": {
                    "today": "view_activity", "session": "view_activity",
                    "catalog": "view_activity", "limits": "view_limits",
                }.get(str(payload.get("scope") or "today"), "view_analysis"),
                "policy_overview": "view_limits",
                "policy_usage": "view_analysis",
                "policy_action": "manage_limits",
                "cancel_policy_operation": "manage_limits",
                "catalog_action": "manage_activity",
                "device_action": (
                    "manage_limits"
                    if str(dict(payload.get("command") or {}).get("action") or "")
                    in {
                        "set_limit", "remove_limit", "reset_limit",
                        "set_computer_block", "set_computer_block_enabled",
                        "clear_computer_block",
                    }
                    else "manage_activity"
                ),
                "device_action_status": "view_limits",
                "cancel_device_action": "manage_limits",
            }.get(action)
            if required_permission and not permissions.get(required_permission):
                message = {
                    "manage_notifications": (
                        "Modification de notification non autorisée."
                    ),
                    "view_notifications": (
                        "Consultation des notifications non autorisée."
                    ),
                }.get(
                    required_permission, "Consultation de cette vue non autorisée."
                )
                raise PermissionError(message)
        try:
            if action == "session_devices":
                return self.client.session_devices(management_session)
            if action == "policy_users":
                return self.client.policy_users(management_session)
            if action == "notification_overview":
                return self.client.notification_overview(
                    payload.get("owner"), payload.get("device_id"),
                    management_session,
                )
            if action == "analysis_overview":
                return self.client.analysis_overview(
                    payload, management_session,
                )
            if action == "policy_overview":
                return self.client.policy_overview(
                    payload.get("username"), management_session,
                )
            if action == "policy_usage":
                return self.client.policy_usage(
                    payload.get("username"), payload, management_session,
                )
            if action == "policy_action":
                return self.client.policy_action(
                    payload.get("username"), payload.get("command"),
                    management_session,
                )
            if action == "cancel_policy_operation":
                return self.client.cancel_policy_operation(
                    payload.get("username"), payload.get("operation_id"),
                    management_session,
                )
            if action == "catalog_action":
                return self.client.catalog_action(
                    payload.get("username"), payload.get("command"),
                    management_session,
                )
            if action == "device_action":
                return self.client.device_action(
                    payload.get("command"), payload.get("device_id"),
                    management_session,
                )
            if action == "device_action_status":
                return self.client.device_action_status(
                    payload.get("command_id"), payload.get("device_id"),
                    management_session,
                )
            if action == "cancel_device_action":
                return self.client.cancel_device_action(
                    payload.get("command_id"), payload.get("device_id"),
                    management_session,
                )
            if action == "notification_action":
                command = dict(payload.get("command") or {})
                if command.get("action") not in {
                    "set_notification_rule", "remove_notification_rule",
                }:
                    raise PermissionError(
                        "Mutation de notification requise."
                    )
                return self.client.notification_action(
                    command, payload.get("device_id"),
                    management_session,
                )
            if action == "list_users":
                return self.client.list_users(management_session)
            if action == "create_user":
                arguments = (
                    payload.get("username"), payload.get("password"),
                    payload.get("email", ""),
                    payload.get("is_admin", False), payload.get("permissions", {}),
                )
                if any(key in payload for key in ("role", "device_ids")):
                    return self.client.create_user(
                        *arguments, payload.get("role"), payload.get("device_ids"),
                        management_session,
                    )
                return self.client.create_user(
                    *arguments, management_session=management_session
                )
            if action == "delete_user":
                return self.client.delete_user(
                    payload.get("username"), management_session
                )
            if action == "create_device_enrollment":
                return self.client.create_device_enrollment(
                    payload, management_session,
                )
            if action == "rename_managed_device":
                return self.client.rename_managed_device(
                    payload.get("device_id"), payload.get("label"),
                    management_session,
                )
            if action == "update_user_access":
                arguments = (
                    payload.get("username"), payload.get("is_admin", False),
                    payload.get("permissions", {}), payload.get("email"),
                )
                if any(key in payload for key in ("role", "device_ids")):
                    return self.client.update_user_access(
                        *arguments, payload.get("role"), payload.get("device_ids"),
                        management_session,
                    )
                return self.client.update_user_access(
                    *arguments, management_session=management_session
                )
            if action == "rename_device":
                return self.rename_device(payload.get("label"), management_session)
            if action == "commit_control":
                command = dict(payload.get("command") or {})
                result = dict(payload.get("result") or {})
                if command_source(command) != SOURCE_LOCAL_ADMIN:
                    raise PermissionError("Mutation administrateur locale requise.")
                missing_block_id = not str(command.get("block_id") or "")
                if command.get("action") in {
                    "set_computer_block", "set_computer_block_enabled",
                    "clear_computer_block",
                } and missing_block_id:
                    block = result.get("computer_block")
                    block_id = str(
                        (block or {}).get("block_id")
                        if isinstance(block, dict) else ""
                    )
                    if block_id:
                        command["block_id"] = block_id
                        if command.get("action") == "set_computer_block":
                            command["create_new"] = True
                policy_sync = self.queue_personal_policy_action(
                    command, session.get("username") or "administrateur local",
                )
                return {
                    **self.registry.commit(command, result),
                    "policy_sync": policy_sync,
                }
            if action == "traffic_stats":
                return self.client.traffic_stats()
            if action == "reset_traffic_stats":
                return self.client.reset_traffic_stats()
            if action == "email_settings":
                return self.client.email_settings(management_session)
            if action == "save_email_settings":
                return self.client.save_email_settings(payload, management_session)
            if action == "test_email_settings":
                return self.client.test_email_settings(
                    payload.get("recipient"), management_session
                )
            if action == "update_status":
                return self.update_manager.status()
            if action == "install_update":
                return self.update_manager.request_install()
            raise ValueError("Opération backend inconnue.")
        except (HTTPError, URLError) as error:
            raise RuntimeError(_backend_error_message(error)) from error

    def rename_device(self, label, management_session=None):
        result = self.client.rename_device(label, management_session)
        confirmed = str(
            dict(result.get("device") or {}).get("label")
            or getattr(self.client, "display_name", "")
            or label
            or ""
        ).strip()
        if confirmed:
            with self._lock:
                self.settings["display_name"] = confirmed
                self._save_settings()
        return result

    @staticmethod
    def _command_session_scope(command):
        command = dict(command or {})
        username = str(
            command.get("_usage_guard_target_username") or ""
        ).strip()
        raw_sids = command.get("_usage_guard_target_windows_sids")
        if not isinstance(raw_sids, list):
            raw_sids = []
        sids = {
            str(value or "").strip().upper()
            for value in raw_sids[:64]
            if str(value or "").strip().upper().startswith("S-1-")
        }
        return username, sids

    def _command_matches_windows_session(
        self, command, windows_sid="", usage_guard_username="",
    ):
        """Keep person-scoped commands inside their intended logon session."""
        target_username, target_sids = self._command_session_scope(command)
        if not target_username and not target_sids:
            return True
        sid = str(windows_sid or "").strip().upper()
        supplied_username = str(usage_guard_username or "").strip()
        if not sid.startswith("S-1-"):
            return False
        if target_sids and sid not in target_sids:
            return False
        mapping = next((
            item for item in self._windows_identities
            if str(item.get("windows_sid") or "").upper() == sid
        ), None)
        mapped_username = str(
            (mapping or {}).get("usage_guard_username") or ""
        ).strip()
        if target_username:
            if mapped_username:
                if mapped_username.casefold() != target_username.casefold():
                    return False
            elif not target_sids:
                # A username without a proven SID must never be handed to an
                # arbitrary interactive desktop.  It remains durable/pending
                # until the account mapping is refreshed.
                return False
            if (
                supplied_username
                and supplied_username.casefold() != target_username.casefold()
            ):
                return False
        return True

    def next_command(self, windows_sid="", usage_guard_username=""):
        with self._lock:
            if not self._pending:
                return None
            command_id = next((
                candidate for candidate in sorted(
                    self._pending, key=_command_order,
                )
                if self._command_matches_windows_session(
                    self._pending[candidate].get("command"),
                    windows_sid, usage_guard_username,
                )
            ), None)
            if command_id is None:
                return None
            return {
                "service_command_id": command_id,
                "command": _clone(self._pending[command_id]["command"]),
            }

    def complete_command(self, command_id, result):
        command_id = str(command_id or "")
        if not isinstance(result, dict):
            raise ValueError("invalid command result")
        with self._lock:
            pending = self._pending.get(command_id)
            if not isinstance(pending, dict):
                completed = self._completed.get(command_id)
                if isinstance(completed, dict):
                    return _clone(completed["result"])
                raise KeyError("unknown backend command")
            command = pending.get("command", {})
            clean_result = _clone(result)
            if clean_result.get("ok") and is_control_mutation(command):
                self.registry.commit(command, clean_result)
            self._completed[command_id] = {
                "result": clean_result,
                "completed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
            self._pending.pop(command_id, None)
            ordered = sorted(
                self._completed, key=_command_order,
            )
            for old_id in ordered[:-200]:
                self._completed.pop(old_id, None)
            self._save_state()
            return clean_result

    def status(self):
        with self._lock:
            return {
                "installation_profile": self.installation_profile,
                "enabled": self.client.enabled,
                "configured": self.client.configured,
                "started": self.started,
                "desktop_connected": self._snapshot is not None,
                "desktop_updated_at": self._desktop_updated_at,
                "pending_commands": len(self._pending),
                "completed_commands": len(self._completed),
                "windows_identity_count": len(self._windows_identities),
                "personal_policy_count": len(self._personal_policies),
                "pending_policy_acknowledgements": sum(
                    1 for entry in self._personal_policies.values()
                    if entry.get("ack_pending")
                ),
                "pending_personal_policy_uploads": len(
                    self._personal_policy_outbox
                ),
                "traffic": self.client.traffic_stats(),
                "protection": self.protection_status(),
                "update": self.update_manager.status(),
            }
