"""Incremental local activity storage and bounded daily-summary export.

The desktop still exposes the historical in-memory shape to the rest of the
application, but the growing portions are persisted row-by-row in SQLite.
``activity.json`` can therefore remain a small configuration document.  The
daily export deliberately contains totals only: no session, timestamp or raw
history record is accepted by this module's export boundary.
"""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path


SCHEMA_VERSION = 1
DAILY_EXPORT_OWNER_SCOPE_VERSION = 2
DAILY_EXPORT_FORMAT_VERSION = 2
DAILY_EXPORT_MAX_DAYS = 31
DAILY_EXPORT_MAX_METRICS = 500
DAILY_EXPORT_MAX_BYTES = 512 * 1024

DICT_SECTIONS = (
    "days", "passive_days", "other_site_days", "system_days",
    "app_limit_days", "app_limit_rolling", "open_sessions",
)
LIST_SECTIONS = ("sessions", "windows_sessions", "system_events")
ACTIVITY_SECTIONS = DICT_SECTIONS + LIST_SECTIONS


def _encoded(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    )


def _digest(value):
    return hashlib.sha256(_encoded(value).encode("utf-8")).hexdigest()


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class LocalActivitySqlite:
    """Durable SQLite owner for the growing fields of ``AppUsageStore``."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA auto_vacuum=INCREMENTAL")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS activity_items (
                    section TEXT NOT NULL,
                    item_key TEXT NOT NULL,
                    position INTEGER NOT NULL DEFAULT 0,
                    payload TEXT NOT NULL,
                    PRIMARY KEY(section, item_key)
                );
                CREATE INDEX IF NOT EXISTS activity_items_order
                    ON activity_items(section, position, item_key);
                CREATE TABLE IF NOT EXISTS activity_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS activity_configuration (
                    field TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS daily_aggregate_export (
                    local_day TEXT PRIMARY KEY,
                    aggregate_id TEXT NOT NULL UNIQUE,
                    payload TEXT NOT NULL,
                    bridge_acked INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS daily_aggregate_pending
                    ON daily_aggregate_export(bridge_acked, local_day);
                """
            )
            owner_scope = db.execute(
                "SELECT value FROM activity_meta "
                "WHERE key='daily_export_owner_scope_version'"
            ).fetchone()
            if not owner_scope or str(owner_scope["value"]) != str(
                DAILY_EXPORT_OWNER_SCOPE_VERSION
            ):
                # Builds before owner-scoped ACKs could mark a second Windows
                # user's identical digest as delivered when only the first
                # user's row reached the backend.  Replay compact summaries
                # once after the upgrade; server ingestion is idempotent and
                # no raw session/archive crosses this boundary.
                db.execute(
                    "UPDATE daily_aggregate_export SET bridge_acked=0"
                )
                db.execute(
                    "INSERT OR REPLACE INTO activity_meta(key,value) "
                    "VALUES(?,?)",
                    (
                        "daily_export_owner_scope_version",
                        str(DAILY_EXPORT_OWNER_SCOPE_VERSION),
                    ),
                )
            export_format = db.execute(
                "SELECT value FROM activity_meta "
                "WHERE key='daily_export_format_version'"
            ).fetchone()
            if not export_format or str(export_format["value"]) != str(
                DAILY_EXPORT_FORMAT_VERSION
            ):
                document = self._configuration_from_rows(db.execute(
                    "SELECT field,payload FROM activity_configuration "
                    "ORDER BY field"
                ).fetchall())
                document.update(self._sections_from_rows(db.execute(
                    "SELECT section,item_key,position,payload "
                    "FROM activity_items ORDER BY section,position,item_key"
                ).fetchall()))
                self._sync_daily_aggregates(db, document)
                db.execute(
                    "INSERT OR REPLACE INTO activity_meta(key,value) "
                    "VALUES(?,?)",
                    (
                        "daily_export_format_version",
                        str(DAILY_EXPORT_FORMAT_VERSION),
                    ),
                )

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        try:
            db.execute("PRAGMA busy_timeout=15000")
            db.execute("PRAGMA synchronous=FULL")
            db.row_factory = sqlite3.Row
            with db:
                yield db
        finally:
            db.close()

    def initialized(self):
        with self._connect() as db:
            row = db.execute(
                "SELECT value FROM activity_meta WHERE key='validated_schema'"
            ).fetchone()
        return bool(row and str(row["value"]) == str(SCHEMA_VERSION))

    @staticmethod
    def contains_history(data):
        return any(bool(dict(data or {}).get(section)) for section in ACTIVITY_SECTIONS)

    @staticmethod
    def empty_sections():
        return {
            **{section: {} for section in DICT_SECTIONS},
            **{section: [] for section in LIST_SECTIONS},
        }

    @staticmethod
    def _list_identity(section, value):
        source = value if isinstance(value, dict) else {}
        if section == "sessions":
            identity = [
                source.get("kind"), source.get("id"), source.get("key"),
                source.get("started_at"), source.get("windows_sid"),
                source.get("windows_session_id"),
            ]
        elif section == "windows_sessions":
            identity = [
                source.get("started_at"), source.get("windows_sid"),
                source.get("windows_session_id"),
            ]
        else:
            identity = [
                source.get("type"), source.get("at"), source.get("reason"),
            ]
        if not any(item not in (None, "") for item in identity):
            identity = value
        return _digest(identity)

    @classmethod
    def _section_rows(cls, section, value):
        if section == "other_site_days":
            rows = []
            position = 0
            for browser, days in dict(value or {}).items():
                for day, hosts in dict(days or {}).items():
                    rows.append((
                        _encoded([str(browser), str(day)]), position,
                        _encoded(hosts if isinstance(hosts, dict) else {}),
                    ))
                    position += 1
            return rows
        if section in DICT_SECTIONS:
            return [
                (str(key), position, _encoded(item))
                for position, (key, item) in enumerate(dict(value or {}).items())
            ]
        occurrences = {}
        rows = []
        for position, item in enumerate(list(value or [])):
            base = cls._list_identity(section, item)
            occurrence = occurrences.get(base, 0)
            occurrences[base] = occurrence + 1
            rows.append((f"{base}:{occurrence}", position, _encoded(item)))
        return rows

    @classmethod
    def _sections_from_rows(cls, rows):
        result = cls.empty_sections()
        for row in rows:
            section = str(row["section"])
            if section not in ACTIVITY_SECTIONS:
                continue
            try:
                value = json.loads(row["payload"])
            except (TypeError, ValueError):
                raise RuntimeError("Base d’activité SQLite endommagée.")
            if section == "other_site_days":
                try:
                    browser, day = json.loads(row["item_key"])
                except (TypeError, ValueError):
                    raise RuntimeError("Base d’activité SQLite endommagée.")
                result[section].setdefault(str(browser), {})[str(day)] = value
            elif section in DICT_SECTIONS:
                result[section][str(row["item_key"])] = value
            else:
                result[section].append(value)
        return result

    @classmethod
    def activity_digest(cls, data):
        canonical = cls.empty_sections()
        source = dict(data or {})
        for section in ACTIVITY_SECTIONS:
            value = source.get(section, canonical[section])
            canonical[section] = value
        return _digest(canonical)

    @classmethod
    def document_digest(cls, data):
        return _digest(dict(data or {}))

    @staticmethod
    def _configuration_from_rows(rows):
        result = {}
        for row in rows:
            try:
                result[str(row["field"])] = json.loads(row["payload"])
            except (TypeError, ValueError):
                raise RuntimeError("Configuration SQLite endommagée.")
        return result

    def load_document(self, *, validate=True):
        """Load the complete logical document from the authoritative DB."""
        with self._connect() as db:
            if validate:
                check = db.execute("PRAGMA quick_check").fetchone()
                if not check or str(check[0]).lower() != "ok":
                    raise RuntimeError("Base d’activité SQLite endommagée.")
            document = self._configuration_from_rows(db.execute(
                "SELECT field,payload FROM activity_configuration ORDER BY field"
            ).fetchall())
            document.update(self._sections_from_rows(db.execute(
                "SELECT section,item_key,position,payload FROM activity_items "
                "ORDER BY section,position,item_key"
            ).fetchall()))
            if validate:
                expected = db.execute(
                    "SELECT value FROM activity_meta WHERE key='document_digest'"
                ).fetchone()
                if expected and str(expected["value"]) != self.document_digest(document):
                    raise RuntimeError("Validation de la base d’activité SQLite impossible.")
        return document

    def load_sections(self, *, validate=True):
        with self._connect() as db:
            if validate:
                check = db.execute("PRAGMA quick_check").fetchone()
                if not check or str(check[0]).lower() != "ok":
                    raise RuntimeError("Base d’activité SQLite endommagée.")
            rows = db.execute(
                "SELECT section,item_key,position,payload FROM activity_items "
                "ORDER BY section,position,item_key"
            ).fetchall()
            result = self._sections_from_rows(rows)
            if validate:
                expected = db.execute(
                    "SELECT value FROM activity_meta WHERE key='activity_digest'"
                ).fetchone()
                if expected and str(expected["value"]) != self.activity_digest(result):
                    raise RuntimeError("Validation de la base d’activité SQLite impossible.")
        return result

    def import_legacy(self, data):
        """Import once, validate by re-reading, then mark the DB authoritative."""
        if self.initialized():
            return False
        expected = self.document_digest(data)
        with self._connect() as db:
            self._replace_sections(db, data)
            self._replace_configuration(db, data)
            actual_document = self._configuration_from_rows(db.execute(
                "SELECT field,payload FROM activity_configuration ORDER BY field"
            ).fetchall())
            actual_document.update(self._sections_from_rows(db.execute(
                "SELECT section,item_key,position,payload FROM activity_items "
                "ORDER BY section,position,item_key"
            ).fetchall()))
            actual = self.document_digest(actual_document)
            if actual != expected:
                raise RuntimeError("Validation de la migration SQLite impossible.")
            db.execute(
                "INSERT OR REPLACE INTO activity_meta(key,value) VALUES(?,?)",
                ("activity_digest", self.activity_digest(actual_document)),
            )
            db.execute(
                "INSERT OR REPLACE INTO activity_meta(key,value) VALUES(?,?)",
                ("document_digest", actual),
            )
            db.execute(
                "INSERT OR REPLACE INTO activity_meta(key,value) VALUES(?,?)",
                ("validated_schema", str(SCHEMA_VERSION)),
            )
            db.execute(
                "INSERT OR REPLACE INTO activity_meta(key,value) VALUES(?,?)",
                ("validated_at", _utc_now()),
            )
            self._sync_daily_aggregates(db, data)
        # Validate the committed transaction through a fresh connection.
        if self.document_digest(self.load_document()) != expected:
            raise RuntimeError("Validation de la migration SQLite impossible.")
        return True

    def _replace_configuration(self, db, data):
        source = dict(data or {})
        desired = {
            str(field): _encoded(value)
            for field, value in source.items()
            if field not in ACTIVITY_SECTIONS
        }
        existing = {
            str(row["field"]): str(row["payload"])
            for row in db.execute(
                "SELECT field,payload FROM activity_configuration"
            ).fetchall()
        }
        changed = [
            (field, payload) for field, payload in desired.items()
            if existing.get(field) != payload
        ]
        if changed:
            db.executemany(
                "INSERT INTO activity_configuration(field,payload) VALUES(?,?) "
                "ON CONFLICT(field) DO UPDATE SET payload=excluded.payload",
                changed,
            )
        removed = set(existing).difference(desired)
        if removed:
            db.executemany(
                "DELETE FROM activity_configuration WHERE field=?",
                ((field,) for field in removed),
            )

    def _replace_sections(self, db, data):
        source = dict(data or {})
        for section in ACTIVITY_SECTIONS:
            desired = {
                key: (position, payload)
                for key, position, payload in self._section_rows(
                    section, source.get(section),
                )
            }
            existing = {
                str(row["item_key"]): (int(row["position"]), str(row["payload"]))
                for row in db.execute(
                    "SELECT item_key,position,payload FROM activity_items "
                    "WHERE section=?", (section,),
                ).fetchall()
            }
            changed = [
                (section, key, position, payload)
                for key, (position, payload) in desired.items()
                if existing.get(key) != (position, payload)
            ]
            if changed:
                db.executemany(
                    "INSERT INTO activity_items(section,item_key,position,payload) "
                    "VALUES(?,?,?,?) ON CONFLICT(section,item_key) DO UPDATE SET "
                    "position=excluded.position,payload=excluded.payload",
                    changed,
                )
            removed = set(existing).difference(desired)
            if removed:
                db.executemany(
                    "DELETE FROM activity_items WHERE section=? AND item_key=?",
                    ((section, key) for key in removed),
                )

    def _replace_selected_sections(self, db, data, sections):
        source = dict(data or {})
        for section in sections:
            if section not in ACTIVITY_SECTIONS:
                raise ValueError("Section d’activité SQLite inconnue.")
            desired = {
                key: (position, payload)
                for key, position, payload in self._section_rows(
                    section, source.get(section),
                )
            }
            existing = {
                str(row["item_key"]): (int(row["position"]), str(row["payload"]))
                for row in db.execute(
                    "SELECT item_key,position,payload FROM activity_items "
                    "WHERE section=?", (section,),
                ).fetchall()
            }
            changed = [
                (section, key, position, payload)
                for key, (position, payload) in desired.items()
                if existing.get(key) != (position, payload)
            ]
            if changed:
                db.executemany(
                    "INSERT INTO activity_items(section,item_key,position,payload) "
                    "VALUES(?,?,?,?) ON CONFLICT(section,item_key) DO UPDATE SET "
                    "position=excluded.position,payload=excluded.payload",
                    changed,
                )
            removed = set(existing).difference(desired)
            if removed:
                db.executemany(
                    "DELETE FROM activity_items WHERE section=? AND item_key=?",
                    ((section, key) for key in removed),
                )

    @classmethod
    def list_record_row(cls, section, item, position):
        if section not in LIST_SECTIONS:
            raise ValueError("Section de liste SQLite inconnue.")
        base = cls._list_identity(section, item)
        # Runtime records have stable identities and are de-duplicated before
        # insertion.  The occurrence suffix remains compatible with the full
        # migration representation for the normal (unique) case.
        return f"{base}:0", int(position), _encoded(item)

    @staticmethod
    def _safe_seconds(value):
        try:
            seconds = float(value or 0)
        except (TypeError, ValueError):
            return None
        if not math.isfinite(seconds) or seconds < 0:
            return None
        return round(seconds, 3)

    @classmethod
    def _daily_metrics_for_day(cls, source, day):
        metrics = []
        for kind, values in (
            ("usage", dict(source.get("days") or {}).get(day, {})),
            ("passive", dict(source.get("passive_days") or {}).get(day, {})),
            ("system", dict(source.get("system_days") or {}).get(day, {})),
        ):
            for key, raw_seconds in dict(values or {}).items():
                seconds = cls._safe_seconds(raw_seconds)
                if seconds is None or seconds <= 0:
                    continue
                metrics.append({
                    "kind": kind, "key": str(key), "seconds": seconds,
                })
        for browser, browser_days in dict(
            source.get("other_site_days") or {}
        ).items():
            hosts = dict(dict(browser_days or {}).get(day, {}) or {})
            for host, raw_seconds in hosts.items():
                seconds = cls._safe_seconds(raw_seconds)
                if seconds is None or seconds <= 0:
                    continue
                metrics.append({
                    "kind": "other_site",
                    "key": f"site:{str(browser).lower()}:{str(host).lower()}",
                    "seconds": seconds,
                })
        return sorted(metrics, key=lambda item: (item["kind"], item["key"]))

    @classmethod
    def _daily_documents(cls, data):
        source = dict(data or {})
        days = set(dict(source.get("days") or {}))
        days.update(dict(source.get("passive_days") or {}))
        days.update(dict(source.get("system_days") or {}))
        for browser_days in dict(source.get("other_site_days") or {}).values():
            days.update(dict(browser_days or {}))
        result = {}
        today = date.today().isoformat()
        for day in sorted(day for day in days if str(day) < today):
            metrics = cls._daily_metrics_for_day(source, day)
            canonical = {
                "schema_version": SCHEMA_VERSION,
                "local_day": str(day), "metrics": metrics,
            }
            result[str(day)] = {
                "aggregate_id": "daily-v1-" + _digest(canonical),
                "local_day": str(day), "metrics": metrics,
            }
        return result

    def _sync_daily_aggregates(self, db, data):
        desired = self._daily_documents(data)
        existing = {
            str(row["local_day"]): str(row["payload"])
            for row in db.execute(
                "SELECT local_day,payload FROM daily_aggregate_export"
            ).fetchall()
        }
        # Retain an empty tombstone for a removed day so the remote summary is
        # corrected instead of silently keeping a stale earlier aggregate.
        today = date.today().isoformat()
        for day in (
            day for day in set(existing).difference(desired) if day < today
        ):
            canonical = {
                "schema_version": SCHEMA_VERSION,
                "local_day": day, "metrics": [],
            }
            desired[day] = {
                "aggregate_id": "daily-v1-" + _digest(canonical),
                "local_day": day, "metrics": [],
            }
        for day, aggregate in desired.items():
            payload = _encoded(aggregate)
            if existing.get(day) == payload:
                continue
            db.execute(
                "INSERT INTO daily_aggregate_export(local_day,aggregate_id,"
                "payload,bridge_acked,updated_at) VALUES(?,?,?,?,?) "
                "ON CONFLICT(local_day) DO UPDATE SET "
                "aggregate_id=excluded.aggregate_id,payload=excluded.payload,"
                "bridge_acked=0,updated_at=excluded.updated_at",
                (day, aggregate["aggregate_id"], payload, 0, _utc_now()),
            )

    @classmethod
    def _daily_document_for_day(cls, data, day):
        source = dict(data or {})
        metrics = cls._daily_metrics_for_day(source, day)
        canonical = {
            "schema_version": SCHEMA_VERSION,
            "local_day": str(day), "metrics": metrics,
        }
        return {
            "aggregate_id": "daily-v1-" + _digest(canonical),
            "local_day": str(day), "metrics": metrics,
        }

    def _sync_daily_days(self, db, data, days):
        today = date.today().isoformat()
        for day in sorted(set(
            str(value) for value in days
            if str(value) and str(value) < today
        )):
            aggregate = self._daily_document_for_day(data, day)
            payload = _encoded(aggregate)
            existing = db.execute(
                "SELECT payload FROM daily_aggregate_export WHERE local_day=?",
                (day,),
            ).fetchone()
            if existing and str(existing["payload"]) == payload:
                continue
            db.execute(
                "INSERT INTO daily_aggregate_export(local_day,aggregate_id,"
                "payload,bridge_acked,updated_at) VALUES(?,?,?,?,?) "
                "ON CONFLICT(local_day) DO UPDATE SET "
                "aggregate_id=excluded.aggregate_id,payload=excluded.payload,"
                "bridge_acked=0,updated_at=excluded.updated_at",
                (day, aggregate["aggregate_id"], payload, 0, _utc_now()),
            )

    def sync(self, data):
        """Incrementally reconcile changed rows in one durable transaction."""
        expected = self.document_digest(data)
        with self._connect() as db:
            initialized = db.execute(
                "SELECT value FROM activity_meta WHERE key='validated_schema'"
            ).fetchone()
            if not initialized or str(initialized["value"]) != str(SCHEMA_VERSION):
                raise RuntimeError("La base d’activité SQLite n’est pas initialisée.")
            self._replace_sections(db, data)
            self._replace_configuration(db, data)
            actual_document = self._configuration_from_rows(db.execute(
                "SELECT field,payload FROM activity_configuration ORDER BY field"
            ).fetchall())
            actual_document.update(self._sections_from_rows(db.execute(
                "SELECT section,item_key,position,payload FROM activity_items "
                "ORDER BY section,position,item_key"
            ).fetchall()))
            actual = self.document_digest(actual_document)
            if actual != expected:
                raise RuntimeError("Validation de l’écriture SQLite impossible.")
            db.execute(
                "INSERT OR REPLACE INTO activity_meta(key,value) VALUES(?,?)",
                ("document_digest", actual),
            )
            db.execute(
                "INSERT OR REPLACE INTO activity_meta(key,value) VALUES(?,?)",
                ("activity_digest", self.activity_digest(actual_document)),
            )
            self._sync_daily_aggregates(db, data)

    def sync_changes(
        self, data, configuration, *, full_sections=(), dict_keys=None,
        other_site_keys=None, list_records=None, daily_days=(),
        refresh_all_daily=False,
    ):
        """Persist only explicitly changed rows after the initial migration.

        This path intentionally performs no whole-document deepcopy, digest or
        re-read.  A one-day counter update therefore remains O(the changed
        day), even if the immutable migration source and SQLite history later
        reach hundreds of megabytes.
        """
        dict_keys = {
            str(section): set(keys or ())
            for section, keys in dict(dict_keys or {}).items()
        }
        other_site_keys = set(other_site_keys or ())
        list_records = {
            str(section): list(records or ())
            for section, records in dict(list_records or {}).items()
        }
        with self._connect() as db:
            initialized = db.execute(
                "SELECT value FROM activity_meta WHERE key='validated_schema'"
            ).fetchone()
            if not initialized or str(initialized["value"]) != str(SCHEMA_VERSION):
                raise RuntimeError("La base d’activité SQLite n’est pas initialisée.")
            self._replace_configuration(db, dict(configuration or {}))
            self._replace_selected_sections(db, data, set(full_sections or ()))
            source = dict(data or {})
            for section, keys in dict_keys.items():
                if section not in DICT_SECTIONS or section == "other_site_days":
                    raise ValueError("Section d’activité SQLite inconnue.")
                values = dict(source.get(section) or {})
                for key in keys:
                    key = str(key)
                    if key in values:
                        db.execute(
                            "INSERT INTO activity_items(section,item_key,position,payload) "
                            "VALUES(?,?,?,?) ON CONFLICT(section,item_key) DO UPDATE SET "
                            "payload=excluded.payload",
                            (section, key, 0, _encoded(values[key])),
                        )
                    else:
                        db.execute(
                            "DELETE FROM activity_items WHERE section=? AND item_key=?",
                            (section, key),
                        )
            other = dict(source.get("other_site_days") or {})
            for browser, day in other_site_keys:
                browser, day = str(browser), str(day)
                hosts = dict(other.get(browser) or {}).get(day)
                item_key = _encoded([browser, day])
                if hosts is None:
                    db.execute(
                        "DELETE FROM activity_items WHERE section=? AND item_key=?",
                        ("other_site_days", item_key),
                    )
                else:
                    db.execute(
                        "INSERT INTO activity_items(section,item_key,position,payload) "
                        "VALUES(?,?,?,?) ON CONFLICT(section,item_key) DO UPDATE SET "
                        "payload=excluded.payload",
                        ("other_site_days", item_key, 0, _encoded(hosts)),
                    )
            for section, records in list_records.items():
                if section not in LIST_SECTIONS:
                    raise ValueError("Section de liste SQLite inconnue.")
                for item, position in records:
                    key, position, payload = self.list_record_row(
                        section, item, position,
                    )
                    db.execute(
                        "INSERT INTO activity_items(section,item_key,position,payload) "
                        "VALUES(?,?,?,?) ON CONFLICT(section,item_key) DO UPDATE SET "
                        "position=excluded.position,payload=excluded.payload",
                        (section, key, position, payload),
                    )
            previous_day = (date.today() - timedelta(days=1)).isoformat()
            closed_days = set(daily_days or ())
            if any(
                previous_day in (source.get(section) or {})
                for section in ("days", "passive_days", "system_days")
            ):
                closed_days.add(previous_day)
            if refresh_all_daily:
                self._sync_daily_aggregates(db, source)
            else:
                self._sync_daily_days(db, source, closed_days)
            # Builds predating the closed-day rule may have queued a partial
            # current day. Never upload it: exact live/interval paths own it.
            db.execute(
                "DELETE FROM daily_aggregate_export WHERE local_day>=?",
                (date.today().isoformat(),),
            )
            # The initial checksum proves migration completeness.  Subsequent
            # row transactions are protected by SQLite/WAL and invalidate that
            # whole-document checksum rather than recomputing O(history).
            db.execute(
                "DELETE FROM activity_meta WHERE key IN "
                "('document_digest','activity_digest')"
            )

    def pending_daily_aggregates(
        self, max_days=DAILY_EXPORT_MAX_DAYS,
        max_metrics=DAILY_EXPORT_MAX_METRICS,
        max_bytes=DAILY_EXPORT_MAX_BYTES,
    ):
        """Return one bounded pending page without any raw history fields."""
        max_days = max(1, min(DAILY_EXPORT_MAX_DAYS, int(max_days)))
        max_metrics = max(1, min(DAILY_EXPORT_MAX_METRICS, int(max_metrics)))
        max_bytes = max(1024, min(DAILY_EXPORT_MAX_BYTES, int(max_bytes)))
        with self._connect() as db:
            rows = db.execute(
                "SELECT payload FROM daily_aggregate_export "
                "WHERE bridge_acked=0 ORDER BY local_day LIMIT ?",
                (max_days,),
            ).fetchall()
        aggregates, metric_count, used = [], 0, 2
        for row in rows:
            aggregate = json.loads(row["payload"])
            metrics = list(aggregate.get("metrics") or [])
            size = len(str(row["payload"]).encode("utf-8")) + (
                1 if aggregates else 0
            )
            if len(metrics) > max_metrics or size + 2 > max_bytes:
                if not aggregates:
                    raise ValueError("Agrégat journalier trop volumineux.")
                break
            if (
                aggregates
                and (metric_count + len(metrics) > max_metrics or used + size > max_bytes)
            ):
                break
            aggregates.append(aggregate)
            metric_count += len(metrics)
            used += size
        return aggregates

    def acknowledge_daily_aggregates(self, aggregate_ids):
        """ACK only the still-current content; newer same-day totals stay pending."""
        values = list(dict.fromkeys(
            str(value) for value in aggregate_ids or [] if str(value)
        ))
        if not values:
            return 0
        with self._connect() as db:
            before = db.total_changes
            db.executemany(
                "UPDATE daily_aggregate_export SET bridge_acked=1 "
                "WHERE aggregate_id=?", ((value,) for value in values),
            )
            return db.total_changes - before

    def pending_daily_count(self):
        with self._connect() as db:
            return int(db.execute(
                "SELECT COUNT(*) FROM daily_aggregate_export "
                "WHERE bridge_acked=0"
            ).fetchone()[0])
