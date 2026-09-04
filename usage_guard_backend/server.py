"""Usage Guard remote backend: stdlib-only, loopback-only and session-authenticated."""
import base64
import binascii
import copy
import hashlib
import hmac
import ipaddress
import json
import math
import mimetypes
import os
import re
import secrets
import smtplib
import ssl
import sqlite3
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import parseaddr
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


ROOT = Path(__file__).resolve().parent
PWA_DIR = ROOT / "pwa"
HOST = os.environ.get("USAGE_GUARD_BACKEND_HOST", "127.0.0.1")
PORT = int(os.environ.get("USAGE_GUARD_BACKEND_PORT", "8767"))
PREFIX = "/" + os.environ.get("USAGE_GUARD_BACKEND_PREFIX", "usage-guard").strip("/")
DB_PATH = Path(os.environ.get("USAGE_GUARD_BACKEND_DB", ROOT / "data" / "backend.sqlite3"))
CLIENT_RELEASE_DIR = Path(os.environ.get(
    "USAGE_GUARD_CLIENT_RELEASE_DIR", DB_PATH.parent / "client_updates"
))
DEVICE_ID = os.environ.get("USAGE_GUARD_DEVICE_ID", "").strip()
DEVICE_TOKEN = os.environ.get("USAGE_GUARD_DEVICE_TOKEN", "").strip()
PUBLIC_ORIGIN = os.environ.get("USAGE_GUARD_PUBLIC_ORIGIN", "").rstrip("/")
MAX_BODY = 8 * 1024 * 1024
MAX_INCREMENTAL_ACTIVITY_BYTES = 512 * 1024
SESSION_SECONDS = 12 * 60 * 60
ENROLLMENT_SECONDS = 30 * 60
PASSWORD_MIN_LENGTH = 10
COMMAND_RETRY_SECONDS = 90
ACKED_LIMIT_RETRY_SECONDS = 10 * 60
PENDING_LIMIT_VISIBLE_SECONDS = 10 * 60
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$")
IDEMPOTENCY_KEY_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
ALLOWED_ACTIONS = {
    "rename_target", "add_catalog_item", "set_category", "make_root", "exclude_target",
    "unexclude_target", "dismiss_target", "delete_target", "merge_target",
    "rename_category",
    "move_category", "reorder_category", "reorder_target", "reorder_navigation", "reorder_unclassified", "clear_category", "make_category_root",
    "set_category_for_keys", "rename_browser", "make_browser_root",
    "clear_browser_category", "clear_site_category", "rename_site_category",
    "reorder_site_category",
    "exclude_passive", "make_site_specific", "categorize_site", "exclude_site",
    "delete_site", "set_limit", "remove_limit", "reset_limit", "set_language",
    "set_notification_rule", "remove_notification_rule", "set_notification_warning",
    "set_default_limit_warning",
    "set_computer_block", "set_computer_block_enabled", "clear_computer_block",
}
CATALOG_ACTIONS = {"replace_catalog"} | (ALLOWED_ACTIONS - {
    "set_limit", "remove_limit", "reset_limit", "set_language",
    "set_notification_rule", "remove_notification_rule",
    "set_notification_warning", "set_default_limit_warning",
    "set_computer_block", "set_computer_block_enabled", "clear_computer_block",
})
CATALOG_INCREMENTAL_ACTIONS = CATALOG_ACTIONS - {
    "replace_catalog", "delete_site",
}
CATALOG_DOCUMENT_FIELDS = (
    "targets", "excluded", "excluded_sites", "browser_categories",
    "category_parents", "category_order", "target_order",
    "navigation_position", "unclassified_position", "browser_labels",
    "browser_specific_sites", "site_categories",
    "site_category_order_manual", "passive_excluded", "merged_targets",
    "dismissed_targets",
)
CATALOG_DOCUMENT_LIST_FIELDS = {
    "excluded", "excluded_sites", "category_order", "target_order",
    "site_categories", "passive_excluded",
}
CATALOG_DOCUMENT_DICT_FIELDS = set(CATALOG_DOCUMENT_FIELDS) - (
    CATALOG_DOCUMENT_LIST_FIELDS | {"site_category_order_manual"}
)
TIMELINE_SESSION_KINDS = {
    "active", "program", "web", "multimedia",
    "windows_session", "system_event",
}
PERMISSION_KEYS = (
    "view_activity", "view_analysis", "view_limits", "view_notifications",
    "manage_activity", "manage_limits", "manage_other_limits",
    "manage_notifications",
)
DEFAULT_PERMISSIONS = {
    "view_activity": True, "view_analysis": True, "view_limits": True,
    "view_notifications": True,
    "manage_activity": False, "manage_limits": False,
    "manage_other_limits": False, "manage_notifications": False,
}
PERMISSION_LABELS = {
    "view_activity": "voir les activités du jour",
    "view_analysis": "voir l’analyse et l’historique",
    "view_limits": "voir les limitations",
    "view_notifications": "voir les notifications",
    "manage_activity": "modifier et classer les activités",
    "manage_limits": "créer et modifier les limitations",
    "manage_other_limits": (
        "modifier ou désactiver les limitations demandées par d’autres"
    ),
    "manage_notifications": "créer et modifier les notifications",
}
ROLE_LABELS = {
    "limited": "Utilisateur à limiter",
    "user": "Utilisateur",
    "admin": "Administrateur",
}
USER_ROLES = {"limited", "user", "admin"}
MANAGE_PERMISSION_KEYS = {
    "manage_activity", "manage_limits", "manage_other_limits",
    "manage_notifications",
}
LIMIT_ACTIONS = {
    "set_limit", "remove_limit", "reset_limit", "set_computer_block",
    "set_computer_block_enabled", "clear_computer_block",
    "replace_computer_blocks",
}
POLICY_LIMIT_FIELDS = (
    "name", "enabled", "enforcement_action", "target_key",
    "block_during_validity", "delete_after_expiry", "limit_seconds",
    "extension_seconds", "extension_unit", "warning_seconds",
    "blocked_after", "schedule_date", "valid_from", "valid_from_time",
    "valid_until", "valid_until_time", "schedule_start", "schedule_end",
    "actor", "updated_at", "requested_by", "requested_at",
)
REFLECTED_RETRY_ACTIONS = {
    "set_limit", "remove_limit", "set_computer_block",
    "set_computer_block_enabled", "clear_computer_block",
    "replace_computer_blocks",
}
NOTIFICATION_ACTIONS = {
    "set_notification_rule", "remove_notification_rule", "set_notification_warning",
    "set_default_limit_warning",
}


def target_display_label(target_key, label=""):
    """Return a human label when normalized rows only contain a target key."""
    key = str(target_key or "").strip()
    saved = str(label or "").strip()
    if key.startswith("site:"):
        parts = key.split(":", 2)
        host = parts[2] if len(parts) == 3 else ""
        if not saved or saved == key or saved.startswith("site:"):
            return "Autres sites" if host == "other-sites" else host or saved or key
    if key.startswith("app:") and (not saved or saved == key):
        return key[4:] or saved or key
    return saved or key


def is_other_sites_usage_key(target_key):
    """Return whether a key is the accounting-only browser-site aggregate."""
    parts = str(target_key or "").strip().split(":")
    return (
        len(parts) == 3
        and parts[0] == "site"
        and bool(parts[1])
        and parts[2] == "other-sites"
    )


OTHER_SITES_USAGE_SQL = (
    "trim(target_key) GLOB 'site:?*:other-sites' AND "
    "length(trim(target_key))-length(replace(trim(target_key),':',''))=2"
)


def snapshot_without_other_sites_timeline(snapshot):
    """Remove accounting-only sentinels from timeline-bearing snapshot fields.

    Daily usage, per-host ``other_sites`` detail and the current target are left
    intact.  Only session records are removed: the aggregate key measures quota
    consumption but does not identify a site that can be drawn on a timeline.
    """
    result = copy.deepcopy(snapshot) if isinstance(snapshot, dict) else {}

    def clean(document):
        if not isinstance(document, dict):
            return
        sessions = document.get("sessions")
        if isinstance(sessions, list):
            document["sessions"] = [
                item for item in sessions
                if not isinstance(item, dict)
                or not is_other_sites_usage_key(item.get("key"))
            ]
        open_sessions = document.get("open_sessions")
        if isinstance(open_sessions, dict):
            document["open_sessions"] = {
                key: item for key, item in open_sessions.items()
                if not isinstance(item, dict)
                or not is_other_sites_usage_key(item.get("key"))
            }
        for field in ("analysis", "activity"):
            child = document.get(field)
            if isinstance(child, dict):
                clean(child)

    clean(result)
    return result


def notification_subject_roles(rule):
    """Return exact roles selected by a rule, including legacy policies."""
    explicit = rule.get("subject_roles") if isinstance(rule, dict) else None
    if isinstance(explicit, (list, tuple, set)):
        roles = {
            str(role).strip().lower() for role in explicit
            if str(role).strip().lower() in USER_ROLES
        }
        if roles:
            return roles
    legacy = str((rule or {}).get("login_role_scope") or "both").lower()
    if legacy == "admins":
        return {"admin"}
    if legacy == "users":
        return {"limited", "user"}
    return set(USER_ROLES)


def action_permission(action):
    if action in LIMIT_ACTIONS:
        return "manage_limits"
    if action in NOTIFICATION_ACTIONS:
        return "manage_notifications"
    return "manage_activity"
EMAIL_SECURITY_MODES = {"starttls", "ssl", "none"}
DEFAULT_EMAIL_SETTINGS = {
    "enabled": False,
    "smtp_host": "",
    "smtp_port": 587,
    "security": "starttls",
    "username": "",
    "password": "",
    "sender": "",
    "recipient": "",
    "message_templates": {},
}
EMAIL_TEMPLATE_KINDS = {
    "limit_change", "limit_warning", "limit_reached", "pwa_login",
    "limit_override_login",
    "access_change", "computer_state", "usage_threshold", "protection_interrupted",
}
NOTIFICATION_KIND_ALIASES = {
    "computer_block_change": "limit_change",
    "computer_block_warning": "limit_warning",
}
EMAIL_TEMPLATE_ALIASES = {
    **NOTIFICATION_KIND_ALIASES,
    "limit_extension": "limit_reached",
    "client_connected": "computer_state",
    "client_disconnected": "computer_state",
    "limited_app_start": "usage_threshold",
    "startup_reminder": "usage_threshold",
}
EMAIL_RATE_LIMIT = 30
EMAIL_RATE_WINDOW_SECONDS = 10 * 60
CLIENT_OFFLINE_SECONDS = 60


def canonical_notification_kind(kind):
    """Collapse legacy computer-only events into the shared limit events."""
    kind = str(kind or "").strip()
    return NOTIFICATION_KIND_ALIASES.get(kind, kind)


def normalize_notification_rules(rules):
    """Return one user-facing rule for each legacy/shared limit pair."""
    if not isinstance(rules, list):
        return []
    current, legacy = [], []
    for source in rules:
        if not isinstance(source, dict):
            continue
        rule = dict(source)
        if str(rule.get("kind") or "") in NOTIFICATION_KIND_ALIASES:
            legacy.append(rule)
        else:
            current.append(rule)
    for rule in legacy:
        rule["kind"] = canonical_notification_kind(rule.get("kind"))
        if rule["kind"] == "limit_change":
            rule["label"] = "Ajout, modification ou suppression d’une limite"
        elif rule["kind"] == "limit_warning":
            rule["label"] = "Préavis avant une limite"
        key = (
            rule["kind"], str(rule.get("owner") or "").casefold(),
            str(rule.get("target_key") or ""),
        )
        existing = next((
            item for item in current
            if (
                str(item.get("kind") or ""),
                str(item.get("owner") or "").casefold(),
                str(item.get("target_key") or ""),
            ) == key
        ), None)
        if existing is None:
            current.append(rule)
            continue
        channels = set(existing.get("channels") or ["windows"])
        channels.update(rule.get("channels") or ["windows"])
        existing["channels"] = [
            channel for channel in ("windows", "email") if channel in channels
        ]
        if not str(existing.get("email_recipient") or "").strip():
            existing["email_recipient"] = str(
                rule.get("email_recipient") or ""
            ).strip()
        if not str(existing.get("description") or "").strip():
            existing["description"] = str(rule.get("description") or "").strip()
    for rule in current:
        if rule.get("kind") == "limit_change" and str(
            rule.get("label") or ""
        ) in {
            "", "Ajout ou modification d’une limite",
            "Modification d’une limitation de l’ordinateur",
        }:
            rule["label"] = "Ajout, modification ou suppression d’une limite"
    return current


class DocumentConflict(ValueError):
    pass


class IdempotencyConflict(ValueError):
    pass


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def pwa_release_version(pwa_dir):
    try:
        worker = (Path(pwa_dir) / "service-worker.js").read_text(
            encoding="utf-8"
        )
    except OSError:
        return "unknown"
    match = re.search(r"usage-guard-shell-v(\d+)-(\d+)", worker)
    return f"{match.group(1)}.{match.group(2)}" if match else "unknown"


def json_hash(value):
    raw = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _aware_utc(value):
    try:
        moment = datetime.fromisoformat(str(value))
    except (TypeError, ValueError) as error:
        raise ValueError("Horodatage d’activité invalide.") from error
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("Un fuseau horaire est requis pour chaque tranche.")
    return moment.astimezone(timezone.utc)


def _view_timezone(name):
    value = str(name or "").strip()
    if not value:
        return timezone.utc
    if len(value) > 128 or not re.fullmatch(r"[A-Za-z0-9._+\-/]+", value):
        raise ValueError("Fuseau horaire invalide.")
    try:
        return ZoneInfo(value)
    except ZoneInfoNotFoundError as error:
        raise ValueError("Fuseau horaire inconnu.") from error


def interval_union_seconds(intervals, start=None, end=None):
    """Measure the union of touching/overlapping aware activity intervals."""
    lower = _aware_utc(start) if start is not None else None
    upper = _aware_utc(end) if end is not None else None
    if lower is not None and upper is not None and upper <= lower:
        raise ValueError("Période d’activité invalide.")
    periods = []
    for source in intervals or []:
        source = dict(source or {})
        opened = _aware_utc(source.get("started_at"))
        closed = _aware_utc(source.get("ended_at"))
        if closed <= opened:
            raise ValueError("La fin d’une tranche doit suivre son début.")
        opened = max(opened, lower) if lower is not None else opened
        closed = min(closed, upper) if upper is not None else closed
        if opened < closed:
            periods.append((opened, closed))
    periods.sort()
    merged = []
    for opened, closed in periods:
        if not merged or opened > merged[-1][1]:
            merged.append([opened, closed])
        elif closed > merged[-1][1]:
            merged[-1][1] = closed
    return round(sum(
        (closed - opened).total_seconds() for opened, closed in merged
    ), 3)


def snapshot_with_presence(snapshot, protection, now=None):
    """Annotate a stored snapshot without mistaking lost tracking for sleep."""
    result = json.loads(json.dumps(snapshot or {}))
    protection = dict(protection or {})
    status = dict(protection.get("status") or {})
    offline = not bool(status.get("service_connected"))
    result["protection"] = protection
    result["offline"] = offline
    last_seen = str(status.get("service_last_seen_at") or "")
    if not offline or not last_seen:
        return result
    # A stored snapshot can still name the last counted foreground target.
    # Once the agent is offline that is history, not a live activity signal.
    result["current"] = {}
    open_windows = []
    for source in result.get("windows_sessions") or []:
        if not isinstance(source, dict):
            continue
        item = dict(source)
        if not item.get("ended_at"):
            boundary = str(item.get("last_observed_at") or last_seen)
            try:
                if _aware_utc(boundary) >= _aware_utc(item.get("started_at")):
                    item["ended_at"] = boundary
                    item["closed_inferred"] = True
            except (TypeError, ValueError):
                pass
        open_windows.append(item)
    if open_windows:
        result["windows_sessions"] = open_windows
    observed_boundaries = [
        str(item.get("ended_at"))
        for item in open_windows
        if item.get("closed_inferred") and item.get("ended_at")
    ]
    activity_boundary = (
        max(observed_boundaries, key=_aware_utc)
        if observed_boundaries else last_seen
    )
    closed_sessions = []
    for source in result.get("sessions") or []:
        if not isinstance(source, dict):
            continue
        item = dict(source)
        if not item.get("ended_at"):
            boundary = str(item.get("last_observed_at") or activity_boundary)
            try:
                if _aware_utc(boundary) >= _aware_utc(item.get("started_at")):
                    item["ended_at"] = boundary
                    item["closed_inferred"] = True
            except (TypeError, ValueError):
                pass
        closed_sessions.append(item)
    if closed_sessions:
        result["sessions"] = closed_sessions
    events = list(result.get("system_events") or [])
    ordered = sorted(
        (item for item in events if isinstance(item, dict) and item.get("at")),
        key=lambda item: str(item["at"]),
    )
    latest_kind = str(ordered[-1].get("type") or "") if ordered else ""
    if latest_kind not in {"shutdown", "guard_stop", "tracking_gap"}:
        events.append({
            "type": "tracking_gap", "at": last_seen,
            "ended_at": str(now or utc_now()), "inferred": True,
            "reason": "service_heartbeat_lost",
        })
        result["system_events"] = events
    return result


def snapshot_with_device_context(snapshot, device, identities):
    """Expose one visible device name and the current authoritative SID mapping."""
    result = json.loads(json.dumps(snapshot or {}))
    device = dict(device or {})
    visible_name = str(
        device.get("label") or device.get("hostname_last_seen")
        or device.get("device_id") or ""
    ).strip()
    runtime = dict(result.get("runtime") or {})
    runtime["device"] = {
        "device_id": str(device.get("device_id") or ""),
        "display_name": visible_name,
    }
    result["runtime"] = runtime
    by_sid = {
        str(item.get("windows_sid") or "").strip().upper(): str(
            item.get("usage_guard_username") or ""
        ).strip()
        for item in identities or []
        if item.get("windows_sid") and item.get("usage_guard_username")
    }
    runtime_identity = dict(runtime.get("windows_identity") or {})
    runtime_username = by_sid.get(
        str(runtime_identity.get("windows_sid") or "").strip().upper()
    )
    if runtime_username:
        runtime_identity["usage_guard_username"] = runtime_username
        runtime_identity["mapped"] = True
        runtime_identity["mapping_status"] = "mapped"
        runtime["windows_identity"] = runtime_identity
        result["runtime"] = runtime
    windows_sessions = []
    for source in result.get("windows_sessions") or []:
        item = dict(source) if isinstance(source, dict) else source
        if isinstance(item, dict):
            username = by_sid.get(
                str(item.get("windows_sid") or "").strip().upper()
            )
            if username:
                item["usage_guard_username"] = username
        windows_sessions.append(item)
    if windows_sessions:
        result["windows_sessions"] = windows_sessions
    return result


def catalog_snapshot(snapshot):
    """Return only the metadata needed by the remote Classification view."""
    source = snapshot if isinstance(snapshot, dict) else {}
    fields = (
        "date", "timeline_now", "runtime", "current", "offline",
        "usage", "passive", "categories", "top_level_categories",
        "category_parents", "category_order", "target_order", "navigation_position", "unclassified_position", "site_categories",
        "site_category_order_manual", "merge_candidates", "other_sites",
        "excluded", "browsers", "dismissed_targets",
    )
    return {
        "scope": "catalog",
        **{field: source[field] for field in fields if field in source},
    }


def analysis_with_live_other_sites(summary, live):
    """Overlay the bounded current-day domain detail onto server history."""
    result = dict(summary or {})
    live = live if isinstance(live, dict) else {}
    by_day = {
        str(day.get("date")): dict(day)
        for day in result.get("daily_stats") or []
        if isinstance(day, dict) and day.get("date")
    }
    live_days = {
        str(day.get("date")): day
        for day in live.get("daily_stats") or []
        if isinstance(day, dict) and day.get("date")
    }
    live_day = str(live.get("date") or "")
    if live_day and live.get("other_sites"):
        source = dict(live_days.get(live_day) or {"date": live_day})
        source["other_sites"] = list(live.get("other_sites") or [])
        live_days[live_day] = source

    def merged_entries(*collections):
        entries = {}
        for collection in collections:
            for item in collection or []:
                if not isinstance(item, dict):
                    continue
                browser = str(item.get("browser") or "brave.exe").lower()
                host = str(item.get("host") or "").lower()
                if not host:
                    continue
                identity = (browser, host)
                seconds = max(0.0, float(item.get("seconds") or 0))
                previous = entries.get(identity)
                if previous is None or seconds > previous["seconds"]:
                    entries[identity] = {
                        "browser": browser, "host": host,
                        "seconds": round(seconds, 1),
                    }
        return sorted(entries.values(), key=lambda item: -item["seconds"])

    for day_text, source in live_days.items():
        current = by_day.get(day_text)
        if current is None:
            current = {
                "date": day_text,
                "usage": list(source.get("usage") or []),
                "passive": list(source.get("passive") or []),
                "active": float(source.get("active") or 0),
                "system": dict(source.get("system") or {}),
                "session_summary": dict(source.get("session_summary") or {}),
            }
            by_day[day_text] = current
        current["other_sites"] = merged_entries(
            current.get("other_sites"), source.get("other_sites"),
        )
    daily_stats = [by_day[key] for key in sorted(by_day)]
    totals = {}
    for day in daily_stats:
        for item in day.get("other_sites") or []:
            identity = (item["browser"], item["host"])
            totals[identity] = totals.get(identity, 0.0) + float(
                item.get("seconds") or 0
            )
    result["daily_stats"] = daily_stats
    result["other_sites"] = [
        {"browser": browser, "host": host, "seconds": round(seconds, 1)}
        for (browser, host), seconds in sorted(
            totals.items(), key=lambda item: -item[1]
        )
    ]
    return result


def analysis_snapshot_from_activity(activity, fallback=None):
    fallback = dict(fallback or {})
    activity = activity if isinstance(activity, dict) else {}
    days = activity.get("days") if isinstance(activity.get("days"), dict) else {}
    targets = activity.get("targets") if isinstance(activity.get("targets"), dict) else {}
    category_parents = activity.get("category_parents") if isinstance(activity.get("category_parents"), dict) else {}
    site_categories = list(activity.get("site_categories") or [])
    category_order = list(activity.get("category_order") or [])
    target_order = list(activity.get("target_order") or [])
    navigation_position = dict(activity.get("navigation_position") or {})
    unclassified_position = dict(activity.get("unclassified_position") or {})
    totals = {}
    other_site_totals = {}
    daily_stats = []
    categories = set(category_parents) | set(category_parents.values())
    known_site_categories = set(site_categories)
    for key, metadata in targets.items():
        if not isinstance(metadata, dict):
            continue
        category = str(metadata.get("category", "")).strip()
        site_category = str(metadata.get("site_category", "")).strip()
        if category and category not in {"__root__", "Applications non classées"}:
            categories.add(category)
        if str(key).startswith("site:") and site_category and site_category != "__root__":
            known_site_categories.add(site_category)
    for day_key in sorted(days):
        values = days.get(day_key)
        if not isinstance(values, dict):
            continue
        usage = []
        for key, seconds in sorted(values.items(), key=lambda item: float(item[1] or 0), reverse=True):
            key = str(key)
            metadata = targets.get(key, {}) if isinstance(targets.get(key), dict) else {}
            entry = {
                "key": key,
                "label": str(metadata.get("label") or key),
                "category": str(metadata.get("category") or ""),
                "site_category": str(metadata.get("site_category") or ""),
                "category_scope": str(metadata.get("category_scope") or ""),
                "seconds": round(float(seconds or 0), 1),
                "web": key.startswith("site:"),
                "multimedia": False,
            }
            usage.append(entry)
            totals[key] = totals.get(key, 0.0) + entry["seconds"]
            category = entry["category"]
            if category and category not in {"__root__", "Applications non classées"}:
                categories.add(category)
            if entry["web"] and entry["site_category"] and entry["site_category"] != "__root__":
                known_site_categories.add(entry["site_category"])
        other_sites = []
        for browser, browser_days in (activity.get("other_site_days") or {}).items():
            hosts = (
                (browser_days or {}).get(day_key, {})
                if isinstance(browser_days, dict) else {}
            )
            for host, seconds in (hosts or {}).items():
                seconds = round(float(seconds or 0), 1)
                if seconds <= 0:
                    continue
                entry = {
                    "browser": str(browser).lower(),
                    "host": str(host).lower(),
                    "seconds": seconds,
                }
                other_sites.append(entry)
                identity = (entry["browser"], entry["host"])
                other_site_totals[identity] = (
                    other_site_totals.get(identity, 0.0) + seconds
                )
        daily_stats.append({
            "date": str(day_key),
            "usage": usage,
            "active": round(sum(item["seconds"] for item in usage), 1),
            "passive": [],
            "system": (activity.get("system_days") or {}).get(day_key, {}),
            "other_sites": other_sites,
        })
    usage = []
    for key, seconds in sorted(totals.items(), key=lambda item: item[1], reverse=True):
        metadata = targets.get(key, {}) if isinstance(targets.get(key), dict) else {}
        usage.append({
            "key": key,
            "label": str(metadata.get("label") or key),
            "category": str(metadata.get("category") or ""),
            "site_category": str(metadata.get("site_category") or ""),
            "category_scope": str(metadata.get("category_scope") or ""),
            "seconds": round(seconds, 1),
            "web": str(key).startswith("site:"),
            "multimedia": False,
        })
    ordered_categories = [
        category for category in category_order
        if category and category != "__root__" and category in categories
    ]
    ordered_categories.extend(
        sorted(category for category in categories if category and category != "__root__" and category not in ordered_categories)
    )
    top_level = [
        category for category in ordered_categories
        if not category_parents.get(category)
    ]
    start = daily_stats[0]["date"] if daily_stats else fallback.get("date", utc_now()[:10])
    end = daily_stats[-1]["date"] if daily_stats else fallback.get("date", utc_now()[:10])
    activity_sessions = list(activity.get("sessions") or [])
    open_sessions = activity.get("open_sessions")
    if isinstance(open_sessions, dict):
        activity_sessions.extend(
            {**session, "ended_at": None}
            for session in open_sessions.values()
            if isinstance(session, dict)
        )
    return {
        **fallback,
        "scope": "all",
        "sessions": activity_sessions or list(fallback.get("sessions") or []),
        "windows_sessions": list(activity.get("windows_sessions") or fallback.get("windows_sessions") or []),
        "system_events": list(activity.get("system_events") or fallback.get("system_events") or []),
        "usage": usage,
        "passive": [],
        "other_sites": [
            {"browser": browser, "host": host, "seconds": round(seconds, 1)}
            for (browser, host), seconds in sorted(
                other_site_totals.items(), key=lambda item: -item[1]
            )
        ],
        "daily_stats": daily_stats,
        "categories": ordered_categories,
        "top_level_categories": top_level,
        "category_parents": category_parents,
        "category_order": category_order,
        "target_order": target_order,
        "navigation_position": navigation_position,
        "unclassified_position": unclassified_position,
        "dismissed_targets": dict(activity.get("dismissed_targets") or {}),
        "site_categories": [
            category for category in site_categories if category in known_site_categories
        ] + sorted(known_site_categories - set(site_categories)),
        "merge_candidates": [
            {
                "key": str(key),
                "label": str(metadata.get("label") or key) if isinstance(metadata, dict) else str(key),
                "category": str(metadata.get("category") or "") if isinstance(metadata, dict) else "",
                "site_category": str(metadata.get("site_category") or "") if isinstance(metadata, dict) else "",
                "category_scope": str(metadata.get("category_scope") or "") if isinstance(metadata, dict) else "",
                "planned": bool(metadata.get("manual")) if isinstance(metadata, dict) else False,
            }
            for key, metadata in targets.items()
        ],
        "timeline": {"start": start, "end": end},
    }


def snapshot_with_activity_history(snapshot, activity):
    """Complete a fresh compact snapshot with persisted timeline history.

    Agent snapshots intentionally stay small and can restart in the middle of
    a Windows session. The archive is authoritative for earlier intervals,
    while the snapshot remains authoritative for current and open intervals.
    """
    result = dict(snapshot or {})
    activity = activity if isinstance(activity, dict) else {}
    archived_sessions = list(activity.get("sessions") or [])
    open_sessions = activity.get("open_sessions")
    if isinstance(open_sessions, dict):
        archived_sessions.extend(
            {**item, "ended_at": None}
            for item in open_sessions.values()
            if isinstance(item, dict)
        )

    def merged(archived, fresh, identity, time_field):
        values = {}
        for collection in (archived or [], fresh or []):
            for source in collection:
                if not isinstance(source, dict):
                    continue
                item = dict(source)
                key = tuple(
                    str(item.get(field) or "") for field in identity
                )
                if any(key):
                    values[key] = item
        return sorted(
            values.values(),
            key=lambda item: str(item.get(time_field) or ""),
        )

    result["sessions"] = merged(
        archived_sessions, result.get("sessions"),
        ("kind", "id", "key", "started_at", "windows_sid"),
        "started_at",
    )
    result["windows_sessions"] = merged(
        activity.get("windows_sessions"), result.get("windows_sessions"),
        ("started_at", "windows_sid", "windows_session_id"), "started_at",
    )
    result["system_events"] = merged(
        activity.get("system_events"), result.get("system_events"),
        ("type", "at"), "at",
    )
    return result


def snapshot_with_interval_history(
    snapshot, sessions, *, truncated=False, timezone_name="",
):
    """Rebuild bounded analysis data from normalized interval rows.

    The legacy activity JSON is intentionally not needed here.  Every interval
    is split at day boundaries, so an application such as Kona that remains
    active over midnight contributes to both days.
    """
    result = dict(snapshot or {})
    view_timezone = _view_timezone(timezone_name)
    window_records = [
        dict(item) for item in sessions or []
        if isinstance(item, dict) and item.get("kind") == "windows_session"
    ]
    system_records = [
        dict(item) for item in sessions or []
        if isinstance(item, dict) and item.get("kind") == "system_event"
    ]
    display_sessions = [
        item for item in sessions or []
        if isinstance(item, dict)
        and item.get("kind") not in {"windows_session", "system_event"}
    ]
    candidates = {
        str(item.get("key") or ""): dict(item)
        for item in result.get("merge_candidates") or []
        if isinstance(item, dict) and str(item.get("key") or "")
    }
    merged = {}
    for collection in (display_sessions, result.get("sessions") or []):
        for source in collection:
            if not isinstance(source, dict):
                continue
            item = dict(source)
            identity = (
                str(item.get("kind") or ""), str(item.get("key") or ""),
                str(item.get("started_at") or ""),
                str(item.get("ended_at") or ""),
                str(item.get("windows_sid") or "").upper(),
            )
            if not identity[2]:
                continue
            metadata = candidates.get(identity[1], {})
            if not item.get("label") or item.get("label") == item.get("key"):
                item["label"] = target_display_label(
                    identity[1], metadata.get("label") or item.get("label"),
                )
            if not item.get("category") and metadata.get("category"):
                item["category"] = str(metadata.get("category") or "")
            merged[identity] = item
    timeline_sessions = sorted(merged.values(), key=lambda item: (
        str(item.get("started_at") or ""),
        str(item.get("ended_at") or ""), str(item.get("record_id") or ""),
    ))
    result["sessions"] = timeline_sessions

    fallback_days = {
        str(item.get("date") or ""): dict(item)
        for item in result.get("daily_stats") or []
        if isinstance(item, dict) and str(item.get("date") or "")
    }
    dates = set(fallback_days)
    for item in timeline_sessions:
        try:
            opened = _aware_utc(item.get("started_at"))
            raw_end = item.get("ended_at") or item.get("last_observed_at")
            closed = _aware_utc(raw_end) if raw_end else opened
        except (TypeError, ValueError):
            continue
        cursor = opened.astimezone(view_timezone).date()
        last = max(opened, closed - timedelta(microseconds=1)).astimezone(
            view_timezone
        ).date()
        while cursor <= last:
            dates.add(cursor.isoformat())
            cursor += timedelta(days=1)

    daily_stats = []
    for day_text in sorted(dates):
        try:
            lower = datetime.fromisoformat(day_text).replace(
                tzinfo=view_timezone
            ).astimezone(timezone.utc)
        except ValueError:
            continue
        upper = datetime.fromisoformat(
            (datetime.fromisoformat(day_text).date() + timedelta(days=1)).isoformat()
        ).replace(tzinfo=view_timezone).astimezone(timezone.utc)
        active_groups, passive_groups, all_active = {}, {}, []
        for item in timeline_sessions:
            raw_end = item.get("ended_at") or item.get("last_observed_at")
            if not raw_end:
                continue
            try:
                opened, closed = (
                    _aware_utc(item.get("started_at")), _aware_utc(raw_end),
                )
            except (TypeError, ValueError):
                continue
            # Historical rows can outlive a clock correction performed by a
            # monitored PC.  They remain useful in the raw timeline, but a
            # reversed or empty interval must not break the whole overview.
            if closed <= opened:
                continue
            if closed <= lower or opened >= upper:
                continue
            interval = {
                "started_at": max(opened, lower).isoformat(),
                "ended_at": min(closed, upper).isoformat(),
            }
            if item.get("kind") == "active" and item.get("key"):
                active_groups.setdefault(str(item["key"]), []).append(interval)
                all_active.append(interval)
            elif item.get("kind") == "multimedia" and item.get("label"):
                passive_groups.setdefault(str(item["label"]), []).append(interval)
        fallback = fallback_days.get(day_text, {})
        fallback_usage = {
            str(item.get("key") or ""): dict(item)
            for item in fallback.get("usage") or [] if isinstance(item, dict)
        }
        usage = []
        for key in sorted(set(active_groups) | set(fallback_usage)):
            saved = fallback_usage.get(key, {})
            metadata = candidates.get(key, saved)
            measured = interval_union_seconds(
                active_groups.get(key, []), lower.isoformat(), upper.isoformat(),
            )
            seconds = max(
                measured, float(saved.get("seconds") or 0),
            )
            if seconds <= 0 and not saved.get("open_seconds") and not saved.get(
                "launches"
            ):
                continue
            usage.append({
                **saved,
                "key": key, "label": target_display_label(
                    key, metadata.get("label"),
                ),
                "category": str(metadata.get("category") or ""),
                "site_category": str(metadata.get("site_category") or ""),
                "category_scope": str(metadata.get("category_scope") or ""),
                "seconds": round(seconds, 1), "web": key.startswith("site:"),
                "multimedia": False,
            })
        fallback_passive = {
            str(item.get("label") or ""): dict(item)
            for item in fallback.get("passive") or [] if isinstance(item, dict)
        }
        passive = []
        for label in sorted(set(passive_groups) | set(fallback_passive)):
            saved = fallback_passive.get(label, {})
            seconds = max(
                interval_union_seconds(
                    passive_groups.get(label, []), lower.isoformat(),
                    upper.isoformat(),
                ),
                float(saved.get("seconds") or 0),
            )
            if seconds > 0 or saved.get("open_seconds") or saved.get("launches"):
                passive.append({
                    **saved, "label": label, "seconds": round(seconds, 1),
                })
        active = max(
            interval_union_seconds(all_active, lower.isoformat(), upper.isoformat()),
            float(fallback.get("active") or 0),
        )
        daily_stats.append({
            **fallback, "date": day_text,
            "usage": sorted(usage, key=lambda item: -item["seconds"]),
            "passive": sorted(passive, key=lambda item: -item["seconds"]),
            "active": round(active, 1),
        })

    totals = {}
    passive_totals = {}
    for day in daily_stats:
        for item in day.get("usage") or []:
            current = totals.setdefault(item["key"], {**item, "seconds": 0.0})
            current["seconds"] += float(item.get("seconds") or 0)
        for item in day.get("passive") or []:
            passive_totals[item["label"]] = (
                passive_totals.get(item["label"], 0.0)
                + float(item.get("seconds") or 0)
            )
    result["daily_stats"] = daily_stats
    result["usage"] = sorted((
        {**item, "seconds": round(item["seconds"], 1)}
        for item in totals.values()
    ), key=lambda item: -item["seconds"])
    result["passive"] = sorted((
        {"label": label, "seconds": round(seconds, 1)}
        for label, seconds in passive_totals.items()
    ), key=lambda item: -item["seconds"])

    windows = [
        dict(item) for item in result.get("windows_sessions") or []
        if isinstance(item, dict) and item.get("started_at")
    ]
    windows.extend({
        "windows_sid": item.get("windows_sid", ""),
        "windows_session_id": item.get("windows_session_id", ""),
        "started_at": item.get("started_at"),
        "ended_at": item.get("ended_at"),
        "last_observed_at": item.get("ended_at"),
        "ended_reason": item.get("source", ""),
    } for item in window_records if item.get("started_at"))
    grouped = {}
    ungrouped = {}
    for item in timeline_sessions:
        try:
            opened = _aware_utc(item.get("started_at"))
            raw_end = item.get("ended_at") or item.get("last_observed_at")
            if not raw_end:
                continue
            closed = _aware_utc(raw_end)
        except (TypeError, ValueError):
            continue
        sid = str(item.get("windows_sid") or "").upper()
        session_id = str(item.get("windows_session_id") or "")
        if session_id:
            group = grouped.setdefault((sid, session_id), [opened, closed])
            group[0], group[1] = min(group[0], opened), max(group[1], closed)
        else:
            ungrouped.setdefault(sid, []).append((opened, closed))
    synthesized = [
        {
            "windows_sid": sid, "windows_session_id": session_id,
            "started_at": bounds[0].isoformat(timespec="milliseconds"),
            "ended_at": bounds[1].isoformat(timespec="milliseconds"),
            "last_observed_at": bounds[1].isoformat(timespec="milliseconds"),
        }
        for (sid, session_id), bounds in grouped.items()
    ]
    maximum_gap = timedelta(hours=4)
    for sid, periods in ungrouped.items():
        for opened, closed in sorted(periods):
            if not synthesized or synthesized[-1].get("windows_sid") != sid:
                synthesized.append({
                    "windows_sid": sid,
                    "started_at": opened.isoformat(timespec="milliseconds"),
                    "ended_at": closed.isoformat(timespec="milliseconds"),
                    "last_observed_at": closed.isoformat(timespec="milliseconds"),
                })
                continue
            previous_end = _aware_utc(synthesized[-1]["ended_at"])
            if opened - previous_end > maximum_gap:
                synthesized.append({
                    "windows_sid": sid,
                    "started_at": opened.isoformat(timespec="milliseconds"),
                    "ended_at": closed.isoformat(timespec="milliseconds"),
                    "last_observed_at": closed.isoformat(timespec="milliseconds"),
                })
            elif closed > previous_end:
                synthesized[-1]["ended_at"] = closed.isoformat(timespec="milliseconds")
                synthesized[-1]["last_observed_at"] = synthesized[-1]["ended_at"]
    # A closed activity interval cannot delimit a Windows session while a
    # fresh snapshot still contains an open activity.  In that situation an
    # inferred closed window would hide the live interval from the day/session
    # view.  A real windows_session record remains authoritative when present.
    if not windows and any(
        not (item.get("ended_at") or item.get("last_observed_at"))
        for item in timeline_sessions
    ):
        synthesized = []
    for item in synthesized:
        try:
            opened, closed = _aware_utc(item["started_at"]), _aware_utc(item["ended_at"])
        except (TypeError, ValueError):
            continue
        if any(
            _aware_utc(saved.get("started_at")) < closed
            and (not saved.get("ended_at") or _aware_utc(saved.get("ended_at")) > opened)
            and (
                not item.get("windows_sid")
                or not saved.get("windows_sid")
                or str(saved.get("windows_sid")).upper()
                == str(item.get("windows_sid")).upper()
            )
            for saved in windows
            if saved.get("started_at")
        ):
            continue
        windows.append(item)
    unique_windows = {}
    for item in windows:
        identity = (
            str(item.get("windows_sid") or "").upper(),
            str(item.get("windows_session_id") or ""),
            str(item.get("started_at") or ""),
        )
        if identity[2]:
            unique_windows[identity] = item
    result["windows_sessions"] = sorted(
        unique_windows.values(),
        key=lambda item: str(item.get("started_at") or ""),
    )
    saved_events = {
        (str(item.get("type") or ""), str(item.get("at") or "")): dict(item)
        for item in result.get("system_events") or []
        if isinstance(item, dict) and item.get("type") and item.get("at")
    }
    for item in system_records:
        event_type = str(item.get("id") or item.get("label") or "")
        if event_type.startswith("system:"):
            event_type = event_type.split(":", 1)[1]
        at = str(item.get("started_at") or "")
        if event_type and at:
            saved_events[(event_type, at)] = {
                "type": event_type, "at": at,
                "source": str(item.get("source") or ""),
            }
    result["system_events"] = sorted(
        saved_events.values(), key=lambda item: str(item.get("at") or ""),
    )
    if daily_stats:
        result["timeline"] = {
            "start": daily_stats[0]["date"], "end": daily_stats[-1]["date"],
        }
    result["history_truncated"] = bool(truncated)
    return result


def analysis_snapshot_usable(snapshot):
    if not isinstance(snapshot, dict):
        return False
    daily_stats = snapshot.get("daily_stats")
    if isinstance(daily_stats, list):
        for day in daily_stats:
            if isinstance(day, dict) and (
                day.get("usage") or day.get("passive") or day.get("active")
            ):
                return True
    usage = snapshot.get("usage")
    if isinstance(usage, list) and usage:
        return True
    return False


def snapshot_for_day_scope(snapshot, day, timezone_name=""):
    """Keep live/today responses small without altering stored history."""
    if not isinstance(snapshot, dict) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}", str(day or "")
    ):
        return snapshot
    result = dict(snapshot)
    view_timezone = _view_timezone(timezone_name)
    local_start = datetime.fromisoformat(str(day)).replace(
        tzinfo=view_timezone
    )
    local_end = datetime.fromisoformat(
        (local_start.date() + timedelta(days=1)).isoformat()
    ).replace(tzinfo=view_timezone)
    day_start = local_start.astimezone(timezone.utc)
    day_end = local_end.astimezone(timezone.utc)

    def overlaps_day(item):
        if not isinstance(item, dict):
            return False
        try:
            started = _aware_utc(item.get("started_at") or item.get("at"))
            raw_end = item.get("ended_at")
            ended = _aware_utc(raw_end) if raw_end else None
        except (TypeError, ValueError):
            return False
        return started < day_end and (ended is None or ended > day_start)

    selected_windows = [
        item for item in result.get("windows_sessions") or []
        if overlaps_day(item)
    ]

    def parsed_period(item, point=False):
        if not isinstance(item, dict):
            return None
        try:
            started = _aware_utc(item.get("started_at") or item.get("at"))
            raw_end = item.get("ended_at")
            ended = _aware_utc(raw_end) if raw_end else None
        except (TypeError, ValueError):
            return None
        if point and ended is None:
            ended = started + timedelta(microseconds=1)
        return started, ended

    window_periods = [
        period
        for period in (parsed_period(item) for item in selected_windows)
        if period is not None
    ]

    def overlaps_selected_windows(item, point=False):
        if not window_periods:
            return overlaps_day(item)
        period = parsed_period(item, point=point)
        if period is None:
            return False
        started, ended = period
        return any(
            (ended is None or ended > window_start)
            and (window_end is None or started < window_end)
            for window_start, window_end in window_periods
        )

    result["sessions"] = [
        item for item in result.get("sessions") or []
        if overlaps_selected_windows(item)
    ]
    # Never leave unrelated Windows sessions in a day-scoped response.  Apart
    # from making the payload unnecessarily large, stale open sessions could
    # otherwise become the PWA fallback and make an activity-free day look as
    # if it belonged to another Windows session.
    result["windows_sessions"] = selected_windows
    result["system_events"] = [
        item for item in result.get("system_events") or []
        if overlaps_selected_windows(item, point=True)
    ]
    result["daily_stats"] = [
        item for item in result.get("daily_stats") or []
        if isinstance(item, dict) and str(item.get("date") or "") == day
    ]
    result["timeline"] = {"start": day, "end": day}
    return result


def analysis_snapshot_since(snapshot, since_day, timezone_name=""):
    """Return the mutable tail of an analysis snapshot for cache merging."""
    if not isinstance(snapshot, dict) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}", str(since_day or "")
    ):
        return snapshot
    result = dict(snapshot)
    view_timezone = _view_timezone(timezone_name)
    lower = datetime.fromisoformat(str(since_day)).replace(
        tzinfo=view_timezone
    ).astimezone(timezone.utc)

    def overlaps_tail(item, field):
        if not isinstance(item, dict):
            return False
        try:
            started = _aware_utc(item.get("started_at") or item.get("at"))
            raw_end = item.get("ended_at")
            ended = _aware_utc(raw_end) if raw_end else None
        except (TypeError, ValueError):
            return False
        if field == "system_events":
            # Power events are usually points (``at`` only), while a
            # tracking_gap is a real period.  Keep the latter when it crosses
            # the requested local-midnight boundary instead of dropping it
            # solely because it started the previous evening.
            return ended > lower if raw_end else started >= lower
        return ended is None or ended > lower

    for field in ("sessions", "windows_sessions", "system_events"):
        result[field] = [
            item for item in result.get(field) or [] if overlaps_tail(item, field)
        ]
    result["daily_stats"] = [
        item for item in result.get("daily_stats") or []
        if isinstance(item, dict) and str(item.get("date") or "") >= since_day
    ]
    end = str(dict(result.get("timeline") or {}).get("end") or since_day)
    result["timeline"] = {"start": since_day, "end": end}
    result["delta_since"] = since_day
    return result


def apply_json_delta(base, delta):
    if not isinstance(delta, dict):
        raise ValueError("Delta JSON invalide")
    kind = delta.get("kind")

    if kind == "value":
        return delta.get("value")

    if kind == "dict":
        if not isinstance(base, dict):
            raise ValueError("Delta dictionnaire incompatible")
        result = dict(base)
        remove = delta.get("remove", [])
        set_values = delta.get("set", {})
        patch = delta.get("patch", {})
        if not isinstance(remove, list) or not isinstance(set_values, dict) or not isinstance(patch, dict):
            raise ValueError("Delta dictionnaire invalide")
        for key in remove:
            result.pop(str(key), None)
        result.update(set_values)
        for key, child in patch.items():
            if key not in result:
                raise ValueError("Delta dictionnaire sans base")
            result[key] = apply_json_delta(result[key], child)
        return result

    if kind == "list":
        if not isinstance(base, list):
            raise ValueError("Delta liste incompatible")
        start, stop, items = delta.get("start"), delta.get("stop"), delta.get("items")
        if (
            not isinstance(start, int)
            or not isinstance(stop, int)
            or not isinstance(items, list)
            or start < 0
            or stop < start
            or stop > len(base)
        ):
            raise ValueError("Delta liste invalide")
        return base[:start] + items + base[stop:]

    raise ValueError("Type de delta JSON inconnu")


def password_digest(password, salt):
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2 ** 14, r=8, p=1, dklen=32
    )


def validate_username(username):
    username = str(username or "").strip()
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("L’identifiant doit contenir 3 à 32 lettres, chiffres, points, tirets ou underscores.")
    return username


def validate_password(password):
    password = str(password or "")
    if len(password) < PASSWORD_MIN_LENGTH:
        raise ValueError(f"Le mot de passe doit contenir au moins {PASSWORD_MIN_LENGTH} caractères.")
    if len(password) > 256:
        raise ValueError("Le mot de passe est trop long.")
    return password


class LoginLimiter:
    def __init__(self, attempts=5, window=600, block=900):
        self.attempts, self.window, self.block = attempts, window, block
        self.failures, self.blocked_until = {}, {}
        self.lock = threading.Lock()

    def allowed(self, key):
        with self.lock:
            return self.blocked_until.get(key, 0) <= time.monotonic()

    def failed(self, key):
        now = time.monotonic()
        with self.lock:
            recent = [stamp for stamp in self.failures.get(key, []) if now - stamp <= self.window]
            recent.append(now)
            self.failures[key] = recent
            if len(recent) >= self.attempts:
                self.blocked_until[key] = now + self.block

    def succeeded(self, key):
        with self.lock:
            self.failures.pop(key, None)
            self.blocked_until.pop(key, None)


class EmailLimiter:
    def __init__(self, limit=EMAIL_RATE_LIMIT, window=EMAIL_RATE_WINDOW_SECONDS):
        self.limit, self.window = limit, window
        self.sent = {}
        self.lock = threading.Lock()

    def allow(self, recipient):
        now = time.monotonic()
        key = str(recipient or "").casefold()
        with self.lock:
            recent = [value for value in self.sent.get(key, []) if now - value < self.window]
            if len(recent) >= self.limit:
                self.sent[key] = recent
                return False
            recent.append(now)
            self.sent[key] = recent
            return True

class Store:
    def __init__(self, path=DB_PATH, email_encryption_key=None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._policy_operation_lock = threading.Lock()
        self._email_encryption_key = None
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                PRAGMA foreign_keys=ON;
                CREATE TABLE IF NOT EXISTS snapshots (
                    device_id TEXT PRIMARY KEY, payload TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS activity_stores (
                    device_id TEXT PRIMARY KEY, payload TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL,
                    payload TEXT NOT NULL, created_at TEXT NOT NULL,
                    delivered_at TEXT, acknowledged_at TEXT, result TEXT,
                    idempotency_key TEXT NOT NULL DEFAULT '', cancelled_at TEXT
                );
                CREATE INDEX IF NOT EXISTS commands_pending
                    ON commands(device_id, acknowledged_at, id);
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY COLLATE NOCASE,
                    salt BLOB NOT NULL, password_hash BLOB NOT NULL,
                    must_change INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    is_admin INTEGER NOT NULL DEFAULT 0,
                    permissions TEXT NOT NULL DEFAULT '{}',
                    email TEXT NOT NULL DEFAULT '',
                    role TEXT NOT NULL DEFAULT 'limited'
                );
                CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    label TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    token_hash TEXT NOT NULL DEFAULT '',
                    hostname_last_seen TEXT NOT NULL DEFAULT '',
                    credential_updated_at TEXT,
                    revoked_at TEXT
                );
                CREATE TABLE IF NOT EXISTS device_enrollments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code_hash TEXT NOT NULL UNIQUE,
                    device_id TEXT NOT NULL,
                    username TEXT COLLATE NOCASE,
                    created_by TEXT NOT NULL COLLATE NOCASE,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    used_at TEXT,
                    FOREIGN KEY(device_id) REFERENCES devices(device_id),
                    FOREIGN KEY(username) REFERENCES users(username) ON DELETE SET NULL
                );
                CREATE INDEX IF NOT EXISTS device_enrollments_expiry
                    ON device_enrollments(expires_at,used_at);
                CREATE TABLE IF NOT EXISTS user_devices (
                    username TEXT NOT NULL COLLATE NOCASE,
                    device_id TEXT NOT NULL,
                    PRIMARY KEY(username,device_id),
                    FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE,
                    FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS user_person_access (
                    username TEXT NOT NULL COLLATE NOCASE,
                    person_username TEXT NOT NULL COLLATE NOCASE,
                    PRIMARY KEY(username,person_username),
                    FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE,
                    FOREIGN KEY(person_username) REFERENCES users(username) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS device_windows_identities (
                    device_id TEXT NOT NULL,
                    windows_sid TEXT NOT NULL COLLATE NOCASE,
                    usage_guard_username TEXT NOT NULL COLLATE NOCASE,
                    windows_domain TEXT NOT NULL DEFAULT '',
                    windows_username TEXT NOT NULL,
                    is_windows_admin INTEGER NOT NULL DEFAULT 0,
                    created_by TEXT NOT NULL COLLATE NOCASE,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(device_id,windows_sid),
                    UNIQUE(device_id,usage_guard_username),
                    FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE CASCADE,
                    FOREIGN KEY(usage_guard_username) REFERENCES users(username) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS device_windows_identity_user
                    ON device_windows_identities(usage_guard_username,device_id);
                CREATE TABLE IF NOT EXISTS user_policy_revisions (
                    usage_guard_username TEXT NOT NULL COLLATE NOCASE,
                    revision INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    actor TEXT NOT NULL COLLATE NOCASE,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(usage_guard_username,revision),
                    FOREIGN KEY(usage_guard_username) REFERENCES users(username)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS device_policy_state (
                    device_id TEXT NOT NULL,
                    usage_guard_username TEXT NOT NULL COLLATE NOCASE,
                    desired_revision INTEGER NOT NULL DEFAULT 0,
                    applied_revision INTEGER NOT NULL DEFAULT 0,
                    last_result TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(device_id,usage_guard_username),
                    FOREIGN KEY(device_id) REFERENCES devices(device_id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(usage_guard_username) REFERENCES users(username)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS device_policy_revision
                    ON device_policy_state(device_id,desired_revision,applied_revision);
                CREATE TABLE IF NOT EXISTS user_computer_block_policies (
                    usage_guard_username TEXT PRIMARY KEY COLLATE NOCASE,
                    revision INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    actor TEXT NOT NULL COLLATE NOCASE,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(usage_guard_username) REFERENCES users(username)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS device_computer_block_state (
                    device_id TEXT NOT NULL,
                    usage_guard_username TEXT NOT NULL COLLATE NOCASE,
                    desired_revision INTEGER NOT NULL DEFAULT 0,
                    applied_revision INTEGER NOT NULL DEFAULT 0,
                    command_id INTEGER,
                    last_result TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(device_id,usage_guard_username),
                    FOREIGN KEY(device_id) REFERENCES devices(device_id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(usage_guard_username) REFERENCES users(username)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS user_computer_block_operations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    usage_guard_username TEXT NOT NULL COLLATE NOCASE,
                    idempotency_key TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(usage_guard_username,idempotency_key),
                    FOREIGN KEY(usage_guard_username) REFERENCES users(username)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS user_policy_operations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    usage_guard_username TEXT NOT NULL COLLATE NOCASE,
                    idempotency_key TEXT NOT NULL,
                    actor TEXT NOT NULL COLLATE NOCASE,
                    before_payload TEXT NOT NULL,
                    target_revision INTEGER NOT NULL,
                    rollback_revision INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL,
                    cancelled_at TEXT,
                    UNIQUE(usage_guard_username,idempotency_key),
                    FOREIGN KEY(usage_guard_username) REFERENCES users(username)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS user_policy_operation_status
                    ON user_policy_operations(usage_guard_username,status,id);
                CREATE TABLE IF NOT EXISTS activity_intervals (
                    device_id TEXT NOT NULL,
                    interval_id TEXT NOT NULL,
                    windows_sid TEXT NOT NULL COLLATE NOCASE,
                    usage_guard_username TEXT NOT NULL COLLATE NOCASE,
                    target_key TEXT NOT NULL,
                    category_key TEXT NOT NULL DEFAULT '',
                    started_at TEXT NOT NULL,
                    ended_at TEXT NOT NULL,
                    policy_revision INTEGER NOT NULL,
                    received_at TEXT NOT NULL,
                    PRIMARY KEY(device_id,interval_id),
                    FOREIGN KEY(device_id) REFERENCES devices(device_id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(usage_guard_username) REFERENCES users(username)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS activity_interval_categories (
                    device_id TEXT NOT NULL,
                    interval_id TEXT NOT NULL,
                    category_key TEXT NOT NULL,
                    PRIMARY KEY(device_id,interval_id,category_key),
                    FOREIGN KEY(device_id,interval_id)
                        REFERENCES activity_intervals(device_id,interval_id)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS activity_interval_category_lookup
                    ON activity_interval_categories(category_key,device_id,interval_id);
                CREATE TABLE IF NOT EXISTS activity_live_intervals (
                    device_id TEXT NOT NULL,
                    live_id TEXT NOT NULL,
                    windows_sid TEXT NOT NULL COLLATE NOCASE,
                    usage_guard_username TEXT NOT NULL COLLATE NOCASE,
                    target_key TEXT NOT NULL,
                    category_key TEXT NOT NULL DEFAULT '',
                    started_at TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    policy_revision INTEGER NOT NULL,
                    received_at TEXT NOT NULL,
                    PRIMARY KEY(device_id,live_id),
                    FOREIGN KEY(device_id) REFERENCES devices(device_id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(usage_guard_username) REFERENCES users(username)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS activity_live_categories (
                    device_id TEXT NOT NULL,
                    live_id TEXT NOT NULL,
                    category_key TEXT NOT NULL,
                    PRIMARY KEY(device_id,live_id,category_key),
                    FOREIGN KEY(device_id,live_id)
                        REFERENCES activity_live_intervals(device_id,live_id)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS activity_live_category_lookup
                    ON activity_live_categories(category_key,device_id,live_id);
                CREATE INDEX IF NOT EXISTS activity_interval_union
                    ON activity_intervals(
                        usage_guard_username,target_key,started_at,ended_at
                    );
                CREATE TABLE IF NOT EXISTS activity_timeline_sessions (
                    device_id TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    windows_sid TEXT NOT NULL COLLATE NOCASE,
                    usage_guard_username TEXT NOT NULL COLLATE NOCASE,
                    session_kind TEXT NOT NULL,
                    session_id TEXT NOT NULL DEFAULT '',
                    target_key TEXT NOT NULL DEFAULT '',
                    label TEXT NOT NULL DEFAULT '',
                    category_key TEXT NOT NULL DEFAULT '',
                    category_lineage TEXT NOT NULL DEFAULT '[]',
                    started_at TEXT NOT NULL,
                    ended_at TEXT NOT NULL,
                    windows_session_id TEXT NOT NULL DEFAULT '',
                    started_before_tracking INTEGER NOT NULL DEFAULT 0,
                    source TEXT NOT NULL DEFAULT '',
                    received_at TEXT NOT NULL,
                    PRIMARY KEY(device_id,record_id),
                    FOREIGN KEY(device_id) REFERENCES devices(device_id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(usage_guard_username) REFERENCES users(username)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS activity_timeline_device_period
                    ON activity_timeline_sessions(device_id,started_at,ended_at);
                CREATE INDEX IF NOT EXISTS activity_timeline_user_period
                    ON activity_timeline_sessions(
                        usage_guard_username,started_at,ended_at
                    );
                CREATE TABLE IF NOT EXISTS device_catalogs (
                    device_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    score TEXT NOT NULL DEFAULT '[]',
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(device_id) REFERENCES devices(device_id)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS activity_store_migrations (
                    device_id TEXT PRIMARY KEY,
                    payload_hash TEXT NOT NULL DEFAULT '',
                    source_updated_at TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'pending',
                    migrated_records INTEGER NOT NULL DEFAULT 0,
                    pending_records INTEGER NOT NULL DEFAULT 0,
                    skipped_records INTEGER NOT NULL DEFAULT 0,
                    daily_aggregates_migrated INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT,
                    last_error TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS activity_daily_legacy (
                    device_id TEXT NOT NULL,
                    usage_guard_username TEXT NOT NULL COLLATE NOCASE,
                    local_day TEXT NOT NULL,
                    metric_kind TEXT NOT NULL,
                    metric_key TEXT NOT NULL,
                    seconds REAL NOT NULL,
                    PRIMARY KEY(
                        device_id,usage_guard_username,local_day,
                        metric_kind,metric_key
                    ),
                    FOREIGN KEY(device_id) REFERENCES devices(device_id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(usage_guard_username) REFERENCES users(username)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS activity_daily_legacy_period
                    ON activity_daily_legacy(
                        device_id,usage_guard_username,local_day
                    );
                CREATE TABLE IF NOT EXISTS activity_daily_aggregate_batches (
                    device_id TEXT NOT NULL,
                    aggregate_id TEXT NOT NULL,
                    usage_guard_username TEXT NOT NULL COLLATE NOCASE,
                    local_day TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    PRIMARY KEY(device_id,aggregate_id),
                    UNIQUE(device_id,usage_guard_username,local_day),
                    FOREIGN KEY(device_id) REFERENCES devices(device_id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(usage_guard_username) REFERENCES users(username)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS activity_daily_aggregate_metrics (
                    device_id TEXT NOT NULL,
                    aggregate_id TEXT NOT NULL,
                    metric_kind TEXT NOT NULL,
                    metric_key TEXT NOT NULL,
                    seconds REAL NOT NULL,
                    PRIMARY KEY(
                        device_id,aggregate_id,metric_kind,metric_key
                    ),
                    FOREIGN KEY(device_id,aggregate_id)
                        REFERENCES activity_daily_aggregate_batches(
                            device_id,aggregate_id
                        ) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS activity_daily_aggregate_period
                    ON activity_daily_aggregate_batches(
                        device_id,usage_guard_username,local_day
                    );
                CREATE TABLE IF NOT EXISTS activity_daily_aggregate_receipts (
                    device_id TEXT NOT NULL,
                    aggregate_id TEXT NOT NULL,
                    local_day TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    PRIMARY KEY(device_id,aggregate_id),
                    FOREIGN KEY(device_id) REFERENCES devices(device_id)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS activity_target_deletion_operations (
                    usage_guard_username TEXT NOT NULL COLLATE NOCASE,
                    idempotency_key TEXT NOT NULL,
                    target_key TEXT NOT NULL,
                    device_scope TEXT NOT NULL,
                    cutoff_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    applied_at TEXT,
                    PRIMARY KEY(usage_guard_username,idempotency_key),
                    FOREIGN KEY(usage_guard_username) REFERENCES users(username)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS activity_target_deletion_seals (
                    device_id TEXT NOT NULL,
                    usage_guard_username TEXT NOT NULL COLLATE NOCASE,
                    target_key TEXT NOT NULL,
                    sealed_through_at TEXT NOT NULL,
                    sealed_through_day TEXT NOT NULL,
                    catalog_sealed INTEGER NOT NULL DEFAULT 1,
                    catalog_confirmation_after TEXT,
                    operation_key TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(device_id,usage_guard_username,target_key),
                    FOREIGN KEY(device_id) REFERENCES devices(device_id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(usage_guard_username) REFERENCES users(username)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS activity_target_deletion_lookup
                    ON activity_target_deletion_seals(
                        device_id,usage_guard_username,target_key
                    );
                CREATE TABLE IF NOT EXISTS activity_target_deletion_deliveries (
                    command_id INTEGER NOT NULL,
                    device_id TEXT NOT NULL,
                    usage_guard_username TEXT NOT NULL COLLATE NOCASE,
                    target_key TEXT NOT NULL,
                    PRIMARY KEY(command_id,device_id),
                    FOREIGN KEY(command_id) REFERENCES commands(id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(device_id) REFERENCES devices(device_id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(usage_guard_username) REFERENCES users(username)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS device_notification_policies (
                    device_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY, username TEXT NOT NULL COLLATE NOCASE,
                    csrf_token TEXT NOT NULL, expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
                CREATE TABLE IF NOT EXISTS email_settings (
                    id INTEGER PRIMARY KEY CHECK(id=1),
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS device_presence (
                    device_id TEXT PRIMARY KEY,
                    last_seen TEXT NOT NULL,
                    online INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS protection_status (
                    device_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS protection_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    event_key TEXT,
                    kind TEXT NOT NULL,
                    components TEXT NOT NULL,
                    message TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    occurred_at TEXT,
                    received_at TEXT
                );
                CREATE INDEX IF NOT EXISTS protection_events_device
                    ON protection_events(device_id,id DESC);
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL,
                    actor TEXT NOT NULL COLLATE NOCASE,
                    details TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS audit_events_created
                    ON audit_events(created_at,id);
            """)
            columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
            role_column_added = "role" not in columns
            if "is_admin" not in columns:
                db.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
            if "permissions" not in columns:
                db.execute("ALTER TABLE users ADD COLUMN permissions TEXT NOT NULL DEFAULT '{}'")
            if "email" not in columns:
                db.execute("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''")
            if role_column_added:
                db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'limited'")
            device_columns = {
                row["name"] for row in db.execute("PRAGMA table_info(devices)")
            }
            if "token_hash" not in device_columns:
                db.execute("ALTER TABLE devices ADD COLUMN token_hash TEXT NOT NULL DEFAULT ''")
            if "hostname_last_seen" not in device_columns:
                db.execute("ALTER TABLE devices ADD COLUMN hostname_last_seen TEXT NOT NULL DEFAULT ''")
            if "credential_updated_at" not in device_columns:
                db.execute("ALTER TABLE devices ADD COLUMN credential_updated_at TEXT")
            if "revoked_at" not in device_columns:
                db.execute("ALTER TABLE devices ADD COLUMN revoked_at TEXT")
            command_columns = {
                row["name"] for row in db.execute("PRAGMA table_info(commands)")
            }
            if "idempotency_key" not in command_columns:
                db.execute(
                    "ALTER TABLE commands ADD COLUMN idempotency_key "
                    "TEXT NOT NULL DEFAULT ''"
                )
            if "cancelled_at" not in command_columns:
                db.execute("ALTER TABLE commands ADD COLUMN cancelled_at TEXT")
            activity_migration_columns = {
                row["name"] for row in db.execute(
                    "PRAGMA table_info(activity_store_migrations)"
                )
            }
            if "source_updated_at" not in activity_migration_columns:
                db.execute(
                    "ALTER TABLE activity_store_migrations ADD COLUMN "
                    "source_updated_at TEXT NOT NULL DEFAULT ''"
                )
            if "daily_aggregates_migrated" not in activity_migration_columns:
                db.execute(
                    "ALTER TABLE activity_store_migrations ADD COLUMN "
                    "daily_aggregates_migrated INTEGER NOT NULL DEFAULT 0"
                )
            db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS commands_idempotency "
                "ON commands(device_id,idempotency_key) "
                "WHERE idempotency_key<>''"
            )
            event_columns = {
                row["name"] for row in db.execute(
                    "PRAGMA table_info(protection_events)"
                )
            }
            if "event_key" not in event_columns:
                db.execute("ALTER TABLE protection_events ADD COLUMN event_key TEXT")
            if "occurred_at" not in event_columns:
                db.execute("ALTER TABLE protection_events ADD COLUMN occurred_at TEXT")
            if "received_at" not in event_columns:
                db.execute("ALTER TABLE protection_events ADD COLUMN received_at TEXT")
            db.execute(
                "UPDATE protection_events SET event_key='legacy:' || id "
                "WHERE event_key IS NULL OR event_key=''"
            )
            db.execute(
                "UPDATE protection_events SET occurred_at=created_at "
                "WHERE occurred_at IS NULL OR occurred_at=''"
            )
            db.execute(
                "UPDATE protection_events SET received_at=created_at "
                "WHERE received_at IS NULL OR received_at=''"
            )
            db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS protection_events_key "
                "ON protection_events(device_id,event_key)"
            )
            email_columns = {row["name"] for row in db.execute("PRAGMA table_info(email_settings)")}
            if email_columns and "payload" not in email_columns:
                db.execute("DROP TABLE email_settings")
                db.execute(
                    "CREATE TABLE email_settings (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL, updated_at TEXT NOT NULL)"
                )
            if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] and not db.execute(
                "SELECT 1 FROM users WHERE is_admin=1 LIMIT 1"
            ).fetchone():
                db.execute(
                    "UPDATE users SET is_admin=1 WHERE username=(SELECT username FROM users ORDER BY created_at,username LIMIT 1)"
                )
            for row in db.execute(
                "SELECT username,is_admin,permissions,role FROM users"
            ).fetchall():
                try:
                    saved_permissions = json.loads(row["permissions"] or "{}")
                except (TypeError, ValueError):
                    saved_permissions = {}
                role = str(row["role"] or "").strip().lower()
                if row["is_admin"]:
                    role = "admin"
                elif role == "manager":
                    role = "user"
                elif role_column_added or role not in USER_ROLES or role == "admin":
                    role = "user" if any(
                        saved_permissions.get(key) for key in MANAGE_PERMISSION_KEYS
                    ) else "limited"
                db.execute(
                    "UPDATE users SET role=?,is_admin=? WHERE username=?",
                    (role, int(role == "admin"), row["username"]),
                )
            legacy_manager_table = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='manager_users'"
            ).fetchone()
            if legacy_manager_table:
                db.execute(
                    "INSERT OR IGNORE INTO user_devices(username,device_id) "
                    "SELECT m.manager_username,d.device_id FROM manager_users m "
                    "JOIN user_devices d ON d.username=m.limited_username "
                    "JOIN users u ON u.username=m.manager_username "
                    "WHERE u.role='user'"
                )
            db.execute(
                "INSERT OR IGNORE INTO activity_interval_categories("
                "device_id,interval_id,category_key) "
                "SELECT device_id,interval_id,category_key "
                "FROM activity_intervals WHERE category_key<>''"
            )
        # Existing snapshot rows may already contain protected notification
        # recipients.  Configure the key before any startup migration reads
        # those rows; doing it afterwards makes a valid deployed database
        # impossible to reopen.
        if email_encryption_key:
            self.configure_email_encryption_key(email_encryption_key)
        # This is a strictly local, one-time normalization of activity blobs
        # already present in the server database.  It never calls an HTTP
        # endpoint and never returns or republishes the historical document.
        self.migrate_legacy_activity_stores()
        # Older agents already publish a compact snapshot.  Normalize its
        # closed tail locally as well so a machine does not disappear from
        # today's remote/local admin views while it is being upgraded to the
        # incremental outbox protocol.
        self.migrate_snapshot_activity_tails()
        # Old compact snapshots and the incremental outbox could describe the
        # exact same active interval with different transport IDs.  Keep the
        # modern outbox row and remove only byte-for-byte business duplicates.
        self.purge_duplicate_snapshot_activity_intervals()
        # ``site:<browser>:other-sites`` is an accounting key, not a concrete
        # site identity.  Purge legacy timeline copies after importing old
        # snapshot tails, while deliberately retaining usage intervals and
        # daily aggregates used by quotas and totals.
        self.purge_other_sites_timeline_records()
        self._migrate_computer_block_policy_documents()
        self.purge_stale_commands()
        if email_encryption_key:
            self.reconcile_startup_state()

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            yield db
            db.commit()
        finally:
            db.close()

    def purge_other_sites_timeline_records(self):
        """Purge legacy aggregate-site timeline rows without changing usage."""
        counts = {"timeline": 0, "snapshots": 0, "activity_stores": 0}
        with self._lock, self.connect() as db:
            rows = db.execute(
                "SELECT device_id,record_id,target_key "
                "FROM activity_timeline_sessions"
            ).fetchall()
            identities = [
                (row["device_id"], row["record_id"])
                for row in rows
                if is_other_sites_usage_key(row["target_key"])
            ]
            if identities:
                db.executemany(
                    "DELETE FROM activity_timeline_sessions "
                    "WHERE device_id=? AND record_id=?",
                    identities,
                )
                counts["timeline"] = len(identities)

            for table in ("snapshots", "activity_stores"):
                for row in db.execute(
                    f"SELECT device_id,payload FROM {table}"
                ).fetchall():
                    try:
                        source = json.loads(row["payload"])
                    except (TypeError, ValueError, json.JSONDecodeError):
                        continue
                    sanitized = snapshot_without_other_sites_timeline(source)
                    if sanitized == source:
                        continue
                    db.execute(
                        f"UPDATE {table} SET payload=? WHERE device_id=?",
                        (
                            json.dumps(
                                sanitized, ensure_ascii=False,
                                separators=(",", ":"),
                            ),
                            row["device_id"],
                        ),
                    )
                    counts[table] += 1
        return counts

    def purge_duplicate_snapshot_activity_intervals(self):
        """Remove legacy snapshot intervals duplicated by a modern outbox row.

        The comparison deliberately covers every usage-bearing field and the
        complete category set.  Removing the compatibility copy therefore
        cannot change the union of recorded usage.
        """
        removed = 0
        with self._lock, self.connect() as db:
            legacy_rows = db.execute(
                "SELECT device_id,interval_id,windows_sid,"
                "usage_guard_username,target_key,category_key,started_at,"
                "ended_at,policy_revision FROM activity_intervals "
                "WHERE interval_id GLOB 'snapshot-activity-*'"
            ).fetchall()
            for legacy in legacy_rows:
                candidates = db.execute(
                    "SELECT interval_id FROM activity_intervals WHERE "
                    "device_id=? AND interval_id GLOB 'activity-*' AND "
                    "windows_sid=? AND usage_guard_username=? AND "
                    "target_key=? AND category_key=? AND started_at=? AND "
                    "ended_at=? AND policy_revision=?",
                    (
                        legacy["device_id"], legacy["windows_sid"],
                        legacy["usage_guard_username"], legacy["target_key"],
                        legacy["category_key"], legacy["started_at"],
                        legacy["ended_at"], legacy["policy_revision"],
                    ),
                ).fetchall()
                legacy_categories = tuple(row[0] for row in db.execute(
                    "SELECT category_key FROM activity_interval_categories "
                    "WHERE device_id=? AND interval_id=? ORDER BY category_key",
                    (legacy["device_id"], legacy["interval_id"]),
                ).fetchall())
                duplicate = any(
                    tuple(row[0] for row in db.execute(
                        "SELECT category_key FROM activity_interval_categories "
                        "WHERE device_id=? AND interval_id=? "
                        "ORDER BY category_key",
                        (legacy["device_id"], candidate["interval_id"]),
                    ).fetchall()) == legacy_categories
                    for candidate in candidates
                )
                if not duplicate:
                    continue
                db.execute(
                    "DELETE FROM activity_intervals WHERE device_id=? "
                    "AND interval_id=?",
                    (legacy["device_id"], legacy["interval_id"]),
                )
                removed += 1
        return removed

    @staticmethod
    def _purge_snapshot_duplicates_for_modern_interval(
        db, interval, category_keys,
    ):
        """Drop compatibility rows once their exact outbox row is durable."""
        if not str(interval[1]).startswith("activity-"):
            return 0
        candidates = db.execute(
            "SELECT interval_id FROM activity_intervals WHERE device_id=? "
            "AND interval_id GLOB 'snapshot-activity-*' AND windows_sid=? "
            "AND usage_guard_username=? AND target_key=? AND category_key=? "
            "AND started_at=? AND ended_at=? AND policy_revision=?",
            (
                interval[0], interval[2], interval[3], interval[4],
                interval[5], interval[6], interval[7], interval[8],
            ),
        ).fetchall()
        expected_categories = tuple(sorted(category_keys))
        duplicates = []
        for candidate in candidates:
            stored_categories = tuple(row[0] for row in db.execute(
                "SELECT category_key FROM activity_interval_categories "
                "WHERE device_id=? AND interval_id=? ORDER BY category_key",
                (interval[0], candidate["interval_id"]),
            ).fetchall())
            if stored_categories == expected_categories:
                duplicates.append((interval[0], candidate["interval_id"]))
        if duplicates:
            db.executemany(
                "DELETE FROM activity_intervals WHERE device_id=? "
                "AND interval_id=?", duplicates,
            )
        return len(duplicates)

    def create_database_backup(self, destination, actor, version):
        destination = Path(destination)
        created_at = utc_now()
        details = json.dumps(
            {"version": str(version or "unknown")},
            ensure_ascii=False, separators=(",", ":"),
        )
        with self._lock:
            with self.connect() as db:
                db.execute(
                    "INSERT INTO audit_events(kind,actor,details,created_at) "
                    "VALUES(?,?,?,?)",
                    ("database_backup_download", str(actor), details, created_at),
                )
            source = sqlite3.connect(self.path, timeout=10)
            target = sqlite3.connect(destination)
            try:
                source.backup(target)
                target.commit()
                check = target.execute("PRAGMA quick_check").fetchone()
                if not check or check[0] != "ok":
                    raise sqlite3.DatabaseError(
                        "La sauvegarde SQLite n’a pas passé le contrôle d’intégrité."
                    )
            finally:
                target.close()
                source.close()
        return {"created_at": created_at, "version": str(version or "unknown")}

    def _save_document(self, table, device_id, document):
        payload = json.dumps(
            self._protect_document_recipients(document),
            ensure_ascii=False, separators=(",", ":"),
        )
        with self._lock, self.connect() as db:
            db.execute(
                f"INSERT INTO {table} VALUES(?,?,?) ON CONFLICT(device_id) DO UPDATE SET payload=excluded.payload, updated_at=excluded.updated_at",
                (device_id, payload, utc_now()),
            )

    def _load_document(self, table, device_id):
        with self.connect() as db:
            row = db.execute(
                f"SELECT payload,updated_at FROM {table} WHERE device_id=?",
                (device_id,),
            ).fetchone()
        if not row:
            return None, None
        return self._unprotect_document_recipients(
            json.loads(row["payload"])
        ), row["updated_at"]

    def _patch_document(self, table, device_id, delta, base_hash, target_hash):
        current, _ = self._load_document(table, device_id)
        if current is None:
            raise DocumentConflict("Document de base absent")
        if json_hash(current) != str(base_hash or ""):
            raise DocumentConflict("Document distant modifié")
        updated = apply_json_delta(current, delta)
        if json_hash(updated) != str(target_hash or ""):
            raise ValueError("Hash cible incohérent")
        self._save_document(table, device_id, updated)

    def _snapshot_sanitized_by_deletion_seals(
        self, device_id, snapshot, *, include_released=False,
    ):
        result = snapshot_without_other_sites_timeline(snapshot)
        with self.connect() as db:
            seals = db.execute(
                "SELECT usage_guard_username,target_key FROM "
                "activity_target_deletion_seals WHERE device_id=?"
                + ("" if include_released else " AND catalog_sealed=1"),
                (str(device_id or "").strip(),),
            ).fetchall()
            identities = db.execute(
                "SELECT DISTINCT usage_guard_username FROM "
                "device_windows_identities WHERE device_id=?",
                (str(device_id or "").strip(),),
            ).fetchall()
        default_username = (
            str(identities[0]["usage_guard_username"])
            if len(identities) == 1 else ""
        )
        for seal in seals:
            result = self._snapshot_without_user_target(
                result, seal["usage_guard_username"], seal["target_key"],
                default_username,
            )
        return result

    def save_snapshot(self, device_id, snapshot):
        # Catalogue confirmation must inspect the raw new snapshot, while the
        # compatibility bridge must inspect it before timeline-only sentinels
        # are removed.  It keeps the sentinel's usage interval, but its own
        # exact-key guard prevents a drawable timeline row.
        self._save_snapshot_catalog(device_id, snapshot)
        self._normalize_snapshot_activity_tail(device_id, snapshot)
        sanitized = self._snapshot_sanitized_by_deletion_seals(
            device_id, snapshot,
        )
        self._save_document("snapshots", device_id, sanitized)

    def _save_snapshot_catalog(self, device_id, snapshot):
        """Keep classification state independent from the activity archive.

        An empty/lightweight snapshot is never allowed to erase a catalogue
        that already contains categories or assignments.  Destructive
        catalogue commands still flow through the explicit command log; this
        guard only rejects accidental absence of catalogue fields.
        """
        document = self._snapshot_catalog_document(snapshot)
        raw_document = copy.deepcopy(document)
        runtime = snapshot.get("runtime") if isinstance(snapshot, dict) else {}
        runtime = runtime if isinstance(runtime, dict) else {}
        identity = runtime.get("windows_identity")
        identity = identity if isinstance(identity, dict) else {}
        snapshot_username = str(
            identity.get("usage_guard_username") or ""
        ).strip()
        explicit_catalog = bool(
            isinstance(snapshot, dict)
            and (
                isinstance(snapshot.get("targets"), dict)
                or isinstance(snapshot.get("merge_candidates"), list)
            )
            and any(self._catalog_document_score(raw_document))
        )
        now = datetime.now(timezone.utc)
        sealed_targets = []
        with self._lock, self.connect() as db:
            rows = db.execute(
                "SELECT usage_guard_username,target_key,catalog_sealed,"
                "catalog_confirmation_after FROM "
                "activity_target_deletion_seals WHERE device_id=? "
                "ORDER BY target_key,usage_guard_username",
                (str(device_id or "").strip(),),
            ).fetchall()
            for row in rows:
                sealed = bool(row["catalog_sealed"])
                confirmation = str(row["catalog_confirmation_after"] or "")
                fresh = False
                if confirmation:
                    try:
                        fresh = _aware_utc(confirmation) <= now
                    except (TypeError, ValueError):
                        fresh = False
                target_absent = str(row["target_key"]) not in dict(
                    raw_document.get("targets") or {}
                )
                if (
                    sealed and fresh and explicit_catalog and target_absent
                    and snapshot_username.casefold()
                    == str(row["usage_guard_username"]).casefold()
                ):
                    db.execute(
                        "UPDATE activity_target_deletion_seals SET "
                        "catalog_sealed=0,updated_at=? WHERE device_id=? AND "
                        "usage_guard_username=? AND target_key=?",
                        (
                            utc_now(), device_id,
                            row["usage_guard_username"], row["target_key"],
                        ),
                    )
                    sealed = False
                if sealed:
                    sealed_targets.append(str(row["target_key"]))
        for target_key in sealed_targets:
            document = self._catalog_document_without_target(
                document, target_key,
            )
        score = self._catalog_document_score(document)
        if not any(score):
            return False
        encoded_score = json.dumps(score, separators=(",", ":"))
        encoded_payload = json.dumps(
            self._protect_document_recipients(document),
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        )
        with self._lock, self.connect() as db:
            current = db.execute(
                "SELECT payload,score FROM device_catalogs WHERE device_id=?",
                (device_id,),
            ).fetchone()
            if current:
                try:
                    current_document = self._unprotect_document_recipients(
                        json.loads(current["payload"])
                    )
                except (TypeError, ValueError):
                    current_document = {}
                # A snapshot missing every known target/category is a compact
                # or broken publication, never an instruction to erase them.
                if (
                    self._catalog_document_score(current_document) > (0,) * 8
                    and not document.get("targets")
                    and not self._catalog_categories(document)
                ):
                    return False
                # ``updated_at`` is the catalogue revision, not the last
                # activity snapshot time.  Otherwise whichever computer was
                # merely online most recently would win an equal-score merge,
                # even when it kept publishing the same stale classification.
                if (
                    current_document == document
                    and str(current["score"] or "") == encoded_score
                ):
                    return False
            db.execute(
                "INSERT INTO device_catalogs(device_id,payload,score,updated_at) "
                "VALUES(?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET "
                "payload=excluded.payload,score=excluded.score,"
                "updated_at=excluded.updated_at",
                (device_id, encoded_payload, encoded_score, utc_now()),
            )
        return True

    def device_catalog(self, device_id):
        payload, _updated_at = self._load_document("device_catalogs", device_id)
        return payload

    def mark_device_seen(self, device_id):
        now = utc_now()
        with self._lock, self.connect() as db:
            row = db.execute(
                "SELECT online FROM device_presence WHERE device_id=?", (device_id,)
            ).fetchone()
            connected = row is None or not bool(row["online"])
            db.execute(
                """INSERT INTO device_presence(device_id,last_seen,online) VALUES(?,?,1)
                   ON CONFLICT(device_id) DO UPDATE SET last_seen=excluded.last_seen,online=1""",
                (device_id, now),
            )
        return connected

    def mark_device_offline_if_stale(self, device_id, stale_seconds=CLIENT_OFFLINE_SECONDS):
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=stale_seconds)).isoformat(timespec="seconds")
        with self._lock, self.connect() as db:
            cursor = db.execute(
                "UPDATE device_presence SET online=0 WHERE device_id=? AND online=1 AND last_seen<?",
                (device_id, cutoff),
            )
        return cursor.rowcount == 1

    def device_presence(self, device_id):
        with self.connect() as db:
            row = db.execute(
                "SELECT last_seen,online FROM device_presence WHERE device_id=?",
                (device_id,),
            ).fetchone()
        return dict(row) if row else None

    @staticmethod
    def _normalized_protection_status(status):
        source = dict(status or {})
        try:
            stale_after = max(15, min(300, int(
                source.get("stale_after_seconds", 45)
            )))
        except (TypeError, ValueError):
            stale_after = 45
        return {
            "service_connected": True,
            "desktop_connected": bool(source.get("desktop_connected")),
            "desktop_last_seen_at": str(
                source.get("desktop_last_seen_at") or ""
            )[:64],
            "extension_connected": bool(source.get("extension_connected")),
            "extension_last_seen_at": str(
                source.get("extension_last_seen_at") or ""
            )[:64],
            "stale_after_seconds": stale_after,
        }

    def record_protection_event(
        self, device_id, kind, components, message,
        event_key=None, occurred_at=None,
    ):
        kind = "restored" if kind == "restored" else "interrupted"
        components = sorted({
            str(item) for item in components
            if str(item) in {"service", "desktop", "extension"}
        })
        received_at = utc_now()
        occurred_at = str(occurred_at or received_at)[:64]
        event_key = str(event_key or ("server:" + secrets.token_hex(16)))[:128]
        message = str(message or "")[:500]
        with self._lock, self.connect() as db:
            cursor = db.execute(
                "INSERT OR IGNORE INTO protection_events(device_id,event_key,kind,components,message,created_at,occurred_at,received_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    device_id, event_key, kind,
                    json.dumps(components, separators=(",", ":")),
                    message, received_at, occurred_at, received_at,
                ),
            )
            if cursor.rowcount != 1:
                return None
            db.execute(
                "DELETE FROM protection_events WHERE device_id=? AND id NOT IN (SELECT id FROM protection_events WHERE device_id=? ORDER BY id DESC LIMIT 200)",
                (device_id, device_id),
            )
        return {
            "id": cursor.lastrowid, "event_key": event_key, "kind": kind,
            "components": components, "message": message,
            "occurred_at": occurred_at, "received_at": received_at,
            "created_at": received_at,
        }

    def save_protection_status(self, device_id, status):
        normalized = self._normalized_protection_status(status)
        supplied_events = (
            status.get("events", []) if isinstance(status, dict) else []
        )
        if not isinstance(supplied_events, list):
            supplied_events = []
        now = utc_now()
        with self._lock, self.connect() as db:
            row = db.execute(
                "SELECT payload FROM protection_status WHERE device_id=?",
                (device_id,),
            ).fetchone()
            previous = json.loads(row["payload"]) if row else None
            maintenance = dict(previous or {})
            try:
                maintenance_active = bool(
                    maintenance.get("maintenance_until")
                    and _aware_utc(maintenance["maintenance_until"])
                    > datetime.now(timezone.utc)
                )
            except (TypeError, ValueError):
                maintenance_active = False
            if maintenance_active:
                normalized.update({
                    "maintenance_until": maintenance["maintenance_until"],
                    "maintenance_version": str(
                        maintenance.get("maintenance_version") or ""
                    ),
                    "maintenance_alerted": bool(
                        maintenance.get("maintenance_alerted")
                    ),
                    "maintenance_reconnected": bool(
                        maintenance.get("maintenance_reconnected")
                    ),
                })
            db.execute(
                "INSERT INTO protection_status(device_id,payload,updated_at) VALUES(?,?,?) ON CONFLICT(device_id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at",
                (
                    device_id,
                    json.dumps(normalized, separators=(",", ":")), now,
                ),
            )
        accepted_event_ids = []
        events = []
        for source in supplied_events[:200]:
            if not isinstance(source, dict):
                continue
            event_key = str(source.get("id") or "")[:128]
            if not event_key:
                continue
            accepted_event_ids.append(event_key)
            event = self.record_protection_event(
                device_id, source.get("kind"),
                source.get("components", []), source.get("message", ""),
                event_key=event_key,
                occurred_at=source.get("occurred_at"),
            )
            if event and not maintenance_active:
                events.append(event)
        if previous is not None and not supplied_events and not maintenance_active:
            was_healthy = bool(
                previous.get("desktop_connected")
                and previous.get("extension_connected")
            )
            healthy = bool(
                normalized["desktop_connected"]
                and normalized["extension_connected"]
            )
            if was_healthy != healthy:
                if healthy:
                    event = self.record_protection_event(
                        device_id, "restored", ["desktop", "extension"],
                        "Le systray et l’extension communiquent de nouveau avec le service protégé.",
                    )
                else:
                    missing = [
                        component for component, connected in (
                            ("desktop", normalized["desktop_connected"]),
                            ("extension", normalized["extension_connected"]),
                        ) if not connected
                    ]
                    labels = {
                        "desktop": "systray", "extension": "extension navigateur",
                    }
                    event = self.record_protection_event(
                        device_id, "interrupted", missing,
                        "Signal de protection perdu : "
                        + ", ".join(labels[item] for item in missing)
                        + ". Un arrêt ou un contournement est possible.",
                    )
                if event:
                    events.append(event)
        return {
            "status": {**normalized, "updated_at": now},
            "events": events,
            "accepted_event_ids": accepted_event_ids,
        }

    def begin_device_maintenance(self, device_id, version="", duration_seconds=900):
        duration = max(60, min(1800, int(duration_seconds)))
        until = (
            datetime.now(timezone.utc) + timedelta(seconds=duration)
        ).isoformat(timespec="seconds")
        with self._lock, self.connect() as db:
            row = db.execute(
                "SELECT payload FROM protection_status WHERE device_id=?",
                (device_id,),
            ).fetchone()
            payload = json.loads(row["payload"]) if row else {}
            payload.update({
                "maintenance_until": until,
                "maintenance_version": str(version or "")[:32],
                "maintenance_alerted": False,
                "maintenance_reconnected": False,
            })
            db.execute(
                "INSERT INTO protection_status(device_id,payload,updated_at) "
                "VALUES(?,?,?) ON CONFLICT(device_id) DO UPDATE SET "
                "payload=excluded.payload,updated_at=excluded.updated_at",
                (device_id, json.dumps(payload, separators=(",", ":")), utc_now()),
            )
        return {
            "active": True, "until": until,
            "version": str(version or "")[:32],
        }

    def device_maintenance(self, device_id):
        with self.connect() as db:
            row = db.execute(
                "SELECT payload FROM protection_status WHERE device_id=?",
                (device_id,),
            ).fetchone()
        payload = json.loads(row["payload"]) if row else {}
        until = str(payload.get("maintenance_until") or "")
        try:
            active = bool(
                until and _aware_utc(until) > datetime.now(timezone.utc)
            )
        except (TypeError, ValueError):
            active = False
        return {
            "active": active,
            "until": until,
            "version": str(payload.get("maintenance_version") or ""),
            "alerted": bool(payload.get("maintenance_alerted")),
            "reconnected": bool(payload.get("maintenance_reconnected")),
        }

    def mark_device_maintenance_reconnected(self, device_id):
        with self._lock, self.connect() as db:
            row = db.execute(
                "SELECT payload FROM protection_status WHERE device_id=?",
                (device_id,),
            ).fetchone()
            if not row:
                return
            payload = json.loads(row["payload"])
            payload["maintenance_reconnected"] = True
            db.execute(
                "UPDATE protection_status SET payload=?,updated_at=? "
                "WHERE device_id=?",
                (
                    json.dumps(payload, separators=(",", ":")),
                    utc_now(), device_id,
                ),
            )

    def clear_device_maintenance(self, device_id):
        with self._lock, self.connect() as db:
            row = db.execute(
                "SELECT payload FROM protection_status WHERE device_id=?",
                (device_id,),
            ).fetchone()
            if not row:
                return
            payload = json.loads(row["payload"])
            for key in (
                "maintenance_until", "maintenance_version",
                "maintenance_alerted", "maintenance_reconnected",
            ):
                payload.pop(key, None)
            db.execute(
                "UPDATE protection_status SET payload=?,updated_at=? "
                "WHERE device_id=?",
                (
                    json.dumps(payload, separators=(",", ":")),
                    utc_now(), device_id,
                ),
            )

    def claim_expired_device_maintenance(self, device_id):
        with self._lock, self.connect() as db:
            row = db.execute(
                "SELECT payload FROM protection_status WHERE device_id=?",
                (device_id,),
            ).fetchone()
            if not row:
                return False
            payload = json.loads(row["payload"])
            until = str(payload.get("maintenance_until") or "")
            try:
                expired = bool(
                    until and _aware_utc(until) <= datetime.now(timezone.utc)
                )
            except (TypeError, ValueError):
                expired = False
            if not expired or payload.get("maintenance_alerted"):
                return False
            payload["maintenance_alerted"] = True
            db.execute(
                "UPDATE protection_status SET payload=?,updated_at=? "
                "WHERE device_id=?",
                (
                    json.dumps(payload, separators=(",", ":")),
                    utc_now(), device_id,
                ),
            )
            return True

    def protection_overview(self, device_id):
        with self.connect() as db:
            status_row = db.execute(
                "SELECT payload,updated_at FROM protection_status WHERE device_id=?",
                (device_id,),
            ).fetchone()
            presence = db.execute(
                "SELECT last_seen,online FROM device_presence WHERE device_id=?",
                (device_id,),
            ).fetchone()
            rows = db.execute(
                "SELECT id,event_key,kind,components,message,created_at,occurred_at,received_at FROM protection_events WHERE device_id=? ORDER BY id DESC LIMIT 30",
                (device_id,),
            ).fetchall()
        status = json.loads(status_row["payload"]) if status_row else {}
        updated_at = str(status_row["updated_at"] if status_row else "")
        status_age_seconds = None
        if updated_at:
            try:
                updated = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
                status_age_seconds = max(
                    0, int((datetime.now(timezone.utc) - updated).total_seconds())
                )
            except (TypeError, ValueError):
                pass
        stale_after = int(status.get("stale_after_seconds", 45))
        stale = status_age_seconds is None or status_age_seconds > stale_after
        status.update({
            "service_connected": bool(presence and presence["online"]),
            "service_last_seen_at": str(presence["last_seen"] if presence else ""),
            "updated_at": updated_at,
            "status_age_seconds": status_age_seconds,
            "stale": stale,
        })
        status["healthy"] = bool(
            status["service_connected"] and not stale
            and status.get("desktop_connected")
            and status.get("extension_connected")
        )
        return {
            "status": status,
            "events": [{
                "id": row["id"], "event_key": row["event_key"],
                "kind": row["kind"],
                "components": json.loads(row["components"]),
                "message": row["message"], "created_at": row["created_at"],
                "occurred_at": row["occurred_at"] or row["created_at"],
                "received_at": row["received_at"] or row["created_at"],
            } for row in rows],
        }

    def patch_snapshot(self, device_id, delta, base_hash, target_hash):
        self._patch_document("snapshots", device_id, delta, base_hash, target_hash)
        snapshot, _updated_at = self._load_document("snapshots", device_id)
        if snapshot:
            self._save_snapshot_catalog(device_id, snapshot)
            self._normalize_snapshot_activity_tail(device_id, snapshot)
            sanitized = self._snapshot_sanitized_by_deletion_seals(
                device_id, snapshot,
            )
            if json_hash(sanitized) != json_hash(snapshot):
                self._save_document("snapshots", device_id, sanitized)

    def snapshot(self, device_id):
        payload, updated_at = self._load_document("snapshots", device_id)
        if payload and "notification_rules" in payload:
            payload = {
                **payload,
                "notification_rules": normalize_notification_rules(
                    payload.get("notification_rules")
                ),
            }
        return ({**payload, "backend_updated_at": updated_at} if payload else None)

    def migrate_snapshot_activity_tails(self, device_id=None):
        """Normalize compact stored snapshots without any network backfill."""
        clauses, parameters = "", []
        if device_id is not None:
            clauses = " WHERE device_id=?"
            parameters.append(str(device_id or "").strip())
        with self.connect() as db:
            rows = db.execute(
                "SELECT device_id,payload FROM snapshots" + clauses
                + " ORDER BY device_id", parameters,
            ).fetchall()
        result = {"snapshots": 0, "accepted": 0, "duplicates": 0, "skipped": 0}
        for row in rows:
            try:
                snapshot = self._unprotect_document_recipients(
                    json.loads(row["payload"])
                )
            except (TypeError, ValueError, json.JSONDecodeError):
                result["skipped"] += 1
                continue
            current = self._normalize_snapshot_activity_tail(
                str(row["device_id"]), snapshot,
            )
            result["snapshots"] += 1
            for field in ("accepted", "duplicates", "skipped"):
                result[field] += int(current.get(field) or 0)
        return result

    def _normalize_snapshot_activity_tail(self, device_id, snapshot):
        """Persist only closed rows already present in a compact snapshot.

        This compatibility bridge handles old agents until their incremental
        outbox is installed.  It reads the bounded snapshot received by the
        normal snapshot endpoint, never ``activity_stores`` or activity.json.
        Stable content IDs and a natural-key check make repeated snapshots
        harmless.
        """
        device_id = str(device_id or "").strip()
        if not device_id or not isinstance(snapshot, dict):
            return {"accepted": 0, "duplicates": 0, "skipped": 0}
        embedded = snapshot.get("analysis")
        documents = [snapshot]
        if isinstance(embedded, dict):
            documents.insert(0, embedded)
        with self.connect() as db:
            identity_rows = db.execute(
                "SELECT windows_sid,usage_guard_username "
                "FROM device_windows_identities WHERE device_id=? "
                "ORDER BY windows_sid", (device_id,),
            ).fetchall()
        identities = {
            str(row["windows_sid"] or "").strip().upper(): str(
                row["usage_guard_username"] or ""
            ).strip()
            for row in identity_rows
            if row["windows_sid"] and row["usage_guard_username"]
        }
        runtime = snapshot.get("runtime")
        runtime = runtime if isinstance(runtime, dict) else {}
        runtime_identity = runtime.get("windows_identity")
        runtime_identity = (
            runtime_identity if isinstance(runtime_identity, dict) else {}
        )
        runtime_sid = str(
            runtime_identity.get("windows_sid") or ""
        ).strip().upper()
        default_sid = runtime_sid if runtime_sid in identities else (
            next(iter(identities)) if len(identities) == 1 else ""
        )
        if not identities:
            return {"accepted": 0, "duplicates": 0, "skipped": 0}

        candidates = []
        seen_sources = set()

        def append(source, forced_kind="", point=False):
            if not isinstance(source, dict):
                return
            source = dict(source)
            if forced_kind:
                source["kind"] = forced_kind
            if point:
                source["started_at"] = source.get("at")
                if source.get("started_at") and not source.get("ended_at"):
                    try:
                        source["ended_at"] = (
                            _aware_utc(source["started_at"])
                            + timedelta(milliseconds=1)
                        ).isoformat(timespec="milliseconds")
                    except (TypeError, ValueError):
                        pass
            identity = (
                str(source.get("kind") or ""),
                str(source.get("key") or source.get("type") or ""),
                str(source.get("started_at") or ""),
                str(source.get("ended_at") or ""),
                str(source.get("windows_sid") or default_sid).upper(),
            )
            if identity in seen_sources:
                return
            seen_sources.add(identity)
            candidates.append(source)

        for document in documents:
            for source in document.get("sessions") or []:
                append(source)
            for source in document.get("windows_sessions") or []:
                append(source, "windows_session")
            for source in document.get("system_events") or []:
                append(source, "system_event", point=True)

        accepted = duplicates = skipped = 0
        now = utc_now()
        with self._lock, self.connect() as db:
            for source in candidates:
                kind = str(source.get("kind") or "").strip()
                if kind not in TIMELINE_SESSION_KINDS:
                    skipped += 1
                    continue
                sid = str(source.get("windows_sid") or default_sid).strip().upper()
                username = identities.get(sid)
                if not username or not source.get("started_at") or not source.get("ended_at"):
                    skipped += 1
                    continue
                try:
                    opened = _aware_utc(source["started_at"])
                    closed = _aware_utc(source["ended_at"])
                except (TypeError, ValueError):
                    skipped += 1
                    continue
                if closed <= opened:
                    skipped += 1
                    continue

                def cleaned(value, maximum):
                    value = str(value or "").strip()
                    if len(value) > maximum or any(
                        ord(character) < 32 for character in value
                    ):
                        raise ValueError
                    return value

                try:
                    local_id = cleaned(
                        source.get("id") or source.get("type") or "", 512,
                    )
                    if kind == "windows_session":
                        target_key, label = "computer:session", "Session Windows"
                    elif kind == "system_event":
                        target_key = "computer:event"
                        label = cleaned(
                            source.get("type") or source.get("label"), 1024,
                        )
                    else:
                        target_key = cleaned(source.get("key"), 1024)
                        label = cleaned(
                            source.get("label") or target_key, 1024,
                        )
                    category = cleaned(source.get("category"), 512)
                    lineage_source = source.get("category_lineage", [])
                    if not isinstance(lineage_source, list):
                        raise ValueError
                    lineage = list(dict.fromkeys(
                        cleaned(value, 512) for value in lineage_source
                        if str(value or "").strip()
                    ))
                    if category and category not in lineage:
                        lineage.insert(0, category)
                    if len(lineage) > 64 or not target_key:
                        raise ValueError
                    windows_session_id = cleaned(
                        source.get("windows_session_id"), 128,
                    )
                    origin = cleaned(
                        source.get("source") or "compact-snapshot", 128,
                    )
                    policy_revision = max(
                        0, int(source.get("policy_revision") or 0),
                    )
                except (TypeError, ValueError):
                    skipped += 1
                    continue
                started_at = opened.isoformat(timespec="milliseconds")
                ended_at = closed.isoformat(timespec="milliseconds")
                identity = {
                    "windows_sid": sid, "kind": kind, "id": local_id,
                    "key": target_key, "label": label,
                    "category": category, "category_lineage": lineage,
                    "started_at": started_at, "ended_at": ended_at,
                    "windows_session_id": windows_session_id,
                    "started_before_tracking": int(bool(
                        source.get("started_before_tracking", False)
                    )),
                    "source": origin,
                }
                usage_only = is_other_sites_usage_key(target_key)
                existing = None
                if not usage_only:
                    existing = db.execute(
                        "SELECT record_id FROM activity_timeline_sessions WHERE "
                        "device_id=? AND UPPER(windows_sid)=? AND session_kind=? "
                        "AND target_key=? AND started_at=? AND ended_at=? LIMIT 1",
                        (
                            device_id, sid, kind, target_key, started_at, ended_at,
                        ),
                    ).fetchone()
                    if existing:
                        duplicates += 1
                    else:
                        record_id = self._legacy_migration_id(
                            "snapshot-timeline-", identity,
                        )
                        db.execute(
                            "INSERT OR IGNORE INTO activity_timeline_sessions("
                            "device_id,record_id,windows_sid,usage_guard_username,"
                            "session_kind,session_id,target_key,label,category_key,"
                            "category_lineage,started_at,ended_at,windows_session_id,"
                            "started_before_tracking,source,received_at) "
                            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (
                                device_id, record_id, sid, username, kind, local_id,
                                target_key, label, category,
                                json.dumps(
                                    lineage, ensure_ascii=False,
                                    separators=(",", ":"),
                                ),
                                started_at, ended_at, windows_session_id,
                                identity["started_before_tracking"], origin, now,
                            ),
                        )
                if kind == "active" and target_key.startswith(
                    ("app:", "site:", "category:", "computer:")
                ):
                    interval_id = self._legacy_migration_id(
                        "snapshot-activity-", {
                            "windows_sid": sid, "key": target_key,
                            "category": category, "category_lineage": lineage,
                            "started_at": started_at, "ended_at": ended_at,
                        },
                    )
                    modern_rows = db.execute(
                        "SELECT interval_id FROM activity_intervals WHERE "
                        "device_id=? AND interval_id GLOB 'activity-*' AND "
                        "windows_sid=? AND usage_guard_username=? AND "
                        "target_key=? AND category_key=? AND started_at=? AND "
                        "ended_at=? AND policy_revision=?",
                        (
                            device_id, sid, username, target_key, category,
                            started_at, ended_at, policy_revision,
                        ),
                    ).fetchall()
                    expected_categories = tuple(sorted(lineage))
                    already_uploaded = any(
                        tuple(row[0] for row in db.execute(
                            "SELECT category_key FROM "
                            "activity_interval_categories WHERE device_id=? "
                            "AND interval_id=? ORDER BY category_key",
                            (device_id, modern["interval_id"]),
                        ).fetchall()) == expected_categories
                        for modern in modern_rows
                    )
                    if not already_uploaded:
                        db.execute(
                            "INSERT OR IGNORE INTO activity_intervals(device_id,"
                            "interval_id,windows_sid,usage_guard_username,"
                            "target_key,category_key,started_at,ended_at,"
                            "policy_revision,received_at) "
                            "VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (
                                device_id, interval_id, sid, username,
                                target_key, category, started_at, ended_at,
                                policy_revision, now,
                            ),
                        )
                        db.executemany(
                            "INSERT OR IGNORE INTO activity_interval_categories("
                            "device_id,interval_id,category_key) VALUES(?,?,?)",
                            [
                                (device_id, interval_id, value)
                                for value in lineage
                            ],
                        )
                if not usage_only and not existing:
                    accepted += 1
            self._apply_activity_target_deletion_seals(
                db, device_id=device_id,
            )
        return {
            "accepted": accepted, "duplicates": duplicates,
            "skipped": skipped,
        }

    @staticmethod
    def _legacy_activity_store_is_partial(current, activity):
        """Recognise old lightweight/stale publications without a mode flag."""
        if not isinstance(current, dict) or not current:
            return False
        if not isinstance(activity, dict) or not isinstance(
            activity.get("days"), dict
        ):
            return True
        lightweight_fields = {"version", "days", "sessions", "open_sessions"}
        if set(activity) - lightweight_fields:
            return False
        incoming_has_history = bool(activity.get("days")) or bool(
            activity.get("sessions")
        )
        current_has_durable_state = any(
            bool(value) for key, value in current.items()
            if key != "open_sessions"
        )
        return not incoming_has_history and current_has_durable_state

    @staticmethod
    def _merge_partial_activity_store(current, activity):
        """Apply live-only state without deleting durable history/catalogues."""
        merged = copy.deepcopy(current)
        # The sole destructive operation allowed to a partial publication is
        # closing/replacing live sessions.  Missing or empty durable fields are
        # deliberately ignored.
        if isinstance(activity, dict) and "open_sessions" in activity:
            open_sessions = activity.get("open_sessions")
            if isinstance(open_sessions, dict):
                merged["open_sessions"] = copy.deepcopy(open_sessions)
        return merged

    def _persist_without_other_sites_timeline(
        self, table, device_id, document,
    ):
        """Physically remove usage-only sessions without changing revision time."""
        sanitized = snapshot_without_other_sites_timeline(document)
        if sanitized == document:
            return False
        encoded = json.dumps(
            self._protect_document_recipients(sanitized),
            ensure_ascii=False, separators=(",", ":"),
        )
        with self._lock, self.connect() as db:
            db.execute(
                f"UPDATE {table} SET payload=? WHERE device_id=?",
                (encoded, str(device_id or "").strip()),
            )
        return True

    def save_activity_store(self, device_id, activity, complete=True):
        current_payload, _ = self._load_document("activity_stores", device_id)
        if not isinstance(activity, dict):
            raise ValueError("Base d’activité invalide")
        partial = complete is False or (
            complete is None
            and self._legacy_activity_store_is_partial(current_payload, activity)
        )
        if complete is not True and current_payload is None and not isinstance(
            activity.get("days"), dict
        ):
            raise DocumentConflict("Publication d’activité partielle sans base")
        stored = (
            self._merge_partial_activity_store(current_payload, activity)
            if partial else activity
        )
        self._save_document("activity_stores", device_id, stored)
        # Kept for database-import tests and explicit local migrations only.
        # The public legacy activity endpoint is retired and must never become
        # a transport for this (potentially very large) document again.
        migration = self.migrate_legacy_activity_stores(
            device_id=device_id, force=True,
        )
        # Migration above consumes the raw closed session first, so its usage
        # remains durable.  The compatibility blob is then physically cleaned
        # (not merely hidden by a response filter) while its revision stays
        # stable for legacy hash/retry logic.
        if not int(migration.get("pending_records") or 0):
            self._persist_without_other_sites_timeline(
                "activity_stores", device_id, stored,
            )
        return partial

    @staticmethod
    def _legacy_migration_id(prefix, value):
        encoded = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        return str(prefix) + hashlib.sha256(encoded).hexdigest()

    def _save_activity_store_migration_marker(
        self, device_id, payload_hash, source_updated_at, status, migrated,
        pending, skipped, error="", daily_aggregates_migrated=False,
    ):
        now = utc_now()
        with self._lock, self.connect() as db:
            db.execute(
                "INSERT INTO activity_store_migrations(device_id,payload_hash,"
                "source_updated_at,status,migrated_records,pending_records,"
                "skipped_records,daily_aggregates_migrated,updated_at,"
                "completed_at,last_error) VALUES(?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(device_id) DO UPDATE SET "
                "payload_hash=excluded.payload_hash,status=excluded.status,"
                "source_updated_at=excluded.source_updated_at,"
                "migrated_records=excluded.migrated_records,"
                "pending_records=excluded.pending_records,"
                "skipped_records=excluded.skipped_records,"
                "daily_aggregates_migrated="
                "excluded.daily_aggregates_migrated,"
                "updated_at=excluded.updated_at,"
                "completed_at=excluded.completed_at,"
                "last_error=excluded.last_error",
                (
                    str(device_id), str(payload_hash),
                    str(source_updated_at or ""), str(status),
                    max(0, int(migrated)), max(0, int(pending)),
                    max(0, int(skipped)),
                    int(bool(daily_aggregates_migrated)), now,
                    now if status == "completed" else None,
                    str(error or "")[:500],
                ),
            )

    def migrate_legacy_activity_stores(self, device_id=None, force=False):
        """Normalize server-local legacy blobs without moving their payload.

        The method intentionally returns aggregate counters only.  A completed
        payload hash is skipped, while archives containing records whose
        Windows identity is not yet safely resolvable remain pending and are
        retried on the next server start (or explicit local import).

        Timestamped records become exact intervals.  Legacy daily aggregates
        have no trustworthy interval boundaries, so they are copied into a
        separate normalized summary table used only for analysis.  They never
        become quota-bearing activity and the legacy blob is never serialized
        into a response.
        """
        clauses, parameters = "", []
        if device_id is not None:
            clauses = " WHERE source.device_id=?"
            parameters.append(str(device_id or "").strip())
        with self.connect() as db:
            rows = db.execute(
                "SELECT source.device_id,source.updated_at AS source_updated_at,"
                "migration.source_updated_at AS migrated_source_updated_at,"
                "migration.status AS migration_status,"
                "migration.daily_aggregates_migrated "
                "FROM activity_stores AS source LEFT JOIN "
                "activity_store_migrations AS migration "
                "ON migration.device_id=source.device_id" + clauses
                + " ORDER BY source.device_id", parameters,
            ).fetchall()
        summary = {
            "stores": 0, "completed": 0, "pending": 0, "failed": 0,
            "migrated_records": 0, "pending_records": 0,
            "skipped_records": 0,
        }
        for row in rows:
            summary["stores"] += 1
            if (
                not force and row["migration_status"] == "completed"
                and bool(row["daily_aggregates_migrated"])
                and str(row["migrated_source_updated_at"] or "")
                == str(row["source_updated_at"] or "")
            ):
                summary["completed"] += 1
                continue
            with self.connect() as db:
                payload = db.execute(
                    "SELECT payload FROM activity_stores WHERE device_id=?",
                    (row["device_id"],),
                ).fetchone()
            if not payload:
                continue
            result = self._migrate_legacy_activity_store(
                str(row["device_id"]), str(payload["payload"]),
                str(row["source_updated_at"] or ""),
            )
            status = str(result.get("status") or "failed")
            summary[status if status in {"completed", "pending"} else "failed"] += 1
            for field in (
                "migrated_records", "pending_records", "skipped_records",
            ):
                summary[field] += max(0, int(result.get(field) or 0))
        return summary

    def _migrate_legacy_activity_store(
        self, device_id, encoded_activity, source_updated_at="",
    ):
        payload_hash = hashlib.sha256(
            encoded_activity.encode("utf-8")
        ).hexdigest()
        try:
            activity = json.loads(encoded_activity)
            if not isinstance(activity, dict):
                raise ValueError("document non objet")
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            self._save_activity_store_migration_marker(
                device_id, payload_hash, source_updated_at, "failed", 0, 0, 1,
                "Archive d’activité locale invalide: " + str(error),
            )
            return {
                "status": "failed", "migrated_records": 0,
                "pending_records": 0, "skipped_records": 1,
            }

        with self.connect() as db:
            device_exists = bool(db.execute(
                "SELECT 1 FROM devices WHERE device_id=?", (device_id,),
            ).fetchone())
            identity_rows = [dict(row) for row in db.execute(
                "SELECT windows_sid,usage_guard_username,windows_domain,"
                "windows_username FROM device_windows_identities "
                "WHERE device_id=? ORDER BY windows_sid", (device_id,),
            ).fetchall()]
            assigned_users = [str(row["username"]) for row in db.execute(
                "SELECT ud.username FROM user_devices AS ud "
                "JOIN users AS u ON u.username=ud.username "
                "WHERE ud.device_id=? AND u.role='limited' "
                "ORDER BY ud.username COLLATE NOCASE", (device_id,),
            ).fetchall()]

        by_sid = {
            str(item["windows_sid"]).strip().upper(): item
            for item in identity_rows
        }
        by_usage_username = {
            str(item["usage_guard_username"]).casefold(): item
            for item in identity_rows
        }
        by_windows_username = {}
        for item in identity_rows:
            key = str(item.get("windows_username") or "").strip().casefold()
            if key:
                by_windows_username.setdefault(key, []).append(item)
        assigned_by_name = {
            username.casefold(): username for username in assigned_users
        }

        def valid_sid(value):
            value = str(value or "").strip().upper()
            return value if re.fullmatch(r"S-\d+(?:-\d+)+", value) else ""

        def mapped_pair(item):
            return (
                str(item["windows_sid"]).strip().upper(),
                str(item["usage_guard_username"]),
            )

        def resolve_identity(source, inherited=None):
            source = source if isinstance(source, dict) else {}
            sid = valid_sid(source.get("windows_sid") or source.get("sid"))
            if sid and sid in by_sid:
                return mapped_pair(by_sid[sid])
            usage_name = str(
                source.get("usage_guard_username") or ""
            ).strip()
            mapped = by_usage_username.get(usage_name.casefold())
            if mapped:
                return mapped_pair(mapped)
            windows_name = str(source.get("windows_username") or "").strip()
            matches = by_windows_username.get(windows_name.casefold(), [])
            domain = str(source.get("windows_domain") or "").strip().casefold()
            if domain and len(matches) > 1:
                matches = [
                    item for item in matches
                    if str(item.get("windows_domain") or "").casefold() == domain
                ]
            if len(matches) == 1:
                return mapped_pair(matches[0])
            # A record-stamped Usage Guard username is safe with its own SID
            # when that person is explicitly the device's limited user.
            assigned_name = assigned_by_name.get(usage_name.casefold())
            if sid and assigned_name:
                return sid, assigned_name
            if inherited:
                return inherited
            if len(identity_rows) == 1:
                return mapped_pair(identity_rows[0])
            if len(assigned_users) == 1:
                username = assigned_users[0]
                if sid:
                    return sid, username
                matches = [
                    item for item in identity_rows
                    if str(item["usage_guard_username"]).casefold()
                    == username.casefold()
                ]
                if len(matches) == 1:
                    return mapped_pair(matches[0])
            return None

        def parsed_period(source, point=False):
            opened = _aware_utc(
                source.get("at") if point else source.get("started_at")
            )
            raw_end = source.get("ended_at")
            closed = (
                _aware_utc(raw_end) if raw_end else opened + timedelta(
                    milliseconds=1
                )
            ) if point else _aware_utc(raw_end)
            if closed <= opened:
                raise ValueError("période vide")
            return opened, closed

        closed_windows = []
        windows_source = activity.get("windows_sessions", [])
        if not isinstance(windows_source, list):
            windows_source = []
        for source in windows_source:
            if not isinstance(source, dict) or not source.get("ended_at"):
                continue
            try:
                opened, closed = parsed_period(source)
            except (TypeError, ValueError):
                continue
            identity = resolve_identity(source)
            closed_windows.append({
                "source": source, "opened": opened, "closed": closed,
                "identity": identity,
                "session_id": str(
                    source.get("windows_session_id")
                    if source.get("windows_session_id") is not None
                    else source.get("session_id") or ""
                ),
            })

        def inherited_identity(source, opened, closed):
            session_id = str(
                source.get("windows_session_id")
                if source.get("windows_session_id") is not None else ""
            )
            candidates = []
            if session_id:
                candidates = [
                    item["identity"] for item in closed_windows
                    if item["identity"] and item["session_id"] == session_id
                ]
            if not candidates:
                candidates = [
                    item["identity"] for item in closed_windows
                    if item["identity"] and item["opened"] <= opened
                    and item["closed"] >= closed
                ]
            unique = list(dict.fromkeys(candidates))
            return unique[0] if len(unique) == 1 else None

        catalog = self._catalog_document(activity)
        catalog_score = self._catalog_document_score(catalog)
        catalog_pending = 0
        catalog_error = ""
        if any(catalog_score):
            if device_exists:
                try:
                    self._save_snapshot_catalog(device_id, activity)
                except (OSError, sqlite3.Error, TypeError, ValueError) as error:
                    catalog_pending = 1
                    catalog_error = "Catalogue local en attente: " + str(error)
            else:
                catalog_pending = 1
                catalog_error = "Ordinateur du catalogue local encore inconnu."
        target_metadata = (
            activity.get("targets")
            if isinstance(activity.get("targets"), dict) else {}
        )
        category_parents = (
            activity.get("category_parents")
            if isinstance(activity.get("category_parents"), dict) else {}
        )

        def category_fields(source, target_key):
            metadata = target_metadata.get(target_key)
            metadata = metadata if isinstance(metadata, dict) else {}
            category = clean_text(
                source.get("category") or metadata.get("site_category")
                or metadata.get("category") or "", 512,
            )
            raw_lineage = source.get("category_lineage", [])
            lineage = []
            if isinstance(raw_lineage, list):
                lineage.extend(
                    clean_text(value, 512) for value in raw_lineage
                    if str(value or "").strip()
                )
            current = category
            while current and current not in lineage and len(lineage) < 64:
                lineage.append(current)
                current = clean_text(category_parents.get(current), 512)
            return category, list(dict.fromkeys(lineage))[:64]

        def clean_text(value, maximum):
            value = str(value or "").strip()
            if any(ord(character) < 32 for character in value):
                raise ValueError("texte de session invalide")
            return value[:maximum]

        def normalized_record(source, forced_kind=None, point=False):
            if not isinstance(source, dict):
                raise ValueError("session non objet")
            kind = clean_text(forced_kind or source.get("kind"), 32)
            if kind not in TIMELINE_SESSION_KINDS:
                raise ValueError("type de session inconnu")
            opened, closed = parsed_period(source, point=point)
            inherited = inherited_identity(source, opened, closed)
            identity = resolve_identity(source, inherited=inherited)
            if not identity:
                return None
            sid, username = identity
            if kind == "windows_session":
                target_key, label = "computer:session", "Session Windows"
            elif kind == "system_event":
                target_key = "computer:event"
                label = clean_text(source.get("type") or source.get("label"), 1024)
            else:
                target_key = clean_text(source.get("key"), 1024)
                metadata = target_metadata.get(target_key)
                metadata = metadata if isinstance(metadata, dict) else {}
                label = clean_text(
                    source.get("label") or metadata.get("label") or target_key,
                    1024,
                )
            if not target_key:
                raise ValueError("cible de session absente")
            category, lineage = category_fields(source, target_key)
            local_id = clean_text(
                source.get("id") or source.get("type")
                or f"legacy:{kind}:{target_key}", 512,
            )
            windows_session_id = clean_text(
                source.get("windows_session_id")
                if source.get("windows_session_id") is not None
                else source.get("session_id"), 128,
            )
            origin = clean_text(source.get("source") or "legacy-activity-store", 128)
            try:
                revision = max(0, int(source.get("policy_revision") or 0))
            except (TypeError, ValueError):
                revision = 0
            return {
                "windows_sid": sid, "usage_guard_username": username,
                "kind": kind, "id": local_id, "key": target_key,
                "label": label, "category": category,
                "category_lineage": lineage,
                "started_at": opened.isoformat(timespec="milliseconds"),
                "ended_at": closed.isoformat(timespec="milliseconds"),
                "windows_session_id": windows_session_id,
                "started_before_tracking": int(bool(
                    source.get("started_before_tracking", False)
                )),
                "source": origin, "policy_revision": revision,
            }

        migrated = skipped = 0
        pending = catalog_pending
        sessions_source = activity.get("sessions", [])
        if not isinstance(sessions_source, list):
            sessions_source = []
        events_source = activity.get("system_events", [])
        if not isinstance(events_source, list):
            events_source = []

        daily_rows = []
        for metric_kind, field in (
            ("active", "days"), ("passive", "passive_days"),
            ("system", "system_days"),
        ):
            source_days = activity.get(field, {})
            if not isinstance(source_days, dict):
                skipped += 1
                continue
            for day, values in source_days.items():
                if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(day or "")):
                    skipped += 1
                    continue
                try:
                    datetime.fromisoformat(str(day)).date()
                except ValueError:
                    skipped += 1
                    continue
                if not isinstance(values, dict):
                    skipped += 1
                    continue
                for key, value in values.items():
                    try:
                        metric_key = clean_text(key, 1024)
                        seconds = float(value or 0)
                    except (TypeError, ValueError):
                        skipped += 1
                        continue
                    if (
                        not metric_key or not math.isfinite(seconds)
                        or seconds < 0
                    ):
                        skipped += 1
                        continue
                    if seconds:
                        daily_rows.append((
                            str(day), metric_kind, metric_key, seconds,
                        ))
        other_site_days = activity.get("other_site_days", {})
        if isinstance(other_site_days, dict):
            for browser, browser_days in other_site_days.items():
                if not isinstance(browser_days, dict):
                    skipped += 1
                    continue
                for day, hosts in browser_days.items():
                    try:
                        datetime.fromisoformat(str(day)).date()
                    except (TypeError, ValueError):
                        skipped += 1
                        continue
                    if not isinstance(hosts, dict):
                        skipped += 1
                        continue
                    for host, value in hosts.items():
                        try:
                            metric_key = clean_text(
                                f"site:{str(browser).lower()}:"
                                f"{str(host).lower()}", 1024,
                            )
                            seconds = float(value or 0)
                        except (TypeError, ValueError):
                            skipped += 1
                            continue
                        if metric_key and math.isfinite(seconds) and seconds > 0:
                            daily_rows.append((
                                str(day), "other_site", metric_key, seconds,
                            ))

        def legacy_records():
            # Yield one source at a time so the decoded archive is never
            # duplicated into another unbounded in-memory list.
            for source in sessions_source:
                if isinstance(source, dict) and source.get("ended_at"):
                    yield source, None, False
            for item in closed_windows:
                yield item["source"], "windows_session", False
            for source in events_source:
                if isinstance(source, dict) and source.get("at"):
                    yield source, "system_event", True

        now = utc_now()
        daily_aggregates_migrated = not daily_rows
        try:
            with self._lock, self.connect() as db:
                daily_identity = resolve_identity({}) if daily_rows else None
                if daily_identity:
                    _, daily_username = daily_identity
                    db.execute(
                        "DELETE FROM activity_daily_legacy WHERE device_id=?",
                        (device_id,),
                    )
                    db.executemany(
                        "INSERT INTO activity_daily_legacy(device_id,"
                        "usage_guard_username,local_day,metric_kind,metric_key,"
                        "seconds) VALUES(?,?,?,?,?,?)",
                        [
                            (
                                device_id, daily_username, day, kind, key,
                                seconds,
                            )
                            for day, kind, key, seconds in daily_rows
                        ],
                    )
                    migrated += len(daily_rows)
                    daily_aggregates_migrated = True
                elif daily_rows:
                    pending += len(daily_rows)
                for source, forced_kind, point in legacy_records():
                    try:
                        record = normalized_record(
                            source, forced_kind=forced_kind, point=point,
                        )
                    except (TypeError, ValueError):
                        skipped += 1
                        continue
                    if record is None:
                        pending += 1
                        continue
                    timeline_identity = {
                        key: record[key] for key in (
                            "windows_sid", "kind", "id", "key", "label",
                            "category", "category_lineage", "started_at",
                            "ended_at", "windows_session_id",
                            "started_before_tracking", "source",
                        )
                    }
                    record_id = self._legacy_migration_id(
                        "legacy-timeline-", timeline_identity,
                    )
                    if not is_other_sites_usage_key(record["key"]):
                        db.execute(
                            "INSERT OR IGNORE INTO activity_timeline_sessions("
                            "device_id,record_id,windows_sid,"
                            "usage_guard_username,session_kind,session_id,"
                            "target_key,label,category_key,category_lineage,"
                            "started_at,ended_at,windows_session_id,"
                            "started_before_tracking,source,received_at) "
                            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (
                                device_id, record_id, record["windows_sid"],
                                record["usage_guard_username"], record["kind"],
                                record["id"], record["key"], record["label"],
                                record["category"], json.dumps(
                                    record["category_lineage"],
                                    ensure_ascii=False, separators=(",", ":"),
                                ), record["started_at"], record["ended_at"],
                                record["windows_session_id"],
                                record["started_before_tracking"],
                                record["source"], now,
                            ),
                        )
                    if record["kind"] == "active" and record["key"].startswith(
                        ("app:", "site:", "category:", "computer:")
                    ):
                        interval_identity = {
                            key: record[key] for key in (
                                "windows_sid", "key", "category",
                                "category_lineage", "started_at", "ended_at",
                                "policy_revision",
                            )
                        }
                        interval_id = self._legacy_migration_id(
                            "legacy-activity-", interval_identity,
                        )
                        db.execute(
                            "INSERT OR IGNORE INTO activity_intervals("
                            "device_id,interval_id,windows_sid,"
                            "usage_guard_username,target_key,category_key,"
                            "started_at,ended_at,policy_revision,received_at) "
                            "VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (
                                device_id, interval_id, record["windows_sid"],
                                record["usage_guard_username"], record["key"],
                                record["category"], record["started_at"],
                                record["ended_at"], record["policy_revision"],
                                now,
                            ),
                        )
                        db.executemany(
                            "INSERT OR IGNORE INTO activity_interval_categories("
                            "device_id,interval_id,category_key) VALUES(?,?,?)",
                            [
                                (device_id, interval_id, category)
                                for category in record["category_lineage"]
                            ],
                        )
                    migrated += 1
                status = "completed" if pending == 0 else "pending"
                stamp = utc_now()
                error = catalog_error or (
                    "Certaines sessions attendent une association Windows sûre."
                    if pending else ""
                )
                db.execute(
                    "INSERT INTO activity_store_migrations(device_id,"
                    "payload_hash,source_updated_at,status,migrated_records,pending_records,"
                    "skipped_records,daily_aggregates_migrated,updated_at,"
                    "completed_at,last_error) VALUES(?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(device_id) DO "
                    "UPDATE SET payload_hash=excluded.payload_hash,"
                    "source_updated_at=excluded.source_updated_at,"
                    "status=excluded.status,"
                    "migrated_records=excluded.migrated_records,"
                    "pending_records=excluded.pending_records,"
                    "skipped_records=excluded.skipped_records,"
                    "daily_aggregates_migrated="
                    "excluded.daily_aggregates_migrated,"
                    "updated_at=excluded.updated_at,"
                    "completed_at=excluded.completed_at,"
                    "last_error=excluded.last_error",
                    (
                        device_id, payload_hash, source_updated_at, status,
                        migrated, pending,
                        skipped, int(daily_aggregates_migrated), stamp,
                        stamp if status == "completed" else None,
                        error[:500],
                    ),
                )
                self._apply_activity_target_deletion_seals(
                    db, device_id=device_id,
                )
        except (OSError, sqlite3.Error) as error:
            self._save_activity_store_migration_marker(
                device_id, payload_hash, source_updated_at, "failed", 0,
                pending, skipped,
                "Migration locale interrompue: " + str(error),
            )
            return {
                "status": "failed", "migrated_records": 0,
                "pending_records": pending, "skipped_records": skipped,
            }
        return {
            "status": status, "migrated_records": migrated,
            "pending_records": pending, "skipped_records": skipped,
        }

    def patch_activity_store(
        self, device_id, delta, base_hash, target_hash, complete=None,
    ):
        current, _ = self._load_document("activity_stores", device_id)
        if current is None:
            raise DocumentConflict("Document de base absent")
        if json_hash(current) != str(base_hash or ""):
            raise DocumentConflict("Document distant modifié")
        updated = apply_json_delta(current, delta)
        if json_hash(updated) != str(target_hash or ""):
            raise ValueError("Hash cible incohérent")
        if complete is not True and self._legacy_activity_store_is_partial(
            current, updated
        ):
            # Force a legacy client to rebase/fall back to a full POST, where
            # the partial merge can safely close open sessions.
            raise DocumentConflict("Mise à jour d’activité partielle refusée")
        self._save_document("activity_stores", device_id, updated)
        migration = self.migrate_legacy_activity_stores(
            device_id=device_id, force=True,
        )
        if not int(migration.get("pending_records") or 0):
            self._persist_without_other_sites_timeline(
                "activity_stores", device_id, updated,
            )

    def activity_store(self, device_id):
        payload, updated_at = self._load_document("activity_stores", device_id)
        if payload:
            # The legacy blob stays byte-for-byte in the server archive: it is
            # never retransferred or rewritten just to delete one target.
            # Any remaining read-only compatibility fallback is sanitized in
            # memory from the durable deletion seals instead.
            payload = self._snapshot_sanitized_by_deletion_seals(
                device_id, payload, include_released=True,
            )
        return ({"activity": payload, "updated_at": updated_at} if payload else None)

    @staticmethod
    def _valid_email_address(value, label):
        value = str(value or "").strip()
        address = parseaddr(value)[1]
        if value and (not address or "@" not in address or "\n" in value or "\r" in value):
            raise ValueError(f"{label} invalide.")
        return value

    def configure_email_encryption_key(self, secret):
        secret = str(secret or "").encode("utf-8")
        if len(secret) < 32:
            raise ValueError("Clé de chiffrement e-mail trop courte.")
        self._email_encryption_key = hashlib.sha256(
            b"usage-guard-email-settings\0" + secret
        ).digest()
        self._migrate_document_recipients()

    def _protect_document_recipients(self, document):
        protected = copy.deepcopy(document)

        def walk(value):
            if isinstance(value, dict):
                recipient = str(value.pop("email_recipient", "") or "").strip()
                if recipient:
                    value["email_recipient_protected"] = self._encrypt_email_settings({
                        "recipient": recipient,
                    })
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(protected)
        return protected

    def _unprotect_document_recipients(self, document):
        clear = copy.deepcopy(document)

        def walk(value):
            if isinstance(value, dict):
                protected = value.get("email_recipient_protected")
                if protected and not value.get("email_recipient"):
                    value["email_recipient"] = str(
                        self._decrypt_email_settings(protected).get("recipient", "")
                    )
                    value.pop("email_recipient_protected", None)
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(clear)
        return clear

    def _migrate_document_recipients(self):
        with self._lock, self.connect() as db:
            for table in (
                "snapshots", "activity_stores", "device_notification_policies",
            ):
                rows = db.execute(
                    f"SELECT device_id,payload FROM {table}"
                ).fetchall()
                for row in rows:
                    if '"email_recipient"' not in row["payload"]:
                        continue
                    protected = json.dumps(
                        self._protect_document_recipients(
                            json.loads(row["payload"])
                        ),
                        ensure_ascii=False, separators=(",", ":"),
                    )
                    db.execute(
                        f"UPDATE {table} SET payload=? WHERE device_id=?",
                        (protected, row["device_id"]),
                    )

    def _email_keys(self):
        if self._email_encryption_key is None:
            raise RuntimeError("Clé de chiffrement e-mail non configurée.")
        encryption = hmac.new(self._email_encryption_key, b"encryption", hashlib.sha256).digest()
        authentication = hmac.new(self._email_encryption_key, b"authentication", hashlib.sha256).digest()
        return encryption, authentication

    @staticmethod
    def _xor_email_payload(payload, key, nonce):
        output = bytearray(len(payload))
        offset = 0
        counter = 0
        while offset < len(payload):
            stream = hmac.new(
                key, nonce + counter.to_bytes(8, "big"), hashlib.sha256
            ).digest()
            chunk = min(len(stream), len(payload) - offset)
            for index in range(chunk):
                output[offset + index] = payload[offset + index] ^ stream[index]
            offset += chunk
            counter += 1
        return bytes(output)

    def _encrypt_email_settings(self, settings):
        encryption_key, authentication_key = self._email_keys()
        nonce = secrets.token_bytes(16)
        clear = json.dumps(
            settings, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        encrypted = self._xor_email_payload(clear, encryption_key, nonce)
        tag = hmac.new(authentication_key, nonce + encrypted, hashlib.sha256).digest()
        return "v1." + base64.urlsafe_b64encode(nonce + encrypted + tag).decode("ascii")

    def _decrypt_email_settings(self, payload):
        if not str(payload or "").startswith("v1."):
            raise ValueError("Configuration e-mail chiffrée invalide.")
        try:
            packed = base64.urlsafe_b64decode(str(payload)[3:].encode("ascii"))
        except (ValueError, UnicodeError) as error:
            raise ValueError("Configuration e-mail chiffrée invalide.") from error
        if len(packed) < 49:
            raise ValueError("Configuration e-mail chiffrée invalide.")
        nonce, encrypted, supplied_tag = packed[:16], packed[16:-32], packed[-32:]
        encryption_key, authentication_key = self._email_keys()
        expected_tag = hmac.new(authentication_key, nonce + encrypted, hashlib.sha256).digest()
        if not hmac.compare_digest(supplied_tag, expected_tag):
            raise ValueError("Configuration e-mail chiffrée illisible.")
        clear = self._xor_email_payload(encrypted, encryption_key, nonce)
        try:
            settings = json.loads(clear.decode("utf-8"))
        except (UnicodeError, ValueError) as error:
            raise ValueError("Configuration e-mail chiffrée invalide.") from error
        if not isinstance(settings, dict):
            raise ValueError("Configuration e-mail chiffrée invalide.")
        return settings

    @staticmethod
    def _normalize_email_templates(value):
        source = value if isinstance(value, dict) else {}
        normalized = {}
        for kind in EMAIL_TEMPLATE_KINDS:
            template = source.get(kind, {})
            if not isinstance(template, dict):
                template = {}
            title = str(template.get("title") or "").strip()
            message = str(template.get("message") or "").strip()
            if len(title) > 160 or "\r" in title or "\n" in title:
                raise ValueError(
                    f"L’objet personnalisé « {kind} » est invalide ou dépasse 160 caractères."
                )
            if len(message) > 2000:
                raise ValueError(
                    f"Le message personnalisé « {kind} » dépasse 2 000 caractères."
                )
            if title or message:
                normalized[kind] = {"title": title, "message": message}
        return normalized

    @staticmethod
    def _email_template_content(settings, kind, default_title, default_message):
        canonical = EMAIL_TEMPLATE_ALIASES.get(str(kind or ""), str(kind or ""))
        template = dict(settings.get("message_templates", {}).get(canonical, {}))
        title = str(default_title or "Notification")
        message = str(default_message or "")
        replacements = {
            "{titre}": title,
            "{title}": title,
            "{message}": message,
        }
        custom_title = str(template.get("title") or "")
        custom_message = str(template.get("message") or "")
        for marker, value in replacements.items():
            custom_title = custom_title.replace(marker, value)
            custom_message = custom_message.replace(marker, value)
        return custom_title or title, custom_message or message

    def email_settings(self, include_password=False):
        with self.connect() as db:
            row = db.execute("SELECT payload,updated_at FROM email_settings WHERE id=1").fetchone()
        stored = self._decrypt_email_settings(row["payload"]) if row else {}
        settings = {**DEFAULT_EMAIL_SETTINGS, **stored}
        settings["message_templates"] = self._normalize_email_templates(
            settings.get("message_templates")
        )
        if row:
            settings["updated_at"] = row["updated_at"]
        settings["enabled"] = bool(settings["smtp_host"] and settings["sender"])
        password = str(settings.pop("password", ""))
        settings["password_configured"] = bool(password)
        if include_password:
            settings["password"] = password
        else:
            settings.pop("recipient", None)
        settings.pop("id", None)
        return settings

    def save_email_settings(self, payload):
        payload = dict(payload or {})
        current = self.email_settings(include_password=True)
        try:
            port = int(payload.get("smtp_port", current["smtp_port"]))
        except (TypeError, ValueError) as error:
            raise ValueError("Port SMTP invalide.") from error
        if not 1 <= port <= 65535:
            raise ValueError("Port SMTP invalide.")
        security = str(payload.get("security", current["security"])).strip().lower()
        if security not in EMAIL_SECURITY_MODES:
            raise ValueError("Sécurité SMTP invalide.")
        host = str(payload.get("smtp_host", current["smtp_host"])).strip()
        username = str(payload.get("username", current["username"])).strip()
        password = current.get("password", "")
        if payload.get("clear_password"):
            password = ""
        elif payload.get("password"):
            password = str(payload["password"])
        sender = self._valid_email_address(payload.get("sender", current["sender"]), "Adresse d’expédition")
        recipient = self._valid_email_address(payload.get("recipient", current["recipient"]), "Adresse de destination")
        message_templates = self._normalize_email_templates(
            payload.get("message_templates", current.get("message_templates", {}))
        )
        enabled = bool(host and sender)
        if len(host) > 255 or len(username) > 320 or len(password) > 1024:
            raise ValueError("Paramètre SMTP trop long.")
        now = utc_now()
        encrypted = self._encrypt_email_settings({
            "enabled": enabled,
            "smtp_host": host,
            "smtp_port": port,
            "security": security,
            "username": username,
            "password": password,
            "sender": sender,
            "recipient": recipient,
            "message_templates": message_templates,
        })
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO email_settings(id,payload,updated_at) VALUES(1,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                       payload=excluded.payload,updated_at=excluded.updated_at""",
                (encrypted, now),
            )
        return self.email_settings()

    def send_email_notification(
        self, title, message, recipient, force=False, kind="",
    ):
        settings = self.email_settings(include_password=True)
        if not settings["enabled"] and not force:
            return {"ok": True, "skipped": True, "reason": "disabled"}
        recipient = self._valid_email_address(recipient, "Adresse de destination")
        if not settings["smtp_host"] or not settings["sender"] or not recipient:
            raise ValueError("Configuration e-mail incomplète.")
        if not force:
            title, message = self._email_template_content(
                settings, kind, title, message
            )
        mail = EmailMessage()
        clean_title = str(title or "Notification").replace("\r", " ").replace("\n", " ").strip()[:200]
        clean_message = str(message or "")[:20000]
        mail["Subject"] = f"Usage Guard · {clean_title}"
        mail["From"] = settings["sender"]
        mail["To"] = recipient
        mail.set_content(clean_message)
        tls_context = ssl.create_default_context()
        smtp_class = smtplib.SMTP_SSL if settings["security"] == "ssl" else smtplib.SMTP
        options = {"timeout": 15}
        if settings["security"] == "ssl":
            options["context"] = tls_context
        with smtp_class(settings["smtp_host"], settings["smtp_port"], **options) as smtp:
            if settings["security"] == "starttls":
                smtp.starttls(context=tls_context)
            if settings["username"]:
                smtp.login(settings["username"], settings["password"])
            smtp.send_message(mail)
        return {"ok": True, "recipient": recipient}

    def queue(self, device_id, command):
        payload = json.dumps(command, ensure_ascii=False, separators=(",", ":"))
        with self._lock, self.connect() as db:
            cursor = db.execute("INSERT INTO commands(device_id,payload,created_at) VALUES(?,?,?)", (device_id, payload, utc_now()))
            return cursor.lastrowid

    def queue_idempotent(self, device_id, command, idempotency_key):
        key = str(idempotency_key or "").strip()
        if not key:
            key = str(uuid.uuid4())
        if not IDEMPOTENCY_KEY_PATTERN.fullmatch(key):
            raise ValueError("Clé d’idempotence invalide")
        payload = json.dumps(
            command, ensure_ascii=False, separators=(",", ":"), sort_keys=True,
        )
        snapshot = self.snapshot(device_id) or {}
        if (
            self._command_uses_limit_warning_action(command)
            and not self._device_supports_limit_warning_action(
                device_id, snapshot,
            )
        ):
            raise ValueError(
                "Le mode Avertir exige la mise à jour du client Usage Guard "
                f"sur : {self.device_display_name(device_id)}."
            )
        with self._lock, self.connect() as db:
            existing = db.execute(
                "SELECT id,payload FROM commands "
                "WHERE device_id=? AND idempotency_key=?",
                (device_id, key),
            ).fetchone()
            if existing:
                if json.loads(existing["payload"]) != json.loads(payload):
                    raise IdempotencyConflict(
                        "Cette opération existe déjà avec un contenu différent"
                    )
                return existing["id"], True

            settings = command.get("settings")
            strict_creation = (
                command.get("action") == "set_limit"
                and isinstance(settings, dict)
                and bool(settings.get("create_new"))
            )
            if strict_creation:
                rows = db.execute(
                    "SELECT id,payload,acknowledged_at,result,cancelled_at "
                    "FROM commands WHERE device_id=? ORDER BY id DESC LIMIT 200",
                    (device_id,),
                ).fetchall()
                expected = json.loads(payload)
                for row in rows:
                    if row["cancelled_at"]:
                        continue
                    candidate = json.loads(row["payload"])
                    if candidate != expected:
                        continue
                    result = json.loads(row["result"]) if row["result"] else None
                    completed = bool(row["acknowledged_at"]) and bool(
                        isinstance(result, dict) and result.get("ok")
                        and self._limit_command_reflected(
                            snapshot, candidate, result,
                        )
                    )
                    if not completed:
                        return row["id"], True

            cursor = db.execute(
                "INSERT INTO commands"
                "(device_id,payload,created_at,idempotency_key) VALUES(?,?,?,?)",
                (device_id, payload, utc_now(), key),
            )
            return cursor.lastrowid, False

    def purge_stale_commands(self):
        acknowledged_cutoff = (datetime.now(timezone.utc) - timedelta(seconds=ACKED_LIMIT_RETRY_SECONDS)).isoformat(timespec="seconds")
        delivered_cutoff = (datetime.now(timezone.utc) - timedelta(seconds=PENDING_LIMIT_VISIBLE_SECONDS)).isoformat(timespec="seconds")
        with self._lock, self.connect() as db:
            db.execute(
                "DELETE FROM commands WHERE acknowledged_at IS NOT NULL AND (acknowledged_at < ? OR created_at < ?)",
                (acknowledged_cutoff, acknowledged_cutoff),
            )
            db.execute(
                "DELETE FROM commands WHERE acknowledged_at IS NULL AND delivered_at IS NOT NULL AND (delivered_at < ? OR created_at < ?)",
                (delivered_cutoff, delivered_cutoff),
            )
            db.execute(
                "DELETE FROM commands WHERE cancelled_at IS NOT NULL "
                "AND cancelled_at < ?",
                (acknowledged_cutoff,),
            )

    def pending(self, device_id):
        snapshot = self.snapshot(device_id) or {}
        snapshot_updated_at = str(snapshot.get("backend_updated_at") or "")
        retry_cutoff = (datetime.now(timezone.utc) - timedelta(seconds=COMMAND_RETRY_SECONDS)).isoformat(timespec="seconds")
        acked_retry_cutoff = (datetime.now(timezone.utc) - timedelta(seconds=ACKED_LIMIT_RETRY_SECONDS)).isoformat(timespec="seconds")
        with self._lock, self.connect() as db:
            rows = db.execute(
                "SELECT id,payload,created_at,delivered_at,acknowledged_at,result FROM commands WHERE device_id=? AND cancelled_at IS NULL ORDER BY id LIMIT 1000",
                (device_id,),
            ).fetchall()
            superseded = self._superseded_limit_command_ids(rows)
            obsolete_ids = set(superseded)
            reflected_ids = set()
            deliver = []
            for row in rows:
                if row["id"] in superseded:
                    continue
                command = json.loads(row["payload"])
                action = command.get("action")
                acknowledged = bool(row["acknowledged_at"])
                if acknowledged and action not in REFLECTED_RETRY_ACTIONS:
                    continue
                result = json.loads(row["result"]) if row["result"] else None
                delivered_at = str(row["delivered_at"] or "")
                if (acknowledged or delivered_at) and self._limit_command_effect_present(snapshot, command, result):
                    obsolete_ids.add(row["id"])
                    reflected_ids.add(row["id"])
                    continue
                if acknowledged and isinstance(result, dict) and result.get("ok") and (
                    str(row["acknowledged_at"] or "") < acked_retry_cutoff
                    or str(row["created_at"] or "") < acked_retry_cutoff
                ):
                    obsolete_ids.add(row["id"])
                    continue
                if delivered_at:
                    # The protected service deliberately defers its HTTP
                    # acknowledgement until the desktop process has applied
                    # the command.  Catalogue mutations therefore need the
                    # same redelivery handshake as limits; otherwise the
                    # service can complete them locally while the server
                    # keeps an eternally unacknowledged delivery.
                    if action not in LIMIT_ACTIONS | CATALOG_ACTIONS:
                        continue
                    if delivered_at < acked_retry_cutoff:
                        obsolete_ids.add(row["id"])
                        continue
                    if snapshot_updated_at and delivered_at <= snapshot_updated_at and delivered_at > retry_cutoff:
                        continue
                    if delivered_at > retry_cutoff:
                        continue
                deliver.append((row, command))
                if len(deliver) >= 100:
                    break
            if obsolete_ids:
                reflected_result = json.dumps({
                    "ok": True, "phase": "reflected", "validated": True,
                }, ensure_ascii=False, separators=(",", ":"))
                db.executemany(
                    "UPDATE device_computer_block_state SET "
                    "applied_revision=desired_revision,last_result=?,updated_at=? "
                    "WHERE device_id=? AND command_id=?",
                    [
                        (reflected_result, utc_now(), device_id, command_id)
                        for command_id in reflected_ids
                    ],
                )
                db.executemany("DELETE FROM commands WHERE id=?", [(command_id,) for command_id in obsolete_ids])
            if deliver:
                db.executemany("UPDATE commands SET delivered_at=? WHERE id=?", [(utc_now(), row["id"]) for row, _ in deliver])
        return [{"id": str(row["id"]), **command} for row, command in deliver]

    def acknowledge(self, device_id, command_id, result):
        payload = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
        with self._lock, self.connect() as db:
            command_row = db.execute(
                "SELECT payload FROM commands WHERE id=? AND device_id=?",
                (command_id, device_id),
            ).fetchone()
            deletion_delivery = db.execute(
                "SELECT usage_guard_username,target_key FROM "
                "activity_target_deletion_deliveries WHERE command_id=? AND "
                "device_id=?",
                (command_id, device_id),
            ).fetchone()
            cursor = db.execute(
                "UPDATE commands SET acknowledged_at=?,result=? WHERE id=? AND device_id=?",
                (utc_now(), payload, command_id, device_id),
            )
            if cursor.rowcount == 1:
                try:
                    acknowledged_command = json.loads(
                        command_row["payload"] if command_row else "{}"
                    )
                except (TypeError, ValueError):
                    acknowledged_command = {}
                if (
                    isinstance(result, dict) and result.get("ok")
                    and acknowledged_command.get("action") in {
                        "delete_target", "delete_site",
                    }
                    and deletion_delivery
                ):
                    db.execute(
                        "UPDATE activity_target_deletion_seals SET "
                        "catalog_confirmation_after=?,updated_at=? WHERE "
                        "device_id=? AND "
                        "usage_guard_username=? AND target_key=?",
                        (
                            utc_now(), utc_now(), device_id,
                            deletion_delivery["usage_guard_username"],
                            deletion_delivery["target_key"],
                        ),
                    )
                state = db.execute(
                    "SELECT desired_revision FROM device_computer_block_state "
                    "WHERE device_id=? AND command_id=?",
                    (device_id, command_id),
                ).fetchone()
                if state:
                    applied = (
                        int(state["desired_revision"])
                        if isinstance(result, dict) and result.get("ok") else 0
                    )
                    db.execute(
                        "UPDATE device_computer_block_state SET "
                        "applied_revision=CASE WHEN ?>0 THEN ? ELSE applied_revision END,"
                        "last_result=?,updated_at=? WHERE device_id=? AND command_id=?",
                        (applied, applied, payload, utc_now(), device_id, command_id),
                    )
            return cursor.rowcount == 1

    def command_status(self, device_id, command_id):
        with self.connect() as db:
            row = db.execute(
                "SELECT id,payload,created_at,delivered_at,acknowledged_at,"
                "result,cancelled_at FROM commands WHERE id=? AND device_id=?",
                (command_id, device_id),
            ).fetchone()
        if not row:
            return None
        command = json.loads(row["payload"])
        result = json.loads(row["result"]) if row["result"] else None
        acknowledged = bool(row["acknowledged_at"])
        successful = bool(
            acknowledged and isinstance(result, dict) and result.get("ok")
        )
        reflected = successful
        if command.get("action") in REFLECTED_RETRY_ACTIONS:
            reflected = successful and self._limit_command_reflected(
                self.snapshot(device_id) or {}, command, result,
            )
        return {
            "id": str(row["id"]),
            "action": command.get("action"),
            "created_at": row["created_at"],
            "delivered": bool(row["delivered_at"]),
            "acknowledged": acknowledged,
            "result": result,
            "cancelled": bool(row["cancelled_at"]),
            "applied": bool(reflected),
        }

    def cancel_command(self, device_id, command_id):
        with self._lock, self.connect() as db:
            row = db.execute(
                "SELECT delivered_at,acknowledged_at,cancelled_at FROM commands "
                "WHERE id=? AND device_id=?",
                (command_id, device_id),
            ).fetchone()
            if not row:
                return "missing"
            if row["cancelled_at"]:
                return "cancelled"
            if row["acknowledged_at"]:
                return "acknowledged"
            if row["delivered_at"]:
                return "delivered"
            db.execute(
                "UPDATE commands SET cancelled_at=? WHERE id=? AND device_id=?",
                (utc_now(), command_id, device_id),
            )
            return "cancelled"

    def pending_limit_commands(self, device_id, snapshot):
        snapshot = snapshot or {}
        visible_cutoff = (datetime.now(timezone.utc) - timedelta(seconds=PENDING_LIMIT_VISIBLE_SECONDS)).isoformat(timespec="seconds")
        with self._lock, self.connect() as db:
            rows = db.execute(
                "SELECT id,payload,created_at,delivered_at,acknowledged_at,result FROM commands WHERE device_id=? AND cancelled_at IS NULL ORDER BY id DESC LIMIT 200",
                (device_id,),
            ).fetchall()
            superseded = self._superseded_limit_command_ids(rows)
            obsolete_ids = set(superseded)
            reflected_ids = set()
            commands = []
            for row in reversed(rows):
                if row["id"] in superseded:
                    continue
                command = json.loads(row["payload"])
                if command.get("action") not in LIMIT_ACTIONS:
                    continue
                if row["acknowledged_at"] and command.get("action") not in {
                    "set_limit", "set_computer_block", "replace_computer_blocks",
                }:
                    obsolete_ids.add(row["id"])
                    continue
                result = json.loads(row["result"]) if row["result"] else None
                completed_or_taken = bool(row["acknowledged_at"] or row["delivered_at"])
                if completed_or_taken and self._limit_command_effect_present(snapshot, command, result):
                    obsolete_ids.add(row["id"])
                    reflected_ids.add(row["id"])
                    continue
                if row["acknowledged_at"] and isinstance(result, dict) and result.get("ok") and (
                    str(row["acknowledged_at"]) < visible_cutoff
                    or str(row["created_at"] or "") < visible_cutoff
                ):
                    obsolete_ids.add(row["id"])
                    continue
                if row["delivered_at"] and not row["acknowledged_at"] and str(row["delivered_at"]) < visible_cutoff:
                    obsolete_ids.add(row["id"])
                    continue
                commands.append({
                    "id": str(row["id"]),
                    "created_at": row["created_at"],
                    "delivered": bool(row["delivered_at"]),
                    "acknowledged": bool(row["acknowledged_at"]),
                    "result": result,
                    **command,
                })
            if obsolete_ids:
                reflected_result = json.dumps({
                    "ok": True, "phase": "reflected", "validated": True,
                }, ensure_ascii=False, separators=(",", ":"))
                db.executemany(
                    "UPDATE device_computer_block_state SET "
                    "applied_revision=desired_revision,last_result=?,updated_at=? "
                    "WHERE device_id=? AND command_id=?",
                    [
                        (reflected_result, utc_now(), device_id, command_id)
                        for command_id in reflected_ids
                    ],
                )
                db.executemany("DELETE FROM commands WHERE id=?", [(command_id,) for command_id in obsolete_ids])
        return commands

    @classmethod
    def _superseded_limit_command_ids(cls, rows):
        seen = set()
        superseded = set()
        newer_computer_command = False
        newer_computer_document = False
        computer_actions = {
            "set_computer_block", "set_computer_block_enabled",
            "clear_computer_block", "replace_computer_blocks",
        }
        for row in sorted(rows, key=lambda item: int(item["id"]), reverse=True):
            command = json.loads(row["payload"])
            action = str(command.get("action") or "")
            if action == "replace_computer_blocks" and newer_computer_command:
                superseded.add(row["id"])
                continue
            if action in computer_actions and newer_computer_document:
                superseded.add(row["id"])
                continue
            keys = cls._command_supersede_keys(command)
            if not keys:
                continue
            if any(key in seen for key in keys):
                superseded.add(row["id"])
            else:
                seen.update(keys)
                if action in computer_actions:
                    newer_computer_command = True
                    newer_computer_document = action == "replace_computer_blocks"
        return superseded

    @staticmethod
    def _command_supersede_keys(command):
        action = command.get("action")
        target_key = str(command.get("target_key", ""))
        if action == "set_limit":
            settings = command.get("settings") if isinstance(command.get("settings"), dict) else {}
            measured = str(settings.get("target_key") or target_key)
            keys = {("limit", value) for value in (target_key, measured) if value}
            return keys
        if action in {"remove_limit", "reset_limit"}:
            return {("limit", target_key)} if target_key else set()
        if action == "replace_computer_blocks":
            return {("computer_blocks_document", "computer:all")}
        block_id = str(command.get("block_id") or "legacy")
        if action == "set_computer_block":
            # Enabling/disabling is a distinct transition.  A legacy client
            # receives a disabled singleton as ``set`` followed by ``disable``;
            # treating the latter as a replacement for the former drops the
            # definition before the client can disable it.
            return {("computer_block_mode", block_id)}
        if action == "set_computer_block_enabled":
            return {("computer_block_enabled", block_id)}
        if action == "clear_computer_block":
            return {
                ("computer_block_mode", block_id),
                ("computer_block_enabled", block_id),
            }
        return set()

    _command_supersede_key = _command_supersede_keys

    @staticmethod
    def _limit_enforcement_action_reflected(item, settings):
        if "enforcement_action" not in settings:
            return True
        expected = (
            "warn" if settings.get("enforcement_action") == "warn" else "block"
        )
        current = (
            "warn" if dict(item or {}).get("enforcement_action") == "warn"
            else "block"
        )
        return current == expected

    @classmethod
    def _limit_command_effect_present(cls, snapshot, command, result=None):
        if cls._limit_command_reflected(snapshot, command, result):
            return True
        action = command.get("action")
        target_key = str(command.get("target_key", ""))
        if action == "set_limit":
            settings = command.get("settings") if isinstance(command.get("settings"), dict) else {}
            measured = str(settings.get("target_key") or target_key)
            expected = {value for value in (target_key, measured) if value}
            if isinstance(result, dict) and isinstance(result.get("limit"), dict):
                expected.update(
                    str(result["limit"].get(field) or "")
                    for field in ("key", "target_key")
                )
            expected.discard("")
            return any(
                (
                    str(item.get("key") or "") in expected
                    or str(item.get("target_key") or "") in expected
                )
                and cls._limit_enforcement_action_reflected(item, settings)
                for item in snapshot.get("limits", [])
            )
        if action == "replace_computer_blocks":
            return False
        if action == "set_computer_block":
            block_id = str(command.get("block_id") or "")
            if block_id and isinstance(snapshot.get("computer_blocks"), list):
                return any(
                    str(item.get("block_id") or item.get("id") or "") == block_id
                    for item in snapshot["computer_blocks"]
                    if isinstance(item, dict)
                )
            return bool(snapshot.get("computer_block", {}).get("mode"))
        return False

    @classmethod
    def _limit_command_reflected(cls, snapshot, command, result=None):
        action = command.get("action")
        target_key = str(command.get("target_key", ""))
        if action == "set_limit":
            settings = command.get("settings") if isinstance(command.get("settings"), dict) else {}
            measured = str(settings.get("target_key") or target_key)
            if settings.get("create_new"):
                created_key = ""
                if isinstance(result, dict) and isinstance(result.get("limit"), dict):
                    created_key = str(result["limit"].get("key") or result["limit"].get("target_key") or "")
                if not created_key:
                    return False
                return any(
                    str(item.get("key") or item.get("target_key")) == created_key
                    and cls._limit_enforcement_action_reflected(item, settings)
                    for item in snapshot.get("limits", [])
                )
            return any(
                (
                    str(item.get("key") or item.get("target_key")) == target_key
                    or str(item.get("target_key")) == measured
                )
                and cls._limit_enforcement_action_reflected(item, settings)
                for item in snapshot.get("limits", [])
            )
        if action == "replace_computer_blocks":
            blocks = command.get("blocks")
            return isinstance(blocks, list) and cls._computer_block_policy_reflected(
                snapshot, {"version": 2, "blocks": blocks},
            )
        if action == "set_computer_block":
            if not isinstance(result, dict) or not isinstance(result.get("computer_block"), dict):
                return False
            expected = result["computer_block"]
            block_id = str(expected.get("block_id") or command.get("block_id") or "")
            if block_id and isinstance(snapshot.get("computer_blocks"), list):
                current = next((
                    item for item in snapshot["computer_blocks"]
                    if isinstance(item, dict) and str(
                        item.get("block_id") or item.get("id") or ""
                    ) == block_id
                ), None)
                return cls._computer_block_rule_reflected(current, expected)
            current = snapshot.get("computer_block", {})
            if not current.get("mode"):
                return False
            return all(
                str(current.get(key, "")) == str(expected.get(key, ""))
                for key in ("mode", "started_at", "ends_at")
            )
        if action == "set_computer_block_enabled":
            if not isinstance(result, dict) or not isinstance(result.get("computer_block"), dict):
                return False
            block_id = str(
                result["computer_block"].get("block_id")
                or command.get("block_id") or ""
            )
            if block_id and isinstance(snapshot.get("computer_blocks"), list):
                current = next((
                    item for item in snapshot["computer_blocks"]
                    if isinstance(item, dict) and str(
                        item.get("block_id") or item.get("id") or ""
                    ) == block_id
                ), None)
                return bool(current) and bool(
                    current.get("enabled", True)
                ) == bool(result["computer_block"].get("enabled", True))
            current = snapshot.get("computer_block", {})
            return bool(current.get("mode")) and bool(current.get("enabled", True)) == bool(result["computer_block"].get("enabled", True))
        if action == "remove_limit":
            return not any(
                str(item.get("key") or item.get("target_key")) == target_key
                for item in snapshot.get("limits", [])
            )
        if action == "clear_computer_block":
            block_id = str(command.get("block_id") or "")
            if block_id and isinstance(snapshot.get("computer_blocks"), list):
                return not any(
                    isinstance(item, dict) and str(
                        item.get("block_id") or item.get("id") or ""
                    ) == block_id for item in snapshot["computer_blocks"]
                )
            return not bool(snapshot.get("computer_block", {}).get("mode"))
        return False

    @staticmethod
    def _device_token_hash(token):
        return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()

    def register_device(self, device_id, label="", token=None, hostname=""):
        device_id = str(device_id or "").strip()
        if not device_id:
            raise ValueError("Identifiant d’appareil manquant.")
        now = utc_now()
        label = str(label or "").strip()
        hostname = str(hostname or "").strip()
        token_hash = self._device_token_hash(token) if token else ""
        with self._lock, self.connect() as db:
            db.execute(
                "INSERT INTO devices(device_id,label,created_at,updated_at,token_hash,hostname_last_seen,credential_updated_at) "
                "VALUES(?,?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET "
                "label=CASE WHEN excluded.label<>'' THEN excluded.label ELSE devices.label END,"
                "hostname_last_seen=CASE WHEN excluded.hostname_last_seen<>'' THEN excluded.hostname_last_seen ELSE devices.hostname_last_seen END,"
                "token_hash=CASE WHEN devices.token_hash='' AND devices.revoked_at IS NULL THEN excluded.token_hash ELSE devices.token_hash END,"
                "credential_updated_at=CASE WHEN devices.token_hash='' AND devices.revoked_at IS NULL AND excluded.token_hash<>'' THEN excluded.credential_updated_at ELSE devices.credential_updated_at END,"
                "updated_at=excluded.updated_at",
                (device_id, label, now, now, token_hash, hostname, now if token_hash else None),
            )
        return device_id

    def authenticate_device(self, device_id, token):
        device_id, token = str(device_id or "").strip(), str(token or "").strip()
        if not device_id or len(token) < 32:
            return False
        with self.connect() as db:
            row = db.execute(
                "SELECT token_hash,revoked_at FROM devices WHERE device_id=?",
                (device_id,),
            ).fetchone()
        expected = str(row["token_hash"] or "") if row and not row["revoked_at"] else ""
        return bool(expected) and secrets.compare_digest(
            expected, self._device_token_hash(token)
        )

    def device_display_name(self, device_id):
        device_id = str(device_id or "").strip()
        with self.connect() as db:
            row = db.execute(
                "SELECT label,hostname_last_seen FROM devices WHERE device_id=?",
                (device_id,),
            ).fetchone()
        if not row:
            return device_id
        return str(
            row["label"] or row["hostname_last_seen"] or device_id
        ).strip()

    def create_device_enrollment(
        self, actor, username=None, device_id=None, label="",
        lifetime=ENROLLMENT_SECONDS, windows_identities=None,
    ):
        actor = validate_username(actor)
        username = validate_username(username) if str(username or "").strip() else None
        device_id = str(device_id or "").strip() or str(uuid.uuid4())
        label = str(label or "").strip()
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=max(60, min(int(lifetime), 24 * 60 * 60)))
        raw_code = secrets.token_urlsafe(18)
        code_hash = self._device_token_hash(raw_code)
        with self._lock, self.connect() as db:
            if username and not db.execute(
                "SELECT 1 FROM users WHERE username=?", (username,)
            ).fetchone():
                raise ValueError("Utilisateur inconnu.")
            existing = db.execute(
                "SELECT 1 FROM devices WHERE device_id=?", (device_id,)
            ).fetchone()
            if not existing:
                stamp = now.isoformat(timespec="seconds")
                db.execute(
                    "INSERT INTO devices(device_id,label,created_at,updated_at) VALUES(?,?,?,?)",
                    (device_id, label, stamp, stamp),
                )
            elif label:
                db.execute(
                    "UPDATE devices SET label=?,updated_at=? WHERE device_id=?",
                    (label, now.isoformat(timespec="seconds"), device_id),
                )
            if windows_identities is not None:
                if not isinstance(windows_identities, list) or not windows_identities:
                    raise ValueError("Associez au moins un compte Windows existant.")
                self._replace_device_windows_identities(
                    db, device_id, windows_identities, actor,
                )
            if username:
                db.execute(
                    "INSERT OR IGNORE INTO user_devices(username,device_id) VALUES(?,?)",
                    (username, device_id),
                )
            db.execute(
                "DELETE FROM device_enrollments WHERE used_at IS NOT NULL OR expires_at<?",
                (now.isoformat(timespec="seconds"),),
            )
            db.execute(
                "INSERT INTO device_enrollments(code_hash,device_id,username,created_by,created_at,expires_at) VALUES(?,?,?,?,?,?)",
                (code_hash, device_id, username, actor, now.isoformat(timespec="seconds"), expires.isoformat(timespec="seconds")),
            )
        return {
            "code": raw_code, "device_id": device_id, "username": username,
            "label": label, "expires_at": expires.isoformat(timespec="seconds"),
            "windows_identities": self.device_windows_identities(device_id),
        }

    def consume_device_enrollment(self, code, hostname="", label=""):
        code = str(code or "").strip()
        if len(code) < 16:
            raise ValueError("Code d’enrôlement invalide.")
        code_hash = self._device_token_hash(code)
        now = datetime.now(timezone.utc)
        token = secrets.token_urlsafe(48)
        token_hash = self._device_token_hash(token)
        hostname, label = str(hostname or "").strip(), str(label or "").strip()
        with self._lock, self.connect() as db:
            row = db.execute(
                "SELECT device_id,username,expires_at,used_at FROM device_enrollments WHERE code_hash=?",
                (code_hash,),
            ).fetchone()
            if not row or row["used_at"] or row["expires_at"] < now.isoformat(timespec="seconds"):
                raise ValueError("Code d’enrôlement invalide ou expiré.")
            device = db.execute(
                "SELECT label FROM devices WHERE device_id=?", (row["device_id"],)
            ).fetchone()
            if not device:
                raise ValueError("Appareil d’enrôlement introuvable.")
            visible_name = label or hostname or str(device["label"] or "") or row["device_id"]
            stamp = now.isoformat(timespec="seconds")
            db.execute(
                "UPDATE devices SET label=?,hostname_last_seen=?,token_hash=?,credential_updated_at=?,revoked_at=NULL,updated_at=? WHERE device_id=?",
                (visible_name, hostname, token_hash, stamp, stamp, row["device_id"]),
            )
            db.execute(
                "UPDATE device_enrollments SET used_at=? WHERE code_hash=? AND used_at IS NULL",
                (stamp, code_hash),
            )
        return {
            "device_id": row["device_id"], "device_token": token,
            "display_name": visible_name, "hostname": hostname,
            "username": row["username"],
            "windows_identities": self.device_windows_identities(row["device_id"]),
        }

    @staticmethod
    def _normalized_windows_identity(source):
        source = dict(source or {})
        sid = str(
            source.get("windows_sid") or source.get("sid") or ""
        ).strip().upper()
        if not re.fullmatch(r"S-\d+(?:-\d+)+", sid):
            raise ValueError("SID Windows invalide.")
        usage_username = validate_username(
            source.get("usage_guard_username") or source.get("username")
        )
        windows_username = str(source.get("windows_username") or "").strip()
        windows_domain = str(source.get("windows_domain") or "").strip()
        if not windows_username or len(windows_username) > 256:
            raise ValueError("Compte Windows invalide.")
        if len(windows_domain) > 256 or any(
            ord(character) < 32
            for character in windows_domain + windows_username
        ):
            raise ValueError("Nom de compte Windows invalide.")
        return {
            "windows_sid": sid,
            "usage_guard_username": usage_username,
            "windows_domain": windows_domain,
            "windows_username": windows_username,
            "is_windows_admin": bool(source.get("is_windows_admin")),
        }

    @classmethod
    def _replace_device_windows_identities(
        cls, db, device_id, identities, actor,
    ):
        normalized = [
            cls._normalized_windows_identity(item) for item in identities
        ]
        sids = [item["windows_sid"].casefold() for item in normalized]
        usernames = [
            item["usage_guard_username"].casefold() for item in normalized
        ]
        if len(sids) != len(set(sids)):
            raise ValueError("Un compte Windows est associé plusieurs fois.")
        if len(usernames) != len(set(usernames)):
            raise ValueError(
                "Un utilisateur Usage Guard ne peut correspondre qu’à un compte Windows sur ce PC."
            )
        known_users = {
            row["username"].casefold(): str(row["role"] or "")
            for row in db.execute("SELECT username,role FROM users").fetchall()
        }
        if not set(usernames) <= set(known_users):
            raise ValueError("Un utilisateur Usage Guard associé est inconnu.")
        if any(known_users[username] != "limited" for username in usernames):
            raise ValueError(
                "Un compte Windows doit être associé à un utilisateur à limiter."
            )
        now = utc_now()
        db.execute(
            "DELETE FROM device_windows_identities WHERE device_id=?",
            (device_id,),
        )
        db.executemany(
            "INSERT INTO device_windows_identities("
            "device_id,windows_sid,usage_guard_username,windows_domain,"
            "windows_username,is_windows_admin,created_by,created_at,updated_at"
            ") VALUES(?,?,?,?,?,?,?,?,?)",
            [(
                device_id, item["windows_sid"],
                item["usage_guard_username"], item["windows_domain"],
                item["windows_username"], int(item["is_windows_admin"]),
                actor, now, now,
            ) for item in normalized],
        )
        db.executemany(
            "INSERT OR IGNORE INTO user_devices(username,device_id) VALUES(?,?)",
            [
                (item["usage_guard_username"], device_id)
                for item in normalized
            ],
        )
        if normalized:
            placeholders = ",".join("?" for _ in normalized)
            db.execute(
                "DELETE FROM device_policy_state WHERE device_id=? "
                f"AND usage_guard_username NOT IN ({placeholders})",
                (
                    device_id,
                    *(item["usage_guard_username"] for item in normalized),
                ),
            )
        else:
            db.execute(
                "DELETE FROM device_policy_state WHERE device_id=?",
                (device_id,),
            )
        for item in normalized:
            revision = int(db.execute(
                "SELECT COALESCE(MAX(revision),0) FROM user_policy_revisions "
                "WHERE usage_guard_username=?",
                (item["usage_guard_username"],),
            ).fetchone()[0])
            db.execute(
                "INSERT INTO device_policy_state(device_id,"
                "usage_guard_username,desired_revision,applied_revision,"
                "last_result,updated_at) VALUES(?,?,?,0,NULL,?) "
                "ON CONFLICT(device_id,usage_guard_username) DO UPDATE SET "
                "desired_revision=excluded.desired_revision,"
                "updated_at=excluded.updated_at",
                (device_id, item["usage_guard_username"], revision, now),
            )
        return normalized

    def set_device_windows_identities(self, device_id, identities, actor):
        device_id = str(device_id or "").strip()
        actor = validate_username(actor)
        if not isinstance(identities, list):
            raise ValueError("Liste d’identités Windows invalide.")
        with self._lock, self.connect() as db:
            if not db.execute(
                "SELECT 1 FROM devices WHERE device_id=?", (device_id,)
            ).fetchone():
                raise ValueError("Ordinateur inconnu.")
            self._replace_device_windows_identities(
                db, device_id, identities, actor,
            )
        # A startup migration can legitimately be pending until an admin maps
        # the Windows account.  Retry immediately after that mapping commits;
        # stable row IDs make the already-normalized part replay-safe.
        self.migrate_legacy_activity_stores(device_id=device_id)
        return self.device_windows_identities(device_id)

    def device_windows_identities(self, device_id):
        device_id = str(device_id or "").strip()
        with self.connect() as db:
            rows = db.execute(
                "SELECT windows_sid,usage_guard_username,windows_domain,"
                "windows_username,is_windows_admin,created_by,created_at,updated_at "
                "FROM device_windows_identities WHERE device_id=? "
                "ORDER BY windows_domain COLLATE NOCASE,windows_username COLLATE NOCASE",
                (device_id,),
            ).fetchall()
        return [{
            **dict(row),
            "is_windows_admin": bool(row["is_windows_admin"]),
        } for row in rows]

    def user_for_windows_sid(self, device_id, windows_sid):
        sid = str(windows_sid or "").strip().upper()
        if not re.fullmatch(r"S-\d+(?:-\d+)+", sid):
            return None
        with self.connect() as db:
            row = db.execute(
                "SELECT usage_guard_username,windows_domain,windows_username,"
                "is_windows_admin FROM device_windows_identities "
                "WHERE device_id=? AND windows_sid=?",
                (str(device_id or "").strip(), sid),
            ).fetchone()
        if not row:
            return None
        return {
            **dict(row), "windows_sid": sid,
            "is_windows_admin": bool(row["is_windows_admin"]),
        }

    @staticmethod
    def _policy_payload(policy):
        if not isinstance(policy, dict):
            raise ValueError("Politique utilisateur invalide.")
        encoded = json.dumps(
            policy, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        )
        if len(encoded.encode("utf-8")) > MAX_BODY:
            raise ValueError("Politique utilisateur trop volumineuse.")
        return encoded

    def _normalized_policy_document(self, policy):
        source = dict(policy or {})
        mode = str(source.get("enforcement_mode") or "enforced").strip().lower()
        if mode not in {"shadow", "enforced"}:
            raise ValueError("Mode d’application de politique invalide.")
        limits = source.get("limits", [])
        if not isinstance(limits, list):
            raise ValueError("Limites de politique invalides.")
        normalized = [self._policy_limit(item) for item in limits]
        keys = [item["key"] for item in normalized]
        if len(keys) != len(set(keys)):
            raise ValueError("Une politique contient une limite en double.")
        return {
            **source, "enforcement_mode": "enforced", "limits": normalized,
        }

    @staticmethod
    def _policy_limit(source):
        source = dict(source or {})
        key = str(source.get("key") or source.get("target_key") or "").strip()
        target = str(source.get("target_key") or key).strip()
        name = str(source.get("name") or "").strip()
        if len(name) > 120:
            raise ValueError(
                "Le nom de la limitation ne peut pas dépasser 120 caractères."
            )
        if not key.startswith(("app:", "site:", "category:")) or not target.startswith(
            ("app:", "site:", "category:")
        ):
            raise ValueError("Cible de politique non prise en charge.")
        device_ids = source.get("device_ids")
        if device_ids is not None and not isinstance(device_ids, list):
            raise ValueError("Périmètre d’ordinateurs de la limite invalide.")
        normalized_device_ids = sorted({
            str(device_id).strip() for device_id in (device_ids or [])
            if str(device_id).strip()
        })
        if device_ids is not None and not normalized_device_ids:
            raise ValueError("Sélectionnez au moins un ordinateur pour la limite.")
        return {
            "key": key,
            **({"operation_id": str(source["operation_id"])}
               if source.get("operation_id") else {}),
            **{
                field: source[field] for field in POLICY_LIMIT_FIELDS
                if field in source
            },
            **({"name": name} if name else {}),
            "enforcement_action": (
                "warn" if source.get("enforcement_action") == "warn" else "block"
            ),
            "target_key": target,
            **({"device_ids": normalized_device_ids}
               if device_ids is not None else {}),
        }

    def _initial_user_policy(self, username, base_device_id):
        base_device_id = str(base_device_id or "").strip()
        if not base_device_id:
            return {"enforcement_mode": "enforced", "limits": []}
        mapping = any(
            item.get("usage_guard_username", "").casefold()
            == str(username).casefold()
            for item in self.device_windows_identities(base_device_id)
        )
        if not mapping:
            raise ValueError(
                "L’ordinateur de référence n’est pas associé à cette personne."
            )
        snapshot = self.snapshot(base_device_id) or {}
        limits = snapshot.get("limits") or []
        if not isinstance(limits, list):
            raise ValueError("Limites de référence invalides.")
        return {
            "enforcement_mode": "enforced",
            "limits": [self._policy_limit(item) for item in limits],
        }

    def mutate_user_policy(
        self, username, command, actor, base_device_id="",
        idempotency_key="",
    ):
        """Apply an existing limit command to one person's policy document."""
        command = dict(command or {})
        action = str(command.get("action") or "")
        if action not in {"set_limit", "remove_limit"}:
            raise ValueError("Mutation de politique non prise en charge.")
        current = self.user_policy(username)
        policy = json.loads(json.dumps(current.get("policy"))) if (
            current and current.get("configured")
        ) else self._initial_user_policy(username, base_device_id)
        limits = [
            self._policy_limit(item) for item in policy.get("limits", [])
        ]
        policy = {**dict(policy), "enforcement_mode": "enforced"}
        target_key = str(command.get("target_key") or "").strip()
        if action == "remove_limit":
            if not any(item["key"] == target_key for item in limits):
                raise ValueError("Cette limite n’existe pas dans la politique.")
            limits = [item for item in limits if item["key"] != target_key]
        else:
            settings = dict(command.get("settings") or {})
            settings_has_enforcement_action = "enforcement_action" in settings
            if "device_ids" in command:
                settings["device_ids"] = self.selected_user_device_ids(
                    username, command.get("device_ids"),
                )
            create_new = bool(settings.pop("create_new", False))
            measured = str(settings.get("target_key") or target_key).strip()
            candidate = self._policy_limit({
                "key": target_key, **settings, "target_key": measured,
            })
            existing = next((
                item for item in limits if item["key"] == target_key
            ), None)
            if create_new:
                operation = str(idempotency_key or "").strip()
                if not operation:
                    raise ValueError(
                        "Identifiant d’opération requis pour cette limite."
                    )
                replay = next((
                    item for item in limits
                    if item.get("operation_id") == operation
                ), None)
                if replay:
                    candidate["key"] = replay["key"]
                    candidate["operation_id"] = operation
                    existing = replay
                else:
                    candidate["operation_id"] = operation
                    if existing:
                        suffix = hashlib.sha256(
                            operation.encode("utf-8")
                        ).hexdigest()[:8]
                        candidate["key"] = f"{measured}#{suffix}"
                        existing = next((
                            item for item in limits
                            if item["key"] == candidate["key"]
                        ), None)
            replayed = bool(
                existing and create_new and candidate.get("operation_id")
                and candidate.get("operation_id") == existing.get("operation_id")
            )
            if existing and not settings_has_enforcement_action:
                candidate["enforcement_action"] = existing.get(
                    "enforcement_action", "block",
                )
            changed_at = utc_now()
            requested_by = (
                existing.get("requested_by") or existing.get("actor")
                if existing else str(actor or "").strip()
            )
            requested_at = (
                existing.get("requested_at") or existing.get("updated_at")
                if existing else changed_at
            )
            candidate = self._policy_limit({
                **candidate,
                "actor": (
                    existing.get("actor", "") if replayed
                    else str(actor or "").strip()
                ),
                "updated_at": (
                    existing.get("updated_at", "") if replayed else changed_at
                ),
                "requested_by": requested_by,
                "requested_at": requested_at,
            })
            if existing:
                candidate = self._policy_limit({**existing, **candidate})
                limits = [
                    candidate if item["key"] == existing["key"] else item
                    for item in limits
                ]
            else:
                limits.append(candidate)
        policy = {**dict(policy), "limits": limits}
        return self.save_user_policy(username, policy, actor)

    def begin_user_policy_operation(
        self, username, command, actor, base_device_id="",
        idempotency_key="",
    ):
        """Create one durable, replay-safe personal-policy mutation."""
        username = str(username or "").strip()
        operation_key = str(idempotency_key or "").strip()
        if not operation_key or len(operation_key) > 200:
            raise ValueError("Identifiant d’opération invalide.")
        with self._policy_operation_lock:
            with self.connect() as db:
                existing = db.execute(
                    "SELECT id FROM user_policy_operations WHERE "
                    "usage_guard_username=? AND idempotency_key=?",
                    (username, operation_key),
                ).fetchone()
            if existing:
                return {**self.user_policy_operation(
                    username, int(existing["id"]),
                ), "reused": True}
            current = self.user_policy(username)
            before = (
                current.get("policy")
                if current and current.get("configured")
                else {"enforcement_mode": "enforced", "limits": []}
            )
            saved = self.mutate_user_policy(
                username, command, actor, base_device_id, operation_key,
            )
            catalog_sync = self.reconcile_user_policy_catalog(
                username, saved, actor="synchronisation de politique",
            )
            with self._lock, self.connect() as db:
                cursor = db.execute(
                    "INSERT INTO user_policy_operations("
                    "usage_guard_username,idempotency_key,actor,before_payload,"
                    "target_revision,created_at) VALUES(?,?,?,?,?,?)",
                    (
                        saved["usage_guard_username"], operation_key, actor,
                        self._policy_payload(before), int(saved["revision"]),
                        utc_now(),
                    ),
                )
                operation_id = int(cursor.lastrowid)
            return {
                **self.user_policy_operation(
                    saved["usage_guard_username"], operation_id,
                ),
                "catalog_sync": catalog_sync,
                "reused": False,
            }

    @staticmethod
    def _mutation_actor_username(actor):
        """Recover the authenticated account from a device-qualified actor."""
        value = str(actor or "").strip()
        if value.casefold().startswith("appareil ") and " · " in value:
            return value.rsplit(" · ", 1)[-1].strip()
        return value

    def user_policy_mutation_owner(self, username, command):
        """Return the original requester when a mutation targets an existing rule."""
        command = dict(command or {})
        action = str(command.get("action") or "")
        if action in {
            "set_computer_block", "set_computer_block_enabled",
            "clear_computer_block",
        }:
            policy = self.user_computer_block_policy(username) or {}
            blocks = list(policy.get("blocks") or [])
            block_id = str(command.get("block_id") or "")
            if action == "set_computer_block" and not block_id:
                return ""
            item = next((
                block for block in blocks
                if str(block.get("block_id") or "") == block_id
            ), None) if block_id else (blocks[0] if len(blocks) == 1 else None)
            return self._mutation_actor_username(
                (item or {}).get("actor") or policy.get("actor") or ""
            )
        if action not in {"set_limit", "remove_limit"}:
            return ""
        policy = self.user_policy(username) or {}
        target_key = str(command.get("target_key") or "")
        item = next((
            limit for limit in dict(policy.get("policy") or {}).get("limits", [])
            if str(limit.get("key") or "") == target_key
        ), None)
        return self._mutation_actor_username(
            (item or {}).get("requested_by") or (item or {}).get("actor") or ""
        )

    def user_policy_operation(self, username, operation_id):
        username = str(username or "").strip()
        try:
            operation_id = int(operation_id)
        except (TypeError, ValueError):
            return None
        with self.connect() as db:
            row = db.execute(
                "SELECT id,usage_guard_username,idempotency_key,actor,"
                "target_revision,rollback_revision,status,created_at,"
                "cancelled_at FROM user_policy_operations WHERE id=? AND "
                "usage_guard_username=?",
                (operation_id, username),
            ).fetchone()
        if not row:
            return None
        policy = self.user_policy(row["usage_guard_username"])
        revision = (
            int(row["rollback_revision"])
            if row["status"] == "cancelled"
            else int(row["target_revision"])
        )
        devices = list((policy or {}).get("devices") or [])
        pending = [
            item for item in devices
            if int(item.get("applied_revision") or 0) < revision
        ]
        failed = [
            item for item in pending
            if isinstance(item.get("last_result"), dict)
            and item["last_result"].get("ok") is False
            and int(item.get("desired_revision") or 0) >= revision
        ]
        return {
            "id": str(row["id"]),
            "usage_guard_username": row["usage_guard_username"],
            "idempotency_key": row["idempotency_key"],
            "actor": row["actor"],
            "status": row["status"],
            "target_revision": int(row["target_revision"]),
            "rollback_revision": int(row["rollback_revision"]),
            "revision": revision,
            "created_at": row["created_at"],
            "cancelled_at": row["cancelled_at"],
            "complete": not pending,
            "pending_devices": [item["device_id"] for item in pending],
            "failed_devices": [item["device_id"] for item in failed],
            "devices": devices,
            "policy": policy,
        }

    def cancel_user_policy_operation(self, username, operation_id, actor):
        """Rollback an operation by publishing its exact previous document."""
        username = str(username or "").strip()
        actor = str(actor or "").strip()
        with self._policy_operation_lock:
            with self.connect() as db:
                row = db.execute(
                    "SELECT id,before_payload,target_revision,status,"
                    "rollback_revision FROM user_policy_operations WHERE id=? "
                    "AND usage_guard_username=?",
                    (int(operation_id), username),
                ).fetchone()
            if not row:
                return None
            if row["status"] == "cancelled":
                return self.user_policy_operation(username, operation_id)
            current = self.user_policy(username)
            if int((current or {}).get("revision") or 0) != int(
                row["target_revision"]
            ):
                raise ValueError(
                    "Une politique plus récente empêche l’annulation sûre."
                )
            restored = self.save_user_policy(
                username, json.loads(row["before_payload"]), actor,
            )
            with self._lock, self.connect() as db:
                db.execute(
                    "UPDATE user_policy_operations SET status='cancelled',"
                    "rollback_revision=?,cancelled_at=? WHERE id=?",
                    (int(restored["revision"]), utc_now(), int(operation_id)),
                )
            return self.user_policy_operation(username, operation_id)

    def save_user_policy(self, username, policy, actor):
        username = str(username or "").strip()
        actor = str(actor or "").strip()
        if not username or not actor:
            raise ValueError("Utilisateur ou auteur manquant.")
        policy = self._normalized_policy_document(policy)
        payload = self._policy_payload(policy)
        now = utc_now()
        with self._lock, self.connect() as db:
            user = db.execute(
                "SELECT username,role,is_admin FROM users WHERE username=?",
                (username,),
            ).fetchone()
            if not user:
                raise ValueError("Utilisateur Usage Guard inconnu.")
            role = self._normalize_role(user["role"], user["is_admin"])
            if role != "limited":
                raise ValueError(
                    "Une politique de limitation cible un utilisateur à limiter."
                )
            available_device_ids = {
                str(item["device_id"]) for item in db.execute(
                    "SELECT device_id FROM user_devices WHERE username=?",
                    (user["username"],),
                ).fetchall()
            }
            if any(
                set(item.get("device_ids") or []) - available_device_ids
                for item in policy.get("limits", [])
            ):
                raise ValueError(
                    "Une limite cible un ordinateur non associé à cette personne."
                )
            warning_device_ids = set()
            for item in policy.get("limits", []):
                if item.get("enforcement_action") != "warn":
                    continue
                scope = item.get("device_ids")
                warning_device_ids.update(
                    scope if isinstance(scope, list) and scope
                    else available_device_ids
                )
            self._require_limit_warning_action(warning_device_ids)
            previous = db.execute(
                "SELECT payload FROM user_policy_revisions "
                "WHERE usage_guard_username=? ORDER BY revision DESC LIMIT 1",
                (user["username"],),
            ).fetchone()
            if previous and str(previous["payload"]) == payload:
                return self.user_policy(user["username"])
            revision = int(db.execute(
                "SELECT COALESCE(MAX(revision),0)+1 FROM user_policy_revisions "
                "WHERE usage_guard_username=?",
                (user["username"],),
            ).fetchone()[0])
            db.execute(
                "INSERT INTO user_policy_revisions(usage_guard_username,"
                "revision,payload,actor,created_at) VALUES(?,?,?,?,?)",
                (user["username"], revision, payload, actor, now),
            )
            devices = db.execute(
                "SELECT device_id FROM device_windows_identities "
                "WHERE usage_guard_username=? ORDER BY device_id",
                (user["username"],),
            ).fetchall()
            db.executemany(
                "INSERT INTO device_policy_state(device_id,"
                "usage_guard_username,desired_revision,applied_revision,"
                "last_result,updated_at) VALUES(?,?,?,0,NULL,?) "
                "ON CONFLICT(device_id,usage_guard_username) DO UPDATE SET "
                "desired_revision=excluded.desired_revision,last_result=NULL,"
                "updated_at=excluded.updated_at",
                [
                    (item["device_id"], user["username"], revision, now)
                    for item in devices
                ],
            )
        return self.user_policy(user["username"])

    @staticmethod
    def _computer_block_id(username, block, index=0):
        value = str(
            (block or {}).get("block_id") or (block or {}).get("id") or ""
        ).strip()
        if value and len(value) <= 120 and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]*", value
        ):
            return value
        source = {
            key: item for key, item in dict(block or {}).items()
            if key not in {"block_id", "id"}
        }
        digest = hashlib.sha256(
            f"{str(username or '').casefold()}:{index}:{json_hash(source)}".encode(
                "utf-8"
            )
        ).hexdigest()[:24]
        return f"legacy-{digest}"

    @classmethod
    def _normalize_computer_block_document(cls, payload, username=""):
        """Return the canonical v2 policy document for old and new payloads."""
        source = dict(payload or {}) if isinstance(payload, dict) else {}
        raw_blocks = (
            source.get("blocks")
            if source.get("version") == 2 and isinstance(source.get("blocks"), list)
            else [source] if source.get("mode") else []
        )
        blocks = []
        seen = set()
        for index, item in enumerate(raw_blocks):
            if not isinstance(item, dict) or not str(item.get("mode") or ""):
                continue
            block = dict(item)
            block_id = cls._computer_block_id(username, block, index)
            if block_id in seen:
                block_id = cls._computer_block_id(
                    username, {**block, "block_id": ""}, index + len(raw_blocks)
                )
            seen.add(block_id)
            block.pop("id", None)
            block["block_id"] = block_id
            name = str(block.get("name") or "").strip()
            if len(name) > 120:
                name = name[:120].rstrip()
            if name:
                block["name"] = name
            else:
                block.pop("name", None)
            if "device_ids" in block:
                block["device_ids"] = sorted({
                    str(device_id).strip()
                    for device_id in (block.get("device_ids") or [])
                    if str(device_id).strip()
                })
            block["enabled"] = block.get("enabled") is not False
            block["enforcement_action"] = (
                "warn" if block.get("enforcement_action") == "warn" else "block"
            )
            blocks.append(block)
        return {"version": 2, "blocks": blocks}

    def _migrate_computer_block_policy_documents(self):
        """Persist stable IDs for every legacy singleton policy exactly once."""
        with self._lock, self.connect() as db:
            rows = db.execute(
                "SELECT usage_guard_username,payload FROM "
                "user_computer_block_policies"
            ).fetchall()
            for row in rows:
                try:
                    payload = json.loads(row["payload"])
                except (TypeError, ValueError):
                    payload = {}
                document = self._normalize_computer_block_document(
                    payload, row["usage_guard_username"]
                )
                encoded = self._policy_payload(document)
                if encoded != row["payload"]:
                    db.execute(
                        "UPDATE user_computer_block_policies SET payload=? "
                        "WHERE usage_guard_username=?",
                        (encoded, row["usage_guard_username"]),
                    )

    @staticmethod
    def _computer_block_targets_device(block, device_id):
        scope = block.get("device_ids")
        return not isinstance(scope, list) or not scope or device_id in scope

    @classmethod
    def _computer_blocks_for_device(cls, document, device_id):
        return [
            dict(block) for block in document.get("blocks", [])
            if cls._computer_block_targets_device(block, device_id)
        ]

    def _device_supports_capability(self, device_id, capability, snapshot=None):
        if snapshot is None:
            snapshot = self.snapshot(device_id) or {}
        capabilities = dict(snapshot or {}).get("capabilities", [])
        if isinstance(capabilities, dict):
            return bool(capabilities.get(capability))
        return capability in (
            capabilities if isinstance(capabilities, (list, tuple, set)) else []
        )

    def _device_supports_computer_blocks_v2(self, device_id):
        return self._device_supports_capability(
            device_id, "computer_blocks_v2",
        )

    def _device_supports_limit_warning_action(self, device_id, snapshot=None):
        return self._device_supports_capability(
            device_id, "limit_warning_action", snapshot,
        )

    @staticmethod
    def _command_uses_limit_warning_action(command):
        command = dict(command or {})
        action = str(command.get("action") or "")
        if action == "set_limit":
            settings = command.get("settings")
            return bool(
                isinstance(settings, dict)
                and settings.get("enforcement_action") == "warn"
            )
        if action == "set_computer_block":
            return command.get("enforcement_action") == "warn"
        if action == "replace_computer_blocks":
            return any(
                isinstance(block, dict)
                and block.get("enforcement_action") == "warn"
                for block in (command.get("blocks") or [])
            )
        return False

    def _require_limit_warning_action(self, device_ids, command=None):
        if command is not None and not self._command_uses_limit_warning_action(
            command
        ):
            return
        unsupported = sorted({
            str(device_id).strip() for device_id in (device_ids or [])
            if str(device_id).strip()
            and not self._device_supports_limit_warning_action(device_id)
        })
        if not unsupported:
            return
        labels = ", ".join(
            self.device_display_name(device_id) for device_id in unsupported
        )
        raise ValueError(
            "Le mode Avertir exige la mise à jour du client Usage Guard sur : "
            f"{labels}."
        )

    def _computer_block_delivery_commands(self, document, device_id):
        blocks = self._computer_blocks_for_device(document, device_id)
        if self._device_supports_computer_blocks_v2(device_id):
            return [{
                "action": "replace_computer_blocks",
                "blocks": blocks,
            }]
        if len(blocks) > 1:
            raise ValueError(
                "Cet ordinateur doit être mis à jour avant de recevoir "
                "plusieurs limitations de l’ordinateur."
            )
        if not blocks:
            return [{"action": "clear_computer_block"}]
        block = blocks[0]
        command = self._legacy_computer_block_command({
            **block, "enabled": True,
        })
        if not command:
            return [{"action": "clear_computer_block"}]
        if block.get("enabled") is False:
            return [command, {
                "action": "set_computer_block_enabled", "enabled": False,
            }]
        return [command]

    @staticmethod
    def _legacy_computer_block_command(block):
        """Convert the previous per-device snapshot state into a reusable command."""
        block = dict(block or {})
        mode = str(block.get("mode") or "")
        if not mode or block.get("enabled") is False:
            return None
        command = {
            "action": "set_computer_block", "mode": mode,
            "grace_seconds": max(300, int(block.get("grace_seconds") or 300)),
            "name": str(block.get("name") or "").strip(),
            "delete_after_expiry": block.get("delete_after_expiry", True) is not False,
            "enforcement_action": (
                "warn" if block.get("enforcement_action") == "warn" else "block"
            ),
        }
        if mode == "schedule":
            command.update({
                "start_time": block.get("daily_start") or block.get("start_time"),
                "end_time": block.get("daily_end") or block.get("end_time"),
                "valid_from": block.get("valid_from") or "",
                "valid_from_time": block.get("valid_from_time") or "",
                "valid_until": block.get("valid_until") or "",
                "valid_until_time": block.get("valid_until_time") or "",
            })
        elif mode == "daily_duration":
            command.update({
                "duration_seconds": int(
                    block.get("limit_seconds") or block.get("duration_seconds") or 0
                ),
                "start_time": block.get("schedule_start") or block.get("start_time") or "",
                "end_time": block.get("schedule_end") or block.get("end_time") or "",
                "valid_from": block.get("valid_from") or "",
                "valid_from_time": block.get("valid_from_time") or "",
                "valid_until": block.get("valid_until") or "",
                "valid_until_time": block.get("valid_until_time") or "",
            })
        elif mode == "absolute_range":
            command.update({
                "valid_from": block.get("valid_from") or "",
                "valid_from_time": block.get("valid_from_time") or "",
                "valid_until": block.get("valid_until") or "",
                "valid_until_time": block.get("valid_until_time") or "",
            })
            try:
                if datetime.fromisoformat(
                    f"{command['valid_until']}T{command['valid_until_time']}:00"
                ).astimezone() <= datetime.now().astimezone():
                    return None
            except (TypeError, ValueError):
                return None
        elif mode == "duration":
            try:
                started = datetime.fromisoformat(str(block.get("started_at")))
                ended = datetime.fromisoformat(str(block.get("ends_at")))
            except (TypeError, ValueError):
                return None
            if ended <= datetime.now(ended.tzinfo):
                return None
            command.update({
                "duration_seconds": max(60, int((ended - started).total_seconds())),
                "delay_seconds": 0,
            })
        else:
            for field in ("day", "start_time", "end_time", "duration_seconds"):
                if field in block:
                    command[field] = block[field]
        return command

    def _migrate_legacy_computer_blocks(self):
        """Adopt one existing per-device block per person after the v2.040 split."""
        with self.connect() as db:
            users = db.execute(
                "SELECT username FROM users WHERE role='limited' AND username NOT IN "
                "(SELECT usage_guard_username FROM user_computer_block_policies)"
            ).fetchall()
            candidates = {}
            for user in users:
                rows = db.execute(
                    "SELECT snapshots.payload,snapshots.updated_at FROM snapshots "
                    "JOIN device_windows_identities identity ON "
                    "identity.device_id=snapshots.device_id WHERE "
                    "identity.usage_guard_username=? ORDER BY snapshots.updated_at DESC",
                    (user["username"],),
                ).fetchall()
                for row in rows:
                    try:
                        block = dict(json.loads(row["payload"]).get("computer_block") or {})
                    except (TypeError, ValueError):
                        continue
                    command = self._legacy_computer_block_command(block)
                    if command:
                        candidates[user["username"]] = (
                            command, str(block.get("actor") or "migration serveur"),
                            str(row["updated_at"]),
                        )
                        break
        for username, (command, actor, updated_at) in candidates.items():
            digest = hashlib.sha256(
                f"{username}:{updated_at}:{json_hash(command)}".encode("utf-8")
            ).hexdigest()[:24]
            self.mutate_user_computer_block(
                username, command, actor, f"legacy-computer-block:{digest}",
            )

    def reconcile_startup_state(self):
        """Run snapshot-dependent repairs only after secrets are available."""
        if self._email_encryption_key is None:
            raise RuntimeError("Initialisation sécurisée incomplète.")
        self._migrate_legacy_computer_blocks()
        self._repair_reflected_computer_block_states()
        self._reconcile_computer_block_fanout()

    @staticmethod
    def _computer_block_rule_reflected(current, expected):
        current = dict(current or {})
        expected = dict(expected or {})
        mode = str(expected.get("mode") or "")
        if str(current.get("mode") or "") != mode:
            return False
        expected_id = str(expected.get("block_id") or "")
        current_id = str(current.get("block_id") or current.get("id") or "")
        if expected_id and current_id and current_id != expected_id:
            return False
        if bool(current.get("enabled", True)) != bool(expected.get("enabled", True)):
            return False
        aliases = {
            "name": ("name",),
            "enforcement_action": ("enforcement_action",),
            "start_time": ("start_time", "daily_start", "schedule_start"),
            "end_time": ("end_time", "daily_end", "schedule_end"),
            "duration_seconds": ("duration_seconds", "limit_seconds"),
            "delay_seconds": ("delay_seconds",),
            "grace_seconds": ("grace_seconds",),
            "valid_from": ("valid_from",),
            "valid_from_time": ("valid_from_time",),
            "valid_until": ("valid_until",),
            "valid_until_time": ("valid_until_time",),
            "day": ("day",),
        }

        def aliased_value(block, candidates, default=""):
            for key in candidates:
                if block.get(key) not in (None, ""):
                    return block[key]
            for key in candidates:
                if key in block:
                    return block.get(key)
            return default

        fields = {"name", "enforcement_action", "grace_seconds"}
        fields.update(
            field for field, candidates in aliases.items()
            if any(key in expected for key in candidates)
        )
        if mode in {"schedule", "daily_duration", "absolute_range"}:
            fields.update({
                "valid_from", "valid_from_time",
                "valid_until", "valid_until_time",
            })
        if mode in {"schedule", "daily_duration", "range"}:
            fields.update({"start_time", "end_time"})
        if mode in {"duration", "daily_duration"}:
            fields.add("duration_seconds")

        numeric_defaults = {
            "duration_seconds": 0,
            "delay_seconds": 0,
            "grace_seconds": 300,
        }
        for field, candidates in aliases.items():
            if field not in fields:
                continue
            default = (
                "block" if field == "enforcement_action"
                else numeric_defaults.get(field, "")
            )
            actual = aliased_value(current, candidates, default)
            wanted = aliased_value(expected, candidates, default)
            if field == "enforcement_action":
                actual = "warn" if actual == "warn" else "block"
                wanted = "warn" if wanted == "warn" else "block"
            if field == "duration_seconds" and mode == "duration" and not any(
                key in current for key in candidates
            ):
                try:
                    started = datetime.fromisoformat(str(current.get("started_at")))
                    ended = datetime.fromisoformat(str(current.get("ends_at")))
                    actual = int((ended - started).total_seconds())
                except (TypeError, ValueError):
                    pass
            if field in numeric_defaults:
                try:
                    if int(actual or default) == int(wanted or default):
                        continue
                except (TypeError, ValueError):
                    pass
            elif str(actual or "") == str(wanted or ""):
                continue
            if actual != wanted:
                return False
        return True

    @classmethod
    def _computer_block_policy_reflected(
        cls, snapshot, expected, device_id="",
    ):
        snapshot = dict(snapshot or {})
        document = cls._normalize_computer_block_document(expected)
        expected_blocks = (
            cls._computer_blocks_for_device(document, device_id)
            if device_id else list(document["blocks"])
        )
        current_blocks = snapshot.get("computer_blocks")
        if isinstance(current_blocks, list):
            current_by_id = {
                str(item.get("block_id") or item.get("id") or ""): item
                for item in current_blocks if isinstance(item, dict)
            }
            expected_by_id = {
                str(item.get("block_id") or ""): item
                for item in expected_blocks
            }
            if set(current_by_id) != set(expected_by_id):
                return False
            return all(
                cls._computer_block_rule_reflected(
                    current_by_id[block_id], expected_block,
                )
                for block_id, expected_block in expected_by_id.items()
            )
        current = dict(snapshot.get("computer_block") or {})
        if not expected_blocks:
            return not bool(current.get("mode"))
        if len(expected_blocks) != 1:
            return False
        return cls._computer_block_rule_reflected(current, expected_blocks[0])

    def _repair_reflected_computer_block_states(self):
        """Repair acknowledgements lost after the PC already saved the block."""
        repaired = []
        with self._lock, self.connect() as db:
            rows = db.execute(
                "SELECT state.device_id,state.usage_guard_username,"
                "state.desired_revision,policy.payload,snapshots.payload AS snapshot "
                "FROM device_computer_block_state state JOIN "
                "user_computer_block_policies policy ON "
                "policy.usage_guard_username=state.usage_guard_username LEFT JOIN "
                "commands command ON command.id=state.command_id AND "
                "command.device_id=state.device_id LEFT JOIN snapshots ON "
                "snapshots.device_id=state.device_id WHERE "
                "state.applied_revision<state.desired_revision AND command.id IS NULL"
            ).fetchall()
            for row in rows:
                try:
                    expected = json.loads(row["payload"])
                    snapshot = json.loads(row["snapshot"] or "{}")
                except (TypeError, ValueError):
                    continue
                if not self._computer_block_policy_reflected(
                    snapshot, expected, row["device_id"],
                ):
                    continue
                result = json.dumps({
                    "ok": True, "phase": "reflected", "validated": True,
                }, ensure_ascii=False, separators=(",", ":"))
                db.execute(
                    "UPDATE device_computer_block_state SET "
                    "applied_revision=desired_revision,last_result=?,updated_at=? "
                    "WHERE device_id=? AND usage_guard_username=?",
                    (result, utc_now(), row["device_id"], row["usage_guard_username"]),
                )
                repaired.append((row["device_id"], row["usage_guard_username"]))
        return repaired

    def _queue_computer_block_policy_delivery(
        self, username, revision, actor, document, device_id,
    ):
        commands = self._computer_block_delivery_commands(document, device_id)
        command_id = None
        for index, command in enumerate(commands):
            queued = {**command, "actor": actor}
            delivery_key = f"computer-policy:{username}:{revision}:{device_id}"
            if index:
                delivery_key += f":{index}"
            try:
                command_id, _ = self.queue_idempotent(
                    device_id, queued, delivery_key,
                )
            except IdempotencyConflict:
                with self.connect() as db:
                    existing = db.execute(
                        "SELECT id FROM commands WHERE device_id=? AND "
                        "idempotency_key=?",
                        (device_id, delivery_key),
                    ).fetchone()
                if not existing:
                    raise
                command_id = existing["id"]
        with self._lock, self.connect() as db:
            previous = db.execute(
                "SELECT applied_revision FROM device_computer_block_state "
                "WHERE device_id=? AND usage_guard_username=?",
                (device_id, username),
            ).fetchone()
            applied = int(previous["applied_revision"] or 0) if previous else 0
            db.execute(
                "INSERT INTO device_computer_block_state(device_id,"
                "usage_guard_username,desired_revision,applied_revision,"
                "command_id,last_result,updated_at) VALUES(?,?,?,?,?,NULL,?) "
                "ON CONFLICT(device_id,usage_guard_username) DO UPDATE SET "
                "desired_revision=excluded.desired_revision,"
                "command_id=excluded.command_id,last_result=NULL,"
                "updated_at=excluded.updated_at",
                (
                    device_id, username, revision, applied, command_id,
                    utc_now(),
                ),
            )
        return command_id

    def _reconcile_computer_block_fanout(self):
        """Repair missing per-PC delivery state for every canonical block."""
        with self.connect() as db:
            policies = db.execute(
                "SELECT usage_guard_username,revision,payload,actor FROM "
                "user_computer_block_policies ORDER BY usage_guard_username"
            ).fetchall()
            work = []
            for policy in policies:
                devices = db.execute(
                    "SELECT identity.device_id,state.desired_revision FROM "
                    "device_windows_identities identity LEFT JOIN "
                    "device_computer_block_state state ON "
                    "state.device_id=identity.device_id AND "
                    "state.usage_guard_username=identity.usage_guard_username "
                    "WHERE identity.usage_guard_username=? ORDER BY identity.device_id",
                    (policy["usage_guard_username"],),
                ).fetchall()
                for device in devices:
                    if int(device["desired_revision"] or 0) >= int(policy["revision"]):
                        continue
                    work.append((policy, device["device_id"]))
        for policy, device_id in work:
            document = self._normalize_computer_block_document(
                json.loads(policy["payload"]),
                policy["usage_guard_username"],
            )
            revision = int(policy["revision"])
            username = str(policy["usage_guard_username"])
            actor = str(policy["actor"] or "synchronisation serveur")
            try:
                self._queue_computer_block_policy_delivery(
                    username, revision, actor, document, device_id,
                )
            except ValueError:
                # Never collapse a multi-rule policy or a warning action onto
                # an incompatible legacy client. The state remains behind
                # until that client advertises the required capability.
                continue

    def user_computer_block_policy(self, username):
        """Return the server-authoritative whole-computer limits for one person."""
        username = str(username or "").strip()
        with self.connect() as db:
            user = db.execute(
                "SELECT username FROM users WHERE username=?", (username,),
            ).fetchone()
            if not user:
                return None
            row = db.execute(
                "SELECT revision,payload,actor,updated_at FROM "
                "user_computer_block_policies WHERE usage_guard_username=?",
                (user["username"],),
            ).fetchone()
            states = db.execute(
                "SELECT state.device_id,state.desired_revision,"
                "state.applied_revision,state.command_id,state.last_result,"
                "state.updated_at FROM device_computer_block_state state "
                "JOIN device_windows_identities identity ON "
                "identity.device_id=state.device_id AND "
                "identity.usage_guard_username=state.usage_guard_username "
                "WHERE state.usage_guard_username=? ORDER BY state.device_id",
                (user["username"],),
            ).fetchall()
        document = self._normalize_computer_block_document(
            json.loads(row["payload"]) if row else {}, user["username"],
        )
        blocks = document["blocks"]
        return {
            "usage_guard_username": user["username"],
            "configured": bool(blocks),
            "revision": int(row["revision"]) if row else 0,
            "version": 2,
            "blocks": blocks,
            "block": dict(blocks[0]) if len(blocks) == 1 else {},
            "actor": str(row["actor"]) if row else "",
            "updated_at": str(row["updated_at"]) if row else "",
            "devices": [{
                "device_id": item["device_id"],
                "desired_revision": int(item["desired_revision"]),
                "applied_revision": int(item["applied_revision"]),
                "command_id": (
                    str(item["command_id"])
                    if item["command_id"] is not None else ""
                ),
                "last_result": (
                    json.loads(item["last_result"])
                    if item["last_result"] else None
                ),
                "updated_at": item["updated_at"],
            } for item in states],
        }

    def mutate_user_computer_block(
        self, username, command, actor, idempotency_key="",
    ):
        """Mutate one identified rule in the person's whole-computer policy."""
        username = str(username or "").strip()
        actor = str(actor or "").strip()
        command = dict(command or {})
        operation_key = str(idempotency_key or "").strip()
        action = str(command.get("action") or "")
        supported = {
            "set_computer_block", "set_computer_block_enabled",
            "clear_computer_block",
        }
        if action not in supported:
            raise ValueError("Mutation de limitation globale non prise en charge.")
        if not username or not actor or not operation_key or len(operation_key) > 200:
            raise ValueError("Utilisateur, auteur ou opération manquant.")
        allowed_fields = {
            "mode", "day", "duration_seconds", "delay_seconds", "start_time",
            "end_time", "grace_seconds", "valid_from", "valid_from_time",
            "valid_until", "valid_until_time", "name", "delete_after_expiry",
        }
        requested_id = str(command.get("block_id") or "").strip()
        create_new = bool(command.get("create_new"))
        if requested_id and (
            len(requested_id) > 120
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*", requested_id)
        ):
            raise ValueError("Identifiant de limitation globale invalide.")
        with self._policy_operation_lock:
            reused = False
            changed_block_id = requested_id
            with self._lock, self.connect() as db:
                user = db.execute(
                    "SELECT username,role,is_admin FROM users WHERE username=?",
                    (username,),
                ).fetchone()
                if not user or self._normalize_role(
                    user["role"], user["is_admin"],
                ) != "limited":
                    raise ValueError(
                        "Une limitation globale cible un utilisateur à limiter."
                    )
                existing_operation = db.execute(
                    "SELECT id FROM user_computer_block_operations WHERE "
                    "usage_guard_username=? AND idempotency_key=?",
                    (user["username"], operation_key),
                ).fetchone()
                if existing_operation:
                    reused = True
                    devices = []
                else:
                    current = db.execute(
                        "SELECT revision,payload FROM user_computer_block_policies "
                        "WHERE usage_guard_username=?",
                        (user["username"],),
                    ).fetchone()
                    previous_document = self._normalize_computer_block_document(
                        json.loads(current["payload"]) if current else {},
                        user["username"],
                    )
                    previous_blocks = [
                        dict(block) for block in previous_document["blocks"]
                    ]
                    blocks = [dict(block) for block in previous_blocks]
                    matches = [
                        index for index, block in enumerate(blocks)
                        if str(block.get("block_id") or "") == requested_id
                    ] if requested_id else []
                    if action != "set_computer_block" or (
                        requested_id and not create_new
                    ):
                        if not requested_id:
                            if len(blocks) > 1:
                                raise ValueError(
                                    "Plusieurs limitations existent : indiquez block_id."
                                )
                            if len(blocks) == 1:
                                matches = [0]
                                changed_block_id = str(
                                    blocks[0].get("block_id") or ""
                                )
                        if len(matches) != 1:
                            raise ValueError("Limitation globale introuvable.")
                    elif requested_id and matches:
                        raise ValueError(
                            "Une limitation globale utilise déjà cet identifiant."
                        )
                    now = utc_now()
                    if action == "set_computer_block":
                        mode = str(command.get("mode") or "")
                        name = str(command.get("name") or "").strip()
                        if len(name) > 120:
                            raise ValueError(
                                "Le nom de la limitation ne peut pas dépasser 120 caractères."
                            )
                        if mode not in {
                            "today", "24h", "day", "schedule", "absolute_range",
                            "range", "duration", "daily_duration",
                        }:
                            raise ValueError("Mode de limitation globale invalide.")
                        existing = blocks[matches[0]] if matches else None
                        if not changed_block_id:
                            changed_block_id = str(uuid.uuid4())
                        requested_scope = (
                            self.selected_user_device_ids(
                                user["username"], command.get("device_ids"),
                            )
                            if "device_ids" in command
                            else (
                                list(existing.get("device_ids") or [])
                                if existing else self.selected_user_device_ids(
                                    user["username"]
                                )
                            )
                        )
                        block = {
                            key: command[key] for key in allowed_fields
                            if key in command
                        }
                        block.update({
                            "block_id": changed_block_id,
                            "mode": mode, "enabled": (
                                existing.get("enabled") is not False
                                if existing else True
                            ),
                            "enforcement_action": (
                                "warn" if (
                                    command.get("enforcement_action")
                                    if "enforcement_action" in command else
                                    (existing or {}).get(
                                        "enforcement_action", "block",
                                    )
                                ) == "warn" else "block"
                            ),
                            "device_ids": requested_scope,
                            "actor": actor, "updated_at": now,
                        })
                        if name:
                            block["name"] = name
                        else:
                            block.pop("name", None)
                        if matches:
                            blocks[matches[0]] = block
                        else:
                            blocks.append(block)
                    elif action == "set_computer_block_enabled":
                        index = matches[0]
                        block = dict(blocks[index])
                        block["enabled"] = bool(command.get("enabled"))
                        block["actor"] = actor
                        block["updated_at"] = now
                        blocks[index] = block
                    else:
                        blocks.pop(matches[0])
                    document = {"version": 2, "blocks": blocks}
                    mapped_devices = [
                        item["device_id"] for item in db.execute(
                            "SELECT device_id FROM device_windows_identities "
                            "WHERE usage_guard_username=? ORDER BY device_id",
                            (user["username"],),
                        ).fetchall()
                    ]
                    warning_device_ids = set()
                    for item in blocks:
                        if item.get("enforcement_action") != "warn":
                            continue
                        scope = item.get("device_ids")
                        warning_device_ids.update(
                            scope if isinstance(scope, list) and scope
                            else mapped_devices
                        )
                    self._require_limit_warning_action(warning_device_ids)
                    for device_id in mapped_devices:
                        targeted = self._computer_blocks_for_device(
                            document, device_id,
                        )
                        if len(targeted) > 1 and not self._device_supports_computer_blocks_v2(
                            device_id
                        ):
                            raise ValueError(
                                f"{self.device_display_name(device_id)} doit être "
                                "mis à jour avant de recevoir plusieurs limitations "
                                "de l’ordinateur."
                            )
                    affected_devices = [
                        device_id for device_id in mapped_devices
                        if self._computer_blocks_for_device(
                            previous_document, device_id,
                        ) or self._computer_blocks_for_device(document, device_id)
                    ]
                    revision = int(current["revision"] if current else 0) + 1
                    db.execute(
                        "INSERT INTO user_computer_block_policies("
                        "usage_guard_username,revision,payload,actor,updated_at) "
                        "VALUES(?,?,?,?,?) ON CONFLICT(usage_guard_username) "
                        "DO UPDATE SET revision=excluded.revision,"
                        "payload=excluded.payload,actor=excluded.actor,"
                        "updated_at=excluded.updated_at",
                        (
                            user["username"], revision,
                            self._policy_payload(document), actor, now,
                        ),
                    )
                    db.execute(
                        "INSERT INTO user_computer_block_operations("
                        "usage_guard_username,idempotency_key,revision,created_at) "
                        "VALUES(?,?,?,?)",
                        (user["username"], operation_key, revision, now),
                    )
                    devices = affected_devices
            if not reused:
                for device_id in devices:
                    self._queue_computer_block_policy_delivery(
                        user["username"], revision, actor, document, device_id,
                    )
            result = self.user_computer_block_policy(user["username"])
            if not changed_block_id and len(result.get("blocks") or []) == 1:
                changed_block_id = result["blocks"][0]["block_id"]
            return {
                **result, "block_id": changed_block_id, "reused": reused,
            }

    def user_policy(self, username):
        username = str(username or "").strip()
        with self.connect() as db:
            user = db.execute(
                "SELECT username FROM users WHERE username=?", (username,)
            ).fetchone()
            if not user:
                return None
            row = db.execute(
                "SELECT revision,payload,actor,created_at "
                "FROM user_policy_revisions WHERE usage_guard_username=? "
                "ORDER BY revision DESC LIMIT 1",
                (user["username"],),
            ).fetchone()
            states = db.execute(
                "SELECT device_id,desired_revision,applied_revision,"
                "last_result,updated_at FROM device_policy_state "
                "WHERE usage_guard_username=? ORDER BY device_id",
                (user["username"],),
            ).fetchall()
        return {
            "usage_guard_username": user["username"],
            "configured": bool(row),
            "revision": int(row["revision"]) if row else 0,
            "policy": json.loads(row["payload"]) if row else None,
            "actor": str(row["actor"]) if row else "",
            "created_at": str(row["created_at"]) if row else "",
            "devices": [{
                "device_id": item["device_id"],
                "desired_revision": int(item["desired_revision"]),
                "applied_revision": int(item["applied_revision"]),
                "last_result": (
                    json.loads(item["last_result"])
                    if item["last_result"] else None
                ),
                "updated_at": item["updated_at"],
            } for item in states],
        }

    def policy_for_windows_sid(self, device_id, windows_sid):
        mapping = self.user_for_windows_sid(device_id, windows_sid)
        if not mapping:
            return None
        policy = self.user_policy(mapping["usage_guard_username"])
        if policy:
            # Repairs policies created before catalogue synchronization was a
            # prerequisite.  The operation is content-addressed and therefore
            # safe on every agent refresh.
            self.reconcile_user_policy_catalog(
                mapping["usage_guard_username"], policy,
                actor="synchronisation de politique",
            )
        if policy and isinstance(policy.get("policy"), dict):
            document = dict(policy["policy"])
            document["limits"] = [
                item for item in document.get("limits", [])
                if not item.get("device_ids")
                or str(device_id) in item.get("device_ids", [])
            ]
            if any(
                item.get("enforcement_action") == "warn"
                for item in document["limits"]
            ):
                self._require_limit_warning_action([device_id])
            policy = {**policy, "policy": document}
        return {
            **(policy or {}),
            "device_id": str(device_id),
            "windows_sid": str(windows_sid or "").strip().upper(),
        }

    def acknowledge_user_policy(
        self, device_id, windows_sid, revision, result,
    ):
        mapping = self.user_for_windows_sid(device_id, windows_sid)
        if not mapping:
            raise ValueError("Session Windows non associée.")
        try:
            revision = int(revision)
        except (TypeError, ValueError) as error:
            raise ValueError("Révision de politique invalide.") from error
        if revision < 1 or not isinstance(result, dict):
            raise ValueError("Accusé de politique invalide.")
        username = mapping["usage_guard_username"]
        encoded = json.dumps(
            result, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        )
        with self._lock, self.connect() as db:
            state = db.execute(
                "SELECT desired_revision,applied_revision FROM device_policy_state "
                "WHERE device_id=? AND usage_guard_username=?",
                (device_id, username),
            ).fetchone()
            if not state or revision > int(state["desired_revision"]):
                raise ValueError("Révision de politique non demandée.")
            applied = int(state["applied_revision"])
            if result.get("ok"):
                applied = max(applied, revision)
            elif revision >= applied:
                # A newer client may discover that a previously accepted
                # category rule cannot actually resolve against its local
                # catalogue.  Do not keep presenting that revision as linked
                # in the PWA while reconciliation is still pending.
                applied = min(applied, max(0, revision - 1))
            db.execute(
                "UPDATE device_policy_state SET applied_revision=?,"
                "last_result=?,updated_at=? WHERE device_id=? "
                "AND usage_guard_username=?",
                (applied, encoded, utc_now(), device_id, username),
            )
        return self.policy_for_windows_sid(device_id, windows_sid)

    @staticmethod
    def _validated_activity_deletion_target(target_key):
        target_key = str(target_key or "").strip()
        if (
            not target_key.startswith(("app:", "site:", "category:"))
            or len(target_key) > 1024
            or any(ord(character) < 32 for character in target_key)
        ):
            raise ValueError("Cible de tranche invalide.")
        prefix, separator, remainder = target_key.partition(":")
        if not separator or not remainder.strip():
            raise ValueError("Cible de tranche invalide.")
        if prefix != "site":
            return target_key
        browser, separator, raw_host = remainder.partition(":")
        browser = browser.strip().lower()
        raw_host = raw_host.strip().lower()
        if (
            not separator or not browser or not raw_host
            or any(character in browser for character in ":/\\?#@")
            or any(character.isspace() for character in browser + raw_host)
        ):
            raise ValueError("Cible de tranche invalide.")
        try:
            parsed = urlparse("//" + raw_host)
            host = str(parsed.hostname or "").lower().rstrip(".")
            port = parsed.port
        except ValueError as error:
            raise ValueError("Cible de tranche invalide.") from error
        if (
            not host or parsed.username is not None or parsed.password is not None
            or parsed.path or parsed.query or parsed.fragment
        ):
            raise ValueError("Cible de tranche invalide.")
        host = host.removeprefix("www.")
        if not host:
            raise ValueError("Cible de tranche invalide.")
        normalized_host = (
            f"[{host}]:{port}" if port is not None and ":" in host
            else f"{host}:{port}" if port is not None
            else host
        )
        return f"site:{browser}:{normalized_host}"

    @classmethod
    def _catalog_deletion_target(cls, command):
        command = dict(command or {})
        action = str(command.get("action") or "")
        if action == "delete_target":
            return cls._validated_activity_deletion_target(
                command.get("target_key")
            )
        return ""

    @staticmethod
    def _delete_normalized_target_rows(
        db, device_id, username, target_key, *,
        sealed_through_at=None, sealed_through_day=None,
    ):
        """Delete one exact target without ever widening the user/PC scope."""
        counts = {
            "intervals": 0, "timeline": 0, "live": 0,
            "legacy_metrics": 0, "aggregate_metrics": 0,
        }
        for table, counter in (
            ("activity_intervals", "intervals"),
            ("activity_timeline_sessions", "timeline"),
            ("activity_live_intervals", "live"),
        ):
            clauses = [
                "device_id=?", "usage_guard_username=?", "target_key=?",
            ]
            parameters = [device_id, username, target_key]
            if sealed_through_at is not None:
                # A session which began before the deletion is discarded in
                # full, even if its stale closing edge arrives afterwards.
                # This preserves both the privacy boundary and source-row
                # idempotency (no timestamp rewriting).
                clauses.append("started_at<=?")
                parameters.append(sealed_through_at)
            cursor = db.execute(
                f"DELETE FROM {table} WHERE " + " AND ".join(clauses),
                parameters,
            )
            counts[counter] += max(0, int(cursor.rowcount or 0))

        legacy_clauses = [
            "device_id=?", "usage_guard_username=?",
            "metric_kind IN ('active','usage','other_site')", "metric_key=?",
        ]
        legacy_parameters = [device_id, username, target_key]
        if sealed_through_day is not None:
            legacy_clauses.append("local_day<=?")
            legacy_parameters.append(sealed_through_day)
        cursor = db.execute(
            "DELETE FROM activity_daily_legacy WHERE "
            + " AND ".join(legacy_clauses), legacy_parameters,
        )
        counts["legacy_metrics"] += max(0, int(cursor.rowcount or 0))

        aggregate_day_clause = ""
        aggregate_parameters = [
            device_id, target_key, device_id, username,
        ]
        if sealed_through_day is not None:
            aggregate_day_clause = " AND local_day<=?"
            aggregate_parameters.append(sealed_through_day)
        cursor = db.execute(
            "DELETE FROM activity_daily_aggregate_metrics WHERE device_id=? "
            "AND metric_kind IN ('usage','other_site') AND metric_key=? "
            "AND aggregate_id IN ("
            "SELECT aggregate_id FROM activity_daily_aggregate_batches "
            "WHERE device_id=? AND usage_guard_username=?"
            + aggregate_day_clause + ")",
            aggregate_parameters,
        )
        counts["aggregate_metrics"] += max(0, int(cursor.rowcount or 0))
        return counts

    def _apply_activity_target_deletion_seals(
        self, db, *, device_id=None, username=None,
    ):
        clauses, parameters = [], []
        if device_id is not None:
            clauses.append("device_id=?")
            parameters.append(str(device_id or "").strip())
        if username is not None:
            clauses.append("usage_guard_username=?")
            parameters.append(str(username or "").strip())
        rows = db.execute(
            "SELECT device_id,usage_guard_username,target_key,"
            "sealed_through_at,sealed_through_day FROM "
            "activity_target_deletion_seals"
            + (" WHERE " + " AND ".join(clauses) if clauses else ""),
            parameters,
        ).fetchall()
        totals = {
            "intervals": 0, "timeline": 0, "live": 0,
            "legacy_metrics": 0, "aggregate_metrics": 0,
        }
        for row in rows:
            current = self._delete_normalized_target_rows(
                db, row["device_id"], row["usage_guard_username"],
                row["target_key"],
                sealed_through_at=row["sealed_through_at"],
                sealed_through_day=row["sealed_through_day"],
            )
            for key, value in current.items():
                totals[key] += value
        return totals

    def prepare_user_target_deletion(
        self, username, target_key, device_ids, idempotency_key,
    ):
        """Reserve and validate deletion identity before queuing any command."""
        username = str(username or "").strip()
        target_key = self._validated_activity_deletion_target(target_key)
        operation_key = str(idempotency_key or "").strip()
        if not IDEMPOTENCY_KEY_PATTERN.fullmatch(operation_key):
            raise ValueError("Clé d’idempotence invalide.")
        selected = self.selected_user_device_ids(username, device_ids)
        scope_payload = json.dumps(
            selected, ensure_ascii=False, separators=(",", ":"),
        )
        with self._lock, self.connect() as db:
            user = db.execute(
                "SELECT username FROM users WHERE username=?", (username,),
            ).fetchone()
            if not user:
                raise ValueError("Utilisateur inconnu.")
            username = str(user["username"])
            existing = db.execute(
                "SELECT target_key,device_scope,cutoff_at,applied_at FROM "
                "activity_target_deletion_operations WHERE "
                "usage_guard_username=? AND idempotency_key=?",
                (username, operation_key),
            ).fetchone()
            if existing and (
                str(existing["target_key"]) != target_key
                or str(existing["device_scope"]) != scope_payload
            ):
                raise IdempotencyConflict(
                    "Cette opération existe déjà avec un contenu différent"
                )
            if existing:
                cutoff_at = str(existing["cutoff_at"])
                applied = bool(existing["applied_at"])
            else:
                cutoff_at = datetime.now(timezone.utc).isoformat(
                    timespec="milliseconds"
                )
                db.execute(
                    "INSERT INTO activity_target_deletion_operations("
                    "usage_guard_username,idempotency_key,target_key,"
                    "device_scope,cutoff_at,created_at) VALUES(?,?,?,?,?,?)",
                    (
                        username, operation_key, target_key, scope_payload,
                        cutoff_at, utc_now(),
                    ),
                )
                applied = False
        return {
            "usage_guard_username": username, "target_key": target_key,
            "operation_id": operation_key, "device_ids": selected,
            "device_scope": scope_payload, "cutoff_at": cutoff_at,
            "applied": applied,
        }

    def purge_user_target_activity(
        self, username, target_key, device_ids, actor, idempotency_key,
    ):
        """Purge and seal one target on an exact, authorized PC scope.

        The seal is intentionally bounded: exact rows that start after the
        cutoff are new activity and remain valid.  Daily aggregates cannot
        express an intra-day boundary, so the deletion day is sealed as a
        whole; later days are accepted normally.
        """
        prepared = self.prepare_user_target_deletion(
            username, target_key, device_ids, idempotency_key,
        )
        username = prepared["usage_guard_username"]
        target_key = prepared["target_key"]
        operation_key = prepared["operation_id"]
        selected = prepared["device_ids"]
        scope_payload = prepared["device_scope"]
        actor = str(actor or "").strip()[:120]
        if not actor:
            raise ValueError("Utilisateur ou auteur manquant.")
        with self._lock, self.connect() as db:
            user = db.execute(
                "SELECT username FROM users WHERE username=?", (username,),
            ).fetchone()
            if not user:
                raise ValueError("Utilisateur inconnu.")
            username = str(user["username"])
            existing = db.execute(
                "SELECT target_key,device_scope,cutoff_at,applied_at FROM "
                "activity_target_deletion_operations WHERE "
                "usage_guard_username=? AND idempotency_key=?",
                (username, operation_key),
            ).fetchone()
            if existing and (
                str(existing["target_key"]) != target_key
                or str(existing["device_scope"]) != scope_payload
            ):
                raise IdempotencyConflict(
                    "Cette opération existe déjà avec un contenu différent"
                )
            if not existing:
                raise RuntimeError("Opération backend inconnue.")
            reused = bool(existing["applied_at"])
            cutoff_at = str(existing["cutoff_at"])

            totals = {
                "intervals": 0, "timeline": 0, "live": 0,
                "legacy_metrics": 0, "aggregate_metrics": 0,
            }
            if not reused:
                # UTC+14 is the furthest possible local calendar date.  It
                # seals every correction for a day that could already have
                # begun at deletion time without making this an unbounded ban.
                global_day = (
                    datetime.now(timezone.utc) + timedelta(hours=14)
                ).date().isoformat()
                for scoped_device_id in selected:
                    known_day = db.execute(
                        "SELECT MAX(local_day) FROM ("
                        "SELECT local_day FROM activity_daily_legacy WHERE "
                        "device_id=? AND usage_guard_username=? UNION ALL "
                        "SELECT local_day FROM activity_daily_aggregate_batches "
                        "WHERE device_id=? AND usage_guard_username=?"
                        ")",
                        (
                            scoped_device_id, username,
                            scoped_device_id, username,
                        ),
                    ).fetchone()[0]
                    sealed_day = max(global_day, str(known_day or ""))
                    db.execute(
                        "INSERT INTO activity_target_deletion_seals("
                        "device_id,usage_guard_username,target_key,"
                        "sealed_through_at,sealed_through_day,catalog_sealed,"
                        "operation_key,updated_at) VALUES(?,?,?,?,?,?,?,?) "
                        "ON CONFLICT("
                        "device_id,usage_guard_username,target_key) DO UPDATE SET "
                        "sealed_through_at=MAX(sealed_through_at,"
                        "excluded.sealed_through_at),"
                        "sealed_through_day=MAX(sealed_through_day,"
                        "excluded.sealed_through_day),"
                        "catalog_sealed=1,"
                        "catalog_confirmation_after=NULL,"
                        "operation_key=CASE WHEN excluded.sealed_through_at>="
                        "sealed_through_at THEN excluded.operation_key ELSE "
                        "operation_key END,updated_at=excluded.updated_at",
                        (
                            scoped_device_id, username, target_key, cutoff_at,
                            sealed_day, 1, operation_key, utc_now(),
                        ),
                    )
                    catalog_row = db.execute(
                        "SELECT payload FROM device_catalogs WHERE device_id=?",
                        (scoped_device_id,),
                    ).fetchone()
                    if catalog_row:
                        try:
                            catalog = self._unprotect_document_recipients(
                                json.loads(catalog_row["payload"])
                            )
                            catalog = self._catalog_document_without_target(
                                catalog, target_key,
                            )
                            db.execute(
                                "UPDATE device_catalogs SET payload=?,score=?,"
                                "updated_at=? WHERE device_id=?",
                                (
                                    json.dumps(
                                        self._protect_document_recipients(catalog),
                                        ensure_ascii=False, sort_keys=True,
                                        separators=(",", ":"),
                                    ),
                                    json.dumps(
                                        self._catalog_document_score(catalog),
                                        separators=(",", ":"),
                                    ),
                                    utc_now(), scoped_device_id,
                                ),
                            )
                        except (TypeError, ValueError, json.JSONDecodeError):
                            # An unreadable catalogue cannot expose a target;
                            # keep the deletion itself independent from repair
                            # of that unrelated corrupt document.
                            pass
                    snapshot_row = db.execute(
                        "SELECT payload FROM snapshots WHERE device_id=?",
                        (scoped_device_id,),
                    ).fetchone()
                    if snapshot_row:
                        try:
                            snapshot = self._unprotect_document_recipients(
                                json.loads(snapshot_row["payload"])
                            )
                            snapshot = self._snapshot_without_user_target(
                                snapshot, username, target_key, username,
                            )
                            db.execute(
                                "UPDATE snapshots SET payload=?,updated_at=? "
                                "WHERE device_id=?",
                                (
                                    json.dumps(
                                        self._protect_document_recipients(
                                            snapshot
                                        ),
                                        ensure_ascii=False,
                                        separators=(",", ":"),
                                    ),
                                    utc_now(), scoped_device_id,
                                ),
                            )
                        except (TypeError, ValueError, json.JSONDecodeError):
                            pass
                    current = self._delete_normalized_target_rows(
                        db, scoped_device_id, username, target_key,
                    )
                    for key, value in current.items():
                        totals[key] += value
                db.execute(
                    "INSERT INTO audit_events(kind,actor,details,created_at) "
                    "VALUES(?,?,?,?)",
                    (
                        "activity_target_deleted", actor,
                        json.dumps({
                            "usage_guard_username": username,
                            "target_key": target_key,
                            "device_ids": selected,
                            "idempotency_key": operation_key,
                        }, ensure_ascii=False, separators=(",", ":")),
                        utc_now(),
                    ),
                )
                db.execute(
                    "UPDATE activity_target_deletion_operations SET "
                    "applied_at=? WHERE usage_guard_username=? AND "
                    "idempotency_key=?",
                    (utc_now(), username, operation_key),
                )
            else:
                # Replays never advance the cutoff and therefore cannot erase
                # activity created after the original request.
                for scoped_device_id in selected:
                    seal = db.execute(
                        "SELECT sealed_through_at,sealed_through_day FROM "
                        "activity_target_deletion_seals WHERE device_id=? AND "
                        "usage_guard_username=? AND target_key=?",
                        (scoped_device_id, username, target_key),
                    ).fetchone()
                    if not seal:
                        continue
                    current = self._delete_normalized_target_rows(
                        db, scoped_device_id, username, target_key,
                        sealed_through_at=seal["sealed_through_at"],
                        sealed_through_day=seal["sealed_through_day"],
                    )
                    for key, value in current.items():
                        totals[key] += value
        return {
            "target_key": target_key, "device_ids": selected,
            "cutoff_at": cutoff_at, "reused": reused, "purged": totals,
        }

    def _remove_deleted_target_from_user_policy(
        self, username, target_key, selected_device_ids, actor,
    ):
        """Prevent the central policy from recreating deleted local limits."""
        state = self.user_policy(username)
        if not state or not state.get("configured") or not isinstance(
            state.get("policy"), dict
        ):
            return None
        available = set(self.selected_user_device_ids(username))
        selected = set(selected_device_ids or [])
        changed = False
        limits = []
        for source in state["policy"].get("limits", []):
            item = dict(source or {})
            if target_key not in {
                str(item.get("key") or ""),
                str(item.get("target_key") or ""),
            }:
                limits.append(item)
                continue
            current_scope = set(item.get("device_ids") or available)
            if not current_scope.intersection(selected):
                limits.append(item)
                continue
            changed = True
            remaining = sorted(current_scope - selected)
            if remaining:
                item["device_ids"] = remaining
                limits.append(item)
        if not changed:
            return state
        saved = self.save_user_policy(
            username, {**state["policy"], "limits": limits},
            "suppression définitive · " + str(actor or "")[:90],
        )
        return saved

    def target_policy_deletion_impact(
        self, username, target_key, selected_device_ids,
    ):
        """Describe central limits affected by one scoped target deletion."""
        target_key = self._validated_activity_deletion_target(target_key)
        selected = set(self.selected_user_device_ids(
            username, list(selected_device_ids),
        ))
        available = set(self.selected_user_device_ids(username))
        state = self.user_policy(username) or {}
        policy = state.get("policy")
        if not isinstance(policy, dict):
            return {"limit_keys": [], "owners": []}
        affected, owners = [], set()
        for source in policy.get("limits", []):
            item = dict(source or {})
            if target_key not in {
                str(item.get("key") or ""),
                str(item.get("target_key") or ""),
            }:
                continue
            scope = set(item.get("device_ids") or available)
            if not scope.intersection(selected):
                continue
            affected.append(str(item.get("key") or target_key))
            owner = self._mutation_actor_username(
                item.get("requested_by") or item.get("actor") or ""
            )
            if owner:
                owners.add(owner)
        return {
            "limit_keys": sorted(set(affected)),
            "owners": sorted(owners, key=str.casefold),
        }

    def ingest_activity_daily_aggregates(
        self, device_id, aggregates, windows_sid="",
    ):
        """Store corrected daily summaries without accepting raw history."""
        device_id = str(device_id or "").strip()
        sid = str(windows_sid or "").strip().upper()
        if sid:
            mapping = self.user_for_windows_sid(device_id, sid)
        else:
            identities = self.device_windows_identities(device_id)
            mapping = identities[0] if len(identities) == 1 else None
        if not mapping:
            raise ValueError("Session Windows non associée.")
        if not isinstance(aggregates, list) or len(aggregates) > 31:
            raise ValueError("Lot d’agrégats journaliers invalide.")
        if len(json.dumps(
            aggregates, ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")) > MAX_INCREMENTAL_ACTIVITY_BYTES:
            raise ValueError("Lot d’agrégats journaliers trop volumineux.")
        username = str(mapping["usage_guard_username"])
        normalized = []
        rejected = []
        metric_count = 0
        seen_days = set()
        for source in aggregates:
            source = source if isinstance(source, dict) else {}
            aggregate_id = str(source.get("aggregate_id") or "").strip()
            day = str(source.get("local_day") or "").strip()
            metrics = source.get("metrics")
            reason = ""
            if not IDEMPOTENCY_KEY_PATTERN.fullmatch(aggregate_id):
                reason = "Identifiant d’agrégat invalide."
            elif day in seen_days:
                reason = "Journée dupliquée dans le lot."
            elif not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day):
                reason = "Date d’agrégat invalide."
            else:
                try:
                    datetime.fromisoformat(day).date()
                except ValueError:
                    reason = "Date d’agrégat invalide."
            if not reason and not isinstance(metrics, list):
                reason = "Métriques journalières invalides."
            current_metrics = []
            metric_keys = set()
            if not reason:
                for metric in metrics:
                    metric = metric if isinstance(metric, dict) else {}
                    kind = str(metric.get("kind") or "").strip()
                    key = str(metric.get("key") or "").strip()
                    try:
                        seconds = float(metric.get("seconds") or 0)
                    except (TypeError, ValueError):
                        seconds = math.nan
                    identity = (kind, key)
                    if (
                        kind not in {"usage", "passive", "system", "other_site"}
                        or not key or len(key) > 1024
                        or any(ord(character) < 32 for character in key)
                        or identity in metric_keys
                        or not math.isfinite(seconds) or seconds < 0
                    ):
                        reason = "Métrique journalière invalide."
                        break
                    metric_keys.add(identity)
                    current_metrics.append((kind, key, round(seconds, 3)))
            metric_count += len(current_metrics)
            if metric_count > 500 and not reason:
                reason = "Le lot dépasse 500 métriques."
            if reason:
                rejected.append({
                    "aggregate_id": aggregate_id, "local_day": day,
                    "reason": reason,
                })
                continue
            seen_days.add(day)
            canonical = json.dumps(
                {
                    "schema_version": 1, "local_day": day,
                    "metrics": [
                        {"kind": kind, "key": key, "seconds": seconds}
                        for kind, key, seconds in sorted(current_metrics)
                    ],
                }, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            )
            # ``aggregate_id`` is a content identifier generated in the
            # Windows user's local profile.  Two different users can
            # legitimately produce the same identifier for the same totals.
            # Namespace the durable server identity by Usage Guard owner while
            # keeping the transport identifier in the ACK for old clients.
            stored_aggregate_id = "daily-owner-v1-" + hashlib.sha256(
                (
                    username.casefold() + "\0" + aggregate_id
                ).encode("utf-8")
            ).hexdigest()
            normalized.append((
                aggregate_id, stored_aggregate_id, day, hashlib.sha256(
                    canonical.encode("utf-8")
                ).hexdigest(), current_metrics,
            ))

        accepted_ids = []
        duplicates = 0
        with self._lock, self.connect() as db:
            for (
                aggregate_id, stored_aggregate_id, day, content_hash, metrics,
            ) in normalized:
                existing_id = db.execute(
                    "SELECT content_hash FROM activity_daily_aggregate_receipts "
                    "WHERE device_id=? AND aggregate_id=?",
                    (device_id, stored_aggregate_id),
                ).fetchone()
                if existing_id:
                    if existing_id["content_hash"] != content_hash:
                        raise IdempotencyConflict(
                            "Cet agrégat existe avec un contenu différent."
                        )
                    accepted_ids.append(aggregate_id)
                    duplicates += 1
                    continue
                db.execute(
                    "DELETE FROM activity_daily_aggregate_batches WHERE "
                    "device_id=? AND usage_guard_username=? AND local_day=?",
                    (device_id, username, day),
                )
                db.execute(
                    "INSERT INTO activity_daily_aggregate_batches(device_id,"
                    "aggregate_id,usage_guard_username,local_day,content_hash,"
                    "received_at) VALUES(?,?,?,?,?,?)",
                    (
                        device_id, stored_aggregate_id, username, day,
                        content_hash, utc_now(),
                    ),
                )
                db.executemany(
                    "INSERT INTO activity_daily_aggregate_metrics(device_id,"
                    "aggregate_id,metric_kind,metric_key,seconds) "
                    "VALUES(?,?,?,?,?)",
                    [
                        (device_id, stored_aggregate_id, kind, key, seconds)
                        for kind, key, seconds in metrics
                    ],
                )
                db.execute(
                    "INSERT INTO activity_daily_aggregate_receipts(device_id,"
                    "aggregate_id,local_day,content_hash,received_at) "
                    "VALUES(?,?,?,?,?)",
                    (
                        device_id, stored_aggregate_id, day, content_hash,
                        utc_now(),
                    ),
                )
                accepted_ids.append(aggregate_id)
            self._apply_activity_target_deletion_seals(
                db, device_id=device_id, username=username,
            )
        return {
            "accepted_ids": accepted_ids, "rejected": rejected,
            "duplicates": duplicates,
            "usage_guard_username": username,
        }

    def ingest_activity_intervals(self, device_id, windows_sid, intervals):
        device_id = str(device_id or "").strip()
        sid = str(windows_sid or "").strip().upper()
        mapping = self.user_for_windows_sid(device_id, sid)
        if not mapping:
            raise ValueError("Session Windows non associée.")
        if not isinstance(intervals, list) or len(intervals) > 500:
            raise ValueError("Lot de tranches d’activité invalide.")
        if len(json.dumps(
            intervals, ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")) > MAX_INCREMENTAL_ACTIVITY_BYTES:
            raise ValueError("Lot de tranches d’activité trop volumineux.")
        username = mapping["usage_guard_username"]
        normalized = []
        for source in intervals:
            source = dict(source or {})
            interval_id = str(source.get("interval_id") or "").strip()
            if not IDEMPOTENCY_KEY_PATTERN.fullmatch(interval_id):
                raise ValueError("Identifiant de tranche invalide.")
            target_key = str(source.get("target_key") or "").strip()
            if (
                len(target_key) > 1024
                or any(ord(character) < 32 for character in target_key)
                or not target_key.startswith(
                    ("app:", "site:", "category:", "computer:")
                )
            ):
                raise ValueError("Cible de tranche invalide.")
            category_key = str(source.get("category_key") or "").strip()
            if len(category_key) > 512 or any(
                ord(character) < 32 for character in category_key
            ):
                raise ValueError("Catégorie historique invalide.")
            supplied_categories = source.get("category_keys", [])
            if not isinstance(supplied_categories, list):
                raise ValueError("Lignée de catégorie historique invalide.")
            category_keys = list(dict.fromkeys(
                str(category).strip() for category in supplied_categories
                if str(category).strip()
            ))
            if category_key and category_key not in category_keys:
                category_keys.insert(0, category_key)
            if len(category_keys) > 64 or any(
                len(category) > 512
                or any(ord(character) < 32 for character in category)
                for category in category_keys
            ):
                raise ValueError("Lignée de catégorie historique invalide.")
            opened = _aware_utc(source.get("started_at"))
            closed = _aware_utc(source.get("ended_at"))
            if closed <= opened:
                raise ValueError("La fin d’une tranche doit suivre son début.")
            try:
                revision = int(source.get("policy_revision") or 0)
            except (TypeError, ValueError) as error:
                raise ValueError("Révision de tranche invalide.") from error
            if revision < 0:
                raise ValueError("Révision de tranche invalide.")
            normalized.append(((
                device_id, interval_id, sid, username, target_key,
                category_key, opened.isoformat(timespec="milliseconds"),
                closed.isoformat(timespec="milliseconds"), revision,
            ), category_keys))
        accepted = duplicates = 0
        with self._lock, self.connect() as db:
            for item, category_keys in normalized:
                existing = db.execute(
                    "SELECT windows_sid,usage_guard_username,target_key,"
                    "category_key,started_at,ended_at,policy_revision "
                    "FROM activity_intervals WHERE device_id=? AND interval_id=?",
                    item[:2],
                ).fetchone()
                expected = item[2:9]
                if existing:
                    actual = tuple(existing[field] for field in (
                        "windows_sid", "usage_guard_username", "target_key",
                        "category_key", "started_at", "ended_at",
                        "policy_revision",
                    ))
                    if actual != expected:
                        raise IdempotencyConflict(
                            "Cette tranche existe avec un contenu différent."
                        )
                    stored_categories = [row[0] for row in db.execute(
                        "SELECT category_key FROM activity_interval_categories "
                        "WHERE device_id=? AND interval_id=? ORDER BY category_key",
                        item[:2],
                    ).fetchall()]
                    if stored_categories != sorted(category_keys):
                        raise IdempotencyConflict(
                            "Cette tranche existe avec une catégorie différente."
                        )
                    duplicates += 1
                else:
                    db.execute(
                        "INSERT INTO activity_intervals(device_id,interval_id,"
                        "windows_sid,usage_guard_username,target_key,category_key,"
                        "started_at,ended_at,policy_revision,received_at) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (*item, utc_now()),
                    )
                    db.executemany(
                        "INSERT INTO activity_interval_categories(device_id,"
                        "interval_id,category_key) VALUES(?,?,?)",
                        [
                            (device_id, item[1], category)
                            for category in category_keys
                        ],
                    )
                    accepted += 1
                self._purge_snapshot_duplicates_for_modern_interval(
                    db, item, category_keys,
                )
            self._apply_activity_target_deletion_seals(
                db, device_id=device_id, username=username,
            )
        return {
            "accepted": accepted, "duplicates": duplicates,
            "usage_guard_username": username,
        }

    def ingest_activity_timeline_sessions(
        self, device_id, windows_sid, sessions,
    ):
        """Persist a bounded, idempotent batch used only by the PWA timeline.

        These rows deliberately live outside ``activity_intervals``: a
        program being open is useful on the timeline, but must never consume a
        foreground quota merely because its window exists.
        """
        device_id = str(device_id or "").strip()
        sid = str(windows_sid or "").strip().upper()
        mapping = self.user_for_windows_sid(device_id, sid)
        if not mapping:
            raise ValueError("Session Windows non associée.")
        if not isinstance(sessions, list) or len(sessions) > 500:
            raise ValueError("Lot de sessions de frise invalide.")
        if len(json.dumps(
            sessions, ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")) > MAX_INCREMENTAL_ACTIVITY_BYTES:
            raise ValueError("Lot de sessions de frise trop volumineux.")
        username = mapping["usage_guard_username"]

        def clean_text(value, label, maximum=1024):
            value = str(value or "").strip()
            if len(value) > maximum or any(ord(character) < 32 for character in value):
                raise ValueError(f"{label} invalide.")
            return value

        normalized = []
        ignored_usage_only = 0
        for source in sessions:
            source = dict(source or {})
            record_id = clean_text(
                source.get("record_id") or source.get("interval_id"),
                "Identifiant de session", 128,
            )
            if not IDEMPOTENCY_KEY_PATTERN.fullmatch(record_id):
                raise ValueError("Identifiant de session de frise invalide.")
            kind = clean_text(source.get("kind"), "Type de session", 32)
            if kind not in TIMELINE_SESSION_KINDS:
                raise ValueError("Type de session de frise invalide.")
            session_id = clean_text(source.get("id"), "Identifiant local", 512)
            target_key = clean_text(source.get("key"), "Cible de session", 1024)
            label = clean_text(source.get("label"), "Libellé de session", 1024)
            category_key = clean_text(
                source.get("category"), "Catégorie de session", 512,
            )
            supplied_lineage = source.get("category_lineage", [])
            if not isinstance(supplied_lineage, list):
                raise ValueError("Lignée de catégorie de session invalide.")
            category_lineage = list(dict.fromkeys(
                clean_text(value, "Catégorie de session", 512)
                for value in supplied_lineage if str(value or "").strip()
            ))
            if category_key and category_key not in category_lineage:
                category_lineage.insert(0, category_key)
            if len(category_lineage) > 64:
                raise ValueError("Lignée de catégorie de session invalide.")
            opened = _aware_utc(source.get("started_at"))
            closed = _aware_utc(source.get("ended_at"))
            if closed <= opened:
                raise ValueError("La fin d’une session doit suivre son début.")
            windows_session_id = clean_text(
                source.get("windows_session_id"),
                "Identifiant de session Windows", 128,
            )
            origin = clean_text(source.get("source"), "Source de session", 128)
            if is_other_sites_usage_key(target_key):
                # The same active record still reaches ``activity_intervals``
                # through the usage channel.  It must never be duplicated as
                # a drawable site session.
                ignored_usage_only += 1
                continue
            normalized.append((
                device_id, record_id, sid, username, kind, session_id,
                target_key, label, category_key,
                json.dumps(
                    category_lineage, ensure_ascii=False, separators=(",", ":"),
                ),
                opened.isoformat(timespec="milliseconds"),
                closed.isoformat(timespec="milliseconds"),
                windows_session_id,
                int(bool(source.get("started_before_tracking", False))),
                origin,
            ))

        compared_fields = (
            "windows_sid", "usage_guard_username", "session_kind",
            "session_id", "target_key", "label", "category_key",
            "category_lineage", "started_at", "ended_at",
            "windows_session_id", "started_before_tracking", "source",
        )
        accepted = duplicates = 0
        with self._lock, self.connect() as db:
            for item in normalized:
                existing = db.execute(
                    "SELECT " + ",".join(compared_fields)
                    + " FROM activity_timeline_sessions "
                    "WHERE device_id=? AND record_id=?",
                    item[:2],
                ).fetchone()
                expected = item[2:]
                if existing:
                    actual = tuple(existing[field] for field in compared_fields)
                    if actual != expected:
                        raise IdempotencyConflict(
                            "Cette session de frise existe avec un contenu différent."
                        )
                    duplicates += 1
                    continue
                db.execute(
                    "INSERT INTO activity_timeline_sessions("
                    "device_id,record_id,windows_sid,usage_guard_username,"
                    "session_kind,session_id,target_key,label,category_key,"
                    "category_lineage,started_at,ended_at,windows_session_id,"
                    "started_before_tracking,source,received_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (*item, utc_now()),
                )
                accepted += 1
            self._apply_activity_target_deletion_seals(
                db, device_id=device_id, username=username,
            )
        return {
            "accepted": accepted, "duplicates": duplicates,
            "ignored_usage_only": ignored_usage_only,
            "usage_guard_username": username,
        }

    def activity_timeline_sessions(
        self, device_id, *, username=None, start=None, end=None, limit=10_001,
    ):
        clauses = ["device_id=?", f"NOT ({OTHER_SITES_USAGE_SQL})"]
        parameters = [str(device_id or "").strip()]
        if username:
            clauses.append("usage_guard_username=?")
            parameters.append(str(username).strip())
        if start is not None:
            clauses.append("ended_at>?")
            parameters.append(_aware_utc(start).isoformat(timespec="milliseconds"))
        if end is not None:
            clauses.append("started_at<?")
            parameters.append(_aware_utc(end).isoformat(timespec="milliseconds"))
        limit = max(1, min(10_001, int(limit)))
        with self.connect() as db:
            rows = db.execute(
                "SELECT record_id,windows_sid,usage_guard_username,session_kind,"
                "session_id,target_key,label,category_key,category_lineage,"
                "started_at,ended_at,windows_session_id,"
                "started_before_tracking,source "
                "FROM activity_timeline_sessions WHERE "
                + " AND ".join(clauses)
                + " ORDER BY started_at DESC,ended_at DESC,record_id DESC LIMIT ?",
                (*parameters, limit),
            ).fetchall()
        result = []
        for row in reversed(rows):
            result.append({
                "record_id": row["record_id"],
                "windows_sid": row["windows_sid"],
                "usage_guard_username": row["usage_guard_username"],
                "windows_identity_mapped": True,
                "kind": row["session_kind"], "id": row["session_id"],
                "key": row["target_key"], "label": target_display_label(
                    row["target_key"], row["label"],
                ),
                "category": row["category_key"],
                "category_lineage": json.loads(row["category_lineage"]),
                "started_at": row["started_at"], "ended_at": row["ended_at"],
                "windows_session_id": row["windows_session_id"],
                "started_before_tracking": bool(row["started_before_tracking"]),
                "source": row["source"],
            })
        return result

    @staticmethod
    def _activity_history_cursor(order):
        raw = json.dumps(
            list(order), ensure_ascii=True, separators=(",", ":"),
        ).encode("ascii")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    @staticmethod
    def _parse_activity_history_cursor(cursor):
        cursor = str(cursor or "").strip()
        if not cursor or len(cursor) > 512:
            raise ValueError("Curseur d’historique invalide.")
        try:
            padding = "=" * (-len(cursor) % 4)
            order = json.loads(base64.urlsafe_b64decode(
                (cursor + padding).encode("ascii"),
            ).decode("ascii"))
            if not isinstance(order, list) or len(order) != 4:
                raise ValueError
            started_at, ended_at, source_order, record_id = order
            _aware_utc(started_at)
            _aware_utc(ended_at)
            source_order = int(source_order)
            record_id = str(record_id or "")
            if source_order not in {0, 1} or not record_id:
                raise ValueError
        except (
            TypeError, ValueError, UnicodeError, json.JSONDecodeError,
            binascii.Error,
        ) as error:
            raise ValueError("Curseur d’historique invalide.") from error
        return str(started_at), str(ended_at), source_order, record_id

    def device_activity_history_page(
        self, device_id, *, username=None, start=None, end=None,
        before="", limit=500, max_bytes=MAX_INCREMENTAL_ACTIVITY_BYTES,
    ):
        """Read one stable backwards page from both normalized closed stores.

        The opaque cursor includes the complete descending sort key.  It
        therefore cannot skip rows when hundreds of records share the same
        timestamp, and no legacy activity document is read or serialized.
        """
        device_id = str(device_id or "").strip()
        username = str(username or "").strip()
        limit = max(1, min(500, int(limit)))
        max_bytes = max(64 * 1024, min(
            MAX_INCREMENTAL_ACTIVITY_BYTES, int(max_bytes),
        ))
        cursor_order = (
            self._parse_activity_history_cursor(before) if before else None
        )

        def selection(identifier, source_order):
            clauses = ["device_id=?", f"NOT ({OTHER_SITES_USAGE_SQL})"]
            parameters = [device_id]
            if username:
                clauses.append("usage_guard_username=?")
                parameters.append(username)
            if start is not None:
                clauses.append("ended_at>?")
                parameters.append(
                    _aware_utc(start).isoformat(timespec="milliseconds")
                )
            if end is not None:
                clauses.append("started_at<?")
                parameters.append(
                    _aware_utc(end).isoformat(timespec="milliseconds")
                )
            if cursor_order:
                cursor_start, cursor_end, cursor_source, cursor_id = cursor_order
                clauses.append(
                    "(started_at<? OR (started_at=? AND (ended_at<? OR "
                    "(ended_at=? AND (?<? OR (?=? AND "
                    f"{identifier}<?))))))"
                )
                parameters.extend((
                    cursor_start, cursor_start, cursor_end, cursor_end,
                    source_order, cursor_source, source_order, cursor_source,
                    cursor_id,
                ))
            return clauses, parameters

        timeline_clauses, timeline_parameters = selection("record_id", 1)
        interval_clauses, interval_parameters = selection("interval_id", 0)
        with self.connect() as db:
            timeline_rows = db.execute(
                "SELECT record_id,windows_sid,usage_guard_username,session_kind,"
                "session_id,target_key,label,category_key,category_lineage,"
                "started_at,ended_at,windows_session_id,"
                "started_before_tracking,source "
                "FROM activity_timeline_sessions WHERE "
                + " AND ".join(timeline_clauses)
                + " ORDER BY started_at DESC,ended_at DESC,record_id DESC LIMIT ?",
                (*timeline_parameters, limit + 1),
            ).fetchall()
            interval_rows = db.execute(
                "SELECT interval_id,windows_sid,usage_guard_username,target_key,"
                "category_key,started_at,ended_at FROM activity_intervals WHERE "
                + " AND ".join(interval_clauses)
                + " AND NOT EXISTS (SELECT 1 FROM activity_timeline_sessions "
                "AS timeline WHERE timeline.device_id=activity_intervals.device_id "
                "AND timeline.usage_guard_username="
                "activity_intervals.usage_guard_username "
                "AND timeline.session_kind='active' "
                "AND timeline.target_key=activity_intervals.target_key "
                "AND timeline.started_at=activity_intervals.started_at "
                "AND timeline.ended_at=activity_intervals.ended_at "
                "AND UPPER(timeline.windows_sid)="
                "UPPER(activity_intervals.windows_sid))"
                + " ORDER BY started_at DESC,ended_at DESC,interval_id DESC LIMIT ?",
                (*interval_parameters, limit + 1),
            ).fetchall()

        candidates = []
        for row in timeline_rows:
            order = (
                row["started_at"], row["ended_at"], 1, row["record_id"],
            )
            try:
                lineage = json.loads(row["category_lineage"])
            except (TypeError, json.JSONDecodeError):
                lineage = []
            candidates.append((order, {
                "record_id": row["record_id"],
                "windows_sid": row["windows_sid"],
                "usage_guard_username": row["usage_guard_username"],
                "windows_identity_mapped": True,
                "kind": row["session_kind"], "id": row["session_id"],
                "key": row["target_key"], "label": target_display_label(
                    row["target_key"], row["label"],
                ),
                "category": row["category_key"],
                "category_lineage": lineage if isinstance(lineage, list) else [],
                "started_at": row["started_at"], "ended_at": row["ended_at"],
                "windows_session_id": row["windows_session_id"],
                "started_before_tracking": bool(row["started_before_tracking"]),
                "source": row["source"],
            }))
        for row in interval_rows:
            order = (
                row["started_at"], row["ended_at"], 0, row["interval_id"],
            )
            candidates.append((order, {
                "record_id": row["interval_id"],
                "windows_sid": row["windows_sid"],
                "usage_guard_username": row["usage_guard_username"],
                "windows_identity_mapped": True,
                "kind": "active", "id": "active:" + row["target_key"],
                "key": row["target_key"], "label": target_display_label(
                    row["target_key"], row["target_key"],
                ),
                "category": row["category_key"],
                "category_lineage": [row["category_key"]]
                if row["category_key"] else [],
                "started_at": row["started_at"], "ended_at": row["ended_at"],
                "source": "activity_interval",
            }))
        candidates.sort(key=lambda item: item[0], reverse=True)

        selected = []
        encoded_bytes = 2  # JSON list brackets.
        selected_order = None
        for order, record in candidates:
            if len(selected) >= limit:
                break
            record_bytes = len(json.dumps(
                record, ensure_ascii=False, separators=(",", ":"),
            ).encode("utf-8")) + (1 if selected else 0)
            if encoded_bytes + record_bytes > max_bytes:
                if not selected:
                    raise ValueError(
                        "Lot de tranches d’activité trop volumineux."
                    )
                break
            selected.append(record)
            selected_order = order
            encoded_bytes += record_bytes
        has_more = len(selected) < len(candidates)
        next_before = (
            self._activity_history_cursor(selected_order)
            if has_more and selected_order else ""
        )
        # Responses are chronological like all existing overview payloads;
        # the cursor still points immediately before the oldest returned row.
        selected.reverse()
        return selected, {
            "has_more": has_more, "next_before": next_before,
            "rows": len(selected), "payload_bytes": encoded_bytes,
            "max_rows": limit, "max_bytes": max_bytes,
        }

    def device_activity_sessions(
        self, device_id, *, username=None, start=None, end=None, limit=10_000,
    ):
        """Return a bounded timeline from normalized rows, never an archive blob."""
        limit = max(1, min(10_000, int(limit)))
        timeline = self.activity_timeline_sessions(
            device_id, username=username, start=start, end=end, limit=limit + 1,
        )
        clauses = ["device_id=?", f"NOT ({OTHER_SITES_USAGE_SQL})"]
        parameters = [str(device_id or "").strip()]
        if username:
            clauses.append("usage_guard_username=?")
            parameters.append(str(username).strip())
        if start is not None:
            clauses.append("ended_at>?")
            parameters.append(_aware_utc(start).isoformat(timespec="milliseconds"))
        if end is not None:
            clauses.append("started_at<?")
            parameters.append(_aware_utc(end).isoformat(timespec="milliseconds"))
        with self.connect() as db:
            archived = db.execute(
                "SELECT interval_id,windows_sid,usage_guard_username,target_key,"
                "category_key,started_at,ended_at FROM activity_intervals WHERE "
                + " AND ".join(clauses)
                + " ORDER BY started_at DESC,interval_id DESC LIMIT ?",
                (*parameters, limit + 1),
            ).fetchall()
            live_clauses = [
                clause.replace("ended_at", "observed_at") for clause in clauses
            ]
            live = db.execute(
                "SELECT live_id,windows_sid,usage_guard_username,target_key,"
                "category_key,started_at,observed_at FROM activity_live_intervals "
                "WHERE " + " AND ".join(live_clauses)
                + " ORDER BY started_at DESC,live_id DESC LIMIT 257",
                parameters,
            ).fetchall()
        result = list(timeline)
        identities = {
            (
                str(item.get("kind") or ""), str(item.get("key") or ""),
                str(item.get("started_at") or ""),
                str(item.get("ended_at") or ""),
                str(item.get("windows_sid") or "").upper(),
            )
            for item in result
        }
        for row in reversed(archived):
            identity = (
                "active", row["target_key"], row["started_at"], row["ended_at"],
                str(row["windows_sid"]).upper(),
            )
            if identity in identities:
                continue
            identities.add(identity)
            result.append({
                "record_id": row["interval_id"],
                "windows_sid": row["windows_sid"],
                "usage_guard_username": row["usage_guard_username"],
                "windows_identity_mapped": True,
                "kind": "active", "id": "active:" + row["target_key"],
                "key": row["target_key"], "label": target_display_label(
                    row["target_key"], row["target_key"],
                ),
                "category": row["category_key"],
                "category_lineage": [row["category_key"]]
                if row["category_key"] else [],
                "started_at": row["started_at"], "ended_at": row["ended_at"],
                "source": "activity_interval",
            })
        for row in reversed(live):
            result.append({
                "record_id": row["live_id"],
                "windows_sid": row["windows_sid"],
                "usage_guard_username": row["usage_guard_username"],
                "windows_identity_mapped": True,
                "kind": "active", "id": "active:" + row["target_key"],
                "key": row["target_key"], "label": target_display_label(
                    row["target_key"], row["target_key"],
                ),
                "category": row["category_key"],
                "category_lineage": [row["category_key"]]
                if row["category_key"] else [],
                "started_at": row["started_at"], "ended_at": None,
                "last_observed_at": row["observed_at"],
                "source": "activity_live_interval",
            })
        result.sort(key=lambda item: (
            str(item.get("started_at") or ""),
            str(item.get("ended_at") or ""), str(item.get("record_id") or ""),
        ))
        truncated = len(archived) > limit or len(result) > limit
        if len(result) > limit:
            result = result[-limit:]
        return result, truncated

    def activity_analysis_revision(self, device_id, username=None):
        """Return an opaque revision for the complete closed archive.

        Analysis clients normally refresh only a recent tail. A daily import
        or normalized-history backfill can nevertheless add or correct a day
        before that tail. The revision is deliberately independent from the
        requested date window so such a cache can be invalidated without
        downloading the raw archive. The current UTC day and live intervals
        are excluded: they are mutable tail data already covered by deltas.
        """
        device_id = str(device_id or "").strip()
        username = str(username or "").strip()
        clauses = ["device_id=?"]
        parameters = [device_id]
        if username:
            clauses.append("usage_guard_username=?")
            parameters.append(username)
        where = " AND ".join(clauses)
        settled_before = datetime.combine(
            datetime.now(timezone.utc).date(), datetime.min.time(),
            tzinfo=timezone.utc,
        ).isoformat(timespec="milliseconds")
        source = {"schema": 1}
        with self.connect() as db:
            for table, identifier in (
                ("activity_intervals", "interval_id"),
                ("activity_timeline_sessions", "record_id"),
            ):
                row = db.execute(
                    "SELECT COUNT(*) AS row_count,"
                    f"MIN({identifier}) AS first_id,"
                    f"MAX({identifier}) AS last_id,"
                    "MIN(started_at) AS first_started_at,"
                    "MAX(ended_at) AS last_ended_at,"
                    "MAX(received_at) AS last_received_at "
                    f"FROM {table} WHERE {where} AND ended_at<?",
                    (*parameters, settled_before),
                ).fetchone()
                source[table] = [
                    int(row["row_count"] or 0),
                    str(row["first_id"] or ""),
                    str(row["last_id"] or ""),
                    str(row["first_started_at"] or ""),
                    str(row["last_ended_at"] or ""),
                    str(row["last_received_at"] or ""),
                ]
            source["activity_daily_aggregate_batches"] = [
                [
                    str(row["usage_guard_username"] or ""),
                    str(row["local_day"] or ""),
                    str(row["content_hash"] or ""),
                ]
                for row in db.execute(
                    "SELECT usage_guard_username,local_day,content_hash FROM "
                    "activity_daily_aggregate_batches WHERE " + where
                    + " ORDER BY usage_guard_username,local_day",
                    parameters,
                ).fetchall()
            ]
            source["activity_daily_legacy"] = [
                [
                    str(row["usage_guard_username"] or ""),
                    str(row["local_day"] or ""),
                    str(row["metric_kind"] or ""),
                    str(row["metric_key"] or ""),
                    float(row["seconds"] or 0),
                ]
                for row in db.execute(
                    "SELECT usage_guard_username,local_day,metric_kind,"
                    "metric_key,seconds FROM activity_daily_legacy WHERE "
                    + where
                    + " ORDER BY usage_guard_username,local_day,metric_kind,"
                    "metric_key",
                    parameters,
                ).fetchall()
            ]
        return "analysis-v1-" + json_hash(source)

    def device_activity_analysis_summary(
        self, device_id, *, username=None, start=None, end=None,
        timezone_name="",
    ):
        """Aggregate the complete normalized history without returning rows.

        Raw sessions remain cursor-paginated.  This method streams sorted SQL
        cursors into day/key union accumulators, so analyses cover the oldest
        normalized date without loading or serializing the interval archive.
        Server-local legacy daily totals are a read-only analysis fallback and
        never participate in quota decisions.
        """
        device_id = str(device_id or "").strip()
        username = str(username or "").strip()
        view_timezone = _view_timezone(timezone_name)
        lower = _aware_utc(start) if start is not None else None
        upper = _aware_utc(end) if end is not None else None
        if lower is not None and upper is not None and upper <= lower:
            raise ValueError("Période d’activité invalide.")

        def split_days(opened, closed):
            opened = max(opened, lower) if lower is not None else opened
            closed = min(closed, upper) if upper is not None else closed
            while opened < closed:
                local = opened.astimezone(view_timezone)
                next_local = datetime.combine(
                    local.date() + timedelta(days=1), datetime.min.time(),
                    tzinfo=view_timezone,
                )
                boundary = next_local.astimezone(timezone.utc)
                segment_end = min(closed, boundary)
                yield local.date().isoformat(), opened, segment_end
                opened = segment_end

        authoritative_daily_aggregates = set()

        class UnionAccumulator:
            def __init__(self, suppress_authoritative_days=True):
                self._states = {}
                self._suppress_authoritative_days = bool(
                    suppress_authoritative_days
                )

            def add(self, group, opened, closed, owner=""):
                for day, segment_start, segment_end in split_days(opened, closed):
                    if (
                        self._suppress_authoritative_days
                        and (str(owner or "").casefold(), day)
                        in authoritative_daily_aggregates
                    ):
                        continue
                    key = (day, str(group or ""))
                    state = self._states.get(key)
                    if state is None:
                        self._states[key] = [
                            segment_start, segment_end, 0.0,
                        ]
                    elif segment_start <= state[1]:
                        if segment_end > state[1]:
                            state[1] = segment_end
                    else:
                        state[2] += (state[1] - state[0]).total_seconds()
                        state[0], state[1] = segment_start, segment_end

            def values(self):
                return {
                    key: round(total + (closed - opened).total_seconds(), 3)
                    for key, (opened, closed, total) in self._states.items()
                }

        def conditions(end_field):
            clauses, parameters = ["device_id=?"], [device_id]
            if username:
                clauses.append("usage_guard_username=?")
                parameters.append(username)
            if lower is not None:
                clauses.append(f"{end_field} > ?")
                parameters.append(lower.isoformat(timespec="milliseconds"))
            if upper is not None:
                clauses.append("started_at < ?")
                parameters.append(upper.isoformat(timespec="milliseconds"))
            return " AND ".join(clauses), parameters

        archived_where, archived_parameters = conditions("ended_at")
        live_where, live_parameters = conditions("observed_at")
        timeline_where, timeline_parameters = conditions("ended_at")
        active_by_target = UnionAccumulator()
        active_all = UnionAccumulator()
        # Open durations and launch counts do not exist in the compact daily
        # format.  Keep the exact timeline for those auxiliary fields, while
        # corrected daily batches replace exact/legacy *usage totals* for the
        # same owner and local day.
        open_by_target = UnionAccumulator(suppress_authoritative_days=False)
        passive_by_label = UnionAccumulator()
        windows_all = UnionAccumulator()
        category_by_target = {}
        launches = {}
        passive_launches = {}
        window_summary = {}

        legacy_clauses = ["device_id=?"]
        legacy_parameters = [device_id]
        if username:
            legacy_clauses.append("usage_guard_username=?")
            legacy_parameters.append(username)
        if lower is not None:
            legacy_clauses.append("local_day>=?")
            legacy_parameters.append(
                lower.astimezone(view_timezone).date().isoformat()
            )
        if upper is not None:
            legacy_clauses.append("local_day<=?")
            legacy_parameters.append(
                (upper - timedelta(microseconds=1)).astimezone(
                    view_timezone
                ).date().isoformat()
            )
        aggregate_clauses = [
            clause.replace("local_day", "batch.local_day")
            .replace("device_id", "batch.device_id")
            .replace(
                "usage_guard_username", "batch.usage_guard_username",
            )
            for clause in legacy_clauses
        ]

        with self.connect() as db:
            authoritative_daily_aggregates.update((
                str(row["usage_guard_username"] or "").casefold(),
                str(row["local_day"] or ""),
            ) for row in db.execute(
                "SELECT batch.usage_guard_username,batch.local_day FROM "
                "activity_daily_aggregate_batches AS batch WHERE "
                + " AND ".join(aggregate_clauses),
                legacy_parameters,
            ))
            active_sql = (
                "SELECT usage_guard_username,target_key,category_key,"
                "started_at,ended_at "
                "FROM activity_intervals WHERE " + archived_where
                + " UNION ALL SELECT usage_guard_username,target_key,"
                "category_key,started_at,observed_at AS ended_at FROM "
                "activity_live_intervals WHERE "
                + live_where + " ORDER BY target_key,started_at,ended_at"
            )
            active_parameters = (*archived_parameters, *live_parameters)
            for row in db.execute(active_sql, active_parameters):
                try:
                    opened = _aware_utc(row["started_at"])
                    closed = _aware_utc(row["ended_at"])
                except (TypeError, ValueError):
                    continue
                if closed <= opened:
                    continue
                key = str(row["target_key"] or "")
                active_by_target.add(
                    key, opened, closed, row["usage_guard_username"],
                )
                if row["category_key"]:
                    category_by_target[key] = str(row["category_key"])

            active_all_sql = (
                "SELECT usage_guard_username,started_at,ended_at FROM "
                "activity_intervals WHERE " + archived_where
                + " UNION ALL SELECT usage_guard_username,started_at,"
                "observed_at AS ended_at FROM activity_live_intervals WHERE "
                + live_where
                + " ORDER BY started_at,ended_at"
            )
            for row in db.execute(active_all_sql, active_parameters):
                try:
                    opened = _aware_utc(row["started_at"])
                    closed = _aware_utc(row["ended_at"])
                except (TypeError, ValueError):
                    continue
                if closed > opened:
                    active_all.add(
                        "computer", opened, closed,
                        row["usage_guard_username"],
                    )

            open_sql = (
                "SELECT target_key,started_at,ended_at FROM activity_intervals "
                "WHERE " + archived_where
                + " UNION ALL SELECT target_key,started_at,observed_at AS "
                "ended_at FROM activity_live_intervals WHERE " + live_where
                + " UNION ALL SELECT target_key,started_at,ended_at FROM "
                "activity_timeline_sessions WHERE " + timeline_where
                + " AND session_kind IN ('program','web') "
                "ORDER BY target_key,started_at,ended_at"
            )
            open_parameters = (
                *archived_parameters, *live_parameters, *timeline_parameters,
            )
            for row in db.execute(open_sql, open_parameters):
                try:
                    opened = _aware_utc(row["started_at"])
                    closed = _aware_utc(row["ended_at"])
                except (TypeError, ValueError):
                    continue
                if closed > opened:
                    open_by_target.add(row["target_key"], opened, closed)

            timeline_sql = (
                "SELECT usage_guard_username,session_kind,target_key,label,"
                "started_at,ended_at "
                "FROM activity_timeline_sessions WHERE " + timeline_where
                + " AND session_kind IN "
                "('program','web','multimedia') "
                "ORDER BY session_kind,label,started_at,ended_at,target_key"
            )
            for row in db.execute(timeline_sql, timeline_parameters):
                try:
                    opened = _aware_utc(row["started_at"])
                    closed = _aware_utc(row["ended_at"])
                except (TypeError, ValueError):
                    continue
                if closed <= opened:
                    continue
                kind = str(row["session_kind"])
                start_day = opened.astimezone(view_timezone).date().isoformat()
                if kind in {"program", "web"}:
                    key = str(row["target_key"] or "")
                    launches[(start_day, key)] = launches.get(
                        (start_day, key), 0,
                    ) + 1
                elif kind == "multimedia":
                    label = str(row["label"] or "Multimédia")
                    passive_by_label.add(
                        label, opened, closed,
                        row["usage_guard_username"],
                    )
                    passive_launches[(start_day, label)] = passive_launches.get(
                        (start_day, label), 0,
                    ) + 1
            windows_sql = (
                "SELECT usage_guard_username,started_at,ended_at FROM "
                "activity_timeline_sessions "
                "WHERE " + timeline_where
                + " AND session_kind='windows_session' "
                "ORDER BY started_at,ended_at"
            )
            for row in db.execute(windows_sql, timeline_parameters):
                try:
                    opened = _aware_utc(row["started_at"])
                    closed = _aware_utc(row["ended_at"])
                except (TypeError, ValueError):
                    continue
                if closed <= opened:
                    continue
                windows_all.add(
                    "computer", opened, closed,
                    row["usage_guard_username"],
                )
                for day, segment_start, segment_end in split_days(
                    opened, closed,
                ):
                    current = window_summary.setdefault(day, {
                        "sessions": 0, "first_started_at": "",
                        "last_ended_at": "", "carried_in": False,
                        "carried_out": False,
                    })
                    current["sessions"] += 1
                    if opened == segment_start:
                        stamp = opened.isoformat(timespec="milliseconds")
                        if not current["first_started_at"] or stamp < current[
                            "first_started_at"
                        ]:
                            current["first_started_at"] = stamp
                    else:
                        current["carried_in"] = True
                    if closed == segment_end:
                        stamp = closed.isoformat(timespec="milliseconds")
                        if not current["last_ended_at"] or stamp > current[
                            "last_ended_at"
                        ]:
                            current["last_ended_at"] = stamp
                    else:
                        current["carried_out"] = True

            legacy_rows = db.execute(
                "SELECT usage_guard_username,local_day,metric_kind,"
                "metric_key,seconds FROM "
                "activity_daily_legacy WHERE "
                + " AND ".join(legacy_clauses)
                + " ORDER BY local_day,metric_kind,metric_key",
                legacy_parameters,
            ).fetchall()
            aggregate_rows = db.execute(
                "SELECT batch.usage_guard_username,batch.local_day,"
                "metric.metric_kind,metric.metric_key,metric.seconds FROM "
                "activity_daily_aggregate_batches AS "
                "batch JOIN activity_daily_aggregate_metrics AS metric ON "
                "metric.device_id=batch.device_id AND "
                "metric.aggregate_id=batch.aggregate_id WHERE "
                + " AND ".join(aggregate_clauses)
                + " ORDER BY batch.local_day,metric.metric_kind,"
                "metric.metric_key",
                legacy_parameters,
            ).fetchall()

        active_values = active_by_target.values()
        active_totals = active_all.values()
        open_values = open_by_target.values()
        passive_values = passive_by_label.values()
        window_values = windows_all.values()
        days = {}

        def day_entry(day):
            return days.setdefault(day, {
                "date": day, "usage": {}, "passive": {}, "system": {},
                "other_sites": {},
            })

        authoritative_rows = [
            row for row in legacy_rows
            if (
                str(row["usage_guard_username"] or "").casefold(),
                str(row["local_day"] or ""),
            ) not in authoritative_daily_aggregates
        ]
        authoritative_rows.extend(aggregate_rows)
        for row in authoritative_rows:
            day = day_entry(str(row["local_day"]))
            kind, key, seconds = (
                str(row["metric_kind"]), str(row["metric_key"]),
                max(0.0, float(row["seconds"] or 0)),
            )
            if kind in {"active", "usage"}:
                day["usage"][key] = max(day["usage"].get(key, 0.0), seconds)
            elif kind == "passive":
                day["passive"][key] = max(
                    day["passive"].get(key, 0.0), seconds,
                )
            elif kind == "system":
                day["system"][key] = max(
                    float(day["system"].get(key) or 0), seconds,
                )
            elif kind == "other_site":
                day["other_sites"][key] = max(
                    float(day["other_sites"].get(key) or 0), seconds,
                )

        catalog = self.device_catalog(device_id) or {}
        targets = catalog.get("targets")
        targets = targets if isinstance(targets, dict) else {}
        for (day, key), seconds in active_values.items():
            current = day_entry(day)["usage"].get(key, 0.0)
            day_entry(day)["usage"][key] = max(current, seconds)
        for (day, label), seconds in passive_values.items():
            current = day_entry(day)["passive"].get(label, 0.0)
            day_entry(day)["passive"][label] = max(current, seconds)
        for (day, _), seconds in active_totals.items():
            day_entry(day)["active_exact"] = seconds
        for (day, _), seconds in window_values.items():
            system = day_entry(day)["system"]
            system["on"] = max(float(system.get("on") or 0), seconds)
        for day, summary in window_summary.items():
            day_entry(day)["session_summary"] = summary

        result = []
        other_site_totals = {}
        for day_text in sorted(days):
            source = days[day_text]
            usage = []
            for key, seconds in source["usage"].items():
                metadata = targets.get(key)
                metadata = metadata if isinstance(metadata, dict) else {}
                usage.append({
                    "key": key,
                    "label": str(metadata.get("label") or key),
                    "category": str(
                        metadata.get("category")
                        or category_by_target.get(key, "")
                    ),
                    "site_category": str(metadata.get("site_category") or ""),
                    "category_scope": str(metadata.get("category_scope") or ""),
                    "seconds": round(seconds, 1),
                    "open_seconds": round(max(
                        seconds, open_values.get((day_text, key), 0.0),
                    ), 1),
                    "launches": int(launches.get((day_text, key), 0)),
                    "web": key.startswith("site:"), "multimedia": False,
                })
            passive = [{
                "label": label, "seconds": round(seconds, 1),
                "open_seconds": round(seconds, 1),
                "launches": int(passive_launches.get((day_text, label), 0)),
            } for label, seconds in source["passive"].items()]
            other_sites = []
            for key, seconds in source["other_sites"].items():
                parts = str(key).split(":", 2)
                if len(parts) != 3 or parts[0] != "site":
                    continue
                browser, host = parts[1], parts[2]
                other_sites.append({
                    "browser": browser, "host": host,
                    "seconds": round(seconds, 1),
                })
                identity = (browser, host)
                other_site_totals[identity] = (
                    other_site_totals.get(identity, 0.0) + seconds
                )
            legacy_foreground = float(
                source["system"].get("foreground") or 0
            )
            active = max(
                float(source.get("active_exact") or 0), legacy_foreground,
                sum(float(item["seconds"]) for item in usage)
                if not legacy_foreground and not source.get("active_exact")
                else 0,
            )
            result.append({
                "date": day_text,
                "usage": sorted(usage, key=lambda item: -item["seconds"]),
                "passive": sorted(
                    passive, key=lambda item: -item["seconds"],
                ),
                "other_sites": sorted(
                    other_sites, key=lambda item: -item["seconds"],
                ),
                "active": round(active, 1),
                "system": source["system"],
                "session_summary": source.get("session_summary", {}),
            })
        return {
            "daily_stats": result,
            "other_sites": [
                {
                    "browser": browser, "host": host,
                    "seconds": round(seconds, 1),
                }
                for (browser, host), seconds in sorted(
                    other_site_totals.items(), key=lambda item: -item[1]
                )
            ],
            "timeline": {
                "start": result[0]["date"] if result else "",
                "end": result[-1]["date"] if result else "",
            },
            "analysis_coverage": {
                "complete": True,
                "source": "normalized-server-aggregates",
                "start": result[0]["date"] if result else "",
                "end": result[-1]["date"] if result else "",
                "revision": self.activity_analysis_revision(
                    device_id, username or None,
                ),
            },
        }

    def user_usage_union(
        self, username, start, end, target_key=None, category_key=None,
        device_ids=None,
    ):
        username = str(username or "").strip()
        lower, upper = _aware_utc(start), _aware_utc(end)
        if upper <= lower:
            raise ValueError("Période d’activité invalide.")
        canonical_categories = (
            self._user_canonical_category_map(username)
            if category_key is not None else {}
        )
        canonical_targets = set(canonical_categories)
        canonical_members = {
            target for target, categories in canonical_categories.items()
            if str(category_key) in categories
        }
        selected_device_ids = (
            self.selected_user_device_ids(username, device_ids)
            if device_ids is not None else None
        )
        with self.connect() as db:
            rows = []
            for table, identifier, end_field, categories in (
                (
                    "activity_intervals", "interval_id", "ended_at",
                    "activity_interval_categories",
                ),
                (
                    "activity_live_intervals", "live_id", "observed_at",
                    "activity_live_categories",
                ),
            ):
                clauses = [
                    "usage_guard_username=?", f"{end_field}>?", "started_at<?",
                ]
                parameters = [
                    username, lower.isoformat(timespec="milliseconds"),
                    upper.isoformat(timespec="milliseconds"),
                ]
                if target_key is not None:
                    clauses.append("target_key=?")
                    parameters.append(str(target_key))
                if category_key is not None:
                    stamped = (
                        f"EXISTS(SELECT 1 FROM {categories} AS cats "
                        f"WHERE cats.device_id={table}.device_id "
                        f"AND cats.{identifier}={table}.{identifier} "
                        "AND cats.category_key=?)"
                    )
                    membership = []
                    membership_parameters = []
                    if canonical_members:
                        membership.append(
                            "target_key IN (" + ",".join(
                                "?" for _ in canonical_members
                            ) + ")"
                        )
                        membership_parameters.extend(sorted(canonical_members))
                    if canonical_targets:
                        membership.append(
                            "(target_key NOT IN (" + ",".join(
                                "?" for _ in canonical_targets
                            ) + f") AND {stamped})"
                        )
                        membership_parameters.extend(sorted(canonical_targets))
                        membership_parameters.append(str(category_key))
                    else:
                        membership.append(stamped)
                        membership_parameters.append(str(category_key))
                    clauses.append("(" + " OR ".join(membership) + ")")
                    parameters.extend(membership_parameters)
                if selected_device_ids is not None:
                    clauses.append(
                        "device_id IN (" + ",".join(
                            "?" for _ in selected_device_ids
                        ) + ")"
                    )
                    parameters.extend(selected_device_ids)
                rows.extend(db.execute(
                    f"SELECT started_at,{end_field} AS ended_at FROM {table} "
                    "WHERE " + " AND ".join(clauses), parameters,
                ).fetchall())
        return interval_union_seconds(
            [dict(row) for row in rows], lower.isoformat(), upper.isoformat(),
        )

    def replace_live_activity_intervals(self, device_id, intervals):
        """Atomically replace bounded live intervals reported by one device."""
        device_id = str(device_id or "").strip()
        if not isinstance(intervals, list) or len(intervals) > 256:
            raise ValueError("Lot de tranches actives invalide.")
        normalized = []
        for source in intervals:
            source = dict(source or {})
            live_id = str(source.get("live_id") or "").strip()
            if not IDEMPOTENCY_KEY_PATTERN.fullmatch(live_id):
                raise ValueError("Identifiant de tranche active invalide.")
            sid = str(source.get("windows_sid") or "").strip().upper()
            mapping = self.user_for_windows_sid(device_id, sid)
            if not mapping:
                raise ValueError("Session Windows non associée.")
            target_key = str(source.get("target_key") or "").strip()
            if not target_key.startswith(("app:", "site:", "category:")):
                raise ValueError("Cible de tranche active invalide.")
            category_key = str(source.get("category_key") or "").strip()
            supplied_categories = source.get("category_keys", [])
            if not isinstance(supplied_categories, list):
                raise ValueError("Lignée de catégorie historique invalide.")
            category_keys = list(dict.fromkeys(
                str(category).strip() for category in supplied_categories
                if str(category).strip()
            ))
            if category_key and category_key not in category_keys:
                category_keys.insert(0, category_key)
            if len(category_keys) > 64 or any(
                len(category) > 512
                or any(ord(character) < 32 for character in category)
                for category in category_keys
            ):
                raise ValueError("Lignée de catégorie historique invalide.")
            opened = _aware_utc(source.get("started_at"))
            observed = _aware_utc(source.get("observed_at"))
            if observed < opened:
                raise ValueError("Observation active antérieure à son début.")
            try:
                revision = int(source.get("policy_revision") or 0)
            except (TypeError, ValueError) as error:
                raise ValueError("Révision de tranche active invalide.") from error
            if revision < 0:
                raise ValueError("Révision de tranche active invalide.")
            normalized.append(((
                device_id, live_id, sid, mapping["usage_guard_username"],
                target_key, category_key,
                opened.isoformat(timespec="milliseconds"),
                observed.isoformat(timespec="milliseconds"), revision,
            ), category_keys))
        with self._lock, self.connect() as db:
            db.execute(
                "DELETE FROM activity_live_intervals WHERE device_id=?",
                (device_id,),
            )
            for item, category_keys in normalized:
                db.execute(
                    "INSERT INTO activity_live_intervals(device_id,live_id,"
                    "windows_sid,usage_guard_username,target_key,category_key,"
                    "started_at,observed_at,policy_revision,received_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (*item, utc_now()),
                )
                db.executemany(
                    "INSERT INTO activity_live_categories(device_id,live_id,"
                    "category_key) VALUES(?,?,?)",
                    [(device_id, item[1], category) for category in category_keys],
                )
            self._apply_activity_target_deletion_seals(
                db, device_id=device_id,
            )
        return {"active": len(normalized)}

    def user_usage_breakdown(self, username, start, end, device_ids=None):
        """Return person-wide union totals without exposing per-device intervals."""
        username = str(username or "").strip()
        lower, upper = _aware_utc(start), _aware_utc(end)
        if upper <= lower:
            raise ValueError("Période d’activité invalide.")
        lower_text = lower.isoformat(timespec="milliseconds")
        upper_text = upper.isoformat(timespec="milliseconds")
        selected_device_ids = self.selected_user_device_ids(
            username, device_ids,
        )
        canonical_categories = self._user_canonical_category_map(username)
        target_groups, category_groups, all_intervals = {}, {}, []
        with self.connect() as db:
            for table, identifier, end_field, categories in (
                (
                    "activity_intervals", "interval_id", "ended_at",
                    "activity_interval_categories",
                ),
                (
                    "activity_live_intervals", "live_id", "observed_at",
                    "activity_live_categories",
                ),
            ):
                device_clause = (
                    " AND device_id IN (" + ",".join(
                        "?" for _ in selected_device_ids
                    ) + ")"
                ) if selected_device_ids else ""
                rows = db.execute(
                    f"SELECT device_id,{identifier},target_key,started_at,"
                    f"{end_field} AS ended_at FROM {table} WHERE "
                    f"usage_guard_username=? AND {end_field}>? AND started_at<?"
                    f"{device_clause}",
                    (username, lower_text, upper_text, *selected_device_ids),
                ).fetchall()
                for row in rows:
                    interval = {
                        "started_at": row["started_at"],
                        "ended_at": row["ended_at"],
                    }
                    all_intervals.append(interval)
                    target_groups.setdefault(row["target_key"], []).append(interval)
                    for category in canonical_categories.get(
                        row["target_key"], []
                    ):
                        category_groups.setdefault(category, []).append(interval)
                source_device_clause = (
                    " AND source.device_id IN (" + ",".join(
                        "?" for _ in selected_device_ids
                    ) + ")"
                ) if selected_device_ids else ""
                category_rows = db.execute(
                    f"SELECT cats.category_key,source.target_key,source.started_at,"
                    f"source.{end_field} AS ended_at FROM {table} AS source "
                    f"JOIN {categories} AS cats ON "
                    "cats.device_id=source.device_id AND "
                    f"cats.{identifier}=source.{identifier} WHERE "
                    f"source.usage_guard_username=? AND source.{end_field}>? "
                    f"AND source.started_at<?{source_device_clause}",
                    (username, lower_text, upper_text, *selected_device_ids),
                ).fetchall()
                for row in category_rows:
                    # Known targets use their current canonical classification.
                    # Stamped categories remain the fallback for historical
                    # intervals whose target has not reached any catalogue.
                    if row["target_key"] in canonical_categories:
                        continue
                    category_groups.setdefault(row["category_key"], []).append({
                        "started_at": row["started_at"],
                        "ended_at": row["ended_at"],
                    })
        measure = lambda intervals: interval_union_seconds(
            intervals, lower_text, upper_text,
        )
        return {
            "usage_guard_username": username,
            "start": lower.isoformat(timespec="milliseconds"),
            "end": upper.isoformat(timespec="milliseconds"),
            "seconds": measure(all_intervals),
            "targets": sorted((
                {"key": key, "seconds": measure(intervals)}
                for key, intervals in target_groups.items()
            ), key=lambda item: (-item["seconds"], item["key"].casefold())),
            "categories": sorted((
                {"key": key, "seconds": measure(intervals)}
                for key, intervals in category_groups.items()
            ), key=lambda item: (-item["seconds"], item["key"].casefold())),
        }

    def revoke_device(self, device_id):
        device_id = str(device_id or "").strip()
        with self._lock, self.connect() as db:
            cursor = db.execute(
                "UPDATE devices SET revoked_at=?,token_hash='',updated_at=? WHERE device_id=?",
                (utc_now(), utc_now(), device_id),
            )
        if cursor.rowcount != 1:
            raise ValueError("Appareil inconnu.")

    def rename_device(self, device_id, label=""):
        device_id = str(device_id or "").strip()
        label = str(label or "").strip()
        if not device_id:
            raise ValueError("Ordinateur inconnu.")
        if len(label) > 80:
            raise ValueError("Le nom de l’ordinateur est trop long.")
        with self._lock, self.connect() as db:
            device = db.execute(
                "SELECT hostname_last_seen FROM devices WHERE device_id=?",
                (device_id,),
            ).fetchone()
            if not device:
                raise ValueError("Ordinateur inconnu.")
            visible_name = label or str(device["hostname_last_seen"] or "").strip()
            if not visible_name:
                raise ValueError("Indiquez un nom pour cet ordinateur.")
            db.execute(
                "UPDATE devices SET label=?,updated_at=? WHERE device_id=?",
                (visible_name, utc_now(), device_id),
            )
        return next(
            device for device in self.list_devices()
            if device["device_id"] == device_id
        )

    def assign_unscoped_users(self, device_id):
        device_id = str(device_id or "").strip()
        with self._lock, self.connect() as db:
            if not db.execute(
                "SELECT 1 FROM devices WHERE device_id=?", (device_id,)
            ).fetchone():
                raise ValueError("Ordinateur inconnu.")
            if db.execute("SELECT COUNT(*) FROM devices").fetchone()[0] != 1:
                return
            db.execute(
                "INSERT OR IGNORE INTO user_devices(username,device_id) "
                "SELECT u.username,? FROM users u "
                "WHERE u.role IN ('limited','user') AND NOT EXISTS ("
                "SELECT 1 FROM user_devices d WHERE d.username=u.username) "
                "AND NOT EXISTS (SELECT 1 FROM device_enrollments e "
                "WHERE e.device_id=? AND e.used_at IS NOT NULL "
                "AND e.username IS NOT NULL)",
                (device_id, device_id),
            )

    def list_devices(self):
        with self.connect() as db:
            rows = db.execute(
                "SELECT d.device_id,d.label,d.hostname_last_seen,d.created_at,d.updated_at,"
                "d.credential_updated_at,d.revoked_at,CASE WHEN d.token_hash<>'' AND d.revoked_at IS NULL THEN 1 ELSE 0 END AS enrolled,"
                "COALESCE(p.online,0) AS online,p.last_seen "
                "FROM devices d LEFT JOIN device_presence p ON p.device_id=d.device_id "
                "ORDER BY d.label COLLATE NOCASE,d.device_id"
            ).fetchall()
        return [{**dict(row), "enrolled": bool(row["enrolled"]), "online": bool(row["online"])} for row in rows]

    def initialize_device_notification_policy(self, device_id):
        snapshot = self.snapshot(device_id) or {}
        rules = snapshot.get("notification_rules", [])
        if not isinstance(rules, list):
            rules = []
        with self._lock, self.connect() as db:
            db.execute(
                "INSERT OR IGNORE INTO device_notification_policies(device_id,payload,updated_at) VALUES(?,?,?)",
                (device_id, json.dumps(
                    self._protect_document_recipients({"rules": rules}),
                    ensure_ascii=False, separators=(",", ":"),
                ), utc_now()),
            )

    def update_device_notification_policy(self, device_id, action, rule=None, rule_id=""):
        with self._lock, self.connect() as db:
            row = db.execute(
                "SELECT payload FROM device_notification_policies WHERE device_id=?",
                (device_id,),
            ).fetchone()
            saved = self._unprotect_document_recipients(
                json.loads(row["payload"])
            ) if row else {"rules": []}
            rules = normalize_notification_rules(
                saved.get("rules", []) if isinstance(saved, dict) else []
            )
            requested_rule = dict(rule or {})
            requested_rule["kind"] = canonical_notification_kind(
                requested_rule.get("kind")
            )
            identifier = str(
                (rule or {}).get("id") if action == "set_notification_rule" else rule_id
            )
            rules = [item for item in rules if str(item.get("id") or "") != identifier]
            if action == "set_notification_rule":
                rules.append(requested_rule)
            rules = normalize_notification_rules(rules)
            db.execute(
                "INSERT INTO device_notification_policies(device_id,payload,updated_at) VALUES(?,?,?) "
                "ON CONFLICT(device_id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at",
                (device_id, json.dumps(
                    self._protect_document_recipients({"rules": rules}),
                    ensure_ascii=False, separators=(",", ":"),
                ), utc_now()),
            )

    def device_notification_rules(self, device_id, kind=""):
        """Return the server-side notification policy for one device."""
        with self.connect() as db:
            row = db.execute(
                "SELECT payload FROM device_notification_policies WHERE device_id=?",
                (str(device_id or ""),),
            ).fetchone()
        saved = self._unprotect_document_recipients(
            json.loads(row["payload"])
        ) if row else {"rules": []}
        rules = normalize_notification_rules(
            saved.get("rules", []) if isinstance(saved, dict) else []
        )
        requested = canonical_notification_kind(kind)
        return [
            dict(rule) for rule in rules
            if isinstance(rule, dict)
            and (
                not requested
                or canonical_notification_kind(rule.get("kind")) == requested
            )
        ]

    def device_notification_recipient_allowed(self, device_id, recipient, kind):
        recipient = str(recipient or "").strip().casefold()
        kind = str(kind or "").strip()
        if not recipient or kind not in EMAIL_TEMPLATE_KINDS | set(EMAIL_TEMPLATE_ALIASES):
            return False
        canonical_kind = canonical_notification_kind(kind)
        rules = self.device_notification_rules(device_id, canonical_kind)
        return any(
            rule.get("enabled")
            and "email" in (rule.get("channels") or [])
            and str(rule.get("email_recipient") or "").strip().casefold() == recipient
            and canonical_notification_kind(rule.get("kind")) == canonical_kind
            for rule in rules
        )

    def _user_scope(self, username):
        with self.connect() as db:
            row = db.execute(
                "SELECT role,is_admin FROM users WHERE username=?", (username,)
            ).fetchone()
            role = self._normalize_role(
                row["role"] if row else None,
                row["is_admin"] if row else False,
            )
            device_ids = [
                row["device_id"] for row in db.execute(
                    "SELECT device_id FROM user_devices WHERE username=? ORDER BY device_id",
                    (username,),
                ).fetchall()
            ]
            person_usernames = [
                item["person_username"] for item in db.execute(
                    "SELECT person_username FROM user_person_access "
                    "WHERE username=? ORDER BY person_username COLLATE NOCASE",
                    (username,),
                ).fetchall()
            ]
            if role == "admin":
                accessible_device_ids = [
                    item["device_id"] for item in db.execute(
                        "SELECT device_id FROM devices ORDER BY device_id"
                    ).fetchall()
                ]
                accessible_person_usernames = [
                    item["username"] for item in db.execute(
                        "SELECT username FROM users WHERE role='limited' "
                        "ORDER BY username COLLATE NOCASE"
                    ).fetchall()
                ]
            else:
                accessible_person_usernames = list(person_usernames)
                if role == "limited":
                    accessible_person_usernames.append(str(username))
                person_devices = [
                    item["device_id"] for item in db.execute(
                        "SELECT DISTINCT device_id FROM user_devices WHERE "
                        "username IN (SELECT person_username FROM "
                        "user_person_access WHERE username=?)",
                        (username,),
                    ).fetchall()
                ]
                accessible_device_ids = sorted(set(device_ids) | set(person_devices))
        return {
            "device_ids": device_ids,
            "person_usernames": person_usernames,
            "accessible_person_usernames": sorted(
                set(accessible_person_usernames), key=str.casefold,
            ),
            "accessible_device_ids": accessible_device_ids,
        }

    def user_can_access_device(self, username, device_id):
        return str(device_id or "") in self._user_scope(username)[
            "accessible_device_ids"
        ]

    def user_can_access_policy(self, actor, target, is_admin=False):
        actor = str(actor or "").strip()
        target = str(target or "").strip()
        if not actor or not target:
            return False
        users = {
            item["username"].casefold(): item for item in self.list_users()
        }
        target_user = users.get(target.casefold())
        if not target_user or target_user.get("role") != "limited":
            return False
        if is_admin or actor.casefold() == target_user["username"].casefold():
            return True
        scope = self._user_scope(actor)
        if target_user["username"] in set(
            scope.get("accessible_person_usernames") or []
        ):
            return True
        actor_scope = set(scope.get("accessible_device_ids") or [])
        return bool(actor_scope & set(target_user.get("device_ids") or []))

    def accessible_policy_users(self, actor, is_admin=False):
        """List only limited users whose policies the actor may inspect."""
        result = []
        for user in self.list_users():
            if user.get("role") != "limited" or not self.user_can_access_policy(
                actor, user["username"], is_admin,
            ):
                continue
            policy = self.user_policy(user["username"]) or {}
            device_ids = list(user.get("device_ids") or [])
            catalog_device_id, _catalog = self._user_canonical_catalog(
                user["username"]
            )
            result.append({
                "username": user["username"],
                "device_ids": device_ids,
                "catalog_device_id": (
                    str(catalog_device_id) if catalog_device_id else
                    (device_ids[0] if device_ids else "")
                ),
                "configured": bool(policy.get("configured")),
                "revision": int(policy.get("revision") or 0),
                "devices": list(policy.get("devices") or []),
            })
        return result

    def selected_user_device_ids(self, username, requested=None):
        """Validate an optional UI device scope against one limited person."""
        username = str(username or "").strip()
        with self.connect() as db:
            available = [
                str(row["device_id"]) for row in db.execute(
                    "SELECT device_id FROM user_devices WHERE username=? "
                    "ORDER BY device_id", (username,),
                ).fetchall()
            ]
        if requested is None:
            return available
        if not isinstance(requested, list):
            raise ValueError("Périmètre d’ordinateurs invalide.")
        selected = sorted({
            str(device_id).strip() for device_id in requested
            if str(device_id).strip()
        })
        if not selected:
            raise ValueError("Sélectionnez au moins un ordinateur.")
        unknown = sorted(set(selected) - set(available))
        if unknown:
            raise ValueError(
                "Un ordinateur sélectionné n’est pas associé à cette personne."
            )
        return selected

    def _catalog_command_for_user_device(
        self, username, device_id, command,
    ):
        """Stamp catalogue commands so another Windows session cannot apply them."""
        username = str(username or "").strip()
        device_id = str(device_id or "").strip()
        with self.connect() as db:
            user = db.execute(
                "SELECT username FROM users WHERE username=?", (username,),
            ).fetchone()
            if not user:
                raise ValueError("Utilisateur inconnu.")
            username = str(user["username"])
            windows_sids = [
                str(row["windows_sid"]).strip().upper()
                for row in db.execute(
                    "SELECT windows_sid FROM device_windows_identities WHERE "
                    "device_id=? AND usage_guard_username=? "
                    "ORDER BY windows_sid",
                    (device_id, username),
                ).fetchall()
                if str(row["windows_sid"] or "").strip()
            ]
        return {
            **dict(command or {}),
            "_usage_guard_target_username": username,
            "_usage_guard_target_windows_sids": windows_sids,
        }

    @staticmethod
    def _catalog_document(activity):
        """Extract only replaceable classification state from an activity store."""
        source = dict(activity or {})
        document = {}
        for field in CATALOG_DOCUMENT_FIELDS:
            if field == "site_category_order_manual":
                document[field] = bool(source.get(field, False))
                continue
            value = source.get(field)
            if field in CATALOG_DOCUMENT_LIST_FIELDS:
                document[field] = copy.deepcopy(value if isinstance(value, list) else [])
            else:
                document[field] = copy.deepcopy(value if isinstance(value, dict) else {})
        return document

    @staticmethod
    def _catalog_document_without_target(document, target_key):
        """Remove one exact target while preserving every unrelated entry."""
        document = copy.deepcopy(document) if isinstance(document, dict) else {}
        target_key = str(target_key or "").strip()
        document.setdefault("targets", {}).pop(target_key, None)
        for field in ("excluded", "excluded_sites", "target_order"):
            values = document.get(field)
            if isinstance(values, list):
                document[field] = [value for value in values if value != target_key]
        for field in ("merged_targets", "dismissed_targets"):
            values = document.get(field)
            if not isinstance(values, dict):
                continue
            document[field] = {
                source: destination
                for source, destination in values.items()
                if source != target_key and (
                    field != "merged_targets" or destination != target_key
                )
            }
        parts = target_key.split(":", 2)
        if len(parts) == 3 and parts[0] == "site":
            browser, host = parts[1], parts[2]
            sites_by_browser = document.get("browser_specific_sites")
            if isinstance(sites_by_browser, dict) and isinstance(
                sites_by_browser.get(browser), list
            ):
                sites_by_browser[browser] = [
                    value for value in sites_by_browser[browser]
                    if value != host
                ]
        return document

    @classmethod
    def _snapshot_without_user_target(
        cls, document, username, target_key, default_username="",
    ):
        """Sanitize a bounded snapshot without touching another user."""
        source = copy.deepcopy(document) if isinstance(document, dict) else {}
        username_key = str(username or "").strip().casefold()
        runtime = source.get("runtime")
        runtime = runtime if isinstance(runtime, dict) else {}
        identity = runtime.get("windows_identity")
        identity = identity if isinstance(identity, dict) else {}
        owner = str(
            identity.get("usage_guard_username") or default_username or ""
        ).strip().casefold()

        def belongs(item):
            stamped = str(
                (item or {}).get("usage_guard_username") or ""
            ).strip().casefold()
            return stamped == username_key if stamped else owner == username_key

        target_parts = str(target_key or "").split(":", 2)
        target_is_site = len(target_parts) == 3 and target_parts[0] == "site"

        def is_target_site(item=None, browser="", host=""):
            if not target_is_site:
                return False
            item = item if isinstance(item, dict) else {}
            candidate_key = str(item.get("key") or "").strip()
            if not candidate_key:
                candidate_browser = str(
                    item.get("browser") or browser or ""
                ).strip()
                candidate_host = str(item.get("host") or host or "").strip()
                if not candidate_browser or not candidate_host:
                    return False
                candidate_key = f"site:{candidate_browser}:{candidate_host}"
            try:
                return (
                    cls._validated_activity_deletion_target(candidate_key)
                    == target_key
                )
            except ValueError:
                return False

        source = cls._catalog_document_without_target(source, target_key)
        candidates = source.get("merge_candidates")
        if isinstance(candidates, list):
            source["merge_candidates"] = [
                item for item in candidates
                if not (
                    isinstance(item, dict)
                    and str(item.get("key") or "") == target_key
                )
            ]
        for field in ("usage", "open_usage"):
            values = source.get(field)
            if isinstance(values, list) and owner == username_key:
                source[field] = [
                    item for item in values
                    if not (
                        isinstance(item, dict)
                        and str(item.get("key") or "") == target_key
                    )
                ]
        sessions = source.get("sessions")
        if isinstance(sessions, list):
            source["sessions"] = [
                item for item in sessions
                if not (
                    isinstance(item, dict) and belongs(item)
                    and str(item.get("key") or "") == target_key
                )
            ]
        open_sessions = source.get("open_sessions")
        if isinstance(open_sessions, dict):
            source["open_sessions"] = {
                key: item for key, item in open_sessions.items()
                if not (
                    isinstance(item, dict) and belongs(item)
                    and str(item.get("key") or "") == target_key
                )
            }
        if owner == username_key:
            for values in (source.get("days"),):
                if isinstance(values, dict):
                    for daily in values.values():
                        if isinstance(daily, dict):
                            daily.pop(target_key, None)
            other_sites = source.get("other_sites")
            if isinstance(other_sites, list) and target_is_site:
                source["other_sites"] = [
                    item for item in other_sites
                    if not is_target_site(item)
                ]
            other_site_days = source.get("other_site_days")
            if isinstance(other_site_days, dict) and target_is_site:
                for browser, browser_days in other_site_days.items():
                    if not isinstance(browser_days, dict):
                        continue
                    for day, hosts in list(browser_days.items()):
                        if not isinstance(hosts, dict):
                            continue
                        browser_days[day] = {
                            host: seconds for host, seconds in hosts.items()
                            if not is_target_site(browser=browser, host=host)
                        }
            daily_stats = source.get("daily_stats")
            if isinstance(daily_stats, list):
                for daily in daily_stats:
                    if not isinstance(daily, dict):
                        continue
                    usage = daily.get("usage")
                    if isinstance(usage, list):
                        daily["usage"] = [
                            item for item in usage
                            if not (
                                isinstance(item, dict)
                                and str(item.get("key") or "") == target_key
                            )
                        ]
                    other_sites = daily.get("other_sites")
                    if isinstance(other_sites, list) and target_is_site:
                        daily["other_sites"] = [
                            item for item in other_sites
                            if not is_target_site(item)
                        ]
            current = source.get("current")
            if isinstance(current, dict) and str(
                current.get("target_key") or current.get("key") or ""
            ) == target_key:
                source["current"] = {}
            limits = source.get("limits")
            if isinstance(limits, list):
                source["limits"] = [
                    item for item in limits
                    if target_key not in {
                        str((item or {}).get("key") or ""),
                        str((item or {}).get("target_key") or ""),
                    }
                ]
        analysis = source.get("analysis")
        if isinstance(analysis, dict):
            source["analysis"] = cls._snapshot_without_user_target(
                analysis, username, target_key, owner,
            )
        return source

    @staticmethod
    def _snapshot_catalog_document(snapshot):
        """Rebuild catalogue fields exposed by a desktop snapshot.

        Snapshots flatten targets into merge_candidates and browser mappings
        into a list.  Converting those views back to the catalogue shape lets
        a rich snapshot repair an accidentally lightweight activity store.
        """
        source = copy.deepcopy(snapshot) if isinstance(snapshot, dict) else {}
        if not isinstance(source.get("targets"), dict):
            source["targets"] = {
                str(item.get("key") or "").strip(): {
                    field: copy.deepcopy(item.get(field))
                    for field in (
                        "label", "category", "site_category",
                        "category_scope", "manual",
                    )
                    if item.get(field) is not None and item.get(field) != ""
                }
                for item in source.get("merge_candidates", [])
                if isinstance(item, dict) and str(item.get("key") or "").strip()
            }
        if not isinstance(source.get("browser_categories"), dict):
            source["browser_categories"] = {
                str(item.get("browser") or "").strip(): str(
                    item.get("category") or ""
                ).strip()
                for item in source.get("browsers", [])
                if isinstance(item, dict)
                and str(item.get("browser") or "").strip()
            }
        excluded = source.get("excluded")
        if isinstance(excluded, list) and any(
            isinstance(item, dict) for item in excluded
        ):
            source["excluded"] = [
                str(item.get("key") or "").strip()
                for item in excluded if isinstance(item, dict)
                and str(item.get("key") or "").strip()
            ]
        return Store._catalog_document(source)

    @staticmethod
    def _catalog_document_score(document):
        browser_categories = {
            str(value) for value in document.get("browser_categories", {}).values()
            if str(value).strip()
        }
        categories = set(document.get("category_order", []))
        parents = document.get("category_parents", {})
        categories.update(parents)
        categories.update(parents.values())
        categorized = 0
        metadata_fields = 0
        for metadata in document.get("targets", {}).values():
            if not isinstance(metadata, dict):
                continue
            metadata_fields += sum(
                value not in {"", None, False} for value in metadata.values()
                if isinstance(value, (str, int, float, bool)) or value is None
            )
            category = str(metadata.get("category") or "").strip()
            if category and category not in {
                "__root__", "Applications non classées", "site", "sites",
            } | browser_categories:
                categories.add(category)
                categorized += 1
        categories.discard("")
        categories.discard("__root__")
        categories.discard("Applications non classées")
        return (
            len(categories), categorized,
            len(document.get("category_order", [])),
            len(document.get("target_order", [])),
            len(document.get("category_parents", {})),
            len(document.get("site_categories", [])),
            metadata_fields, len(document.get("targets", {})),
        )

    @staticmethod
    def _merge_catalog_documents(documents, preferred_categories=None):
        """Use the richest, freshest catalogue, then add missing identities."""
        normalized = [
            (
                str(item[0]), item[1],
                str(item[2] or "") if len(item) > 2 else "",
            )
            for item in documents or []
            if isinstance(item, (list, tuple)) and len(item) >= 2
            and isinstance(item[1], dict)
        ]
        if not normalized:
            raise ValueError("Aucun classement d’ordinateur n’est disponible.")
        preferred = {
            str(category).strip() for category in (preferred_categories or [])
            if str(category).strip()
        }

        def preference_score(document):
            if not preferred:
                return 0, 0
            target_categories = Store._catalog_target_categories(document)
            assigned = sum(
                bool(preferred & set(categories))
                for categories in target_categories.values()
            )
            resolvable = len(preferred & Store._catalog_categories(document))
            return assigned, resolvable

        def freshness(updated_at):
            try:
                return _aware_utc(updated_at).timestamp()
            except (TypeError, ValueError):
                return float("-inf")

        ranked = sorted(
            normalized,
            key=lambda item: (
                *(-value for value in preference_score(item[1])),
                *(-value for value in Store._catalog_document_score(item[1])),
                -freshness(item[2]),
                str(item[0]),
            ),
        )
        canonical_device_id, canonical, _updated_at = ranked[0]
        merged = copy.deepcopy(canonical)
        for _device_id, source, _source_updated_at in ranked[1:]:
            for field in CATALOG_DOCUMENT_LIST_FIELDS:
                values = merged.setdefault(field, [])
                values.extend(value for value in source.get(field, []) if value not in values)
            for field in CATALOG_DOCUMENT_DICT_FIELDS - {
                "targets", "browser_specific_sites", "navigation_position",
                "unclassified_position",
            }:
                destination = merged.setdefault(field, {})
                for key, value in source.get(field, {}).items():
                    destination.setdefault(key, copy.deepcopy(value))
            targets = merged.setdefault("targets", {})
            for key, metadata in source.get("targets", {}).items():
                if key not in targets:
                    targets[key] = copy.deepcopy(metadata)
                    continue
                if isinstance(targets[key], dict) and isinstance(metadata, dict):
                    for name, value in metadata.items():
                        if name not in targets[key] or targets[key][name] in {"", None}:
                            targets[key][name] = copy.deepcopy(value)
            specific_sites = merged.setdefault("browser_specific_sites", {})
            for browser, hosts in source.get("browser_specific_sites", {}).items():
                saved = specific_sites.setdefault(browser, [])
                if isinstance(hosts, list):
                    saved.extend(host for host in hosts if host not in saved)
        return canonical_device_id, merged

    def _user_catalog_documents(self, username, device_ids=None):
        """Load catalogues without coupling classification to usage history."""
        selected = self.selected_user_device_ids(username, device_ids)
        documents = []
        for device_id in selected:
            catalog, catalog_updated_at = self._load_document(
                "device_catalogs", device_id,
            )
            if catalog is None or not any(self._catalog_document_score(catalog)):
                snapshot, snapshot_updated_at = self._load_document(
                    "snapshots", device_id,
                )
                snapshot = snapshot or {}
                snapshot_catalog = self._snapshot_catalog_document(snapshot)
                if any(self._catalog_document_score(snapshot_catalog)):
                    catalog = snapshot_catalog
                    catalog_updated_at = snapshot_updated_at
            # Read-only compatibility for devices that have not published a
            # post-migration snapshot yet. New agents never upload this store.
            if catalog is None or not any(self._catalog_document_score(catalog)):
                stored, stored_updated_at = self._load_document(
                    "activity_stores", device_id,
                )
                stored = stored or {}
                activity = stored.get("activity")
                legacy = (
                    self._catalog_document(activity)
                    if isinstance(activity, dict) else None
                )
                if legacy is not None and any(self._catalog_document_score(legacy)):
                    catalog = legacy
                    catalog_updated_at = stored_updated_at
            if catalog is not None and any(self._catalog_document_score(catalog)):
                documents.append((device_id, catalog, catalog_updated_at))
        return documents

    @staticmethod
    def _catalog_target_categories(document):
        """Resolve each known concrete target against one catalogue.

        The result is deliberately based on the current canonical catalogue,
        rather than on category names stamped into old activity intervals.  A
        classification correction can therefore repair today's counters too.
        """
        document = dict(document or {})
        parents = dict(document.get("category_parents") or {})
        browser_categories = dict(document.get("browser_categories") or {})
        reserved = {"", "__root__", "Applications non classées"}

        def lineage(category):
            result = []
            current = str(category or "").strip()
            while current and current not in result:
                if current not in reserved:
                    result.append(current)
                current = str(parents.get(current) or "").strip()
            return result

        mapping = {}
        for raw_key, raw_metadata in dict(document.get("targets") or {}).items():
            key = str(raw_key or "").strip()
            if not key:
                continue
            metadata = raw_metadata if isinstance(raw_metadata, dict) else {}
            categories = [
                str(metadata.get("category") or "").strip(),
                str(metadata.get("site_category") or "").strip(),
            ]
            # A few old stores only persisted the browser's common category.
            # Use it solely as a fallback so an explicit site classification
            # remains authoritative.
            if not any(category not in reserved for category in categories):
                parts = key.split(":", 2)
                if len(parts) == 3 and parts[0] == "site":
                    categories.append(str(
                        browser_categories.get(parts[1].casefold()) or ""
                    ).strip())
            mapping[key] = sorted({
                ancestor
                for category in categories
                for ancestor in lineage(category)
            }, key=str.casefold)
        return mapping

    @staticmethod
    def _catalog_categories(document):
        """Return names that a local UsageStore can resolve as categories."""
        document = dict(document or {})
        categories = set(document.get("site_categories") or [])
        parents = dict(document.get("category_parents") or {})
        categories.update(parents)
        categories.update(parents.values())
        for metadata in dict(document.get("targets") or {}).values():
            if isinstance(metadata, dict):
                categories.add(str(metadata.get("category") or "").strip())
                categories.add(str(metadata.get("site_category") or "").strip())
        return {
            str(category).strip() for category in categories
            if str(category).strip() not in {
                "", "__root__", "Applications non classées",
            }
        }

    def _user_canonical_catalog(self, username):
        documents = self._user_catalog_documents(username)
        if not documents:
            return "", None
        state = self.user_policy(username) or {}
        policy = state.get("policy") if isinstance(state, dict) else {}
        preferred = {
            str(item.get("target_key") or item.get("key") or "")
            .removeprefix("category:").strip()
            for item in (
                policy.get("limits", []) if isinstance(policy, dict) else []
            )
            if isinstance(item, dict)
            and str(item.get("target_key") or item.get("key") or "").startswith(
                "category:"
            )
        }
        return self._merge_catalog_documents(
            documents, preferred_categories=preferred,
        )

    def _user_canonical_category_map(self, username):
        _device_id, document = self._user_canonical_catalog(username)
        return (
            self._catalog_target_categories(document)
            if isinstance(document, dict) else {}
        )

    def reconcile_user_policy_catalog(self, username, policy_state, actor):
        """Queue the canonical catalogue before category-policy activation.

        Policy delivery and catalogue delivery are independent transports.  A
        client must therefore reject an unresolved category revision, while
        this reconciliation makes the prerequisite durable on every targeted
        computer.
        """
        username = str(username or "").strip()
        actor = str(actor or "").strip()[:120]
        state = dict(policy_state or {})
        policy = state.get("policy")
        if not isinstance(policy, dict):
            policy = state if isinstance(state.get("limits"), list) else {}
        limits = [
            item for item in policy.get("limits", [])
            if isinstance(item, dict)
            and str(item.get("target_key") or item.get("key") or "").startswith(
                "category:"
            )
        ]
        if not limits:
            return {
                "queued": False, "reason": "no_category_limit",
                "deliveries": [], "unresolved_categories": [],
            }

        all_device_ids = self.selected_user_device_ids(username)
        available = set(all_device_ids)
        target_device_ids = set()
        category_names = set()
        for limit in limits:
            category_names.add(str(
                limit.get("target_key") or limit.get("key")
            ).removeprefix("category:").strip())
            scope = limit.get("device_ids")
            target_device_ids.update(
                available if scope is None else available & {
                    str(device_id).strip() for device_id in scope
                }
            )
        if not target_device_ids:
            return {
                "queued": False, "reason": "no_target_device",
                "deliveries": [],
                "unresolved_categories": sorted(category_names, key=str.casefold),
            }

        documents = self._user_catalog_documents(username)
        if not documents:
            return {
                "queued": False, "reason": "catalog_unavailable",
                "deliveries": [],
                "unresolved_categories": sorted(category_names, key=str.casefold),
            }
        canonical_device_id, catalog = self._merge_catalog_documents(
            documents, preferred_categories=category_names,
        )
        known_categories = self._catalog_categories(catalog)
        unresolved = sorted(
            category_names - known_categories, key=str.casefold,
        )
        command = {
            "action": "replace_catalog", "catalog": catalog, "actor": actor,
        }
        if len(json.dumps(command, ensure_ascii=False).encode("utf-8")) > MAX_BODY:
            raise ValueError("Le classement fusionné est trop volumineux.")
        current_documents = {
            device_id: document
            for device_id, document, *_metadata in documents
        }
        catalog_digest = json_hash(catalog)
        try:
            revision = int(state.get("revision") or 0)
        except (TypeError, ValueError):
            revision = 0
        operation_key = f"policy-catalog-v1:{revision}:{catalog_digest[:32]}"
        deliveries = []
        for device_id in sorted(target_device_ids):
            current = current_documents.get(device_id)
            if isinstance(current, dict) and json_hash(current) == catalog_digest:
                continue
            scoped_command = self._catalog_command_for_user_device(
                username, device_id, command,
            )
            command_id, reused = self.queue_idempotent(
                device_id, scoped_command, operation_key,
            )
            deliveries.append({
                "device_id": device_id, "command_id": str(command_id),
                "reused": bool(reused),
            })
        return {
            "queued": bool(deliveries),
            "canonical_device_id": canonical_device_id,
            "catalog_hash": catalog_digest,
            "deliveries": deliveries,
            "unresolved_categories": unresolved,
        }

    def bootstrap_user_catalog(
        self, username, actor, idempotency_key, *, device_ids=None,
    ):
        """Queue one authoritative initial catalogue on every selected PC."""
        username = str(username or "").strip()
        actor = str(actor or "").strip()[:120]
        operation_key = str(idempotency_key or "").strip()
        if not username or not actor:
            raise ValueError("Utilisateur ou auteur manquant.")
        if not IDEMPOTENCY_KEY_PATTERN.fullmatch(operation_key):
            raise ValueError("Clé d’idempotence invalide.")
        selected = self.selected_user_device_ids(username, device_ids)
        documents = self._user_catalog_documents(username, selected)
        canonical_device_id, catalog = self._merge_catalog_documents(documents)
        command = {
            "action": "replace_catalog", "catalog": catalog, "actor": actor,
        }
        if len(json.dumps(command, ensure_ascii=False).encode("utf-8")) > MAX_BODY:
            raise ValueError("Le classement fusionné est trop volumineux.")
        deliveries = []
        for device_id in selected:
            scoped_command = self._catalog_command_for_user_device(
                username, device_id, command,
            )
            command_id, reused = self.queue_idempotent(
                device_id, scoped_command,
                f"catalog-bootstrap:{operation_key}:{device_id}",
            )
            deliveries.append({
                "device_id": device_id, "command_id": str(command_id),
                "reused": bool(reused),
            })
        return {
            "queued": bool(deliveries), "operation_id": operation_key,
            "canonical_device_id": canonical_device_id,
            "deliveries": deliveries,
        }

    def queue_user_catalog_action(
        self, username, command, actor, idempotency_key,
        *, exclude_device_id="", device_ids=None, remove_policy_limits=True,
    ):
        """Queue one catalogue mutation for every PC assigned to a person."""
        username = str(username or "").strip()
        command = dict(command or {})
        actor = str(actor or "").strip()[:120]
        operation_key = str(idempotency_key or "").strip()
        excluded = str(exclude_device_id or "").strip()
        if command.get("action") not in CATALOG_INCREMENTAL_ACTIONS:
            raise ValueError("Mutation de classement non autorisée.")
        if not username or not actor:
            raise ValueError("Utilisateur ou auteur manquant.")
        if not IDEMPOTENCY_KEY_PATTERN.fullmatch(operation_key):
            raise ValueError("Clé d’idempotence invalide.")
        with self.connect() as db:
            user = db.execute(
                "SELECT username FROM users WHERE username=?", (username,),
            ).fetchone()
            if not user:
                raise ValueError("Utilisateur inconnu.")
            available_device_ids = [
                str(row["device_id"]) for row in db.execute(
                    "SELECT device_id FROM user_devices WHERE username=? "
                    "ORDER BY device_id", (user["username"],),
                ).fetchall()
            ]
        selected_device_ids = self.selected_user_device_ids(
            user["username"], device_ids,
        )
        if excluded and excluded not in available_device_ids:
            raise ValueError("Le PC source n’est pas associé à cet utilisateur.")
        clean_command = {
            key: value for key, value in command.items()
            if key not in {
                "device_id", "device_ids", "idempotency_key", "base_device_id",
                "_usage_guard_source", "_usage_guard_service_admin_token",
                "_remote_command_id",
                "_usage_guard_delete_limits_authorized",
                "_usage_guard_delete_other_limits_authorized",
            }
        }
        clean_command["actor"] = actor
        deletion_target = self._catalog_deletion_target(clean_command)
        if clean_command.get("action") == "delete_target":
            clean_command["target_key"] = deletion_target
        if deletion_target:
            # This reservation is intentionally before queue_idempotent: a
            # replay with a changed target or A -> A+B scope must have zero
            # command-log side effects.
            self.prepare_user_target_deletion(
                user["username"], deletion_target, selected_device_ids,
                operation_key,
            )
        deliveries = []
        for device_id in selected_device_ids:
            if device_id == excluded:
                continue
            scoped_command = self._catalog_command_for_user_device(
                user["username"], device_id, clean_command,
            )
            command_id, reused = self.queue_idempotent(
                device_id, scoped_command,
                f"catalog:{operation_key}:{device_id}",
            )
            deliveries.append({
                "device_id": device_id,
                "command_id": str(command_id),
                "reused": bool(reused),
            })
        if deletion_target and deliveries:
            with self._lock, self.connect() as db:
                db.executemany(
                    "INSERT OR IGNORE INTO "
                    "activity_target_deletion_deliveries(command_id,device_id,"
                    "usage_guard_username,target_key) VALUES(?,?,?,?)",
                    [(
                        int(item["command_id"]), item["device_id"],
                        user["username"], deletion_target,
                    ) for item in deliveries],
                )
        deletion = None
        policy_revision = 0
        if deletion_target:
            # Include the source PC in the data purge: a device-originated
            # command has already removed its local target and is excluded
            # only from command echo, never from the server privacy scope.
            deletion = self.purge_user_target_activity(
                user["username"], deletion_target, selected_device_ids,
                actor, operation_key,
            )
            if excluded:
                # The source PC sends this request only after applying the
                # local mutation, so there is deliberately no echo command
                # whose ACK could release its catalogue seal.
                with self._lock, self.connect() as db:
                    db.execute(
                        "UPDATE activity_target_deletion_seals SET "
                        "catalog_confirmation_after=?,updated_at=? WHERE "
                        "device_id=? AND "
                        "usage_guard_username=? AND target_key=?",
                        (
                            utc_now(), utc_now(), excluded, user["username"],
                            deletion_target,
                        ),
                    )
            policy = (
                self._remove_deleted_target_from_user_policy(
                    user["username"], deletion_target, selected_device_ids,
                    actor,
                ) if remove_policy_limits else None
            )
            policy_revision = int((policy or {}).get("revision") or 0)
        return {
            "queued": bool(deliveries),
            "operation_id": operation_key,
            "deliveries": deliveries,
            "source_device_id": excluded,
            **({
                "deletion": deletion,
                "policy_revision": policy_revision,
            } if deletion is not None else {}),
        }

    def _with_user_scope(self, user):
        return {**user, **self._user_scope(user["username"])}

    @staticmethod
    def _normalize_role(role, is_admin=False, permissions=None):
        requested = str(role or "").strip().lower()
        if requested == "manager":
            requested = "user"
        if requested not in USER_ROLES:
            if is_admin:
                return "admin"
            requested = "user" if any(
                dict(permissions or {}).get(key) for key in MANAGE_PERMISSION_KEYS
            ) else "limited"
        return requested

    @staticmethod
    def _replace_user_scope(db, username, role, device_ids):
        db.execute("DELETE FROM user_devices WHERE username=?", (username,))
        if role in {"limited", "user"}:
            selected = sorted({str(value).strip() for value in device_ids or [] if str(value).strip()})
            known = {
                row["device_id"] for row in db.execute(
                    "SELECT device_id FROM devices"
                ).fetchall()
            }
            if not set(selected) <= known:
                raise ValueError("Un ordinateur affecté est inconnu.")
            db.executemany(
                "INSERT INTO user_devices(username,device_id) VALUES(?,?)",
                [(username, device_id) for device_id in selected],
            )

    @staticmethod
    def _replace_user_person_scope(db, username, role, person_usernames):
        db.execute("DELETE FROM user_person_access WHERE username=?", (username,))
        if role == "admin":
            return
        selected = sorted({
            str(value).strip() for value in person_usernames or []
            if str(value).strip() and str(value).casefold() != username.casefold()
        }, key=str.casefold)
        limited = {
            row["username"].casefold(): row["username"] for row in db.execute(
                "SELECT username FROM users WHERE role='limited'"
            ).fetchall()
        }
        if not {value.casefold() for value in selected} <= set(limited):
            raise ValueError("Une personne du périmètre est inconnue.")
        db.executemany(
            "INSERT INTO user_person_access(username,person_username) VALUES(?,?)",
            [(username, limited[value.casefold()]) for value in selected],
        )

    def list_users(self):
        with self.connect() as db:
            rows = db.execute(
                "SELECT username,must_change,created_at,updated_at,is_admin,permissions,email,role FROM users ORDER BY username COLLATE NOCASE"
            ).fetchall()
        return [self._with_user_scope(self.public_user(row)) for row in rows]

    def has_admin(self):
        with self.connect() as db:
            return db.execute(
                "SELECT 1 FROM users WHERE is_admin=1 LIMIT 1"
            ).fetchone() is not None

    def has_users(self):
        with self.connect() as db:
            return db.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None

    @staticmethod
    def public_user(row):
        source = dict(row)
        try: saved = json.loads(source.get("permissions", "{}"))
        except (TypeError, ValueError): saved = {}
        role = Store._normalize_role(
            source.get("role"), source.get("is_admin"), saved
        )
        is_admin = role == "admin"
        result = {
            key: source[key] for key in ("username", "created_at", "updated_at")
            if key in source
        }
        result["must_change"] = bool(source.get("must_change"))
        result["email"] = str(source.get("email") or "").strip()
        result["must_set_email"] = not bool(result["email"])
        result["is_admin"] = is_admin
        result["role"] = role
        result["permissions"] = {
            key: True if is_admin else bool(saved.get(key, DEFAULT_PERMISSIONS[key]))
            for key in PERMISSION_KEYS
        }
        return result

    def create_user(
        self, username, password, must_change=True, email="",
        is_admin=False, permissions=None, role=None, device_ids=None,
    ):
        username, password = validate_username(username), validate_password(password)
        email = self._valid_email_address(email, "Adresse e-mail")
        salt = secrets.token_bytes(16)
        digest, now = password_digest(password, salt), utc_now()
        normalized_permissions = {
            key: bool(dict(permissions or {}).get(key, DEFAULT_PERMISSIONS[key]))
            for key in PERMISSION_KEYS
        }
        try:
            with self._lock, self.connect() as db:
                first_user = not bool(
                    db.execute("SELECT 1 FROM users LIMIT 1").fetchone()
                )
                role = self._normalize_role(role, is_admin, normalized_permissions)
                if first_user:
                    role = "admin"
                is_admin = role == "admin"
                db.execute(
                    "INSERT INTO users(username,salt,password_hash,must_change,created_at,updated_at,is_admin,permissions,email,role) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (username, salt, digest, int(bool(must_change)), now, now, int(is_admin), json.dumps(normalized_permissions), email, role),
                )
                self._replace_user_scope(db, username, role, device_ids)
        except sqlite3.IntegrityError as error:
            raise ValueError("Cet utilisateur existe déjà.") from error
        return next(
            user for user in self.list_users()
            if user["username"].casefold() == username.casefold()
        )

    def update_user_access(
        self, username, is_admin, permissions, actor, email=None, role=None,
        device_ids=None, person_usernames=None,
    ):
        username = validate_username(username)
        normalized = {key: bool(dict(permissions or {}).get(key, DEFAULT_PERMISSIONS[key])) for key in PERMISSION_KEYS}
        normalized_email = None if email is None else self._valid_email_address(email, "Adresse e-mail")
        with self._lock, self.connect() as db:
            target = db.execute("SELECT username,is_admin,role FROM users WHERE username=?", (username,)).fetchone()
            if not target: raise ValueError("Utilisateur inconnu.")
            role = self._normalize_role(role, is_admin, normalized)
            is_admin = role == "admin"
            if target["is_admin"] and not is_admin:
                admins = db.execute("SELECT COUNT(*) FROM users WHERE is_admin=1").fetchone()[0]
                if admins <= 1: raise ValueError("Le dernier administrateur doit le rester.")
            current_devices = [row["device_id"] for row in db.execute(
                "SELECT device_id FROM user_devices WHERE username=?", (username,)
            ).fetchall()]
            if device_ids is None:
                device_ids = current_devices if role in {"limited", "user"} else []
            if person_usernames is None:
                person_usernames = [
                    row["person_username"] for row in db.execute(
                        "SELECT person_username FROM user_person_access "
                        "WHERE username=?", (username,),
                    ).fetchall()
                ]
            if normalized_email is None:
                db.execute(
                    "UPDATE users SET is_admin=?,role=?,permissions=?,updated_at=? WHERE username=?",
                    (int(bool(is_admin)), role, json.dumps(normalized, separators=(",", ":")), utc_now(), username),
                )
            else:
                db.execute(
                    "UPDATE users SET is_admin=?,role=?,permissions=?,email=?,updated_at=? WHERE username=?",
                    (int(bool(is_admin)), role, json.dumps(normalized, separators=(",", ":")), normalized_email, utc_now(), username),
                )
            self._replace_user_scope(db, username, role, device_ids)
            self._replace_user_person_scope(
                db, username, role, person_usernames,
            )
            db.execute("DELETE FROM sessions WHERE username=? AND username<>?", (username, actor))
        return next(user for user in self.list_users() if user["username"].casefold() == username.casefold())

    def delete_user(self, username):
        username = validate_username(username)
        with self._lock, self.connect() as db:
            count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if count <= 1:
                raise ValueError("Le dernier utilisateur ne peut pas être supprimé.")
            target = db.execute("SELECT is_admin FROM users WHERE username=?", (username,)).fetchone()
            if target and target["is_admin"] and db.execute("SELECT COUNT(*) FROM users WHERE is_admin=1").fetchone()[0] <= 1:
                raise ValueError("Le dernier administrateur ne peut pas être supprimé.")
            cursor = db.execute("DELETE FROM users WHERE username=?", (username,))
            if cursor.rowcount != 1:
                raise ValueError("Utilisateur inconnu.")

    def _verify(self, username, password, db=None):
        owns_connection = db is None
        if owns_connection:
            db = sqlite3.connect(self.path, timeout=10)
            db.row_factory = sqlite3.Row
        try:
            row = db.execute(
                "SELECT username,salt,password_hash,must_change,is_admin,permissions,email,role FROM users WHERE username=?",
                (str(username or "").strip(),),
            ).fetchone()
            if not row:
                password_digest(str(password or ""), b"\0" * 16)
                return None
            supplied = password_digest(str(password or ""), row["salt"])
            return row if hmac.compare_digest(supplied, row["password_hash"]) else None
        finally:
            if owns_connection:
                db.close()

    def authenticate(self, username, password):
        row = self._verify(username, password)
        return (self._with_user_scope(self.public_user(row)) if row else None)

    def update_user_email(self, username, email):
        username = validate_username(username)
        email = self._valid_email_address(email, "Adresse e-mail")
        if not email:
            raise ValueError("L’adresse e-mail est obligatoire.")
        with self._lock, self.connect() as db:
            cursor = db.execute(
                "UPDATE users SET email=?,updated_at=? WHERE username=?",
                (email, utc_now(), username),
            )
            if cursor.rowcount != 1:
                raise ValueError("Utilisateur inconnu.")
        return next(
            user for user in self.list_users()
            if user["username"].casefold() == username.casefold()
        )

    def create_session(self, username):
        raw_token, csrf = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("ascii")).hexdigest()
        expires = (datetime.now(timezone.utc) + timedelta(seconds=SESSION_SECONDS)).isoformat(timespec="seconds")
        with self._lock, self.connect() as db:
            db.execute("DELETE FROM sessions WHERE expires_at<=?", (utc_now(),))
            db.execute(
                "INSERT INTO sessions(token_hash,username,csrf_token,expires_at,created_at) VALUES(?,?,?,?,?)",
                (token_hash, username, csrf, expires, utc_now()),
            )
        return raw_token, csrf, expires

    def session(self, raw_token):
        if not raw_token:
            return None
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        with self.connect() as db:
            row = db.execute(
                "SELECT s.token_hash,s.username,s.csrf_token,s.expires_at,u.must_change,u.is_admin,u.permissions,u.email,u.role "
                "FROM sessions s JOIN users u ON u.username=s.username "
                "WHERE s.token_hash=? AND s.expires_at>?",
                (token_hash, utc_now()),
            ).fetchone()
        if not row:
            return None
        session = self.public_user(row)
        session.update(self._user_scope(session["username"]))
        session.update({key: row[key] for key in ("token_hash", "csrf_token", "expires_at")})
        return session

    def delete_session(self, raw_token):
        if not raw_token:
            return
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        with self._lock, self.connect() as db:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))

    def change_password(self, username, current_password, new_password):
        new_password = validate_password(new_password)
        with self._lock, self.connect() as db:
            row = self._verify(username, current_password, db)
            if not row:
                raise ValueError("Mot de passe actuel incorrect.")
            salt, now = secrets.token_bytes(16), utc_now()
            db.execute(
                "UPDATE users SET salt=?,password_hash=?,must_change=0,updated_at=? WHERE username=?",
                (salt, password_digest(new_password, salt), now, username),
            )
            db.execute("DELETE FROM sessions WHERE username=?", (username,))


class BackendServer:
    def __init__(self, host=HOST, port=PORT, store=None, device_id=DEVICE_ID,
                 device_token=DEVICE_TOKEN, public_origin=PUBLIC_ORIGIN,
                 pwa_dir=PWA_DIR, client_release_dir=CLIENT_RELEASE_DIR,
                 local_mode=False):
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("The backend must listen on loopback only")
        if not device_id or len(device_token) < 32:
            raise RuntimeError("USAGE_GUARD_DEVICE_ID and a 32+ character DEVICE_TOKEN are required")
        parsed_origin = urlparse(public_origin)
        local_origin = (
            bool(local_mode)
            and parsed_origin.scheme == "http"
            and parsed_origin.hostname in {"127.0.0.1", "::1", "localhost"}
        )
        if (
            parsed_origin.scheme != "https" and not local_origin
            or not parsed_origin.netloc
            or parsed_origin.path not in {"", "/"}
        ):
            raise RuntimeError(
                "USAGE_GUARD_PUBLIC_ORIGIN must be HTTPS, or HTTP loopback in local mode"
            )
        self.store = store or Store(email_encryption_key=device_token)
        self.store.configure_email_encryption_key(device_token)
        self.store.reconcile_startup_state()
        self.device_id, self.device_token = device_id, device_token
        # Le libellé est administré et doit survivre aux redémarrages/déploiements.
        # Un appareil neuf reste identifiable par son device_id via les fallbacks
        # d'affichage, sans réécrire le libellé d'un appareil déjà renommé.
        self.store.register_device(device_id, token=device_token)
        self.store.assign_unscoped_users(device_id)
        self.store.initialize_device_notification_policy(device_id)
        self.local_mode = bool(local_mode)
        self.public_origin, self.pwa_dir = public_origin.rstrip("/"), Path(pwa_dir)
        self.client_release_dir = Path(client_release_dir)
        self.host, self.port, self.httpd = host, port, None
        self.login_limiter = LoginLimiter()
        self.enrollment_limiter = LoginLimiter(attempts=8, window=600, block=900)
        self.email_limiter = EmailLimiter()
        self._client_release_cache = None
        self._presence_stop = threading.Event()
        self._presence_thread = None

    def _send_email_background(self, title, message, recipient, kind=""):
        try:
            self.store.send_email_notification(
                title, message, recipient, False, kind
            )
        except (ValueError, OSError, smtplib.SMTPException) as error:
            print(f"SMTP_FAILURE error={error}")

    def _dispatch_limit_change(self, username, command, actor):
        """Send one shared limit-change e-mail, independently of PC delivery."""
        command = dict(command or {})
        action = str(command.get("action") or "")
        settings = dict(command.get("settings") or {})
        if action == "set_limit":
            verb = "créée" if settings.get("create_new") else "modifiée"
            target = str(command.get("target_key") or settings.get("target_key") or "activité")
        elif action == "remove_limit":
            verb, target = "supprimée", str(command.get("target_key") or "activité")
        elif action == "set_computer_block_enabled":
            verb, target = (
                "activée" if command.get("enabled") else "désactivée"
            ), "ordinateur complet"
        elif action == "clear_computer_block":
            verb, target = "supprimée", "ordinateur complet"
        elif action == "set_computer_block":
            verb, target = "créée ou modifiée", "ordinateur complet"
        else:
            return False
        username = str(username or "Utilisateur").strip()
        actor = str(actor or "Administrateur").strip()
        target = target.removeprefix("app:").removeprefix("category:").removeprefix("site:")
        title = f"Limite {verb} par {actor} — Usage Guard"
        message_verb = {
            "créée": "créé", "modifiée": "modifié", "supprimée": "supprimé",
            "activée": "activé", "désactivée": "désactivé",
            "créée ou modifiée": "créé ou modifié",
        }[verb]
        message = f"{actor} a {message_verb} la limite « {target} » pour {username}."
        requested = command.get("device_ids") if "device_ids" in command else None
        try:
            device_ids = self.store.selected_user_device_ids(username, requested)
        except ValueError:
            device_ids = self.store.selected_user_device_ids(username)
        recipients = {}
        for device_id in device_ids:
            for rule in self.store.device_notification_rules(
                device_id, "limit_change"
            ):
                if not rule.get("enabled"):
                    continue
                channels = rule.get("channels") or ["windows"]
                recipient = str(rule.get("email_recipient") or "").strip()
                if "email" not in channels or not recipient:
                    continue
                try:
                    recipient = self.store._valid_email_address(
                        recipient, "Adresse de destination"
                    )
                except ValueError:
                    continue
                recipients.setdefault(
                    recipient.casefold(),
                    (recipient, str(rule.get("description") or message)),
                )
        if not recipients or not self.store.email_settings()["enabled"]:
            return False
        for recipient, rule_message in recipients.values():
            if not self.email_limiter.allow(recipient):
                continue
            threading.Thread(
                target=self._send_email_background,
                args=(title, rule_message, recipient, "limit_change"),
                daemon=True,
            ).start()
        return True

    def _dispatch_access_change(self, before, after, actor):
        """Queue a detailed event only on devices that opted into it."""
        before, after = dict(before or {}), dict(after or {})
        username = str(after.get("username") or before.get("username") or "Utilisateur")
        actor = str(actor or "Administrateur")
        details = []
        before_role = str(before.get("role") or "limited")
        after_role = str(after.get("role") or "limited")
        if before_role != after_role:
            details.append(
                f"Rôle : {ROLE_LABELS.get(before_role, before_role)} → "
                f"{ROLE_LABELS.get(after_role, after_role)}."
            )

        before_permissions = {
            key for key in PERMISSION_KEYS
            if bool(dict(before.get("permissions") or {}).get(key))
        }
        after_permissions = {
            key for key in PERMISSION_KEYS
            if bool(dict(after.get("permissions") or {}).get(key))
        }
        added_permissions = [
            key for key in PERMISSION_KEYS
            if key in after_permissions - before_permissions
        ]
        removed_permissions = [
            key for key in PERMISSION_KEYS
            if key in before_permissions - after_permissions
        ]
        if added_permissions:
            details.append(
                "Droits ajoutés : "
                + ", ".join(PERMISSION_LABELS[key] for key in added_permissions)
                + "."
            )
        if removed_permissions:
            details.append(
                "Droits retirés : "
                + ", ".join(PERMISSION_LABELS[key] for key in removed_permissions)
                + "."
            )

        devices = {
            item["device_id"]: str(
                item.get("label") or item.get("hostname_last_seen")
                or item["device_id"]
            )
            for item in self.store.list_devices()
        }
        before_devices = set(before.get("accessible_device_ids") or [])
        after_devices = set(after.get("accessible_device_ids") or [])
        added_devices = sorted(
            after_devices - before_devices,
            key=lambda item: devices.get(item, item).casefold(),
        )
        removed_devices = sorted(
            before_devices - after_devices,
            key=lambda item: devices.get(item, item).casefold(),
        )
        if added_devices:
            details.append(
                "Ordinateurs ajoutés : "
                + ", ".join(devices.get(item, item) for item in added_devices)
                + "."
            )
        if removed_devices:
            details.append(
                "Ordinateurs retirés : "
                + ", ".join(devices.get(item, item) for item in removed_devices)
                + "."
            )
        if not details:
            return False

        title = f"Droits de {username} modifiés par {actor} — Usage Guard"
        message = (
            f"{actor} a modifié les droits de {username}.\n"
            + "\n".join(f"• {detail}" for detail in details)
        )
        queued = False
        affected_roles = {before_role, after_role} & USER_ROLES
        for device in self.store.list_devices():
            if device.get("revoked_at"):
                continue
            rules = self.store.device_notification_rules(
                device["device_id"], "access_change"
            )
            matching_rules = [
                rule for rule in rules
                if rule.get("enabled")
                and notification_subject_roles(rule) & affected_roles
            ]
            if not matching_rules:
                continue
            self.store.queue(device["device_id"], {
                "action": "notify_access_change",
                "title": title,
                "message": message,
                "subject_roles": sorted(affected_roles),
            })
            queued = True
        return queued

    def client_release(self):
        manifest_path = self.client_release_dir / "manifest.json"
        try:
            stamp = manifest_path.stat().st_mtime_ns
        except OSError:
            return None
        if self._client_release_cache and self._client_release_cache[0] == stamp:
            return self._client_release_cache[1]
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            filename = str(manifest.get("filename") or "")
            expected_hash = str(manifest.get("sha256") or "").lower()
            version = str(manifest.get("version") or "")
            if (
                Path(filename).name != filename
                or not re.fullmatch(r"\d+\.\d{3}", version)
                or not re.fullmatch(r"[0-9a-f]{64}", expected_hash)
            ):
                raise ValueError("Manifest client invalide")
            package = (self.client_release_dir / filename).resolve()
            if self.client_release_dir.resolve() not in package.parents:
                raise ValueError("Paquet client hors du répertoire autorisé")
            size = package.stat().st_size
            if size != int(manifest.get("size") or -1):
                raise ValueError("Taille du paquet client incohérente")
            actual_hash = hashlib.sha256(package.read_bytes()).hexdigest()
            if not secrets.compare_digest(actual_hash, expected_hash):
                raise ValueError("Empreinte du paquet client incohérente")
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
            print(f"CLIENT_RELEASE_INVALID error={error}")
            return None
        result = {
            "manifest": {
                "version": version,
                "minimum_version": str(manifest.get("minimum_version") or version),
                "mandatory": bool(manifest.get("mandatory")),
                "sha256": expected_hash,
                "size": size,
                "filename": filename,
                "published_at": str(manifest.get("published_at") or ""),
                "notes": str(manifest.get("notes") or "")[:1000],
            },
            "path": package,
        }
        self._client_release_cache = (stamp, result)
        return result

    def _dispatch_client_presence(self, device_id, connected):
        kind = "client_connected" if connected else "client_disconnected"
        title = "Ordinateur allumé — Usage Guard" if connected else "Ordinateur éteint ou inaccessible — Usage Guard"
        message = (
            "Le client Usage Guard vient de se connecter au serveur."
            if connected else
            "Le client Usage Guard ne communique plus avec le serveur depuis au moins une minute."
        )
        snapshot = self.store.snapshot(device_id) or {}
        rules = [
            rule for rule in snapshot.get("notification_rules", [])
            if rule.get("enabled") and rule.get("kind") in {kind, "computer_state"}
        ]
        if self.store.email_settings()["enabled"]:
            recipient_rules = {}
            for rule in rules:
                recipient = str(rule.get("email_recipient", "")).strip()
                if "email" in (rule.get("channels") or ["windows"]) and recipient:
                    recipient_rules.setdefault(recipient, rule)
            for recipient, rule in recipient_rules.items():
                try:
                    recipient = self.store._valid_email_address(recipient, "Adresse de destination")
                except ValueError:
                    continue
                if self.email_limiter.allow(recipient):
                    threading.Thread(
                        target=self._send_email_background,
                        args=(title, message, recipient, "computer_state"),
                        daemon=True,
                    ).start()
        windows_rule = next((
            rule for rule in rules
            if "windows" in (rule.get("channels") or ["windows"])
        ), None)
        if windows_rule:
            self.store.queue(device_id, {
                "action": "notify_client_presence",
                "connected": connected,
                "title": title,
                "message": message,
                "windows_only": True,
            })

    def _dispatch_protection_event(self, device_id, event):
        if not event:
            return
        restored = event.get("kind") == "restored"
        title = (
            "Protection rétablie — Usage Guard" if restored else
            "Protection interrompue — Usage Guard"
        )
        message = str(event.get("message") or "L’état de la protection a changé.")
        snapshot = self.store.snapshot(device_id) or {}
        rules = [
            rule for rule in snapshot.get("notification_rules", [])
            if rule.get("enabled")
            and rule.get("kind") == "protection_interrupted"
        ]
        if self.store.email_settings()["enabled"]:
            recipient_rules = {}
            for rule in rules:
                recipient = str(rule.get("email_recipient", "")).strip()
                if "email" in (rule.get("channels") or ["windows"]) and recipient:
                    recipient_rules.setdefault(recipient, rule)
            for recipient, rule in recipient_rules.items():
                try:
                    recipient = self.store._valid_email_address(
                        recipient, "Adresse de destination"
                    )
                except ValueError:
                    continue
                if self.email_limiter.allow(recipient):
                    threading.Thread(
                        target=self._send_email_background,
                        args=(title, message, recipient, "protection_interrupted"),
                        daemon=True,
                    ).start()
        windows_rule = next((
            rule for rule in rules
            if "windows" in (rule.get("channels") or ["windows"])
        ), None)
        if windows_rule:
            self.store.queue(device_id, {
                "action": "notify_protection_event",
                "title": title, "message": message,
                "windows_only": True,
            })

    def _presence_loop(self):
        while not self._presence_stop.wait(10):
            for device in self.store.list_devices():
                device_id = device["device_id"]
                if not device["enrolled"]:
                    continue
                transitioned = self.store.mark_device_offline_if_stale(device_id)
                if not transitioned:
                    if (
                        not device.get("online")
                        and self.store.claim_expired_device_maintenance(device_id)
                    ):
                        self._dispatch_client_presence(device_id, False)
                        event = self.store.record_protection_event(
                            device_id, "interrupted", ["service"],
                            "Le service n’est pas revenu après la fenêtre de mise à jour prévue.",
                        )
                        self._dispatch_protection_event(device_id, event)
                    continue
                if self.store.device_maintenance(device_id)["active"]:
                    continue
                self._dispatch_client_presence(device_id, False)
                event = self.store.record_protection_event(
                    device_id, "interrupted", ["service"],
                    "Le service protégé ne communique plus avec le serveur depuis au moins une minute. Un arrêt, une coupure réseau ou un contournement est possible.",
                )
                self._dispatch_protection_event(device_id, event)

    def _mark_agent_seen(self, device_id):
        previous_presence = self.store.device_presence(device_id)
        if not self.store.mark_device_seen(device_id):
            return
        if (
            previous_presence is not None
            and self.store.device_maintenance(device_id)["active"]
        ):
            self.store.mark_device_maintenance_reconnected(device_id)
            return
        self._dispatch_client_presence(device_id, True)
        if previous_presence is not None:
            event = self.store.record_protection_event(
                device_id, "restored", ["service"],
                "Le service protégé communique de nouveau avec le serveur.",
            )
            self._dispatch_protection_event(device_id, event)

    def start(self):
        owner = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "UsageGuardBackend/2"

            def do_GET(self):
                parsed = urlparse(self.path)
                if parsed.path == PREFIX + "/api/v1/health":
                    return self.json(HTTPStatus.OK, {"ok": True})
                if parsed.path == PREFIX + "/api/v1/agent/commands":
                    device_id = self.require_agent_query(parsed)
                    if not device_id: return
                    owner._mark_agent_seen(device_id)
                    return self.json(HTTPStatus.OK, {"commands": owner.store.pending(device_id)})
                if parsed.path == PREFIX + "/api/v1/agent/users":
                    return self.error(HTTPStatus.FORBIDDEN, "Le secret appareil ne donne aucun droit sur les comptes")
                if parsed.path == PREFIX + "/api/v1/agent/activity":
                    return self.error(
                        HTTPStatus.GONE,
                        "La synchronisation de l’archive complète est désactivée; mettez le client à jour.",
                    )
                if parsed.path == PREFIX + "/api/v1/agent/windows-identities":
                    device_id = self.require_agent_query(parsed)
                    if not device_id: return
                    device = next((
                        item for item in owner.store.list_devices()
                        if item["device_id"] == device_id
                    ), {"device_id": device_id})
                    return self.json(HTTPStatus.OK, {
                        "device": {
                            "device_id": device_id,
                            "display_name": str(
                                device.get("label")
                                or device.get("hostname_last_seen")
                                or device_id
                            ),
                        },
                        "windows_identities": owner.store.device_windows_identities(
                            device_id
                        ),
                    })
                if parsed.path == PREFIX + "/api/v1/agent/policy":
                    device_id = self.require_agent_query(parsed)
                    if not device_id: return
                    windows_sid = parse_qs(parsed.query).get(
                        "windows_sid", [""]
                    )[0]
                    try:
                        policy = owner.store.policy_for_windows_sid(
                            device_id, windows_sid,
                        )
                    except ValueError as error:
                        return self.error(HTTPStatus.CONFLICT, str(error))
                    if not policy:
                        return self.error(
                            HTTPStatus.CONFLICT,
                            "Cette session Windows n’est pas associée à un "
                            "utilisateur Usage Guard.",
                        )
                    return self.json(HTTPStatus.OK, policy)
                if parsed.path == PREFIX + "/api/v1/agent/activity/union":
                    device_id = self.require_agent_query(parsed)
                    if not device_id:
                        return
                    query = parse_qs(parsed.query)
                    windows_sid = query.get("windows_sid", [""])[0]
                    mapping = owner.store.user_for_windows_sid(
                        device_id, windows_sid,
                    )
                    if not mapping:
                        return self.error(
                            HTTPStatus.CONFLICT,
                            "Cette session Windows n’est pas associée.",
                        )
                    try:
                        target_key = query.get("target_key", [None])[0]
                        category_key = query.get("category_key", [None])[0]
                        policy = owner.store.user_policy(
                            mapping["usage_guard_username"]
                        ) or {}
                        limits = dict(policy.get("policy") or {}).get(
                            "limits", []
                        )
                        measured_key = (
                            str(target_key) if target_key is not None else
                            f"category:{category_key}"
                            if category_key is not None else ""
                        )
                        matching_limits = [
                            item for item in limits
                            if str(item.get("target_key") or item.get("key") or "")
                            == measured_key
                        ]
                        usage_device_ids = None
                        if matching_limits and all(
                            item.get("device_ids") for item in matching_limits
                        ):
                            usage_device_ids = sorted({
                                device for item in matching_limits
                                for device in item.get("device_ids", [])
                            })
                        seconds = owner.store.user_usage_union(
                            mapping["usage_guard_username"],
                            query.get("start", [""])[0],
                            query.get("end", [""])[0],
                            target_key=target_key,
                            category_key=category_key,
                            device_ids=usage_device_ids,
                        )
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.OK, {
                        "usage_guard_username": mapping[
                            "usage_guard_username"
                        ],
                        "seconds": seconds,
                    })
                if parsed.path == PREFIX + "/api/v1/agent/email/settings":
                    return self.error(HTTPStatus.FORBIDDEN, "Le secret appareil ne donne aucun droit sur le SMTP")
                if parsed.path == PREFIX + "/api/v1/agent/update":
                    device_id = self.require_agent_query(parsed)
                    if not device_id: return
                    release = owner.client_release()
                    return self.json(HTTPStatus.OK, {
                        "update": ({
                            **release["manifest"],
                            "download_path": "/api/v1/agent/update/package",
                        } if release else None),
                    })
                if parsed.path == PREFIX + "/api/v1/agent/update/package":
                    device_id = self.require_agent_query(parsed)
                    if not device_id: return
                    release = owner.client_release()
                    if not release:
                        return self.error(HTTPStatus.NOT_FOUND, "Aucune mise à jour client publiée")
                    return self.binary_file(
                        release["path"], release["manifest"]["filename"]
                    )
                if parsed.path == PREFIX + "/api/v1/auth/session":
                    session = self.user_session()
                    if not session: return self.error(HTTPStatus.UNAUTHORIZED, "Connexion requise")
                    return self.json(HTTPStatus.OK, self.session_payload(session))
                if parsed.path == PREFIX + "/api/v1/admin/users":
                    session = self.user_session()
                    if not session: return self.error(HTTPStatus.UNAUTHORIZED, "Connexion requise")
                    if not session["is_admin"]: return self.error(HTTPStatus.FORBIDDEN, "Droits administrateur requis")
                    return self.json(HTTPStatus.OK, {
                        "users": owner.store.list_users(),
                        "devices": owner.store.list_devices(),
                    })
                identity_suffix = "/windows-identities"
                identity_prefix = PREFIX + "/api/v1/admin/devices/"
                if (
                    parsed.path.startswith(identity_prefix)
                    and parsed.path.endswith(identity_suffix)
                ):
                    session = self.user_session()
                    if not session:
                        return self.error(
                            HTTPStatus.UNAUTHORIZED, "Connexion requise"
                        )
                    if not session["is_admin"]:
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Droits administrateur requis",
                        )
                    device_id = unquote(
                        parsed.path[
                            len(identity_prefix):-len(identity_suffix)
                        ].rstrip("/")
                    )
                    return self.json(HTTPStatus.OK, {
                        "windows_identities": owner.store.device_windows_identities(
                            device_id
                        ),
                    })
                if parsed.path == PREFIX + "/api/v1/devices":
                    session = self.user_session()
                    if not session: return self.error(HTTPStatus.UNAUTHORIZED, "Connexion requise")
                    if session["must_change"]: return self.error(HTTPStatus.FORBIDDEN, "Changement de mot de passe requis")
                    accessible = set(session.get("accessible_device_ids") or [])
                    return self.json(HTTPStatus.OK, {
                        "devices": [
                            item for item in owner.store.list_devices()
                            if item["device_id"] in accessible
                        ],
                    })
                if parsed.path == PREFIX + "/api/v1/policies":
                    session = self.user_session()
                    if not session:
                        return self.error(
                            HTTPStatus.UNAUTHORIZED, "Connexion requise"
                        )
                    if session["must_change"]:
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Changement de mot de passe requis",
                        )
                    if not session["permissions"]["view_limits"]:
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Ces politiques ne sont pas autorisées",
                        )
                    return self.json(HTTPStatus.OK, {
                        "users": owner.store.accessible_policy_users(
                            session["username"], session["is_admin"],
                        ),
                    })
                policy_prefix = PREFIX + "/api/v1/policies/"
                policy_operation_marker = "/operations/"
                if (
                    parsed.path.startswith(policy_prefix)
                    and policy_operation_marker in parsed.path
                ):
                    session = self.user_session()
                    if not session:
                        return self.error(
                            HTTPStatus.UNAUTHORIZED, "Connexion requise"
                        )
                    if session["must_change"]:
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Changement de mot de passe requis",
                        )
                    relative = parsed.path[len(policy_prefix):]
                    username, operation_id = relative.split(
                        policy_operation_marker, 1,
                    )
                    username = unquote(username.strip("/"))
                    operation_id = operation_id.strip("/")
                    if not operation_id.isdigit():
                        return self.error(
                            HTTPStatus.NOT_FOUND, "Opération inconnue"
                        )
                    if not session["permissions"]["view_limits"]:
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Cette politique n’est pas autorisée",
                        )
                    if not owner.store.user_can_access_policy(
                        session["username"], username, session["is_admin"],
                    ):
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Cet utilisateur n’est pas autorisé pour ce compte",
                        )
                    operation = owner.store.user_policy_operation(
                        username, int(operation_id),
                    )
                    if not operation:
                        return self.error(
                            HTTPStatus.NOT_FOUND, "Opération inconnue"
                        )
                    return self.json(HTTPStatus.OK, operation)
                policy_usage_suffix = "/usage"
                if (
                    parsed.path.startswith(policy_prefix)
                    and parsed.path.endswith(policy_usage_suffix)
                ):
                    session = self.user_session()
                    if not session:
                        return self.error(
                            HTTPStatus.UNAUTHORIZED, "Connexion requise"
                        )
                    if session["must_change"]:
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Changement de mot de passe requis",
                        )
                    if not session["permissions"]["view_analysis"]:
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Cette analyse n’est pas autorisée",
                        )
                    username = unquote(parsed.path[
                        len(policy_prefix):-len(policy_usage_suffix)
                    ].strip("/"))
                    if not owner.store.user_can_access_policy(
                        session["username"], username, session["is_admin"],
                    ):
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Cet utilisateur n’est pas autorisé pour ce compte",
                        )
                    query = parse_qs(parsed.query)
                    requested_device_ids = query.get("device_id")
                    try:
                        usage = owner.store.user_usage_breakdown(
                            username, query.get("start", [""])[0],
                            query.get("end", [""])[0],
                            device_ids=requested_device_ids,
                        )
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.OK, usage)
                if parsed.path.startswith(policy_prefix):
                    session = self.user_session()
                    if not session:
                        return self.error(
                            HTTPStatus.UNAUTHORIZED, "Connexion requise"
                        )
                    if session["must_change"]:
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Changement de mot de passe requis",
                        )
                    username = unquote(
                        parsed.path[len(policy_prefix):].strip("/")
                    )
                    if not session["permissions"]["view_limits"]:
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Cette politique n’est pas autorisée",
                        )
                    if not owner.store.user_can_access_policy(
                        session["username"], username, session["is_admin"],
                    ):
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Cet utilisateur n’est pas autorisé pour ce compte",
                        )
                    policy = owner.store.user_policy(username)
                    if not policy:
                        return self.error(
                            HTTPStatus.NOT_FOUND, "Utilisateur inconnu"
                        )
                    return self.json(HTTPStatus.OK, {
                        **policy,
                        "computer_block_policy": (
                            owner.store.user_computer_block_policy(username)
                        ),
                    })
                action_prefix = PREFIX + "/api/v1/actions/"
                if parsed.path.startswith(action_prefix):
                    command_id = parsed.path[len(action_prefix):].strip("/")
                    if not command_id.isdigit():
                        return self.error(
                            HTTPStatus.NOT_FOUND, "Opération inconnue"
                        )
                    session = self.user_session()
                    if not session:
                        return self.error(
                            HTTPStatus.UNAUTHORIZED, "Connexion requise"
                        )
                    device_id = self.selected_device(session, parsed=parsed)
                    if not device_id:
                        return
                    status = owner.store.command_status(
                        device_id, int(command_id)
                    )
                    if not status:
                        return self.error(
                            HTTPStatus.NOT_FOUND, "Opération inconnue"
                        )
                    permission = action_permission(status.get("action"))
                    if not session["permissions"][permission]:
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Suivi non autorisé pour ce compte",
                        )
                    return self.json(HTTPStatus.OK, status)
                if parsed.path == PREFIX + "/api/v1/email/settings":
                    session = self.user_session()
                    if not session: return self.error(HTTPStatus.UNAUTHORIZED, "Connexion requise")
                    if session["must_change"]: return self.error(HTTPStatus.FORBIDDEN, "Changement de mot de passe requis")
                    if not session["is_admin"]:
                        return self.error(HTTPStatus.FORBIDDEN, "Droits administrateur requis")
                    return self.json(HTTPStatus.OK, {"email_settings": owner.store.email_settings()})
                if parsed.path == PREFIX + "/api/v1/overview":
                    session = self.user_session()
                    if not session: return self.error(HTTPStatus.UNAUTHORIZED, "Connexion requise")
                    if session["must_change"]: return self.error(HTTPStatus.FORBIDDEN, "Changement de mot de passe requis")
                    device_id = self.selected_device(session, parsed=parsed)
                    if not device_id: return
                    overview_query = parse_qs(parsed.query)
                    scope = overview_query.get("scope", ["today"])[0]
                    requested_day = overview_query.get("day", [""])[0]
                    since_day = overview_query.get("since", [""])[0]
                    history_before = overview_query.get("before", [""])[0]
                    timezone_name = overview_query.get("tz", [""])[0]
                    try:
                        _view_timezone(timezone_name)
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    if requested_day and not re.fullmatch(
                        r"\d{4}-\d{2}-\d{2}", requested_day
                    ):
                        return self.error(
                            HTTPStatus.BAD_REQUEST, "Date d’aperçu invalide",
                        )
                    if since_day and not re.fullmatch(
                        r"\d{4}-\d{2}-\d{2}", since_day
                    ):
                        return self.error(
                            HTTPStatus.BAD_REQUEST, "Date de cache invalide",
                        )
                    if history_before and scope != "all":
                        return self.error(
                            HTTPStatus.BAD_REQUEST,
                            "Curseur réservé à l’historique d’analyse",
                        )
                    if scope == "notifications":
                        snapshot = owner.store.snapshot(device_id) or {}
                        requested_owner = str(
                            overview_query.get(
                                "owner", [session["username"]]
                            )[0] or session["username"]
                        ).strip()
                        if (
                            requested_owner.casefold()
                            != session["username"].casefold()
                            and (
                                not session["permissions"]["manage_notifications"]
                                or not owner.store.user_can_access_policy(
                                    session["username"], requested_owner,
                                    session["is_admin"],
                                )
                            )
                        ):
                            return self.error(
                                HTTPStatus.FORBIDDEN,
                                "Notifications de cette personne non autorisées",
                            )
                        rules = [
                            item for item in snapshot.get("notification_rules", [])
                            if item.get("mandatory")
                            or str(item.get("owner", "")).casefold() == requested_owner.casefold()
                            or session["is_admin"] and not str(item.get("owner", "")).strip()
                        ]
                        if not session["permissions"]["view_notifications"]:
                            rules = [item for item in rules if item.get("mandatory")]
                        limits = snapshot.get("limits", []) if session["permissions"]["manage_notifications"] else []
                        return self.json(HTTPStatus.OK, {
                            "notification_owner": requested_owner,
                            "notification_rules": rules, "limits": limits,
                            "merge_candidates": snapshot.get("merge_candidates", []),
                            "categories": snapshot.get("categories", []),
                            "top_level_categories": snapshot.get("top_level_categories", []),
                            "category_parents": snapshot.get("category_parents", {}),
                        })
                    required = {
                        "today": "view_activity",
                        "session": "view_activity",
                        "catalog": "view_activity",
                        "limits": "view_limits",
                    }.get(scope, "view_analysis")
                    if not session["permissions"][required]: return self.error(HTTPStatus.FORBIDDEN, "Cette vue n’est pas autorisée")
                    snapshot = owner.store.snapshot(device_id)
                    embedded_analysis = (
                        snapshot.get("analysis", snapshot) if snapshot else {}
                    )
                    if scope == "catalog":
                        # Classification is a bounded document in its own
                        # table. An empty legacy activity store must never hide
                        # Codex or an entire category.
                        catalog = owner.store.device_catalog(device_id)
                        if catalog:
                            catalog_analysis = analysis_snapshot_from_activity(
                                catalog, embedded_analysis,
                            )
                            snapshot = {
                                **embedded_analysis,
                                **catalog_snapshot(catalog_analysis),
                            }
                        else:
                            snapshot = embedded_analysis or None
                    elif scope == "limits":
                        snapshot = embedded_analysis or None
                    else:
                        query_start = query_end = None
                        history_page = None
                        if requested_day:
                            # Include either side of the UTC day: the PWA does
                            # the final split in the viewer's local timezone.
                            selected = datetime.fromisoformat(
                                requested_day
                            ).replace(
                                tzinfo=_view_timezone(timezone_name)
                            ).astimezone(timezone.utc)
                            query_start = selected - timedelta(days=1)
                            query_end = selected + timedelta(days=2)
                        elif since_day:
                            query_start = datetime.fromisoformat(
                                since_day
                            ).replace(
                                tzinfo=_view_timezone(timezone_name)
                            ).astimezone(timezone.utc) - timedelta(days=1)
                        elif scope in {"today", "session"}:
                            recording = dict(
                                embedded_analysis.get("session_recording") or {}
                            ).get("started_at")
                            if recording:
                                try:
                                    query_start = _aware_utc(recording)
                                except (TypeError, ValueError):
                                    query_start = None
                            if query_start is None:
                                query_start = datetime.now(timezone.utc) - timedelta(days=2)
                        if scope == "all":
                            try:
                                timeline_sessions, history_page = (
                                    owner.store.device_activity_history_page(
                                        device_id,
                                        username=(
                                            None if session["is_admin"]
                                            else session["username"]
                                        ),
                                        start=query_start, end=query_end,
                                        before=history_before, limit=500,
                                    )
                                )
                            except ValueError as error:
                                return self.error(
                                    HTTPStatus.BAD_REQUEST, str(error),
                                )
                            history_page = {
                                **history_page, "since": since_day,
                                "complete": not history_page["has_more"],
                            }
                            timeline_truncated = history_page["has_more"]
                        else:
                            timeline_sessions, timeline_truncated = owner.store.device_activity_sessions(
                                device_id,
                                username=(
                                    None if session["is_admin"]
                                    else session["username"]
                                ),
                                start=query_start, end=query_end, limit=10_000,
                            )
                        # Historical analysis uses the compact analysis
                        # document as catalogue/fallback metadata.  Live
                        # views must keep the current top-level snapshot.
                        base = embedded_analysis if scope == "all" else snapshot
                        aggregate_summary = None
                        if scope == "all" and not history_before:
                            try:
                                aggregate_summary = (
                                    owner.store.device_activity_analysis_summary(
                                        device_id,
                                        username=(
                                            None if session["is_admin"]
                                            else session["username"]
                                        ),
                                        start=query_start, end=query_end,
                                        timezone_name=timezone_name,
                                    )
                                )
                            except ValueError as error:
                                return self.error(
                                    HTTPStatus.BAD_REQUEST, str(error),
                                )
                            # Closed snapshot rows have just been normalized
                            # server-side.  Keeping them again in the base
                            # would bypass the raw-history page bound.  Only
                            # genuinely open rows remain useful here.
                            summary_fields = (
                                analysis_with_live_other_sites(
                                    aggregate_summary, base,
                                )
                                if aggregate_summary.get("daily_stats")
                                else {
                                    **(
                                        {}
                                        if "daily_stats" in base
                                        else {"daily_stats": []}
                                    ),
                                    "analysis_coverage": aggregate_summary[
                                        "analysis_coverage"
                                    ],
                                }
                            )
                            base = {
                                **base,
                                "sessions": [
                                    item for item in base.get("sessions") or []
                                    if isinstance(item, dict)
                                    and not item.get("ended_at")
                                ],
                                "windows_sessions": [
                                    item for item in base.get(
                                        "windows_sessions"
                                    ) or []
                                    if isinstance(item, dict)
                                    and not item.get("ended_at")
                                ],
                                "system_events": [],
                                **summary_fields,
                            }
                        # Never fall back to the legacy monolithic activity
                        # document here.  Even a read-only compatibility path
                        # would serialize the complete growing archive into a
                        # PWA response.  Existing archives are migrated locally
                        # on the server; until that migration can map a device,
                        # only the bounded snapshot/catalogue is exposed.
                        snapshot = (
                            snapshot_with_interval_history(
                                base, timeline_sessions,
                                truncated=timeline_truncated,
                                timezone_name=timezone_name,
                            )
                            if timeline_sessions or (
                                aggregate_summary
                                and aggregate_summary.get("daily_stats")
                            )
                            else base or None
                        )
                        if snapshot:
                            snapshot["scope"] = scope
                            if history_page is not None:
                                snapshot["history_page"] = history_page
                    if snapshot:
                        snapshot = snapshot_with_presence(
                            snapshot,
                            owner.store.protection_overview(device_id),
                        )
                        device = next((
                            item for item in owner.store.list_devices()
                            if item["device_id"] == device_id
                        ), {"device_id": device_id})
                        snapshot = snapshot_with_device_context(
                            snapshot, device,
                            owner.store.device_windows_identities(device_id),
                        ) | {
                            "pending_limit_commands": owner.store.pending_limit_commands(
                                device_id, snapshot
                            ),
                        }
                        if scope in {"today", "session"} and requested_day:
                            snapshot = snapshot_for_day_scope(
                                snapshot, requested_day, timezone_name,
                            )
                        if scope == "catalog":
                            snapshot = catalog_snapshot(snapshot)
                        elif scope == "all" and since_day:
                            snapshot = analysis_snapshot_since(
                                snapshot, since_day, timezone_name,
                            )
                    if snapshot and scope != "catalog" and not session["permissions"]["view_limits"]:
                        snapshot = {**snapshot, "limits": [], "merge_candidates": [], "computer_block": {}, "pending_limit_commands": []}
                    if snapshot and scope != "catalog" and not session["permissions"]["view_notifications"]:
                        snapshot = {**snapshot, "notification_rules": [
                            item for item in snapshot.get("notification_rules", [])
                            if item.get("mandatory")
                        ]}
                    elif snapshot and scope != "catalog":
                        snapshot = {**snapshot, "notification_rules": [
                            item for item in snapshot.get("notification_rules", [])
                            if item.get("mandatory")
                            or str(item.get("owner", "")).casefold() == session["username"].casefold()
                            or session["is_admin"] and not str(item.get("owner", "")).strip()
                        ]}
                    if not snapshot:
                        return self.json(HTTPStatus.OK, {
                            "error": "Aucune donnée reçue", "offline": True,
                            "protection": owner.store.protection_overview(
                                device_id
                            ),
                            "pending_limit_commands": owner.store.pending_limit_commands(device_id, {}),
                        })
                    return self.json(HTTPStatus.OK, snapshot)
                return self.static(parsed.path)

            def do_POST(self):
                parsed = urlparse(self.path)
                # Refuse the retired monolithic archive endpoint before
                # reading its request body.  This prevents an old client from
                # making the server receive tens or hundreds of megabytes.
                if parsed.path == PREFIX + "/api/v1/agent/activity":
                    return self.error(
                        HTTPStatus.GONE,
                        "La synchronisation de l’archive complète est désactivée; mettez le client à jour.",
                    )
                try: payload = self.body()
                except ValueError as error: return self.error(HTTPStatus.BAD_REQUEST, str(error))
                if parsed.path == PREFIX + "/api/v1/device/enroll":
                    key = self.client_ip()
                    if not owner.enrollment_limiter.allowed(key):
                        return self.error(HTTPStatus.TOO_MANY_REQUESTS, "Trop de tentatives. Réessayez dans 15 minutes.")
                    try:
                        result = owner.store.consume_device_enrollment(
                            payload.get("code"), payload.get("hostname"),
                            payload.get("display_name"),
                        )
                    except ValueError as error:
                        owner.enrollment_limiter.failed(key)
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    owner.enrollment_limiter.succeeded(key)
                    return self.json(HTTPStatus.CREATED, {"ok": True, **result})
                if parsed.path == PREFIX + "/api/v1/auth/login":
                    return self.login(payload)
                if parsed.path == PREFIX + "/api/v1/auth/logout":
                    session = self.require_user_write(allow_password_change=True)
                    if not session: return
                    owner.store.delete_session(self.session_cookie())
                    return self.json(HTTPStatus.OK, {"ok": True}, {"Set-Cookie": self.expired_cookie()})
                if parsed.path == PREFIX + "/api/v1/auth/password":
                    session = self.require_user_write(allow_password_change=True)
                    if not session: return
                    try:
                        owner.store.change_password(session["username"], payload.get("current_password"), payload.get("new_password"))
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    raw, csrf, expires = owner.store.create_session(session["username"])
                    refreshed = owner.store.session(raw)
                    return self.json(HTTPStatus.OK, {
                        "ok": True, **self.session_payload(refreshed),
                    }, {"Set-Cookie": self.session_cookie_header(raw)})
                if parsed.path == PREFIX + "/api/v1/auth/email":
                    session = self.require_user_write(allow_email_setup=True)
                    if not session: return
                    try:
                        owner.store.update_user_email(
                            session["username"], payload.get("email")
                        )
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    refreshed = self.user_session()
                    return self.json(HTTPStatus.OK, {
                        "ok": True, **self.session_payload(refreshed),
                    })
                if parsed.path == PREFIX + "/api/v1/agent/status":
                    device_id = self.require_agent_payload(payload)
                    if not device_id: return
                    owner._mark_agent_seen(device_id)
                    result = owner.store.save_protection_status(
                        device_id, payload.get("status", {})
                    )
                    for event in result.get("events", []):
                        owner._dispatch_protection_event(device_id, event)
                    maintenance = owner.store.device_maintenance(device_id)
                    reported = dict(payload.get("status") or {})
                    if (
                        maintenance["active"] and maintenance["reconnected"]
                        and reported.get("desktop_connected")
                        and reported.get("extension_connected")
                    ):
                        owner.store.clear_device_maintenance(device_id)
                    return self.json(HTTPStatus.OK, {
                        "ok": True, "protection": result["status"],
                        "accepted_event_ids": result["accepted_event_ids"],
                    })
                if parsed.path == PREFIX + "/api/v1/agent/maintenance":
                    device_id = self.require_agent_payload(payload)
                    if not device_id: return
                    owner._mark_agent_seen(device_id)
                    try:
                        maintenance = owner.store.begin_device_maintenance(
                            device_id, payload.get("version", ""),
                            payload.get("duration_seconds", 900),
                        )
                    except (TypeError, ValueError) as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.OK, {
                        "ok": True, "maintenance": maintenance,
                    })
                if parsed.path == PREFIX + "/api/v1/agent/snapshot":
                    device_id = self.require_agent_payload(payload)
                    if not device_id: return
                    try:
                        if isinstance(payload.get("snapshot"), dict):
                            owner.store.save_snapshot(device_id, payload["snapshot"])
                        elif isinstance(payload.get("snapshot_delta"), dict):
                            owner.store.patch_snapshot(
                                device_id,
                                payload["snapshot_delta"],
                                payload.get("base_hash"),
                                payload.get("target_hash"),
                            )
                        else:
                            return self.error(HTTPStatus.BAD_REQUEST, "Snapshot invalide")
                    except DocumentConflict as error:
                        return self.error(HTTPStatus.CONFLICT, str(error))
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.OK, {"ok": True})
                if parsed.path == PREFIX + "/api/v1/agent/activity/intervals":
                    device_id = self.require_agent_payload(payload)
                    if not device_id:
                        return
                    try:
                        result = owner.store.ingest_activity_intervals(
                            device_id, payload.get("windows_sid"),
                            payload.get("intervals"),
                        )
                    except IdempotencyConflict as error:
                        return self.error(HTTPStatus.CONFLICT, str(error))
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.OK, {
                        "ok": True, **result,
                    })
                if parsed.path == PREFIX + "/api/v1/agent/activity/daily-aggregates":
                    device_id = self.require_agent_payload(payload)
                    if not device_id:
                        return
                    if payload.get("schema_version") != 1:
                        return self.error(
                            HTTPStatus.BAD_REQUEST,
                            "Version d’agrégats journaliers invalide.",
                        )
                    try:
                        result = owner.store.ingest_activity_daily_aggregates(
                            device_id, payload.get("aggregates"),
                            payload.get("windows_sid"),
                        )
                    except IdempotencyConflict as error:
                        return self.error(HTTPStatus.CONFLICT, str(error))
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.OK, {
                        "ok": True, **result,
                    })
                if parsed.path == PREFIX + "/api/v1/agent/activity/timeline":
                    device_id = self.require_agent_payload(payload)
                    if not device_id:
                        return
                    try:
                        result = owner.store.ingest_activity_timeline_sessions(
                            device_id, payload.get("windows_sid"),
                            payload.get("sessions"),
                        )
                    except IdempotencyConflict as error:
                        return self.error(HTTPStatus.CONFLICT, str(error))
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.OK, {
                        "ok": True, **result,
                    })
                if parsed.path == PREFIX + "/api/v1/agent/activity/live":
                    device_id = self.require_agent_payload(payload)
                    if not device_id:
                        return
                    try:
                        result = owner.store.replace_live_activity_intervals(
                            device_id, payload.get("live_intervals"),
                        )
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.OK, {"ok": True, **result})
                if parsed.path == PREFIX + "/api/v1/agent/email/settings":
                    return self.error(HTTPStatus.FORBIDDEN, "Le secret appareil ne donne aucun droit sur le SMTP")
                if parsed.path == PREFIX + "/api/v1/agent/email/test":
                    return self.error(HTTPStatus.FORBIDDEN, "Le secret appareil ne peut pas tester le SMTP")
                if parsed.path == PREFIX + "/api/v1/agent/email/send":
                    device_id = self.require_agent_payload(payload)
                    if not device_id: return
                    if not owner.store.device_notification_recipient_allowed(
                        device_id, payload.get("recipient"), payload.get("kind"),
                    ):
                        return self.error(HTTPStatus.FORBIDDEN, "Notification e-mail hors du périmètre de cet appareil")
                    return self.send_email(
                        payload.get("title"), payload.get("message"),
                        payload.get("recipient"), False, payload.get("kind", ""),
                    )
                if parsed.path == PREFIX + "/api/v1/agent/users":
                    return self.error(HTTPStatus.FORBIDDEN, "Le secret appareil ne donne aucun droit sur les comptes")
                agent_user_prefix = PREFIX + "/api/v1/agent/users/"
                if parsed.path.startswith(agent_user_prefix) and parsed.path.endswith("/access"):
                    return self.error(HTTPStatus.FORBIDDEN, "Le secret appareil ne donne aucun droit sur les comptes")
                if parsed.path.startswith(PREFIX + "/api/v1/agent/commands/") and parsed.path.endswith("/ack"):
                    device_id = self.require_agent_payload(payload)
                    if not device_id: return
                    command_id = parsed.path.removesuffix("/ack").rsplit("/", 1)[-1]
                    if not command_id.isdigit():
                        return self.error(HTTPStatus.BAD_REQUEST, "Accusé invalide")
                    ok = owner.store.acknowledge(device_id, int(command_id), payload.get("result", {}))
                    return self.json(HTTPStatus.OK if ok else HTTPStatus.NOT_FOUND, {"ok": ok})
                if parsed.path == PREFIX + "/api/v1/agent/catalog/actions":
                    device_id = self.require_agent_payload(payload)
                    if not device_id:
                        return
                    mapping = owner.store.user_for_windows_sid(
                        device_id, payload.get("windows_sid"),
                    )
                    if not mapping:
                        return self.error(
                            HTTPStatus.CONFLICT,
                            "Cette session Windows n’est pas associée.",
                        )
                    reported_actor = str(payload.get("actor") or "").strip()
                    actor = "appareil " + owner.store.device_display_name(device_id)
                    if reported_actor:
                        actor += " · " + reported_actor[:100]
                    try:
                        command = dict(payload.get("command") or {})
                        action = str(command.get("action") or "")
                        if action == "delete_site":
                            return self.error(
                                HTTPStatus.FORBIDDEN,
                                "Mutation locale de limite non autorisée.",
                            )
                        remove_policy_limits = False
                        if action == "delete_target":
                            if command.get(
                                "_usage_guard_delete_limits_authorized"
                            ) is not True:
                                return self.error(
                                    HTTPStatus.FORBIDDEN,
                                    "Mutation locale de limite non autorisée.",
                                )
                            target_key = owner.store._catalog_deletion_target(
                                command
                            )
                            selected_ids = owner.store.selected_user_device_ids(
                                mapping["usage_guard_username"]
                            )
                            impact = owner.store.target_policy_deletion_impact(
                                mapping["usage_guard_username"], target_key,
                                selected_ids,
                            )
                            other_owners = {
                                value.casefold() for value in impact["owners"]
                                if value.casefold() != str(
                                    mapping["usage_guard_username"]
                                ).casefold()
                            }
                            if (
                                other_owners
                                and command.get(
                                    "_usage_guard_delete_other_limits_authorized"
                                ) is not True
                            ):
                                return self.error(
                                    HTTPStatus.FORBIDDEN,
                                    "Cette limitation a été demandée par une autre personne",
                                )
                            remove_policy_limits = True
                        operation = owner.store.queue_user_catalog_action(
                            mapping["usage_guard_username"],
                            command, actor,
                            payload.get("idempotency_key"),
                            exclude_device_id=device_id,
                            remove_policy_limits=remove_policy_limits,
                        )
                    except IdempotencyConflict as error:
                        return self.error(HTTPStatus.CONFLICT, str(error))
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    owner._mark_agent_seen(device_id)
                    return self.json(HTTPStatus.ACCEPTED, {
                        "ok": True, **operation,
                    })
                if parsed.path == PREFIX + "/api/v1/agent/policy/actions":
                    device_id = self.require_agent_payload(payload)
                    if not device_id:
                        return
                    windows_sid = payload.get("windows_sid")
                    mapping = owner.store.user_for_windows_sid(
                        device_id, windows_sid,
                    )
                    if not mapping:
                        return self.error(
                            HTTPStatus.CONFLICT,
                            "Cette session Windows n’est pas associée.",
                        )
                    command = payload.get("command")
                    computer_actions = {
                        "set_computer_block", "set_computer_block_enabled",
                        "clear_computer_block",
                    }
                    if (
                        not isinstance(command, dict)
                        or command.get("action") not in {
                            "set_limit", "remove_limit", *computer_actions,
                        }
                    ):
                        return self.error(
                            HTTPStatus.BAD_REQUEST,
                            "Mutation locale de limite non autorisée.",
                        )
                    reported_actor = str(payload.get("actor") or "").strip()
                    actor = "appareil " + owner.store.device_display_name(device_id)
                    if reported_actor:
                        actor += " · " + reported_actor[:100]
                    if command.get("action") in computer_actions:
                        try:
                            computer_policy = owner.store.mutate_user_computer_block(
                                mapping["usage_guard_username"], command, actor,
                                payload.get("idempotency_key"),
                            )
                        except ValueError as error:
                            return self.error(HTTPStatus.BAD_REQUEST, str(error))
                        if not computer_policy.get("reused"):
                            owner._dispatch_limit_change(
                                mapping["usage_guard_username"], command, actor,
                            )
                        owner._mark_agent_seen(device_id)
                        return self.json(HTTPStatus.ACCEPTED, {
                            "ok": True,
                            "usage_guard_username": mapping[
                                "usage_guard_username"
                            ],
                            "computer_block_policy": computer_policy,
                        })
                    try:
                        operation = owner.store.begin_user_policy_operation(
                            mapping["usage_guard_username"], command, actor,
                            device_id, payload.get("idempotency_key"),
                        )
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    owner._mark_agent_seen(device_id)
                    return self.json(HTTPStatus.ACCEPTED, {
                        "ok": True, **operation,
                    })
                if parsed.path == PREFIX + "/api/v1/agent/policy/ack":
                    device_id = self.require_agent_payload(payload)
                    if not device_id: return
                    try:
                        policy = owner.store.acknowledge_user_policy(
                            device_id, payload.get("windows_sid"),
                            payload.get("revision"), payload.get("result"),
                        )
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.OK, {
                        "ok": True, "policy": policy,
                    })
                catalog_prefix = PREFIX + "/api/v1/catalogs/"
                catalog_bootstrap_suffix = "/bootstrap"
                if (
                    parsed.path.startswith(catalog_prefix)
                    and parsed.path.endswith(catalog_bootstrap_suffix)
                ):
                    session = self.require_user_write()
                    if not session:
                        return
                    username = unquote(parsed.path[
                        len(catalog_prefix):-len(catalog_bootstrap_suffix)
                    ].strip("/"))
                    if not session["permissions"]["manage_activity"]:
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Modification du classement non autorisée",
                        )
                    if not owner.store.user_can_access_policy(
                        session["username"], username, session["is_admin"],
                    ):
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Cet utilisateur n’est pas autorisé pour ce compte",
                        )
                    try:
                        operation = owner.store.bootstrap_user_catalog(
                            username, session["username"],
                            payload.get("idempotency_key"),
                            device_ids=payload.get("device_ids"),
                        )
                    except IdempotencyConflict as error:
                        return self.error(HTTPStatus.CONFLICT, str(error))
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.ACCEPTED, {
                        "ok": True, **operation,
                    })
                catalog_action_suffix = "/actions"
                if (
                    parsed.path.startswith(catalog_prefix)
                    and parsed.path.endswith(catalog_action_suffix)
                ):
                    session = self.require_user_write()
                    if not session:
                        return
                    username = unquote(parsed.path[
                        len(catalog_prefix):-len(catalog_action_suffix)
                    ].strip("/"))
                    if not session["permissions"]["manage_activity"]:
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Modification du classement non autorisée",
                        )
                    if not owner.store.user_can_access_policy(
                        session["username"], username, session["is_admin"],
                    ):
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Cet utilisateur n’est pas autorisé pour ce compte",
                        )
                    action = str(payload.get("action") or "")
                    if (
                        action in {"delete_target", "delete_site"}
                        and not session["permissions"]["manage_limits"]
                    ):
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Modification de politique non autorisée",
                        )
                    if action == "delete_site":
                        return self.error(
                            HTTPStatus.BAD_REQUEST,
                            "Mutation de classement non autorisée.",
                        )
                    try:
                        deletion_target = owner.store._catalog_deletion_target(
                            payload
                        )
                        if deletion_target:
                            selected_ids = owner.store.selected_user_device_ids(
                                username, payload.get("device_ids"),
                            )
                            impact = owner.store.target_policy_deletion_impact(
                                username, deletion_target, selected_ids,
                            )
                            other_owners = {
                                value.casefold() for value in impact["owners"]
                                if value.casefold()
                                != session["username"].casefold()
                            }
                            if (
                                other_owners
                                and not session["permissions"].get(
                                    "manage_other_limits", False
                                )
                            ):
                                return self.error(
                                    HTTPStatus.FORBIDDEN,
                                    "Cette limitation a été demandée par une autre personne",
                                )
                        operation = owner.store.queue_user_catalog_action(
                            username, payload, session["username"],
                            payload.get("idempotency_key"),
                            device_ids=payload.get("device_ids"),
                        )
                    except IdempotencyConflict as error:
                        return self.error(HTTPStatus.CONFLICT, str(error))
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.ACCEPTED, {
                        "ok": True, **operation,
                    })
                policy_prefix = PREFIX + "/api/v1/policies/"
                policy_operation_marker = "/operations/"
                if (
                    parsed.path.startswith(policy_prefix)
                    and policy_operation_marker in parsed.path
                    and parsed.path.endswith("/cancel")
                ):
                    session = self.require_user_write()
                    if not session:
                        return
                    relative = parsed.path[
                        len(policy_prefix):-len("/cancel")
                    ].rstrip("/")
                    username, operation_id = relative.split(
                        policy_operation_marker, 1,
                    )
                    username = unquote(username.strip("/"))
                    operation_id = operation_id.strip("/")
                    if not operation_id.isdigit():
                        return self.error(
                            HTTPStatus.NOT_FOUND, "Opération inconnue"
                        )
                    if not session["permissions"]["manage_limits"]:
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Modification de politique non autorisée",
                        )
                    if not owner.store.user_can_access_policy(
                        session["username"], username, session["is_admin"],
                    ):
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Cet utilisateur n’est pas autorisé pour ce compte",
                        )
                    operation = owner.store.user_policy_operation(
                        username, int(operation_id),
                    )
                    if (
                        operation
                        and str(operation.get("actor") or "").casefold()
                        != session["username"].casefold()
                        and not session["permissions"].get(
                            "manage_other_limits", False
                        )
                    ):
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Cette limitation a été demandée par une autre personne",
                        )
                    try:
                        operation = owner.store.cancel_user_policy_operation(
                            username, int(operation_id), session["username"],
                        )
                    except ValueError as error:
                        return self.error(HTTPStatus.CONFLICT, str(error))
                    if not operation:
                        return self.error(
                            HTTPStatus.NOT_FOUND, "Opération inconnue"
                        )
                    return self.json(HTTPStatus.OK, operation)
                policy_action_suffix = "/actions"
                if (
                    parsed.path.startswith(policy_prefix)
                    and parsed.path.endswith(policy_action_suffix)
                ):
                    session = self.require_user_write()
                    if not session:
                        return
                    username = unquote(parsed.path[
                        len(policy_prefix):-len(policy_action_suffix)
                    ].strip("/"))
                    if not session["permissions"]["manage_limits"]:
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Modification de politique non autorisée",
                        )
                    if not owner.store.user_can_access_policy(
                        session["username"], username, session["is_admin"],
                    ):
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Cet utilisateur n’est pas autorisé pour ce compte",
                        )
                    mutation_owner = owner.store.user_policy_mutation_owner(
                        username, payload,
                    )
                    if (
                        mutation_owner
                        and mutation_owner.casefold()
                        != session["username"].casefold()
                        and not session["permissions"].get(
                            "manage_other_limits", False
                        )
                    ):
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Cette limitation a été demandée par une autre personne",
                        )
                    if payload.get("action") in {
                        "set_computer_block", "set_computer_block_enabled",
                        "clear_computer_block",
                    }:
                        try:
                            computer_policy = (
                                owner.store.mutate_user_computer_block(
                                    username, payload, session["username"],
                                    payload.get("idempotency_key"),
                                )
                            )
                        except ValueError as error:
                            return self.error(
                                HTTPStatus.BAD_REQUEST, str(error)
                            )
                        if not computer_policy.get("reused"):
                            owner._dispatch_limit_change(
                                username, payload, session["username"]
                            )
                        return self.json(HTTPStatus.ACCEPTED, {
                            "ok": True,
                            "computer_block_policy": computer_policy,
                        })
                    try:
                        operation = owner.store.begin_user_policy_operation(
                            username, payload, session["username"],
                            payload.get("base_device_id"),
                            payload.get("idempotency_key"),
                        )
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    if not operation.get("reused"):
                        owner._dispatch_limit_change(
                            username, payload, session["username"]
                        )
                    return self.json(HTTPStatus.ACCEPTED, {
                        "ok": True, **operation,
                    })
                if parsed.path.startswith(policy_prefix):
                    session = self.require_user_write()
                    if not session: return
                    username = unquote(
                        parsed.path[len(policy_prefix):].strip("/")
                    )
                    if not session["permissions"]["manage_limits"]:
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Modification de politique non autorisée",
                        )
                    if not owner.store.user_can_access_policy(
                        session["username"], username, session["is_admin"],
                    ):
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Cet utilisateur n’est pas autorisé pour ce compte",
                        )
                    try:
                        policy = owner.store.save_user_policy(
                            username, payload.get("policy"),
                            session["username"],
                        )
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.OK, {
                        "ok": True, **policy,
                    })
                action_prefix = PREFIX + "/api/v1/actions/"
                if (
                    parsed.path.startswith(action_prefix)
                    and parsed.path.endswith("/cancel")
                ):
                    session = self.require_user_write()
                    if not session:
                        return
                    command_id = parsed.path[
                        len(action_prefix):-len("/cancel")
                    ].strip("/")
                    if not command_id.isdigit():
                        return self.error(
                            HTTPStatus.NOT_FOUND, "Opération inconnue"
                        )
                    device_id = self.selected_device(session, payload=payload)
                    if not device_id:
                        return
                    status = owner.store.command_status(
                        device_id, int(command_id)
                    )
                    if not status:
                        return self.error(
                            HTTPStatus.NOT_FOUND, "Opération inconnue"
                        )
                    permission = action_permission(status.get("action"))
                    if not session["permissions"][permission]:
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Annulation non autorisée pour ce compte",
                        )
                    outcome = owner.store.cancel_command(
                        device_id, int(command_id)
                    )
                    if outcome == "cancelled":
                        return self.json(
                            HTTPStatus.OK, {"ok": True, "cancelled": True}
                        )
                    if outcome == "delivered":
                        return self.error(
                            HTTPStatus.CONFLICT,
                            "La commande a déjà été récupérée par le PC ; "
                            "son application doit maintenant être confirmée.",
                        )
                    if outcome == "acknowledged":
                        return self.error(
                            HTTPStatus.CONFLICT,
                            "La commande a déjà été appliquée par le PC.",
                        )
                    return self.error(
                        HTTPStatus.NOT_FOUND, "Opération inconnue"
                    )
                if parsed.path == PREFIX + "/api/v1/actions":
                    session = self.require_user_write()
                    if not session: return
                    device_id = self.selected_device(session, payload=payload)
                    if not device_id: return
                    if payload.get("action") not in ALLOWED_ACTIONS:
                        return self.error(HTTPStatus.BAD_REQUEST, "Commande non autorisée")
                    permission = action_permission(payload.get("action"))
                    if not session["permissions"][permission]:
                        return self.error(HTTPStatus.FORBIDDEN, "Modification non autorisée pour ce compte")
                    if payload.get("action") in {"set_notification_rule", "remove_notification_rule"}:
                        snapshot = owner.store.snapshot(device_id) or {}
                        rules = snapshot.get("notification_rules", [])
                        rule_id = str(
                            payload.get("rule", {}).get("id", "")
                            if payload.get("action") == "set_notification_rule"
                            else payload.get("rule_id", "")
                        )
                        existing = next((item for item in rules if str(item.get("id", "")) == rule_id), None)
                        existing_owner = str(existing.get("owner", "")).strip() if existing else ""
                        requested_owner = str((
                            dict(payload.get("rule") or {}).get("owner")
                            if payload.get("action") == "set_notification_rule"
                            else payload.get("notification_owner")
                        ) or session["username"]).strip()
                        if (
                            requested_owner.casefold()
                            != session["username"].casefold()
                            and not owner.store.user_can_access_policy(
                                session["username"], requested_owner,
                                session["is_admin"],
                            )
                        ):
                            return self.error(
                                HTTPStatus.FORBIDDEN,
                                "Notifications de cette personne non autorisées",
                            )
                        if (
                            existing and existing_owner
                            and existing_owner.casefold()
                            != requested_owner.casefold()
                        ):
                            return self.error(
                                HTTPStatus.FORBIDDEN,
                                "Cette notification appartient à une autre personne",
                            )
                        if payload.get("action") == "set_notification_rule":
                            payload = {
                                **payload,
                                "rule": {
                                    **dict(payload.get("rule") or {}),
                                    "owner": requested_owner,
                                },
                            }
                        owner.store.update_device_notification_policy(
                            device_id, payload.get("action"),
                            payload.get("rule"), payload.get("rule_id", ""),
                        )
                    command = {
                        key: value for key, value in payload.items()
                        if key not in {"device_id", "idempotency_key"}
                    }
                    command["actor"] = session["username"]
                    try:
                        command_id, reused = owner.store.queue_idempotent(
                            device_id, command, payload.get("idempotency_key"),
                        )
                    except IdempotencyConflict as error:
                        return self.error(HTTPStatus.CONFLICT, str(error))
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.ACCEPTED, {
                        "ok": True, "queued": True,
                        "id": str(command_id), "reused": reused,
                    })
                if parsed.path in {PREFIX + "/api/v1/email/settings", PREFIX + "/api/v1/email/test"}:
                    session = self.require_user_write()
                    if not session: return
                    if not session["is_admin"]:
                        return self.error(HTTPStatus.FORBIDDEN, "Droits administrateur requis")
                    if parsed.path.endswith("/settings"):
                        try:
                            settings = owner.store.save_email_settings(payload)
                        except ValueError as error:
                            return self.error(HTTPStatus.BAD_REQUEST, str(error))
                        return self.json(HTTPStatus.OK, {"ok": True, "email_settings": settings})
                    return self.send_email("Test de notification", "Ce message confirme que les notifications par e-mail de Usage Guard fonctionnent.", payload.get("recipient"), True)
                if parsed.path == PREFIX + "/api/v1/admin/database/backup":
                    session = self.require_user_write()
                    if not session:
                        return
                    if not session["is_admin"]:
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Droits administrateur requis",
                        )
                    version = pwa_release_version(owner.pwa_dir)
                    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
                    filename = f"usage-guard-backup-v{version}-{stamp}.sqlite3"
                    temporary = tempfile.NamedTemporaryFile(
                        prefix="usage-guard-backup-", suffix=".sqlite3",
                        delete=False,
                    )
                    backup_path = Path(temporary.name)
                    temporary.close()
                    try:
                        owner.store.create_database_backup(
                            backup_path, session["username"], version,
                        )
                        return self.binary_file(
                            backup_path, filename,
                            content_type="application/vnd.sqlite3",
                        )
                    except (OSError, sqlite3.DatabaseError) as error:
                        return self.error(
                            HTTPStatus.INTERNAL_SERVER_ERROR,
                            f"Sauvegarde SQLite impossible : {error}",
                        )
                    finally:
                        backup_path.unlink(missing_ok=True)
                admin_prefix = PREFIX + "/api/v1/admin/users/"
                if parsed.path == PREFIX + "/api/v1/admin/users":
                    session = self.require_user_write()
                    if not session: return
                    if not session["is_admin"]:
                        return self.error(HTTPStatus.FORBIDDEN, "Droits administrateur requis")
                    try:
                        user = owner.store.create_user(
                            payload.get("username"), payload.get("password"),
                            True, payload.get("email", ""),
                            payload.get("is_admin", False), payload.get("permissions", {}),
                            payload.get("role"), payload.get("device_ids", []),
                        )
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.CREATED, {"ok": True, "user": user})
                if parsed.path.startswith(admin_prefix) and parsed.path.endswith("/access"):
                    session = self.require_user_write()
                    if not session: return
                    if not session["is_admin"]: return self.error(HTTPStatus.FORBIDDEN, "Droits administrateur requis")
                    username = unquote(parsed.path[len(admin_prefix):-len("/access")].rstrip("/"))
                    users_before = {
                        item["username"].casefold(): item
                        for item in owner.store.list_users()
                    }
                    try:
                        user = owner.store.update_user_access(
                            username, payload.get("is_admin", False),
                            payload.get("permissions", {}), session["username"],
                            payload.get("email"),
                            payload.get("role"),
                            payload.get("device_ids"),
                            payload.get("person_usernames"),
                        )
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    users_after = {
                        item["username"].casefold(): item
                        for item in owner.store.list_users()
                    }
                    for key in sorted(users_before.keys() & users_after.keys()):
                        owner._dispatch_access_change(
                            users_before[key], users_after[key],
                            session["username"],
                        )
                    return self.json(HTTPStatus.OK, {"ok": True, "user": user})
                if parsed.path == PREFIX + "/api/v1/admin/device-enrollments":
                    session = self.require_user_write()
                    if not session: return
                    if not session["is_admin"]:
                        return self.error(HTTPStatus.FORBIDDEN, "Droits administrateur requis")
                    try:
                        enrollment = owner.store.create_device_enrollment(
                            session["username"], payload.get("username"),
                            payload.get("device_id"), payload.get("display_name", ""),
                            payload.get("lifetime_seconds", ENROLLMENT_SECONDS),
                            payload.get("windows_identities")
                            if "windows_identities" in payload else None,
                        )
                    except (TypeError, ValueError) as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.CREATED, {
                        "ok": True, "enrollment": enrollment,
                    })
                identity_suffix = "/windows-identities"
                identity_prefix = PREFIX + "/api/v1/admin/devices/"
                if (
                    parsed.path.startswith(identity_prefix)
                    and parsed.path.endswith(identity_suffix)
                ):
                    session = self.require_user_write()
                    if not session: return
                    if not session["is_admin"]:
                        return self.error(
                            HTTPStatus.FORBIDDEN,
                            "Droits administrateur requis",
                        )
                    device_id = unquote(
                        parsed.path[
                            len(identity_prefix):-len(identity_suffix)
                        ].rstrip("/")
                    )
                    try:
                        identities = owner.store.set_device_windows_identities(
                            device_id, payload.get("windows_identities"),
                            session["username"],
                        )
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.OK, {
                        "ok": True, "windows_identities": identities,
                    })
                if parsed.path.startswith(PREFIX + "/api/v1/admin/devices/") and parsed.path.endswith("/revoke"):
                    session = self.require_user_write()
                    if not session: return
                    if not session["is_admin"]:
                        return self.error(HTTPStatus.FORBIDDEN, "Droits administrateur requis")
                    device_id = unquote(parsed.path[len(PREFIX + "/api/v1/admin/devices/"):-len("/revoke")].rstrip("/"))
                    try:
                        owner.store.revoke_device(device_id)
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.OK, {"ok": True})
                if parsed.path.startswith(PREFIX + "/api/v1/admin/devices/") and parsed.path.endswith("/rename"):
                    session = self.require_user_write()
                    if not session: return
                    if not session["is_admin"]:
                        return self.error(HTTPStatus.FORBIDDEN, "Droits administrateur requis")
                    device_id = unquote(parsed.path[len(PREFIX + "/api/v1/admin/devices/"):-len("/rename")].rstrip("/"))
                    try:
                        device = owner.store.rename_device(
                            device_id, payload.get("label", ""),
                        )
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                    return self.json(HTTPStatus.OK, {"ok": True, "device": device})
                return self.error(HTTPStatus.NOT_FOUND, "Endpoint inconnu")

            def do_DELETE(self):
                parsed = urlparse(self.path)
                agent_prefix = PREFIX + "/api/v1/agent/users/"
                if parsed.path.startswith(agent_prefix):
                    return self.error(HTTPStatus.FORBIDDEN, "Le secret appareil ne donne aucun droit sur les comptes")
                prefix = PREFIX + "/api/v1/admin/users/"
                if not parsed.path.startswith(prefix):
                    return self.error(HTTPStatus.NOT_FOUND, "Endpoint inconnu")
                session = self.require_user_write()
                if not session: return
                if not session["is_admin"]:
                    return self.error(HTTPStatus.FORBIDDEN, "Droits administrateur requis")
                try:
                    owner.store.delete_user(unquote(parsed.path[len(prefix):]))
                except ValueError as error:
                    return self.error(HTTPStatus.BAD_REQUEST, str(error))
                return self.json(HTTPStatus.OK, {"ok": True})

            def send_email(self, title, message, recipient, force, kind=""):
                try:
                    recipient = owner.store._valid_email_address(recipient, "Adresse de destination")
                except ValueError as error:
                    return self.error(HTTPStatus.BAD_REQUEST, str(error))
                if not force and not owner.store.email_settings()["enabled"]:
                    return self.json(HTTPStatus.OK, {"ok": True, "skipped": True, "reason": "disabled"})
                if not owner.email_limiter.allow(recipient):
                    return self.error(HTTPStatus.TOO_MANY_REQUESTS, "Trop d’envois vers cette adresse. Réessayez dans quelques minutes.")
                try:
                    result = owner.store.send_email_notification(
                        title, message, recipient, force, kind
                    )
                except ValueError as error:
                    return self.error(HTTPStatus.BAD_REQUEST, str(error))
                except (OSError, smtplib.SMTPException) as error:
                    return self.error(HTTPStatus.BAD_GATEWAY, f"Envoi SMTP impossible : {error}")
                return self.json(HTTPStatus.OK, result)

            def login(self, payload):
                if not self.valid_origin(): return self.error(HTTPStatus.FORBIDDEN, "Origine refusée")
                username = str(payload.get("username", "")).strip()
                key = (self.client_ip(), username.casefold())
                if not owner.login_limiter.allowed(key):
                    return self.error(HTTPStatus.TOO_MANY_REQUESTS, "Trop de tentatives. Réessayez dans 15 minutes.")
                user = owner.store.authenticate(username, payload.get("password"))
                if not user:
                    if not owner.store.has_admin() and not owner.store.has_users():
                        return self.error(
                            HTTPStatus.SERVICE_UNAVAILABLE,
                            "Aucun administrateur n’est configuré sur ce serveur. "
                            "Le premier administrateur doit être créé localement "
                            "sur le serveur avant d’installer un ordinateur.",
                        )
                    owner.login_limiter.failed(key)
                    print(f"AUTH_FAILURE ip={key[0]} username={username[:32]!r}")
                    return self.error(HTTPStatus.UNAUTHORIZED, "Identifiant ou mot de passe incorrect")
                owner.login_limiter.succeeded(key)
                if user["must_set_email"] and str(payload.get("email") or "").strip():
                    try:
                        user = owner.store.update_user_email(
                            user["username"], payload.get("email")
                        )
                    except ValueError as error:
                        return self.error(HTTPStatus.BAD_REQUEST, str(error))
                raw, csrf, expires = owner.store.create_session(user["username"])
                snapshot = owner.store.snapshot(owner.device_id) or {}
                actor, ip = user["username"], self.client_ip()
                actor_key = actor.strip().casefold()
                actor_is_admin = bool(user["is_admin"])
                actor_role = str(user.get("role") or (
                    "admin" if actor_is_admin else "user"
                )).strip().lower()
                login_rules = [
                    rule for rule in snapshot.get("notification_rules", [])
                    if rule.get("enabled") and rule.get("kind") == "pwa_login"
                    and not (
                        str(rule.get("owner", "")).strip()
                        and str(rule.get("owner", "")).strip().casefold() == actor_key
                    )
                    and actor_role in notification_subject_roles(rule)
                ]
                title = f"{actor} connecté à la PWA — Usage Guard"
                message = f"{actor} vient de se connecter à la PWA depuis {ip}."
                recipient_rules = {}
                for rule in login_rules:
                    recipient = str(rule.get("email_recipient", "")).strip()
                    if "email" in (rule.get("channels") or ["windows"]) and recipient:
                        recipient_rules.setdefault(recipient, rule)
                if owner.store.email_settings()["enabled"]:
                    for recipient, rule in recipient_rules.items():
                        try:
                            recipient = owner.store._valid_email_address(recipient, "Adresse de destination")
                        except ValueError:
                            continue
                        if owner.email_limiter.allow(recipient):
                            threading.Thread(
                                target=owner._send_email_background,
                                args=(
                                    title,
                                    str(rule.get("description") or message),
                                    recipient,
                                    "pwa_login",
                                ),
                                daemon=True,
                            ).start()
                windows_rule = next((
                    rule for rule in login_rules
                    if "windows" in (rule.get("channels") or ["windows"])
                ), None)
                if windows_rule:
                    owner.store.queue(owner.device_id, {
                        "action": "notify_pwa_login",
                        "actor": actor,
                        "actor_is_admin": actor_is_admin,
                        "actor_role": actor_role,
                        "ip": ip,
                        "title": title,
                        "message": str(windows_rule.get("description") or message),
                        "windows_only": True,
                    })
                return self.json(HTTPStatus.OK, {
                    "ok": True, **user, "csrf_token": csrf, "expires_at": expires,
                }, {"Set-Cookie": self.session_cookie_header(raw)})

            def require_user_write(
                self, allow_password_change=False, allow_email_setup=False,
            ):
                if not self.valid_origin():
                    self.error(HTTPStatus.FORBIDDEN, "Origine refusée"); return None
                session = self.user_session()
                if not session:
                    self.error(HTTPStatus.UNAUTHORIZED, "Connexion requise"); return None
                if session["must_change"] and not allow_password_change:
                    self.error(HTTPStatus.FORBIDDEN, "Changement de mot de passe requis"); return None
                supplied = self.headers.get("X-CSRF-Token", "")
                if not supplied or not secrets.compare_digest(supplied, session["csrf_token"]):
                    self.error(HTTPStatus.FORBIDDEN, "Protection CSRF refusée"); return None
                return session

            def agent_authorized(self, device_id):
                supplied = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
                return owner.store.authenticate_device(device_id, supplied)

            def require_agent_query(self, parsed):
                device_id = parse_qs(parsed.query).get("device_id", [""])[0]
                if not self.agent_authorized(device_id):
                    self.error(HTTPStatus.UNAUTHORIZED, "Authentification appareil refusée")
                    return None
                return device_id

            def require_agent_payload(self, payload):
                device_id = str(payload.get("device_id") or "").strip()
                if not self.agent_authorized(device_id):
                    self.error(HTTPStatus.UNAUTHORIZED, "Authentification appareil refusée")
                    return None
                return device_id

            def selected_device(self, session, parsed=None, payload=None):
                requested = ""
                if parsed is not None:
                    requested = parse_qs(parsed.query).get("device_id", [""])[0]
                elif isinstance(payload, dict):
                    requested = str(payload.get("device_id") or "").strip()
                accessible = list(session.get("accessible_device_ids") or [])
                if not requested:
                    requested = owner.device_id if owner.device_id in accessible else (accessible[0] if accessible else "")
                if not requested or requested not in accessible:
                    self.error(
                        HTTPStatus.FORBIDDEN,
                        "Ce compte n’est pas autorisé à accéder à cet ordinateur",
                    )
                    return None
                return requested

            def valid_origin(self):
                return self.headers.get("Origin", "").rstrip("/") == owner.public_origin

            def client_ip(self):
                forwarded = self.headers.get("X-Forwarded-For", "").split(",", 1)[0].strip()
                try: return str(ipaddress.ip_address(forwarded))
                except ValueError: return self.client_address[0]

            def session_cookie(self):
                try:
                    cookie = SimpleCookie(self.headers.get("Cookie", ""))
                    return cookie.get("ug_session").value if cookie.get("ug_session") else ""
                except Exception:
                    return ""

            def user_session(self):
                return owner.store.session(self.session_cookie())

            @staticmethod
            def session_payload(session):
                return {
                    "authenticated": True, "username": session["username"],
                    "must_change": bool(session["must_change"]),
                    "email": str(session.get("email") or ""),
                    "must_set_email": bool(session["must_set_email"]),
                    "is_admin": bool(session["is_admin"]),
                    "role": str(session.get("role") or ("admin" if session["is_admin"] else "limited")),
                    "device_ids": list(session.get("device_ids") or []),
                    "person_usernames": list(session.get("person_usernames") or []),
                    "accessible_person_usernames": list(session.get("accessible_person_usernames") or []),
                    "accessible_device_ids": list(session.get("accessible_device_ids") or []),
                    "permissions": session["permissions"],
                    "csrf_token": session["csrf_token"], "expires_at": session["expires_at"],
                }

            @staticmethod
            def session_cookie_header(raw):
                secure = "" if owner.local_mode else " Secure;"
                return f"ug_session={raw}; Path={PREFIX}; Max-Age={SESSION_SECONDS};{secure} HttpOnly; SameSite=Strict"

            @staticmethod
            def expired_cookie():
                secure = "" if owner.local_mode else " Secure;"
                return f"ug_session=; Path={PREFIX}; Max-Age=0;{secure} HttpOnly; SameSite=Strict"

            def body(self):
                try: length = int(self.headers.get("Content-Length", "0"))
                except ValueError: raise ValueError("Taille invalide")
                if length < 0 or length > MAX_BODY:
                    raise ValueError("Charge utile trop volumineuse")
                try: payload = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
                except (UnicodeDecodeError, json.JSONDecodeError): raise ValueError("JSON invalide")
                if not isinstance(payload, dict): raise ValueError("Objet JSON requis")
                return payload

            def static(self, request_path):
                relative = request_path[len(PREFIX):].lstrip("/") if request_path.startswith(PREFIX) else ""
                if not relative: relative = "index.html"
                candidate = (owner.pwa_dir / relative).resolve()
                if owner.pwa_dir.resolve() not in candidate.parents or not candidate.is_file():
                    return self.error(HTTPStatus.NOT_FOUND, "Fichier inconnu")
                content = candidate.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.security_headers()
                self.send_header("Content-Type", mimetypes.guess_type(candidate.name)[0] or "application/octet-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers(); self.wfile.write(content)

            def json(self, status, payload, headers=None):
                content = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(status); self.security_headers()
                for name, value in (headers or {}).items(): self.send_header(name, value)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers(); self.wfile.write(content)

            def binary_file(self, path, filename, content_type="application/zip"):
                size = path.stat().st_size
                self.send_response(HTTPStatus.OK); self.security_headers()
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("Cache-Control", "no-store")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self.send_header("Content-Length", str(size))
                self.end_headers()
                with path.open("rb") as stream:
                    while True:
                        chunk = stream.read(1024 * 1024)
                        if not chunk: break
                        self.wfile.write(chunk)

            def error(self, status, message): return self.json(status, {"error": message})

            def security_headers(self):
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'; style-src-attr 'unsafe-inline'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'")

            def log_message(self, format_, *args):
                print(f"{self.client_ip()} - {format_ % args}")

        self.httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self._presence_stop.clear()
        self._presence_thread = threading.Thread(target=self._presence_loop, daemon=True)
        self._presence_thread.start()
        self.httpd.serve_forever()

    def stop(self):
        self._presence_stop.set()
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None


if __name__ == "__main__":
    BackendServer().start()
