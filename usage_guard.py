import json
import os
import shutil
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, date, timezone, timedelta
from pathlib import Path
from urllib.parse import urlparse

import yaml


APP_DIR = Path(__file__).resolve().parent
CONFIG_PATH = APP_DIR / "config.yaml"
APP_NAME = "Usage Guard"
LEGACY_APP_NAME = "Usage Monitor"
KNOWN_LOCAL_SITE_LABELS = {
    "localhost:8766": APP_NAME,
    "127.0.0.1:8766": APP_NAME,
    "[::1]:8766": APP_NAME,
}


def _repair_mojibake_text(value):
    """Undo UTF-8 bytes accidentally decoded as Windows-1252."""
    text = str(value)
    for _ in range(2):
        repaired = []
        index = 0
        changed = False
        while index < len(text):
            replacement = ""
            consumed = 0
            if text[index] in "ÃÂâ":
                for size in range(min(4, len(text) - index), 1, -1):
                    fragment = text[index:index + size]
                    try:
                        candidate = fragment.encode("cp1252").decode("utf-8")
                    except (UnicodeEncodeError, UnicodeDecodeError):
                        continue
                    if candidate != fragment and not any(ord(char) < 32 for char in candidate):
                        replacement = candidate
                        consumed = size
                        break
            if consumed:
                repaired.append(replacement)
                index += consumed
                changed = True
            else:
                repaired.append(text[index])
                index += 1
        text = "".join(repaired)
        if not changed:
            break
    return text


def _repair_mojibake_data(value, sum_numbers=False):
    if isinstance(value, str):
        repaired = _repair_mojibake_text(value)
        return repaired, repaired != value
    if isinstance(value, list):
        output = []
        changed = False
        for item in value:
            repaired, item_changed = _repair_mojibake_data(item, sum_numbers)
            changed |= item_changed
            if repaired not in output:
                output.append(repaired)
            else:
                changed = True
        return output, changed
    if isinstance(value, dict):
        output = {}
        changed = False
        for key, item in value.items():
            repaired_key = _repair_mojibake_text(key) if isinstance(key, str) else key
            child_sums = sum_numbers or repaired_key in {
                "days", "passive_days", "other_site_days"
            }
            repaired_item, item_changed = _repair_mojibake_data(item, child_sums)
            changed |= item_changed or repaired_key != key
            if repaired_key not in output:
                output[repaired_key] = repaired_item
            elif isinstance(output[repaired_key], dict) and isinstance(repaired_item, dict):
                merged, _ = _repair_mojibake_data(
                    {**output[repaired_key], **repaired_item}, child_sums
                )
                output[repaired_key] = merged
            elif child_sums and isinstance(output[repaired_key], (int, float)) and isinstance(repaired_item, (int, float)):
                output[repaired_key] = round(output[repaired_key] + repaired_item, 3)
            else:
                output[repaired_key] = repaired_item
        return output, changed
    return value, False


def _usage_path():
    """Return a location which survives a PyInstaller one-file restart."""
    if not getattr(sys, "frozen", False):
        return APP_DIR / "activity.json"

    # In a one-file executable, ``__file__`` is inside PyInstaller's temporary
    # extraction directory.  It is removed when the application exits, so it
    # must never be used to hold user data.
    local_app_data = os.environ.get("LOCALAPPDATA")
    base = (
        Path(local_app_data)
        if local_app_data
        else Path.home() / "AppData" / "Local"
    )
    destination = base / APP_NAME / "activity.json"
    legacy = base / LEGACY_APP_NAME / "activity.json"
    if not destination.exists() and legacy.exists():
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(legacy, destination)
        except OSError:
            return legacy
    return destination


USAGE_PATH = _usage_path()


class Config:
    def __init__(self, path=CONFIG_PATH):
        self._path = Path(path)
        if self._path.exists():
            with self._path.open("r", encoding="utf-8") as stream:
                data = yaml.safe_load(stream) or {}
        else:
            data = {}
        self._data = data
        self.__dict__.update(data)


config = Config()


def computer_on_seconds_today():
    """Return today's awake time, independently of this app's start time.

    ``GetTickCount64`` includes time spent sleeping, which made the value shown
    as "Allumé" grow while the computer was in standby.  Windows' unbiased
    interrupt time advances only while the system is awake.
    """
    if sys.platform != "win32":
        return None
    try:
        import ctypes

        awake_time_100ns = ctypes.c_ulonglong()
        if not ctypes.windll.kernel32.QueryUnbiasedInterruptTime(
            ctypes.byref(awake_time_100ns)
        ):
            return None
        awake_seconds = awake_time_100ns.value / 10_000_000.0
        now = datetime.now()
        start_of_day = datetime.combine(now.date(), datetime.min.time())
        return min(awake_seconds, (now - start_of_day).total_seconds())
    except (AttributeError, OSError):
        return None


def windows_session_started_at():
    """Return the logon time of the current interactive Windows session."""
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class WTSINFO(ctypes.Structure):
            _fields_ = [
                ("State", ctypes.c_int), ("SessionId", wintypes.DWORD),
                ("IncomingBytes", wintypes.DWORD), ("OutgoingBytes", wintypes.DWORD),
                ("IncomingFrames", wintypes.DWORD), ("OutgoingFrames", wintypes.DWORD),
                ("IncomingCompressedBytes", wintypes.DWORD),
                ("OutgoingCompressedBytes", wintypes.DWORD),
                ("WinStationName", wintypes.WCHAR * 33),
                ("Domain", wintypes.WCHAR * 18), ("UserName", wintypes.WCHAR * 21),
                ("ConnectTime", ctypes.c_longlong),
                ("DisconnectTime", ctypes.c_longlong),
                ("LastInputTime", ctypes.c_longlong),
                ("LogonTime", ctypes.c_longlong),
                ("CurrentTime", ctypes.c_longlong),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)
        session_id = kernel32.WTSGetActiveConsoleSessionId()
        if session_id == 0xFFFFFFFF:
            return None
        buffer, returned = wintypes.LPVOID(), wintypes.DWORD()
        if not wtsapi32.WTSQuerySessionInformationW(
            None, session_id, 24, ctypes.byref(buffer), ctypes.byref(returned)
        ):
            return None
        try:
            if returned.value < ctypes.sizeof(WTSINFO):
                return None
            logon_time = ctypes.cast(buffer, ctypes.POINTER(WTSINFO)).contents.LogonTime
            if logon_time <= 0:
                return None
            unix_seconds = logon_time / 10_000_000 - 11_644_473_600
            started = datetime.fromtimestamp(unix_seconds, timezone.utc).astimezone()
            now = datetime.now().astimezone()
            if started > now or (now - started).days > 365:
                return None
            return started
        finally:
            wtsapi32.WTSFreeMemory(buffer)
    except (AttributeError, OSError, OverflowError, ValueError):
        return None


DEBUG_LOG_PATH = (
    Path(sys.executable).resolve().parent / "usage-guard-debug.log"
    if getattr(sys, "frozen", False)
    else APP_DIR / "usage-guard-debug.log"
)


def debug_log(message):
    """Write diagnostics next to the executable when explicitly enabled."""
    if not getattr(config, "DEBUG_LOGGING", False):
        return
    try:
        with DEBUG_LOG_PATH.open("a", encoding="utf-8") as stream:
            stream.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} {message}\n")
    except OSError:
        pass


class AppUsageStore:
    """Small local store containing active seconds per application and day."""

    def __init__(self, path=USAGE_PATH):
        self.path = Path(path)
        self._import_legacy_activity_file()
        self._backup_activity_file()
        self.data = self._load()
        self.data, encoding_repaired = _repair_mojibake_data(self.data)
        legacy_migrated = self._migrate_legacy_targets()
        legacy_sessions_migrated = self._synthesize_legacy_daily_sessions()
        self._dirty = encoding_repaired or legacy_migrated or legacy_sessions_migrated
        if encoding_repaired:
            backup = self.path.with_suffix(".encoding-backup.json")
            try:
                if self.path.exists() and not backup.exists():
                    shutil.copy2(self.path, backup)
            except OSError:
                pass
        if self._dirty:
            self.save(force=True)

    def _backup_activity_file(self):
        """Keep one immutable pre-load copy per day next to the live store."""
        if not self.path.exists():
            return
        backup = (
            self.path.parent
            / "backups"
            / f"{self.path.stem}-{date.today().isoformat()}{self.path.suffix}"
        )
        if backup.exists():
            return
        try:
            backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.path, backup)
        except OSError:
            # Tracking must continue even if a locked-down installation does
            # not allow creation of the optional backup directory.
            pass

    def _import_legacy_activity_file(self):
        """Merge project-side activity data when upgrading to a one-file exe."""
        if not getattr(sys, "frozen", False) or self.path != USAGE_PATH:
            return

        executable_dir = Path(sys.executable).resolve().parent
        candidates = (executable_dir / "activity.json", executable_dir.parent / "activity.json")
        for source in candidates:
            if not source.exists() or source == self.path:
                continue
            source_id = str(source.resolve())
            try:
                source_data = json.loads(source.read_text(encoding="utf-8"))
                if not isinstance(source_data.get("days"), dict):
                    continue
                target_data = (
                    json.loads(self.path.read_text(encoding="utf-8"))
                    if self.path.exists()
                    else self._empty_data()
                )
                migrated = target_data.setdefault("migrated_sources", [])
                if source_id in migrated:
                    continue
                self._merge_activity_data(target_data, source_data)
                migrated.append(source_id)
                self.path.parent.mkdir(parents=True, exist_ok=True)
                temporary = self.path.with_suffix(".json.tmp")
                temporary.write_text(
                    json.dumps(target_data, ensure_ascii=False, indent=2, sort_keys=True),
                    encoding="utf-8",
                )
                os.replace(temporary, self.path)
            except (json.JSONDecodeError, OSError, ValueError, AttributeError):
                continue

    @staticmethod
    def _merge_activity_data(target, source):
        for section in ("days", "passive_days", "system_days"):
            target_section = target.setdefault(section, {})
            for day, values in source.get(section, {}).items():
                target_values = target_section.setdefault(day, {})
                for key, seconds in values.items():
                    target_values[key] = round(
                        float(target_values.get(key, 0.0)) + float(seconds), 3
                    )
        for key, metadata in source.get("targets", {}).items():
            target.setdefault("targets", {}).setdefault(key, metadata)
        target.setdefault("excluded", [])[:0] = list(
            dict.fromkeys(target.get("excluded", []) + source.get("excluded", []))
        )
        for key, category in source.get("browser_categories", {}).items():
            target.setdefault("browser_categories", {}).setdefault(key, category)
        for category, parent in source.get("category_parents", {}).items():
            target.setdefault("category_parents", {}).setdefault(category, parent)
        existing_order = target.setdefault("category_order", [])
        existing_order.extend(
            category for category in source.get("category_order", [])
            if category not in existing_order
        )
        if source.get("site_category_order_manual"):
            target["site_category_order_manual"] = True

    def _load(self):
        if not self.path.exists():
            return self._empty_data()
        try:
            # Accept a UTF-8 BOM too: some Windows tools write JSON that way.
            data = json.loads(self.path.read_text(encoding="utf-8-sig"))
            if not isinstance(data.get("days"), dict):
                raise ValueError("invalid activity store")
            data.setdefault("targets", {})
            data.setdefault("excluded", [])
            data.setdefault("excluded_sites", [])
            data.setdefault("browser_categories", {})
            data.setdefault("category_parents", {})
            data.setdefault("category_order", [])
            data.setdefault("browser_labels", {})
            data.setdefault("browser_specific_sites", {})
            data.setdefault("site_categories", [])
            data.setdefault("site_category_order_manual", False)
            data.setdefault("other_site_days", {})
            data.setdefault("passive_days", {})
            data.setdefault("passive_excluded", [])
            data.setdefault("merged_targets", {})
            data.setdefault("system_days", {})
            data.setdefault("app_limit_days", {})
            data.setdefault("app_limit_rolling", {})
            data.setdefault("app_limit_rolling_migrated", [])
            data.setdefault("app_limit_settings", {})
            data.setdefault("sessions", [])
            data.setdefault("open_sessions", {})
            data.setdefault("windows_sessions", [])
            data.setdefault("notification_rules", [])
            data.setdefault("default_limit_warning_seconds", 300)
            data.setdefault("computer_block", {})
            self._repair_sessions(data)
            self._repair_windows_sessions(data)
            data["version"] = 2
            return data
        except (json.JSONDecodeError, OSError, ValueError, AttributeError):
            corrupt_path = self.path.with_suffix(".json.corrupt")
            try:
                os.replace(self.path, corrupt_path)
            except OSError:
                pass
            return self._empty_data()

    @staticmethod
    def _empty_data():
        return {
            "version": 2,
            "days": {},
            "targets": {},
            "excluded": [],
            "excluded_sites": [],
            "browser_categories": {},
            "category_parents": {},
            "category_order": [],
            "browser_labels": {},
            "browser_specific_sites": {},
            "site_categories": [],
            "site_category_order_manual": False,
            "other_site_days": {},
            "passive_days": {},
            "passive_excluded": [],
            "merged_targets": {},
            "system_days": {},
            "app_limit_days": {},
            "app_limit_rolling": {},
            "app_limit_rolling_migrated": [],
            "app_limit_settings": {},
            "sessions": [],
            "open_sessions": {},
            "windows_sessions": [],
            "notification_rules": [],
            "default_limit_warning_seconds": 300,
            "computer_block": {},
        }

    def record_windows_session(self, started_at, observed_at=None):
        """Remember distinct Windows logon sessions across app restarts."""
        started_at = str(started_at)
        observed_at = str(observed_at or started_at)
        sessions = self.data.setdefault("windows_sessions", [])
        existing = next((item for item in sessions if item.get("started_at") == started_at), None)
        if existing is None:
            # An unclean shutdown leaves the last observed applications in
            # open_sessions.  They belong to the preceding Windows session,
            # so close them at its last persisted observation before the new
            # inventory is recorded.  The new logon time is only a boundary,
            # not evidence that the previous applications were still open.
            previous_ends = [
                str(item.get("last_observed_at") or item.get("ended_at") or started_at)
                for item in sessions
                if not item.get("ended_at")
                and self._session_ordered(str(item.get("started_at", started_at)), started_at)
            ]
            self.update_sessions({}, at=max(previous_ends, default=started_at))
            for item in sessions:
                if not item.get("ended_at") and self._session_ordered(str(item.get("started_at", started_at)), started_at):
                    item["ended_at"] = str(item.get("last_observed_at") or started_at)
            sessions.append({
                "started_at": started_at,
                "ended_at": None,
                "last_observed_at": observed_at,
            })
            sessions.sort(key=lambda item: str(item.get("started_at", "")), reverse=True)
            self._dirty = True
            self.save(force=True)
        elif self._session_ordered(started_at, observed_at):
            existing["last_observed_at"] = observed_at
            self._dirty = True

    def windows_sessions(self):
        return [dict(item) for item in self.data.get("windows_sessions", []) if item.get("started_at")]

    def _synthesize_legacy_daily_sessions(self):
        """Make pre-timeline daily totals selectable without inventing exact hours."""
        real_starts = [
            str(item.get("started_at", ""))
            for item in self.data.get("sessions", [])
            if item.get("started_at") and not item.get("estimated")
        ]
        real_starts.extend(
            str(item.get("started_at", ""))
            for item in self.data.get("windows_sessions", [])
            if item.get("started_at") and not item.get("estimated")
        )
        first_real_day = min((value[:10] for value in real_starts), default=date.today().isoformat())
        existing_days = {
            str(item.get("started_at", ""))[:10]
            for item in self.data.get("windows_sessions", [])
            if item.get("started_at")
        }
        changed = False
        for day in sorted(self.data.get("days", {})):
            if day >= first_real_day or day in existing_days:
                continue
            try:
                day_start = datetime.combine(
                    date.fromisoformat(day), datetime.min.time()
                ).astimezone()
            except ValueError:
                continue
            day_end = day_start + timedelta(days=1) - timedelta(seconds=1)
            self.data.setdefault("windows_sessions", []).append({
                "started_at": day_start.isoformat(timespec="seconds"),
                "ended_at": day_end.isoformat(timespec="seconds"),
                "last_observed_at": day_end.isoformat(timespec="seconds"),
                "estimated": True,
                "source": "legacy-daily-total",
            })
            for target_key, raw_seconds in self.data.get("days", {}).get(day, {}).items():
                seconds = min(86399.0, max(0.0, float(raw_seconds or 0)))
                if not seconds:
                    continue
                metadata = self.data.get("targets", {}).get(target_key, {})
                label = str(metadata.get("label") or _legacy_label(target_key))
                end = day_start + timedelta(seconds=seconds)
                kind = "web" if str(target_key).startswith("site:") else "program"
                common = {
                    "key": str(target_key), "label": label,
                    "started_at": day_start.isoformat(timespec="seconds"),
                    "ended_at": end.isoformat(timespec="seconds"),
                    "estimated": True, "source": "legacy-daily-total",
                }
                self.data.setdefault("sessions", []).extend((
                    {**common, "id": f"legacy:{day}:{target_key}", "kind": kind},
                    {**common, "id": f"active:legacy:{day}:{target_key}", "kind": "active"},
                ))
            for media_name, raw_seconds in self.data.get("passive_days", {}).get(day, {}).items():
                seconds = min(86399.0, max(0.0, float(raw_seconds or 0)))
                if not seconds:
                    continue
                self.data.setdefault("sessions", []).append({
                    "id": f"multimedia:legacy:{day}:{media_name}",
                    "kind": "multimedia", "key": f"passive:{media_name}",
                    "label": str(media_name),
                    "started_at": day_start.isoformat(timespec="seconds"),
                    "ended_at": (day_start + timedelta(seconds=seconds)).isoformat(timespec="seconds"),
                    "estimated": True, "source": "legacy-daily-total",
                })
            changed = True
        if changed:
            self.data["windows_sessions"].sort(
                key=lambda item: str(item.get("started_at", "")), reverse=True
            )
            self.data["sessions"].sort(
                key=lambda item: str(item.get("started_at", ""))
            )
        return changed

    def notification_rules(self):
        """Return only notifications explicitly configured by the user."""
        self.prune_expired_notification_rules()
        return [dict(item) for item in self.data.get("notification_rules", [])]

    @staticmethod
    def notification_rule_active(rule, now=None):
        now = now or datetime.now().astimezone()
        try:
            if rule.get("valid_from"):
                starts_at = datetime.combine(
                    date.fromisoformat(str(rule["valid_from"])),
                    datetime.strptime(str(rule.get("valid_from_time") or "00:00"), "%H:%M").time(),
                ).replace(tzinfo=now.tzinfo)
                if now < starts_at:
                    return False
            if rule.get("valid_until"):
                ends_at = datetime.combine(
                    date.fromisoformat(str(rule["valid_until"])),
                    datetime.strptime(str(rule.get("valid_until_time") or "23:59"), "%H:%M").time(),
                ).replace(tzinfo=now.tzinfo)
                if now >= ends_at:
                    return False
        except (TypeError, ValueError):
            return False
        return True

    def prune_expired_notification_rules(self, now=None):
        now = now or datetime.now().astimezone()
        rules = self.data.setdefault("notification_rules", [])
        kept = []
        for rule in rules:
            if rule.get("valid_until") and not self.notification_rule_active(rule, now):
                try:
                    end_day = date.fromisoformat(str(rule["valid_until"]))
                    end_time = datetime.strptime(str(rule.get("valid_until_time") or "23:59"), "%H:%M").time()
                    if now >= datetime.combine(end_day, end_time).replace(tzinfo=now.tzinfo):
                        continue
                except (TypeError, ValueError):
                    pass
            kept.append(rule)
        if len(kept) != len(rules):
            self.data["notification_rules"] = kept
            self._dirty = True
            self.save(force=True)
        return len(rules) - len(kept)

    def default_limit_warning_seconds(self):
        return max(1, int(self.data.get("default_limit_warning_seconds", 300)))

    def set_default_limit_warning_seconds(self, seconds):
        value = max(1, int(seconds))
        self.data["default_limit_warning_seconds"] = value
        self._dirty = True
        self.save(force=True)
        return value

    def set_notification_rule(self, rule):
        source = dict(rule or {})
        kind = str(source.get("kind", ""))
        if kind not in {
            "limited_app_start", "limit_change", "limit_warning",
            "pwa_login", "usage_threshold", "startup_reminder",
            "computer_block_warning", "computer_block_change",
        }:
            raise ValueError("Type de notification non pris en charge.")
        target_key = str(source.get("target_key", ""))
        if kind in {"limited_app_start", "limit_warning"}:
            target_key = ""
        known_limits = self.data.get("app_limit_settings", {})
        known_targets = self.data.get("targets", {})
        threshold_mode = str(source.get("threshold_mode", ""))
        if kind == "usage_threshold" and not threshold_mode:
            threshold_mode = "legacy_percent" if "threshold_percent" in source and "duration_seconds" not in source else "duration"
        if kind == "usage_threshold" and threshold_mode not in {"duration", "time", "legacy_percent"}:
            raise ValueError("Type de seuil invalide.")
        if kind == "usage_threshold" and threshold_mode in {"duration", "time"}:
            valid_target = (
                target_key == "computer:all"
                or target_key.startswith("category:") and target_key.removeprefix("category:") in self.categories()
                or target_key in known_targets
                or target_key in known_limits
            )
            if not valid_target:
                raise ValueError("Choisissez tout l’ordinateur, une catégorie ou une activité.")
        if kind == "usage_threshold" and threshold_mode == "legacy_percent" and target_key not in known_limits:
            raise ValueError("Choisissez une activité possédant une limite.")
        threshold = max(1, min(100, int(source.get("threshold_percent", 80))))
        duration_seconds = max(1, int(source.get("duration_seconds", 3600)))
        after_time = str(source.get("after_time", "")).strip()
        if kind == "usage_threshold" and threshold_mode == "time":
            try:
                datetime.strptime(after_time, "%H:%M")
            except ValueError as error:
                raise ValueError("Indiquez une heure valide.") from error
        valid_from = str(source.get("valid_from", "")).strip()
        valid_from_time = str(source.get("valid_from_time", "")).strip()
        valid_until = str(source.get("valid_until", "")).strip()
        valid_until_time = str(source.get("valid_until_time", "")).strip()
        if kind == "usage_threshold":
            if bool(valid_from) != bool(valid_from_time) or bool(valid_until) != bool(valid_until_time):
                raise ValueError("Chaque date de validité doit être accompagnée de son heure.")
            try:
                start_boundary = datetime.fromisoformat(f"{valid_from}T{valid_from_time}") if valid_from else None
                end_boundary = datetime.fromisoformat(f"{valid_until}T{valid_until_time}") if valid_until else None
            except ValueError as error:
                raise ValueError("Période de validité invalide.") from error
            if start_boundary and end_boundary and start_boundary >= end_boundary:
                raise ValueError("La fin de validité doit être après son début.")
        warning_seconds = max(1, int(source.get("warning_seconds", 300)))
        weekdays = sorted({
            int(value) for value in source.get("weekdays", [])
            if str(value).isdigit() and 0 <= int(value) <= 6
        })
        if kind == "startup_reminder" and not weekdays:
            raise ValueError("Choisissez au moins un jour pour le rappel au démarrage.")
        rule_id = str(source.get("id", ""))
        if rule_id.startswith("builtin:"):
            raise ValueError("Identifiant de notification réservé.")
        normalized = {
            "id": rule_id or uuid.uuid4().hex,
            "kind": kind,
            "label": str(source.get("label", "")).strip() or (
                "Démarrage d’une activité limitée" if kind == "limited_app_start"
                else "Ajout ou modification d’une limite" if kind == "limit_change"
                else "Préavis avant une limite" if kind == "limit_warning"
                else "Préavis avant une limitation de l’ordinateur" if kind == "computer_block_warning"
                else "Modification d’une limitation de l’ordinateur" if kind == "computer_block_change"
                else "Connexion à la PWA" if kind == "pwa_login"
                else f"Seuil de durée atteint" if kind == "usage_threshold" and threshold_mode == "duration"
                else f"Horaire atteint" if kind == "usage_threshold" and threshold_mode == "time"
                else f"Dépassement du seuil de {threshold} %" if kind == "usage_threshold"
                else "Rappel au démarrage"
            ),
            "description": str(source.get("description", "")).strip(),
            "target_key": target_key,
            "threshold_mode": threshold_mode,
            "threshold_percent": threshold,
            "duration_seconds": duration_seconds,
            "after_time": after_time,
            "valid_from": valid_from,
            "valid_from_time": valid_from_time,
            "valid_until": valid_until,
            "valid_until_time": valid_until_time,
            "warning_seconds": warning_seconds,
            "weekdays": weekdays,
            "enabled": bool(source.get("enabled", True)),
        }
        rules = self.data.setdefault("notification_rules", [])
        for index, existing in enumerate(rules):
            if existing.get("id") == normalized["id"]:
                rules[index] = normalized
                break
        else:
            rules.append(normalized)
        self._dirty = True
        self.save(force=True)
        return dict(normalized)

    def remove_notification_rule(self, rule_id):
        rule_id = str(rule_id)
        if rule_id.startswith("builtin:"):
            raise ValueError("Identifiant de notification réservé.")
        rules = self.data.setdefault("notification_rules", [])
        kept = [item for item in rules if item.get("id") != rule_id]
        if len(kept) == len(rules):
            raise ValueError("Règle de notification introuvable.")
        self.data["notification_rules"] = kept
        self._dirty = True
        self.save(force=True)

    def set_computer_block(
        self, mode, actor="", *, day=None, duration_seconds=None,
        delay_seconds=0, start_time=None, end_time=None,
        valid_from=None, valid_from_time=None,
        valid_until=None, valid_until_time=None, now=None,
    ):
        now = now or datetime.now().astimezone()
        if mode == "today":
            starts_at = now
            ends_at = datetime.combine(now.date() + timedelta(days=1), datetime.min.time()).astimezone()
        elif mode == "24h":
            starts_at = now
            ends_at = now + timedelta(hours=24)
        elif mode == "day":
            try:
                selected_day = date.fromisoformat(str(day))
            except (TypeError, ValueError):
                raise ValueError("Jour de blocage invalide.")
            if selected_day < now.date():
                raise ValueError("Le jour choisi est déjà passé.")
            ends_at = datetime.combine(
                selected_day + timedelta(days=1), datetime.min.time()
            ).astimezone()
            if start_time:
                try:
                    selected_time = datetime.strptime(
                        str(start_time), "%H:%M"
                    ).time()
                except (TypeError, ValueError):
                    raise ValueError("Heure de début invalide.")
                requested_start = datetime.combine(
                    selected_day, selected_time
                ).astimezone()
                starts_at = max(now, requested_start)
            else:
                # Compatibilité avec les anciennes commandes déjà en attente.
                try:
                    delay_seconds = max(0, int(delay_seconds or 0))
                except (TypeError, ValueError):
                    raise ValueError("Délai de blocage invalide.")
                starts_at = (
                    now + timedelta(seconds=delay_seconds)
                    if selected_day == now.date()
                    else datetime.combine(selected_day, datetime.min.time()).astimezone()
                )
            if starts_at >= ends_at:
                raise ValueError("Le délai dépasse la fin du jour choisi.")
        elif mode == "schedule":
            try:
                selected_start = datetime.strptime(str(start_time), "%H:%M").time()
                selected_end = datetime.strptime(str(end_time), "%H:%M").time()
            except (TypeError, ValueError):
                raise ValueError("Heures de début et de fin invalides.")
            if selected_end == selected_start:
                raise ValueError("Les heures de début et de fin doivent être différentes.")
            crosses_midnight = selected_end < selected_start
            try:
                first_day = date.fromisoformat(str(valid_from)) if valid_from else None
                last_day = date.fromisoformat(str(valid_until)) if valid_until else None
                first_boundary = (
                    datetime.combine(
                        first_day,
                        datetime.strptime(str(valid_from_time), "%H:%M").time(),
                    ).astimezone()
                    if valid_from else None
                )
                last_boundary = (
                    datetime.combine(
                        last_day,
                        datetime.strptime(str(valid_until_time), "%H:%M").time(),
                    ).astimezone()
                    if valid_until else None
                )
            except (TypeError, ValueError):
                raise ValueError("Période de validité invalide.")
            if bool(valid_from) != bool(valid_from_time):
                raise ValueError("La date de début doit être accompagnée de son heure.")
            if bool(valid_until) != bool(valid_until_time):
                raise ValueError("La date de fin doit être accompagnée de son heure.")
            if first_boundary and last_boundary and last_boundary <= first_boundary:
                raise ValueError("La fin de validité doit être après son début.")
            occurrence_day = now.date()
            if (
                crosses_midnight
                and now.time().replace(tzinfo=None) < selected_end
            ):
                occurrence_day -= timedelta(days=1)
            if first_day:
                occurrence_day = max(occurrence_day, first_day)
            while True:
                requested_start = datetime.combine(
                    occurrence_day, selected_start
                ).astimezone()
                requested_end = datetime.combine(
                    occurrence_day + timedelta(days=1) if crosses_midnight else occurrence_day,
                    selected_end,
                ).astimezone()
                starts_at = max(
                    requested_start, now,
                    first_boundary or requested_start,
                )
                ends_at = min(requested_end, last_boundary or requested_end)
                if starts_at < ends_at:
                    break
                occurrence_day += timedelta(days=1)
                if last_day and occurrence_day > last_day:
                    raise ValueError("La période de validité est déjà terminée.")
        elif mode == "range":
            try:
                selected_start = datetime.strptime(
                    str(start_time), "%H:%M"
                ).time()
                selected_end = datetime.strptime(
                    str(end_time), "%H:%M"
                ).time()
            except (TypeError, ValueError):
                raise ValueError("Heures de début et de fin invalides.")
            requested_start = datetime.combine(
                now.date(), selected_start
            ).astimezone()
            if selected_end == selected_start:
                raise ValueError("Les heures de début et de fin doivent être différentes.")
            end_day = now.date() + (
                timedelta(days=1) if selected_end < selected_start else timedelta()
            )
            ends_at = datetime.combine(end_day, selected_end).astimezone()
            starts_at = max(now, requested_start)
            if starts_at >= ends_at:
                raise ValueError("L’heure de fin est déjà passée.")
        elif mode == "duration":
            # Compatibilité avec les commandes créées par les anciennes versions.
            try:
                duration_seconds = int(duration_seconds)
            except (TypeError, ValueError):
                raise ValueError("Durée de blocage invalide.")
            if duration_seconds < 60:
                raise ValueError("La durée doit être d’au moins une minute.")
            if start_time:
                try:
                    selected_time = datetime.strptime(
                        str(start_time), "%H:%M"
                    ).time()
                except (TypeError, ValueError):
                    raise ValueError("Heure de début invalide.")
                requested_start = datetime.combine(
                    now.date(), selected_time
                ).astimezone()
                starts_at = max(now, requested_start)
            else:
                # Compatibilité avec les anciennes commandes déjà en attente.
                try:
                    delay_seconds = max(0, int(delay_seconds or 0))
                except (TypeError, ValueError):
                    raise ValueError("Délai de blocage invalide.")
                starts_at = now + timedelta(seconds=delay_seconds)
            ends_at = starts_at + timedelta(seconds=duration_seconds)
        else:
            raise ValueError("Durée de blocage de l’ordinateur invalide.")
        self.data["computer_block"] = {
            "enabled": True, "mode": mode,
            "started_at": starts_at.isoformat(timespec="seconds"),
            "ends_at": ends_at.isoformat(timespec="seconds"),
            "actor": str(actor or "Utilisateur local"),
        }
        if mode == "schedule":
            self.data["computer_block"].update({
                "daily_start": str(start_time),
                "daily_end": str(end_time),
                "valid_from": str(valid_from or ""),
                "valid_from_time": str(valid_from_time or ""),
                "valid_until": str(valid_until or ""),
                "valid_until_time": str(valid_until_time or ""),
            })
        self._dirty = True
        self.save(force=True)
        return dict(self.data["computer_block"])

    def clear_computer_block(self):
        self.data["computer_block"] = {}
        self._dirty = True
        self.save(force=True)

    def set_computer_block_enabled(self, enabled):
        block = self.data.get("computer_block")
        if not isinstance(block, dict) or not block:
            raise ValueError("Limitation de l’ordinateur introuvable.")
        block["enabled"] = bool(enabled)
        self._dirty = True
        self.save(force=True)
        return dict(block)

    @staticmethod
    def _repair_sessions(data):
        """Discard malformed session records so history always has valid ranges."""
        complete = []
        for session in data.get("sessions", []):
            if not isinstance(session, dict):
                continue
            start, end = session.get("started_at"), session.get("ended_at")
            if not isinstance(start, str) or not isinstance(end, str) or not AppUsageStore._session_ordered(start, end):
                continue
            complete.append(session)
        data["sessions"] = complete
        data["open_sessions"] = {
            key: session for key, session in data.get("open_sessions", {}).items()
            if isinstance(key, str) and isinstance(session, dict)
            and isinstance(session.get("started_at"), str)
        }

    @staticmethod
    def _repair_windows_sessions(data):
        """Replace legacy next-logon boundaries with the last known activity."""
        windows = [
            item for item in data.get("windows_sessions", [])
            if isinstance(item, dict) and isinstance(item.get("started_at"), str)
        ]
        ordered = sorted(windows, key=lambda item: item["started_at"])
        activity = data.get("sessions", [])
        for index, item in enumerate(ordered[:-1]):
            boundary = ordered[index + 1]["started_at"]
            if item.get("last_observed_at") or item.get("ended_at") != boundary:
                continue
            candidates = []
            for session in activity:
                if session.get("kind") != "active":
                    continue
                opened = session.get("started_at")
                if not isinstance(opened, str) or opened < item["started_at"] or opened >= boundary:
                    continue
                candidates.append(opened)
                closed = session.get("ended_at")
                if isinstance(closed, str) and closed < boundary:
                    candidates.append(closed)
            if candidates:
                item["ended_at"] = max(candidates)
                item["last_observed_at"] = item["ended_at"]
        data["windows_sessions"] = windows

    @staticmethod
    def _session_ordered(start, end):
        try:
            start_at = datetime.fromisoformat(start)
            end_at = datetime.fromisoformat(end)
            if start_at.tzinfo is None:
                start_at = start_at.replace(tzinfo=timezone.utc)
            if end_at.tzinfo is None:
                end_at = end_at.replace(tzinfo=timezone.utc)
            return end_at.astimezone(timezone.utc) >= start_at.astimezone(timezone.utc)
        except (TypeError, ValueError):
            return False

    def _migrate_legacy_targets(self):
        """Merge pre-category app keys without losing any recorded seconds."""
        changed = False
        for day, apps in self.data["days"].items():
            for key, seconds in list(apps.items()):
                canonical = _canonical_target_key(key)
                if canonical == key:
                    continue
                apps[canonical] = round(float(apps.get(canonical, 0.0)) + float(seconds), 3)
                del apps[key]
                self.data["targets"].setdefault(canonical, {"label": str(key)})
                changed = True
            # A Chrome PWA can expose a long page subtitle at its first tick
            # (for example "ChatGPT: Chat, Work..."). Keep that time under
            # the stable application entry used by subsequent ticks.
            for key, seconds in list(apps.items()):
                if not key.startswith("app:chatgpt:"):
                    continue
                stable_key = "app:chatgpt"
                apps[stable_key] = round(
                    float(apps.get(stable_key, 0.0)) + float(seconds), 3
                )
                del apps[key]
                self.data["targets"].setdefault(stable_key, {})["label"] = "ChatGPT"
                changed = True
        # Earlier builds stored every browser host as its own entry. Keep only
        # YouTube and sites explicitly requested by the user separate.
        for apps in self.data["days"].values():
            for key, seconds in list(apps.items()):
                browser, host = _browser_site_parts(key)
                if not browser or not host or self.is_browser_site_specific(browser, host):
                    continue
                grouped_key = f"site:{browser}:other-sites"
                apps[grouped_key] = round(
                    float(apps.get(grouped_key, 0.0)) + float(seconds), 3
                )
                self._record_other_site(browser, day, host, seconds)
                del apps[key]
                self.data["targets"].pop(key, None)
                self.data["targets"].setdefault(grouped_key, {})["label"] = "Autres sites"
                changed = True
        # A local server is not web browsing. Promote it out of "Autres
        # sites" (also for activity recorded before this distinction existed)
        # and treat it like an unclassified application.
        for browser, by_day in self.data.get("other_site_days", {}).items():
            for hosts in by_day.values():
                for host in list(hosts):
                    if _local_site_category(host):
                        self.make_browser_site_specific(browser, host, save=False)
                        changed = True
        excluded = []
        for key in self.data["excluded"]:
            canonical = _canonical_target_key(key)
            if canonical not in excluded:
                excluded.append(canonical)
            changed |= canonical != key
        self.data["excluded"] = excluded
        # Earlier builds represented a browser group as "Internet / Brave".
        # Brave is an application group, not a second user category.
        for metadata in self.data["targets"].values():
            if metadata.get("category") == "Autres":
                metadata["category"] = "Applications non classées"
                changed = True
            category = str(metadata.get("category", ""))
            if category.lower().endswith(" / brave"):
                metadata["category"] = category.rsplit(" / ", 1)[0]
                changed = True
        # A category assigned to Brave applies to every Brave site, including
        # sites discovered after the category was created.
        browser_categories = self.data.setdefault("browser_categories", {})
        for browser in _browser_apps():
            app_key = f"app:{Path(browser).stem.lower()}"
            category = self.data["targets"].get(app_key, {}).get("category")
            if category and browser_categories.get(browser) != category:
                browser_categories[browser] = category
                changed = True
        general_categories = set(self.data.get("category_parents", {}))
        general_categories.update(self.data.get("category_parents", {}).values())
        general_categories.update(
            str(metadata.get("category", "")).strip()
            for target_key, metadata in self.data["targets"].items()
            if not _browser_for_target(target_key)
            or metadata.get("category_scope") == "site"
        )
        general_categories.discard("")
        general_categories.discard("__root__")
        promoted_site_categories = set()
        for key, metadata in self.data["targets"].items():
            browser = _browser_for_target(key)
            category = browser_categories.get(browser) if browser else None
            _, host = _browser_site_parts(key)
            local_category = _local_site_category(host)
            site_category = str(metadata.get("site_category", "")).strip()
            if browser and host and site_category in general_categories:
                # A site dropped onto an existing general category belongs to
                # that category directly. Older builds kept the same name as
                # an Internet sub-category, which duplicated the category.
                metadata.pop("root", None)
                metadata.pop("site_category", None)
                metadata["category"] = site_category
                metadata["category_scope"] = "site"
                if not str(metadata.get("label", "")).strip():
                    metadata["label"] = host
                promoted_site_categories.add(site_category)
                changed = True
                continue
            if _is_youtube_host(host):
                # YouTube is tracked as a distinct activity, so a category
                # selected for it must replace the browser category instead
                # of becoming an "Internet" sub-category.  Hoist choices
                # saved by older builds to their intended top-level scope.
                site_category = metadata.pop("site_category", None)
                if site_category:
                    changed = True
                    if metadata.get("category") != site_category:
                        metadata["category"] = site_category
                if metadata.get("category_scope") != "site":
                    metadata["category_scope"] = "site"
                    changed = True
                continue
            if local_category:
                known_label = KNOWN_LOCAL_SITE_LABELS.get(host)
                if known_label and metadata.get("label") != known_label:
                    metadata["label"] = known_label
                    changed = True
                # A local site starts in the configured default category, but
                # it is still a normal user activity: never overwrite a
                # category chosen manually (for example, "Programmation").
                if not metadata.get("category"):
                    metadata["category"] = local_category
                    changed = True
                if metadata.get("category_scope") != "site":
                    metadata["category_scope"] = "site"
                    changed = True
                continue
            if metadata.get("category_scope") == "site":
                continue
            # A category chosen for an individual browser site is a child of
            # that browser, never a replacement for the browser's root group.
            if (
                browser
                and category
                and metadata.get("category")
                and metadata.get("category") != category
            ):
                metadata.setdefault("site_category", metadata["category"])
                metadata["category"] = category
                changed = True
            if category and metadata.get("category") != category:
                metadata["category"] = category
                changed = True
        for session in (
            list(self.data.get("sessions", []))
            + list(self.data.get("open_sessions", {}).values())
        ):
            _, host = _browser_site_parts(session.get("key", ""))
            known_label = KNOWN_LOCAL_SITE_LABELS.get(host)
            if known_label and session.get("label") != known_label:
                session["label"] = known_label
                changed = True
        saved_site_categories = self.data.setdefault("site_categories", [])
        for category in promoted_site_categories:
            if not any(
                metadata.get("site_category") == category
                for metadata in self.data["targets"].values()
            ):
                saved_site_categories[:] = [
                    saved for saved in saved_site_categories if saved != category
                ]
        for metadata in self.data["targets"].values():
            category = str(metadata.get("site_category", "")).strip()
            if category and category not in saved_site_categories:
                saved_site_categories.append(category)
                changed = True
        for media in self.data.get("passive_days", {}).values():
            # Old builds could only identify Brave's media session. The
            # browser extension now resolves this case as YouTube instead.
            if "Brave" in media:
                media["YouTube"] = round(
                    float(media.get("YouTube", 0.0)) + float(media.pop("Brave")), 3
                )
                changed = True
        return changed

    def target_for_context(self, context):
        app_name = _display_app_name(context.app_name, context.window_title)
        executable = Path(str(context.app_name)).name.lower()
        host = _site_host(context.url)
        browser_apps = _browser_apps()
        if app_name and executable in browser_apps and host:
            site_key = host if self.is_browser_site_specific(executable, host) else "other-sites"
            local_category = _local_site_category(host)
            target = UsageTarget(
                key=f"site:{executable}:{site_key}",
                label=(KNOWN_LOCAL_SITE_LABELS.get(host, host)
                       if site_key == host else "Autres sites"),
                category=(
                    local_category
                    or self.data["browser_categories"].get(
                        executable, _browser_label(executable)
                    )
                ),
                detail_host=host if site_key == "other-sites" else "",
            )
            return self._resolved_target(target)
        # A browser without an identifiable site is deliberately not counted:
        # there is no meaningful activity to attribute it to.
        if executable in browser_apps:
            return None
        target = UsageTarget(
            key=f"app:{app_name.lower()}",
            label=app_name,
            category=(
                self.data["browser_categories"].get(executable, _browser_label(executable))
                if executable in browser_apps
                else ""
            ),
        )
        return self._resolved_target(target)

    def is_browser_site_specific(self, browser, host):
        host = str(host).lower()
        if _is_youtube_host(host) or _local_site_category(host):
            return True
        sites = self.data.get("browser_specific_sites", {}).get(str(browser).lower(), [])
        return host in sites

    def make_browser_site_specific(self, browser, host, category="", save=True):
        browser = str(browser).lower()
        host = _site_host(host) or str(host).lower().strip()
        if not host:
            return
        selected_category = str(category).strip() or _local_site_category(host)
        sites = self.data.setdefault("browser_specific_sites", {}).setdefault(browser, [])
        changed = False
        if host not in sites:
            sites.append(host)
            changed = True
            details = self.data.get("other_site_days", {}).get(browser, {})
            for day, hosts in details.items():
                seconds = float(hosts.pop(host, 0.0))
                if not seconds:
                    continue
                apps = self.data["days"].setdefault(day, {})
                grouped_key = f"site:{browser}:other-sites"
                apps[grouped_key] = round(float(apps.get(grouped_key, 0.0)) - seconds, 3)
                if apps[grouped_key] <= 0:
                    apps.pop(grouped_key, None)
                specific_key = f"site:{browser}:{host}"
                apps[specific_key] = round(float(apps.get(specific_key, 0.0)) + seconds, 3)
                metadata = self.data["targets"].setdefault(specific_key, {})
                metadata["label"] = host
                # A specific site remains part of its browser's category.
                # Without this, it falls back to the generic "Autres" group.
                browser_category = self.data.get("browser_categories", {}).get(browser)
                if browser_category:
                    metadata["category"] = browser_category
        if selected_category:
            metadata = self.data["targets"].setdefault(f"site:{browser}:{host}", {})
            metadata["label"] = host
            metadata["category"] = selected_category
            metadata["category_scope"] = "site"
            changed = True
        if changed:
            self._dirty = True
        if changed and save:
            self.save(force=True)

    def move_browser_site_to_category(self, browser, host, category):
        """Promote one browser host and place it outside the browser group."""
        self.make_browser_site_specific(browser, host, category=category)

    def other_sites(self, browser, when=None):
        """Return unclassified browser-site totals for one day or all time."""
        browser = str(browser).lower()
        all_days = self.data.get("other_site_days", {}).get(browser, {})
        totals = {
            host: 0.0
            for hosts in all_days.values()
            for host in hosts
            if not self.is_browser_site_excluded(browser, host)
        }
        days = all_days
        if when is not None:
            days = {when.isoformat(): days.get(when.isoformat(), {})}
        for hosts in days.values():
            for host, seconds in hosts.items():
                if self.is_browser_site_excluded(browser, host):
                    continue
                totals[host] = totals.get(host, 0.0) + float(seconds)
        return totals

    def _record_other_site(self, browser, day, host, seconds):
        hosts = (
            self.data.setdefault("other_site_days", {})
            .setdefault(browser, {})
            .setdefault(day, {})
        )
        hosts[host] = round(float(hosts.get(host, 0.0)) + float(seconds), 3)

    def _resolved_target(self, target):
        key = target.key
        merged_targets = self.data.get("merged_targets", {})
        seen = set()
        while key in merged_targets and key not in seen:
            seen.add(key)
            key = merged_targets[key]
        metadata = self.data["targets"].get(key, {})
        return UsageTarget(
            key=key,
            label=metadata.get(
                "label", target.label if key == target.key else _legacy_label(key)
            ),
            category=metadata.get("category", target.category),
            detail_host=target.detail_host if key == target.key else "",
        )

    def add_seconds(self, target, seconds, when=None):
        if not target or not target.key or seconds <= 0 or self.is_excluded(target.key):
            return
        if target.detail_host and self.is_browser_site_excluded(
            _other_sites_browser(target.key), target.detail_host
        ):
            return
        day = (when or date.today()).isoformat()
        apps = self.data["days"].setdefault(day, {})
        apps[target.key] = round(float(apps.get(target.key, 0.0)) + seconds, 3)
        if target.detail_host:
            self._record_other_site(_other_sites_browser(target.key), day, target.detail_host, seconds)
        metadata = self.data["targets"].setdefault(target.key, {})
        metadata.setdefault("label", target.label)
        if target.category and not metadata.get("category"):
            metadata["category"] = target.category
        self._dirty = True

    def add_passive_seconds(self, media_name, seconds, when=None):
        if not media_name or seconds <= 0 or self.is_passive_excluded(media_name):
            return
        day = (when or date.today()).isoformat()
        media = self.data["passive_days"].setdefault(day, {})
        media[media_name] = round(float(media.get(media_name, 0.0)) + seconds, 3)
        self._dirty = True

    def is_passive_excluded(self, media_name):
        return str(media_name) in self.data.get("passive_excluded", [])

    def exclude_passive(self, media_name):
        media_name = str(media_name)
        if media_name and media_name not in self.data["passive_excluded"]:
            self.data["passive_excluded"].append(media_name)
            self._dirty = True
            self.save(force=True)

    def add_system_seconds(self, seconds, foreground=False, passive=False, when=None):
        if seconds <= 0:
            return
        day = (when or date.today()).isoformat()
        totals = self.data["system_days"].setdefault(
            day, {"on": 0.0, "foreground": 0.0, "with_passive": 0.0}
        )
        totals["on"] = round(float(totals.get("on", 0.0)) + seconds, 3)
        if foreground:
            totals["foreground"] = round(
                float(totals.get("foreground", 0.0)) + seconds, 3
            )
        if foreground or passive:
            totals["with_passive"] = round(
                float(totals.get("with_passive", 0.0)) + seconds, 3
            )
        self._dirty = True

    def is_excluded(self, key):
        return key in self.data["excluded"]

    def exclude(self, key):
        if key not in self.data["excluded"]:
            self.data["excluded"].append(key)
        # Exclusions apply from now on. Keep the raw history intact so a
        # category/exclusion change can never erase already collected data.
        self._dirty = True

    def remember_target(self, target):
        """Make an observed target available to PWA actions before it accrues usage."""
        if not target or not target.key:
            return
        metadata = self.data["targets"].setdefault(target.key, {})
        metadata.setdefault("label", target.label)
        if target.category and not metadata.get("category"):
            metadata["category"] = target.category
        self._dirty = True

    def update_sessions(self, observed, at=None):
        """Synchronize open programs/media and foreground activity sessions."""
        timestamp = at or datetime.now().astimezone().isoformat(timespec="seconds")
        for windows_session in self.data.setdefault("windows_sessions", []):
            if not windows_session.get("ended_at") and self._session_ordered(
                str(windows_session.get("started_at", timestamp)), timestamp
            ):
                windows_session["last_observed_at"] = timestamp
                self._dirty = True
                break
        observed = {str(key): dict(value) for key, value in dict(observed).items()}
        open_sessions = self.data.setdefault("open_sessions", {})
        completed = self.data.setdefault("sessions", [])
        changed = False
        for key, session in list(open_sessions.items()):
            if key in observed:
                continue
            # Never write a closing timestamp earlier than its opening timestamp.
            started_at = str(session.get("started_at", timestamp))
            ended_at = timestamp if self._session_ordered(started_at, timestamp) else started_at
            completed.append({**session, "ended_at": ended_at})
            del open_sessions[key]
            changed = True
        for key, details in observed.items():
            if key in open_sessions:
                session = open_sessions[key]
                for field in ("key", "label", "source"):
                    value = str(details.get(field, session.get(field, "")))
                    if value and session.get(field) != value:
                        session[field] = value
                        changed = True
                continue
            open_sessions[key] = {
                "id": key, "kind": str(details.get("kind", "program")),
                "key": str(details.get("key", key)),
                "label": str(details.get("label", key)), "started_at": timestamp,
                "started_before_tracking": bool(details.get("started_before_tracking", False)),
                "source": str(details.get("source", "monitor")),
            }
            changed = True
        if changed:
            self._dirty = True

    def reassign_program_sessions(self, session_id, target_key, label, since=None):
        """Fuse a technical browser row into its resolved installed application."""
        changed = False
        candidates = list(self.data.setdefault("sessions", []))
        candidates.extend(self.data.setdefault("open_sessions", {}).values())
        for session in candidates:
            if session.get("id") != session_id or session.get("kind") != "program":
                continue
            if since and str(session.get("started_at", "")) < str(since):
                continue
            if session.get("key") == target_key and session.get("label") == label:
                continue
            session["key"] = target_key
            session["label"] = label
            changed = True
        if changed:
            self._dirty = True

    def sessions_for_period(self, start=None, end=None):
        """Return sessions overlapping an inclusive date range, including open ones."""
        start_text = start.isoformat() if start else ""
        end_text = end.isoformat() + "T23:59:59" if end else ""
        sessions = list(self.data.get("sessions", [])) + [
            {**session, "ended_at": None}
            for session in self.data.get("open_sessions", {}).values()
        ]
        result = []
        for session in sessions:
            opened, closed = str(session.get("started_at", "")), session.get("ended_at")
            if not opened or (start_text and str(closed or opened) < start_text) or (end_text and opened > end_text):
                continue
            result.append(dict(session))
        return sorted(result, key=lambda item: item["started_at"], reverse=True)

    @staticmethod
    def _limit_moment(when=None):
        if isinstance(when, datetime):
            return when.astimezone() if when.tzinfo else when.astimezone()
        if isinstance(when, date) and when != date.today():
            return datetime.combine(when, datetime.max.time()).astimezone()
        return datetime.now().astimezone()

    def _rolling_limit_state(self, target_key, when=None):
        moment = self._limit_moment(when)
        rolling = self.data.setdefault("app_limit_rolling", {})
        migrated = self.data.setdefault("app_limit_rolling_migrated", [])
        if target_key not in rolling:
            state = {"buckets": {}, "extension_granted_at": None}
            if target_key not in migrated:
                legacy = self.data.setdefault("app_limit_days", {}).get(moment.date().isoformat(), {}).get(target_key, {})
                if float(legacy.get("seconds", 0.0)) > 0:
                    bucket = moment.replace(second=0, microsecond=0).isoformat(timespec="minutes")
                    state["buckets"][bucket] = float(legacy["seconds"])
                if legacy.get("extension_used"):
                    state["extension_granted_at"] = moment.isoformat(timespec="seconds")
                migrated.append(target_key)
            rolling[target_key] = state
        state = rolling[target_key]
        cutoff = datetime.combine(moment.date(), datetime.min.time()).replace(
            tzinfo=moment.tzinfo
        )
        buckets = state.setdefault("buckets", {})
        expired = [stamp for stamp in buckets if datetime.fromisoformat(stamp) < cutoff]
        for stamp in expired:
            buckets.pop(stamp, None)
        granted = state.get("extension_granted_at")
        extension_used = bool(granted and datetime.fromisoformat(granted) >= cutoff)
        if granted and not extension_used:
            state["extension_granted_at"] = None
        if expired or (granted and not extension_used):
            self._dirty = True
        return state, moment, extension_used

    def app_limit_state_for_day(self, target_key, when=None):
        state, _, extension_used = self._rolling_limit_state(target_key, when)
        return {"seconds": round(sum(float(value) for value in state["buckets"].values()), 3), "extension_used": extension_used}

    def app_limit_settings(self, target_key, defaults=None):
        defaults = dict(defaults or {})
        saved = self.data.setdefault("app_limit_settings", {}).get(target_key, {})
        valid_from = str(saved.get("valid_from", defaults.get("valid_from", "")))
        valid_until = str(saved.get("valid_until", defaults.get("valid_until", "")))
        return {
            "enabled": bool(saved.get("enabled", defaults.get("enabled", True))),
            "block_during_validity": bool(saved.get("block_during_validity", defaults.get("block_during_validity", False))),
            "limit_seconds": int(saved.get("limit_seconds", defaults.get("limit_seconds", 60))),
            "extension_seconds": int(saved.get("extension_seconds", defaults.get("extension_seconds", 60))),
            "warning_seconds": int(saved.get("warning_seconds", defaults.get("warning_seconds", 15))),
            "blocked_after": str(saved.get("blocked_after", defaults.get("blocked_after", ""))),
            "schedule_date": str(saved.get("schedule_date", defaults.get("schedule_date", ""))),
            "valid_from": valid_from,
            "valid_from_time": str(saved.get("valid_from_time", defaults.get("valid_from_time", "00:00" if valid_from else ""))),
            "valid_until": valid_until,
            "valid_until_time": str(saved.get("valid_until_time", defaults.get("valid_until_time", "23:59" if valid_until else ""))),
            "schedule_start": str(saved.get("schedule_start", defaults.get("schedule_start", ""))),
            "schedule_end": str(saved.get("schedule_end", defaults.get("schedule_end", ""))),
        }

    def set_app_limit_settings(self, target_key, settings):
        normalized = {
            "enabled": bool(settings.get("enabled", True)),
            "block_during_validity": bool(settings.get("block_during_validity", False)),
            "limit_seconds": max(1, int(settings.get("limit_seconds", 60))),
            "extension_seconds": max(0, int(settings.get("extension_seconds", 60))),
            "warning_seconds": max(1, int(settings.get("warning_seconds", 15))),
            "blocked_after": str(settings.get("blocked_after", "")).strip(),
            "schedule_date": str(settings.get("schedule_date", "")).strip(),
            "valid_from": str(settings.get("valid_from", "")).strip(),
            "valid_from_time": str(settings.get("valid_from_time", "")).strip(),
            "valid_until": str(settings.get("valid_until", "")).strip(),
            "valid_until_time": str(settings.get("valid_until_time", "")).strip(),
            "schedule_start": str(settings.get("schedule_start", "")).strip(),
            "schedule_end": str(settings.get("schedule_end", "")).strip(),
        }
        if normalized["blocked_after"]:
            try:
                datetime.strptime(normalized["blocked_after"], "%H:%M")
            except ValueError:
                raise ValueError("Heure de fin invalide.")
        if normalized["schedule_date"]:
            try:
                date.fromisoformat(normalized["schedule_date"])
            except ValueError:
                raise ValueError("Jour précis invalide.")
        for field in ("valid_from", "valid_until"):
            if normalized[field]:
                try:
                    date.fromisoformat(normalized[field])
                except ValueError:
                    raise ValueError("Période de validité invalide.")
        for field in ("valid_from_time", "valid_until_time"):
            if normalized[field]:
                try:
                    datetime.strptime(normalized[field], "%H:%M")
                except ValueError:
                    raise ValueError("Heure de validité invalide.")
        if bool(normalized["valid_from"]) != bool(normalized["valid_from_time"]):
            raise ValueError("La date de début doit être accompagnée de son heure.")
        if bool(normalized["valid_until"]) != bool(normalized["valid_until_time"]):
            raise ValueError("La date de fin doit être accompagnée de son heure.")
        if (
            normalized["valid_from"] and normalized["valid_until"]
            and (
                normalized["valid_from"], normalized["valid_from_time"]
            ) >= (
                normalized["valid_until"], normalized["valid_until_time"]
            )
        ):
            raise ValueError("La fin de validité doit être après son début.")
        for field in ("schedule_start", "schedule_end"):
            if normalized[field]:
                try:
                    datetime.strptime(normalized[field], "%H:%M")
                except ValueError:
                    raise ValueError("Plage horaire invalide.")
        if bool(normalized["schedule_start"]) != bool(normalized["schedule_end"]):
            raise ValueError("Indiquez le début et la fin de la plage horaire.")
        if (
            normalized["schedule_start"]
            and normalized["schedule_start"] == normalized["schedule_end"]
        ):
            raise ValueError("Les heures de début et de fin doivent être différentes.")
        if normalized["block_during_validity"]:
            if not normalized["valid_from"] and not normalized["valid_until"]:
                raise ValueError("Un blocage par période exige au moins une borne datée.")
            normalized["extension_seconds"] = 0
            normalized["blocked_after"] = ""
            normalized["schedule_start"] = ""
            normalized["schedule_end"] = ""
        normalized["warning_seconds"] = min(
            normalized["warning_seconds"], normalized["limit_seconds"]
        )
        self.data.setdefault("app_limit_settings", {})[target_key] = normalized
        self._dirty = True
        self.save(force=True)
        return normalized

    def remove_app_limit_settings(self, target_key):
        self.data.setdefault("app_limit_settings", {}).pop(target_key, None)
        for states in self.data.setdefault("app_limit_days", {}).values():
            states.pop(target_key, None)
        self.data.setdefault("app_limit_rolling", {}).pop(target_key, None)
        if target_key in self.data.setdefault("app_limit_rolling_migrated", []):
            self.data["app_limit_rolling_migrated"].remove(target_key)
        self._dirty = True
        self.save(force=True)

    def reset_app_limit_state(self, target_key, when=None):
        moment = self._limit_moment(when)
        self.data.setdefault("app_limit_rolling", {})[target_key] = {
            "buckets": {}, "extension_granted_at": None,
            "usage_seeded_at": moment.isoformat(timespec="seconds"),
            "usage_seed_version": 4,
        }
        migrated = self.data.setdefault("app_limit_rolling_migrated", [])
        if target_key not in migrated:
            migrated.append(target_key)
        self._dirty = True
        self.save(force=True)

    def prepare_app_limit(self, target_key, limit_seconds, extension_seconds, when=None):
        """Initialize a limit from activity already measured in its rolling window."""
        state, moment, _ = self._rolling_limit_state(target_key, when)
        if int(state.get("usage_seed_version", 0)) >= 4:
            return
        seed_start = datetime.combine(moment.date(), datetime.min.time()).replace(
            tzinfo=moment.tzinfo
        )
        measured = self._daily_usage_for_limit(target_key, moment.date())
        state["buckets"] = (
            {seed_start.isoformat(timespec="minutes"): measured}
            if measured > 0 else {}
        )
        state["usage_seeded_at"] = moment.isoformat(timespec="seconds")
        state["usage_seed_version"] = 4
        self._dirty = True
        self.save(force=True)

    def _daily_usage_for_limit(self, target_key, day):
        """Return the authoritative active total for one target or category."""
        return round(sum(
            float(seconds or 0)
            for activity_key, seconds in self.data.get("days", {}).get(
                day.isoformat(), {}
            ).items()
            if self._activity_matches_limit(str(activity_key), target_key)
        ), 3)

    def _activity_matches_limit(self, activity_key, target_key):
        if activity_key == target_key:
            return True
        if not str(target_key).startswith("category:"):
            return False
        wanted = str(target_key).removeprefix("category:")
        metadata = self.data.get("targets", {}).get(activity_key, {})
        categories = {
            str(metadata.get("category", "") or "").strip(),
            str(metadata.get("site_category", "") or "").strip(),
        }
        return any(
            wanted in self.category_lineage(category)
            for category in categories if category
        )

    def add_app_limit_seconds(self, target_key, seconds, when=None):
        if seconds <= 0:
            return self.app_limit_state_for_day(target_key, when)
        state, moment, _ = self._rolling_limit_state(target_key, when)
        bucket = moment.replace(second=0, microsecond=0).isoformat(timespec="minutes")
        state["buckets"][bucket] = round(float(state["buckets"].get(bucket, 0.0)) + seconds, 3)
        self._dirty = True
        return self.app_limit_state_for_day(target_key, when)

    def grant_app_limit_extension(self, target_key, when=None):
        state, moment, extension_used = self._rolling_limit_state(target_key, when)
        if extension_used:
            return False
        state["extension_granted_at"] = moment.isoformat(timespec="seconds")
        self._dirty = True
        self.save(force=True)
        return True

    def is_browser_site_excluded(self, browser, host):
        key = f"site:{str(browser).lower()}:{str(host).lower()}"
        return key in self.data.get("excluded_sites", [])

    def exclude_browser_site(self, browser, host):
        """Stop counting one host, whether or not it was already specific."""
        browser = str(browser).lower()
        host = _site_host(host) or str(host).lower().strip()
        if not browser or not host:
            return
        self.make_browser_site_specific(browser, host, save=False)
        key = f"site:{browser}:{host}"
        excluded = self.data.setdefault("excluded_sites", [])
        if key not in excluded:
            excluded.append(key)
        if key not in self.data["excluded"]:
            self.data["excluded"].append(key)
        self.data.setdefault("targets", {}).setdefault(key, {})["label"] = host
        self._dirty = True
        self.save(force=True)

    def unexclude(self, key):
        if key in self.data["excluded"]:
            self.data["excluded"].remove(key)
            if key in self.data.get("excluded_sites", []):
                self.data["excluded_sites"].remove(key)
            self._dirty = True
            self.save(force=True)

    def delete_target(self, key):
        """Permanently remove the recorded history and settings for a target."""
        key = str(key)
        browser = _other_sites_browser(key)
        if browser:
            for apps in self.data["days"].values():
                apps.pop(key, None)
            self.data.get("other_site_days", {}).pop(browser, None)
        else:
            for apps in self.data["days"].values():
                apps.pop(key, None)
            browser, host = _browser_site_parts(key)
            if browser and host:
                sites = self.data.get("browser_specific_sites", {}).get(browser, [])
                if host in sites:
                    sites.remove(host)
                if key in self.data.get("excluded_sites", []):
                    self.data["excluded_sites"].remove(key)
        self.data["targets"].pop(key, None)
        if key in self.data["excluded"]:
            self.data["excluded"].remove(key)
        self.data.get("merged_targets", {}).pop(key, None)
        self.data["sessions"] = [
            session for session in self.data.get("sessions", [])
            if session.get("key") != key
        ]
        for session_id, session in list(self.data.get("open_sessions", {}).items()):
            if session.get("key") == key:
                self.data["open_sessions"].pop(session_id, None)
        self._dirty = True
        self.save(force=True)

    def delete_browser_site(self, browser, host):
        """Permanently remove one host from the aggregated browser history."""
        browser = str(browser).lower()
        host = _site_host(host) or str(host).lower().strip()
        if not browser or not host:
            return
        specific_key = f"site:{browser}:{host}"
        for day, hosts in self.data.get("other_site_days", {}).get(browser, {}).items():
            seconds = float(hosts.pop(host, 0.0))
            if not seconds:
                continue
            apps = self.data["days"].setdefault(day, {})
            grouped_key = f"site:{browser}:other-sites"
            apps[grouped_key] = round(float(apps.get(grouped_key, 0.0)) - seconds, 3)
            if apps[grouped_key] <= 0:
                apps.pop(grouped_key, None)
        for apps in self.data["days"].values():
            apps.pop(specific_key, None)
        sites = self.data.get("browser_specific_sites", {}).get(browser, [])
        if host in sites:
            sites.remove(host)
        self.data["targets"].pop(specific_key, None)
        for excluded_key in ("excluded", "excluded_sites"):
            if specific_key in self.data.get(excluded_key, []):
                self.data[excluded_key].remove(specific_key)
        self._dirty = True
        self.save(force=True)

    def excluded_targets(self):
        return [
            UsageTarget(
                key=key,
                label=self.data["targets"].get(key, {}).get("label", _legacy_label(key)),
            )
            for key in self.data["excluded"]
        ]

    def merge_candidates(self, source_key):
        keys = set(self.data["targets"])
        for apps in self.data["days"].values():
            keys.update(apps)
        return [
            UsageTarget(
                key=key,
                label=self.data["targets"].get(key, {}).get("label", _legacy_label(key)),
            )
            for key in sorted(keys)
            if key != source_key
        ]

    def merge_target_into(self, source_key, destination_key):
        """Move all recorded usage from one application into another."""
        if not source_key or source_key == destination_key:
            return
        for apps in self.data["days"].values():
            if source_key not in apps:
                continue
            apps[destination_key] = round(
                float(apps.get(destination_key, 0.0)) + float(apps.pop(source_key)), 3
            )
        source_metadata = self.data["targets"].pop(source_key, {})
        destination_metadata = self.data["targets"].setdefault(destination_key, {})
        for key, value in source_metadata.items():
            destination_metadata.setdefault(key, value)
        if source_key in self.data["excluded"]:
            self.data["excluded"].remove(source_key)
        merged_targets = self.data.setdefault("merged_targets", {})
        for key, destination in list(merged_targets.items()):
            if destination == source_key:
                merged_targets[key] = destination_key
        merged_targets[source_key] = destination_key
        destination_label = destination_metadata.get("label", _legacy_label(destination_key))
        for session in self.data.get("sessions", []):
            if session.get("key") == source_key:
                session["key"] = destination_key
                session["label"] = destination_label
        for session in self.data.get("open_sessions", {}).values():
            if session.get("key") == source_key:
                session["key"] = destination_key
                session["label"] = destination_label
        self._dirty = True
        self.save(force=True)

    def set_category(self, key, category):
        metadata = self.data["targets"].setdefault(key, {})
        category = str(category).strip()
        browser = _browser_for_target(key)
        _, host = _browser_site_parts(key)
        if browser and host and host != "other-sites" and category:
            # An individual site dropped into a general category leaves the
            # browser tree. A Web badge in the UI keeps its type explicit.
            previous_site_category = metadata.pop("site_category", None)
            metadata.pop("root", None)
            metadata["category_scope"] = "site"
            metadata["category"] = category
            if not str(metadata.get("label", "")).strip():
                metadata["label"] = host
            specific_sites = self.data.setdefault(
                "browser_specific_sites", {}
            ).setdefault(browser, [])
            if host not in specific_sites:
                specific_sites.append(host)
            self._remove_unused_site_category(previous_site_category)
            self._dirty = True
            self.save(force=True)
            return
        if browser and (
            metadata.get("category_scope") == "site" or _is_youtube_host(host)
        ):
            # Some browser hosts (notably localhost) are presented as
            # independent applications. YouTube is likewise tracked as its
            # own activity. Moving one must therefore change its top-level
            # category, not create a browser sub-category.
            metadata.pop("root", None)
            previous_site_category = metadata.pop("site_category", None)
            metadata["category_scope"] = "site"
            if category:
                metadata["category"] = category
            else:
                metadata["category"] = "Applications non classées"
            self._remove_unused_site_category(previous_site_category)
            self._dirty = True
            self.save(force=True)
            return
        if browser:
            if category:
                metadata["site_category"] = category
                saved_categories = self.data.setdefault("site_categories", [])
                if category not in saved_categories:
                    saved_categories.append(category)
                metadata.setdefault(
                    "category", self.data.get("browser_categories", {}).get(browser, _browser_label(browser))
                )
            else:
                metadata.pop("site_category", None)
            self._dirty = True
            self.save(force=True)
            return
        if category:
            metadata.pop("root", None)
            metadata["category"] = category
        else:
            metadata.pop("category", None)
        self._dirty = True
        self.save(force=True)

    def make_root(self, key):
        metadata = self.data["targets"].setdefault(key, {})
        metadata["root"] = True
        metadata.pop("category", None)
        metadata.pop("site_category", None)
        self._dirty = True
        self.save(force=True)

    def make_browser_root(self, browser):
        self.data.setdefault("browser_categories", {})[str(browser).lower()] = "__root__"
        for key, metadata in self.data["targets"].items():
            if _browser_for_target(key) == str(browser).lower():
                metadata["category"] = "__root__"
        self._dirty = True
        self.save(force=True)

    def browser_label(self, browser):
        browser = str(browser).lower()
        return self.data.get("browser_labels", {}).get(browser, _browser_label(browser))

    def rename_browser(self, browser, label):
        label = str(label).strip()
        if label:
            self.data.setdefault("browser_labels", {})[str(browser).lower()] = label
            self._dirty = True
            self.save(force=True)

    def rename_target(self, key, label):
        label = str(label).strip()
        if not label:
            return
        self.data["targets"].setdefault(key, {})["label"] = label
        for session in self.data.get("sessions", []):
            if session.get("key") == key:
                session["label"] = label
        for session in self.data.get("open_sessions", {}).values():
            if session.get("key") == key:
                session["label"] = label
        self._dirty = True
        self.save(force=True)

    def rename_category(self, old_category, new_category):
        old_category = str(old_category).strip()
        new_category = str(new_category).strip()
        if not old_category or not new_category or new_category == old_category:
            return
        for browser, category in self.data.get("browser_categories", {}).items():
            if category == old_category:
                self.data["browser_categories"][browser] = new_category
        for metadata in self.data["targets"].values():
            if metadata.get("category") == old_category:
                metadata["category"] = new_category
        parents = self.data.setdefault("category_parents", {})
        previous_parent = parents.pop(old_category, None)
        if previous_parent and new_category not in parents:
            parents[new_category] = previous_parent
        for category, parent in list(parents.items()):
            if parent == old_category:
                parents[category] = new_category
        order = self.data.setdefault("category_order", [])
        order[:] = list(dict.fromkeys(
            new_category if category == old_category else category
            for category in order
        ))
        self._dirty = True
        self.save(force=True)

    def move_category(self, category, parent):
        """Nest one category below another without changing its activities."""
        category = str(category).strip()
        parent = str(parent).strip()
        if not category or not parent or category == parent:
            return
        parents = self.data.setdefault("category_parents", {})
        ancestor = parent
        seen = {category}
        while ancestor:
            if ancestor in seen:
                raise ValueError("Une catégorie ne peut pas contenir son propre parent.")
            seen.add(ancestor)
            ancestor = str(parents.get(ancestor, "")).strip()
        parents[category] = parent
        self._dirty = True
        self.save(force=True)

    def make_category_root(self, category):
        category = str(category).strip()
        if category and self.data.setdefault("category_parents", {}).pop(category, None):
            self._dirty = True
            self.save(force=True)

    def reorder_category(self, category, destination, before=True):
        """Reorder two sibling categories without changing their hierarchy."""
        category = str(category).strip()
        destination = str(destination).strip()
        if not category or not destination or category == destination:
            return
        parents = self.data.get("category_parents", {})
        if parents.get(category) != parents.get(destination):
            raise ValueError("Seules les catégories d'un même niveau peuvent être réordonnées.")
        known = self.top_level_categories()
        if category not in known or destination not in known:
            return
        known.remove(category)
        index = known.index(destination) + (0 if before else 1)
        known.insert(index, category)
        self.data["category_order"] = known
        self._dirty = True
        self.save(force=True)

    def reorder_site_category(self, category, destination, before=True):
        """Reorder site subcategories without changing their contents."""
        category = str(category).strip()
        destination = str(destination).strip()
        if not category or not destination or category == destination:
            return
        known = self.site_categories()
        if category not in known or destination not in known:
            raise ValueError("Sous-catégorie de site introuvable.")
        known.remove(category)
        index = known.index(destination) + (0 if before else 1)
        known.insert(index, category)
        self.data["site_categories"] = known
        self.data["site_category_order_manual"] = True
        self._dirty = True
        self.save(force=True)

    def set_category_for_keys(self, keys, category):
        category = str(category).strip()
        removed_site_categories = set()
        for key in keys:
            metadata = self.data["targets"].setdefault(key, {})
            browser = _browser_for_target(key)
            _, host = _browser_site_parts(key)
            if browser and host and host != "other-sites" and category:
                previous = metadata.pop("site_category", None)
                if previous:
                    removed_site_categories.add(previous)
                metadata.pop("root", None)
                metadata["category"] = category
                metadata["category_scope"] = "site"
                if not str(metadata.get("label", "")).strip():
                    metadata["label"] = host
                specific_sites = self.data.setdefault(
                    "browser_specific_sites", {}
                ).setdefault(browser, [])
                if host not in specific_sites:
                    specific_sites.append(host)
                continue
            if category:
                metadata["category"] = category
            else:
                metadata.pop("category", None)
            if browser and metadata.get("category_scope") != "site":
                self.data["browser_categories"][browser] = category
        for site_category in removed_site_categories:
            self._remove_unused_site_category(site_category)
        self._dirty = True
        self.save(force=True)

    def _remove_unused_site_category(self, category):
        category = str(category or "").strip()
        if not category or any(
            metadata.get("site_category") == category
            for metadata in self.data["targets"].values()
        ):
            return
        saved_categories = self.data.setdefault("site_categories", [])
        saved_categories[:] = [saved for saved in saved_categories if saved != category]

    def clear_browser_category(self, browser):
        """Detach every target of a browser from its common parent category."""
        browser = str(browser).lower()
        self.data.setdefault("browser_categories", {}).pop(browser, None)
        for key, metadata in self.data["targets"].items():
            if _browser_for_target(key) == browser:
                metadata.pop("category", None)
        self._dirty = True
        self.save(force=True)

    def clear_site_category_for_keys(self, keys, category=""):
        """Remove a site sub-category and discard it when it is now empty."""
        removed_categories = {str(category).strip()} if str(category).strip() else set()
        for key in keys:
            category = self.data["targets"].setdefault(key, {}).pop("site_category", None)
            if category:
                removed_categories.add(category)

        saved_categories = self.data.setdefault("site_categories", [])
        for category in removed_categories:
            still_used = any(
                metadata.get("site_category") == category
                for metadata in self.data["targets"].values()
            )
            if not still_used:
                saved_categories[:] = [
                    saved for saved in saved_categories if saved != category
                ]
        self._dirty = True
        self.save(force=True)

    def clear_category(self, category):
        """Detach every activity from one top-level category."""
        category = str(category).strip()
        if not category:
            return
        browser_categories = self.data.setdefault("browser_categories", {})
        for browser, browser_category in list(browser_categories.items()):
            if browser_category == category:
                browser_categories.pop(browser, None)
        for metadata in self.data["targets"].values():
            if metadata.get("category") == category:
                metadata.pop("category", None)
        parents = self.data.setdefault("category_parents", {})
        parents.pop(category, None)
        for child, parent in list(parents.items()):
            if parent == category:
                parents.pop(child, None)
        order = self.data.setdefault("category_order", [])
        order[:] = [name for name in order if name != category]
        self._dirty = True
        self.save(force=True)

    def rename_site_category_for_keys(self, keys, category):
        category = str(category).strip()
        if not category:
            return
        saved_categories = self.data.setdefault("site_categories", [])
        for key in keys:
            previous = self.data["targets"].setdefault(key, {}).get("site_category")
            if previous in saved_categories:
                saved_categories.remove(previous)
        if category not in saved_categories:
            saved_categories.append(category)
        for key in keys:
            self.data["targets"].setdefault(key, {})["site_category"] = category
        self._dirty = True
        self.save(force=True)

    def categories(self):
        categories = set(self.data.get("browser_categories", {}).values())
        categories.update(self.data.get("site_categories", []))
        parents = self.data.get("category_parents", {})
        categories.update(parents)
        categories.update(parents.values())
        categories.update(
            metadata.get("category", "")
            for metadata in self.data["targets"].values()
        )
        categories.update(
            metadata.get("site_category", "")
            for metadata in self.data["targets"].values()
        )
        return sorted(
            category for category in categories
            if category
            and category not in {"__root__", "Applications non classées"}
        )

    def top_level_categories(self):
        """Return every known main category, including categories idle today."""
        categories = set(self.data.get("browser_categories", {}).values())
        parents = self.data.get("category_parents", {})
        categories.update(parents)
        categories.update(parents.values())
        categories.update(
            metadata.get("category", "")
            for metadata in self.data["targets"].values()
        )
        known = {
            category for category in categories
            if category
            and category not in {"__root__", "Applications non classées"}
        }
        saved_order = self.data.get("category_order", [])
        ordered = [category for category in saved_order if category in known]
        ordered.extend(sorted(known.difference(ordered)))
        return ordered

    def category_order_key(self, category):
        """Return a stable display key, with manually ordered categories first."""
        category = str(category)
        if category == "__root__":
            return (-1, "")
        ordered = self.top_level_categories()
        try:
            return (0, ordered.index(category))
        except ValueError:
            return (1, category.casefold())

    def category_lineage(self, category):
        """Return a category followed by all its ancestors, at any depth."""
        lineage = []
        current = str(category or "").strip()
        parents = self.data.get("category_parents", {})
        while current and current not in lineage:
            lineage.append(current)
            current = str(parents.get(current, "")).strip()
        return lineage

    def site_categories(self):
        return list(dict.fromkeys(
            category for category in self.data.get("site_categories", []) if category
        ))

    def presentation(self, usage):
        entries = []
        visible_usage = dict(usage)
        # Classification is persistent, while usage belongs to the selected
        # period. Every known target must therefore remain visible at zero in
        # today's tree, historical analysis and both PWAs.
        for key in self.data.get("targets", {}):
            visible_usage.setdefault(key, 0.0)
        for key in self.data.get("app_limit_settings", {}):
            visible_usage.setdefault(key, 0.0)
        for key, seconds in visible_usage.items():
            if self.is_excluded(key):
                continue
            browser = _browser_for_target(key)
            if browser and key == f"app:{Path(browser).stem.lower()}":
                continue
            metadata = self.data["targets"].get(key, {})
            entries.append(
                UsageEntry(
                    key=key,
                    label=metadata.get("label", _legacy_label(key)),
                    category=("__root__" if metadata.get("root") else
                              metadata.get("category") or _default_category(key, metadata.get("label", _legacy_label(key)))),
                    seconds=float(seconds),
                    site_category=metadata.get("site_category", ""),
                    category_scope=metadata.get("category_scope", ""),
                )
            )
        return entries

    def save(self, force=False):
        if not self._dirty and not force:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(self.data, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        os.replace(temporary, self.path)
        self._dirty = False

    def usage_for_day(self, when=None):
        day = (when or date.today()).isoformat()
        return dict(self.data["days"].get(day, {}))

    def total_usage(self):
        totals = {}
        for apps in self.data["days"].values():
            for app_name, seconds in apps.items():
                totals[app_name] = totals.get(app_name, 0.0) + float(seconds)
        return totals

    def usage_for_period(self, start, end):
        """Return application usage accumulated between two inclusive dates."""
        return self._period_totals(self.data["days"], start, end)

    def passive_usage_for_day(self, when=None):
        day = (when or date.today()).isoformat()
        return {
            name: seconds
            for name, seconds in self.data["passive_days"].get(day, {}).items()
            if not self.is_passive_excluded(name)
        }

    def total_passive_usage(self):
        totals = {}
        for media in self.data["passive_days"].values():
            for name, seconds in media.items():
                if self.is_passive_excluded(name):
                    continue
                totals[name] = totals.get(name, 0.0) + float(seconds)
        return totals

    def passive_usage_for_period(self, start, end):
        totals = self._period_totals(self.data["passive_days"], start, end)
        return {
            name: seconds for name, seconds in totals.items()
            if not self.is_passive_excluded(name)
        }

    def system_usage_for_day(self, when=None):
        day = (when or date.today()).isoformat()
        return self._system_totals([self.data["system_days"].get(day, {})])

    def total_system_usage(self):
        return self._system_totals(self.data["system_days"].values())

    def system_usage_for_period(self, start, end):
        start_day, end_day = self._ordered_period(start, end)
        return self._system_totals(
            values for day, values in self.data["system_days"].items()
            if start_day <= day <= end_day
        )

    @staticmethod
    def _ordered_period(start, end):
        start_day, end_day = start.isoformat(), end.isoformat()
        return min(start_day, end_day), max(start_day, end_day)

    def _period_totals(self, day_values, start, end):
        start_day, end_day = self._ordered_period(start, end)
        totals = {}
        for day, values in day_values.items():
            if not start_day <= day <= end_day:
                continue
            for name, seconds in values.items():
                totals[name] = totals.get(name, 0.0) + float(seconds)
        return totals

    @staticmethod
    def _system_totals(days):
        totals = {"on": 0.0, "foreground": 0.0, "with_passive": 0.0}
        for day in days:
            for key in totals:
                totals[key] += float(day.get(key, 0.0))
        return totals


@dataclass(frozen=True)
class UsageTarget:
    key: str
    label: str
    category: str = ""
    detail_host: str = ""


@dataclass(frozen=True)
class UsageEntry:
    key: str
    label: str
    category: str
    seconds: float
    site_category: str = ""
    category_scope: str = ""


def configure_windows_autostart(enabled=True):
    """Register this program for the current user's Windows logon."""
    if sys.platform != "win32":
        return False
    try:
        import winreg

        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            key_path,
            0,
            winreg.KEY_SET_VALUE,
        ) as key:
            if enabled:
                winreg.SetValueEx(key, "UsageGuard", 0, winreg.REG_SZ, _startup_command())
                try:
                    winreg.DeleteValue(key, "UsageMonitor")
                except FileNotFoundError:
                    pass
            else:
                for value_name in ("UsageGuard", "UsageMonitor"):
                    try:
                        winreg.DeleteValue(key, value_name)
                    except FileNotFoundError:
                        pass
        return True
    except OSError:
        return False


def _startup_command():
    if getattr(sys, "frozen", False):
        return f'"{Path(sys.executable).resolve()}" --background'
    python = Path(sys.executable).resolve()
    pythonw = python.with_name("pythonw.exe")
    interpreter = pythonw if pythonw.exists() else python
    main_script = APP_DIR / "main.py"
    return f'"{interpreter}" "{main_script}" --background'


def _display_app_name(app_name, window_title=""):
    name = Path(str(app_name).strip()).name
    display_name = name[:-4] if name.lower().endswith(".exe") else name
    if display_name.lower() == "chrome":
        chrome_app_name = _chrome_app_name(window_title)
        if chrome_app_name:
            return chrome_app_name
    return display_name


def _chrome_app_name(window_title):
    """Return the installed Chrome web-app name, or an empty string for tabs."""
    title = str(window_title or "").strip()
    browser_suffixes = (" - Google Chrome", " – Google Chrome", " - Chrome", " – Chrome")
    if not title or title.endswith(browser_suffixes):
        return ""
    # PWA titles commonly have a document/page subtitle after the app name.
    return title.split(":", 1)[0].split(" - ", 1)[0].split(" – ", 1)[0].strip()


def _site_host(url):
    try:
        parsed = urlparse(str(url))
        host = parsed.hostname or ""
    except ValueError:
        return ""
    host = host.lower().removeprefix("www.")
    # Ports distinguish local PWAs (for example localhost:3000 and :5173).
    if host.rstrip(".") in {"localhost", "127.0.0.1", "::1"}:
        try:
            port = parsed.port
        except ValueError:
            return host
        if port is not None:
            return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    return host


def _is_youtube_host(host):
    host = str(host).lower()
    return host == "youtube.com" or host.endswith(".youtube.com") or host == "youtu.be"


def _local_site_category(host):
    """Return the category for a loopback site, if *host* is local."""
    normalized = str(host or "").lower().rstrip(".")
    if normalized.startswith("["):
        normalized = normalized.split("]", 1)[0].lstrip("[")
    elif normalized.count(":") == 1:
        normalized = normalized.rsplit(":", 1)[0]
    if normalized not in {"localhost", "127.0.0.1", "::1"}:
        return ""
    return str(
        getattr(config, "LOCALHOST_CATEGORY", "Applications non classées")
    ).strip()


def _browser_site_parts(key):
    prefix, separator, host = str(key).lower().partition(":")
    if prefix != "site" or not separator:
        return "", ""
    browser, separator, host = host.partition(":")
    if not browser or not separator or host == "other-sites":
        return "", ""
    return browser, host


def _other_sites_browser(key):
    browser, host = _browser_site_parts(str(key).replace(":other-sites", ":placeholder"))
    return browser if host == "placeholder" else ""


def _browser_label(executable):
    return Path(executable).stem.replace("-", " ").title()


def _legacy_label(key):
    return str(key).removeprefix("app:")


def _default_category(key, label):
    executable = str(key).removeprefix("app:").lower()
    browser_apps = _browser_apps()
    for browser in browser_apps:
        if executable in {browser, Path(browser).stem.lower()}:
            return _browser_label(browser)
    return "Applications non classées"


def _canonical_target_key(key):
    key = str(key)
    if key.startswith(("app:", "site:")):
        return key
    return f"app:{key.lower()}"


def _browser_apps():
    return {str(value).lower() for value in getattr(config, "BROWSER_APPS", ["brave.exe"])}


def _browser_for_target(key):
    key = str(key).lower()
    for browser in _browser_apps():
        if key == f"app:{Path(browser).stem.lower()}" or key.startswith(f"site:{browser}:"):
            return browser
    return None
