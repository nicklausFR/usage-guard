import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, date
from pathlib import Path
from urllib.parse import urlparse

import yaml


APP_DIR = Path(__file__).resolve().parent
CONFIG_PATH = APP_DIR / "config.yaml"
APP_NAME = "Usage Monitor"


def _usage_path():
    """Return a location which survives a PyInstaller one-file restart."""
    if not getattr(sys, "frozen", False):
        return APP_DIR / "activity.json"

    # In a one-file executable, ``__file__`` is inside PyInstaller's temporary
    # extraction directory.  It is removed when the application exits, so it
    # must never be used to hold user data.
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / APP_NAME / "activity.json"
    return Path.home() / "AppData" / "Local" / APP_NAME / "activity.json"


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
        self.data = self._load()
        self._dirty = self._migrate_legacy_targets()

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

    def _load(self):
        if not self.path.exists():
            return self._empty_data()
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data.get("days"), dict):
                raise ValueError("invalid activity store")
            data.setdefault("targets", {})
            data.setdefault("excluded", [])
            data.setdefault("browser_categories", {})
            data.setdefault("passive_days", {})
            data.setdefault("passive_excluded", [])
            data.setdefault("system_days", {})
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
            "browser_categories": {},
            "passive_days": {},
            "passive_excluded": [],
            "system_days": {},
        }

    def _migrate_legacy_targets(self):
        """Merge pre-category app keys without losing any recorded seconds."""
        changed = False
        for apps in self.data["days"].values():
            for key, seconds in list(apps.items()):
                canonical = _canonical_target_key(key)
                if canonical == key:
                    continue
                apps[canonical] = round(float(apps.get(canonical, 0.0)) + float(seconds), 3)
                del apps[key]
                self.data["targets"].setdefault(canonical, {"label": str(key)})
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
        for key, metadata in self.data["targets"].items():
            browser = _browser_for_target(key)
            category = browser_categories.get(browser) if browser else None
            if category and metadata.get("category") != category:
                metadata["category"] = category
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
        app_name = _display_app_name(context.app_name)
        executable = Path(str(context.app_name)).name.lower()
        host = _site_host(context.url)
        browser_apps = _browser_apps()
        if app_name and executable in browser_apps and host:
            return UsageTarget(
                key=f"site:{executable}:{host}",
                label=host,
                category=self.data["browser_categories"].get(
                    executable, _browser_label(executable)
                ),
            )
        return UsageTarget(
            key=f"app:{app_name.lower()}",
            label=app_name,
            category=(
                self.data["browser_categories"].get(executable, _browser_label(executable))
                if executable in browser_apps
                else ""
            ),
        )

    def add_seconds(self, target, seconds, when=None):
        if not target or not target.key or seconds <= 0 or self.is_excluded(target.key):
            return
        day = (when or date.today()).isoformat()
        apps = self.data["days"].setdefault(day, {})
        apps[target.key] = round(float(apps.get(target.key, 0.0)) + seconds, 3)
        metadata = self.data["targets"].setdefault(target.key, {})
        metadata["label"] = target.label
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
        self.save(force=True)

    def set_category(self, key, category):
        metadata = self.data["targets"].setdefault(key, {})
        category = str(category).strip()
        if category:
            metadata["category"] = category
        else:
            metadata.pop("category", None)
        self._dirty = True
        self.save(force=True)

    def set_category_for_keys(self, keys, category):
        category = str(category).strip()
        for key in keys:
            metadata = self.data["targets"].setdefault(key, {})
            if category:
                metadata["category"] = category
            else:
                metadata.pop("category", None)
            browser = _browser_for_target(key)
            if browser:
                self.data["browser_categories"][browser] = category
        self._dirty = True
        self.save(force=True)

    def categories(self):
        categories = set(self.data.get("browser_categories", {}).values())
        categories.update(
            metadata.get("category", "")
            for metadata in self.data["targets"].values()
        )
        return sorted(category for category in categories if category and category != "Autres")

    def presentation(self, usage):
        entries = []
        for key, seconds in usage.items():
            if self.is_excluded(key):
                continue
            metadata = self.data["targets"].get(key, {})
            entries.append(
                UsageEntry(
                    key=key,
                    label=metadata.get("label", _legacy_label(key)),
                    category=metadata.get("category") or _default_category(key, metadata.get("label", _legacy_label(key))),
                    seconds=float(seconds),
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

    def system_usage_for_day(self, when=None):
        day = (when or date.today()).isoformat()
        return self._system_totals([self.data["system_days"].get(day, {})])

    def total_system_usage(self):
        return self._system_totals(self.data["system_days"].values())

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


@dataclass(frozen=True)
class UsageEntry:
    key: str
    label: str
    category: str
    seconds: float


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
                winreg.SetValueEx(key, "UsageMonitor", 0, winreg.REG_SZ, _startup_command())
            else:
                try:
                    winreg.DeleteValue(key, "UsageMonitor")
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


def _display_app_name(app_name):
    name = Path(str(app_name).strip()).name
    return name[:-4] if name.lower().endswith(".exe") else name


def _site_host(url):
    try:
        host = urlparse(str(url)).hostname or ""
    except ValueError:
        return ""
    return host.lower().removeprefix("www.")


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
    return "Autres"


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
