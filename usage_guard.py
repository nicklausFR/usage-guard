import os
import base64
import ctypes
import json
import platform
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml


CONFIG_PATH = Path("config.yaml")
RULES_PATH = Path("rules.yaml")
USAGE_PATH = Path("usage.dat")
USAGE_BACKUP_PATH = Path("usage.bak.dat")


class Config:
    def __init__(self, path=CONFIG_PATH):
        self._path = Path(path)
        if self._path.exists():
            with self._path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        else:
            data = {}
        self._data = data
        self.__dict__.update(data)

    def set(self, name, value):
        self._data[name] = value
        setattr(self, name, value)
        self._save_value(name, value)

    def _save_value(self, name, value):
        dumped = yaml.safe_dump(
            value,
            allow_unicode=True,
            default_flow_style=True,
            sort_keys=False,
        ).strip()
        if "\n" in dumped:
            dumped = dumped.splitlines()[0]

        line = f"{name}: {dumped}\n"
        if self._path.exists():
            lines = self._path.read_text(encoding="utf-8").splitlines(True)
        else:
            lines = []

        prefix = f"{name}:"
        for index, current in enumerate(lines):
            if current.lstrip().startswith(prefix):
                indent = current[: len(current) - len(current.lstrip())]
                lines[index] = indent + line
                break
        else:
            if lines and not lines[-1].endswith("\n"):
                lines[-1] += "\n"
            lines.append(line)

        self._path.write_text("".join(lines), encoding="utf-8")


config = Config()


class JokerStore:
    def __init__(self, path=Path("jokers.json")):
        self.path = Path(path)
        self.data = self._load()

    def _load(self):
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def save(self):
        self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")

    def grant(self, rule_name: str, minutes: int, now=None):
        now = now or datetime.now().astimezone()
        existing = self.expires_at(rule_name, now)
        start = existing if existing and existing > now else now
        expires = start + timedelta(minutes=minutes)
        self.data[rule_name] = expires.isoformat()
        self.save()

    def active(self, rule_name: str, now=None):
        expires = self.expires_at(rule_name, now)
        return bool(expires and expires > (now or datetime.now().astimezone()))

    def expires_at(self, rule_name: str, now=None):
        value = self.data.get(rule_name)
        if not value:
            return None
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None


@dataclass
class Quota:
    period: str
    limit_minutes: int


@dataclass
class TimeWindow:
    start: str
    end: str
    days: list[str] = field(default_factory=list)
    mode: str = "allow"


@dataclass
class Rule:
    name: str
    target_type: str
    target: str
    enabled: bool = True
    action: str = "warn"
    quotas: list[Quota] = field(default_factory=list)
    windows: list[TimeWindow] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]):
        return cls(
            name=str(data.get("name", "Unnamed rule")),
            target_type=str(data.get("target_type", "app")),
            target=str(data.get("target", "")),
            enabled=bool(data.get("enabled", True)),
            action=str(data.get("action", "warn")),
            quotas=[
                Quota(
                    period=str(item.get("period", "day")),
                    limit_minutes=int(item.get("limit_minutes", 0)),
                )
                for item in data.get("quotas", []) or []
            ],
            windows=[
                TimeWindow(
                    start=str(item.get("start", "00:00")),
                    end=str(item.get("end", "23:59")),
                    days=list(item.get("days", []) or []),
                    mode=str(item.get("mode", "allow")),
                )
                for item in data.get("windows", []) or []
            ],
        )

    def to_dict(self):
        return {
            "name": self.name,
            "target_type": self.target_type,
            "target": self.target,
            "enabled": self.enabled,
            "action": self.action,
            "quotas": [quota.__dict__ for quota in self.quotas],
            "windows": [window.__dict__ for window in self.windows],
        }


class RuleStore:
    def __init__(self, path=RULES_PATH):
        self.path = Path(path)
        self.rules: list[Rule] = []
        self.load()

    def load(self):
        if self.path.exists():
            data = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        else:
            data = {}
        self.rules = [Rule.from_dict(item) for item in data.get("rules", []) or []]

    def save(self):
        data = {"rules": [rule.to_dict() for rule in self.rules]}
        self.path.write_text(
            yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )


class UsageStore:
    def __init__(self, path=USAGE_PATH, backup_path=USAGE_BACKUP_PATH):
        self.path = Path(path)
        self.backup_path = Path(backup_path)
        self.reset_detected = False
        self.data = self._load()

    def _load(self):
        source = self.path if self.path.exists() else self.backup_path
        if not source.exists():
            if not bool(getattr(config, "USAGE_STORAGE_INITIALIZED", False)):
                self.save_data({})
                config.set("USAGE_STORAGE_INITIALIZED", True)
                return {}
            self.reset_detected = True
            return {}
        try:
            payload = source.read_bytes()
            raw = _unprotect_bytes(payload)
            data = json.loads(raw.decode("utf-8"))
            if source == self.backup_path and not self.path.exists():
                self.save_data(data)
            return data
        except (json.JSONDecodeError, OSError, ValueError):
            corrupt = source.with_suffix(source.suffix + ".corrupt")
            os.replace(source, corrupt)
            return {}

    def save(self):
        self.save_data(self.data)

    def save_data(self, data):
        raw = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
        payload = _protect_bytes(raw)
        self.path.write_bytes(payload)
        self.backup_path.write_bytes(payload)

    def add_seconds(self, target_type: str, target: str, seconds: float, now=None):
        now = now or datetime.now().astimezone()
        for period in ("day", "week", "month"):
            key = usage_key(target_type, target, period, now)
            self.data[key] = round(float(self.data.get(key, 0)) + seconds, 3)
        self.save()

    def seconds_for(self, target_type: str, target: str, period: str, now=None):
        now = now or datetime.now().astimezone()
        return float(self.data.get(usage_key(target_type, target, period, now), 0))


def period_start(period: str, now=None):
    now = now or datetime.now().astimezone()
    if period == "day":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "week":
        start = now - timedelta(days=now.weekday())
        return start.replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "month":
        return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    raise ValueError(f"Unsupported period: {period}")


def usage_key(target_type: str, target: str, period: str, now=None):
    start = period_start(period, now)
    return f"{target_type}:{target}:{period}:{start.isoformat()}"


def _protect_bytes(data: bytes) -> bytes:
    if platform.system() != "Windows":
        return base64.b64encode(data)
    return b"DPAPI:" + _dpapi_crypt(data, protect=True)


def _unprotect_bytes(data: bytes) -> bytes:
    if data.startswith(b"DPAPI:"):
        return _dpapi_crypt(data[6:], protect=False)
    return base64.b64decode(data)


def _dpapi_crypt(data: bytes, protect: bool) -> bytes:
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.c_uint),
            ("pbData", ctypes.POINTER(ctypes.c_byte)),
        ]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_buffer = ctypes.create_string_buffer(data)
    in_blob = DATA_BLOB(len(data), ctypes.cast(in_buffer, ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()

    if protect:
        ok = crypt32.CryptProtectData(
            ctypes.byref(in_blob),
            "Usage-Guard usage counters",
            None,
            None,
            None,
            0,
            ctypes.byref(out_blob),
        )
    else:
        ok = crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            None,
            None,
            None,
            None,
            0,
            ctypes.byref(out_blob),
        )

    if not ok:
        raise ValueError("DPAPI operation failed")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)
