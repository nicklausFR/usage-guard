"""Foreground-only application limits for Windows."""

import ctypes
import sys
import time
from ctypes import wintypes
from datetime import date, datetime, timedelta
from urllib.parse import urlparse

from PySide6.QtCore import QObject, Qt, QTimer, Signal
from PySide6.QtWidgets import QApplication, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget
from i18n import _


EnumWindowsProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

if sys.platform == "win32":
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.GetWindowRect.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.RECT))
    user32.GetWindowRect.restype = wintypes.BOOL
    user32.EnableWindow.argtypes = (wintypes.HWND, wintypes.BOOL)
    user32.EnableWindow.restype = wintypes.BOOL
    user32.IsWindow.argtypes = (wintypes.HWND,)
    user32.IsWindow.restype = wintypes.BOOL
    user32.IsWindowVisible.argtypes = (wintypes.HWND,)
    user32.IsWindowVisible.restype = wintypes.BOOL
    user32.ShowWindow.argtypes = (wintypes.HWND, ctypes.c_int)
    user32.ShowWindow.restype = wintypes.BOOL
    user32.PostMessageW.argtypes = (
        wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
    )
    user32.PostMessageW.restype = wintypes.BOOL
    user32.SendMessageTimeoutW.argtypes = (
        wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
        wintypes.UINT, wintypes.UINT, ctypes.POINTER(ctypes.c_size_t),
    )
    user32.SendMessageTimeoutW.restype = wintypes.LPARAM
    user32.SetForegroundWindow.argtypes = (wintypes.HWND,)
    user32.SetForegroundWindow.restype = wintypes.BOOL
    user32.GetWindowLongPtrW.argtypes = (wintypes.HWND, ctypes.c_int)
    user32.GetWindowLongPtrW.restype = ctypes.c_ssize_t
    user32.SetWindowLongPtrW.argtypes = (
        wintypes.HWND, ctypes.c_int, ctypes.c_ssize_t
    )
    user32.SetWindowLongPtrW.restype = ctypes.c_ssize_t
    user32.GetWindowThreadProcessId.argtypes = (
        wintypes.HWND, ctypes.POINTER(wintypes.DWORD)
    )
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.EnumWindows.argtypes = (EnumWindowsProc, wintypes.LPARAM)
    user32.EnumWindows.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.QueryFullProcessImageNameW.argtypes = (
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)
    )
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL

WM_CLOSE = 0x0010
WM_APPCOMMAND = 0x0319
APPCOMMAND_MEDIA_PAUSE = 47
APPCOMMAND_MEDIA_PLAY = 46
APPCOMMAND_MEDIA_PLAY_PAUSE = 14
SMTO_ABORTIFHUNG = 0x0002
SW_HIDE = 0
SW_SHOW = 5
SW_MINIMIZE = 6
GWL_EXSTYLE = -20
WS_EX_TOOLWINDOW = 0x00000080
WS_EX_APPWINDOW = 0x00040000
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


class LimitOverlay(QWidget):
    def __init__(self, controller):
        super().__init__(None, Qt.WindowType.Window | Qt.WindowType.FramelessWindowHint)
        self.controller = controller
        self.setWindowTitle(_("Limite atteinte"))
        self.setStyleSheet("background:#4a171b; border:2px solid #ff6b6b; color:white;")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 24, 30, 24)
        layout.setSpacing(14)
        title = QLabel(_("Limite d’utilisation atteinte"))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size:22px; font-weight:700; border:none;")
        self.message = QLabel()
        self.message.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.message.setWordWrap(True)
        self.message.setStyleSheet("font-size:15px; border:none;")
        self.extension_button = QPushButton()
        self.extension_button.setStyleSheet(
            "QPushButton { background:#ff5a5f; border:0; border-radius:6px; "
            "padding:10px 16px; font-weight:700; }"
            "QPushButton:disabled { background:#653438; color:#c9b6b7; }"
        )
        self.extension_button.clicked.connect(controller.grant_extension)
        self.close_button = QPushButton(_("Fermer l’application"))
        self.close_button.clicked.connect(controller.close_target)
        self.minimize_button = QPushButton(_("Réduire"))
        self.minimize_button.clicked.connect(self.minimize_to_taskbar)
        for button in (self.close_button, self.minimize_button):
            button.setStyleSheet(
                "QPushButton { background:#303036; border:1px solid #ffb3b3; "
                "border-radius:6px; padding:10px 16px; font-weight:700; }"
            )
        buttons = QHBoxLayout()
        buttons.addStretch()
        buttons.addWidget(self.minimize_button)
        buttons.addWidget(self.close_button)
        buttons.addWidget(self.extension_button)
        buttons.addStretch()
        layout.addStretch()
        layout.addWidget(title)
        layout.addWidget(self.message)
        layout.addLayout(buttons)
        layout.addStretch()

    def closeEvent(self, event):
        self.controller.close_target()
        event.accept()

    def configure(self, label, available, extension_seconds, period_block=False):
        self.setWindowTitle(_("{label} — limite atteinte").format(label=label))
        self.close_button.setText(_("Fermer {label}").format(label=label))
        self.extension_button.setVisible(not period_block)
        self.extension_button.setEnabled(available)
        self.extension_button.setText(
            _("Obtenir une rallonge exceptionnelle de {seconds} sec").format(seconds=extension_seconds)
            if available else _("Rallonge déjà utilisée sur les dernières 24 h")
        )
        self.message.setText(
            _("{label} est bloquée pendant la période planifiée.").format(label=label)
            if period_block else _("{label} est bloquée. Une rallonge exceptionnelle est disponible.").format(label=label)
            if available else _("{label} est bloquée sur la période de 24 h.").format(label=label)
        )

    def minimize_to_taskbar(self):
        """Minimize the red replacement window without revealing the video."""
        self.setWindowTitle(_("{label} — limite atteinte").format(label=self.controller.target_label))
        native_handle = int(self.winId())
        extended_style = user32.GetWindowLongPtrW(native_handle, GWL_EXSTYLE)
        extended_style = (extended_style | WS_EX_APPWINDOW) & ~WS_EX_TOOLWINDOW
        user32.SetWindowLongPtrW(native_handle, GWL_EXSTYLE, extended_style)
        self.show()
        user32.ShowWindow(native_handle, SW_MINIMIZE)


class ComputerBlockOverlay(QWidget):
    """Recoverable full-desktop block for an active global computer limit."""

    def __init__(self, controller):
        super().__init__(None, Qt.WindowType.Window | Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        self.setWindowTitle(_("Ordinateur indisponible — Usage Guard"))
        self.setStyleSheet("background:#231013; color:white;")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(48, 48, 48, 48)
        title = QLabel(_("Utilisation de l’ordinateur bloquée"))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size:30px; font-weight:800;")
        self.message = QLabel()
        self.message.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.message.setStyleSheet("font-size:18px;")
        cancel = QPushButton(_("Lever l’interdiction"))
        cancel.setStyleSheet("padding:10px 18px; background:#5c252b; border:1px solid #ff8b8b;")
        cancel.clicked.connect(controller.clear_computer_block)
        layout.addStretch()
        layout.addWidget(title)
        layout.addWidget(self.message)
        layout.addWidget(cancel, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addStretch()

    def closeEvent(self, event):
        event.ignore()

    def show_block(self, ends_at):
        end = datetime.fromisoformat(str(ends_at))
        self.message.setText(_("Blocage actif jusqu’au {time}.").format(
            time=end.astimezone().strftime("%d/%m/%Y à %H:%M")
        ))
        screens = QApplication.screens()
        if screens:
            geometry = screens[0].geometry()
            for screen in screens[1:]:
                geometry = geometry.united(screen.geometry())
            self.setGeometry(geometry)
        self.show()
        self.raise_()
        self.activateWindow()


class AppLimiter(QObject):
    """Manage independent daily foreground limits for configured applications."""

    notification_requested = Signal(str, str, int)
    email_notification_requested = Signal(str, str, str)

    def __init__(self, usage, limit_seconds=15, extension_seconds=15, warning_seconds=5):
        super().__init__()
        self.usage = usage
        self.default_settings = {
            "enabled": True,
            "limit_seconds": int(limit_seconds),
            "extension_seconds": int(extension_seconds),
            "warning_seconds": int(warning_seconds),
        }
        self._migrate_legacy_potplayer_limit()
        self.policies = {}
        self._reload_policies()
        self.target_key = ""
        self.target_label = "Application"
        self.target_handle = 0
        self.target_handles = []
        self.target_process_id = 0
        self.target_process_ids = []
        self.blocked = False
        self.overlay = LimitOverlay(self)
        self.computer_overlay = ComputerBlockOverlay(self)
        self._target_geometry = None
        self._notified_handles = set()
        self._warning_shown = set()
        self._computer_block_warning_shown = set()
        self._playing_seen_at = {}
        self._running_limits = []

    def computer_block_status(self, now=None):
        block = dict(self.usage.data.get("computer_block", {}))
        try:
            now = now or datetime.now().astimezone()
            if block.get("enabled") and block.get("mode") == "daily_duration":
                policy = {
                    "valid_from": block.get("valid_from", ""),
                    "valid_from_time": block.get("valid_from_time", ""),
                    "valid_until": block.get("valid_until", ""),
                    "valid_until_time": block.get("valid_until_time", ""),
                    "schedule_start": block.get("schedule_start", ""),
                    "schedule_end": block.get("schedule_end", ""),
                }
                schedule = self._schedule_status(policy, now)
                used = float(
                    self.usage.system_usage_for_day(now.date()).get("on", 0.0)
                )
                allowed = max(60, int(block.get("limit_seconds", 60)))
                end = self._schedule_window_end(policy, now) or datetime.combine(
                    now.date() + timedelta(days=1), datetime.min.time()
                ).replace(tzinfo=now.tzinfo)
                active = bool(schedule["active"] and used >= allowed)
                pending = bool(schedule["pending"] or (schedule["active"] and used < allowed))
                return {
                    **block,
                    "started_at": now.isoformat(timespec="seconds"),
                    "ends_at": end.isoformat(timespec="seconds"),
                    "active": active,
                    "pending": pending,
                    "seconds": round(used, 1),
                    "allowed": allowed,
                    "remaining": max(0.0, allowed - used),
                    "schedule_active": schedule["active"],
                    "schedule_pending": schedule["pending"],
                }
            if block.get("enabled") and block.get("mode") == "schedule":
                start_time = datetime.strptime(block["daily_start"], "%H:%M").time()
                end_time = datetime.strptime(block["daily_end"], "%H:%M").time()
                crosses_midnight = end_time < start_time
                first_day = date.fromisoformat(block["valid_from"]) if block.get("valid_from") else None
                last_day = date.fromisoformat(block["valid_until"]) if block.get("valid_until") else None
                first_boundary = (
                    datetime.combine(
                        first_day,
                        datetime.strptime(block.get("valid_from_time") or "00:00", "%H:%M").time(),
                    ).replace(tzinfo=now.tzinfo)
                    if first_day else None
                )
                last_boundary = (
                    datetime.combine(
                        last_day,
                        datetime.strptime(block.get("valid_until_time") or "23:59", "%H:%M").time(),
                    ).replace(tzinfo=now.tzinfo)
                    if last_day else None
                )
                if last_boundary and now >= last_boundary:
                    return {**block, "active": False, "pending": False}
                occurrence_day = now.date()
                if (
                    crosses_midnight
                    and now.time().replace(tzinfo=None) < end_time
                ):
                    occurrence_day -= timedelta(days=1)
                if first_day:
                    occurrence_day = max(occurrence_day, first_day)
                while True:
                    raw_start = datetime.combine(occurrence_day, start_time).replace(tzinfo=now.tzinfo)
                    raw_end = datetime.combine(
                        occurrence_day + timedelta(days=1) if crosses_midnight else occurrence_day,
                        end_time,
                    ).replace(tzinfo=now.tzinfo)
                    starts_at = max(raw_start, first_boundary or raw_start)
                    ends_at = min(raw_end, last_boundary or raw_end)
                    if starts_at < ends_at and now < ends_at:
                        break
                    occurrence_day += timedelta(days=1)
                    if last_day and occurrence_day > last_day:
                        return {**block, "active": False, "pending": False}
                active = starts_at <= now < ends_at
                pending = not active and now < starts_at
                return {
                    **block,
                    "started_at": starts_at.isoformat(timespec="seconds"),
                    "ends_at": ends_at.isoformat(timespec="seconds"),
                    "active": active,
                    "pending": pending,
                }
            starts_at = datetime.fromisoformat(str(block["started_at"]))
            ends_at = datetime.fromisoformat(str(block["ends_at"]))
            enabled = bool(block.get("enabled")) and starts_at < ends_at
            active = enabled and starts_at <= now < ends_at
            pending = enabled and now < starts_at
        except (KeyError, TypeError, ValueError):
            active = pending = False
        return {**block, "active": active, "pending": pending}

    def computer_block_warning_seconds(self):
        warnings = [seconds for _, seconds in self._warning_rules("computer:all")]
        return max(warnings) if warnings else None

    def _warning_rules(self, target_key):
        rules = []
        for index, rule in enumerate(self.usage.data.get("notification_rules", [])):
            if not rule.get("enabled"):
                continue
            kind = str(rule.get("kind", ""))
            watched = str(rule.get("target_key", ""))
            legacy_computer = target_key == "computer:all" and kind == "computer_block_warning"
            matching_limit = kind == "limit_warning"
            if legacy_computer or matching_limit:
                rules.append((
                    str(rule.get("id") or f"legacy-{index}"),
                    max(1, int(rule.get("warning_seconds", 300))),
                ))
        return rules

    def computer_block_warning_due(self, status, now=None):
        warning_seconds = self.computer_block_warning_seconds()
        if warning_seconds is None or not status.get("pending"):
            return False
        now = now or datetime.now().astimezone()
        starts_at = datetime.fromisoformat(str(status["started_at"]))
        return max(0, (starts_at - now).total_seconds()) <= warning_seconds

    def refresh_computer_block(self, now=None):
        block = self.usage.data.get("computer_block", {})
        now = now or datetime.now().astimezone()
        if block.get("valid_until"):
            try:
                expires_at = datetime.combine(
                    date.fromisoformat(str(block["valid_until"])),
                    datetime.strptime(str(block.get("valid_until_time") or "23:59"), "%H:%M").time(),
                ).replace(tzinfo=now.tzinfo)
                if now >= expires_at:
                    self.usage.clear_computer_block()
                    self._computer_block_warning_shown.clear()
                    self.computer_overlay.hide()
                    return self.computer_block_status(now)
            except (TypeError, ValueError):
                pass
        status = self.computer_block_status(now)
        if status["active"]:
            self.computer_overlay.show_block(status["ends_at"])
        else:
            self.computer_overlay.hide()
            if status.get("pending"):
                starts_at = datetime.fromisoformat(status["started_at"])
                remaining = max(0, (starts_at - now).total_seconds())
                for rule_id, warning_seconds in self._warning_rules("computer:all"):
                    token = (str(status["started_at"]), rule_id)
                    if remaining > warning_seconds or token in self._computer_block_warning_shown:
                        continue
                    self._computer_block_warning_shown.add(token)
                    actor = str(status.get("actor") or "Utilisateur local")
                    self._emit_notification(
                        "limit_warning", "computer:all",
                        f"Blocage imminent demandé par {actor} — Usage Guard",
                        f"La limitation de l’ordinateur commencera dans {self._format_duration(remaining)} et durera jusqu’au {datetime.fromisoformat(status['ends_at']).astimezone().strftime('%d/%m/%Y à %H:%M')}.",
                        0, rule_id=rule_id,
                    )
            if (
                status.get("enabled")
                and block.get("mode") != "schedule"
                and self.usage.data.get("computer_block")
            ):
                try:
                    expired = now >= datetime.fromisoformat(str(block["ends_at"]))
                except (KeyError, TypeError, ValueError):
                    expired = False
                if expired:
                    self.usage.clear_computer_block()
                    self._computer_block_warning_shown.clear()
        return status

    def clear_computer_block(self):
        self.usage.clear_computer_block()
        self._computer_block_warning_shown.clear()
        self.computer_overlay.hide()
        # PotPlayer is the seeded media limit. Other applications join this
        # set automatically as soon as Windows exposes a media session for
        # them, including a PAUSED or STOPPED session.
        self._media_target_keys = {
            key for key in self.policies if "potplayer" in key.casefold()
        }
        self._resume_after_extension = False
        self._current_web_limit = None
        self.follow_timer = QTimer(self)
        self.follow_timer.setInterval(250)
        self.follow_timer.timeout.connect(self.follow_target)
        self.follow_timer.start()

    def _migrate_legacy_potplayer_limit(self):
        """Move the old PotPlayer test limit once, without creating a new one."""
        settings = self.usage.data.setdefault("app_limit_settings", {})
        legacy = settings.pop("app-limit:potplayer", None)
        if legacy is None:
            return
        key = "app:potplayermini64"
        if key not in settings:
            self.usage.data.setdefault("targets", {}).setdefault(key, {})["label"] = "PotPlayer"
            self.usage.set_app_limit_settings(key, legacy)
        else:
            self.usage.save(force=True)

    def _reload_policies(self):
        settings = self.usage.data.setdefault("app_limit_settings", {})
        for key in list(settings):
            canonical = self._canonical_limit_target(key)
            if canonical == key:
                continue
            if canonical not in settings:
                settings[canonical] = settings[key]
            del settings[key]
            self.usage.save(force=True)
        self.policies = {
            key: self.usage.app_limit_settings(key)
            for key in settings
            if str(key).startswith(("app:", "site:", "category:"))
        }
        for key, policy in self.policies.items():
            self.usage.prepare_app_limit(
                key, policy["limit_seconds"], policy["extension_seconds"],
                measured_target_key=self._policy_target_key(key, policy),
            )

    def label_for_key(self, target_key):
        target_key = self._policy_target_key(target_key)
        if str(target_key).startswith("category:"):
            return f"Catégorie · {str(target_key).removeprefix('category:')}"
        metadata = self.usage.data.get("targets", {}).get(target_key, {})
        label = metadata.get("label") or target_key.removeprefix("app:").rsplit(":", 1)[-1]
        return f"Site · {label}" if str(target_key).startswith("site:") else label

    def _notification_enabled(self, kind, target_key):
        return bool(self._notification_rules(kind, target_key))

    def _notification_rules(self, kind, target_key):
        matches = []
        for rule in self.usage.data.get("notification_rules", []):
            if not rule.get("enabled") or rule.get("kind") != kind:
                continue
            if kind == "limited_app_start":
                matches.append(rule)
                continue
            watched = str(rule.get("target_key", ""))
            if not watched or watched == target_key:
                matches.append(rule)
        return matches

    def _emit_notification(self, kind, target_key, title, message, process_id=0, rule_id=None):
        if rule_id is None:
            rules = self._notification_rules(kind, target_key)
        else:
            rules = [
                rule for index, rule in enumerate(self.usage.data.get("notification_rules", []))
                if rule.get("enabled")
                and str(rule.get("id") or f"legacy-{index}") == str(rule_id)
            ]
        if any("windows" in (rule.get("channels") or ["windows"]) for rule in rules):
            self.notification_requested.emit(title, message, int(process_id or 0))
        signal = getattr(self, "email_notification_requested", None)
        recipients = {
            str(rule.get("email_recipient", "")).strip()
            for rule in rules
            if "email" in (rule.get("channels") or ["windows"])
            and str(rule.get("email_recipient", "")).strip()
        }
        for recipient in sorted(recipients):
            if signal is not None:
                signal.emit(title, message, recipient)

    def _notify_limit_reached(self, target_key, state):
        token = (
            target_key,
            f"duration-reached:{int(bool(state.get('extension_used')))}:{date.today().isoformat()}",
        )
        if token in self._warning_shown or not self._notification_enabled("limit_warning", target_key):
            return
        self._warning_shown.add(token)
        self._emit_notification(
            "limit_warning", target_key,
            f"{self.target_label} — limite atteinte",
            "La durée autorisée est atteinte. L’utilisation est maintenant bloquée.",
            self.target_process_id,
        )

    def _notify_extension_started(self, target_key, state, policy):
        if (
            not state.get("extension_used")
            or float(state.get("seconds", 0)) < float(policy.get("limit_seconds", 0))
            or int(policy.get("extension_seconds", 0)) <= 0
            or not self._notification_enabled("limit_extension", target_key)
        ):
            return
        token = (target_key, f"extension-start:{date.today().isoformat()}")
        if token in self._warning_shown:
            return
        self._warning_shown.add(token)
        self._emit_notification(
            "limit_extension", target_key,
            f"{self.target_label} — joker utilisé",
            "La durée normale est dépassée. "
            f"Le joker de {self._format_duration(policy['extension_seconds'])} est actif.",
            self.target_process_id,
        )

    def available_targets(self):
        keys = set(self.usage.data.get("targets", {}))
        for apps in self.usage.data.get("days", {}).values():
            keys.update(apps)
        candidates = {}
        for key in keys:
            if not str(key).startswith(("app:", "site:")):
                continue
            if str(key).endswith(":other-sites"):
                continue
            canonical = self._canonical_limit_target(key)
            candidates[canonical] = (
                "ChatGPT" if canonical == "app:chatgpt" else self.label_for_key(canonical)
            )
        for category in self.usage.categories():
            candidates[f"category:{category}"] = f"Catégorie · {category}"
        return sorted(candidates.items(), key=lambda item: item[1].lower())

    def limits(self):
        return [
            {"key": key, "target_key": self._policy_target_key(key, policy), "label": self.label_for_key(key), **policy, **self.current_status(key)}
            for key, policy in sorted(
                self.policies.items(), key=lambda item: self.label_for_key(item[0]).lower()
            )
        ]

    def _policy_target_key(self, policy_key, policy=None):
        policy = policy if policy is not None else self.policies.get(policy_key, {})
        return self._canonical_limit_target(policy.get("target_key") or policy_key)

    @staticmethod
    def _normalized_app_name(value):
        return "".join(
            character for character in str(value).casefold() if character.isalnum()
        )

    @staticmethod
    def _canonical_limit_target(target_key):
        key = str(target_key).casefold()
        if key == "app:chatgpt" or key.startswith("app:chatgpt:") or key.startswith("app:chatgpt.com"):
            return "app:chatgpt"
        return str(target_key)

    def _target_for_media_source(self, source):
        normalized_source = self._normalized_app_name(source)
        matches = []
        target_keys = {self._policy_target_key(key, policy) for key, policy in self.policies.items()}
        target_keys.update(self.usage.data.get("targets", {}))
        for raw_key in target_keys:
            if not str(raw_key).startswith("app:"):
                continue
            target_key = self._canonical_limit_target(raw_key)
            executable = self._normalized_app_name(target_key.removeprefix("app:"))
            if executable and executable in normalized_source:
                matches.append((len(executable), target_key))
        return max(matches, default=(0, ""))[1]

    def _windows_for_target(self, target_key):
        expected = self._normalized_app_name(target_key.removeprefix("app:"))
        visible_matches = []
        hidden_matches = []

        @EnumWindowsProc
        def find_window(hwnd, _lparam):
            process_id = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(process_id))
            process = kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, process_id.value
            )
            if not process:
                return True
            try:
                capacity = wintypes.DWORD(32768)
                path = ctypes.create_unicode_buffer(capacity.value)
                if not kernel32.QueryFullProcessImageNameW(
                    process, 0, path, ctypes.byref(capacity)
                ):
                    return True
                executable = path.value.rsplit("\\", 1)[-1].rsplit(".", 1)[0]
                if self._normalized_app_name(executable) == expected:
                    candidate = (int(hwnd), int(process_id.value))
                    if user32.IsWindowVisible(hwnd):
                        visible_matches.append(candidate)
                    else:
                        hidden_matches.append(candidate)
            finally:
                kernel32.CloseHandle(process)
            return True

        user32.EnumWindows(find_window, 0)
        return visible_matches or hidden_matches

    def _window_for_target(self, target_key):
        matches = self._windows_for_target(target_key)
        return matches[0] if matches else (0, 0)

    @staticmethod
    def _format_duration(seconds):
        seconds = max(0, int(round(seconds)))
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours:
            return f"{hours} h {minutes:02d} min {seconds:02d} s"
        if minutes:
            return f"{minutes} min {seconds:02d} s"
        return f"{seconds} s"

    def _refresh_running_limits(self):
        running = []
        for target_key, policy in self.policies.items():
            if not policy["enabled"]:
                continue
            measured_target = self._policy_target_key(target_key, policy)
            if not measured_target.startswith("app:"):
                continue
            windows = self._windows_for_target(measured_target)
            if not windows:
                continue
            handle, process_id = windows[0]
            status = self.current_status(target_key)
            if not status["schedule_active"]:
                continue
            running.append({
                "key": target_key,
                "label": self.label_for_key(target_key),
                "handle": handle,
                "process_id": process_id,
                "handles": [item[0] for item in windows],
                "process_ids": list(dict.fromkeys(item[1] for item in windows)),
                "limit_seconds": policy["limit_seconds"],
                "block_during_validity": bool(policy.get("block_during_validity")),
                **status,
            })
        self._running_limits = running

        # PotPlayer can destroy and recreate its top-level window when a file
        # is closed while keeping the same process alive. Do not interpret
        # that brief window gap as a new launch and send the initial notice
        # again. Forget a token only after its exact process has exited.
        self._notified_handles = {
            token for token in self._notified_handles
            if self._process_exists(token[1])
        }
        for item in running:
            if any(token[0] == item["key"] for token in self._notified_handles):
                continue
            token = (item["key"], item["process_id"])
            self._notified_handles.add(token)
            if self._notification_enabled("limited_app_start", item["key"]):
                message = (
                    "Utilisation interdite pendant la période planifiée."
                    if item.get("block_during_validity")
                    else f"Usage limité : {self._format_duration(item['limit_seconds'])}."
                )
                self._emit_notification(
                    "limited_app_start", item["key"],
                    f"{item['label']} — Usage Guard",
                    message,
                    item["process_id"],
                )
        return running

    @staticmethod
    def _process_exists(process_id):
        if not process_id:
            return False
        process = kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, int(process_id)
        )
        if not process:
            return False
        kernel32.CloseHandle(process)
        return True

    def running_limits(self):
        return list(self._running_limits)

    def observe(self, context, elapsed, countable, media_sessions=None):
        self.prune_expired_limits()
        self._current_web_limit = None
        running_limits = self._refresh_running_limits()
        if self.blocked:
            if self.target_key in self.policies and not self.current_status(self.target_key)["schedule_active"]:
                self.unblock_target()
            else:
                self.follow_target()
                return

        media_sessions = media_sessions or {}
        session_targets = {}
        session_usage_keys = {}
        for source, is_playing in media_sessions.items():
            usage_target_key = self._target_for_media_source(source)
            if not usage_target_key:
                continue
            self._media_target_keys.add(usage_target_key)
            for policy_key in self._policies_for_key(usage_target_key):
                if not self.policies[policy_key]["enabled"]:
                    continue
                session_targets[policy_key] = (
                    session_targets.get(policy_key, False) or bool(is_playing)
                )
                if is_playing:
                    session_usage_keys[policy_key] = usage_target_key

        foreground_target = self.usage.target_for_context(context)
        candidates = [
            target_key
            for target_key, is_playing in session_targets.items()
            if is_playing
        ]
        if countable:
            for policy_key in self._policies_for_target(foreground_target):
                policy = self.policies[policy_key]
                if (
                    policy["enabled"]
                    and not (
                        policy_key == foreground_target.key
                        and foreground_target.key in self._media_target_keys
                    )
                ):
                    candidates.append(policy_key)

        running_by_key = {item["key"]: item for item in running_limits}
        for target_key in dict.fromkeys(candidates):
            if target_key in self._policies_for_target(foreground_target):
                handle = int(context.window_handle or 0)
                process_id = wintypes.DWORD()
                user32.GetWindowThreadProcessId(handle, ctypes.byref(process_id))
                process_id = int(process_id.value)
                label = self.label_for_key(target_key)
                running = running_by_key.get(target_key, {})
            else:
                running = running_by_key.get(target_key, {})
                windows = self._windows_for_target(
                    session_usage_keys.get(target_key, target_key)
                )
                handle, process_id = windows[0] if windows else (0, 0)
                if windows:
                    running = {
                        "handles": [item[0] for item in windows],
                        "process_ids": list(dict.fromkeys(item[1] for item in windows)),
                    }
                label = self.label_for_key(target_key)
            if not handle:
                continue
            self._consume_limit(
                target_key,
                label,
                handle,
                process_id,
                elapsed,
                playback=session_targets.get(target_key, False),
                handles=running.get("handles", [handle]),
                process_ids=running.get("process_ids", [process_id]),
                browser_managed=(
                    foreground_target.key.startswith("site:")
                    and target_key in self._policies_for_target(foreground_target)
                ),
            )
            if self.blocked:
                break
        self._refresh_web_limit(foreground_target)

    def _policies_for_target(self, target):
        """Return direct and shared-category policies applying to one activity."""
        return self._policies_for_key(
            getattr(target, "key", ""), getattr(target, "category", "")
        )

    def _policies_for_key(self, target_key, target_category=""):
        matches = []
        target_key = self._canonical_limit_target(target_key)
        if target_key in self.policies:
            matches.append(target_key)
        for policy_key, policy in self.policies.items():
            if self._policy_target_key(policy_key, policy) == target_key and policy_key not in matches:
                matches.append(policy_key)
        metadata = self.usage.data.get("targets", {}).get(
            target_key, {}
        )
        categories = {
            str(target_category or "").strip(),
            str(metadata.get("category", "") or "").strip(),
            str(metadata.get("site_category", "") or "").strip(),
        }
        categories = {
            ancestor
            for category in categories
            for ancestor in self.usage.category_lineage(category)
        }
        for category in categories:
            key = f"category:{category}"
            if not category:
                continue
            for policy_key, policy in self.policies.items():
                if self._policy_target_key(policy_key, policy) == key and policy_key not in matches:
                    matches.append(policy_key)
        return matches

    def _consume_limit(
        self, target_key, label, handle, process_id, elapsed, playback=False,
        handles=None, process_ids=None, browser_managed=False,
    ):
        policy = self.policies[target_key]
        status = self.current_status(target_key)
        if not status["schedule_active"]:
            return
        notification_token = (target_key, process_id)
        if notification_token not in self._notified_handles:
            self._notified_handles.add(notification_token)
            if self._notification_enabled("limited_app_start", target_key):
                message = (
                    "Utilisation interdite pendant la période planifiée."
                    if policy.get("block_during_validity")
                    else f"Usage limité : {self._format_duration(policy['limit_seconds'])}."
                )
                self._emit_notification(
                    "limited_app_start", target_key,
                    f"{label} — Usage Guard",
                    message,
                    process_id,
                )
        self.target_key = target_key
        self.target_label = label
        self.target_handle = handle
        self.target_handles = list(dict.fromkeys(handles or [handle]))
        self.target_process_id = process_id
        self.target_process_ids = list(dict.fromkeys(process_ids or [process_id]))
        if playback:
            self._playing_seen_at[target_key] = time.monotonic()
        state = self.usage.app_limit_state_for_day(target_key)
        self._notify_extension_started(target_key, state, policy)
        allowed = 0 if policy.get("block_during_validity") else policy["limit_seconds"] + (
            policy["extension_seconds"] if state["extension_used"] else 0
        )
        cutoff_block_token = (target_key, f"cutoff-block:{date.today().isoformat()}")
        if status.get("time_blocked") and cutoff_block_token not in self._warning_shown and self._notification_enabled("limit_warning", target_key):
            self._warning_shown.add(cutoff_block_token)
            self._emit_notification(
                "limit_warning", target_key,
                f"{self.target_label} — heure autorisée dépassée",
                f"L’utilisation est interdite après {policy['blocked_after']}.",
                self.target_process_id,
            )
        if state["seconds"] >= allowed or status.get("time_blocked"):
            if state["seconds"] >= allowed:
                self._notify_limit_reached(target_key, state)
            if not browser_managed:
                self.block_target()
            return
        state = self.usage.add_app_limit_seconds(target_key, elapsed, date.today())
        self._notify_extension_started(target_key, state, policy)
        if state["seconds"] >= allowed:
            self._notify_limit_reached(target_key, state)
            if not browser_managed:
                self.block_target()
            return
        remaining = allowed - state["seconds"]
        for rule_id, warning_seconds in self._warning_rules(target_key):
            warning_token = (
                target_key,
                f"duration:{int(bool(state['extension_used']))}:{rule_id}",
            )
            if remaining > warning_seconds or warning_token in self._warning_shown:
                continue
            self._warning_shown.add(warning_token)
            self._emit_notification(
                "limit_warning", target_key,
                f"{self.target_label} — bientôt terminé",
                f"Il reste {self._format_duration(remaining)} avant le blocage.",
                self.target_process_id, rule_id=rule_id,
            )
        time_remaining = status.get("time_remaining")
        if time_remaining is not None and time_remaining > 0:
            for rule_id, warning_seconds in self._warning_rules(target_key):
                cutoff_token = (
                    target_key,
                    f"cutoff:{date.today().isoformat()}:{rule_id}",
                )
                if time_remaining > warning_seconds or cutoff_token in self._warning_shown:
                    continue
                self._warning_shown.add(cutoff_token)
                self._emit_notification(
                    "limit_warning", target_key,
                    f"{self.target_label} — bientôt interdit",
                    f"Il reste {self._format_duration(time_remaining)} avant l’heure de fin autorisée.",
                    self.target_process_id, rule_id=rule_id,
                )

    def _refresh_web_limit(self, foreground_target):
        if not foreground_target or not foreground_target.key.startswith("site:"):
            self._current_web_limit = None
            return
        states = []
        for target_key in self._policies_for_target(foreground_target):
            policy = self.policies[target_key]
            if not policy["enabled"]:
                continue
            status = self.current_status(target_key)
            if not status["schedule_active"]:
                continue
            states.append({
                "target_key": target_key,
                "label": self.label_for_key(target_key),
                "limit_seconds": policy["limit_seconds"],
                "extension_seconds": policy["extension_seconds"],
                "warning_seconds": policy["warning_seconds"],
                **status,
            })
        self._current_web_limit = min(
            states,
            key=lambda item: (
                item["remaining"] > 0,
                item["remaining"] / max(1, item["allowed"]),
            ),
            default=None,
        )

    def current_web_limit(self):
        return dict(self._current_web_limit) if self._current_web_limit else None

    def web_limit_for_url(self, url):
        """Resolve a web rule immediately for the Browser Bridge request."""
        try:
            parsed = urlparse(str(url))
            host = (parsed.hostname or "").lower().removeprefix("www.")
            if host.rstrip(".") in {"localhost", "127.0.0.1", "::1"} and parsed.port is not None:
                host = f"[{host}]:{parsed.port}" if ":" in host else f"{host}:{parsed.port}"
        except ValueError:
            return None
        if not host:
            return None

        target_keys = [
            key for key in self.usage.data.get("targets", {})
            if str(key).startswith("site:") and str(key).rsplit(":", 1)[-1] == host
        ]
        direct_keys = [
            key for key, policy in self.policies.items()
            if self._policy_target_key(key, policy).startswith("site:")
            and self._policy_target_key(key, policy).rsplit(":", 1)[-1] == host
        ]
        policy_keys = list(direct_keys)
        categories = set()
        for target_key in target_keys:
            metadata = self.usage.data.get("targets", {}).get(target_key, {})
            categories.update((metadata.get("category", ""), metadata.get("site_category", "")))
        categories.update(self.usage.data.get("browser_categories", {}).values())
        categories = {
            ancestor
            for category in categories
            for ancestor in self.usage.category_lineage(category)
        }
        for category in categories:
            category_key = f"category:{category}"
            if not category:
                continue
            for policy_key, policy in self.policies.items():
                if self._policy_target_key(policy_key, policy) == category_key and policy_key not in policy_keys:
                    policy_keys.append(policy_key)

        states = []
        for target_key in policy_keys:
            policy = self.policies[target_key]
            if not policy["enabled"]:
                continue
            status = self.current_status(target_key)
            if not status["schedule_active"]:
                continue
            states.append({
                "target_key": target_key,
                "label": self.label_for_key(target_key),
                "limit_seconds": policy["limit_seconds"],
                "extension_seconds": policy["extension_seconds"],
                "warning_seconds": policy["warning_seconds"],
                **status,
            })
        return min(
            states,
            key=lambda item: (
                item["remaining"] > 0,
                item["remaining"] / max(1, item["allowed"]),
            ),
            default=None,
        )

    def grant_web_extension(self, target_key):
        measured_target = self._policy_target_key(target_key)
        if target_key not in self.policies or not measured_target.startswith(("site:", "category:")):
            return False
        if self.policies[target_key].get("block_during_validity"):
            return False
        granted = self.usage.grant_app_limit_extension(target_key)
        if granted:
            self._warning_shown = {
                token for token in self._warning_shown
                if token[0] != target_key or not str(token[1]).startswith("duration:")
            }
        return granted

    def apply_settings(self, target_key, settings):
        target_key = self._canonical_limit_target(target_key)
        previous = self.policies.get(target_key)
        normalized = self.usage.set_app_limit_settings(target_key, settings)
        self.policies[target_key] = normalized
        if previous is None or any(
            previous[name] != normalized[name]
            for name in ("limit_seconds", "extension_seconds")
        ):
            self.usage.prepare_app_limit(
                target_key, normalized["limit_seconds"], normalized["extension_seconds"],
                measured_target_key=self._policy_target_key(target_key, normalized),
            )
            self._warning_shown = {token for token in self._warning_shown if token[0] != target_key}
        if self.blocked and target_key == self.target_key and not normalized["enabled"]:
            self.unblock_target()
        return normalized

    def remove_limit(self, target_key):
        if self.blocked and target_key == self.target_key:
            self.unblock_target()
        self.usage.remove_app_limit_settings(target_key)
        self.policies.pop(target_key, None)

    def prune_expired_limits(self, now=None):
        now = now or datetime.now().astimezone()
        expired = []
        for target_key, policy in list(self.policies.items()):
            if not policy.get("valid_until"):
                continue
            try:
                expires_at = datetime.combine(
                    date.fromisoformat(str(policy["valid_until"])),
                    datetime.strptime(str(policy.get("valid_until_time") or "23:59"), "%H:%M").time(),
                ).replace(tzinfo=now.tzinfo)
            except (TypeError, ValueError):
                continue
            if now >= expires_at:
                expired.append(target_key)
        for target_key in expired:
            self.remove_limit(target_key)
        return expired

    def reset_today(self, target_key):
        policy = self.policies[target_key]
        self.usage.reset_app_limit_state(target_key)
        self.usage.prepare_app_limit(
            target_key, policy["limit_seconds"], policy["extension_seconds"]
        )
        self._warning_shown = {token for token in self._warning_shown if token[0] != target_key}
        if self.blocked and target_key == self.target_key:
            self.unblock_target()

    def current_status(self, target_key):
        policy = self.policies[target_key]
        state = self.usage.app_limit_state_for_day(target_key)
        allowed = 0 if policy.get("block_during_validity") else policy["limit_seconds"] + (
            policy["extension_seconds"] if state["extension_used"] else 0
        )
        duration_remaining = max(0.0, allowed - state["seconds"])
        schedule = self._schedule_status(policy)
        time_remaining = self._cutoff_remaining(policy) if schedule["active"] else None
        return {
            "seconds": state["seconds"],
            "extension_used": state["extension_used"],
            "allowed": allowed,
            "remaining": max(0.0, min(duration_remaining, time_remaining)) if time_remaining is not None else duration_remaining,
            "time_remaining": time_remaining,
            "time_blocked": time_remaining is not None and time_remaining <= 0,
            "schedule_active": schedule["active"],
            "schedule_pending": schedule["pending"],
        }

    @staticmethod
    def _schedule_status(policy, now=None):
        selected_date = str(policy.get("schedule_date", "")).strip()
        valid_from = str(policy.get("valid_from", "")).strip()
        valid_from_time = str(policy.get("valid_from_time", "00:00")).strip() or "00:00"
        valid_until = str(policy.get("valid_until", "")).strip()
        valid_until_time = str(policy.get("valid_until_time", "23:59")).strip() or "23:59"
        start_text = str(policy.get("schedule_start", "")).strip()
        end_text = str(policy.get("schedule_end", "")).strip()
        now = now or datetime.now().astimezone()
        if valid_from:
            validity_start = datetime.combine(
                date.fromisoformat(valid_from),
                datetime.strptime(valid_from_time, "%H:%M").time(),
            ).replace(tzinfo=now.tzinfo)
            if now < validity_start:
                return {"active": False, "pending": True}
        if valid_until:
            validity_end = datetime.combine(
                date.fromisoformat(valid_until),
                datetime.strptime(valid_until_time, "%H:%M").time(),
            ).replace(tzinfo=now.tzinfo)
            if now >= validity_end:
                return {"active": False, "pending": False}
        if not selected_date and not start_text:
            return {"active": True, "pending": False}
        if not start_text:
            return {"active": True, "pending": False}
        start_time = datetime.strptime(start_text, "%H:%M").time()
        end_time = datetime.strptime(end_text, "%H:%M").time()
        crosses_midnight = end_time < start_time
        if selected_date:
            occurrence_days = [date.fromisoformat(selected_date)]
        else:
            occurrence_days = [now.date()]
            if crosses_midnight:
                occurrence_days.insert(0, now.date() - timedelta(days=1))
        windows = []
        for occurrence_day in occurrence_days:
            start = datetime.combine(occurrence_day, start_time).replace(tzinfo=now.tzinfo)
            end = datetime.combine(
                occurrence_day + timedelta(days=1) if crosses_midnight else occurrence_day,
                end_time,
            ).replace(tzinfo=now.tzinfo)
            windows.append((start, end))
            if start <= now < end:
                return {"active": True, "pending": False}
        if selected_date:
            return {"active": False, "pending": now < windows[0][0]}
        next_start = datetime.combine(now.date(), start_time).replace(tzinfo=now.tzinfo)
        if next_start <= now:
            next_start += timedelta(days=1)
        if valid_until:
            validity_end = datetime.combine(
                date.fromisoformat(valid_until),
                datetime.strptime(valid_until_time, "%H:%M").time(),
            ).replace(tzinfo=now.tzinfo)
            if next_start >= validity_end:
                return {"active": False, "pending": False}
        return {"active": False, "pending": True}

    @staticmethod
    def _schedule_window_end(policy, now=None):
        start_text = str(policy.get("schedule_start", "")).strip()
        end_text = str(policy.get("schedule_end", "")).strip()
        if not start_text or not end_text:
            return None
        now = now or datetime.now().astimezone()
        start_time = datetime.strptime(start_text, "%H:%M").time()
        end_time = datetime.strptime(end_text, "%H:%M").time()
        crosses_midnight = end_time < start_time
        occurrence_days = [now.date()]
        if crosses_midnight:
            occurrence_days.insert(0, now.date() - timedelta(days=1))
        for occurrence_day in occurrence_days:
            start = datetime.combine(occurrence_day, start_time).replace(tzinfo=now.tzinfo)
            end = datetime.combine(
                occurrence_day + timedelta(days=1) if crosses_midnight else occurrence_day,
                end_time,
            ).replace(tzinfo=now.tzinfo)
            if start <= now < end:
                return end
        return None

    @staticmethod
    def _cutoff_remaining(policy, now=None):
        blocked_after = str(policy.get("blocked_after", "")).strip()
        if not blocked_after:
            return None
        now = now or datetime.now().astimezone()
        cutoff_time = datetime.strptime(blocked_after, "%H:%M").time()
        cutoff = datetime.combine(now.date(), cutoff_time).replace(
            tzinfo=now.tzinfo
        )
        return (cutoff - now).total_seconds()

    def block_target(self):
        if not self._valid_target() or self.target_key not in self.policies:
            return
        rect = wintypes.RECT()
        if user32.GetWindowRect(self.target_handle, ctypes.byref(rect)):
            self._target_geometry = (
                rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top
            )
        self._resume_after_extension = (
            time.monotonic() - self._playing_seen_at.get(self.target_key, 0) <= 10
        )
        # PotPlayer ignores APPCOMMAND_MEDIA_PAUSE on some builds but handles
        # the play/pause toggle reliably. Toggle only when Windows reported
        # that this target was actually playing, so a paused player cannot be
        # started accidentally.
        self._send_media_command(
            APPCOMMAND_MEDIA_PLAY_PAUSE
            if self._resume_after_extension
            else APPCOMMAND_MEDIA_PAUSE
        )
        for handle in self.target_handles or [self.target_handle]:
            if user32.IsWindow(handle):
                user32.EnableWindow(handle, False)
                user32.ShowWindow(handle, SW_HIDE)
        self.blocked = True
        state = self.usage.app_limit_state_for_day(self.target_key)
        policy = self.policies[self.target_key]
        self.overlay.configure(
            self.target_label,
            not state["extension_used"] and not policy.get("block_during_validity"),
            policy["extension_seconds"],
            bool(policy.get("block_during_validity")),
        )
        self.position_overlay()
        self.overlay.show()
        self.overlay.raise_()
        self.overlay.activateWindow()

    def _send_media_command(self, command):
        if not self._valid_target():
            return
        result = ctypes.c_size_t()
        user32.SendMessageTimeoutW(
            self.target_handle, WM_APPCOMMAND, self.target_handle, command << 16,
            SMTO_ABORTIFHUNG, 1000, ctypes.byref(result),
        )

    def grant_extension(self):
        if (
            not self.target_key
            or self.policies.get(self.target_key, {}).get("block_during_validity")
            or not self.usage.grant_app_limit_extension(self.target_key)
        ):
            return
        self._warning_shown = {
            token for token in self._warning_shown
            if token[0] != self.target_key or not str(token[1]).startswith("duration:")
        }
        should_resume = self._resume_after_extension
        self.unblock_target()
        self._resume_after_extension = False
        if should_resume:
            # PotPlayer and several other players ignore MEDIA_PLAY after
            # their hidden window is restored, but reliably handle the toggle.
            QTimer.singleShot(
                400,
                lambda: self._send_media_command(APPCOMMAND_MEDIA_PLAY_PAUSE),
            )

    def unblock_target(self):
        restored = 0
        for handle in self.target_handles or [self.target_handle]:
            if not user32.IsWindow(handle):
                continue
            user32.EnableWindow(handle, True)
            user32.ShowWindow(handle, SW_SHOW)
            restored = restored or handle
        if restored:
            user32.SetForegroundWindow(restored)
        self.blocked = False
        self.overlay.hide()

    def close_target(self):
        process_ids = {
            int(process_id)
            for process_id in (self.target_process_ids or [self.target_process_id])
            if process_id
        }
        if process_ids:
            # Stop playback immediately, before asking the application to
            # close. This prevents a hidden player process from continuing to
            # emit sound during the graceful-close delay.
            self._send_media_command(APPCOMMAND_MEDIA_PAUSE)

            # Ask every top-level window owned by every matching process to
            # close. Some players keep playback in a secondary process.
            @EnumWindowsProc
            def close_window(hwnd, _lparam):
                window_process_id = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(window_process_id))
                if window_process_id.value in process_ids:
                    user32.EnableWindow(hwnd, True)
                    user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
                return True

            user32.EnumWindows(close_window, 0)
            for process_id in process_ids:
                QTimer.singleShot(
                    1500,
                    lambda pid=process_id: self._force_close_process(pid),
                )
        self.blocked = False
        self.overlay.hide()

    @staticmethod
    def _force_close_process(process_id):
        """Terminate only the selected application if graceful close failed."""
        handle = kernel32.OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, False, process_id
        )
        if not handle:
            return
        try:
            kernel32.TerminateProcess(handle, 0)
        finally:
            kernel32.CloseHandle(handle)

    def follow_target(self):
        if not self.blocked:
            return
        valid_handles = [
            handle for handle in (self.target_handles or [self.target_handle])
            if user32.IsWindow(handle)
        ]
        if not valid_handles:
            self.blocked = False
            self.overlay.hide()
            return
        for handle in valid_handles:
            user32.EnableWindow(handle, False)
            user32.ShowWindow(handle, SW_HIDE)

    def position_overlay(self):
        if self._target_geometry is not None:
            self.overlay.setGeometry(*self._target_geometry)
            return
        rect = wintypes.RECT()
        if user32.GetWindowRect(self.target_handle, ctypes.byref(rect)):
            self.overlay.setGeometry(
                rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top
            )

    def _valid_target(self):
        return bool(self.target_handle and user32.IsWindow(self.target_handle))
