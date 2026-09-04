"""Foreground-only application limits for Windows."""

import copy
import ctypes
import subprocess
import sys
import time
from ctypes import wintypes
from datetime import date, datetime, timedelta
from urllib.parse import urlparse

from PySide6.QtCore import QObject, Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QApplication, QHBoxLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout,
    QWidget,
)
from i18n import _
from command_policy import (
    SOURCE_BACKEND, SOURCE_INTERNAL, SOURCE_LOCAL_ADMIN, is_backend_managed,
)
from limit_decision import evaluate_limit
from runtime_profile import current_profile


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
    user32.SetWindowPos.argtypes = (
        wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
        ctypes.c_int, ctypes.c_int, wintypes.UINT,
    )
    user32.SetWindowPos.restype = wintypes.BOOL
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
HWND_TOPMOST = wintypes.HWND(-1)
SWP_NOSIZE = 0x0001
SWP_NOMOVE = 0x0002
SWP_SHOWWINDOW = 0x0040
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

    def configure(
        self, label, available, extension_seconds, extension_unit="seconds",
        period_block=False,
    ):
        self.setWindowTitle(_("{label} — limite atteinte").format(label=label))
        self.close_button.setText(_("Fermer {label}").format(label=label))
        self.extension_button.setVisible(not period_block)
        self.extension_button.setEnabled(available)
        self.extension_button.setText(
            _("Obtenir une rallonge exceptionnelle de {duration}").format(
                duration=AppLimiter._format_configured_duration(
                    extension_seconds, extension_unit,
                )
            )
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
        self.controller = controller
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
        self.grace_button = QPushButton(_("Enregistrer et fermer — 5 min"))
        self.grace_button.setStyleSheet(
            "padding:10px 18px; background:#b44b2a; border:1px solid #ffbb8b; font-weight:700;"
        )
        self.grace_button.clicked.connect(controller.start_computer_close_grace)
        self.shutdown_button = QPushButton(_("Arrêter l’ordinateur"))
        self.restart_button = QPushButton(_("Redémarrer l’ordinateur"))
        for button in (self.shutdown_button, self.restart_button):
            button.setStyleSheet(
                "padding:10px 18px; background:#303036; border:1px solid #d7d7dc;"
            )
        self.shutdown_button.clicked.connect(controller.shutdown_computer)
        self.restart_button.clicked.connect(controller.restart_computer)
        self.cancel_button = QPushButton(_("Lever l’interdiction"))
        self.cancel_button.setStyleSheet("padding:10px 18px; background:#5c252b; border:1px solid #ff8b8b;")
        self.cancel_button.clicked.connect(controller.clear_computer_block)
        self.admin_access_button = QPushButton(_("Accès administrateur"))
        self.admin_access_button.setToolTip(_("Raccourci : Ctrl+Alt+L"))
        self.admin_access_button.setStyleSheet(
            "padding:4px 8px; color:#a98e92; background:transparent; "
            "border:0; text-decoration:underline; font-size:11px;"
        )
        self.admin_access_button.clicked.connect(self._toggle_admin_access)
        self.admin_access = QWidget()
        self.admin_access.setStyleSheet(
            "background:#32181c; border:1px solid #6f3a42; border-radius:7px;"
        )
        admin_layout = QVBoxLayout(self.admin_access)
        admin_layout.setContentsMargins(14, 12, 14, 12)
        admin_layout.setSpacing(7)
        self.admin_username = QLineEdit()
        self.admin_username.setPlaceholderText(_("Identifiant administrateur"))
        self.admin_password = QLineEdit()
        self.admin_password.setPlaceholderText(_("Mot de passe"))
        self.admin_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.admin_status = QLabel()
        self.admin_status.setStyleSheet("color:#ffb4b4; border:0; font-size:12px;")
        self.admin_submit = QPushButton(_("Déverrouiller"))
        self.admin_submit.clicked.connect(self._submit_admin_access)
        self.admin_password.returnPressed.connect(self._submit_admin_access)
        for widget in (
            self.admin_username, self.admin_password, self.admin_status,
            self.admin_submit,
        ):
            admin_layout.addWidget(widget)
        self.admin_access.hide()
        actions = QHBoxLayout()
        actions.addStretch()
        actions.addWidget(self.shutdown_button)
        actions.addWidget(self.restart_button)
        actions.addWidget(self.grace_button)
        actions.addWidget(self.cancel_button)
        actions.addStretch()
        layout.addStretch()
        layout.addWidget(title)
        layout.addWidget(self.message)
        layout.addLayout(actions)
        layout.addStretch()
        layout.addWidget(self.admin_access_button, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.admin_access, alignment=Qt.AlignmentFlag.AlignCenter)

    def _toggle_admin_access(self):
        visible = self.admin_access.isHidden()
        self.admin_access.setVisible(visible)
        self.admin_status.clear()
        if visible:
            self.admin_username.setFocus()

    def _submit_admin_access(self):
        username = self.admin_username.text().strip()
        password = self.admin_password.text()
        if not username or not password:
            self.admin_status.setText(_("Renseignez l’identifiant et le mot de passe."))
            return
        self.admin_submit.setEnabled(False)
        try:
            result = self.controller.unlock_computer_block(username, password)
        except Exception:
            result = {"ok": False, "error": _("Connexion administrateur refusée.")}
        finally:
            self.admin_submit.setEnabled(True)
            self.admin_password.clear()
        if result and result.get("ok"):
            self.admin_username.clear()
            self.admin_status.clear()
            self.admin_access.hide()
            return
        self.admin_status.setText(str(
            (result or {}).get("error") or _("Connexion administrateur refusée.")
        ))

    def keyPressEvent(self, event):
        if (
            event.key() == Qt.Key.Key_L
            and event.modifiers()
            & (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.AltModifier)
            == (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.AltModifier)
        ):
            self._toggle_admin_access()
            event.accept()
            return
        super().keyPressEvent(event)

    def closeEvent(self, event):
        event.ignore()

    def show_block(self, ends_at, can_cancel=True, grace_available=True):
        end = datetime.fromisoformat(str(ends_at))
        self.message.setText(
            _("Blocage actif jusqu’au {time}. Enregistrez vos documents avec le joker, ou arrêtez/redémarrez Windows normalement.").format(
                time=end.astimezone().strftime("%d/%m/%Y à %H:%M")
            )
        )
        self.grace_button.setEnabled(bool(grace_available))
        self.grace_button.setText(
            _("Enregistrer et fermer — 5 min")
            if grace_available else _("Joker de fermeture déjà utilisé")
        )
        self.cancel_button.setVisible(bool(can_cancel))
        self.admin_access_button.setVisible(bool(
            getattr(self.controller, "admin_unlock_handler", None)
        ))
        screens = QApplication.screens()
        if screens:
            geometry = screens[0].geometry()
            for screen in screens[1:]:
                geometry = geometry.united(screen.geometry())
            self.setGeometry(geometry)
            # The global limitation deliberately covers the taskbar as well.
            # Shutdown/restart remain available from the overlay itself.
            self.clearMask()
        # Win+D or a previous minimized occurrence must not leave an active
        # whole-computer rule represented only by its ON switch. Restore the
        # same window and reaffirm its native topmost state on every refresh.
        self.setWindowState(
            self.windowState() & ~Qt.WindowState.WindowMinimized
        )
        self.show()
        if sys.platform == "win32":
            native_handle = int(self.winId())
            user32.SetWindowPos(
                native_handle, HWND_TOPMOST, 0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW,
            )
            user32.SetForegroundWindow(native_handle)
        self.raise_()
        self.activateWindow()


class ComputerGraceWindow(QWidget):
    """Persistent countdown shown while the desktop is temporarily unblocked."""

    def __init__(self, controller):
        super().__init__(
            None,
            Qt.WindowType.Tool
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint,
        )
        self.setWindowTitle(_("Joker de fermeture — Usage Guard"))
        self.setStyleSheet(
            "background:#4a2416; color:white; border:2px solid #ff9d66; border-radius:8px;"
        )
        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 12, 18, 12)
        self.message = QLabel()
        self.message.setStyleSheet("font-size:15px; font-weight:700; border:none;")
        shutdown = QPushButton(_("Arrêter"))
        restart = QPushButton(_("Redémarrer"))
        shutdown.clicked.connect(controller.shutdown_computer)
        restart.clicked.connect(controller.restart_computer)
        layout.addWidget(self.message)
        layout.addWidget(shutdown)
        layout.addWidget(restart)

    def closeEvent(self, event):
        event.ignore()

    def show_countdown(self, ends_at, now=None):
        now = now or datetime.now().astimezone()
        end = datetime.fromisoformat(str(ends_at))
        remaining = max(0, int((end - now).total_seconds()))
        minutes, seconds = divmod(remaining, 60)
        self.message.setText(
            _("Enregistrez et fermez vos applications — reblocage dans {minutes:02d}:{seconds:02d}").format(
                minutes=minutes, seconds=seconds
            )
        )
        screen = QApplication.primaryScreen()
        if screen:
            available = screen.availableGeometry()
            self.adjustSize()
            self.move(
                available.center().x() - self.width() // 2,
                available.bottom() - self.height() - 16,
            )
        self.show()
        self.raise_()


class AppLimiter(QObject):
    """Manage independent daily foreground limits for configured applications."""

    notification_requested = Signal(str, str, int)
    email_notification_requested = Signal(str, str, str, str)

    def __init__(
        self, usage, limit_seconds=15, extension_seconds=15, warning_seconds=5,
        decision_mirror=None, admin_unlock_handler=None,
    ):
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
        self.admin_unlock_handler = admin_unlock_handler
        self.overlay = LimitOverlay(self)
        self.computer_overlay = ComputerBlockOverlay(self)
        self.computer_grace_window = ComputerGraceWindow(self)
        self._target_geometry = None
        self._notified_handles = set()
        self._warning_shown = set()
        self._computer_block_warning_shown = set()
        self._playing_seen_at = {}
        self._running_limits = []
        self._decision_mirror_checks = 0
        self._decision_mirror_mismatches = 0
        self._decision_mirror_last_mismatch = None
        self._decision_mirror_failures = 0
        self._decision_mirror = decision_mirror
        # PotPlayer is the seeded media limit. Other applications join this
        # set automatically as soon as Windows exposes a media session for
        # them, including a PAUSED or STOPPED session.
        self._media_target_keys = {
            key for key in self.policies if "potplayer" in key.casefold()
        }
        self._resume_after_extension = False
        self._current_web_limit = None
        self._personal_usage = {}
        self._personal_usage_baselines = {}
        self._displayed_computer_block = {}
        self.follow_timer = QTimer(self)
        self.follow_timer.setInterval(250)
        self.follow_timer.timeout.connect(self.follow_target)
        self.follow_timer.start()

    def _stored_computer_blocks(self):
        getter = getattr(self.usage, "computer_blocks", None)
        if callable(getter):
            return [dict(item) for item in getter()]
        collection = self.usage.data.get("computer_blocks")
        if isinstance(collection, list):
            return [dict(item) for item in collection if isinstance(item, dict)]
        legacy = self.usage.data.get("computer_block", {})
        return [dict(legacy)] if isinstance(legacy, dict) and legacy else []

    @staticmethod
    def _computer_block_sort_timestamp(status, key):
        try:
            return datetime.fromisoformat(str(status.get(key) or "")).timestamp()
        except (TypeError, ValueError):
            return float("inf")

    @classmethod
    def _effective_computer_block(cls, statuses):
        def priority(status):
            if status.get("active"):
                return (
                    0, cls._computer_block_sort_timestamp(status, "ends_at"),
                    cls._computer_block_sort_timestamp(status, "started_at"),
                    str(status.get("block_id") or ""),
                )
            if status.get("pending"):
                return (
                    1, cls._computer_block_sort_timestamp(status, "started_at"),
                    cls._computer_block_sort_timestamp(status, "ends_at"),
                    str(status.get("block_id") or ""),
                )
            return (
                2 if status.get("enabled") else 3,
                cls._computer_block_sort_timestamp(status, "ends_at"),
                float("inf"), str(status.get("block_id") or ""),
            )
        return dict(min(statuses, key=priority)) if statuses else {}

    @staticmethod
    def _schedule_computer_block_status(block, now):
        start_time = datetime.strptime(block["daily_start"], "%H:%M").time()
        end_time = datetime.strptime(block["daily_end"], "%H:%M").time()
        if end_time == start_time:
            raise ValueError("Heures de blocage identiques.")
        crosses_midnight = end_time < start_time
        first_day = (
            date.fromisoformat(str(block["valid_from"]))
            if block.get("valid_from") else None
        )
        last_day = (
            date.fromisoformat(str(block["valid_until"]))
            if block.get("valid_until") else None
        )
        first_boundary = (
            datetime.combine(
                first_day,
                datetime.strptime(
                    str(block.get("valid_from_time") or "00:00"), "%H:%M"
                ).time(),
            ).replace(tzinfo=now.tzinfo)
            if first_day else None
        )
        last_boundary = (
            datetime.combine(
                last_day,
                datetime.strptime(
                    str(block.get("valid_until_time") or "23:59"), "%H:%M"
                ).time(),
            ).replace(tzinfo=now.tzinfo)
            if last_day else None
        )
        if last_boundary and now >= last_boundary:
            return {**block, "active": False, "pending": False}
        occurrence_day = now.date()
        if crosses_midnight and now.time().replace(tzinfo=None) < end_time:
            occurrence_day -= timedelta(days=1)
        if first_day:
            occurrence_day = max(occurrence_day, first_day)
        while True:
            raw_start = datetime.combine(
                occurrence_day, start_time
            ).replace(tzinfo=now.tzinfo)
            raw_end = datetime.combine(
                occurrence_day + timedelta(days=1)
                if crosses_midnight else occurrence_day,
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
        return {
            **block,
            "started_at": starts_at.isoformat(timespec="seconds"),
            "ends_at": ends_at.isoformat(timespec="seconds"),
            "active": active,
            "pending": not active and now < starts_at,
        }

    def _computer_block_status(self, block, now):
        block = dict(block or {})
        if not block.get("enabled"):
            return {**block, "active": False, "pending": False}
        try:
            if block.get("mode") == "daily_duration":
                if block.get("schedule_start") and block.get("schedule_end"):
                    schedule = self._schedule_computer_block_status({
                        **block,
                        "daily_start": block.get("schedule_start"),
                        "daily_end": block.get("schedule_end"),
                    }, now)
                else:
                    starts_at = datetime.combine(
                        now.date(), datetime.min.time()
                    ).replace(tzinfo=now.tzinfo)
                    ends_at = starts_at + timedelta(days=1)
                    if block.get("valid_from"):
                        starts_at = max(starts_at, datetime.combine(
                            date.fromisoformat(str(block["valid_from"])),
                            datetime.strptime(
                                str(block.get("valid_from_time") or "00:00"),
                                "%H:%M",
                            ).time(),
                        ).replace(tzinfo=now.tzinfo))
                    if block.get("valid_until"):
                        ends_at = min(ends_at, datetime.combine(
                            date.fromisoformat(str(block["valid_until"])),
                            datetime.strptime(
                                str(block.get("valid_until_time") or "23:59"),
                                "%H:%M",
                            ).time(),
                        ).replace(tzinfo=now.tzinfo))
                    schedule = {
                        **block,
                        "started_at": starts_at.isoformat(timespec="seconds"),
                        "ends_at": ends_at.isoformat(timespec="seconds"),
                        "active": starts_at <= now < ends_at,
                        "pending": now < starts_at,
                    }
                used = float(
                    self.usage.system_usage_for_day(now.date()).get("on", 0.0)
                )
                allowed = max(60, int(block.get("limit_seconds", 60)))
                return {
                    **schedule,
                    "active": bool(schedule["active"] and used >= allowed),
                    "pending": bool(
                        schedule["pending"]
                        or (schedule["active"] and used < allowed)
                    ),
                    "seconds": round(used, 1),
                    "allowed": allowed,
                    "remaining": max(0.0, allowed - used),
                    "schedule_active": schedule["active"],
                    "schedule_pending": schedule["pending"],
                }
            if block.get("mode") == "schedule":
                return self._schedule_computer_block_status(block, now)
            starts_at = datetime.fromisoformat(str(block["started_at"]))
            ends_at = datetime.fromisoformat(str(block["ends_at"]))
            active = starts_at < ends_at and starts_at <= now < ends_at
            pending = starts_at < ends_at and now < starts_at
        except (KeyError, TypeError, ValueError):
            active = pending = False
        return {**block, "active": active, "pending": pending}

    def computer_block_statuses(self, now=None):
        now = now or datetime.now().astimezone()
        return [
            self._computer_block_status(block, now)
            for block in self._stored_computer_blocks()
        ]

    def computer_block_status(self, now=None, block_id=None):
        statuses = self.computer_block_statuses(now)
        if block_id is not None:
            wanted = str(block_id)
            return dict(next((
                item for item in statuses
                if str(item.get("block_id") or "") == wanted
            ), {}))
        return self._effective_computer_block(statuses)

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

    def _clear_computer_block_record(self, block_id):
        try:
            return self.usage.clear_computer_block(block_id)
        except TypeError:
            return self.usage.clear_computer_block()

    def _set_effective_computer_block_mirror(self, status):
        setter = getattr(self.usage, "set_effective_computer_block", None)
        if callable(setter):
            setter(status or None)

    @staticmethod
    def _computer_block_validity_expired(block, now):
        if not block.get("valid_until"):
            return False
        try:
            expires_at = datetime.combine(
                date.fromisoformat(str(block["valid_until"])),
                datetime.strptime(
                    str(block.get("valid_until_time") or "23:59"), "%H:%M"
                ).time(),
            ).replace(tzinfo=now.tzinfo)
        except (TypeError, ValueError):
            return False
        return now >= expires_at

    @classmethod
    def _computer_block_record_expired(cls, block, now):
        if block.get("delete_after_expiry", True) is False:
            return False
        if cls._computer_block_validity_expired(block, now):
            return True
        if not block.get("enabled") or block.get("mode") in {
            "schedule", "daily_duration",
        }:
            return False
        try:
            return now >= datetime.fromisoformat(str(block["ends_at"]))
        except (KeyError, TypeError, ValueError):
            return False

    @staticmethod
    def _status_occurrence_matches(status, occurrence):
        wanted = dict(occurrence or {})
        return bool(
            status.get("active")
            and str(status.get("block_id") or "")
            == str(wanted.get("block_id") or "")
            and str(status.get("started_at") or "")
            == str(wanted.get("started_at") or "")
            and str(status.get("ends_at") or "")
            == str(wanted.get("ends_at") or "")
        )

    def refresh_computer_block(self, now=None):
        now = now or datetime.now().astimezone()
        grace_window = getattr(self, "computer_grace_window", None)
        expired_ids = [
            str(block.get("block_id") or "")
            for block in self._stored_computer_blocks()
            if self._computer_block_record_expired(block, now)
        ]
        for block_id in expired_ids:
            self._clear_computer_block_record(block_id or None)
        if expired_ids:
            expired = set(expired_ids)
            self._computer_block_warning_shown = {
                token for token in self._computer_block_warning_shown
                if str(token[0]) not in expired
            }

        statuses = self.computer_block_statuses(now)
        effective = self._effective_computer_block(statuses)
        self._set_effective_computer_block_mirror(effective)

        for status in statuses:
            if not status.get("pending"):
                continue
            starts_at = datetime.fromisoformat(str(status["started_at"]))
            remaining = max(0, (starts_at - now).total_seconds())
            for rule_id, warning_seconds in self._warning_rules("computer:all"):
                token = (
                    str(status.get("block_id") or ""),
                    str(status["started_at"]), rule_id,
                )
                if (
                    remaining > warning_seconds
                    or token in self._computer_block_warning_shown
                ):
                    continue
                self._computer_block_warning_shown.add(token)
                actor = str(status.get("actor") or "Utilisateur local")
                warning_only = status.get("enforcement_action") == "warn"
                self._emit_notification(
                    "limit_warning", "computer:all",
                    (
                        f"Avertissement planifié par {actor} — Usage Guard"
                        if warning_only else
                        f"Blocage imminent demandé par {actor} — Usage Guard"
                    ),
                    (
                        f"La période surveillée commencera dans {self._format_duration(remaining)} et durera jusqu’au {datetime.fromisoformat(status['ends_at']).astimezone().strftime('%d/%m/%Y à %H:%M')}."
                        if warning_only else
                        f"La limitation de l’ordinateur commencera dans {self._format_duration(remaining)} et durera jusqu’au {datetime.fromisoformat(status['ends_at']).astimezone().strftime('%d/%m/%Y à %H:%M')}."
                    ),
                    0, rule_id=rule_id,
                )

        for status in statuses:
            if (
                not status.get("active")
                or status.get("enforcement_action") != "warn"
            ):
                continue
            token = (
                str(status.get("block_id") or ""),
                str(status.get("started_at") or ""),
                "warn-action-active",
            )
            if token in self._computer_block_warning_shown:
                continue
            self._computer_block_warning_shown.add(token)
            actor = str(status.get("actor") or "Utilisateur local")
            title = f"Avertissement demandé par {actor} — Usage Guard"
            message = (
                "La période surveillée de l’ordinateur est atteinte ; "
                "son utilisation reste autorisée."
            )
            rules = self._notification_rules("limit_reached", "computer:all")
            if not any(
                "windows" in (rule.get("channels") or ["windows"])
                for rule in rules
            ):
                self.notification_requested.emit(title, message, 0)
            if rules:
                self._emit_notification(
                    "limit_reached", "computer:all", title, message, 0,
                )

        active = [
            status for status in statuses
            if status.get("active")
            and status.get("enforcement_action") != "warn"
        ]
        grace_by_id = {
            str(status.get("block_id") or ""): self._computer_close_grace(status)
            for status in active
        }
        enforcing = [
            status for status in active
            if not grace_by_id[str(status.get("block_id") or "")].get("active")
        ]
        if enforcing:
            displayed = self._effective_computer_block(enforcing)
            grace = grace_by_id[str(displayed.get("block_id") or "")]
            displayed["close_grace"] = grace
            self._displayed_computer_block = self._computer_block_occurrence(displayed)
            if grace_window is not None:
                grace_window.hide()
            self.computer_overlay.show_block(
                displayed["ends_at"],
                can_cancel=(
                    not self._decision_core_enabled()
                    or not is_backend_managed(displayed)
                ),
                grace_available=bool(grace.get("available")),
            )
            return displayed

        self._displayed_computer_block = {}
        self.computer_overlay.hide()
        active_graces = [
            grace_by_id[str(status.get("block_id") or "")]
            for status in active
            if grace_by_id[str(status.get("block_id") or "")].get("active")
        ]
        if grace_window is not None:
            if active_graces:
                grace = min(
                    active_graces,
                    key=lambda item: str(item.get("ends_at") or ""),
                )
                grace_window.show_countdown(grace["ends_at"], now)
            else:
                grace_window.hide()
        if effective.get("active"):
            effective["close_grace"] = grace_by_id.get(
                str(effective.get("block_id") or ""), {}
            )
        return effective

    @staticmethod
    def _computer_block_occurrence(status):
        return {
            "block_id": str(status.get("block_id") or ""),
            "mode": str(status.get("mode") or ""),
            "started_at": str(status.get("started_at") or ""),
            "ends_at": str(status.get("ends_at") or ""),
            "grace_seconds": int(status.get("grace_seconds", 300) or 300),
        }

    def _computer_close_grace(self, status, start=False):
        service = getattr(self, "_decision_mirror", None)
        if service is None:
            return {
                "state": "unavailable", "available": False,
                "active": False, "used": False,
            }
        try:
            return service.computer_block_grace(
                self._computer_block_occurrence(status), start=start
            )
        except (OSError, EOFError, RuntimeError, ValueError):
            return {
                "state": "unavailable", "available": False,
                "active": False, "used": False,
            }

    def computer_block_snapshot(self, now=None):
        status = self.computer_block_status(now)
        if status.get("active"):
            status["close_grace"] = self._computer_close_grace(status)
        return status

    def computer_blocks_snapshot(self, now=None):
        statuses = self.computer_block_statuses(now)
        for status in statuses:
            if status.get("active"):
                status["close_grace"] = self._computer_close_grace(status)
        return statuses

    def displayed_computer_block(self):
        return dict(getattr(self, "_displayed_computer_block", {}) or {})

    def start_computer_close_grace(self):
        occurrence = self.displayed_computer_block()
        status = self.computer_block_status(
            block_id=occurrence.get("block_id")
        ) if occurrence else {}
        if not self._status_occurrence_matches(status, occurrence):
            return False
        grace = self._computer_close_grace(status, start=True)
        if not grace.get("active"):
            return False
        self.refresh_computer_block()
        return True

    @staticmethod
    def _launch_power_operation(operation):
        argument = "/s" if operation == "shutdown" else "/r"
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        return subprocess.Popen(
            ["shutdown.exe", argument, "/t", "0"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=flags,
        )

    def request_power_operation(self, operation):
        if operation not in {"shutdown", "restart"}:
            raise ValueError("Opération d’alimentation invalide.")
        self.computer_overlay.hide()
        grace_window = getattr(self, "computer_grace_window", None)
        if grace_window is not None:
            grace_window.hide()
        launcher = getattr(self, "_power_launcher", self._launch_power_operation)
        launcher(operation)
        return True

    def shutdown_computer(self):
        return self.request_power_operation("shutdown")

    def restart_computer(self):
        return self.request_power_operation("restart")

    def unlock_computer_block(self, username, password):
        """Delegate a discreet administrator unlock to the protected service."""
        handler = self.admin_unlock_handler
        if not callable(handler):
            return {
                "ok": False,
                "error": _("Déverrouillage administrateur indisponible."),
            }
        return dict(handler(username, password) or {})

    def clear_computer_block(self):
        occurrence = self.displayed_computer_block()
        block_id = str(occurrence.get("block_id") or "")
        status = self.computer_block_status(block_id=block_id) if block_id else {}
        if not self._status_occurrence_matches(status, occurrence):
            return False
        if self._decision_core_enabled() and is_backend_managed(status):
            return False
        self._clear_computer_block_record(block_id)
        self._computer_block_warning_shown = {
            token for token in self._computer_block_warning_shown
            if str(token[0]) != block_id
        }
        self.refresh_computer_block()
        return True

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

    def activate_personal_policy(self, owner, revision, limits):
        """Atomically overlay server rules while retaining local settings."""
        owner = str(owner or "").strip()
        revision = int(revision)
        if not owner or revision < 1 or not isinstance(limits, list):
            raise ValueError("Politique personnelle invalide.")
        desired = {}
        for source in limits:
            if not isinstance(source, dict):
                raise ValueError("Limite personnelle invalide.")
            key = self._canonical_limit_target(
                str(source.get("key") or source.get("target_key") or "").strip()
            )
            measured_target = self._canonical_limit_target(
                str(source.get("target_key") or key).strip()
            )
            if (
                not key.startswith(("app:", "site:", "category:"))
                or not measured_target.startswith(
                    ("app:", "site:", "category:")
                )
                or key in desired
            ):
                raise ValueError("Cible de limite personnelle invalide.")
            settings = {
                name: value for name, value in source.items()
                if name not in {"key", "operation_id"}
            }
            settings["managed_by"] = "backend"
            settings["target_key"] = measured_target
            desired[key] = self.usage.normalize_app_limit_settings(key, settings)

        overlay = dict(self.usage.data.get("personal_policy_overlay") or {})
        if (
            overlay.get("active")
            and str(overlay.get("owner") or "").casefold() != owner.casefold()
        ):
            raise ValueError("Une politique d’un autre utilisateur est active.")
        if (
            overlay.get("active")
            and int(overlay.get("revision") or 0) == revision
            and self.usage.data.get("app_limit_settings") == desired
        ):
            return copy.deepcopy(desired)
        backup = (
            copy.deepcopy(overlay.get("local_settings"))
            if overlay.get("active")
            else copy.deepcopy(self.usage.data.get("app_limit_settings", {}))
        )
        if not isinstance(backup, dict):
            raise ValueError("Sauvegarde des limites locales invalide.")

        self.usage.data["app_limit_settings"] = copy.deepcopy(desired)
        self.usage.data["personal_policy_overlay"] = {
            "active": True,
            "owner": owner,
            "revision": revision,
            "local_settings": backup,
        }
        self.usage._dirty = True
        self.usage.save(force=True)
        self._reload_policies()
        if self.blocked and (
            self.target_key not in self.policies
            or not self.policies[self.target_key].get("enabled")
        ):
            self.unblock_target()
        return copy.deepcopy(desired)

    def deactivate_personal_policy(self):
        """Restore the exact local settings saved before the server overlay."""
        overlay = dict(self.usage.data.get("personal_policy_overlay") or {})
        if not overlay.get("active"):
            return False
        backup = overlay.get("local_settings")
        if not isinstance(backup, dict):
            raise ValueError("Sauvegarde des limites locales invalide.")
        self.usage.data["app_limit_settings"] = copy.deepcopy(backup)
        self.usage.data["personal_policy_overlay"] = {}
        self.usage._dirty = True
        self.usage.save(force=True)
        self._reload_policies()
        if self.blocked and (
            self.target_key not in self.policies
            or not self.policies[self.target_key].get("enabled")
        ):
            self.unblock_target()
        self.clear_personal_usage()
        return True

    def set_personal_usage(self, usage_state):
        """Use a server-unioned snapshot plus this PC's subsequent activity."""
        source = dict(usage_state or {})
        totals = source.get("totals")
        if not isinstance(totals, dict):
            self.clear_personal_usage()
            return False
        token = (
            str(source.get("usage_guard_username") or ""),
            int(source.get("policy_revision") or 0),
            str(source.get("measured_at") or ""),
        )
        if token != self._personal_usage.get("token"):
            normalized = {}
            baselines = {}
            for key, value in totals.items():
                try:
                    seconds = max(0.0, float(dict(value).get("seconds", 0.0)))
                except (TypeError, ValueError):
                    continue
                normalized[str(key)] = seconds
                baselines[str(key)] = float(
                    self.usage.app_limit_state_for_day(str(key))["seconds"]
                )
            self._personal_usage = {"token": token, "totals": normalized}
            self._personal_usage_baselines = baselines
        return True

    def clear_personal_usage(self):
        self._personal_usage = {}
        self._personal_usage_baselines = {}

    def _effective_limit_state(self, target_key):
        state = dict(self.usage.app_limit_state_for_day(target_key))
        policy = self.policies.get(target_key, {})
        personal_usage = getattr(self, "_personal_usage", {})
        remote = personal_usage.get("totals", {}).get(target_key)
        if policy.get("managed_by") != "backend" or remote is None:
            return state
        baselines = getattr(self, "_personal_usage_baselines", {})
        baseline = float(baselines.get(target_key, state["seconds"]))
        state["seconds"] = max(
            float(state["seconds"]),
            float(remote) + max(0.0, float(state["seconds"]) - baseline),
        )
        return state

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
        windows_rule = next((
            rule for rule in rules
            if "windows" in (rule.get("channels") or ["windows"])
        ), None)
        if windows_rule:
            self.notification_requested.emit(
                title, message, int(process_id or 0)
            )
        signal = getattr(self, "email_notification_requested", None)
        recipient_rules = {}
        for rule in rules:
            recipient = str(rule.get("email_recipient", "")).strip()
            if "email" in (rule.get("channels") or ["windows"]) and recipient:
                recipient_rules.setdefault(recipient, rule)
        for recipient in sorted(recipient_rules):
            if signal is not None:
                signal.emit(kind, title, message, recipient)

    def _notify_limit_reached(self, target_key, state, warning_only=False):
        token = (
            target_key,
            f"duration-reached:{int(bool(state.get('extension_used')))}:{date.today().isoformat()}",
        )
        configured = self._notification_enabled("limit_reached", target_key)
        if token in self._warning_shown or (not configured and not warning_only):
            return
        self._warning_shown.add(token)
        title = _("{label} — limite atteinte").format(label=self.target_label)
        message = (
            _("La durée définie est atteinte. L’utilisation reste autorisée en mode avertissement.")
            if warning_only else
            _("La durée autorisée est atteinte. L’utilisation est maintenant bloquée.")
        )
        if warning_only and not any(
            "windows" in (rule.get("channels") or ["windows"])
            for rule in self._notification_rules("limit_reached", target_key)
        ):
            self.notification_requested.emit(
                title, message, int(self.target_process_id or 0)
            )
        if configured:
            self._emit_notification(
                "limit_reached", target_key, title, message,
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
            _("{label} — joker utilisé").format(label=self.target_label),
            _("La durée normale est dépassée. Le joker de {duration} est actif.").format(
                duration=self._format_configured_duration(
                    policy["extension_seconds"], policy.get("extension_unit")
                )
            ),
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

    @staticmethod
    def _format_configured_duration(seconds, unit=None):
        seconds = max(0, int(round(seconds)))
        if unit == "hours":
            value, suffix = seconds / 3600, "h"
        elif unit == "minutes":
            value, suffix = seconds / 60, "min"
        else:
            return AppLimiter._format_duration(seconds)
        number = (
            str(int(value)) if value.is_integer()
            else f"{value:.2f}".rstrip("0").rstrip(".")
        )
        return f"{number} {suffix}"

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
                "enforcement_action": policy.get("enforcement_action", "block"),
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
                warning_only = item.get("enforcement_action") == "warn"
                message = (
                    (
                        _("Période surveillée : un avertissement sera affiché.")
                        if warning_only else
                        _("Utilisation interdite pendant la période planifiée.")
                    )
                    if item.get("block_during_validity")
                    else _("Usage limité : {duration}.").format(
                        duration=self._format_duration(item["limit_seconds"])
                    )
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
            if self.target_key in self.policies and (
                not self.current_status(self.target_key)["schedule_active"]
                or self.policies[self.target_key].get("enforcement_action") == "warn"
            ):
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
        # For browser video sites, the companion extension is the precise
        # play/pause source. Windows media sessions may lag briefly after a
        # pause and must not keep consuming the quota.
        foreground_playing = bool(
            getattr(context, "browser_media_playing", False)
        )
        if countable and (
            not self._target_requires_playback(foreground_target)
            or foreground_playing
        ):
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

    @staticmethod
    def _target_requires_playback(target):
        """Known video sites consume their quota only during actual playback."""
        key = str(getattr(target, "key", "") or "").casefold()
        if not key.startswith("site:"):
            return False
        # Imported lazily to keep this platform controller independent from
        # configuration loading during module initialization.
        from usage_guard import config
        return any(
            str(pattern).casefold().removeprefix("www.") in key
            for pattern in getattr(config, "VIDEO_URL_PATTERNS", [])
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
        warning_only = policy.get("enforcement_action") == "warn"
        status = self.current_status(target_key)
        if not status["schedule_active"]:
            return
        notification_token = (target_key, process_id)
        if notification_token not in self._notified_handles:
            self._notified_handles.add(notification_token)
            if self._notification_enabled("limited_app_start", target_key):
                message = (
                    (
                        _("Période surveillée : l’utilisation reste autorisée.")
                        if warning_only else
                        _("Utilisation interdite pendant la période planifiée.")
                    )
                    if policy.get("block_during_validity")
                    else _("Usage limité : {duration}.").format(
                        duration=self._format_duration(policy["limit_seconds"])
                    )
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
        state = self._effective_limit_state(target_key)
        self._notify_extension_started(target_key, state, policy)
        allowed = 0 if policy.get("block_during_validity") else policy["limit_seconds"] + (
            policy["extension_seconds"] if state["extension_used"] else 0
        )
        cutoff_block_token = (target_key, f"cutoff-block:{date.today().isoformat()}")
        cutoff_configured = self._notification_enabled("limit_warning", target_key)
        if (
            status.get("time_blocked")
            and cutoff_block_token not in self._warning_shown
            and (cutoff_configured or warning_only)
        ):
            self._warning_shown.add(cutoff_block_token)
            title = _("{label} — heure autorisée dépassée").format(
                label=self.target_label
            )
            message = (
                _("L’heure définie ({time}) est dépassée ; l’utilisation reste autorisée en mode avertissement.").format(
                    time=policy["blocked_after"]
                ) if warning_only else
                _("L’utilisation est interdite après {time}.").format(
                    time=policy["blocked_after"]
                )
            )
            if warning_only and not any(
                "windows" in (rule.get("channels") or ["windows"])
                for rule in self._notification_rules("limit_warning", target_key)
            ):
                self.notification_requested.emit(
                    title, message, int(self.target_process_id or 0)
                )
            if cutoff_configured:
                self._emit_notification(
                    "limit_warning", target_key, title, message,
                    self.target_process_id,
                )
        if state["seconds"] >= allowed or status.get("time_blocked"):
            if state["seconds"] >= allowed:
                self._notify_limit_reached(
                    target_key, state, warning_only=warning_only
                )
            if warning_only:
                self.usage.add_app_limit_seconds(
                    target_key, elapsed, date.today()
                )
            elif not browser_managed:
                self.block_target()
            return
        self.usage.add_app_limit_seconds(target_key, elapsed, date.today())
        state = self._effective_limit_state(target_key)
        self._notify_extension_started(target_key, state, policy)
        if state["seconds"] >= allowed:
            self._notify_limit_reached(
                target_key, state, warning_only=warning_only
            )
            if not warning_only and not browser_managed:
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
                (
                    _("{label} — seuil bientôt atteint")
                    if warning_only else _("{label} — bientôt terminé")
                ).format(label=self.target_label),
                (
                    _("Il reste {duration} avant l’avertissement.")
                    if warning_only else _("Il reste {duration} avant le blocage.")
                ).format(
                    duration=self._format_duration(remaining)
                ),
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
                    (
                        _("{label} — heure surveillée bientôt atteinte")
                        if warning_only else _("{label} — bientôt interdit")
                    ).format(label=self.target_label),
                    (
                        _("Il reste {duration} avant l’avertissement de fin de plage.")
                        if warning_only else
                        _("Il reste {duration} avant l’heure de fin autorisée.")
                    ).format(
                        duration=self._format_duration(time_remaining)
                    ),
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
                "extension_unit": policy.get("extension_unit", "seconds"),
                "warning_seconds": policy["warning_seconds"],
                "enforcement_action": policy.get("enforcement_action", "block"),
                **status,
            })
        self._current_web_limit = min(
            states,
            key=lambda item: (
                item.get("enforcement_action") == "warn",
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
                "extension_unit": policy.get("extension_unit", "seconds"),
                "warning_seconds": policy["warning_seconds"],
                "enforcement_action": policy.get("enforcement_action", "block"),
                **status,
            })
        return min(
            states,
            key=lambda item: (
                item.get("enforcement_action") == "warn",
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

    def apply_settings(self, target_key, settings, source="local"):
        target_key = self._canonical_limit_target(target_key)
        previous = self.policies.get(target_key)
        if (
            self._decision_core_enabled()
            and source not in {SOURCE_INTERNAL, SOURCE_BACKEND, SOURCE_LOCAL_ADMIN}
            and is_backend_managed(previous)
        ):
            raise ValueError("Cette limite est administrée à distance.")
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
        if self.blocked and target_key == self.target_key and (
            not normalized["enabled"]
            or normalized.get("enforcement_action") == "warn"
        ):
            self.unblock_target()
        return normalized

    def remove_limit(self, target_key, source="local"):
        if (
            self._decision_core_enabled()
            and source not in {SOURCE_INTERNAL, SOURCE_BACKEND, SOURCE_LOCAL_ADMIN}
            and is_backend_managed(self.policies.get(target_key))
        ):
            raise ValueError("Cette limite est administrée à distance.")
        if self.blocked and target_key == self.target_key:
            self.unblock_target()
        self.usage.remove_app_limit_settings(target_key)
        self.policies.pop(target_key, None)

    def reload_after_target_deleted(self, target_key):
        """Forget every rule measuring a permanently deleted activity.

        A target can have several independent rules whose storage keys carry
        a ``#uuid`` suffix.  ``AppUsageStore.delete_target`` removes all of
        them atomically; this method mirrors that change in the live limiter
        and immediately restores a window which one of those rules blocked.
        """
        target_key = self._canonical_limit_target(target_key)
        removed_policy_keys = {
            policy_key
            for policy_key, policy in self.policies.items()
            if (
                policy_key == target_key
                or self._policy_target_key(policy_key, policy) == target_key
            )
        }
        should_unblock = bool(
            self.blocked
            and (
                self.target_key in removed_policy_keys
                or self.target_key == target_key
            )
        )
        self._reload_policies()
        self._warning_shown = {
            token for token in self._warning_shown
            if token[0] not in removed_policy_keys
        }
        self._notified_handles = {
            token for token in self._notified_handles
            if token[0] not in removed_policy_keys
        }
        for policy_key in removed_policy_keys:
            self._playing_seen_at.pop(policy_key, None)
        self._media_target_keys.discard(target_key)
        self._running_limits = [
            item for item in self._running_limits
            if item.get("key") not in removed_policy_keys
        ]
        if should_unblock:
            self.unblock_target()
        if self._current_web_limit and str(
            self._current_web_limit.get("target_key") or ""
        ) in removed_policy_keys:
            self._current_web_limit = None
        return sorted(removed_policy_keys)

    def prune_expired_limits(self, now=None):
        now = now or datetime.now().astimezone()
        expired = []
        for target_key, policy in list(self.policies.items()):
            if policy.get("delete_after_expiry", True) is False:
                continue
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
            self.remove_limit(target_key, source=SOURCE_INTERNAL)
        return expired

    def reset_today(self, target_key, source="local"):
        if (
            self._decision_core_enabled()
            and source not in {SOURCE_INTERNAL, SOURCE_BACKEND, SOURCE_LOCAL_ADMIN}
            and is_backend_managed(self.policies.get(target_key))
        ):
            raise ValueError("Cette limite est administrée à distance.")
        policy = self.policies[target_key]
        self.usage.reset_app_limit_state(target_key)
        self.usage.prepare_app_limit(
            target_key, policy["limit_seconds"], policy["extension_seconds"]
        )
        self._warning_shown = {token for token in self._warning_shown if token[0] != target_key}
        if self.blocked and target_key == self.target_key:
            self.unblock_target()

    def current_status(self, target_key):
        # A few unit/integration adapters instantiate the limiter without the
        # Qt constructor.  Keep observability counters lazy so evaluation
        # itself never fails in that legitimate headless path.
        if not hasattr(self, "_decision_mirror_checks"):
            self._decision_mirror_checks = 0
            self._decision_mirror_mismatches = 0
            self._decision_mirror_failures = 0
            self._decision_mirror_last_mismatch = {}
        policy = self.policies[target_key]
        state = self._effective_limit_state(target_key)
        allowed = 0 if policy.get("block_during_validity") else policy["limit_seconds"] + (
            policy["extension_seconds"] if state["extension_used"] else 0
        )
        duration_remaining = max(0.0, allowed - state["seconds"])
        now = datetime.now().astimezone()
        schedule = self._schedule_status(policy, now)
        time_remaining = self._cutoff_remaining(policy, now) if schedule["active"] else None
        legacy = {
            "seconds": state["seconds"],
            "extension_used": state["extension_used"],
            "allowed": allowed,
            "remaining": max(0.0, min(duration_remaining, time_remaining)) if time_remaining is not None else duration_remaining,
            "time_remaining": time_remaining,
            "time_blocked": time_remaining is not None and time_remaining <= 0,
            "schedule_active": schedule["active"],
            "schedule_pending": schedule["pending"],
        }
        selected = legacy
        if self._decision_core_enabled():
            try:
                mirror = getattr(self, "_decision_mirror", None)
                mirrored = (
                    mirror.evaluate(policy, state, now)
                    if mirror is not None
                    else evaluate_limit(policy, state, now).as_status()
                )
                self._decision_mirror_checks += 1
                if mirrored != legacy:
                    self._decision_mirror_mismatches += 1
                    self._decision_mirror_last_mismatch = {
                        "target_key": str(target_key),
                        "legacy": legacy,
                        "core": mirrored,
                    }
                elif mirror is not None:
                    selected = mirrored
            except (OSError, EOFError, RuntimeError) as error:
                self._decision_mirror_failures += 1
                self._decision_mirror_last_mismatch = {
                    "target_key": str(target_key),
                    "transport_error": str(error),
                }
        return selected

    def decision_mirror_status(self):
        enabled = self._decision_core_enabled()
        mirror = getattr(self, "_decision_mirror", None)
        service = (
            mirror.status()
            if enabled and mirror is not None
            else {"enabled": False, "connected": False, "pid": 0, "error": ""}
        )
        healthy = bool(
            not enabled
            or (
                self._decision_mirror_mismatches == 0
                and self._decision_mirror_failures == 0
                and (not service["enabled"] or service["connected"])
            )
        )
        authority = (
            "service"
            if enabled and healthy and service["enabled"] and service["connected"]
            else "legacy"
        )
        return {
            "enabled": enabled,
            "checks": int(self._decision_mirror_checks if enabled else 0),
            "mismatches": int(self._decision_mirror_mismatches if enabled else 0),
            "failures": int(self._decision_mirror_failures if enabled else 0),
            "healthy": healthy,
            "authority": authority,
            "service": service,
            "last_mismatch": self._decision_mirror_last_mismatch if enabled else None,
        }

    def _decision_core_enabled(self):
        mirror = getattr(self, "_decision_mirror", None)
        return bool(
            not current_profile().production
            or (mirror is not None and getattr(mirror, "external_service", False))
        )

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
    def _schedule_window_start(policy, now=None):
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
                return start
        return None

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
        if self.policies[self.target_key].get("enforcement_action") == "warn":
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
            policy.get("extension_unit", "seconds"),
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
