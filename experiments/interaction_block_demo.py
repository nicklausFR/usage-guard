"""Prototype autonome de blocage d'interaction sous Windows.

Ce fichier n'est pas importe par Usage Guard. Il lance une fenetre cible de test,
affiche un avertissement, puis la rend non interactive sans fermer son processus.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import time
from ctypes import wintypes

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QSlider,
    QVBoxLayout,
    QWidget,
)


if sys.platform != "win32":
    raise SystemExit("Ce prototype fonctionne uniquement sous Windows.")


user32 = ctypes.WinDLL("user32", use_last_error=True)
WM_CLOSE = 0x0010
SW_MINIMIZE = 6

EnumWindowsProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

user32.EnumWindows.argtypes = (EnumWindowsProc, wintypes.LPARAM)
user32.EnumWindows.restype = wintypes.BOOL
user32.GetWindowThreadProcessId.argtypes = (
    wintypes.HWND,
    ctypes.POINTER(wintypes.DWORD),
)
user32.GetWindowThreadProcessId.restype = wintypes.DWORD
user32.IsWindowVisible.argtypes = (wintypes.HWND,)
user32.IsWindowVisible.restype = wintypes.BOOL
user32.IsWindow.argtypes = (wintypes.HWND,)
user32.IsWindow.restype = wintypes.BOOL
user32.EnableWindow.argtypes = (wintypes.HWND, wintypes.BOOL)
user32.EnableWindow.restype = wintypes.BOOL
user32.GetWindowRect.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.RECT))
user32.GetWindowRect.restype = wintypes.BOOL
user32.PostMessageW.argtypes = (
    wintypes.HWND,
    wintypes.UINT,
    wintypes.WPARAM,
    wintypes.LPARAM,
)
user32.PostMessageW.restype = wintypes.BOOL
user32.GetForegroundWindow.argtypes = ()
user32.GetForegroundWindow.restype = wintypes.HWND
user32.IsIconic.argtypes = (wintypes.HWND,)
user32.IsIconic.restype = wintypes.BOOL
user32.ShowWindow.argtypes = (wintypes.HWND, ctypes.c_int)
user32.ShowWindow.restype = wintypes.BOOL


def visible_windows_for_process(process_id: int) -> list[int]:
    """Retourne les fenetres principales visibles appartenant au processus."""
    handles: list[int] = []

    @EnumWindowsProc
    def callback(hwnd, _lparam):
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value == process_id and user32.IsWindowVisible(hwnd):
            handles.append(int(hwnd))
        return True

    if not user32.EnumWindows(callback, 0):
        raise ctypes.WinError(ctypes.get_last_error())
    return handles


def set_process_windows_enabled(process_id: int, enabled: bool) -> list[int]:
    handles = visible_windows_for_process(process_id)
    for hwnd in handles:
        user32.EnableWindow(hwnd, enabled)
    return handles


class TestTarget(QMainWindow):
    """Petite application factice permettant de verifier clics et clavier."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Application cible - test Usage Guard")
        self.resize(720, 430)

        title = QLabel("Application cible")
        title.setStyleSheet("font-size: 24px; font-weight: 600;")
        explanation = QLabel(
            "Essayez de saisir du texte, de deplacer le curseur et de cliquer.\n"
            "Quand la limite sera atteinte, la fenetre restera ouverte mais ces "
            "actions ne fonctionneront plus."
        )
        explanation.setWordWrap(True)

        self.input = QLineEdit()
        self.input.setPlaceholderText("Saisissez du texte ici")
        self.slider = QSlider(Qt.Orientation.Horizontal)
        self.counter = 0
        self.counter_label = QLabel("Clics enregistres : 0")
        click_button = QPushButton("Tester un clic")
        click_button.clicked.connect(self.record_click)

        layout = QVBoxLayout()
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(18)
        layout.addWidget(title)
        layout.addWidget(explanation)
        layout.addWidget(self.input)
        layout.addWidget(self.slider)
        layout.addWidget(self.counter_label)
        layout.addWidget(click_button)
        layout.addStretch()

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def record_click(self):
        self.counter += 1
        self.counter_label.setText(f"Clics enregistres : {self.counter}")


class BlockOverlay(QWidget):
    def __init__(self, controller: "DemoController"):
        super().__init__(
            None,
            Qt.WindowType.Tool
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint,
        )
        self.controller = controller
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(500, 178)

        panel = QWidget()
        panel.setObjectName("panel")
        panel.setStyleSheet(
            "#panel { background: rgba(20, 24, 32, 238); border-radius: 14px; }"
            "QLabel { color: white; }"
            "QPushButton { min-height: 36px; padding: 0 16px; }"
        )

        title = QLabel("Limite d'utilisation atteinte")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 19px; font-weight: 700;")
        message = QLabel(
            "L'application continue de fonctionner, mais les interactions sont "
            "bloquees. Vous pouvez toujours la fermer."
        )
        message.setAlignment(Qt.AlignmentFlag.AlignCenter)
        message.setWordWrap(True)

        close_button = QPushButton("Fermer l'application")
        close_button.clicked.connect(controller.close_target)
        unlock_button = QPushButton("Debloquer (test)")
        unlock_button.clicked.connect(controller.unblock_target)

        buttons = QHBoxLayout()
        buttons.addWidget(close_button)
        buttons.addWidget(unlock_button)

        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(24, 20, 24, 20)
        panel_layout.setSpacing(12)
        panel_layout.addWidget(title)
        panel_layout.addWidget(message)
        panel_layout.addLayout(buttons)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(5, 5, 5, 5)
        outer.addWidget(panel)


class WarningPopup(QLabel):
    """Notification legere qui ne bloque pas la boucle d'evenements Qt."""

    def __init__(self):
        super().__init__(
            "La limite sera atteinte dans 5 secondes.",
            None,
            Qt.WindowType.Tool
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.WindowDoesNotAcceptFocus,
        )
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFixedSize(390, 64)
        self.setStyleSheet(
            "background: #f5a623; color: #181818; border-radius: 10px; "
            "font-size: 15px; font-weight: 600; padding: 10px;"
        )


class DemoController(QWidget):
    WARNING_AFTER_MS = 3_000
    BLOCK_AFTER_MS = 8_000

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Controleur du prototype")
        self.setFixedSize(440, 190)
        self.target_process: subprocess.Popen | None = None
        self.target_hwnd: int | None = None
        self.blocked = False
        self.group_minimized = False
        self.outside_detection_after = 0.0
        self.overlay = BlockOverlay(self)
        self.warning_popup = WarningPopup()

        self.status = QLabel("Demarrage de l'application cible...")
        self.status.setWordWrap(True)
        start_over = QPushButton("Relancer le scenario")
        start_over.clicked.connect(self.start_scenario)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        layout.addWidget(self.status)
        layout.addStretch()
        layout.addWidget(start_over)

        self.follow_timer = QTimer(self)
        self.follow_timer.timeout.connect(self.follow_target)
        self.follow_timer.start(100)
        QTimer.singleShot(0, self.start_scenario)

    def start_scenario(self):
        self.unblock_target()
        if self.target_process is not None and self.target_process.poll() is None:
            self.close_target()

        self.target_process = subprocess.Popen(
            [sys.executable, os.path.abspath(__file__), "--target"]
        )
        self.target_hwnd = None
        self.status.setText(
            "Scenario lance : avertissement dans 3 secondes, blocage dans 8 secondes."
        )
        QTimer.singleShot(self.WARNING_AFTER_MS, self.show_warning)
        QTimer.singleShot(self.BLOCK_AFTER_MS, self.block_target)

    def show_warning(self):
        if not self.target_is_running() or self.blocked:
            return
        self.position_popup_over_target(self.warning_popup, top_offset=24)
        self.warning_popup.show()
        self.warning_popup.raise_()
        QTimer.singleShot(2_500, self.warning_popup.hide)

    def block_target(self):
        if not self.target_is_running():
            return
        handles = set_process_windows_enabled(self.target_process.pid, False)
        if not handles:
            self.status.setText("Fenetre cible introuvable ; blocage non applique.")
            return
        self.target_hwnd = handles[0]
        self.blocked = True
        self.group_minimized = False
        self.outside_detection_after = time.monotonic() + 0.6
        self.warning_popup.hide()
        self.status.setText(
            "Limite atteinte : processus actif, fenetre non interactive."
        )
        self.position_popup_over_target(self.overlay, top_offset=42)
        self.overlay.show()
        self.overlay.raise_()
        self.overlay.activateWindow()

    def unblock_target(self):
        if self.target_process is not None and self.target_process.poll() is None:
            set_process_windows_enabled(self.target_process.pid, True)
        self.blocked = False
        self.group_minimized = False
        self.overlay.hide()
        if self.target_process is not None and self.target_process.poll() is None:
            self.status.setText("Application cible debloquee.")

    def close_target(self):
        if self.target_process is None or self.target_process.poll() is not None:
            self.overlay.hide()
            return
        for hwnd in visible_windows_for_process(self.target_process.pid):
            user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
        self.blocked = False
        self.group_minimized = False
        self.overlay.hide()
        self.status.setText("Demande de fermeture envoyee a l'application cible.")

    def follow_target(self):
        if not self.blocked or not self.target_is_running():
            if self.blocked:
                self.blocked = False
                self.overlay.hide()
                self.status.setText("L'application cible a ete fermee.")
            return

        handles = visible_windows_for_process(self.target_process.pid)
        if not handles:
            return
        self.target_hwnd = handles[0]

        if self.group_minimized:
            # Les fenetres sont temporairement activees pendant qu'elles sont
            # reduites afin que leur bouton de barre des taches puisse les
            # restaurer. Elles sont rebloquees avant d'afficher le bandeau.
            if all(user32.IsIconic(hwnd) for hwnd in handles):
                return
            self.group_minimized = False
            self.outside_detection_after = time.monotonic() + 0.6
            for hwnd in handles:
                user32.EnableWindow(hwnd, False)
            self.position_popup_over_target(self.overlay, top_offset=42)
            self.overlay.show()
            self.overlay.raise_()
            self.overlay.activateWindow()
            return

        # Reapplique le blocage aux eventuelles nouvelles fenetres de la cible.
        for hwnd in handles:
            user32.EnableWindow(hwnd, False)

        self.position_popup_over_target(self.overlay, top_offset=42)

        foreground = int(user32.GetForegroundWindow() or 0)
        overlay_hwnd = int(self.overlay.winId())
        group_handles = set(handles)
        group_handles.add(overlay_hwnd)
        if (
            time.monotonic() >= self.outside_detection_after
            and foreground not in group_handles
        ):
            # Un clic dans une autre application lui donne le premier plan.
            # On reduit alors la cible et masque son bandeau comme un seul bloc.
            self.overlay.hide()
            for hwnd in handles:
                user32.EnableWindow(hwnd, True)
                user32.ShowWindow(hwnd, SW_MINIMIZE)
            self.group_minimized = True
            self.status.setText(
                "Clic exterieur detecte : application et bandeau reduits ensemble."
            )

    def position_popup_over_target(self, popup: QWidget, top_offset: int):
        if not self.target_is_running():
            return
        handles = visible_windows_for_process(self.target_process.pid)
        if not handles:
            return
        rect = wintypes.RECT()
        if user32.GetWindowRect(handles[0], ctypes.byref(rect)):
            x = rect.left + (rect.right - rect.left - popup.width()) // 2
            popup.move(x, rect.top + top_offset)

    def target_is_running(self) -> bool:
        return self.target_process is not None and self.target_process.poll() is None

    def closeEvent(self, event):
        self.warning_popup.hide()
        self.unblock_target()
        event.accept()


def run_target():
    app = QApplication(sys.argv)
    window = TestTarget()
    window.show()
    sys.exit(app.exec())


def run_controller():
    app = QApplication(sys.argv)
    controller = DemoController()
    controller.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    if "--target" in sys.argv:
        run_target()
    else:
        run_controller()
