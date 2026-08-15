import ctypes
import os
import subprocess
import time
import webbrowser
from ctypes import wintypes
from pathlib import Path

from PySide6.QtWidgets import QSystemTrayIcon

from gui import create_tray_icon
from guard import MonitoringService
from usage_guard import config, debug_log
from windows_notifications import show_notification


class TrayControlSource:
    def __init__(self):
        self.tray_icon = None
        self.service = MonitoringService()
        self._pwa_launching_until = 0.0

    def start(self):
        # The first activity probe performs Windows and WinRT calls
        # synchronously.  Register the notification icon before that probe so
        # a slow or stalled media query can never prevent the control surface
        # from appearing.
        available = QSystemTrayIcon.isSystemTrayAvailable()
        debug_log(f"creating tray icon; system tray available={available}")
        if self.tray_icon is None:
            self.tray_icon = create_tray_icon(self.toggle_panel, self.service)
            self.service.notification_requested.connect(
                show_notification
            )
        debug_log(f"tray icon requested; visible={self.tray_icon.isVisible()}")
        self.service.start()
        return self.tray_icon

    def stop(self):
        self.close_panel()
        self.service.stop()

    def close_panel(self):
        """Close the dedicated local PWA window without touching browser tabs."""
        window = self._pwa_window()
        if window:
            debug_log(f"closing local PWA on Usage Guard shutdown hwnd={window}")
            ctypes.windll.user32.PostMessageW(window, 0x0010, 0, 0)
        self._pwa_launching_until = 0.0

    def toggle_panel(self):
        port = int(getattr(config, "REMOTE_API_PORT", 8766))
        url = f"http://127.0.0.1:{port}"
        debug_log("tray PWA toggle requested")
        window = self._pwa_window()
        if window:
            debug_log(f"closing PWA window hwnd={window}")
            self.close_panel()
            return
        if time.monotonic() < self._pwa_launching_until:
            debug_log("PWA launch already in progress")
            return
        browser = self._app_browser()
        if browser:
            debug_log(f"launching PWA with browser={browser}")
            subprocess.Popen(
                [str(browser), f"--app={url}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self._pwa_launching_until = time.monotonic() + 3
            return
        debug_log("no app-mode browser found; using default browser")
        webbrowser.open(url, new=2)

    @staticmethod
    def _app_browser():
        roots = [
            os.environ.get("PROGRAMFILES(X86)"),
            os.environ.get("PROGRAMFILES"),
            os.environ.get("LOCALAPPDATA"),
        ]
        relative_paths = [
            Path("BraveSoftware/Brave-Browser/Application/brave.exe"),
            Path("Google/Chrome/Application/chrome.exe"),
            Path("Microsoft/Edge/Application/msedge.exe"),
        ]
        # Prefer the browser already used and configured by Usage Guard. Edge
        # can be installed but disabled by policy, in which case launching it
        # silently creates no app window.
        for relative in relative_paths:
            for root in roots:
                if not root:
                    continue
                candidate = Path(root) / relative
                if candidate.is_file():
                    return candidate
        return None

    @staticmethod
    def _pwa_window():
        """Find only the dedicated browser-app window, never a normal tab."""
        user32 = ctypes.windll.user32
        found = []
        callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        @callback_type
        def inspect(hwnd, _lparam):
            if not user32.IsWindowVisible(hwnd):
                return True
            length = user32.GetWindowTextLengthW(hwnd)
            if length <= 0:
                return True
            title = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, title, length + 1)
            # Edge/Chrome app mode uses the document title verbatim. A normal
            # browser window adds its browser/profile suffix, so it is left
            # untouched even if the local dashboard is open in a regular tab.
            if title.value in {"Usage Guard", "127.0.0.1_/"}:
                found.append(hwnd)
                return False
            return True

        user32.EnumWindows(inspect, 0)
        return found[0] if found else 0
