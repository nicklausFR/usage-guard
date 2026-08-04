from PySide6.QtWidgets import QSystemTrayIcon

from gui import PopupPanel, create_tray_icon
from guard import MonitoringService
from usage_guard import debug_log


class TrayControlSource:
    def __init__(self):
        self.panel = None
        self.tray_icon = None
        self.service = MonitoringService()

    def start(self):
        # The first activity probe performs Windows and WinRT calls
        # synchronously.  Register the notification icon before that probe so
        # a slow or stalled media query can never prevent the control surface
        # from appearing.
        available = QSystemTrayIcon.isSystemTrayAvailable()
        debug_log(f"creating tray icon; system tray available={available}")
        if self.tray_icon is None:
            self.tray_icon = create_tray_icon(self.toggle_panel, self.service)
        debug_log(f"tray icon requested; visible={self.tray_icon.isVisible()}")
        self.service.start()
        return self.tray_icon

    def stop(self):
        self.service.stop()

    def toggle_panel(self):
        if self.panel is None:
            self.panel = PopupPanel(self.service)

        if not self.panel.isVisible():
            self.panel.show()
            # A tray callback does not always make a top-level Qt window the
            # foreground window on Windows.  Explicitly raise and activate it
            # so the panel is not opened behind another application.
            self.panel.raise_()
            self.panel.activateWindow()
        else:
            self.panel.close()
