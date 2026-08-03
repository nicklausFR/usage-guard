from gui import PopupPanel, create_tray_icon
from guard import MonitoringService


class TrayControlSource:
    def __init__(self):
        self.panel = None
        self.tray_icon = None
        self.service = MonitoringService()

    def start(self):
        self.service.start()
        self.tray_icon = create_tray_icon(self.toggle_panel, self.service)
        return self.tray_icon

    def stop(self):
        self.service.stop()

    def toggle_panel(self):
        if self.panel is None or not self.panel.isVisible():
            self.panel = PopupPanel(self.service)
            self.panel.show()
        else:
            self.panel.close()
