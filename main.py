import signal
import sys

from PySide6.QtWidgets import QApplication

from activitywatch_manager import ActivityWatchManager
from control_sources import TrayControlSource


app = QApplication(sys.argv)
app.setQuitOnLastWindowClosed(False)
signal.signal(signal.SIGINT, lambda *_: app.quit())

activitywatch = ActivityWatchManager()
activitywatch.ensure_running()
app.aboutToQuit.connect(activitywatch.stop_started_processes)

tray_source = TrayControlSource()
tray_source.start()

sys.exit(app.exec())
