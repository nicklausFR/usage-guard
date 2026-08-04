import signal
import sys
import ctypes
from ctypes import wintypes

from PySide6.QtWidgets import QApplication, QMessageBox

from activitywatch_manager import ActivityWatchManager
from browser_bridge import browser_bridge
from control_sources import TrayControlSource
from usage_guard import config, configure_windows_autostart, debug_log


# Keep this handle alive for the lifetime of the process.  Windows releases
# the mutex automatically if the application exits unexpectedly.
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_create_mutex = _kernel32.CreateMutexW
_create_mutex.argtypes = (wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR)
_create_mutex.restype = wintypes.HANDLE

_instance_mutex = _create_mutex(
    None, False, "Local\\UsageMonitorSingleInstance"
)
if not _instance_mutex:
    raise ctypes.WinError(ctypes.get_last_error())

ERROR_ALREADY_EXISTS = 183
if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
    app = QApplication(sys.argv)
    QMessageBox.information(
        None,
        "Usage Monitor",
        "Usage Monitor est déjà en cours d’exécution.",
    )
    sys.exit(0)

app = QApplication(sys.argv)
app.setQuitOnLastWindowClosed(False)
signal.signal(signal.SIGINT, lambda *_: app.quit())
debug_log("application started")

if bool(getattr(config, "ACTIVITYWATCH_ENABLED", False)):
    activitywatch = ActivityWatchManager()
    activitywatch.ensure_running()
    app.aboutToQuit.connect(activitywatch.stop_started_processes)

browser_bridge.start()
app.aboutToQuit.connect(browser_bridge.stop)

tray_source = TrayControlSource()
tray_source.start()
debug_log("tray icon creation scheduled")
app.aboutToQuit.connect(tray_source.stop)

configure_windows_autostart(bool(getattr(config, "AUTOSTART_WITH_WINDOWS", True)))

sys.exit(app.exec())
