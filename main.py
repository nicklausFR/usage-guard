import signal
import sys
import ctypes
import threading
import os
from pathlib import Path
from ctypes import wintypes

from runtime_profile import configure_from_argv


# Select and consume --profile before Qt and the application modules inspect
# command-line arguments or initialize profile-dependent global objects.
runtime_profile = configure_from_argv()

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from activitywatch_manager import ActivityWatchManager
from browser_bridge import browser_bridge
from control_sources import TrayControlSource
from remote_api import RemoteControlServer
from backend_client import BackendClient
from usage_guard import APP_NAME, config, configure_windows_autostart, debug_log
from windows_notifications import register_notification_identity
from i18n import configure as configure_language, language_preference
from decision_service import DecisionServiceManager
from service_backend_bridge import ServiceBackendBridge
from windows_power_events import WindowsPowerEventFilter, WindowsShellEventFilter


# Keep this handle alive for the lifetime of the process.  Windows releases
# the mutex automatically if the application exits unexpectedly.
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_create_mutex = _kernel32.CreateMutexW
_create_mutex.argtypes = (wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR)
_create_mutex.restype = wintypes.HANDLE

_instance_mutex = _create_mutex(None, False, runtime_profile.mutex_name)
_instance_error = ctypes.get_last_error()
if not _instance_mutex:
    raise ctypes.WinError(_instance_error)

ERROR_ALREADY_EXISTS = 183
if _instance_error == ERROR_ALREADY_EXISTS:
    # Never leave a duplicate one-file process blocked behind a hidden modal
    # dialog. The existing tray instance is already the control surface.
    sys.exit(0)

configure_language(language_preference(getattr(config, "LANGUAGE", "auto")))
app = QApplication(sys.argv)
app.setApplicationName(APP_NAME)
if not runtime_profile.production:
    app.setApplicationDisplayName(f"{APP_NAME} · {runtime_profile.name.upper()}")
app.setQuitOnLastWindowClosed(False)
# Set the same icon as the notification area before any service creates a
# top-level window (notably the limit overlay/taskbar replacement).
from gui import create_usage_icon
app.setWindowIcon(create_usage_icon())
signal.signal(signal.SIGINT, lambda *_: app.quit())
debug_log("application started")

if bool(getattr(config, "ACTIVITYWATCH_ENABLED", False)):
    activitywatch = ActivityWatchManager()
    activitywatch.ensure_running()
    app.aboutToQuit.connect(activitywatch.stop_started_processes)

browser_bridge.start()
app.aboutToQuit.connect(browser_bridge.stop)

decision_service = None
if runtime_profile.production:
    # The v2 production desktop is only valid with the protected SCM service.
    decision_service = DecisionServiceManager(
        runtime_profile, service_detector=lambda _profile: True
    )
    decision_service.start()
else:
    decision_service = DecisionServiceManager(runtime_profile)
    decision_service.start()

tray_source = TrayControlSource(decision_mirror=decision_service)
tray_source.start()
power_event_filter = WindowsPowerEventFilter(tray_source.service.record_runtime_event)
app.installNativeEventFilter(power_event_filter)
shell_event_filter = WindowsShellEventFilter(tray_source.reregister_tray)
app.installNativeEventFilter(shell_event_filter)
service_backend_bridge = None
if decision_service is not None and decision_service.external_service:
    service_backend_bridge = ServiceBackendBridge(
        decision_service, tray_source.service, logger=debug_log
    )
    service_backend_bridge.start()
    app.aboutToQuit.connect(service_backend_bridge.stop)
backend_client = BackendClient(
    tray_source.service.request_remote_snapshot,
    tray_source.service.request_remote_command,
)
tray_source.service.email_notification_requested.connect(
    lambda kind, title, message, recipient: backend_client.queue_email_notification(
        title, message, recipient, kind
    )
)
remote_server = None
if bool(getattr(config, "REMOTE_API_ENABLED", True)):
    remote_server = RemoteControlServer(
        tray_source.service.request_remote_snapshot,
        tray_source.service.request_remote_command,
        backend_client,
        admin_authenticator=(
            decision_service.authenticate_pwa_user
            if decision_service is not None and decision_service.external_service
            else backend_client.authenticate_user
        ),
        backend_manager=(
            decision_service
            if decision_service is not None and decision_service.external_service
            else backend_client
        ),
        windows_session_authenticator=(
            tray_source.service.windows_session_user
            if decision_service is not None and decision_service.external_service
            else None
        ),
    )
    remote_server.start()
    app.aboutToQuit.connect(remote_server.stop)

if service_backend_bridge is None:
    backend_client.start()
app.aboutToQuit.connect(backend_client.stop)
debug_log("tray icon creation scheduled")
app.aboutToQuit.connect(tray_source.stop)
if decision_service is not None:
    app.aboutToQuit.connect(decision_service.stop)
ready_path = (
    runtime_profile.local_data_directory()
    / "ready.pid"
)
def mark_tray_ready():
    # Let the first two forced Shell registration attempts complete before the
    # build script considers the newly launched executable ready.
    try:
        ready_path.parent.mkdir(parents=True, exist_ok=True)
        ready_path.write_text(
            f"{os.getpid()}\n{Path(sys.executable).resolve()}",
            encoding="utf-8",
        )
        debug_log(
            "tray ready marker written; "
            f"visible={tray_source.tray_icon.isVisible()}"
        )
    except OSError as error:
        debug_log(f"ready marker failed: {error!r}")


QTimer.singleShot(2_000, mark_tray_ready)


def prepare_notifications():
    try:
        register_notification_identity()
        debug_log("Windows notification identity registered")
    except Exception as error:
        debug_log(f"Windows notification identity failed: {error!r}")


# COM shortcut registration can occasionally stall during a one-file startup.
# The tray icon and monitoring must never wait for it.
threading.Thread(
    target=prepare_notifications,
    name="notification-identity",
    daemon=True,
).start()

if runtime_profile.allow_autostart_changes:
    configure_windows_autostart(
        bool(getattr(config, "AUTOSTART_WITH_WINDOWS", True))
    )

sys.exit(app.exec())
