"""Native Windows toast notifications with a registered desktop identity."""

from __future__ import annotations

import ctypes
import html
import os
import subprocess
import sys
from pathlib import Path

import pythoncom
from win32com.client import Dispatch
from win32com.propsys import pscon, propsys


CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
APP_ID = "NicklausFR.UsageGuard"


def register_notification_identity() -> None:
    """Register the Start-menu identity required by desktop Windows toasts."""
    if os.name != "nt":
        return
    pythoncom.CoInitialize()
    start_menu = (
        Path(os.environ["APPDATA"])
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
    )
    start_menu.mkdir(parents=True, exist_ok=True)
    legacy_shortcut = start_menu / "Usage Monitor.lnk"
    shortcut_path = start_menu / "Usage Guard.lnk"
    try:
        legacy_shortcut.unlink(missing_ok=True)
    except OSError:
        pass
    shell = Dispatch("WScript.Shell")
    shortcut = shell.CreateShortcut(str(shortcut_path))
    shortcut.TargetPath = sys.executable
    shortcut.Arguments = (
        "" if getattr(sys, "frozen", False)
        else f'"{Path(__file__).with_name("main.py")}"'
    )
    shortcut.WorkingDirectory = str(Path(__file__).parent)
    shortcut.Description = "Usage Guard"
    shortcut.IconLocation = f"{sys.executable},0"
    shortcut.Save()
    store = propsys.SHGetPropertyStoreFromParsingName(
        str(shortcut_path), None, 2, propsys.IID_IPropertyStore
    )
    store.SetValue(
        pscon.PKEY_AppUserModel_ID,
        propsys.PROPVARIANTType(APP_ID, pythoncom.VT_LPWSTR),
    )
    store.Commit()
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)


def show_notification(title: str, message: str, process_id: int = 0) -> None:
    """Send a native Windows toast without relying on tray balloons."""
    if os.name != "nt":
        return
    xml = (
        "<toast duration='short'><visual><binding template='ToastGeneric'>"
        f"<text>{html.escape(title)}</text><text>{html.escape(message)}</text>"
        "</binding></visual></toast>"
    )
    # ElementTree-compatible escaping does not escape quotes. PowerShell gets
    # the XML through an environment variable, avoiding command interpolation.
    script = (
        "$ErrorActionPreference='Stop';"
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null;"
        "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType=WindowsRuntime] | Out-Null;"
        "$xml=[Windows.Data.Xml.Dom.XmlDocument]::new();"
        "$xml.LoadXml($env:USAGE_MONITOR_TOAST_XML);"
        "$toast=[Windows.UI.Notifications.ToastNotification]::new($xml);"
        # Remove the toast from both the popup and notification centre after
        # a short factual notice; duration='short' alone is not an expiry.
        "$toast.ExpirationTime=[DateTimeOffset]::Now.AddSeconds(6);"
        "$pidToCheck=[int]$env:USAGE_MONITOR_TARGET_PID;"
        "if($pidToCheck -gt 0 -and -not (Get-Process -Id $pidToCheck -ErrorAction SilentlyContinue)){exit};"
        f"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{APP_ID}').Show($toast)"
    )
    environment = os.environ.copy()
    environment["USAGE_MONITOR_TOAST_XML"] = xml
    environment["USAGE_MONITOR_TARGET_PID"] = str(max(0, int(process_id)))
    subprocess.Popen(
        ["powershell.exe", "-NoProfile", "-WindowStyle", "Hidden", "-Command", script],
        creationflags=CREATE_NO_WINDOW,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
