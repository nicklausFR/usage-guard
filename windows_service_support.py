"""Windows Service identifiers and protected DEV storage paths."""

from __future__ import annotations

import os
import sys
import ctypes
from ctypes import wintypes
from pathlib import Path


DEV_DECISION_SERVICE_NAME = "UsageGuardDecisionDev"
PRODUCTION_DECISION_SERVICE_NAME = "UsageGuardDecision"


def decision_service_name(profile):
    return (
        PRODUCTION_DECISION_SERVICE_NAME
        if profile.production else DEV_DECISION_SERVICE_NAME
    )


def protected_service_directory(profile, environment=None):
    environment = os.environ if environment is None else environment
    base = Path(environment.get("PROGRAMDATA", r"C:\ProgramData"))
    return base / profile.data_directory_name / "Service"


def service_install_directory(profile, environment=None):
    environment = os.environ if environment is None else environment
    base = Path(environment.get("PROGRAMFILES", r"C:\Program Files"))
    return base / profile.data_directory_name / "Service"


def decision_service_installed(profile):
    if sys.platform != "win32" or profile.name not in {"production", "dev"}:
        return False
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    open_manager = advapi32.OpenSCManagerW
    open_manager.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD)
    open_manager.restype = wintypes.HANDLE
    open_service = advapi32.OpenServiceW
    open_service.argtypes = (wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD)
    open_service.restype = wintypes.HANDLE
    close_handle = advapi32.CloseServiceHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    manager = open_manager(None, None, 0x0001)  # SC_MANAGER_CONNECT
    if not manager:
        return False
    try:
        service = open_service(
            manager, decision_service_name(profile), 0x0004  # SERVICE_QUERY_STATUS
        )
        if not service:
            return False
        close_handle(service)
        return True
    finally:
        close_handle(manager)
