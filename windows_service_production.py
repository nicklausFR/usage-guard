"""SCM host for the production Usage Guard decision and backend service."""

from __future__ import annotations

import sys

import servicemanager
import win32service
import win32serviceutil

from decision_service import (
    PUBLIC_SERVICE_AUTHKEY,
    DecisionServiceClient,
    DecisionServiceHost,
    load_or_create_authkey,
)
from runtime_profile import profile_named
from service_backend import ServiceBackendRuntime
from windows_service_support import (
    PRODUCTION_DECISION_SERVICE_NAME,
    protected_service_directory,
)


class UsageGuardDecisionService(win32serviceutil.ServiceFramework):
    _svc_name_ = PRODUCTION_DECISION_SERVICE_NAME
    _svc_display_name_ = "Usage Guard - Protected Service"
    _svc_description_ = (
        "Owns protected Usage Guard policies, decisions and backend polling."
    )

    def __init__(self, args):
        super().__init__(args)
        self.profile = profile_named("production")
        directory = protected_service_directory(self.profile)
        self.admin_token = load_or_create_authkey(
            directory, "decision-service-admin.key"
        )
        backend_runtime = ServiceBackendRuntime(
            directory, None, logger=servicemanager.LogInfoMsg
        )
        self.host = DecisionServiceHost(
            self.profile.decision_pipe_name,
            PUBLIC_SERVICE_AUTHKEY,
            state_path=directory / "decision-service-controls.json",
            admin_token=self.admin_token,
            allow_interactive_clients=True,
            backend_runtime=backend_runtime,
        )
        backend_runtime.registry = self.host.registry

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        try:
            DecisionServiceClient(
                self.profile.decision_pipe_name, PUBLIC_SERVICE_AUTHKEY
            ).shutdown(self.admin_token)
        except Exception:
            pass

    def SvcDoRun(self):
        servicemanager.LogInfoMsg(
            f"{self._svc_name_} starting on {self.profile.decision_pipe_name}"
        )
        try:
            self.host.serve_forever()
        except Exception as error:
            servicemanager.LogErrorMsg(
                f"{self._svc_name_} failed: {type(error).__name__}: {error}"
            )
            raise
        finally:
            servicemanager.LogInfoMsg(f"{self._svc_name_} stopped")


def _health_check(require_desktop=True):
    """Check the protected backend, optionally including the desktop process."""
    profile = profile_named("production")
    try:
        health = DecisionServiceClient(
            profile.decision_pipe_name, PUBLIC_SERVICE_AUTHKEY
        ).health()
    except Exception:
        return 1
    backend = health.get("backend") or {}
    required = [
        backend.get("enabled"),
        backend.get("configured"),
        backend.get("started"),
    ]
    if require_desktop:
        required.append(backend.get("desktop_connected"))
    return 0 if all(required) else 1


def _initialize_authkey():
    profile = profile_named("production")
    load_or_create_authkey(
        protected_service_directory(profile), "decision-service-admin.key"
    )
    return 0


def main(argv=None):
    """Host the SCM service and the bundled installation utilities."""
    argv = list(sys.argv if argv is None else argv)
    command = argv[1].casefold() if len(argv) > 1 else ""
    if command == "enroll":
        from tools.enroll_device import main as enroll_main

        original = sys.argv
        try:
            sys.argv = [argv[0], *argv[2:]]
            return enroll_main() or 0
        finally:
            sys.argv = original
    if command == "init-local":
        from tools.init_local_backend import main as init_local_main

        return init_local_main(argv[2:])
    if command == "migrate-backend":
        from tools.migrate_existing_backend import main as migrate_backend_main

        return migrate_backend_main(argv[2:])
    if command == "health":
        return _health_check()
    if command == "health-service":
        return _health_check(require_desktop=False)
    if command == "init-authkey":
        return _initialize_authkey()

    # A frozen executable is started without arguments by the Windows Service
    # Control Manager.  PyInstaller does not provide py2exe's implicit service
    # dispatcher, so host the service class explicitly in that case.
    if getattr(sys, "frozen", False) and len(argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(UsageGuardDecisionService)
        servicemanager.StartServiceCtrlDispatcher()
        return 0

    return win32serviceutil.HandleCommandLine(
        UsageGuardDecisionService, argv=argv
    )


if __name__ == "__main__":
    raise SystemExit(main())
