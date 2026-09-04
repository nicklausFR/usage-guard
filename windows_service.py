"""SCM host for the Usage Guard DEV decision service."""

from __future__ import annotations

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
    DEV_DECISION_SERVICE_NAME,
    protected_service_directory,
)


class UsageGuardDecisionDevService(win32serviceutil.ServiceFramework):
    _svc_name_ = DEV_DECISION_SERVICE_NAME
    _svc_display_name_ = "Usage Guard DEV - Decision Service"
    _svc_description_ = (
        "Owns development limit policies and decisions independently from "
        "the Usage Guard desktop session."
    )

    def __init__(self, args):
        super().__init__(args)
        self.profile = profile_named("dev")
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


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(UsageGuardDecisionDevService)
