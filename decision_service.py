"""Authenticated JSON IPC for the isolated limit-decision process."""

from __future__ import annotations

import base64
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from datetime import datetime
from multiprocessing import AuthenticationError
from multiprocessing.connection import Client, Listener
from pathlib import Path
from queue import Queue

from control_registry import ControlRegistry
from limit_decision import evaluate_limit
from windows_service_support import (
    decision_service_installed,
)


PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 8 * 1024 * 1024
DEFAULT_REQUEST_TIMEOUT_SECONDS = 3.0
ADMIN_AUTH_REQUEST_TIMEOUT_SECONDS = 12.0
PWA_AUTH_REQUEST_TIMEOUT_SECONDS = 35.0
PUBLIC_SERVICE_AUTHKEY = b"usage-guard-public-decision-protocol-v1"
_ADMIN_OPERATIONS = {"bootstrap_controls", "commit_control", "shutdown"}


def _json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )


def dispatch_request(
    request: dict, registry: ControlRegistry | None = None,
    admin_token: bytes | None = None, backend_runtime=None,
) -> tuple[dict, bool]:
    if not isinstance(request, dict) or request.get("version") != PROTOCOL_VERSION:
        return {"ok": False, "error": "unsupported protocol"}, False
    operation = request.get("operation")
    if operation in _ADMIN_OPERATIONS and admin_token is not None:
        supplied = str(request.get("admin_token") or "").encode("ascii", "ignore")
        expected = base64.urlsafe_b64encode(admin_token)
        if not secrets.compare_digest(supplied, expected):
            return {"ok": False, "error": "administrative operation forbidden"}, False
    if operation == "health":
        response = {
            "ok": True,
            "service": "usage-guard-decision",
            "version": PROTOCOL_VERSION,
            "pid": os.getpid(),
        }
        if backend_runtime is not None:
            response["backend"] = backend_runtime.status()
        return response, False
    if operation == "evaluate":
        try:
            decision = evaluate_limit(
                request["policy"],
                request["state"],
                datetime.fromisoformat(str(request["now"])),
            )
        except (KeyError, TypeError, ValueError) as error:
            return {"ok": False, "error": f"invalid decision input: {error}"}, False
        return {"ok": True, "decision": decision.as_status()}, False
    if operation == "controls" and registry is not None:
        return {"ok": True, "controls": registry.controls()}, False
    if operation == "computer_block_grace" and registry is not None:
        try:
            action = str(request.get("action") or "status")
            if action == "start":
                grace = registry.start_computer_block_grace(
                    request.get("occurrence"), request.get("duration_seconds", 300)
                )
            elif action == "status":
                grace = registry.computer_block_grace_status(
                    request.get("occurrence")
                )
            else:
                raise ValueError("Action de joker inconnue.")
        except (TypeError, ValueError) as error:
            return {"ok": False, "error": str(error)}, False
        return {"ok": True, "grace": grace}, False
    if operation == "bootstrap_controls" and registry is not None:
        controls = registry.bootstrap(
            request.get("limits", {}),
            request.get("computer_blocks", request.get("computer_block", {})),
        )
        return {"ok": True, "controls": controls}, False
    if operation == "authorize_control" and registry is not None:
        decision = registry.authorize(request.get("command", {}))
        return {"ok": True, **decision}, False
    if operation == "commit_control" and registry is not None:
        controls = registry.commit(
            request.get("command", {}), request.get("result", {})
        )
        return {"ok": True, "controls": controls}, False
    if operation == "publish_desktop_state" and backend_runtime is not None:
        if (
            request.get("activity") is not None
            or request.get("activity_encoding")
            or request.get("activity_data")
        ):
            return {
                "ok": False,
                "error": "complete activity archive transfer is disabled",
            }, False
        activity = None
        export_options = (
            {"activity_export": request["activity_export"]}
            if isinstance(request.get("activity_export"), dict) else {}
        )
        if request.get("activity_unchanged") is True:
            status = backend_runtime.publish_desktop_state(
                request.get("snapshot"), activity,
                preserve_activity=True,
                **export_options,
            )
        else:
            status = backend_runtime.publish_desktop_state(
                request.get("snapshot"), activity,
                **export_options,
            )
        return {"ok": True, "backend": status}, False
    if operation == "next_backend_command" and backend_runtime is not None:
        return {
            "ok": True, "pending": backend_runtime.next_command(
                request.get("windows_sid"),
                request.get("usage_guard_username"),
            )
        }, False
    if operation == "complete_backend_command" and backend_runtime is not None:
        try:
            result = backend_runtime.complete_command(
                request.get("service_command_id"), request.get("result")
            )
        except (KeyError, TypeError, ValueError) as error:
            return {"ok": False, "error": str(error)}, False
        return {"ok": True, "result": result}, False
    if operation == "authenticate_user" and backend_runtime is not None:
        try:
            user = backend_runtime.authenticate_user(
                request.get("username"), request.get("password"),
                request.get("email") or "",
            )
        except Exception as error:
            return {"ok": False, "error": str(error)}, False
        return {"ok": True, "user": user}, False
    if operation == "authenticate_windows_session" and backend_runtime is not None:
        try:
            user = backend_runtime.authenticate_windows_session(
                request.get("windows_sid")
            )
        except Exception as error:
            return {"ok": False, "error": str(error)}, False
        return {"ok": True, "user": user}, False
    if operation == "resolve_windows_identity" and backend_runtime is not None:
        try:
            identity = backend_runtime.resolve_windows_identity(
                request.get("windows_sid")
            )
        except (TypeError, ValueError) as error:
            return {"ok": False, "error": str(error)}, False
        return {"ok": True, "identity": identity}, False
    if operation == "user_policy" and backend_runtime is not None:
        try:
            policy = backend_runtime.cached_user_policy(
                request.get("windows_sid")
            )
        except Exception as error:
            return {"ok": False, "error": str(error)}, False
        return {"ok": True, "policy": policy}, False
    if operation == "personal_usage" and backend_runtime is not None:
        try:
            usage = backend_runtime.cached_personal_usage(
                request.get("windows_sid")
            )
        except Exception as error:
            return {"ok": False, "error": str(error)}, False
        return {"ok": True, "usage": usage}, False
    if operation == "acknowledge_user_policy" and backend_runtime is not None:
        try:
            result = backend_runtime.acknowledge_user_policy(
                request.get("windows_sid"), request.get("revision"),
                request.get("result"),
            )
        except Exception as error:
            return {"ok": False, "error": str(error)}, False
        return {"ok": True, "policy": result}, False
    if operation == "queue_user_catalog_action" and backend_runtime is not None:
        try:
            result = backend_runtime.queue_user_catalog_action(
                request.get("command"), request.get("actor") or "",
            )
        except Exception as error:
            return {"ok": False, "error": str(error)}, False
        return {"ok": True, "catalog": result}, False
    if operation == "backend_admin" and backend_runtime is not None:
        try:
            result = backend_runtime.backend_admin(
                request.get("service_admin_token"), request.get("action"),
                request.get("payload"),
            )
        except Exception as error:
            return {"ok": False, "error": str(error)}, False
        return {"ok": True, "result": result}, False
    if operation == "shutdown":
        return {"ok": True}, True
    return {"ok": False, "error": "unsupported operation"}, False


class DecisionServiceHost:
    def __init__(
        self, address: str, authkey: bytes, state_path: Path | None = None,
        admin_token: bytes | None = None, allow_interactive_clients=False,
        backend_runtime=None,
    ):
        self.address = str(address)
        self.authkey = bytes(authkey)
        self.registry = ControlRegistry(state_path)
        self.admin_token = bytes(admin_token) if admin_token is not None else None
        self.allow_interactive_clients = bool(allow_interactive_clients)
        self.backend_runtime = backend_runtime

    def serve_forever(self) -> None:
        listener = Listener(self.address, family="AF_PIPE", authkey=self.authkey)
        if self.allow_interactive_clients:
            _grant_interactive_pipe_access(listener)
        try:
            if self.backend_runtime is not None:
                self.backend_runtime.start()
            stopping = False
            while not stopping:
                try:
                    connection = listener.accept()
                except AuthenticationError:
                    continue
                except OSError:
                    time.sleep(0.01)
                    continue
                try:
                    raw = connection.recv_bytes(MAX_MESSAGE_BYTES)
                    request = json.loads(raw.decode("utf-8"))
                    response, stopping = dispatch_request(
                        request, self.registry, self.admin_token,
                        self.backend_runtime,
                    )
                    connection.send_bytes(_json_bytes(response))
                except (EOFError, OSError, UnicodeDecodeError, json.JSONDecodeError):
                    try:
                        connection.send_bytes(_json_bytes({
                            "ok": False,
                            "error": "invalid request",
                        }))
                    except OSError:
                        pass
                finally:
                    connection.close()
        finally:
            if self.backend_runtime is not None:
                self.backend_runtime.stop()
            listener.close()


def _grant_interactive_pipe_access(listener) -> None:
    """Allow local interactive sessions to use the public decision protocol."""
    if sys.platform != "win32":
        return
    import _winapi
    import pywintypes
    import types
    import win32api
    import win32con
    import win32pipe
    import win32security
    from multiprocessing.connection import BUFSIZE

    dacl = win32security.ACL()
    process_token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
    )
    creator_sid = win32security.GetTokenInformation(
        process_token, win32security.TokenUser
    )[0]
    dacl.AddAccessAllowedAce(
        win32security.ACL_REVISION, win32con.GENERIC_ALL, creator_sid
    )
    dacl.AddAccessAllowedAce(
        win32security.ACL_REVISION,
        win32con.GENERIC_ALL,
        win32security.CreateWellKnownSid(win32security.WinLocalSystemSid),
    )
    dacl.AddAccessAllowedAce(
        win32security.ACL_REVISION,
        win32con.GENERIC_ALL,
        win32security.CreateWellKnownSid(
            win32security.WinBuiltinAdministratorsSid
        ),
    )
    dacl.AddAccessAllowedAce(
        win32security.ACL_REVISION,
        win32con.GENERIC_READ | win32con.GENERIC_WRITE,
        win32security.CreateWellKnownSid(win32security.WinInteractiveSid),
    )
    mandatory = win32security.ACL()
    mandatory.AddMandatoryAce(
        win32security.ACL_REVISION,
        0,
        win32security.SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        win32security.CreateWellKnownSid(win32security.WinMediumLabelSid),
    )
    security_descriptor = win32security.SECURITY_DESCRIPTOR()
    security_descriptor.SetSecurityDescriptorDacl(True, dacl, False)
    security_descriptor.SetSecurityDescriptorSacl(True, mandatory, False)
    security_attributes = pywintypes.SECURITY_ATTRIBUTES()
    security_attributes.SECURITY_DESCRIPTOR = security_descriptor
    pipe_listener = listener._listener
    # multiprocessing creates later instances with the process default DACL.
    # Replace its factory so every pipe instance receives the same explicit
    # interactive DACL and medium-integrity label, not only the first one.
    old_handle = pipe_listener._handle_queue.pop()
    _winapi.CloseHandle(old_handle)

    def new_handle(self, first=False):
        flags = (
            _winapi.PIPE_ACCESS_DUPLEX
            | _winapi.FILE_FLAG_OVERLAPPED
        )
        if first:
            flags |= _winapi.FILE_FLAG_FIRST_PIPE_INSTANCE
        handle = win32pipe.CreateNamedPipe(
            self._address,
            flags,
            win32pipe.PIPE_TYPE_MESSAGE
            | win32pipe.PIPE_READMODE_MESSAGE
            | win32pipe.PIPE_WAIT,
            win32pipe.PIPE_UNLIMITED_INSTANCES,
            BUFSIZE,
            BUFSIZE,
            win32pipe.NMPWAIT_WAIT_FOREVER,
            security_attributes,
        )
        return handle.Detach()

    pipe_listener._new_handle = types.MethodType(new_handle, pipe_listener)
    pipe_listener._handle_queue.append(pipe_listener._new_handle(first=True))


class DecisionServiceClient:
    def __init__(
        self, address: str, authkey: bytes,
        request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
    ):
        self.address = str(address)
        self.authkey = bytes(authkey)
        self.request_timeout_seconds = max(
            0.05, float(request_timeout_seconds)
        )
        # ``multiprocessing.connection.Client`` bounds a missing Windows pipe,
        # but its authentication and response reads have no deadline.  Keep
        # those blocking calls off the Qt thread and allow only one outstanding
        # request: when the service stalls, later limit evaluations fail fast
        # instead of each freezing the UI for another full timeout.
        self._request_queue = Queue()
        self._request_slot = threading.BoundedSemaphore(1)
        self._request_worker = threading.Thread(
            target=self._run_requests,
            daemon=True,
            name="usage-guard-decision-client",
        )
        self._request_worker.start()

    def request(
        self, operation: str, *, timeout_seconds: float | None = None,
        wait_for_slot: bool = False, **payload,
    ) -> dict:
        timeout = (
            self.request_timeout_seconds
            if timeout_seconds is None else max(0.05, float(timeout_seconds))
        )
        started = time.monotonic()
        acquired = self._request_slot.acquire(
            blocking=bool(wait_for_slot),
            timeout=timeout if wait_for_slot else None,
        )
        if not acquired:
            message = (
                "Le service de décision n’est pas disponible dans le délai imparti."
                if wait_for_slot else
                "Le service de décision traite déjà une requête trop lente."
            )
            raise TimeoutError(message)
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            self._request_slot.release()
            raise TimeoutError(
                "Le service de décision ne répond pas dans le délai imparti."
            )
        task = {
            "operation": str(operation),
            "payload": dict(payload),
            "done": threading.Event(),
            "cancelled": threading.Event(),
        }
        self._request_queue.put(task)
        if not task["done"].wait(remaining):
            task["cancelled"].set()
            raise TimeoutError(
                "Le service de décision ne répond pas dans le délai imparti."
            )
        error = task.get("error")
        if error is not None:
            raise error
        return task["response"]

    def _run_requests(self):
        while True:
            task = self._request_queue.get()
            try:
                if not task["cancelled"].is_set():
                    task["response"] = self._request_blocking(
                        task["operation"], task["payload"]
                    )
            except BaseException as error:
                task["error"] = error
            finally:
                self._request_slot.release()
                task["done"].set()

    def _request_blocking(self, operation: str, payload: dict) -> dict:
        connection = Client(
            self.address,
            family="AF_PIPE",
            authkey=self.authkey,
        )
        try:
            connection.send_bytes(_json_bytes({
                "version": PROTOCOL_VERSION,
                "operation": operation,
                **payload,
            }))
            response = json.loads(
                connection.recv_bytes(MAX_MESSAGE_BYTES).decode("utf-8")
            )
        finally:
            connection.close()
        if not response.get("ok"):
            raise RuntimeError(str(response.get("error", "decision service error")))
        return response

    def health(self) -> dict:
        return self.request("health")

    def evaluate(self, policy: dict, state: dict, now: datetime) -> dict:
        return self.request(
            "evaluate",
            policy=dict(policy),
            state=dict(state),
            now=now.isoformat(),
        )["decision"]

    def bootstrap_controls(self, limits: dict, computer_blocks) -> dict:
        collection = (
            [dict(item) for item in computer_blocks]
            if isinstance(computer_blocks, list)
            else dict(computer_blocks or {})
        )
        return self.request(
            "bootstrap_controls",
            limits=dict(limits),
            computer_blocks=collection,
        )["controls"]

    def controls(self) -> dict:
        return self.request("controls")["controls"]

    def computer_block_grace(self, occurrence: dict, start=False) -> dict:
        return self.request(
            "computer_block_grace",
            action="start" if start else "status",
            occurrence=dict(occurrence),
            duration_seconds=max(300, int(occurrence.get("grace_seconds", 300) or 300)),
        )["grace"]

    def authorize_control(self, command: dict) -> dict:
        response = self.request("authorize_control", command=dict(command))
        return {
            "allowed": bool(response.get("allowed")),
            "error": str(response.get("error") or ""),
        }

    def commit_control(self, command: dict, result: dict) -> dict:
        return self.request(
            "commit_control", command=dict(command), result=dict(result)
        )["controls"]

    def publish_desktop_state(
        self, snapshot: dict, activity: dict | None = None, *,
        activity_unchanged: bool = False, activity_export: dict | None = None,
    ) -> dict:
        payload = {"snapshot": dict(snapshot)}
        if isinstance(activity_export, dict):
            payload["activity_export"] = dict(activity_export)
        if activity_unchanged:
            payload["activity_unchanged"] = True
        elif isinstance(activity, dict):
            raise ValueError(
                "Le transfert IPC de l’archive d’activité complète est désactivé."
            )
        return self.request("publish_desktop_state", **payload)["backend"]

    def next_backend_command(
        self, windows_sid="", usage_guard_username="",
    ):
        return self.request(
            "next_backend_command", windows_sid=str(windows_sid or ""),
            usage_guard_username=str(usage_guard_username or ""),
        ).get("pending")

    def complete_backend_command(self, service_command_id, result: dict) -> dict:
        return self.request(
            "complete_backend_command",
            service_command_id=str(service_command_id), result=dict(result),
        )["result"]

    def authenticate_user(
        self, username, password, email="", *,
        timeout_seconds=ADMIN_AUTH_REQUEST_TIMEOUT_SECONDS,
    ) -> dict:
        return self.request(
            "authenticate_user",
            timeout_seconds=timeout_seconds,
            wait_for_slot=True,
            username=str(username or ""),
            password=str(password or ""),
            email=str(email or ""),
        )["user"]

    def authenticate_windows_session(self, windows_sid) -> dict:
        return self.request(
            "authenticate_windows_session",
            timeout_seconds=PWA_AUTH_REQUEST_TIMEOUT_SECONDS,
            wait_for_slot=True,
            windows_sid=str(windows_sid or ""),
        )["user"]

    def resolve_windows_identity(self, windows_sid) -> dict:
        return self.request(
            "resolve_windows_identity", windows_sid=str(windows_sid or "")
        )["identity"]

    def user_policy(self, windows_sid) -> dict:
        return self.request(
            "user_policy", windows_sid=str(windows_sid or "")
        )["policy"]

    def personal_usage(self, windows_sid) -> dict:
        return self.request(
            "personal_usage", windows_sid=str(windows_sid or "")
        )["usage"]

    def acknowledge_user_policy(self, windows_sid, revision, result) -> dict:
        return self.request(
            "acknowledge_user_policy",
            windows_sid=str(windows_sid or ""), revision=int(revision),
            result=dict(result or {}),
        )["policy"]

    def queue_user_catalog_action(self, command, actor="") -> dict:
        return self.request(
            "queue_user_catalog_action",
            command=dict(command or {}), actor=str(actor or ""),
        )["catalog"]

    def backend_admin(self, service_admin_token, action, payload=None):
        return self.request(
            "backend_admin",
            timeout_seconds=PWA_AUTH_REQUEST_TIMEOUT_SECONDS,
            wait_for_slot=True,
            service_admin_token=str(service_admin_token or ""),
            action=str(action or ""), payload=dict(payload or {}),
        )["result"]

    def shutdown(self, admin_token: bytes | None = None) -> dict:
        payload = {}
        if admin_token is not None:
            payload["admin_token"] = base64.urlsafe_b64encode(
                admin_token
            ).decode("ascii")
        return self.request("shutdown", **payload)


def load_or_create_authkey(
    directory: Path, filename: str = "decision-service.key"
) -> bytes:
    path = Path(directory) / filename
    try:
        encoded = path.read_text(encoding="ascii").strip()
        key = base64.urlsafe_b64decode(encoded.encode("ascii"))
        if len(key) >= 32:
            return key
    except (OSError, ValueError):
        pass
    key = secrets.token_bytes(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(base64.urlsafe_b64encode(key).decode("ascii"), encoding="ascii")
    return key


class DecisionServiceManager:
    """Own the temporary DEV process; production will later use Windows SCM."""

    def __init__(
        self, profile, host_path: Path | None = None, service_detector=None,
    ):
        self.profile = profile
        self.address = profile.decision_pipe_name
        detector = service_detector or decision_service_installed
        self.external_service = bool(detector(profile))
        self.authkey = (
            PUBLIC_SERVICE_AUTHKEY
            if self.external_service
            else load_or_create_authkey(profile.local_data_directory())
        )
        self.client = DecisionServiceClient(self.address, self.authkey)
        self.host_path = Path(host_path or Path(__file__).with_name("decision_service_host.py"))
        self.process = None
        self.connected = False
        self.service_pid = 0
        self.last_error = ""
        self.backend_status = {}

    def bootstrap_controls(self, limits: dict, computer_blocks) -> dict:
        if self.external_service:
            return self.client.controls()
        return self.client.bootstrap_controls(limits, computer_blocks)

    def authorize_control(self, command: dict) -> dict:
        return self.client.authorize_control(command)

    def authenticate_user(self, username, password, email="") -> dict:
        return self.client.authenticate_user(
            username, password, email,
            timeout_seconds=ADMIN_AUTH_REQUEST_TIMEOUT_SECONDS,
        )

    def authenticate_pwa_user(self, username, password, email="") -> dict:
        """Authenticate from a threaded local HTTP request, not the Qt loop."""
        return self.client.authenticate_user(
            username, password, email,
            timeout_seconds=PWA_AUTH_REQUEST_TIMEOUT_SECONDS,
        )

    def authenticate_windows_session(self, windows_sid) -> dict:
        if not self.external_service:
            raise RuntimeError(
                "La connexion par session Windows exige le service protégé."
            )
        return self.client.authenticate_windows_session(windows_sid)

    def resolve_windows_identity(self, windows_sid) -> dict:
        if not self.external_service:
            return {
                "windows_sid": str(windows_sid or "").strip().upper(),
                "usage_guard_username": "",
                "mapped": False,
                "mapping_status": "development",
            }
        return self.client.resolve_windows_identity(windows_sid)

    def user_policy(self, windows_sid) -> dict:
        if not self.external_service:
            raise RuntimeError(
                "La politique personnelle exige le service protégé."
            )
        return self.client.user_policy(windows_sid)

    def personal_usage(self, windows_sid) -> dict:
        if not self.external_service:
            raise RuntimeError(
                "La consommation personnelle exige le service protégé."
            )
        return self.client.personal_usage(windows_sid)

    def acknowledge_user_policy(self, windows_sid, revision, result) -> dict:
        if not self.external_service:
            raise RuntimeError(
                "L’accusé de politique exige le service protégé."
            )
        return self.client.acknowledge_user_policy(
            windows_sid, revision, result,
        )

    def queue_user_catalog_action(self, command, actor="") -> dict:
        if not self.external_service:
            return {"queued": False, "reason": "development_service"}
        return self.client.queue_user_catalog_action(command, actor)

    def backend_admin(self, service_admin_token, action, payload=None):
        return self.client.backend_admin(
            service_admin_token, action, payload,
        )

    def computer_block_grace(self, occurrence: dict, start=False) -> dict:
        return self.client.computer_block_grace(occurrence, start=start)

    def commit_control(self, command: dict, result: dict) -> dict:
        if self.external_service:
            raise RuntimeError(
                "Les mutations backend doivent être déplacées dans le service Windows."
            )
        return self.client.commit_control(command, result)

    def publish_desktop_state(
        self, snapshot: dict, activity: dict | None = None, *,
        activity_unchanged: bool = False, activity_export: dict | None = None,
    ) -> dict:
        if not self.external_service:
            return {}
        return self.client.publish_desktop_state(
            snapshot, activity, activity_unchanged=activity_unchanged,
            activity_export=activity_export,
        )

    def next_backend_command(
        self, windows_sid="", usage_guard_username="",
    ):
        if not self.external_service:
            return None
        return self.client.next_backend_command(
            windows_sid, usage_guard_username,
        )

    def complete_backend_command(self, service_command_id, result: dict) -> dict:
        if not self.external_service:
            raise RuntimeError("Le backend n’est pas hébergé par le service.")
        return self.client.complete_backend_command(service_command_id, result)

    def start(self, timeout_seconds: float = 4.0) -> bool:
        if self._probe():
            return True
        if self.external_service:
            deadline = time.monotonic() + max(0.1, timeout_seconds)
            while time.monotonic() < deadline:
                if self._probe():
                    return True
                time.sleep(0.05)
            self.last_error = "Le service Windows de décision ne répond pas."
            return False
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        self.process = subprocess.Popen(
            [
                sys.executable,
                str(self.host_path),
                "--profile",
                self.profile.name,
            ],
            cwd=str(self.host_path.parent),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=flags,
        )
        deadline = time.monotonic() + max(0.1, timeout_seconds)
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.last_error = "Le processus de décision s’est arrêté."
                return False
            if self._probe():
                return True
            time.sleep(0.05)
        self.last_error = "Délai de connexion au processus de décision dépassé."
        return False

    def _probe(self) -> bool:
        try:
            health = self.client.health()
            self.connected = True
            self.service_pid = int(health.get("pid") or 0)
            self.last_error = ""
            self.backend_status = dict(health.get("backend") or {})
        except (OSError, EOFError, RuntimeError, AuthenticationError):
            self.connected = False
            self.service_pid = 0
            self.backend_status = {}
        return self.connected

    def evaluate(self, policy: dict, state: dict, now: datetime) -> dict:
        try:
            decision = self.client.evaluate(policy, state, now)
            self.connected = True
            self.last_error = ""
            return decision
        except (OSError, EOFError, RuntimeError, AuthenticationError) as error:
            self.connected = False
            self.last_error = str(error)
            raise

    def status(self) -> dict:
        self._probe()
        return {
            "enabled": True,
            "connected": self.connected,
            "pid": (
                int(self.process.pid)
                if self.process and self.process.poll() is None
                else self.service_pid
            ),
            "host": "windows_service" if self.external_service else "desktop_child",
            "error": self.last_error,
            "backend": dict(self.backend_status),
        }

    def stop(self) -> None:
        if self.external_service:
            self.connected = False
            return
        try:
            if self.connected:
                self.client.shutdown()
        except (OSError, EOFError, RuntimeError, AuthenticationError):
            pass
        if self.process is not None:
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.terminate()
            self.process = None
        self.connected = False
