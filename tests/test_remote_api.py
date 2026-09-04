import json
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from remote_api import (
    DELETE_LIMITS_AUTHORIZED_FIELD,
    DELETE_OTHER_LIMITS_AUTHORIZED_FIELD,
    RemoteControlServer,
)
from command_policy import (
    COMMAND_SOURCE_FIELD, SERVICE_ADMIN_TOKEN_FIELD, SOURCE_LOCAL_ADMIN,
)
from usage_guard import config


class RemoteControlServerTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        config.REMOTE_API_HOST = "127.0.0.1"
        config.REMOTE_API_PORT = 0
        config.REMOTE_API_TOKEN_PATH = str(Path(self.temporary.name) / "token.txt")
        self.commands = []
        class Backend:
            configured = True

            @staticmethod
            def authenticate_user(username, password, email=""):
                if username != "admin" or password != "correct-password":
                    raise ValueError("Connexion refusée")
                return {
                    "username": "admin", "is_admin": True,
                    "must_change": False, "must_set_email": False,
                    "email": email or "admin@example.test", "permissions": {},
                    "_service_admin_token": "service-only-secret",
                }

            @staticmethod
            def rename_device(label, management_session=None):
                return {"ok": True, "device": {"label": label}}

        self.server = RemoteControlServer(
            lambda selection: {"scope": selection.get("scope", "today"), "usage": []},
            self._handle_command,
            Backend(),
        )
        self.server.start()
        self.base_url = f"http://127.0.0.1:{self.server._server.server_address[1]}"
        self.admin_token = None
        _, session = self._json(
            "/api/v1/auth/login", "POST",
            {"username": "admin", "password": "correct-password"},
            admin=False,
        )
        self.admin_token = session["admin_token"]

    def tearDown(self):
        self.server.stop()
        self.temporary.cleanup()

    def _handle_command(self, command):
        self.commands.append(command)
        return {"ok": True}

    def _json(self, path, method="GET", payload=None, authorized=True, admin=True):
        headers = {"Accept": "application/json"}
        if authorized:
            headers["Authorization"] = f"Bearer {self.server.token}"
        if admin and self.admin_token:
            headers["X-Usage-Guard-Admin"] = self.admin_token
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(self.base_url + path, data=body, method=method, headers=headers)
        with urlopen(request, timeout=2) as response:
            return response.status, json.loads(response.read().decode("utf-8"))

    def test_bootstrap_overview_and_action(self):
        status, bootstrap = self._json("/api/v1/bootstrap", authorized=False)
        self.assertEqual(status, 200)
        self.assertEqual(bootstrap["token"], self.server.token)

        status, overview = self._json("/api/v1/overview?scope=today")
        self.assertEqual(status, 200)
        self.assertEqual(overview["scope"], "today")

        status, result = self._json(
            "/api/v1/actions",
            method="POST",
            payload={"action": "rename_target", "target_key": "app:test", "label": "Test"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])
        self.assertEqual(self.commands[0]["target_key"], "app:test")
        self.assertEqual(self.commands[0][COMMAND_SOURCE_FIELD], SOURCE_LOCAL_ADMIN)
        self.assertEqual(
            self.commands[0][SERVICE_ADMIN_TOKEN_FIELD], "service-only-secret",
        )
        self.assertEqual(self.commands[0]["actor"], "admin")

    def test_local_history_is_proxied_page_by_page_without_snapshot_archive(self):
        calls = []

        class BackendProxy:
            @staticmethod
            def backend_admin(token, action, payload):
                calls.append((token, action, payload))
                return {
                    "scope": "all", "sessions": [],
                    "history_page": {
                        "has_more": True, "next_before": "next-page",
                        "rows": 500, "payload_bytes": 12345,
                    },
                }

        self.server.backend_manager = BackendProxy()
        self.server.backend_client.device_id = "pc-local"
        self.server.snapshot_provider = lambda _selection: self.fail(
            "scope=all must never serialize the desktop archive"
        )

        status, overview = self._json(
            "/api/v1/overview?scope=all&device_id=local&since=2026-08-01"
            "&before=opaque-cursor&tz=Europe%2FParis"
        )

        self.assertEqual(status, 200)
        self.assertEqual(overview["history_page"]["next_before"], "next-page")
        self.assertEqual(calls, [(
            "service-only-secret", "analysis_overview", {
                "scope": "all", "device_id": "pc-local",
                "since": "2026-08-01", "before": "opaque-cursor",
                "tz": "Europe/Paris",
            },
        )])

    def test_local_history_without_normalized_backend_refuses_full_snapshot(self):
        calls = []
        self.server.snapshot_provider = lambda selection: calls.append(selection)

        with self.assertRaises(HTTPError) as failure:
            self._json("/api/v1/overview?scope=all")

        self.assertEqual(failure.exception.code, 503)
        self.assertEqual(calls, [])

    def test_local_permanent_delete_reaches_the_windows_command_handler(self):
        status, result = self._json(
            "/api/v1/actions",
            method="POST",
            payload={"action": "delete_target", "target_key": "app:excluded"},
        )

        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])
        self.assertEqual(self.commands[-1]["action"], "delete_target")
        self.assertEqual(self.commands[-1]["target_key"], "app:excluded")
        self.assertEqual(
            self.commands[-1][COMMAND_SOURCE_FIELD], SOURCE_LOCAL_ADMIN,
        )
        self.assertTrue(
            self.commands[-1][DELETE_LIMITS_AUTHORIZED_FIELD]
        )
        self.assertTrue(
            self.commands[-1][DELETE_OTHER_LIMITS_AUTHORIZED_FIELD]
        )

    def test_limited_permanent_delete_requires_limit_permissions_and_owner(self):
        permissions = {
            "manage_activity": True, "manage_limits": False,
            "manage_other_limits": False,
        }
        self.server.admin_authenticator = lambda *_args: {
            "username": "alice", "is_admin": False,
            "must_change": False, "must_set_email": False,
            "permissions": dict(permissions),
        }
        self.server.snapshot_provider = lambda selection: {
            "scope": selection.get("scope", "today"),
            "limits": [{
                "key": "app:test#copy", "target_key": "app:test",
                "requested_by": "alice",
            }],
        }
        _, session = self._json(
            "/api/v1/auth/login", "POST",
            {"username": "alice", "password": "correct-password"},
            admin=False,
        )
        self.admin_token = session["admin_token"]

        with self.assertRaises(HTTPError) as forbidden:
            self._json("/api/v1/actions", "POST", {
                "action": "delete_target", "target_key": "app:test",
            })
        self.assertEqual(forbidden.exception.code, 403)
        self.assertEqual(self.commands, [])

        permissions["manage_limits"] = True
        _, session = self._json(
            "/api/v1/auth/login", "POST",
            {"username": "alice", "password": "correct-password"},
            admin=False,
        )
        self.admin_token = session["admin_token"]
        status, result = self._json("/api/v1/actions", "POST", {
            "action": "delete_target", "target_key": "app:test",
        })
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])
        self.assertTrue(
            self.commands[-1][DELETE_LIMITS_AUTHORIZED_FIELD]
        )
        self.assertFalse(
            self.commands[-1][DELETE_OTHER_LIMITS_AUTHORIZED_FIELD]
        )

        self.server.snapshot_provider = lambda selection: {
            "scope": selection.get("scope", "today"),
            "limits": [{
                "key": "site:brave.exe:youtube.com#copy",
                "target_key": "site:brave.exe:youtube.com",
                "requested_by": "bob",
            }],
        }
        with self.assertRaises(HTTPError) as other_forbidden:
            self._json("/api/v1/actions", "POST", {
                "action": "delete_site", "browser": "BRAVE.EXE",
                "host": "https://www.youtube.com/watch?v=1",
            })
        self.assertEqual(other_forbidden.exception.code, 403)
        self.assertEqual(len(self.commands), 1)

        permissions["manage_other_limits"] = True
        _, session = self._json(
            "/api/v1/auth/login", "POST",
            {"username": "alice", "password": "correct-password"},
            admin=False,
        )
        self.admin_token = session["admin_token"]
        status, result = self._json("/api/v1/actions", "POST", {
            "action": "delete_site", "browser": "BRAVE.EXE",
            "host": "https://www.youtube.com/watch?v=1",
        })
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])
        self.assertTrue(
            self.commands[-1][DELETE_OTHER_LIMITS_AUTHORIZED_FIELD]
        )

    def test_local_admin_can_rename_the_single_device(self):
        status, result = self._json(
            "/api/v1/backend/device/rename", "POST",
            {"label": "ordinateur-principal"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["device"]["label"], "ordinateur-principal")

    def test_windows_user_is_proposed_and_can_login_without_usage_guard_password(self):
        calls = []
        self.server.windows_session_authenticator = lambda: calls.append(True) or {
            "username": "alice", "email": "", "is_admin": False,
            "role": "limited", "permissions": {
                "view_activity": True, "view_analysis": True,
                "view_limits": True, "view_notifications": True,
                "manage_activity": True, "manage_limits": False,
                "manage_notifications": True,
            },
        }

        _, bootstrap = self._json("/api/v1/bootstrap", authorized=False)
        self.assertEqual(bootstrap["windows_username"], "alice")
        _, session = self._json(
            "/api/v1/auth/login", "POST",
            {"username": "alice", "password": ""}, admin=False,
        )

        self.assertEqual(session["username"], "alice")
        self.assertFalse(session["is_admin"])
        self.assertTrue(session["permissions"]["manage_notifications"])
        self.assertGreaterEqual(len(calls), 2)

    def test_passwordless_login_cannot_select_another_user_or_admin(self):
        self.server.windows_session_authenticator = lambda: {
            "username": "alice", "is_admin": False,
            "role": "limited", "permissions": {},
        }
        with self.assertRaises(HTTPError) as error:
            self._json(
                "/api/v1/auth/login", "POST",
                {"username": "bob", "password": ""}, admin=False,
            )
        self.assertEqual(error.exception.code, 401)

        self.server.windows_session_authenticator = lambda: {
            "username": "admin", "is_admin": True,
            "role": "admin", "permissions": {},
        }
        with self.assertRaises(HTTPError) as error:
            self._json(
                "/api/v1/auth/login", "POST",
                {"username": "admin", "password": ""}, admin=False,
            )
        self.assertEqual(error.exception.code, 401)

    def test_usage_guard_password_still_uses_explicit_authenticator(self):
        self.server.windows_session_authenticator = lambda: (_ for _ in ()).throw(
            AssertionError("Windows session must not validate a password")
        )
        _, session = self._json(
            "/api/v1/auth/login", "POST",
            {"username": "admin", "password": "correct-password"},
            admin=False,
        )
        self.assertTrue(session["is_admin"])

    def test_local_login_displays_a_safe_service_error(self):
        def refused(*_args, **_kwargs):
            raise RuntimeError(
                "Le service de décision ne répond pas dans le délai imparti."
            )

        self.server.admin_authenticator = refused
        with self.assertRaises(HTTPError) as failure:
            self._json(
                "/api/v1/auth/login", "POST",
                {"username": "admin", "password": "correct-password"},
                admin=False,
            )
        self.assertEqual(failure.exception.code, 401)
        response = json.loads(failure.exception.read().decode("utf-8"))
        self.assertEqual(
            response["error"],
            "Le service de décision ne répond pas dans le délai imparti.",
        )

    def test_local_action_cannot_spoof_backend_identity(self):
        self._json(
            "/api/v1/actions", method="POST",
            payload={
                "action": "remove_limit", "target_key": "app:test",
                "_usage_guard_source": "backend", "_remote_command_id": "42",
                SERVICE_ADMIN_TOKEN_FIELD: "attacker-supplied",
            },
        )

        self.assertEqual(self.commands[0][COMMAND_SOURCE_FIELD], SOURCE_LOCAL_ADMIN)
        self.assertNotIn("_remote_command_id", self.commands[0])
        self.assertEqual(
            self.commands[0][SERVICE_ADMIN_TOKEN_FIELD], "service-only-secret",
        )

    def test_api_requires_token(self):
        with self.assertRaises(HTTPError) as error:
            self._json("/api/v1/overview", authorized=False)
        self.assertEqual(error.exception.code, 401)

    def test_mutation_requires_an_authenticated_administrator(self):
        with self.assertRaises(HTTPError) as error:
            self._json(
                "/api/v1/actions", "POST", {"action": "remove_limit"},
                admin=False,
            )
        self.assertEqual(error.exception.code, 403)
        self.assertEqual(self.commands, [])

    def test_service_token_is_never_exposed_to_the_browser(self):
        """The browser session must never receive the protected service secret."""
        _, session = self._json("/api/v1/auth/session")
        self.assertNotIn("_service_admin_token", session)
        self.assertNotIn("_service_backend_token", session)
        self.assertNotIn("_backend_management_session", session)
        self.assertNotIn("service-only-secret", json.dumps(session))

    def test_standard_user_can_read_views_and_manage_only_own_notifications(self):
        self.server.admin_authenticator = lambda *_args: {
            "username": "nicklaus", "email": "nicklaus@example.test",
            "is_admin": False, "must_change": False,
            "must_set_email": False,
            "permissions": {
                "view_activity": True, "view_analysis": False,
                "view_limits": True, "view_notifications": True,
                "manage_activity": True, "manage_limits": True,
                "manage_notifications": True,
            },
        }
        self.server.snapshot_provider = lambda selection: {
            "scope": selection.get("scope", "today"), "usage": [],
            "limits": [{"key": "app:test"}],
            "notification_rules": [
                {"id": "own", "owner": "nicklaus"},
                {"id": "other", "owner": "admin"},
                {"id": "mandatory", "mandatory": True},
            ],
        }
        _, session = self._json(
            "/api/v1/auth/login", "POST",
            {"username": "nicklaus", "password": "correct-password"},
            admin=False,
        )
        self.assertFalse(session["is_admin"])
        self.admin_token = session["admin_token"]

        status, overview = self._json("/api/v1/overview?scope=today")
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["id"] for item in overview["notification_rules"]],
            ["own", "mandatory"],
        )

        status, result = self._json(
            "/api/v1/actions", "POST", {
                "action": "set_notification_rule",
                "rule": {"kind": "client_connected", "owner": "admin"},
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])
        self.assertEqual(
            self.commands[-1]["rule"]["owner"], "nicklaus",
        )
        self.assertEqual(
            self.commands[-1][COMMAND_SOURCE_FIELD], SOURCE_LOCAL_ADMIN,
        )

        status, result = self._json(
            "/api/v1/actions", "POST", {
                "action": "set_notification_rule",
                "rule": {
                    "id": "own", "kind": "client_connected",
                    "owner": "admin", "enabled": False,
                },
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])
        self.assertEqual(self.commands[-1]["rule"]["id"], "own")
        self.assertEqual(self.commands[-1]["rule"]["owner"], "nicklaus")

        status, result = self._json(
            "/api/v1/actions", "POST", {
                "action": "rename_target", "target_key": "app:test",
                "label": "Test renommé",
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])
        self.assertEqual(self.commands[-1]["action"], "rename_target")

        with self.assertRaises(HTTPError) as error:
            self._json(
                "/api/v1/actions", "POST", {
                    "action": "remove_notification_rule",
                    "rule_id": "other",
                },
            )
        self.assertEqual(error.exception.code, 403)

        with self.assertRaises(HTTPError) as error:
            self._json(
                "/api/v1/actions", "POST",
                {"action": "remove_limit", "target_key": "app:test"},
            )
        self.assertEqual(error.exception.code, 403)
        self.assertEqual(len(self.commands), 3)

        with self.assertRaises(HTTPError) as error:
            self._json("/api/v1/overview?scope=all")
        self.assertEqual(error.exception.code, 403)

    def test_local_admin_notification_view_defaults_to_the_admin_owner(self):
        self.server.snapshot_provider = lambda selection: {
            "scope": selection.get("scope", "today"),
            "notification_rules": [
                {"id": "admin", "owner": "admin"},
                {"id": "nicklaus", "owner": "nicklaus"},
                {"id": "legacy-admin", "owner": ""},
                {"id": "mandatory", "owner": "nicklaus", "mandatory": True},
            ],
        }

        status, overview = self._json(
            "/api/v1/overview?scope=notifications&owner=admin",
        )

        self.assertEqual(status, 200)
        self.assertEqual(
            [item["id"] for item in overview["notification_rules"]],
            ["admin", "legacy-admin", "mandatory"],
        )

    def test_local_notification_scope_and_actions_are_proxied_to_backend(self):
        calls = []

        class BackendProxy:
            @staticmethod
            def backend_admin(token, action, payload):
                calls.append((token, action, payload))
                if action == "session_devices":
                    return {"devices": [
                        {"device_id": "pc-1"}, {"device_id": "pc-2"},
                    ]}
                if action == "policy_users":
                    return {"users": [{
                        "username": "nicklaus",
                        "device_ids": ["pc-1", "pc-2"],
                    }]}
                if action == "notification_overview":
                    return {"notification_rules": [{
                        "id": "admin-rule", "owner": payload["owner"],
                    }]}
                if action == "notification_action":
                    return {"ok": True, "queued": True, "id": 42}
                raise AssertionError(action)

        self.server.backend_manager = BackendProxy()

        _, devices = self._json("/api/v1/devices")
        _, policies = self._json("/api/v1/policies")
        _, overview = self._json(
            "/api/v1/overview?scope=notifications&owner=admin&device_id=pc-2",
        )
        status, queued = self._json(
            "/api/v1/actions", "POST", {
                "action": "set_notification_rule", "device_id": "pc-2",
                "idempotency_key": "notification-test:1",
                "rule": {
                    "id": "admin-rule", "kind": "client_connected",
                    "owner": "admin", "enabled": False,
                },
            },
        )

        self.assertEqual([item["device_id"] for item in devices["devices"]], ["pc-1", "pc-2"])
        self.assertEqual(policies["users"][0]["username"], "nicklaus")
        self.assertEqual(overview["notification_rules"][0]["owner"], "admin")
        self.assertEqual(status, 202)
        self.assertTrue(queued["queued"])
        self.assertEqual(self.commands, [])
        self.assertEqual(calls[-1][0], "service-only-secret")
        self.assertEqual(calls[-1][1], "notification_action")
        self.assertEqual(calls[-1][2]["device_id"], "pc-2")
        self.assertEqual(
            calls[-1][2]["command"]["rule"]["owner"], "admin",
        )

    def test_local_admin_can_manage_policies_catalog_and_all_devices(self):
        calls = []

        class BackendProxy:
            base_url = "https://usage.example.test/usage-guard"

            @staticmethod
            def backend_admin(token, action, payload):
                calls.append((token, action, payload))
                responses = {
                    "session_devices": {"devices": [
                        {"device_id": "pc-local", "label": "ordi 1"},
                        {"device_id": "x20W", "label": "ordi 2"},
                    ]},
                    "policy_users": {"users": [{
                        "username": "nicklaus",
                        "device_ids": ["pc-local", "x20W"],
                    }]},
                    "policy_overview": {
                        "username": "nicklaus", "configured": True,
                        "policy": {"limits": []},
                    },
                    "policy_usage": {"targets": [], "categories": []},
                    "policy_action": {
                        "id": "policy-1", "pending_devices": ["x20W"],
                    },
                    "cancel_policy_operation": {"cancelled": True},
                    "catalog_action": {"id": "catalog-1", "queued": True},
                    "device_action": {"id": "command-1", "queued": True},
                    "device_action_status": {
                        "id": "command-1", "applied": False,
                    },
                    "cancel_device_action": {"cancelled": True},
                    "create_device_enrollment": {
                        "enrollment": {"code": "single-use-code"},
                    },
                }
                if action not in responses:
                    raise AssertionError(action)
                return responses[action]

        self.server.backend_manager = BackendProxy()
        self.server.backend_client.device_id = "pc-local"

        _, devices = self._json("/api/v1/devices")
        _, policies = self._json("/api/v1/policies")
        _, policy = self._json("/api/v1/policies/nicklaus")
        _, usage = self._json(
            "/api/v1/policies/nicklaus/usage"
            "?start=2026-08-30T00%3A00%3A00%2B02%3A00"
            "&end=2026-08-30T12%3A00%3A00%2B02%3A00"
            "&device_id=pc-local&device_id=x20W"
        )
        policy_status, policy_action = self._json(
            "/api/v1/policies/nicklaus/actions", "POST", {
                "action": "set_limit", "device_ids": ["pc-local", "x20W"],
            },
        )
        catalog_status, catalog_action = self._json(
            "/api/v1/catalogs/nicklaus/actions", "POST", {
                "action": "rename_target", "target_key": "app:codex",
                "device_ids": ["pc-local", "x20W"],
            },
        )
        device_status, device_action = self._json(
            "/api/v1/actions", "POST", {
                "action": "reset_limit", "device_id": "x20W",
                "idempotency_key": "reset:1",
            },
        )
        _, action_state = self._json(
            "/api/v1/actions/command-1?device_id=x20W",
        )
        _, cancelled = self._json(
            "/api/v1/actions/command-1/cancel", "POST", {
                "device_id": "x20W",
            },
        )
        _, enrollment = self._json(
            "/api/v1/admin/device-enrollments", "POST", {
                "username": "nicklaus", "display_name": "portable",
            },
        )

        self.assertTrue(devices["federated"])
        self.assertEqual(
            [item["device_id"] for item in devices["devices"]],
            ["pc-local", "x20W"],
        )
        self.assertTrue(policies["federated"])
        self.assertTrue(policy["configured"])
        self.assertEqual(usage, {"targets": [], "categories": []})
        self.assertEqual(policy_status, 202)
        self.assertEqual(policy_action["id"], "policy-1")
        self.assertEqual(catalog_status, 202)
        self.assertEqual(catalog_action["id"], "catalog-1")
        self.assertEqual(device_status, 202)
        self.assertEqual(device_action["id"], "command-1")
        self.assertFalse(action_state["applied"])
        self.assertTrue(cancelled["cancelled"])
        self.assertEqual(
            enrollment["backend_url"],
            "https://usage.example.test/usage-guard",
        )
        usage_call = next(call for call in calls if call[1] == "policy_usage")
        self.assertEqual(usage_call[2]["device_ids"], ["pc-local", "x20W"])
        device_call = next(call for call in calls if call[1] == "device_action")
        self.assertEqual(device_call[2]["device_id"], "x20W")
        self.assertEqual(self.commands, [])

    def test_backend_failure_falls_back_only_for_the_current_computer(self):
        class BackendProxy:
            @staticmethod
            def backend_admin(_token, _action, _payload):
                raise OSError("backend hors ligne")

        self.server.backend_manager = BackendProxy()
        self.server.backend_client.device_id = "pc-local"
        self.server.snapshot_provider = lambda selection: {
            "scope": selection.get("scope", "today"),
            "usage": [{"key": "app:local"}],
        }

        status, overview = self._json(
            "/api/v1/overview?scope=today&device_id=pc-local",
        )
        self.assertEqual(status, 200)
        self.assertEqual(overview["usage"][0]["key"], "app:local")

        status, result = self._json(
            "/api/v1/actions", "POST", {
                "action": "rename_target", "device_id": "pc-local",
                "target_key": "app:local", "label": "Local",
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])
        self.assertEqual(self.commands[-1]["target_key"], "app:local")

        with self.assertRaises(HTTPError) as failure:
            self._json(
                "/api/v1/actions", "POST", {
                    "action": "rename_target", "device_id": "x20W",
                    "target_key": "app:remote", "label": "Remote",
                },
            )
        self.assertEqual(failure.exception.code, 502)
        self.assertEqual(len(self.commands), 1)

    def test_missing_email_returns_the_first_login_step_without_admin_session(self):
        self.server.admin_authenticator = lambda *_args: {
            "username": "new-admin", "email": "", "is_admin": True,
            "must_change": False, "must_set_email": True,
            "_service_admin_token": "must-not-leak",
        }
        _, response = self._json(
            "/api/v1/auth/login", "POST",
            {"username": "new-admin", "password": "correct-password"},
            admin=False,
        )
        self.assertFalse(response["authenticated"])
        self.assertTrue(response["must_set_email"])
        self.assertNotIn("admin_token", response)
        self.assertNotIn("must-not-leak", json.dumps(response))

    def test_query_string_token_is_rejected(self):
        with self.assertRaises(HTTPError) as error:
            self._json(f"/api/v1/overview?token={self.server.token}", authorized=False)
        self.assertEqual(error.exception.code, 401)

    def test_dns_rebinding_host_is_rejected(self):
        request = Request(
            self.base_url + "/api/v1/bootstrap",
            headers={"Host": "attacker.example"},
        )
        with self.assertRaises(HTTPError) as error:
            urlopen(request, timeout=2)
        self.assertEqual(error.exception.code, 421)

    def test_local_backend_traffic_can_be_read_and_reset(self):
        class Backend:
            configured = True

            def __init__(self):
                self.reset = False

            def traffic_stats(self):
                return {
                    "enabled": True, "configured": True,
                    "uploaded_bytes": 2048, "elapsed_seconds": 120,
                    "upload_rate_bytes_per_minute": 1024,
                    "reset_at": "2026-08-20T10:00:00+00:00",
                    "last_upload_at": "2026-08-20T10:01:00+00:00",
                }

            def reset_traffic_stats(self):
                self.reset = True
                return {
                    "enabled": True, "configured": True,
                    "uploaded_bytes": 0, "elapsed_seconds": 0,
                    "upload_rate_bytes_per_minute": 0,
                    "reset_at": "2026-08-20T10:02:00+00:00",
                    "last_upload_at": None,
                }

        self.server.backend_client = Backend()

        status, stats = self._json("/api/v1/backend/traffic")
        self.assertEqual(status, 200)
        self.assertEqual(stats["uploaded_bytes"], 2048)

        status, reset = self._json("/api/v1/backend/traffic/reset", method="POST")
        self.assertEqual(status, 200)
        self.assertEqual(reset["uploaded_bytes"], 0)
        self.assertTrue(self.server.backend_client.reset)

    def test_local_pwa_can_manage_and_test_backend_email(self):
        class Backend:
            configured = True

            def email_settings(self):
                return {"email_settings": {"enabled": False}}

            def save_email_settings(self, settings):
                return {"ok": True, "email_settings": settings}

            def test_email_settings(self, recipient):
                return {"ok": True, "recipient": recipient}

        self.server.backend_client = Backend()
        _, current = self._json("/api/v1/backend/email")
        self.assertFalse(current["email_settings"]["enabled"])
        _, saved = self._json("/api/v1/backend/email", "POST", {"enabled": True})
        self.assertTrue(saved["email_settings"]["enabled"])
        _, tested = self._json(
            "/api/v1/backend/email/test", "POST",
            {"recipient": "owner@example.test"},
        )
        self.assertEqual(tested["recipient"], "owner@example.test")

    def test_local_pwa_displays_service_backend_error(self):
        class Backend:
            def backend_admin(self, _token, _action, _payload):
                raise RuntimeError(
                    "Envoi SMTP impossible : identifiants invalides"
                )

        self.server.backend_manager = Backend()
        with self.assertRaises(HTTPError) as failure:
            self._json(
                "/api/v1/backend/email/test", "POST",
                {"recipient": "owner@example.test"},
            )
        self.assertEqual(failure.exception.code, 502)
        response = json.loads(failure.exception.read().decode("utf-8"))
        self.assertEqual(
            response["error"],
            "Envoi SMTP impossible : identifiants invalides",
        )


if __name__ == "__main__":
    unittest.main()
