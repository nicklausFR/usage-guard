import json
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from remote_api import RemoteControlServer
from usage_guard import config


class RemoteControlServerTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        config.REMOTE_API_HOST = "127.0.0.1"
        config.REMOTE_API_PORT = 0
        config.REMOTE_API_TOKEN_PATH = str(Path(self.temporary.name) / "token.txt")
        self.commands = []
        self.server = RemoteControlServer(
            lambda selection: {"scope": selection.get("scope", "today"), "usage": []},
            self._handle_command,
        )
        self.server.start()
        self.base_url = f"http://127.0.0.1:{self.server._server.server_address[1]}"

    def tearDown(self):
        self.server.stop()
        self.temporary.cleanup()

    def _handle_command(self, command):
        self.commands.append(command)
        return {"ok": True}

    def _json(self, path, method="GET", payload=None, authorized=True):
        headers = {"Accept": "application/json"}
        if authorized:
            headers["Authorization"] = f"Bearer {self.server.token}"
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

        status, overview = self._json("/api/v1/overview?scope=all")
        self.assertEqual(status, 200)
        self.assertEqual(overview["scope"], "all")

        status, result = self._json(
            "/api/v1/actions",
            method="POST",
            payload={"action": "rename_target", "target_key": "app:test", "label": "Test"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])
        self.assertEqual(self.commands[0]["target_key"], "app:test")

    def test_api_requires_token(self):
        with self.assertRaises(HTTPError) as error:
            self._json("/api/v1/overview", authorized=False)
        self.assertEqual(error.exception.code, 401)

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


if __name__ == "__main__":
    unittest.main()
