import json
import sys
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from browser_bridge import BrowserBridge


class BrowserBridgeInventoryTest(unittest.TestCase):
    def test_active_tab_keeps_the_complete_url(self):
        bridge = BrowserBridge(port=0)
        bridge.start()
        try:
            port = bridge._server.server_address[1]
            url = "https://usage.example.test/usage-guard?view=today#activity"
            request = Request(
                f"http://127.0.0.1:{port}/active",
                data=json.dumps({"url": url}).encode("utf-8"),
                headers={"Content-Type": "application/json"}, method="POST",
            )
            with urlopen(request, timeout=2) as response:
                self.assertEqual(response.status, 200)

            self.assertEqual(bridge.current().url, url)
        finally:
            bridge.stop()

    def test_generic_browser_activity_clears_the_previous_url(self):
        bridge = BrowserBridge(port=0)
        bridge.start()
        try:
            port = bridge._server.server_address[1]
            for payload in (
                {"url": "https://example.test"},
                {"generic": True, "audible": False},
            ):
                request = Request(
                    f"http://127.0.0.1:{port}/active",
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"}, method="POST",
                )
                with urlopen(request, timeout=2) as response:
                    self.assertEqual(response.status, 200)
            current = bridge.current()
            self.assertTrue(current.generic)
            self.assertEqual(current.url, "")
            self.assertEqual(current.title, "")
        finally:
            bridge.stop()

    def test_extension_can_publish_complete_open_tab_inventory(self):
        bridge = BrowserBridge(port=0)
        bridge.start()
        try:
            port = bridge._server.server_address[1]
            body = json.dumps({"tabs": [
                {"url": "https://example.test/a", "title": "A"},
                {"url": "https://example.test/b", "title": "B"},
                {"url": "chrome://settings", "title": "Settings"},
            ]}).encode("utf-8")
            request = Request(
                f"http://127.0.0.1:{port}/tabs", data=body,
                headers={"Content-Type": "application/json"}, method="POST",
            )
            with urlopen(request, timeout=2) as response:
                self.assertEqual(response.status, 200)
            tabs = bridge.open_tabs()
            self.assertEqual(len(tabs), 2)
            self.assertEqual({tab["url"] for tab in tabs}, {
                "https://example.test/a",
                "https://example.test/b",
            })
        finally:
            bridge.stop()

    def test_bridge_rejects_web_page_origins(self):
        bridge = BrowserBridge(port=0)
        bridge.start()
        try:
            port = bridge._server.server_address[1]
            request = Request(
                f"http://127.0.0.1:{port}/active",
                data=json.dumps({"url": "https://example.test"}).encode("utf-8"),
                headers={"Content-Type": "text/plain", "Origin": "https://example.test"},
                method="POST",
            )
            # On Windows, the HTTP server can close this rejected request while
            # its body is still unread. Depending on the local network filter,
            # urllib then receives either the explicit 403 or a socket abort;
            # both prove that the untrusted web origin was not accepted.
            with self.assertRaises((HTTPError, ConnectionAbortedError)) as error:
                urlopen(request, timeout=2)
            if isinstance(error.exception, HTTPError):
                self.assertEqual(error.exception.code, 403)
        finally:
            bridge.stop()

    def test_bridge_accepts_browser_extension_origin(self):
        bridge = BrowserBridge(port=0)
        bridge.start()
        try:
            port = bridge._server.server_address[1]
            request = Request(
                f"http://127.0.0.1:{port}/active",
                data=json.dumps({"url": "https://example.test"}).encode("utf-8"),
                headers={"Content-Type": "application/json", "Origin": "chrome-extension://abcdefghijklmnopabcdefghijklmnop"},
                method="POST",
            )
            with urlopen(request, timeout=2) as response:
                self.assertEqual(response.status, 200)
            status = bridge.extension_status()
            self.assertTrue(status["connected"])
            self.assertTrue(status["last_seen_at"])
        finally:
            bridge.stop()

    def test_invalid_extension_payload_does_not_refresh_heartbeat(self):
        bridge = BrowserBridge(port=0)
        bridge.start()
        try:
            port = bridge._server.server_address[1]
            request = Request(
                f"http://127.0.0.1:{port}/active",
                data=json.dumps({"url": "file:///not-accepted"}).encode("utf-8"),
                headers={"Content-Type": "application/json"}, method="POST",
            )
            with self.assertRaises(HTTPError):
                urlopen(request, timeout=2)
            self.assertFalse(bridge.extension_status()["connected"])
        finally:
            bridge.stop()


if __name__ == "__main__":
    unittest.main()
