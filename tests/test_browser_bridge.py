import json
import sys
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from browser_bridge import BrowserBridge


class BrowserBridgeInventoryTest(unittest.TestCase):
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
            with self.assertRaises(HTTPError) as error:
                urlopen(request, timeout=2)
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
        finally:
            bridge.stop()


if __name__ == "__main__":
    unittest.main()
