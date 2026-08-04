"""Local receiver for the Usage Guard browser companion extension."""

import json
import threading
import time
from dataclasses import dataclass, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@dataclass
class BrowserTab:
    url: str = ""
    title: str = ""
    audible: bool = False
    received_at: float = 0.0


class BrowserBridge:
    def __init__(self, host="127.0.0.1", port=8765):
        self.host = host
        self.port = port
        self._tab = BrowserTab()
        self._lock = threading.Lock()
        self._server = None
        self._thread = None

    def start(self):
        if self._server is not None:
            return
        bridge = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path != "/active":
                    self.send_error(404)
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    payload = json.loads(self.rfile.read(length).decode("utf-8"))
                    url = str(payload.get("url", ""))
                    if not url.startswith(("http://", "https://")):
                        raise ValueError("unsupported URL")
                    with bridge._lock:
                        bridge._tab = BrowserTab(
                            url=url,
                            title=str(payload.get("title", "")),
                            audible=bool(payload.get("audible", False)),
                            received_at=time.monotonic(),
                        )
                except (ValueError, TypeError, json.JSONDecodeError):
                    self.send_error(400)
                    return
                self.send_response(204)
                self.end_headers()

            def log_message(self, *_):
                pass

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        self._server = None
        self._thread = None

    def current(self, max_age_seconds=5):
        with self._lock:
            tab = replace(self._tab)
        return tab if time.monotonic() - tab.received_at <= max_age_seconds else None


browser_bridge = BrowserBridge()
