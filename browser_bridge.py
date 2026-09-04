"""Local receiver for the Usage Guard browser companion extension."""

import json
import re
import threading
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from runtime_profile import current_profile


MAX_BODY = 1024 * 1024
EXTENSION_ORIGIN = re.compile(r"^(?:chrome|edge)-extension://[a-z]{32}$")


@dataclass
class BrowserTab:
    url: str = ""
    title: str = ""
    audible: bool = False
    generic: bool = False
    received_at: float = 0.0


class BrowserBridge:
    def __init__(self, host="127.0.0.1", port=None):
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("The browser bridge must listen on loopback only")
        self.host = host
        self.port = (
            current_profile().browser_bridge_port if port is None else int(port)
        )
        self._tab = BrowserTab()
        self._lock = threading.Lock()
        self._server = None
        self._thread = None
        self._limit_host = ""
        self._limit_state = None
        self._limit_provider = None
        self._extension_requests = []
        self._open_tabs = None
        self._extension_seen_monotonic = 0.0
        self._extension_seen_at = ""

    def start(self):
        if self._server is not None:
            return
        bridge = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path not in {"/active", "/extension", "/tabs"}:
                    self.send_error(404)
                    return
                origin = self.headers.get("Origin", "")
                if origin and not EXTENSION_ORIGIN.fullmatch(origin):
                    self.send_error(403)
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if length < 0 or length > MAX_BODY:
                        raise ValueError("invalid payload size")
                    payload = json.loads(self.rfile.read(length).decode("utf-8"))
                    if not isinstance(payload, dict):
                        raise ValueError("invalid payload")
                    if self.path == "/tabs":
                        tabs = payload.get("tabs", [])
                        if not isinstance(tabs, list):
                            raise ValueError("invalid tab inventory")
                        normalized = []
                        for tab in tabs:
                            url = str(tab.get("url", "")) if isinstance(tab, dict) else ""
                            if not url.startswith(("http://", "https://")):
                                continue
                            normalized.append({
                                "url": url,
                                "title": str(tab.get("title", "")),
                                "audible": bool(tab.get("audible", False)),
                            })
                        with bridge._lock:
                            bridge._open_tabs = normalized
                        bridge._mark_extension_seen()
                        self._send_json({"accepted": True})
                        return
                    if self.path == "/extension":
                        target_key = str(payload.get("target_key", ""))
                        if not target_key.startswith(("site:", "category:")):
                            raise ValueError("unsupported limit target")
                        with bridge._lock:
                            bridge._extension_requests.append(target_key)
                        bridge._mark_extension_seen()
                        self._send_json({"accepted": True})
                        return
                    generic = bool(payload.get("generic"))
                    if generic:
                        with bridge._lock:
                            bridge._tab = BrowserTab(
                                title="",
                                audible=bool(payload.get("audible", False)),
                                generic=True,
                                received_at=time.monotonic(),
                            )
                        bridge._mark_extension_seen()
                        self._send_json({"limit": None})
                        return
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
                        provider = bridge._limit_provider
                        cached_state = (
                            dict(bridge._limit_state)
                            if bridge._limit_state is not None
                            and bridge._limit_host == _url_host(url)
                            else None
                        )
                    try:
                        state = provider(url) if provider is not None else cached_state
                    except Exception:
                        state = cached_state
                    bridge._mark_extension_seen()
                except (ValueError, TypeError, json.JSONDecodeError):
                    self.send_error(400)
                    return
                self._send_json({"limit": state})

            def _send_json(self, payload):
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

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

    def set_limit_state(self, url, state):
        with self._lock:
            self._limit_host = _url_host(url)
            self._limit_state = dict(state) if state else None

    def set_limit_provider(self, provider):
        with self._lock:
            self._limit_provider = provider

    def take_extension_requests(self):
        with self._lock:
            requests = self._extension_requests
            self._extension_requests = []
        return requests

    def open_tabs(self):
        """Return the last complete browser inventory, or None before first sync."""
        with self._lock:
            return None if self._open_tabs is None else [dict(tab) for tab in self._open_tabs]

    def extension_status(self, max_age_seconds=75):
        """Return a heartbeat status suitable for protected remote reporting."""
        with self._lock:
            seen = self._extension_seen_monotonic
            seen_at = self._extension_seen_at
        connected = bool(seen) and time.monotonic() - seen <= max_age_seconds
        return {"connected": connected, "last_seen_at": seen_at}

    def _mark_extension_seen(self):
        with self._lock:
            self._extension_seen_monotonic = time.monotonic()
            self._extension_seen_at = datetime.now(timezone.utc).isoformat(
                timespec="seconds"
            )


def _url_host(url):
    from urllib.parse import urlparse

    try:
        parsed = urlparse(str(url))
        host = (parsed.hostname or "").lower().removeprefix("www.")
        if host.rstrip(".") in {"localhost", "127.0.0.1", "::1"} and parsed.port is not None:
            return f"[{host}]:{parsed.port}" if ":" in host else f"{host}:{parsed.port}"
        return host
    except ValueError:
        return ""


browser_bridge = BrowserBridge()
