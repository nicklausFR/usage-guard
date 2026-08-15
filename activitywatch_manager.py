import subprocess
import time
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import urlopen

from usage_guard import config


class ActivityWatchManager:
    def __init__(self):
        self.processes = []
        install_dir = getattr(config, "ACTIVITYWATCH_INSTALL_DIR", "")
        self.install_dir = Path(install_dir) if install_dir else _default_install_dir()
        configured = str(getattr(config, "ACTIVITYWATCH_BASE_URL", "http://localhost:5600")).rstrip("/")
        parsed = urlparse(configured)
        self.base_url = (
            configured
            if parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "::1", "localhost"}
            else "http://localhost:5600"
        )

    def ensure_running(self):
        if not bool(getattr(config, "ACTIVITYWATCH_AUTOSTART_HEADLESS", True)):
            return
        if self.is_server_available():
            return
        self._start(Path("aw-server") / "aw-server.exe")
        self._wait_for_server()
        for relative in (
            Path("aw-watcher-window") / "aw-watcher-window.exe",
            Path("aw-watcher-afk") / "aw-watcher-afk.exe",
        ):
            self._start(relative)

    def is_server_available(self):
        try:
            with urlopen(f"{self.base_url}/api/0/buckets/", timeout=0.5):  # nosec B310
                return True
        except (OSError, URLError, TimeoutError, ValueError):
            return False

    def stop_started_processes(self):
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
        self.processes.clear()

    def _wait_for_server(self):
        for _ in range(20):
            if self.is_server_available():
                return True
            time.sleep(0.25)
        return False

    def _start(self, relative_or_absolute):
        executable = Path(relative_or_absolute)
        if not executable.is_absolute():
            executable = self.install_dir / executable
        if not executable.exists():
            return
        flags = 0
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            flags |= subprocess.CREATE_NO_WINDOW
        process = subprocess.Popen(
            [str(executable)],
            cwd=str(executable.parent),
            creationflags=flags,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.processes.append(process)


def _default_install_dir():
    return Path.home() / "AppData" / "Local" / "Programs" / "ActivityWatch"
