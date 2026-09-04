"""Exchange a one-time enrollment code for a protected client credential."""

import argparse
import json
import os
import socket
import tempfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


def enroll(base_url, code, display_name="", hostname=""):
    base_url = str(base_url or "").rstrip("/")
    parsed = urlparse(base_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("L’adresse du serveur doit utiliser HTTPS.")
    hostname = str(hostname or socket.gethostname()).strip()
    body = json.dumps({
        "code": str(code or "").strip(),
        "hostname": hostname,
        "display_name": str(display_name or hostname).strip(),
    }).encode("utf-8")
    request = Request(
        base_url + "/api/v1/device/enroll", data=body, method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urlopen(request, timeout=20) as response:
            result = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        try:
            detail = json.loads(error.read().decode("utf-8")).get("error", "")
        except (ValueError, UnicodeDecodeError):
            detail = ""
        raise RuntimeError(detail or f"Enrôlement refusé (HTTP {error.code}).") from error
    except URLError as error:
        raise RuntimeError(f"Serveur d’enrôlement inaccessible : {error.reason}") from error
    device_id = str(result.get("device_id") or "").strip()
    device_token = str(result.get("device_token") or "").strip()
    if not device_id or len(device_token) < 32:
        raise RuntimeError("Réponse d’enrôlement incomplète.")
    return {
        "installation_profile": "server",
        "enabled": True,
        "base_url": base_url,
        "device_id": device_id,
        "device_token": device_token,
        "poll_seconds": 15,
        "display_name": str(result.get("display_name") or display_name or hostname),
        "hostname": hostname,
        "windows_identities": list(result.get("windows_identities") or []),
    }


def save_atomic(path, settings):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=path.parent,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(settings, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--code", required=True)
    parser.add_argument("--display-name", default=socket.gethostname())
    parser.add_argument("--hostname", default=socket.gethostname())
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    save_atomic(
        args.output,
        enroll(args.base_url, args.code, args.display_name, args.hostname),
    )
    print("Enrôlement terminé. Les identifiants ont été enregistrés sans être affichés.")


if __name__ == "__main__":
    main()
