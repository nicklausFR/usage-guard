"""Return success when the production service and desktop bridge are ready."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from decision_service import DecisionServiceClient, PUBLIC_SERVICE_AUTHKEY
from runtime_profile import profile_named


def main():
    profile = profile_named("production")
    try:
        health = DecisionServiceClient(
            profile.decision_pipe_name, PUBLIC_SERVICE_AUTHKEY
        ).health()
    except Exception:
        return 1
    backend = health.get("backend") or {}
    return 0 if all((
        backend.get("enabled"),
        backend.get("configured"),
        backend.get("started"),
        backend.get("desktop_connected"),
    )) else 1


if __name__ == "__main__":
    raise SystemExit(main())
