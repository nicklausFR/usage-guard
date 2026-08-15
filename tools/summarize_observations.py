"""Print reconstructed active durations from the experimental raw journal."""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from observation_journal import rebuild_active_seconds
from usage_guard import USAGE_PATH


def format_duration(seconds):
    seconds = int(round(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours} h {minutes:02d} min {seconds:02d} s"


if __name__ == "__main__":
    if len(sys.argv) > 1:
        directory = Path(sys.argv[1])
    else:
        local_app_data = os.environ.get("LOCALAPPDATA")
        installed_directory = (
            Path(local_app_data) / "Usage Guard" / "observations"
            if local_app_data else None
        )
        directory = (
            installed_directory
            if installed_directory and installed_directory.exists()
            else USAGE_PATH.parent / "observations"
        )
    totals = rebuild_active_seconds(directory)
    if not totals:
        print("Aucune observation terminée.")
    for target_key, seconds in sorted(totals.items(), key=lambda item: item[1], reverse=True):
        print(f"{format_duration(seconds):>18}  {target_key}")
