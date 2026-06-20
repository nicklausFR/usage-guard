# Usage-Guard

Version 0.1 is a proof of concept.

Usage-Guard is a Windows systray application for limiting computer, application, and website usage with daily, weekly, or monthly quotas.

This project does not try to measure activity itself. It uses ActivityWatch as the activity source, then adds a small rule engine and systray UI for limits.

Author: nicklausFR

License: GNU General Public License v3.0 or later. See `LICENSE`.

## Status

Version 0.1 is an early proof of concept, not a finished blocker.

Implemented:

- PySide6/Qt systray UI.
- Rule list with per-rule On/Off controls.
- Local YAML rules.
- Local encrypted usage counters on Windows (`usage.dat` + backup mirror).
- Daily, weekly, and monthly quotas.
- ActivityWatch integration for active window, active browser URL, and AFK status.
- Headless startup of ActivityWatch desktop components when installed.
- Joker mode to temporarily extend usage.
- Security lock if usage counter files are deleted after initialization.

Not production-ready yet:

- Blocking/enforcement is still conservative.
- Website limits require the ActivityWatch browser extension.
- Tamper resistance is limited without a Windows service or administrator-controlled storage.
- Configuration is still file-based.

## ActivityWatch Dependency

Usage-Guard depends on ActivityWatch at runtime.

Required for normal use:

- ActivityWatch desktop app installed.
- `aw-server`
- `aw-watcher-window`
- `aw-watcher-afk`

Required for website rules:

- ActivityWatch Web Watcher browser extension.

Usage-Guard can start the desktop ActivityWatch components headlessly, without showing the ActivityWatch tray icon. It reads ActivityWatch through the local REST API:

```text
http://localhost:5600
```

ActivityWatch is not vendored in this repository.

## Install

Install Python dependencies:

```powershell
pip install -r requirements.txt
```

Install ActivityWatch:

```powershell
winget install --id ActivityWatch.ActivityWatch --exact
```

Install the ActivityWatch Web Watcher extension in your browser if you want website limits.

## Run

```powershell
python main.py
```

## Rule Model

Rules live in `rules.yaml`.

```yaml
rules:
  - name: YouTube daily
    target_type: site
    target: youtube
    enabled: true
    action: warn
    quotas:
      - period: day
        limit_minutes: 45
    windows: []
```

Supported target types:

- `computer`
- `app`
- `site`

Supported quota periods:

- `day`
- `week`
- `month`

## Security Notes

Usage counters are encrypted with Windows DPAPI when running on Windows. This protects against casual editing and detects corrupt data.

This does not make files impossible to delete. If `usage.dat` and its mirror are deleted after initialization, Usage-Guard starts in security lock mode. The prototype master password is:

```text
usage-guard
```

Replace `MASTER_PASSWORD_SHA256` in `config.yaml` before relying on this behavior.

## Version

Current version: `0.1`
