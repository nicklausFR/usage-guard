# Usage Monitor

Usage Monitor is a small Windows system-tray application that records how much
active time is spent in each application. It is monitoring only: there are no
limits, quotas, warnings, blocks, passwords, or usage rules.

## Behaviour

- Starts automatically when the current Windows user logs in.
- Counts only the application in the foreground.
- Compte l'application au premier plan uniquement pendant une interaction
  clavier/souris récente (trois secondes par défaut).
- Continue de compter une vidéo en lecture dans l'application au premier plan,
  via les sessions média Windows. Le son seul ne compte jamais.
- Stores totals per application and per calendar day in `activity.json`.
  In the compiled Windows executable, this file is kept in
  `%LOCALAPPDATA%\Usage Monitor\activity.json`, so it survives updates and
  restarts.
- Shows today's totals or all-time totals from the system-tray panel.
- Keeps all activity data locally.

The program uses ActivityWatch when it is installed and falls back to the
Windows foreground-window API otherwise. ActivityWatch is therefore optional.

## Install and run

```powershell
pip install -r requirements.txt
python main.py
```

## Build the `.exe`

```powershell
pip install pyinstaller
python build_exe.py
```

The result is `dist\usage-guard.exe`. The build script bundles `config.yaml`;
the statistics themselves are deliberately stored outside the executable in
the per-user folder shown above. On the first build, an existing project
`activity.json` is copied there automatically, without overwriting a file that
is already present in the per-user folder. At its first launch, the executable
also merges an `activity.json` found next to the executable (or in its parent
folder), so existing project statistics are retained.

The first launch creates this per-user Windows startup entry:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UsageMonitor
```

No administrator rights are required. To disable automatic startup, set
`AUTOSTART_WITH_WINDOWS: false` in `config.yaml` and remove the `UsageMonitor`
value from that registry key.

## Configuration

Relevant values in `config.yaml`:

- `POLL_INTERVAL_MS`: foreground application sampling interval.
- `RECENT_INPUT_SECONDS`: durée pendant laquelle une saisie clavier/souris
  continue à compter l'application au premier plan.
- `VIDEO_PLAYER_APPS` et `VIDEO_URL_PATTERNS`: lecteurs et sites qui peuvent
  être comptés pendant une lecture vidéo. Ajoutez-y vos applications/sites si
  nécessaire; cette liste empêche une session de musique ou de podcast d'être
  considérée comme du temps d'écran. La reconnaissance des sites dans un
  navigateur nécessite l'extension ActivityWatch Web Watcher.
- `AUTOSTART_WITH_WINDOWS`: register automatic startup on launch.
- `ACTIVITYWATCH_ENABLED`: use ActivityWatch when available.
- `ACTIVITYWATCH_AUTOSTART_HEADLESS`: start installed ActivityWatch components.

## Privacy

Only application names and durations are stored. Window titles and browser URLs
are not written to `activity.json`.

Author: nicklausFR

License: GNU General Public License v3.0 or later. See `LICENSE`.
