# Usage Guard

Usage Guard is a Windows activity monitor and usage-control application. It
records application, website, media, and Windows-session activity, then
applies configurable warnings and limits.

It can connect one or more monitored computers to an authenticated backend.
Client connections are outbound, so monitored computers do not need to expose
an inbound Internet port. A local-backend installation profile is also
available.

## Project status

Usage Guard is a **functional beta**. Its principal monitoring, analysis,
policy, notification, multi-computer, installation, and update workflows work
and have substantial automated test coverage.

It does **not** yet have the robustness, field validation, support guarantees,
or security hardening expected from a finished consumer product. In
particular, the fully local deployment mode has not yet been tested end to end
on a clean Windows installation. Use the project for evaluation and controlled
testing, not as the only safety or parental-control mechanism on a computer.

The current security model is designed to resist ordinary actions by a
standard Windows user. It does not claim to withstand a local administrator,
offline disk access, or modification of the operating system.

## Main features

- Tracks the active Windows application and Windows sessions.
- Tracks active websites through the bundled browser extension.
- Records background media separately from foreground usage.
- Displays current activity and detailed timelines.
- Provides daily, ranged, and all-time analysis.
- Organises applications and websites in hierarchical categories.
- Supports renaming, merging, excluding, reordering, and deleting activities.
- Groups private-browser activity without exposing individual visited sites.
- Applies warnings and blocking rules to computers, categories, applications,
  and websites.
- Synchronises user policies across enrolled computers.
- Delivers signed, user-triggered Windows client updates.
- Provides French and English user interfaces.

## Limits and notifications

A rule can target the entire computer, a category and its contents, one
application, or one website. Rules can define a daily quota, a daily time
window, a one-time block, a permanent validity period, or exact start and end
dates. They can also provide warning periods and exceptional extensions.

Notification rules can cover application starts, policy changes, approaching
or exceeded limits, usage-duration thresholds, time-of-day thresholds, PWA
logins, and monitored-computer connection changes. Notifications can use the
Windows notification system, email, or both.

## Architecture

The production Windows client is split into two main processes:

- a protected Windows service owns policy state, counters, backend
  communication, and allow/block decisions;
- a desktop process observes the interactive session and provides the system
  tray, local PWA, notifications, and blocking overlays.

The browser extension is only a sensor and presentation bridge. It cannot
grant extensions, reset counters, or weaken a policy by itself.

The backend stores accounts, device identities, policy state, delivery status,
and remote activity data. Device secrets and email-transport credentials are
kept out of the PWA and are excluded from the repository.

See [the architecture reference](docs/architecture.md) for the trust model and
remaining hardening work.

## Requirements

- Windows 10 or later;
- Python 3.11 or later for source-based development;
- [ActivityWatch](https://activitywatch.net/) when its optional integration is
  enabled;
- the dependencies listed in `requirements.txt`.

The production installer and client-update packages require additional build
tools listed in `requirements-build.txt`.

## Run from source for development

Use the isolated development profile. It has separate data, ports, mutexes,
and browser-extension settings, and it does not change Windows autostart or
connect to the configured production backend.

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py --profile dev
```

The development PWA is then available at `http://127.0.0.1:18766`. Build the
matching development browser extension with:

```powershell
.\.venv\Scripts\python.exe tools\build_dev_extension.py
```

Load `build\browser-extension-dev` as an unpacked extension in Brave or
Chromium. The production extension uses port `8765`; the development extension
uses port `18765`.

Running `python main.py` without `--profile dev` selects the production profile
and expects the protected Windows service. It is not the recommended way to
start a source checkout.

## Production installation

Production installations are created as signed release artifacts, not by
copying a source checkout into `Program Files`. The installer offers two
profiles:

1. install a backend on the same computer;
2. enrol the computer with an existing HTTPS backend.

The first profile is the currently unvalidated fully local mode described in
the project-status section. The connected profile requires an administrator
account on the target backend and explicitly maps Windows accounts to Usage
Guard users.

The bundled Browser Bridge must be loaded in each monitored browser profile.
See [the browser-extension guide](browser_extension/README.md).

## Versioning

The project intentionally uses two independent release numbers:

- `client_version.py` defines the signed Windows client package version;
- the last release entry in `CHANGELOG.md` defines the backend/PWA asset and
  cache version.

The current source tree uses client version `1.020` and PWA/backend version
`1.132`. Earlier `2.xxx` entries were pre-stable development builds; the public
stable line restarted at `1.000`.

## Quality checks

Run the same checks as the GitHub CI workflow before submitting a change:

```powershell
node --check .\pwa\app.js
node --check .\browser_extension\background.js
node --check .\browser_extension\content.js
node --check .\browser_extension\options.js
python .\tools\audit_i18n.py
node .\tools\check_pwa_i18n.js
python -B -m unittest discover -s tests
```

Together, the translation checks cover desktop gettext messages, static and
dynamic PWA text, backend errors displayed by the PWA, and the
browser-extension locale catalogues.

## Releases

The `CI` workflow runs syntax, translation, and test checks on pushes and pull
requests. The separate `Client Windows release` workflow is manual and requires
repository secrets for Authenticode signing and optional backend publication.
Publication is disabled by default.

Generated installers, ZIP files, manifests, databases, credentials, local
configuration, and operational notes are excluded from Git. Release binaries
belong in GitHub Releases or CI artifacts, never in the source history.

## Project structure

- `main.py`: Windows desktop entry point.
- `decision_service.py`: protected decision-service protocol and runtime.
- `guard.py`: activity aggregation and command handling.
- `usage_guard.py`: persistent usage, policy, and notification logic.
- `app_limiter.py`: local enforcement and blocking overlays.
- `pwa/`: local and remote web-interface sources.
- `usage_guard_backend/`: authenticated backend.
- `browser_extension/`: browser activity and limit bridge.
- `tools/`: build, installation, enrolment, migration, and release tools.
- `tests/`: automated test suite.

## License

GNU General Public License v3.0 or later. See [LICENSE](LICENSE).
