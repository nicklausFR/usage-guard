# Usage Guard

Usage Guard is a Windows activity monitor and usage-control application.
It records application, website, media, and Windows-session activity, then
applies configurable usage limits locally.

The monitored computer remains the source of truth. A local PWA provides the
main interface, while an optional authenticated backend enables remote access
without exposing an inbound port on the monitored computer.

## Main features

- Tracks the active Windows application.
- Tracks active browser websites through the browser extension.
- Records background media separately from active usage.
- Displays the current session and detailed timelines.
- Provides daily, ranged, and all-time analysis.
- Organises applications and websites in hierarchical categories.
- Supports renaming, merging, excluding, and reordering activities.
- Offers French and English interfaces.

## Usage limits

Limits can target:

- the entire computer;
- a category and its contents;
- a specific application;
- a specific website.

Each limit can define:

- an allowed daily usage duration;
- a daily start and end time;
- an optional blocking time;
- a permanent validity period;
- or precise start and expiry dates with times;
- an exceptional extension duration;
- a warning before the allowed time ends.

New limits are active immediately. They can later be enabled, disabled,
edited, reset, or removed. A disabled rule remains stored. A date-bound rule
is removed only after its configured expiry has passed.

## Notifications

Notification rules can cover:

- the start of any limited application;
- the addition, modification, or removal of a limit;
- one or more warnings before a limit;
- changes to a whole-computer limitation;
- a successful remote PWA login;
- a usage-duration threshold;
- a configured time-of-day threshold.

Threshold notifications can target the entire computer, a category, an
application, or a website. Notification rules are currently global to the
monitored computer rather than personal to each remote user.

## Interfaces

The Windows process runs in the system tray and performs monitoring and limit
enforcement. Its tray tooltip lists the limitations relevant today.

The local PWA is opened from the tray icon and provides activity, analysis,
limit, notification, category, and user-management views.

The remote PWA uses authenticated accounts with separate permissions for
viewing and managing activity, limits, and notifications. Administrators can
manage remote users and their access rights.

## Browser extension

The browser extension reports the active tab, website, and browser media state
to the Windows client. This is required for accurate per-site tracking and
website limits. The extension acts only as a sensor and display bridge: limit
decisions, counters, and exceptional extensions remain controlled by Usage
Guard on the monitored computer.

## Data and remote access

Primary usage data and enforcement state are stored on the monitored computer.
The Windows client sends snapshots to the optional backend and polls it for
authorised commands. All client-to-backend connections are outbound HTTPS.

The backend stores remote accounts, the latest device snapshot, and queued
commands. Device credentials are never exposed to PWA users.

## Requirements

- Windows 10 or later;
- Python 3.11 or later for source builds;
- [ActivityWatch](https://activitywatch.net/);
- the ActivityWatch browser extension for website detection;
- PySide6 and the packages listed in `requirements.txt`.

## Project structure

- `main.py`: Windows application entry point.
- `guard.py`: activity aggregation and command handling.
- `usage_guard.py`: persistent usage, limit, and notification data.
- `app_limiter.py`: local enforcement and blocking overlays.
- `pwa/`: local and remote web interface sources.
- `usage_guard_backend/`: authenticated remote backend and deployment tools.
- `browser_extension/`: browser activity bridge.
- `tests/`: automated test suite.

## Future architecture

The planned hardened design separates the trusted policy service from the
desktop interface and browser sensors. It introduces protected storage, a
restricted local IPC protocol, service supervision, and managed browser
integration.

See [docs/architecture.md](docs/architecture.md) for the target architecture
and migration sequence.

## License

GNU General Public License v3.0 or later. See [LICENSE](LICENSE).
