# Usage Monitor

Usage Monitor is a Windows desktop application for local activity tracking. It
records active application use, background media playback, and browser-site
time. Time limits and rules will be implemented in a later phase.

## Main features

- Organises applications and browser sites in a collapsible tree. Sites can be
  made specific, placed in sub-categories, renamed, merged, or excluded.
- Tracks background media separately as **Passive playback** when a real media
  session continues while another application is in use.
- Shows today's totals or all-time totals, including computer on time, active
  use, and passive media use.
- Keeps activity data locally.

## Requirements

- Windows
- Python 3.11 or later
- Qt for Python (PySide6), used for the desktop interface
- [ActivityWatch](https://activitywatch.net/), required for active-application
  and browser-site detection; run it with its browser extension enabled.

Author: nicklausFR

License: GNU General Public License v3.0 or later. See `LICENSE`.
