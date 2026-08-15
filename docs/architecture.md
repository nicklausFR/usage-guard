# Target architecture

## Status

Approved direction. This document guides future implementation work and architectural decisions.

## Goal

Make Usage Guard meaningfully difficult for a standard Windows user to bypass, without claiming protection against a local administrator or rewriting the existing application.

The intended deployment has one monitored computer, one restricted user, and a small number of authorized remote users. The design should remain proportionate to that scope.

## Overview

Usage Guard is split into two processes:

1. **UsageGuard Service**, the trusted Windows service;
2. **UsageGuard Desktop**, the user-session application responsible for Windows activity detection, Qt, the system tray, and blocking overlays.

The browser extension remains a sensor and presentation layer. It never decides which permissions or extensions are granted.

```text
Authorized remote users / backend
                 |
                 v
         UsageGuard Service
         - policies and counters
         - protected storage
         - allow/block decisions
         - Desktop supervision
                 ^
                 | local IPC
                 v
         UsageGuard Desktop
         - ActivityProbe
         - Qt UI and system tray
         - blocking overlays
         - session observation
                 ^
                 | Native Messaging (target)
                 v
         Managed browser extension
```

## UsageGuard Service

The service is installed once with administrator elevation and then runs independently of the restricted account.

It is solely responsible for:

- storing policies and limit counters;
- deciding whether an application or website is allowed;
- granting authorized extensions;
- receiving commands from the backend;
- storing protected state under `%ProgramData%\Usage Guard` with appropriate ACLs;
- detecting, reporting, and recovering from Desktop termination;
- using monotonic time for durations and detecting inconsistent system-clock changes.

The service has no Qt dependency and does not display UI directly in the interactive Windows session.

## UsageGuard Desktop

The Desktop process reuses the existing implementation wherever practical:

- foreground-window and media-session detection;
- browser integration;
- system tray, notifications, and local PWA;
- blocking overlays in the user session.

It sends observations to the service and applies the returned decision. It cannot reduce, remove, or reset a production limit.

The local PWA may read state. Operations that reduce protection are reserved for authorized remote users.

## Local communication

The target is a small Windows IPC surface, preferably a named pipe with explicit ACLs.

The versioned protocol separates:

- observations sent by Desktop;
- read-only state queries;
- decisions returned by the service;
- administrative commands unavailable to the restricted account.

The existing local HTTP API may remain during migration, but it must not expose commands that reduce protection.

## Browser extension

The extension supplies information that a Windows application cannot reliably obtain: the active tab, active URL, and browser media playback.

Its role is limited to:

- reporting the active tab and relevant state;
- requesting current limit state;
- displaying or enforcing a block requested by Usage Guard.

It cannot grant an extension, reset a counter, or disable a limit.

For managed deployments:

- the extension has a stable identifier;
- a Brave/Chromium machine policy installs it;
- the standard user cannot disable or remove it;
- guest and unmanaged profiles are disabled;
- unsupervised browsers are blocked as applications;
- a missing extension heartbeat eventually blocks the browser and triggers a remote report.

The authenticated, origin-checked HTTP Browser Bridge may remain temporarily. The target design uses Native Messaging connected to the service IPC.

## Development and testing

Business rules should live in a Python core without direct Qt, Windows-service, or network dependencies.

The core accepts adapters for:

- in-memory unit tests;
- fast single-process local development;
- production IPC with the Windows service.

Unit tests use a simulated clock, temporary storage, and fake adapters. Only a small integration suite starts the real service.

Development and production remain isolated through separate instance names, IPC endpoints, data directories, and extension identifiers. A development instance cannot modify production service state.

Production protection may remain active during normal development. An explicit, logged maintenance window should cover installations or tests that require stopping the service.

## Threat model

The design targets a standard Windows user and should resist simple bypasses such as terminating the tray application, editing local JSON, disabling the extension, calling a local API, or changing the clock.

It does not claim indefinite resistance against a local administrator who can stop services, change ACLs, uninstall software, or boot another operating system. Administrative interruptions should instead be deliberate, explicit, logged, and remotely visible.

## Incremental migration

1. Authenticate the Browser Bridge and keep extension requests read-only.
2. Remove protection-reducing operations from the local PWA.
3. Extract limit rules into a testable Python core.
4. Introduce the Windows service and minimal IPC.
5. Move storage, counters, and decisions into the service.
6. Add Desktop recovery and interruption reporting.
7. Deploy the extension through managed browser policy.
8. Replace the HTTP bridge with Native Messaging.

Every step must leave the application usable and the test suite maintainable. The migration is incremental, not a full rewrite.
