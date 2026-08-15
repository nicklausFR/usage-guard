import time
import json
import getpass
from queue import Empty, Queue
from threading import Event
from datetime import date, datetime, timedelta
from pathlib import Path

from PySide6.QtCore import QObject, QTimer, Signal

from activity import ActiveContext, ActivityProbe
from app_limiter import AppLimiter
from browser_bridge import browser_bridge
from i18n import language_preference, save_language_preference
from observation_journal import ObservationJournal
from usage_guard import (
    AppUsageStore, _browser_site_parts, config, debug_log,
    windows_session_started_at,
)


class MonitoringService(QObject):
    state_changed = Signal()
    notification_requested = Signal(str, str, int)

    def __init__(self):
        super().__init__()
        self.usage = AppUsageStore()
        self.observation_journal = ObservationJournal(
            self.usage.path.parent / "observations",
            enabled=getattr(config, "OBSERVATION_JOURNAL_ENABLED", True),
            heartbeat_seconds=getattr(config, "OBSERVATION_HEARTBEAT_SECONDS", 60),
            retention_days=getattr(config, "OBSERVATION_RETENTION_DAYS", 7),
        )
        self.probe = ActivityProbe()
        self.current_context = ActiveContext()
        self._last_tick = time.monotonic()
        self._last_save = self._last_tick
        self._current_day = date.today()
        self._last_debug_snapshot = None
        session_start = windows_session_started_at() or datetime.now().astimezone()
        self._tracking_started_at = session_start.isoformat(timespec="seconds")
        self.usage.record_windows_session(
            self._tracking_started_at,
            observed_at=datetime.now().astimezone().isoformat(timespec="seconds"),
        )
        self._program_sessions = {}
        self._program_inventory_initialized = False
        self._web_inventory_initialized = False
        self._last_program_inventory = 0.0
        # An unclean shutdown can leave sessions marked open on disk. Close
        # them at this new tracking boundary before detecting current programs.
        self.usage.update_sessions({})
        self.observation_journal.event("service_start", {
            "tracking_started_at": self._tracking_started_at,
        })
        # The remote HTTP server runs in its own thread.  Mutating a limit can
        # affect a Qt overlay, so commands must be applied from this service's
        # Qt thread rather than directly by the HTTP handler.
        self._remote_commands = Queue()
        self.app_limiter = AppLimiter(
            self.usage,
            int(getattr(config, "POTPLAYER_LIMIT_SECONDS", 15)),
            int(getattr(config, "POTPLAYER_EXTENSION_SECONDS", 15)),
            int(getattr(config, "POTPLAYER_WARNING_SECONDS", 5)),
        )
        self.app_limiter.notification_requested.connect(self.notification_requested.emit)
        self._notification_thresholds_shown = set()
        browser_bridge.set_limit_provider(self.app_limiter.web_limit_for_url)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.setInterval(int(getattr(config, "POLL_INTERVAL_MS", 1000)))

    def start(self):
        self._last_tick = time.monotonic()
        self.timer.start()
        # Let Qt process its first events (notably the tray-icon registration)
        # before starting activity collection.
        QTimer.singleShot(0, self.tick)
        QTimer.singleShot(0, self._notify_startup_rules)

    def stop(self):
        self.timer.stop()
        self.observation_journal.event("service_stop")
        self.usage.update_sessions({})
        self.usage.save(force=True)

    def tick(self):
        self._process_remote_commands()
        self.app_limiter.refresh_computer_block()
        now = time.monotonic()
        # A long gap means sleep/resume or a stalled process; do not attribute it
        # to whichever window happens to be focused after the gap.
        elapsed = min(max(0.0, now - self._last_tick), 5.0)
        self._last_tick = now
        self.current_context = self.probe.current()
        for target_key in browser_bridge.take_extension_requests():
            self.app_limiter.grant_web_extension(target_key)

        today = date.today()
        if today != self._current_day:
            self.usage.save(force=True)
            self._current_day = today

        foreground = self.is_activity_countable(self.current_context)
        # Passive time is media playing outside the foreground application.
        # It remains passive while the user works in another window.
        background_media = (
            []
            if self.current_context.is_video_playing
            else self.current_context.background_media or []
        )
        passive = bool(background_media)
        media_sessions = self.probe.media_session_states()
        media_sources = [
            source for source, is_playing in media_sessions.items() if is_playing
        ]
        debug_snapshot = (
            str(self.current_context.source),
            str(self.current_context.app_name),
            str(self.current_context.window_title),
            str(self.current_context.url),
            self.current_context.has_recent_input,
            self.current_context.browser_media_playing,
            self.current_context.is_video_playing,
            foreground,
            tuple(background_media),
            tuple(media_sources),
        )
        if debug_snapshot != self._last_debug_snapshot:
            debug_log(
                "source={!r}; app={!r}; title={!r}; url={!r}; recent_input={}; audible={}; "
                "video_playing={}; foreground_counted={}; "
                "background_media={!r}; windows_media_sources={!r}; passive={}".format(
                    self.current_context.source,
                    self.current_context.app_name,
                    self.current_context.window_title,
                    self.current_context.url,
                    self.current_context.has_recent_input,
                    self.current_context.browser_media_playing,
                    self.current_context.is_video_playing,
                    foreground,
                    background_media,
                    media_sources,
                    passive,
                )
            )
            self._last_debug_snapshot = debug_snapshot
        self.usage.add_system_seconds(elapsed, foreground, passive, today)

        if now - self._last_program_inventory >= 2.0:
            running_apps = self.probe.running_applications()
            if running_apps is not None:
                already_running = not self._program_inventory_initialized
                self._program_sessions = {}
                for executable, details in running_apps.items():
                    program_target = self.usage.target_for_context(ActiveContext(
                        app_name=details["executable"]
                    ))
                    if not program_target or self.usage.is_excluded(program_target.key):
                        continue
                    self.usage.remember_target(program_target)
                    self._program_sessions[f"program:{executable}"] = {
                        "kind": "program", "key": program_target.key,
                        "label": program_target.label,
                        "started_before_tracking": already_running,
                        "source": "windows",
                    }
                self._program_inventory_initialized = True
            self._last_program_inventory = now

        observed_sessions = dict(self._program_sessions)
        observed_target = self.usage.target_for_context(self.current_context)
        target = observed_target if foreground else None
        open_tabs = browser_bridge.open_tabs()
        if open_tabs is not None:
            already_open = not self._web_inventory_initialized
            browser = str(getattr(config, "BROWSER_APPS", ["brave.exe"])[0])
            for tab in open_tabs:
                web_target = self.usage.target_for_context(ActiveContext(
                    app_name=browser, window_title=tab["title"], url=tab["url"]
                ))
                if not web_target or self.usage.is_excluded(web_target.key):
                    continue
                self.usage.remember_target(web_target)
                session_key, session_label = self._session_identity(web_target)
                # Collapse several tabs or windows for the same target into
                # one open session. Focus changes never create a new session.
                observed_sessions[f"web:{session_key}"] = {
                    "kind": "web", "key": session_key,
                    "label": session_label,
                    "started_before_tracking": already_open,
                    "source": "browser-extension",
                }
            self._web_inventory_initialized = True
        for media_name in background_media:
            observed_sessions[f"multimedia:{media_name}"] = {
                "kind": "multimedia", "key": media_name, "label": media_name,
            }
        # Opening inventory and counted activity are deliberately separate.
        # A browser tab can remain open while another tab/window is being used.
        if foreground and target:
            session_key, session_label = self._session_identity(target)
            observed_sessions[f"active:{session_key}"] = {
                "kind": "active", "key": session_key, "label": session_label,
                "source": str(self.current_context.source or "foreground"),
            }
        self.usage.update_sessions(observed_sessions)

        self.observation_journal.record({
            "process": str(self.current_context.app_name or ""),
            "window_handle": int(self.current_context.window_handle or 0),
            "site_host": self._observation_site_host(self.current_context.url),
            "target_key": str(observed_target.key if observed_target else ""),
            "source": str(self.current_context.source or ""),
            "has_recent_input": bool(self.current_context.has_recent_input),
            "idle_seconds": round(float(self.current_context.idle_seconds or 0), 1),
            "is_afk": bool(self.current_context.is_afk),
            "counted_active": bool(foreground),
            "video_playing": bool(self.current_context.is_video_playing),
            "browser_media_playing": bool(self.current_context.browser_media_playing),
            "background_media": sorted(str(item) for item in background_media),
            "open_targets": sorted({
                f"{item.get('kind', '')}:{item.get('key', '')}"
                for item in observed_sessions.values()
                if item.get("kind") != "active"
            }),
        })

        if foreground:
            self.usage.add_seconds(target, elapsed, today)
        # Media-aware application limits consume time only in PLAYING state,
        # including while their window is in the background.
        self.app_limiter.observe(
            self.current_context, elapsed, foreground, media_sessions
        )
        self._check_notification_thresholds()
        browser_bridge.set_limit_state(
            self.current_context.url,
            self.app_limiter.current_web_limit(),
        )
        for media_name in background_media:
            self.usage.add_passive_seconds(media_name, elapsed, today)

        if now - self._last_save >= 10:
            self.usage.save()
            self._last_save = now
        self.state_changed.emit()

    def remote_snapshot(self, selection=None):
        """Return JSON-safe state for the companion PWA.

        This intentionally exposes only the aggregate data and policy state;
        the local activity store remains the source of truth.
        """
        selection = dict(selection or {})
        scope = str(selection.get("scope", "session"))
        selected_day = date.today()
        session_other_sites = {}
        if scope == "session":
            origin = datetime.fromisoformat(self._tracking_started_at)
            now = datetime.now().astimezone()
            sessions = [
                item for item in self.usage.sessions_for_period(origin.date(), now.date())
                if datetime.fromisoformat(str(item["ended_at"] or now.isoformat())) >= origin
            ]
            usage, passive_usage = {}, {}
            for item in sessions:
                if self.usage.is_excluded(str(item.get("key", ""))):
                    continue
                if item.get("kind") == "multimedia" and self.usage.is_passive_excluded(str(item.get("label", ""))):
                    continue
                opened = max(origin, datetime.fromisoformat(str(item["started_at"])))
                closed = min(now, datetime.fromisoformat(str(item["ended_at"] or now.isoformat())))
                seconds = max(0.0, (closed - opened).total_seconds())
                if item.get("kind") == "active":
                    key = str(item.get("key", ""))
                    if key.startswith("site:") and key.endswith(":other-sites"):
                        # Legacy active sessions kept only the aggregate key,
                        # so their seconds cannot be assigned to a host.  Do
                        # not mix that old measurement unit into the current
                        # host-scoped Windows-session view.
                        continue
                    browser, host = _browser_site_parts(key)
                    if (
                        browser and host
                        and not self.usage.is_browser_site_specific(browser, host)
                    ):
                        key = f"site:{browser}:other-sites"
                        host_key = (browser, host)
                        session_other_sites[host_key] = (
                            session_other_sites.get(host_key, 0.0) + seconds
                        )
                    usage[key] = usage.get(key, 0.0) + seconds
                elif item.get("kind") == "multimedia":
                    label = str(item.get("label", ""))
                    passive_usage[label] = passive_usage.get(label, 0.0) + seconds
            foreground = sum(usage.values())
            passive = sum(passive_usage.values())
            system = {
                "on": max(0.0, (now - origin).total_seconds()),
                "foreground": foreground,
                "with_passive": foreground + passive,
            }
            timeline_start, timeline_end = origin.date().isoformat(), now.date().isoformat()
        elif scope == "all":
            usage = self.usage.total_usage()
            passive_usage = self.usage.total_passive_usage()
            system = self.usage.total_system_usage()
            sessions = self.usage.sessions_for_period()
            known_days = set(self.usage.data.get("days", {})) | set(self.usage.data.get("passive_days", {})) | set(self.usage.data.get("system_days", {}))
            known_days.update(str(item.get("started_at", ""))[:10] for item in sessions if item.get("started_at"))
            timeline_start = min(known_days, default=selected_day.isoformat())
            timeline_end = selected_day.isoformat()
        elif scope == "period":
            try:
                start = date.fromisoformat(str(selection["start"]))
                end = date.fromisoformat(str(selection["end"]))
            except (KeyError, TypeError, ValueError):
                raise ValueError("Période invalide.")
            usage = self.usage.usage_for_period(start, end)
            passive_usage = self.usage.passive_usage_for_period(start, end)
            system = self.usage.system_usage_for_period(start, end)
            sessions = self.usage.sessions_for_period(start, end)
            timeline_start, timeline_end = self.usage._ordered_period(start, end)
        else:
            try:
                selected_day = date.fromisoformat(str(selection.get("date"))) if selection.get("date") else date.today()
            except (TypeError, ValueError):
                raise ValueError("Date invalide.")
            usage = self.usage.usage_for_day(selected_day)
            passive_usage = self.usage.passive_usage_for_day(selected_day)
            system = self.usage.system_usage_for_day(selected_day)
            sessions = self.usage.sessions_for_period(selected_day, selected_day)
            timeline_start = timeline_end = selected_day.isoformat()
        sessions = [
            item for item in sessions
            if not self.usage.is_excluded(str(item.get("key", "")))
            and not (
                item.get("kind") == "multimedia"
                and self.usage.is_passive_excluded(str(item.get("label", "")))
            )
        ]
        entries = []
        for entry in self.usage.presentation(usage):
            if scope == "session" and entry.key not in usage:
                continue
            multimedia = self._is_multimedia_target(entry.key)
            entries.append({
                "key": entry.key,
                "label": entry.label,
                "category": entry.category,
                "seconds": round(entry.seconds, 1),
                "site_category": entry.site_category,
                "category_scope": entry.category_scope,
                "multimedia": multimedia,
                "web": entry.key.startswith("site:"),
            })
        if hasattr(self.app_limiter, "prune_expired_limits"):
            self.app_limiter.prune_expired_limits()
        limits = []
        for key, policy in self.app_limiter.policies.items():
            limits.append({
                "target_key": key,
                "label": self.app_limiter.label_for_key(key),
                **policy,
                **self.app_limiter.current_status(key),
            })
        notification_rules = []
        for rule in self.usage.notification_rules():
            target_key = str(rule.get("target_key", ""))
            notification_rules.append({
                **rule,
                "target_label": (
                    "Toutes les applications limitées" if rule.get("kind") == "limited_app_start"
                    else
                    "Tout l’ordinateur" if target_key == "computer:all"
                    else self.app_limiter.label_for_key(target_key) if target_key
                    else "Toutes les limites"
                ),
            })
        context = self.current_context
        current_target = self.usage.target_for_context(context)
        other_sites = []
        selected_days = None
        if scope == "period":
            selected_days = (min(start.isoformat(), end.isoformat()), max(start.isoformat(), end.isoformat()))
        elif scope == "session":
            other_sites = [
                {
                    "browser": browser,
                    "host": host,
                    "seconds": round(seconds, 1),
                }
                for (browser, host), seconds in session_other_sites.items()
                if seconds > 0
                and not self.usage.is_browser_site_excluded(browser, host)
            ]
        if scope != "session":
            for browser, days in self.usage.data.get("other_site_days", {}).items():
                totals = {
                    host: 0.0
                    for hosts in days.values()
                    for host in hosts
                    if not self.usage.is_browser_site_excluded(browser, host)
                }
                for day_key, hosts in days.items():
                    if selected_days:
                        if not selected_days[0] <= day_key <= selected_days[1]:
                            continue
                    elif scope != "all" and day_key != selected_day.isoformat():
                        continue
                    for host, seconds in hosts.items():
                        if self.usage.is_browser_site_excluded(browser, host):
                            continue
                        totals[host] = totals.get(host, 0.0) + float(seconds)
                other_sites.extend(
                    {"browser": browser, "host": host, "seconds": round(seconds, 1)}
                    for host, seconds in totals.items()
                )
        daily_stats = []
        if scope != "session":
            first_day, last_day = date.fromisoformat(timeline_start), date.fromisoformat(timeline_end)
            day = min(first_day, last_day)
            last_day = max(first_day, last_day)
            while day <= last_day:
                day_usage = self.usage.usage_for_day(day)
                day_entries = []
                for entry in self.usage.presentation(day_usage):
                    day_entries.append({
                        "key": entry.key, "label": entry.label, "category": entry.category,
                        "seconds": round(entry.seconds, 1), "site_category": entry.site_category,
                        "category_scope": entry.category_scope,
                        "multimedia": self._is_multimedia_target(entry.key),
                        "web": entry.key.startswith("site:"),
                    })
                day_passive = self.usage.passive_usage_for_day(day)
                day_system = self.usage.system_usage_for_day(day)
                day_other_sites = []
                for browser, days in self.usage.data.get("other_site_days", {}).items():
                    known_hosts = {
                        host
                        for hosts in days.values()
                        for host in hosts
                        if not self.usage.is_browser_site_excluded(browser, host)
                    }
                    selected_hosts = days.get(day.isoformat(), {})
                    day_other_sites.extend(
                        {
                            "browser": browser,
                            "host": host,
                            "seconds": round(float(selected_hosts.get(host, 0.0)), 1),
                        }
                        for host in known_hosts
                    )
                daily_stats.append({
                    "date": day.isoformat(),
                    "usage": day_entries,
                    "active": round(sum(entry["seconds"] for entry in day_entries), 1),
                    "passive": [
                        {"label": label, "seconds": round(float(seconds), 1)}
                        for label, seconds in day_passive.items()
                    ],
                    "system": day_system,
                    "other_sites": day_other_sites,
                })
                day += timedelta(days=1)
        resolved_entries_by_key = {
            entry.key: entry for entry in self.usage.presentation({})
        }
        return {
            "date": selected_day.isoformat(),
            "scope": scope,
            "current": {
                "app_name": str(context.app_name or ""),
                "url": str(context.url or ""),
                "site_host": self._observation_site_host(context.url),
                "target_key": str(current_target.key if current_target else ""),
                "is_counted": self.is_activity_countable(context),
                "is_video_playing": bool(context.is_video_playing),
                "browser_media_playing": bool(context.browser_media_playing),
            },
            "server": {
                "host": "127.0.0.1",
                "port": int(getattr(config, "REMOTE_API_PORT", 8766)),
            },
            "settings": {
                "language": language_preference(getattr(config, "LANGUAGE", "auto")),
                "default_limit_warning_seconds": self.usage.default_limit_warning_seconds(),
            },
            "usage": sorted(entries, key=lambda item: item["seconds"], reverse=True),
            "system": system,
            "passive": [
                {"label": label, "seconds": round(float(seconds), 1)}
                for label, seconds in sorted(passive_usage.items(), key=lambda item: item[1], reverse=True)
            ],
            "limits": sorted(limits, key=lambda item: item["label"].lower()),
            "computer_block": self.app_limiter.computer_block_status(),
            "notification_rules": notification_rules,
            "categories": self.usage.categories(),
            "top_level_categories": self.usage.top_level_categories(),
            "category_parents": dict(self.usage.data.get("category_parents", {})),
            "category_order": list(self.usage.data.get("category_order", [])),
            "site_categories": self.usage.site_categories(),
            "site_category_order_manual": bool(
                self.usage.data.get("site_category_order_manual", False)
            ),
            "browsers": [
                {
                    "browser": browser,
                    "label": self.usage.browser_label(browser),
                    "category": category,
                }
                for browser, category in self.usage.data.get("browser_categories", {}).items()
            ],
            "excluded": [] if scope == "session" else [
                {"key": target.key, "label": target.label}
                for target in self.usage.excluded_targets()
            ],
            "merge_candidates": [
                {
                    "key": key,
                    "label": metadata.get("label", key),
                    "category": metadata.get("category", "") or getattr(
                        resolved_entries_by_key.get(key), "category", ""
                    ),
                    "site_category": metadata.get("site_category", "") or getattr(
                        resolved_entries_by_key.get(key), "site_category", ""
                    ),
                    "category_scope": metadata.get("category_scope", "") or getattr(
                        resolved_entries_by_key.get(key), "category_scope", ""
                    ),
                }
                for key, metadata in self.usage.data.get("targets", {}).items()
            ],
            "other_sites": sorted(other_sites, key=lambda item: item["seconds"], reverse=True),
            "sessions": sessions,
            "windows_sessions": self.usage.windows_sessions(),
            "daily_stats": daily_stats,
            "timeline": {"start": timeline_start, "end": timeline_end},
            "session_recording": {
                "active": True,
                "started_at": self._tracking_started_at,
                "origin": "windows_session",
                "inventory_ready": self._program_inventory_initialized,
                "web_inventory_ready": self._web_inventory_initialized,
                "open_count": sum(
                    session.get("kind") != "active"
                    for session in self.usage.data.get("open_sessions", {}).values()
                ),
                "program_count": sum(
                    session.get("kind") == "program"
                    for session in self.usage.data.get("open_sessions", {}).values()
                ),
                "multimedia_count": sum(
                    session.get("kind") == "multimedia"
                    for session in self.usage.data.get("open_sessions", {}).values()
                ),
                "web_count": sum(
                    session.get("kind") == "web"
                    for session in self.usage.data.get("open_sessions", {}).values()
                ),
            },
        }

    @staticmethod
    def _session_identity(target):
        """Keep an unclassified site's real host in the activity timeline."""
        detail_host = str(getattr(target, "detail_host", "") or "").strip()
        key = str(getattr(target, "key", "") or "")
        if detail_host and key.startswith("site:"):
            browser = key.split(":", 2)[1]
            return f"site:{browser}:{detail_host}", detail_host
        return key, str(getattr(target, "label", "") or key)

    @staticmethod
    def _is_multimedia_target(target_key):
        key = str(target_key or "").casefold()
        if key.startswith("app:"):
            app = key.removeprefix("app:").split(":", 1)[0]
            configured = {
                Path(str(value)).stem.casefold()
                for value in getattr(config, "VIDEO_PLAYER_APPS", [])
            }
            if app in configured:
                return True
        return any(
            str(pattern).casefold().removeprefix("www.") in key
            for pattern in getattr(config, "VIDEO_URL_PATTERNS", [])
        )

    @staticmethod
    def _observation_site_host(url):
        """Keep only a browser host in the raw journal, never a full URL."""
        from usage_guard import _site_host
        return _site_host(url)

    def request_remote_command(self, command, timeout=5):
        """Schedule a PWA change on the Qt thread and wait for its result."""
        done = Event()
        request = {"command": dict(command), "done": done, "result": None}
        self._remote_commands.put(request)
        if not done.wait(timeout):
            return {"ok": False, "error": "Le service local ne répond pas."}
        return request["result"]

    def request_remote_snapshot(self, selection=None, timeout=5):
        """Read the store on the Qt thread, avoiding concurrent dict access."""
        result = self.request_remote_command({"action": "snapshot", "selection": selection}, timeout)
        if result.get("ok") is False:
            return {"error": result["error"]}
        return result

    def request_activity_store(self, timeout=5):
        result = self.request_remote_command({"action": "activity_store"}, timeout)
        return result.get("activity", {}) if isinstance(result, dict) else {}

    def import_activity_store(self, activity, timeout=5):
        return self.request_remote_command({"action": "import_activity_store", "activity": activity}, timeout)

    def _process_remote_commands(self):
        while True:
            try:
                request = self._remote_commands.get_nowait()
            except Empty:
                return
            try:
                request["result"] = self._apply_remote_command(request["command"])
            except (KeyError, TypeError, ValueError) as error:
                request["result"] = {"ok": False, "error": str(error)}
            finally:
                request["done"].set()

    def _apply_remote_command(self, command):
        action = command.get("action")
        if action == "snapshot":
            return self.remote_snapshot(command.get("selection"))
        if action == "activity_store":
            return {"ok": True, "activity": json.loads(json.dumps(self.usage.data))}
        if action == "import_activity_store":
            activity = command.get("activity")
            if not isinstance(activity, dict) or not isinstance(activity.get("days"), dict):
                return {"ok": False, "error": "Base d’activité distante invalide."}
            if not self.usage.data.get("days"):
                self.usage.data = json.loads(json.dumps(activity))
                self.usage._repair_sessions(self.usage.data)
                self.usage.save(force=True)
                self.app_limiter._reload_policies()
            return {"ok": True}
        if action == "set_language":
            language = str(command.get("language", "auto")).lower()
            save_language_preference(language)
            return {"ok": True, "language": language, "restart_required": True}
        if action == "set_default_limit_warning":
            seconds = self.usage.set_default_limit_warning_seconds(
                command.get("warning_seconds", 300)
            )
            return {"ok": True, "warning_seconds": seconds}
        if action == "set_notification_rule":
            rule = self.usage.set_notification_rule(command.get("rule", {}))
            if rule.get("kind") == "limit_warning":
                target_key = str(rule.get("target_key", ""))
                if target_key:
                    if target_key not in self.app_limiter.policies:
                        raise ValueError("Limite introuvable.")
                    policy = self.app_limiter.policies[target_key]
                    self.app_limiter.apply_settings(target_key, {
                        **policy, "warning_seconds": rule["warning_seconds"],
                    })
            return {"ok": True, "rule": rule}
        if action == "remove_notification_rule":
            self.usage.remove_notification_rule(command.get("rule_id", ""))
            return {"ok": True}
        if action == "set_notification_warning":
            target_key = str(command.get("target_key", ""))
            if target_key not in self.app_limiter.policies:
                raise ValueError("Limite introuvable.")
            seconds = max(1, int(command.get("warning_seconds", 300)))
            policy = self.app_limiter.policies[target_key]
            settings = self.app_limiter.apply_settings(target_key, {**policy, "warning_seconds": seconds})
            return {"ok": True, "warning_seconds": settings["warning_seconds"]}
        if action == "set_computer_block":
            actor = self._limit_actor_label(command.get("actor"))
            block = self.usage.set_computer_block(
                command.get("mode"), actor,
                day=command.get("day"),
                duration_seconds=command.get("duration_seconds"),
                delay_seconds=command.get("delay_seconds", 0),
                start_time=command.get("start_time"),
                end_time=command.get("end_time"),
                valid_from=command.get("valid_from"),
                valid_from_time=command.get("valid_from_time"),
                valid_until=command.get("valid_until"),
                valid_until_time=command.get("valid_until_time"),
            )
            self.app_limiter.refresh_computer_block()
            start_at = datetime.fromisoformat(block["started_at"]).astimezone()
            end = datetime.fromisoformat(block["ends_at"]).astimezone().strftime("%d/%m/%Y à %H:%M")
            now = datetime.now().astimezone()
            pending = start_at > now
            title = (
                f"Limitation planifiée par {actor} — Usage Guard"
                if pending else
                f"Usage de l’ordinateur limité par {actor} — Usage Guard"
            )
            message = (
                f"{actor} a planifié la limitation du {start_at.strftime('%d/%m/%Y à %H:%M')} jusqu’au {end}."
                if pending else
                f"{actor} a limité l’usage de l’ordinateur jusqu’au {end}."
            )
            if any(
                rule.get("enabled") and rule.get("kind") == "computer_block_change"
                for rule in self.usage.data.get("notification_rules", [])
            ):
                self.notification_requested.emit(title, message, 0)
            return {"ok": True, "computer_block": block}
        if action == "set_computer_block_enabled":
            actor = self._limit_actor_label(command.get("actor"))
            enabled = bool(command.get("enabled"))
            block = self.usage.set_computer_block_enabled(enabled)
            self.app_limiter.refresh_computer_block()
            if any(
                rule.get("enabled") and rule.get("kind") == "computer_block_change"
                for rule in self.usage.data.get("notification_rules", [])
            ):
                state = "activée" if enabled else "désactivée"
                action_label = "activé" if enabled else "désactivé"
                self.notification_requested.emit(
                    f"Limitation {state} par {actor} — Usage Guard",
                    f"{actor} a {action_label} la limitation de l’usage de l’ordinateur.", 0,
                )
            return {"ok": True, "computer_block": block}
        if action == "clear_computer_block":
            actor = self._limit_actor_label(command.get("actor"))
            self.usage.clear_computer_block()
            self.app_limiter.refresh_computer_block()
            if any(
                rule.get("enabled") and rule.get("kind") == "computer_block_change"
                for rule in self.usage.data.get("notification_rules", [])
            ):
                self.notification_requested.emit(
                    f"Limitation levée par {actor} — Usage Guard",
                    f"{actor} a levé la limitation de l’usage de l’ordinateur.", 0,
                )
            return {"ok": True}
        if action == "notify_pwa_login":
            self._notify_pwa_login(command.get("actor"), command.get("ip"))
            return {"ok": True}
        if action == "rename_target":
            self.usage.rename_target(str(command["target_key"]), str(command["label"]))
            return {"ok": True}
        if action == "set_category":
            self.usage.set_category(str(command["target_key"]), str(command.get("category", "")))
            return {"ok": True}
        if action == "make_root":
            self.usage.make_root(str(command["target_key"]))
            return {"ok": True}
        if action == "exclude_target":
            self.usage.exclude(str(command["target_key"]))
            self.usage.save(force=True)
            return {"ok": True}
        if action == "unexclude_target":
            self.usage.unexclude(str(command["target_key"]))
            return {"ok": True}
        if action == "delete_target":
            self.usage.delete_target(str(command["target_key"]))
            return {"ok": True}
        if action == "merge_target":
            self.usage.merge_target_into(str(command["target_key"]), str(command["destination_key"]))
            return {"ok": True}
        if action == "rename_category":
            self.usage.rename_category(str(command["category"]), str(command["label"]))
            return {"ok": True}
        if action == "move_category":
            self.usage.move_category(
                str(command["category"]), str(command["destination"])
            )
            return {"ok": True}
        if action == "reorder_category":
            self.usage.reorder_category(
                str(command["category"]),
                str(command["destination"]),
                bool(command.get("before", True)),
            )
            return {"ok": True}
        if action == "reorder_site_category":
            self.usage.reorder_site_category(
                str(command["category"]),
                str(command["destination"]),
                bool(command.get("before", True)),
            )
            return {"ok": True}
        if action == "clear_category":
            self.usage.clear_category(str(command["category"]))
            return {"ok": True}
        if action == "make_category_root":
            self.usage.make_category_root(str(command["category"]))
            return {"ok": True}
        if action == "set_category_for_keys":
            self.usage.set_category_for_keys(list(command["target_keys"]), str(command.get("category", "")))
            return {"ok": True}
        if action == "rename_browser":
            self.usage.rename_browser(str(command["browser"]), str(command["label"]))
            return {"ok": True}
        if action == "make_browser_root":
            self.usage.make_browser_root(str(command["browser"]))
            return {"ok": True}
        if action == "clear_browser_category":
            self.usage.clear_browser_category(str(command["browser"]))
            return {"ok": True}
        if action == "clear_site_category":
            self.usage.clear_site_category_for_keys(list(command["target_keys"]), str(command.get("category", "")))
            return {"ok": True}
        if action == "rename_site_category":
            self.usage.rename_site_category_for_keys(list(command["target_keys"]), str(command["label"]))
            return {"ok": True}
        if action == "exclude_passive":
            self.usage.exclude_passive(str(command["label"]))
            return {"ok": True}
        if action == "make_site_specific":
            self.usage.make_browser_site_specific(str(command["browser"]), str(command["host"]))
            return {"ok": True}
        if action == "categorize_site":
            self.usage.move_browser_site_to_category(str(command["browser"]), str(command["host"]), str(command["category"]))
            return {"ok": True}
        if action == "exclude_site":
            self.usage.exclude_browser_site(str(command["browser"]), str(command["host"]))
            return {"ok": True}
        if action == "delete_site":
            self.usage.delete_browser_site(str(command["browser"]), str(command["host"]))
            return {"ok": True}
        target_key = str(command.get("target_key", ""))
        if not target_key.startswith(("app:", "site:", "category:")):
            raise ValueError("Cible de limite non prise en charge.")
        if action == "set_limit":
            existed = target_key in self.app_limiter.policies
            was_enabled = (
                bool(self.app_limiter.policies[target_key].get("enabled"))
                if existed else None
            )
            requested_settings = dict(command["settings"])
            if not existed:
                requested_settings["enabled"] = True
            settings = self.app_limiter.apply_settings(target_key, requested_settings)
            if existed and was_enabled != bool(settings.get("enabled")):
                self._notify_limit_toggle(target_key, bool(settings.get("enabled")), command.get("actor"))
            else:
                self._notify_limit_change(target_key, "modifiée" if existed else "créée", command.get("actor"))
            return {"ok": True, "limit": {"target_key": target_key, **settings}}
        if action == "remove_limit":
            label = self.app_limiter.label_for_key(target_key)
            self.app_limiter.remove_limit(target_key)
            self._notify_limit_change(target_key, "supprimée", command.get("actor"), label)
            return {"ok": True}
        if action == "reset_limit":
            if target_key not in self.app_limiter.policies:
                raise ValueError("Cette limite n'existe pas.")
            self.app_limiter.reset_today(target_key)
            return {"ok": True}
        raise ValueError("Commande distante inconnue.")

    def _notify_limit_change(self, target_key, verb, actor=None, label=None):
        actor = self._limit_actor_label(actor)
        label = label or self.app_limiter.label_for_key(target_key)
        for rule in self.usage.data.get("notification_rules", []):
            if not rule.get("enabled") or rule.get("kind") != "limit_change":
                continue
            watched = str(rule.get("target_key", ""))
            if watched and watched != target_key:
                continue
            self.notification_requested.emit(
                f"Limite {verb} par {actor} — Usage Guard",
                f"{actor} a {dict(créée='créé', modifiée='modifié', supprimée='supprimé').get(verb, verb)} la limite « {label} ».",
                0,
            )

    def _notify_limit_toggle(self, target_key, enabled, actor=None):
        if not any(
            rule.get("enabled") and rule.get("kind") == "limit_change"
            for rule in self.usage.data.get("notification_rules", [])
        ):
            return
        actor = self._limit_actor_label(actor)
        label = self.app_limiter.label_for_key(target_key)
        state = "activée" if enabled else "désactivée"
        action = "activé" if enabled else "désactivé"
        self.notification_requested.emit(
            f"Limite {state} par {actor} — Usage Guard",
            f"{actor} a {action} la limite « {label} ».",
            0,
        )

    def _notify_pwa_login(self, actor=None, ip=None):
        if not any(
            rule.get("enabled") and rule.get("kind") == "pwa_login"
            for rule in self.usage.data.get("notification_rules", [])
        ):
            return
        actor = str(actor or "Utilisateur inconnu")
        location = f" depuis {ip}" if ip else ""
        self.notification_requested.emit(
            f"{actor} connecté à la PWA — Usage Guard",
            f"{actor} vient de se connecter à la PWA{location}.", 0,
        )

    @staticmethod
    def _limit_actor_label(actor=None):
        remote_actor = str(actor or "").strip()
        if remote_actor:
            return remote_actor
        try:
            local_actor = getpass.getuser().strip()
        except (OSError, KeyError):
            local_actor = ""
        return f"Utilisateur local ({local_actor})" if local_actor else "Utilisateur local"

    def _notify_startup_rules(self):
        weekday = date.today().weekday()
        for rule in self.usage.data.get("notification_rules", []):
            if not rule.get("enabled") or rule.get("kind") != "startup_reminder":
                continue
            if weekday not in {int(value) for value in rule.get("weekdays", [])}:
                continue
            self.notification_requested.emit(
                str(rule.get("label") or "Rappel — Usage Guard"),
                str(rule.get("description") or "Rappel programmé au démarrage."),
                0,
            )

    def _check_notification_thresholds(self):
        now = datetime.now().astimezone()
        if hasattr(self.usage, "prune_expired_notification_rules"):
            self.usage.prune_expired_notification_rules(now)
        active_tokens = set()
        for rule in self.usage.data.get("notification_rules", []):
            if not rule.get("enabled") or rule.get("kind") != "usage_threshold":
                continue
            if not AppUsageStore.notification_rule_active(rule, now):
                continue
            mode = str(rule.get("threshold_mode", "legacy_percent"))
            rule_id = str(rule.get("id", ""))
            if mode == "time":
                after_time = str(rule.get("after_time", ""))
                token = (rule_id, now.date().isoformat())
                target_key = str(rule.get("target_key", ""))
                current_target = self.usage.target_for_context(self.current_context)
                if target_key == "computer:all":
                    target_active = self.is_activity_countable(self.current_context)
                    label = "Tout l’ordinateur"
                elif target_key.startswith("category:") and current_target:
                    category = target_key.removeprefix("category:")
                    metadata = self.usage.data.get("targets", {}).get(current_target.key, {})
                    current_categories = {
                        str(current_target.category or ""),
                        str(metadata.get("category", "")),
                        str(metadata.get("site_category", "")),
                    }
                    target_active = any(
                        category in self.usage.category_lineage(current_category)
                        for current_category in current_categories if current_category
                    )
                    label = f"Catégorie · {category}"
                else:
                    target_active = bool(current_target and current_target.key == target_key)
                    label = self.app_limiter.label_for_key(target_key)
                reached = bool(after_time) and now.strftime("%H:%M") >= after_time and target_active
                if reached:
                    active_tokens.add(token)
                    if token not in self._notification_thresholds_shown:
                        self.notification_requested.emit(
                            str(rule.get("label") or "Horaire atteint — Usage Guard"),
                            f"{label} est utilisé après l’heure définie ({after_time}).",
                            0,
                        )
                continue
            if mode == "duration":
                target_key = str(rule.get("target_key", ""))
                usage = self.usage.usage_for_day()
                if target_key == "computer:all":
                    seconds = sum(entry.seconds for entry in self.usage.presentation(usage))
                    label = "Tout l’ordinateur"
                elif target_key.startswith("category:"):
                    category = target_key.removeprefix("category:")
                    seconds = sum(
                        entry.seconds for entry in self.usage.presentation(usage)
                        if (
                            category in self.usage.category_lineage(entry.category)
                            or category in self.usage.category_lineage(entry.site_category)
                        )
                    )
                    label = f"Catégorie · {category}"
                else:
                    seconds = float(usage.get(target_key, 0))
                    label = self.app_limiter.label_for_key(target_key)
                threshold_seconds = max(1, int(rule.get("duration_seconds", 3600)))
                token = (rule_id, now.date().isoformat())
                reached = seconds >= threshold_seconds
                if reached:
                    active_tokens.add(token)
                    if token not in self._notification_thresholds_shown:
                        self.notification_requested.emit(
                            str(rule.get("label") or "Durée atteinte — Usage Guard"),
                            f"{label} a atteint {self.app_limiter._format_duration(threshold_seconds)} d’utilisation.",
                            0,
                        )
                continue
            target_key = str(rule.get("target_key", ""))
            if target_key not in self.app_limiter.policies:
                continue
            status = self.app_limiter.current_status(target_key)
            threshold = int(rule.get("threshold_percent", 80))
            token = (str(rule.get("id", "")), bool(status.get("extension_used")))
            reached = float(status.get("seconds", 0)) >= float(status.get("allowed", 0)) * threshold / 100
            if reached:
                active_tokens.add(token)
                if token not in self._notification_thresholds_shown:
                    self.notification_requested.emit(
                        str(rule.get("label") or "Seuil d’usage atteint"),
                        f"{self.app_limiter.label_for_key(target_key)} a atteint {threshold} % de sa limite.",
                        0,
                    )
        self._notification_thresholds_shown.intersection_update(active_tokens)
        self._notification_thresholds_shown.update(active_tokens)

    @staticmethod
    def is_activity_countable(context):
        return bool(
            context.app_name
            and (
                not context.is_afk
                or context.is_video_playing
                or _is_chrome_web_app(context)
            )
        )


def _is_chrome_web_app(context):
    """Chrome PWAs are standalone foreground applications, not browser tabs."""
    executable = Path(str(context.app_name)).name.lower()
    title = str(context.window_title or "").strip()
    browser_suffixes = (" - Google Chrome", " – Google Chrome", " - Chrome", " – Chrome")
    return executable == "chrome.exe" and bool(title) and not title.endswith(browser_suffixes)



# Kept as an import-compatible alias for integrations using the old name.
UsageGuardService = MonitoringService
