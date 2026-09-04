import time
import json
import getpass
import uuid
from queue import Empty, Queue
from threading import Event
from datetime import date, datetime, timedelta
from pathlib import Path

from PySide6.QtCore import QObject, QTimer, Signal

from activity import ActiveContext, ActivityProbe
from activity_keys import is_other_sites_aggregate_key
from app_limiter import AppLimiter
from browser_bridge import browser_bridge
from command_policy import (
    MANAGED_BY_FIELD, SERVICE_ADMIN_TOKEN_FIELD, SOURCE_BACKEND,
    SOURCE_INTERNAL, SOURCE_LOCAL_ADMIN, command_source,
    is_backend_managed, is_catalog_mutation, is_control_mutation, manager_for_source,
    rejected_mutation, stamp_command,
)
from i18n import _, language_preference, save_language_preference
from observation_journal import ObservationJournal
from runtime_profile import current_profile
from usage_guard import (
    AppUsageStore, _browser_site_parts, _site_host, config, debug_log,
    windows_session_started_at,
)
from windows_identity import current_windows_session_identity
from windows_power_events import (
    awake_monotonic_seconds, inferred_sleep_seconds,
    modern_standby_intervals_since, modern_standby_is_session_boundary,
)


NOTIFICATION_SUBJECT_ROLES = {"limited", "user", "admin"}


def notification_subject_roles(rule):
    explicit = rule.get("subject_roles") if isinstance(rule, dict) else None
    if isinstance(explicit, (list, tuple, set)):
        roles = {
            str(role).strip().lower() for role in explicit
            if str(role).strip().lower() in NOTIFICATION_SUBJECT_ROLES
        }
        if roles:
            return roles
    legacy = str((rule or {}).get("login_role_scope") or "both").lower()
    if legacy == "admins":
        return {"admin"}
    if legacy == "users":
        return {"limited", "user"}
    return set(NOTIFICATION_SUBJECT_ROLES)


def _usage_computer_blocks(usage):
    getter = getattr(usage, "computer_blocks", None)
    if callable(getter):
        return getter()
    data = getattr(usage, "data", {})
    collection = data.get("computer_blocks") if isinstance(data, dict) else None
    if isinstance(collection, list):
        return [dict(block) for block in collection if isinstance(block, dict)]
    legacy = data.get("computer_block", {}) if isinstance(data, dict) else {}
    return [dict(legacy)] if isinstance(legacy, dict) and legacy else []


def _computer_block_rule_identity(block):
    """Return the stable rule identity shared by local and server payloads."""
    source = dict(block or {})
    mode = str(source.get("mode") or "")
    identity = {"mode": mode}
    validity = {
        key: str(source.get(key) or "")
        for key in (
            "valid_from", "valid_from_time",
            "valid_until", "valid_until_time",
        )
    }
    if mode == "schedule":
        identity.update({
            "start_time": str(
                source.get("start_time") or source.get("daily_start") or ""
            ),
            "end_time": str(
                source.get("end_time") or source.get("daily_end") or ""
            ),
            **validity,
        })
    elif mode == "absolute_range":
        identity.update(validity)
    elif mode == "daily_duration":
        identity.update({
            "duration_seconds": int(
                source.get("duration_seconds")
                or source.get("limit_seconds")
                or 0
            ),
            "start_time": str(
                source.get("start_time")
                or source.get("schedule_start")
                or ""
            ),
            "end_time": str(
                source.get("end_time")
                or source.get("schedule_end")
                or ""
            ),
            **validity,
        })
    elif mode == "duration":
        duration = source.get("duration_seconds")
        if duration is None:
            try:
                duration = round((
                    datetime.fromisoformat(str(source["ends_at"]))
                    - datetime.fromisoformat(str(source["started_at"]))
                ).total_seconds())
            except (KeyError, TypeError, ValueError):
                duration = 0
        identity["duration_seconds"] = int(duration or 0)
    elif mode == "day":
        selected_day = str(source.get("day") or "")
        if not selected_day:
            try:
                selected_day = (
                    datetime.fromisoformat(str(source["ends_at"])).date()
                    - timedelta(days=1)
                ).isoformat()
            except (KeyError, TypeError, ValueError):
                pass
        identity["day"] = selected_day
    elif mode == "range":
        # The local start can be clamped to the creation time.  The end stays
        # stable and is sufficient together with the active occurrence below.
        end_time = str(source.get("end_time") or "")
        if not end_time:
            try:
                end_time = datetime.fromisoformat(
                    str(source["ends_at"])
                ).strftime("%H:%M")
            except (KeyError, TypeError, ValueError):
                pass
        identity["end_time"] = end_time
    return identity


def _computer_block_unlock_identity(status):
    source = dict(status or {})
    return {
        "block_id": str(source.get("block_id") or ""),
        "rule": _computer_block_rule_identity(source),
        "occurrence": {
            "started_at": str(source.get("started_at") or ""),
            "ends_at": str(source.get("ends_at") or ""),
        },
    }


def _computer_block_matches_unlock_identity(status, expected):
    source = dict(status or {})
    wanted = dict(expected or {})
    if not source.get("active"):
        return False
    if str(source.get("block_id") or "") != str(wanted.get("block_id") or ""):
        return False
    if dict(wanted.get("rule") or {}) != _computer_block_rule_identity(source):
        return False
    occurrence = dict(wanted.get("occurrence") or {})
    return all(
        str(source.get(key) or "") == str(value or "")
        for key, value in occurrence.items()
        if key in {"started_at", "ends_at"}
    )


class MonitoringService(QObject):
    state_changed = Signal()
    notification_requested = Signal(str, str, int)
    email_notification_requested = Signal(str, str, str, str)

    def __init__(self, decision_mirror=None):
        super().__init__()
        self._decision_service = decision_mirror
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
        self._last_tick_wall = datetime.now().astimezone()
        self._last_awake_clock = awake_monotonic_seconds()
        self._last_save = self._last_tick
        self._current_day = date.today()
        self._last_debug_snapshot = None
        self._suspended = False
        self._suspend_started_at = None
        self._shutdown_recorded = False
        self._windows_identity = current_windows_session_identity() or {}
        self._windows_identity_checked_at = 0.0
        session_start = windows_session_started_at(
            self._windows_identity.get("session_id")
        ) or datetime.now().astimezone()
        if (
            self._windows_identity.get("windows_sid")
            and decision_mirror is not None
        ):
            try:
                self._windows_identity_checked_at = time.monotonic()
                resolved = decision_mirror.resolve_windows_identity(
                    self._windows_identity["windows_sid"]
                )
                self._windows_identity.update(dict(resolved or {}))
            except Exception as error:
                self._windows_identity.update({
                    "mapped": False,
                    "mapping_status": "service_unavailable",
                })
                debug_log(
                    "windows identity resolution failed: "
                    f"{type(error).__name__}"
                )
        self._personal_policy = {
            "configured": False, "revision": 0,
            "policy_status": "unavailable",
            "usage_guard_username": str(
                self._windows_identity.get("usage_guard_username") or ""
            ),
        }
        self._personal_policy_checked_at = 0.0
        self._personal_usage = {"usage_status": "unavailable", "totals": {}}
        self._personal_policy_compared_revision = 0
        self._personal_policy_applied_revision = 0
        self._personal_policy_comparison = {
            "validated": False, "matches": False, "differences": [],
        }
        self._tracking_started_at = session_start.isoformat(timespec="seconds")
        # Prime the stable SID first so startup/gap events are journaled, but
        # do not add the new current session until the previous unexplained
        # gap has been reconstructed from the old session's last observation.
        self.usage.set_active_windows_identity(self._windows_identity)
        self._record_guard_start(self._last_tick_wall)
        self.usage.record_windows_session(
            self._tracking_started_at,
            observed_at=datetime.now().astimezone().isoformat(timespec="seconds"),
            identity=self._windows_identity,
        )
        sleep_intervals = modern_standby_intervals_since(
            session_start,
            getattr(config, "SLEEP_SESSION_BOUNDARY_SECONDS", 1),
            include_reason=True,
        )
        idle_threshold = getattr(
            config, "IDLE_STANDBY_SESSION_BOUNDARY_SECONDS", 4 * 3600,
        )
        screen_idle_periods = [
            interval[:2] for interval in sleep_intervals
            if not modern_standby_is_session_boundary(
                *interval, idle_threshold_seconds=idle_threshold,
            )
        ]
        self.usage.merge_windows_sessions_across_periods(screen_idle_periods)
        split_sleep = False
        for interval in sleep_intervals:
            if not modern_standby_is_session_boundary(
                *interval, idle_threshold_seconds=idle_threshold,
            ):
                continue
            split_sleep = (
                self._start_logical_session_after_sleep(*interval[:2])
                or split_sleep
            )
        active_windows_session = next((
            item for item in self.usage.windows_sessions()
            if not item.get("ended_at")
        ), None)
        if active_windows_session:
            self._tracking_started_at = str(active_windows_session["started_at"])
        self._program_sessions = {}
        self._program_inventory_initialized = False
        self._web_inventory_initialized = False
        self._last_program_inventory = 0.0
        # An unclean shutdown can leave sessions marked open on disk. Close
        # them at this new tracking boundary before detecting current programs.
        if not split_sleep:
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
            decision_mirror=decision_mirror,
            admin_unlock_handler=self.unlock_computer_block_with_login,
        )
        self._refresh_personal_policy(force=True)
        self._restore_service_controls()
        self._compare_personal_policy_if_needed()
        self._apply_personal_policy_if_needed()
        self.app_limiter.notification_requested.connect(self.notification_requested.emit)
        self.app_limiter.email_notification_requested.connect(self.email_notification_requested.emit)
        self._notification_thresholds_shown = set()
        browser_bridge.set_limit_provider(self.app_limiter.web_limit_for_url)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.setInterval(int(getattr(config, "POLL_INTERVAL_MS", 1000)))

    def _restore_service_controls(self):
        service = self._decision_service
        if service is None or (
            current_profile().production
            and not getattr(service, "external_service", False)
        ):
            return
        backend_limits = {
            key: policy for key, policy in self.app_limiter.policies.items()
            if is_backend_managed(policy)
        }
        blocks = self.usage.computer_blocks()
        backend_blocks = [
            block for block in blocks if is_backend_managed(block)
        ]
        try:
            controls = service.bootstrap_controls(
                backend_limits, backend_blocks,
            )
        except Exception as error:
            debug_log(f"service control restore failed: {type(error).__name__}")
            return
        authoritative = controls.get("limits", {})
        for key in list(self.app_limiter.policies):
            if is_backend_managed(self.app_limiter.policies[key]) and key not in authoritative:
                self.app_limiter.remove_limit(key, source=SOURCE_INTERNAL)
        for key, policy in authoritative.items():
            if str(key).startswith(("app:", "site:", "category:")):
                self.app_limiter.apply_settings(
                    key, {**policy, MANAGED_BY_FIELD: "backend"},
                    source=SOURCE_BACKEND,
                )
        authoritative_blocks = controls.get("computer_blocks")
        if not isinstance(authoritative_blocks, list):
            legacy = controls.get("computer_block", {})
            authoritative_blocks = [legacy] if is_backend_managed(legacy) else []
        # The protected service may have reserved a server-shaped document
        # before the desktop applied it. Materialize aliases and occurrence
        # timestamps exactly like a live replace command before restoring it.
        # The store reconciliation itself preserves any unsynchronised local
        # rules and promotes matching server ids to backend ownership.
        try:
            self.usage.replace_computer_blocks(
                [
                    {**dict(block), MANAGED_BY_FIELD: "backend"}
                    for block in authoritative_blocks
                    if isinstance(block, dict) and block.get("block_id")
                ],
                managed_by="backend",
            )
        except (TypeError, ValueError) as error:
            debug_log(
                "service computer control restore failed: "
                f"{type(error).__name__}"
            )
            return
        self.usage.set_effective_computer_block(None)
        self.app_limiter.refresh_computer_block()

    def start(self):
        self._last_tick = time.monotonic()
        self._last_tick_wall = datetime.now().astimezone()
        self._last_awake_clock = awake_monotonic_seconds()
        self.timer.start()
        # Let Qt process its first events (notably the tray-icon registration)
        # before starting activity collection.
        QTimer.singleShot(0, self.tick)
        QTimer.singleShot(0, self._notify_startup_rules)

    def windows_session_user(self):
        """Return the local user proven by this desktop process' own SID."""
        sid = str(self._windows_identity.get("windows_sid") or "")
        if not sid or self._decision_service is None:
            return None
        return self._decision_service.authenticate_windows_session(sid)

    def unlock_computer_block_with_login(self, username, password):
        """Authenticate an administrator before disabling the active block."""
        service = self._decision_service
        if service is None:
            return {
                "ok": False,
                "error": _("Authentification administrateur indisponible."),
            }
        try:
            user = service.authenticate_user(username, password)
        except Exception:
            return {
                "ok": False,
                "error": _("Identifiant ou mot de passe incorrect."),
            }
        if (
            not user.get("is_admin") or user.get("must_change")
            or user.get("must_set_email")
        ):
            return {
                "ok": False,
                "error": _("Un compte administrateur actif est requis."),
            }
        displayed = self.app_limiter.displayed_computer_block()
        block_id = str(displayed.get("block_id") or "")
        status = (
            self.app_limiter.computer_block_status(block_id=block_id)
            if block_id else {}
        )
        expected = _computer_block_unlock_identity(status)
        if (
            not block_id
            or not _computer_block_matches_unlock_identity(status, {
                **expected, "occurrence": {
                    "started_at": str(displayed.get("started_at") or ""),
                    "ends_at": str(displayed.get("ends_at") or ""),
                },
            })
        ):
            return {
                "ok": False,
                "error": _(
                    "La limitation affichée n’est plus active ; "
                    "aucune règle n’a été modifiée."
                ),
                "code": "computer_block_changed",
            }
        actor = str(user.get("username") or username or _("Administrateur"))
        command = stamp_command({
            "action": "set_computer_block_enabled",
            "block_id": block_id,
            "enabled": False,
            "expected_computer_block": expected,
            "actor": actor,
        }, SOURCE_LOCAL_ADMIN)
        command[SERVICE_ADMIN_TOKEN_FIELD] = str(
            user.get("_service_admin_token") or ""
        )
        result = self._apply_remote_command(command)
        if result.get("ok"):
            self._notify_limit_override_login(actor)
        return result

    def _refresh_windows_identity(self, force=False):
        """Retry a transient SID mapping failure without blocking each tick."""
        sid = str(self._windows_identity.get("windows_sid") or "").strip().upper()
        if (
            not sid or self._decision_service is None
            or self._windows_identity.get("mapped")
        ):
            return self._windows_identity
        now = time.monotonic()
        last_checked = float(
            getattr(self, "_windows_identity_checked_at", 0.0) or 0.0
        )
        if not force and now - last_checked < 5:
            return self._windows_identity
        self._windows_identity_checked_at = now
        try:
            resolved = self._decision_service.resolve_windows_identity(sid)
            if not isinstance(resolved, dict):
                raise ValueError("invalid Windows identity response")
            identity = {
                **self._windows_identity,
                **resolved,
                "windows_sid": sid,
            }
        except Exception as error:
            identity = {
                **self._windows_identity,
                "windows_sid": sid,
                "mapped": False,
                "mapping_status": "service_unavailable",
                "mapping_error": type(error).__name__,
            }
        self._windows_identity = identity
        self.usage.update_windows_identity(identity)
        return self._windows_identity

    def _refresh_personal_policy(self, force=False):
        self._refresh_windows_identity(force=force)
        now = time.monotonic()
        if not force and now - self._personal_policy_checked_at < 5:
            return self._personal_policy
        self._personal_policy_checked_at = now
        sid = str(self._windows_identity.get("windows_sid") or "")
        if (
            not sid or not self._windows_identity.get("mapped")
            or self._decision_service is None
        ):
            self._personal_policy = {
                **self._personal_policy,
                "policy_status": "unmapped",
            }
            self._personal_usage = {
                **getattr(self, "_personal_usage", {}),
                "usage_status": "unmapped",
            }
            return self._personal_policy
        try:
            policy = self._decision_service.user_policy(sid)
            if isinstance(policy, dict):
                self._personal_policy = dict(policy)
        except Exception as error:
            self._personal_policy = {
                **self._personal_policy,
                "policy_status": "unavailable",
                "sync_error": type(error).__name__,
            }
        try:
            usage = self._decision_service.personal_usage(sid)
            if isinstance(usage, dict):
                self._personal_usage = dict(usage)
        except Exception as error:
            self._personal_usage = {
                **getattr(self, "_personal_usage", {}),
                "usage_status": "unavailable",
                "sync_error": type(error).__name__,
            }
        return self._personal_policy

    def _compare_personal_policy_if_needed(self):
        """Validate and compare a revision before any possible application."""
        policy_state = dict(self._personal_policy or {})
        if not policy_state.get("configured"):
            return self._personal_policy_comparison
        try:
            revision = int(policy_state.get("revision") or 0)
        except (TypeError, ValueError):
            revision = 0
        document = policy_state.get("policy")
        limits = document.get("limits") if isinstance(document, dict) else None
        if (
            revision == self._personal_policy_compared_revision
            and self._personal_policy_comparison.get("validated")
            and isinstance(limits, list)
        ):
            category_targets = {
                str(source.get("target_key") or source.get("key") or "")
                .removeprefix("category:").strip()
                for source in limits if isinstance(source, dict)
                and str(
                    source.get("target_key") or source.get("key") or ""
                ).startswith("category:")
            }
            if not category_targets or category_targets <= set(
                self.usage.categories()
            ):
                return self._personal_policy_comparison
        enforcement_mode = "enforced"
        differences = []
        desired = {}
        if revision < 1 or not isinstance(limits, list):
            comparison = {
                "validated": False, "matches": False,
                "enforcement_mode": enforcement_mode,
                "differences": ["document_invalid"],
            }
        else:
            for source in limits:
                if not isinstance(source, dict):
                    differences.append("limit_invalid")
                    continue
                key = str(source.get("key") or source.get("target_key") or "")
                target = str(source.get("target_key") or key)
                if (
                    not key.startswith(("app:", "site:", "category:"))
                    or not target.startswith(("app:", "site:", "category:"))
                    or key in desired
                ):
                    differences.append("limit_target_invalid")
                    continue
                if target.startswith("category:"):
                    category = target.removeprefix("category:").strip()
                    known_categories = set(self.usage.categories())
                    if not category or category not in known_categories:
                        differences.append(f"category_unresolved:{key}")
                desired[key] = {
                    name: value for name, value in source.items()
                    if name not in {"key", "operation_id", "managed_by"}
                }
            current = {
                key: {
                    name: value for name, value in dict(policy).items()
                    if name not in {"managed_by"}
                }
                for key, policy in self.app_limiter.policies.items()
            }
            if not differences:
                differences.extend(
                    f"missing:{key}" for key in desired.keys() - current.keys()
                )
                differences.extend(
                    f"local_only:{key}" for key in current.keys() - desired.keys()
                )
                differences.extend(
                    f"different:{key}" for key in desired.keys() & current.keys()
                    if desired[key] != current[key]
                )
            comparison = {
                "validated": not any(
                    item in {"limit_invalid", "limit_target_invalid"}
                    or item.startswith("category_unresolved:")
                    for item in differences
                ),
                "matches": not differences,
                "enforcement_mode": enforcement_mode,
                "differences": sorted(differences),
            }
        self._personal_policy_compared_revision = revision
        self._personal_policy_comparison = comparison
        return comparison

    def _apply_personal_policy_if_needed(self):
        """Apply every configured server policy, respecting each limit's switch."""
        state = dict(self._personal_policy or {})
        document = state.get("policy")
        overlay = dict(
            self.usage.data.get("personal_policy_overlay") or {}
        )
        unavailable = (
            str(state.get("policy_status") or "") == "unavailable"
            or str(self._windows_identity.get("mapping_status") or "")
            in {"service_unavailable", "backend_unavailable"}
        )
        if not state.get("configured") and overlay.get("active") and unavailable:
            # A transient service outage must not disable the last enforced
            # policy already persisted on this Windows account.
            return True
        if not state.get("configured"):
            try:
                self.app_limiter.deactivate_personal_policy()
            except (OSError, TypeError, ValueError) as error:
                debug_log(
                    "personal policy rollback failed: "
                    f"{type(error).__name__}"
                )
            self.app_limiter.clear_personal_usage()
            self._personal_policy_applied_revision = 0
            return False

        try:
            revision = int(state.get("revision") or 0)
        except (TypeError, ValueError):
            revision = 0
        comparison = dict(self._personal_policy_comparison or {})
        sid = str(self._windows_identity.get("windows_sid") or "")
        owner = str(state.get("usage_guard_username") or "")
        if revision < 1 or not comparison.get("validated"):
            result = {
                "ok": False, "phase": "validation", **comparison,
            }
        else:
            try:
                already_applied = bool(
                    getattr(self, "_personal_policy_applied_revision", 0)
                    == revision
                    and overlay.get("active")
                    and int(overlay.get("revision") or 0) == revision
                    and str(overlay.get("owner") or "").casefold()
                    == owner.casefold()
                )
                self.app_limiter.activate_personal_policy(
                    owner, revision, document.get("limits"),
                )
                usage = dict(self._personal_usage or {})
                if (
                    int(usage.get("policy_revision") or 0) == revision
                    and str(usage.get("usage_guard_username") or "").casefold()
                    == owner.casefold()
                ):
                    self.app_limiter.set_personal_usage(usage)
                else:
                    self.app_limiter.clear_personal_usage()
                self._personal_policy_applied_revision = revision
                if already_applied:
                    return True
                result = {
                    **comparison, "ok": True, "phase": "applied",
                    "matches": True, "differences": [],
                }
            except (OSError, TypeError, ValueError) as error:
                result = {
                    "ok": False, "phase": "application",
                    "error": type(error).__name__, **comparison,
                }
        try:
            self._decision_service.acknowledge_user_policy(
                sid, revision, result,
            )
        except Exception as error:
            debug_log(
                "personal policy application report deferred: "
                f"{type(error).__name__}"
            )
        return bool(result.get("ok"))

    def stop(self):
        self.timer.stop()
        self.observation_journal.event("service_stop")
        self.usage.update_sessions({})
        if not self._shutdown_recorded:
            self.usage.record_system_event("guard_stop")
        self.usage.save(force=True)

    def _record_guard_start(self, started_at):
        """Mark startup and reconstruct an unexplained previous tracking gap."""
        events = self.usage.system_events()
        previous_kind = str(events[-1].get("type", "")) if events else ""
        observed = [
            str(item.get("last_observed_at") or "")
            for item in self.usage.windows_sessions()
            if item.get("last_observed_at")
        ]
        if observed and previous_kind not in {"sleep", "shutdown", "guard_stop"}:
            previous_at = max(observed)
            try:
                gap = (started_at - datetime.fromisoformat(previous_at)).total_seconds()
            except (TypeError, ValueError):
                gap = 0
            if gap > 15:
                self.usage.record_system_event(
                    "tracking_gap", at=previous_at,
                    ended_at=started_at.isoformat(timespec="seconds"), inferred=True,
                )
        self.usage.record_system_event(
            "guard_start", at=started_at.isoformat(timespec="seconds")
        )

    def _start_logical_session_after_sleep(self, sleep_at, resume_at):
        """Split display sessions at every verified sleep/resume boundary."""
        minimum = float(getattr(config, "SLEEP_SESSION_BOUNDARY_SECONDS", 1))
        if (resume_at - sleep_at).total_seconds() < minimum:
            return False
        already_recorded = any(
            datetime.fromisoformat(str(item.get("started_at"))) >= resume_at
            for item in self.usage.windows_sessions()
            if item.get("started_at")
        )
        if already_recorded:
            self._tracking_started_at = max(
                str(item["started_at"])
                for item in self.usage.windows_sessions()
                if item.get("started_at")
            )
            return False
        sleep_value = sleep_at.isoformat(timespec="seconds")
        resume_value = resume_at.isoformat(timespec="seconds")
        self.usage.update_sessions({}, at=sleep_value)
        self.usage.close_windows_session(sleep_value, reason="sleep")
        self._tracking_started_at = resume_value
        self.usage.record_windows_session(
            resume_value, observed_at=resume_value,
            identity=self._windows_identity, source="extended-modern-standby",
        )
        self.observation_journal.event("logical_session_resume", {
            "sleep_started_at": sleep_value,
            "tracking_started_at": resume_value,
        })
        return True

    def _verified_standby_interval(self, sleep_at, resume_at):
        """Find the Kernel-Power interval matching one native suspend cycle."""
        intervals = modern_standby_intervals_since(
            sleep_at - timedelta(seconds=5),
            getattr(config, "SLEEP_SESSION_BOUNDARY_SECONDS", 1),
            include_reason=True,
        )
        candidates = [
            interval for interval in intervals
            if abs((interval[0] - sleep_at).total_seconds()) <= 30
            and abs((interval[1] - resume_at).total_seconds()) <= 30
        ]
        return min(
            candidates,
            key=lambda interval: abs((interval[0] - sleep_at).total_seconds())
            + abs((interval[1] - resume_at).total_seconds()),
            default=None,
        )

    @staticmethod
    def _standby_splits_session(interval):
        if interval is None:
            return True
        return modern_standby_is_session_boundary(
            *interval,
            idle_threshold_seconds=getattr(
                config, "IDLE_STANDBY_SESSION_BOUNDARY_SECONDS", 4 * 3600,
            ),
        )

    def record_runtime_event(self, event_type):
        """Persist a native Windows sleep/resume/shutdown transition."""
        event_type = str(event_type)
        now = datetime.now().astimezone()
        if event_type == "sleep":
            if self._suspended:
                return
            self.usage.update_sessions({}, at=now.isoformat(timespec="seconds"))
            self.usage.record_system_event("sleep", at=now.isoformat(timespec="seconds"))
            self._suspended = True
            self._suspend_started_at = now
        elif event_type == "resume":
            if not self._suspended:
                return
            self.usage.record_system_event("resume", at=now.isoformat(timespec="seconds"))
            if self._suspend_started_at is not None:
                interval = self._verified_standby_interval(
                    self._suspend_started_at, now,
                )
                if self._standby_splits_session(interval):
                    sleep_at, resume_at = (
                        interval[:2] if interval
                        else (self._suspend_started_at, now)
                    )
                    self._start_logical_session_after_sleep(sleep_at, resume_at)
                    self._notify_computer_state("sleep")
                    self._notify_computer_state("resume")
            self._suspended = False
            self._suspend_started_at = None
            self._program_sessions = {}
            self._program_inventory_initialized = False
            self._web_inventory_initialized = False
            self._last_program_inventory = 0.0
        elif event_type == "shutdown":
            if self._shutdown_recorded:
                return
            self.usage.update_sessions({}, at=now.isoformat(timespec="seconds"))
            self.usage.close_windows_session(
                now.isoformat(timespec="seconds"), reason="shutdown",
            )
            self.usage.record_system_event("shutdown", at=now.isoformat(timespec="seconds"))
            self._notify_computer_state("shutdown")
            self._shutdown_recorded = True
        elif event_type == "shutdown_cancelled":
            if not self._shutdown_recorded:
                return
            self.usage.record_system_event(
                "shutdown_cancelled", at=now.isoformat(timespec="seconds")
            )
            self._shutdown_recorded = False
        else:
            raise ValueError(f"unsupported runtime event: {event_type}")
        self._last_tick = time.monotonic()
        self._last_tick_wall = now
        self._last_awake_clock = awake_monotonic_seconds()
        self.usage.save(force=True)

    def _notify_computer_state(self, event_type):
        messages = {
            "sleep": (
                _("Ordinateur mis en veille — Usage Guard"),
                _("L’ordinateur vient d’être mis en veille."),
            ),
            "resume": (
                _("Ordinateur sorti de veille — Usage Guard"),
                _("L’ordinateur vient de sortir de veille."),
            ),
            "shutdown": (
                _("Arrêt de l’ordinateur — Usage Guard"),
                _("L’arrêt de l’ordinateur vient d’être demandé."),
            ),
        }
        if event_type not in messages:
            return
        rules = [
            rule for rule in self.usage.data.get("notification_rules", [])
            if rule.get("enabled") and rule.get("kind") == "computer_state"
        ]
        title, message = messages[event_type]
        self._dispatch_notification_rules(rules, title, message, 0)

    def tick(self):
        self._process_remote_commands()
        self._refresh_personal_policy()
        self._compare_personal_policy_if_needed()
        self._apply_personal_policy_if_needed()
        self.app_limiter.refresh_computer_block()
        if self._suspended:
            self._last_tick = time.monotonic()
            self._last_tick_wall = datetime.now().astimezone()
            return
        now = time.monotonic()
        wall_now = datetime.now().astimezone()
        # A long gap means sleep/resume or a stalled process; do not attribute it
        # to whichever window happens to be focused after the gap.
        raw_elapsed = max(0.0, now - self._last_tick)
        awake_now = awake_monotonic_seconds()
        awake_elapsed = max(0.0, awake_now - self._last_awake_clock)
        slept = inferred_sleep_seconds(raw_elapsed, awake_elapsed)
        if raw_elapsed > 15 and not self._suspended:
            self.usage.update_sessions(
                {}, at=self._last_tick_wall.isoformat(timespec="seconds")
            )
            if slept:
                self.usage.record_system_event(
                    "sleep", at=self._last_tick_wall.isoformat(timespec="seconds"),
                    ended_at=wall_now.isoformat(timespec="seconds"), inferred=True,
                )
                self.usage.record_system_event(
                    "resume", at=wall_now.isoformat(timespec="seconds"), inferred=True,
                )
                interval = self._verified_standby_interval(
                    self._last_tick_wall, wall_now,
                )
                if self._standby_splits_session(interval):
                    sleep_at, resume_at = (
                        interval[:2] if interval
                        else (self._last_tick_wall, wall_now)
                    )
                    self._start_logical_session_after_sleep(
                        sleep_at, resume_at,
                    )
                    self._notify_computer_state("sleep")
                    self._notify_computer_state("resume")
            else:
                self.usage.record_system_event(
                    "tracking_gap",
                    at=self._last_tick_wall.isoformat(timespec="seconds"),
                    ended_at=wall_now.isoformat(timespec="seconds"), inferred=True,
                )
            self._program_sessions = {}
            self._program_inventory_initialized = False
            self._web_inventory_initialized = False
            self._last_program_inventory = 0.0
        elapsed = min(raw_elapsed, 5.0)
        self._last_tick = now
        self._last_tick_wall = wall_now
        self._last_awake_clock = awake_now
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
                self._program_sessions = self._resolved_program_sessions(
                    running_apps, already_running
                )
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
                "category": str(getattr(target, "category", "") or ""),
                "category_lineage": self.usage.category_lineage(
                    getattr(target, "category", "")
                ),
                "policy_revision": int(
                    self._personal_policy.get("revision") or 0
                ) if self._personal_policy.get("configured") else 0,
            }
        self.usage.update_sessions(observed_sessions)

        self.observation_journal.record({
            "process": str(self.current_context.app_name or ""),
            "window_handle": int(self.current_context.window_handle or 0),
            "site_host": self._observation_site_host(self.current_context.url),
            "site_url": self._observation_site_url(self.current_context.url),
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
                dict(item)
                for item in getattr(
                    self.usage, "_recent_closed_sessions", (),
                )
                if isinstance(item, dict)
                and datetime.fromisoformat(str(item.get("ended_at"))) >= origin
            ] + [
                {**item, "ended_at": None}
                for item in self.usage.data.get("open_sessions", {}).values()
                if isinstance(item, dict)
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
            sessions = (
                self.usage.sessions_for_windows_day(selected_day)
                if scope == "today"
                else self.usage.sessions_for_period(selected_day, selected_day)
            )
            timeline_start = timeline_end = selected_day.isoformat()
        sessions = [
            item for item in sessions
            if not self.usage.is_excluded(str(item.get("key", "")))
            and not is_other_sites_aggregate_key(item.get("key"))
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
        if hasattr(self.app_limiter, "limits"):
            limits = self.app_limiter.limits()
        else:
            limits = []
            for key, policy in self.app_limiter.policies.items():
                limits.append({
                    "key": key,
                    "target_key": policy.get("target_key", key),
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
            current_other_sites = dict(session_other_sites)
            current_day = selected_day.isoformat()
            for browser, days in self.usage.data.get(
                "other_site_days", {}
            ).items():
                for host, seconds in dict(days.get(current_day, {})).items():
                    identity = (browser, host)
                    current_other_sites[identity] = max(
                        float(current_other_sites.get(identity, 0.0)),
                        float(seconds or 0),
                    )
            other_sites = [
                {
                    "browser": browser,
                    "host": host,
                    "seconds": round(seconds, 1),
                }
                for (browser, host), seconds in current_other_sites.items()
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
        profile = current_profile()
        mirror_status = getattr(
            self.app_limiter,
            "decision_mirror_status",
            lambda: {
                "enabled": False,
                "checks": 0,
                "mismatches": 0,
                "healthy": True,
                "authority": "legacy",
                "failures": 0,
                "service": {
                    "enabled": False,
                    "connected": False,
                    "pid": 0,
                    "error": "",
                },
                "last_mismatch": None,
            },
        )()
        return {
            "capabilities": ["computer_blocks_v2", "limit_warning_action"],
            "date": selected_day.isoformat(),
            "scope": scope,
            "runtime": {
                "profile": profile.name,
                "development": not profile.production,
                "windows_identity": dict(
                    getattr(self, "_windows_identity", {})
                ),
                "personal_policy": {
                    key: value for key, value in dict(
                        getattr(self, "_personal_policy", {})
                    ).items()
                    if key != "policy"
                } | {
                    "shadow": dict(getattr(
                        self, "_personal_policy_comparison", {}
                    )),
                },
                "personal_usage": {
                    key: value for key, value in dict(
                        getattr(self, "_personal_usage", {})
                    ).items()
                    if key != "totals"
                },
                "decision_mirror": mirror_status,
                "protection": {
                    "extension": browser_bridge.extension_status(),
                },
            },
            "current": {
                "app_name": str(context.app_name or ""),
                "url": str(context.url or ""),
                "site_host": self._observation_site_host(context.url),
                "site_url": self._observation_site_url(context.url),
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
            "computer_block": getattr(
                self.app_limiter,
                "computer_block_snapshot",
                self.app_limiter.computer_block_status,
            )(),
            "computer_blocks": getattr(
                self.app_limiter,
                "computer_blocks_snapshot",
                lambda: [getattr(
                    self.app_limiter, "computer_block_status", lambda: {}
                )()],
            )(),
            "notification_rules": notification_rules,
            "categories": self.usage.categories(),
            "top_level_categories": self.usage.top_level_categories(),
            "category_parents": dict(self.usage.data.get("category_parents", {})),
            "category_order": list(self.usage.data.get("category_order", [])),
            "target_order": list(self.usage.data.get("target_order", [])),
            "navigation_position": dict(
                self.usage.data.get("navigation_position", {})
            ),
            "unclassified_position": dict(
                self.usage.data.get("unclassified_position", {})
            ),
            "dismissed_targets": dict(
                self.usage.data.get("dismissed_targets", {})
            ),
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
            # Durable history travels through the bounded JSONL outbox.  The
            # heartbeat contains only a small live/recent window and can never
            # grow with a 500 MB local archive.
            "sessions": sessions[:512],
            "windows_sessions": [
                dict(item)
                for item in self.usage.data.get("windows_sessions", [])[:64]
                if isinstance(item, dict)
                if not item.get("ended_at")
                or str(item.get("ended_at") or "") >= self._tracking_started_at
            ][:64],
            "system_events": [
                dict(item)
                for item in self.usage.data.get("system_events", [])[-512:]
                if isinstance(item, dict)
                if str(item.get("at") or "") >= self._tracking_started_at
            ],
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

    def _resolved_program_sessions(self, running_apps, already_running=False):
        """Resolve installed browser apps from their visible window titles."""
        sessions = {}
        for executable, details in dict(running_apps or {}).items():
            resolved = {}
            for title in details.get("window_titles") or [""]:
                target = self.usage.target_for_context(ActiveContext(
                    app_name=details["executable"], window_title=str(title)
                ))
                if not target or self.usage.is_excluded(target.key):
                    continue
                self.usage.remember_target(target)
                session_key, session_label = self._session_identity(target)
                resolved[session_key] = (target, session_label)

            multiple_targets = len(resolved) > 1
            for session_key, (target, session_label) in resolved.items():
                row_id = (
                    f"program:{executable}:{session_key}"
                    if multiple_targets else f"program:{executable}"
                )
                if not multiple_targets:
                    self.usage.reassign_program_sessions(
                        row_id,
                        target.key,
                        session_label,
                        since=getattr(self, "_tracking_started_at", None),
                    )
                sessions[row_id] = {
                    "kind": "program", "key": target.key,
                    "label": session_label,
                    "started_before_tracking": already_running,
                    "source": "windows",
                }
        self.usage.observe_program_inventory(
            session.get("key", "") for session in sessions.values()
        )
        return sessions

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
        """Return the host used by the existing site classification."""
        from usage_guard import _site_host
        return _site_host(url)

    @staticmethod
    def _observation_site_url(url):
        """Return a host-and-path URL while omitting credentials and parameters."""
        from urllib.parse import urlparse
        from usage_guard import _site_host
        try:
            parsed = urlparse(str(url))
            host = _site_host(url)
        except ValueError:
            return ""
        if not host:
            return ""
        return f"{host}{parsed.path or ''}"

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

    def request_activity_export(self, timeout=5):
        result = self.request_remote_command(
            {"action": "activity_export"}, timeout,
        )
        if not isinstance(result, dict) or result.get("ok") is False:
            raise RuntimeError(
                str((result or {}).get("error") or "Export d’activité indisponible.")
            )
        export = result.get("export")
        if not isinstance(export, dict):
            raise RuntimeError("Export d’activité compact invalide.")
        return export

    def acknowledge_activity_export(
        self, cursor, aggregate_ids=None, timeout=5,
    ):
        result = self.request_remote_command({
            "action": "ack_activity_export", "cursor": int(cursor or 0),
            "aggregate_ids": list(aggregate_ids or []),
        }, timeout)
        if not isinstance(result, dict) or result.get("ok") is False:
            raise RuntimeError(
                str((result or {}).get("error") or "Accusé d’activité refusé.")
            )
        return result

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
        command = dict(command)
        service_admin_token = str(
            command.pop(SERVICE_ADMIN_TOKEN_FIELD, "") or ""
        )
        decision_service = getattr(self, "_decision_service", None)
        external_service = bool(
            decision_service is not None
            and getattr(decision_service, "external_service", False)
        )
        service_protection = bool(
            not current_profile().production
            or external_service
        )
        source = command_source(command)
        if (
            external_service and source == SOURCE_LOCAL_ADMIN
            and is_control_mutation(command) and not service_admin_token
        ):
            return {
                "ok": False,
                "error": "La session administrateur doit être renouvelée.",
                "code": "admin_session_required",
            }
        rejection = rejected_mutation(
            command,
            getattr(self.app_limiter, "policies", {}),
            _usage_computer_blocks(self.usage),
            enforced=service_protection,
        )
        if rejection:
            return {"ok": False, "error": rejection, "code": "managed_remotely"}
        if (
            service_protection
            and decision_service is not None
            and is_control_mutation(command)
        ):
            try:
                authorization = decision_service.authorize_control(command)
            except Exception as error:
                debug_log(f"service control authorization failed: {type(error).__name__}")
            else:
                if not authorization.get("allowed"):
                    return {
                        "ok": False,
                        "error": authorization.get("error") or "Commande locale refusée par le service.",
                        "code": "managed_remotely",
                    }
        command_id = str(command.get("_remote_command_id") or "")
        if command_id:
            results = self.usage.data.setdefault("remote_command_results", {})
            if command_id in results and self._remote_command_result_reflected(command, results[command_id]):
                return dict(results[command_id])
        result = self._apply_remote_command_once(command)
        if (
            result.get("ok")
            and command.get("action") in {
                "set_computer_block", "set_computer_block_enabled",
                "clear_computer_block",
            }
            and not str(command.get("block_id") or "")
        ):
            block = result.get("computer_block")
            if isinstance(block, dict) and block.get("block_id"):
                command["block_id"] = str(block["block_id"])
                if command.get("action") == "set_computer_block":
                    command["create_new"] = True
        if (
            result.get("ok")
            and external_service
            and decision_service is not None
            and source == SOURCE_LOCAL_ADMIN
            and is_catalog_mutation(command)
        ):
            try:
                catalog_sync = decision_service.queue_user_catalog_action(
                    command, str(command.get("actor") or "administrateur local"),
                )
                result["catalog_sync"] = catalog_sync
            except Exception as error:
                debug_log(
                    "catalogue sync queue failed: "
                    f"{type(error).__name__}"
                )
                result["catalog_sync"] = {
                    "queued": False,
                    "error": "Le classement est enregistré sur ce PC, mais sa synchronisation est en attente.",
                }
        if (
            result.get("ok")
            and service_protection
            and decision_service is not None
            and is_control_mutation(command)
        ):
            service_owns_backend = bool(
                external_service and source == SOURCE_BACKEND
            )
            try:
                if external_service and source == SOURCE_LOCAL_ADMIN:
                    committed = decision_service.backend_admin(
                        service_admin_token, "commit_control",
                        {"command": command, "result": result},
                    )
                    if isinstance(committed, dict) and isinstance(
                        committed.get("policy_sync"), dict
                    ):
                        result["policy_sync"] = committed["policy_sync"]
                elif not service_owns_backend:
                    decision_service.commit_control(command, result)
            except Exception as error:
                debug_log(f"service control commit failed: {type(error).__name__}")
                if source == SOURCE_LOCAL_ADMIN:
                    self._restore_service_controls()
                if source in {SOURCE_BACKEND, SOURCE_LOCAL_ADMIN}:
                    return {
                        "ok": False,
                        "error": "Le service n’a pas pu enregistrer durablement la règle.",
                        "code": "service_commit_failed",
                    }
        if command_id and result.get("ok"):
            results = self.usage.data.setdefault("remote_command_results", {})
            results[command_id] = json.loads(json.dumps(result))
            for old_id in sorted(results, key=lambda value: int(value) if str(value).isdigit() else 0)[:-200]:
                results.pop(old_id, None)
            self.usage.save(force=True)
        return result

    def _remote_command_result_reflected(self, command, result):
        if not isinstance(result, dict) or not result.get("ok"):
            return False
        action = command.get("action")
        if action == "set_limit":
            limit = result.get("limit") if isinstance(result.get("limit"), dict) else {}
            key = str(limit.get("key") or command.get("target_key") or "")
            return bool(key and key in self.app_limiter.policies)
        if action == "remove_limit":
            return str(command.get("target_key") or "") not in self.app_limiter.policies
        if action == "replace_computer_blocks":
            expected = command.get("blocks")
            if not isinstance(expected, list):
                return False
            current = self.usage.computer_blocks()
            return current == result.get("computer_blocks") == current
        if action == "set_computer_block":
            expected = result.get("computer_block") if isinstance(result.get("computer_block"), dict) else {}
            block_id = str(expected.get("block_id") or command.get("block_id") or "")
            try:
                current = self.usage.computer_block(block_id or None)
            except ValueError:
                current = {}
            if not expected or not current.get("mode"):
                return False
            return all(
                str(current.get(key, "")) == str(expected.get(key, ""))
                for key in ("block_id", "mode", "started_at", "ends_at")
            )
        if action == "set_computer_block_enabled":
            expected = result.get("computer_block") if isinstance(result.get("computer_block"), dict) else {}
            block_id = str(expected.get("block_id") or command.get("block_id") or "")
            try:
                current = self.usage.computer_block(block_id or None)
            except ValueError:
                current = {}
            return bool(current.get("mode")) and bool(current.get("enabled", True)) == bool(expected.get("enabled", True))
        if action == "clear_computer_block":
            removed = result.get("computer_block") if isinstance(result.get("computer_block"), dict) else {}
            block_id = str(removed.get("block_id") or command.get("block_id") or "")
            try:
                self.usage.computer_block(block_id or None)
            except ValueError:
                return True
            return False
        return True

    def _apply_remote_command_once(self, command):
        action = command.get("action")
        source = command_source(command)
        manager = manager_for_source(source)
        if action == "snapshot":
            return self.remote_snapshot(command.get("selection"))
        if action == "activity_export":
            from backend_client import live_activity_intervals
            export = self.usage.pending_backend_activity_intervals(
                max_bytes=192 * 1024,
            )
            export["daily_aggregates"] = (
                self.usage.pending_backend_daily_aggregates()
            )
            export["live_intervals"] = live_activity_intervals({
                "open_sessions": self.usage.data.get("open_sessions", {}),
            })[:256]
            return {"ok": True, "export": export}
        if action == "ack_activity_export":
            cursor = self.usage.acknowledge_backend_activity_intervals(
                command.get("cursor")
            )
            self.usage.acknowledge_backend_daily_aggregates(
                command.get("aggregate_ids")
            )
            return {"ok": True, "cursor": cursor}
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
            requested_rule = dict(command.get("rule") or {})
            if not str(requested_rule.get("owner", "")).strip():
                rule_id = str(requested_rule.get("id", ""))
                existing = next((
                    item for item in self.usage.data.get("notification_rules", [])
                    if str(item.get("id", "")) == rule_id
                ), None)
                requested_rule["owner"] = str(
                    (existing or {}).get("owner") or command.get("actor") or ""
                ).strip()
            rule = self.usage.set_notification_rule(requested_rule)
            if rule.get("kind") == "limit_warning":
                target_key = str(rule.get("target_key", ""))
                if target_key:
                    if target_key not in self.app_limiter.policies:
                        raise ValueError("Limite introuvable.")
                    policy = self.app_limiter.policies[target_key]
                    self.app_limiter.apply_settings(target_key, {
                        **policy, "warning_seconds": rule["warning_seconds"],
                    }, source=source)
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
            settings = self.app_limiter.apply_settings(
                target_key, {**policy, "warning_seconds": seconds}, source=source
            )
            return {"ok": True, "warning_seconds": settings["warning_seconds"]}
        if action == "replace_computer_blocks":
            blocks = self.usage.replace_computer_blocks(
                command.get("blocks"), managed_by="backend",
            )
            effective = self.app_limiter.refresh_computer_block()
            return {
                "ok": True, "computer_blocks": blocks,
                "computer_block": effective,
            }
        if action == "set_computer_block":
            actor = self._limit_actor_label(command.get("actor"))
            block = self.usage.set_computer_block(
                command.get("mode"), actor,
                day=command.get("day"),
                duration_seconds=command.get("duration_seconds"),
                delay_seconds=command.get("delay_seconds", 0),
                start_time=command.get("start_time"),
                end_time=command.get("end_time"),
                grace_seconds=command.get("grace_seconds", 300),
                valid_from=command.get("valid_from"),
                valid_from_time=command.get("valid_from_time"),
                valid_until=command.get("valid_until"),
                valid_until_time=command.get("valid_until_time"),
                delete_after_expiry=command.get("delete_after_expiry", True),
                name=command.get("name") if "name" in command else None,
                enforcement_action=command.get("enforcement_action"),
                managed_by=manager,
                block_id=command.get("block_id") or None,
            )
            self.app_limiter.refresh_computer_block()
            start_at = datetime.fromisoformat(block["started_at"]).astimezone()
            end = datetime.fromisoformat(block["ends_at"]).astimezone().strftime("%d/%m/%Y %H:%M")
            now = datetime.now().astimezone()
            pending = start_at > now
            title = (
                _("Limitation planifiée par {actor} — Usage Guard").format(actor=actor)
                if pending else
                _("Usage de l’ordinateur limité par {actor} — Usage Guard").format(
                    actor=actor
                )
            )
            message = (
                _("{actor} a planifié la limitation du {start} jusqu’au {end}.").format(
                    actor=actor,
                    start=start_at.strftime("%d/%m/%Y %H:%M"),
                    end=end,
                )
                if pending else
                _("{actor} a limité l’usage de l’ordinateur jusqu’au {end}.").format(
                    actor=actor, end=end
                )
            )
            rules = [rule for rule in self.usage.data.get("notification_rules", []) if rule.get("enabled") and rule.get("kind") == "limit_change"]
            self._dispatch_notification_rules(rules, title, message, 0)
            return {
                "ok": True, "computer_block": block,
                "computer_blocks": self.usage.computer_blocks(),
            }
        if action == "set_computer_block_enabled":
            actor = self._limit_actor_label(command.get("actor"))
            enabled = bool(command.get("enabled"))
            expected = command.get("expected_computer_block")
            block_id = str(command.get("block_id") or "")
            if (
                source == SOURCE_LOCAL_ADMIN
                and expected
                and not _computer_block_matches_unlock_identity(
                    self.app_limiter.computer_block_status(
                        block_id=block_id or None
                    ), expected,
                )
            ):
                return {
                    "ok": False,
                    "error": _(
                        "La limitation active a changé ; "
                        "aucune règle n’a été modifiée."
                    ),
                    "code": "computer_block_changed",
                }
            block = self.usage.set_computer_block_enabled(
                enabled,
                block_id=block_id or None,
                managed_by=None if source == SOURCE_LOCAL_ADMIN else manager,
            )
            self.app_limiter.refresh_computer_block()
            rules = [rule for rule in self.usage.data.get("notification_rules", []) if rule.get("enabled") and rule.get("kind") == "limit_change"]
            if rules:
                title = (
                    _("Limitation activée par {actor} — Usage Guard")
                    if enabled else _("Limitation désactivée par {actor} — Usage Guard")
                ).format(actor=actor)
                message = (
                    _("{actor} a activé la limitation de l’usage de l’ordinateur.")
                    if enabled else
                    _("{actor} a désactivé la limitation de l’usage de l’ordinateur.")
                ).format(actor=actor)
                self._dispatch_notification_rules(rules, title, message, 0)
            return {
                "ok": True, "computer_block": block,
                "computer_blocks": self.usage.computer_blocks(),
            }
        if action == "clear_computer_block":
            actor = self._limit_actor_label(command.get("actor"))
            removed = self.usage.clear_computer_block(
                command.get("block_id") or None
            )
            self.app_limiter.refresh_computer_block()
            rules = [rule for rule in self.usage.data.get("notification_rules", []) if rule.get("enabled") and rule.get("kind") == "limit_change"]
            if rules:
                self._dispatch_notification_rules(rules,
                    _("Limitation levée par {actor} — Usage Guard").format(actor=actor),
                    _("{actor} a levé la limitation de l’usage de l’ordinateur.").format(
                        actor=actor
                    ), 0,
                )
            return {
                "ok": True, "computer_block": removed,
                "computer_blocks": self.usage.computer_blocks(),
            }
        if action == "notify_pwa_login":
            if command.get("title") or command.get("message"):
                self.notification_requested.emit(
                    str(command.get("title") or _("Connexion à l’interface — Usage Guard")),
                    str(command.get("message") or _("Une connexion à l’interface de gestion a été détectée.")),
                    0,
                )
                return {"ok": True}
            self._notify_pwa_login(
                command.get("actor"), command.get("ip"),
                windows_only=bool(command.get("windows_only")),
                actor_is_admin=bool(command.get("actor_is_admin")),
                actor_role=command.get("actor_role"),
            )
            return {"ok": True}
        if action == "notify_access_change":
            affected_roles = {
                str(role).strip().lower()
                for role in (command.get("subject_roles") or [])
                if str(role).strip().lower() in NOTIFICATION_SUBJECT_ROLES
            }
            rules = [
                rule for rule in self.usage.data.get("notification_rules", [])
                if rule.get("enabled") and rule.get("kind") == "access_change"
                and (
                    not affected_roles
                    or notification_subject_roles(rule) & affected_roles
                )
            ]
            self._dispatch_notification_rules(
                rules,
                str(command.get("title") or _("Droits modifiés — Usage Guard")),
                str(command.get("message") or _("Les droits d’un utilisateur ont été modifiés.")),
                0,
            )
            return {"ok": True}
        if action == "notify_client_presence":
            connected = bool(command.get("connected"))
            self.notification_requested.emit(
                str(command.get("title") or (
                    _("Ordinateur allumé — Usage Guard") if connected
                    else _("Ordinateur éteint ou inaccessible — Usage Guard")
                )),
                str(command.get("message") or (
                    _("Le client Usage Guard vient de se connecter au serveur.")
                    if connected else
                    _("Le client Usage Guard ne communiquait plus avec le serveur.")
                )),
                0,
            )
            return {"ok": True}
        if action == "notify_protection_event":
            self.notification_requested.emit(
                str(command.get("title") or _("État de protection — Usage Guard")),
                str(command.get("message") or _("L’état de la protection a changé.")),
                0,
            )
            return {"ok": True}
        if action == "rename_target":
            self.usage.rename_target(
                str(command["target_key"]), str(command["label"])
            )
            return {"ok": True}
        if action == "replace_catalog":
            self.usage.replace_catalog(command.get("catalog"))
            return {"ok": True}
        if action == "add_catalog_item":
            item = self.usage.add_catalog_item(
                str(command.get("kind", "")),
                str(command.get("identifier", "")),
                label=str(command.get("label", "")),
                browser=str(command.get("browser", "brave.exe")),
                parent=str(command.get("parent", "")),
            )
            return {"ok": True, "item": item}
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
        if action == "dismiss_target":
            self.usage.dismiss_target(str(command["target_key"]))
            return {"ok": True}
        if action == "delete_target":
            target_key = str(command["target_key"])
            removed_limits = self.usage.delete_target(target_key)
            limiter = getattr(self, "app_limiter", None)
            if limiter is not None and hasattr(
                limiter, "reload_after_target_deleted"
            ):
                limiter.reload_after_target_deleted(target_key)
            return {"ok": True, "removed_limits": removed_limits}
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
        if action == "reorder_target":
            self.usage.reorder_target(
                str(command["target_key"]),
                str(command["destination"]),
                bool(command.get("before", True)),
                list(command.get("displayed_siblings") or []),
            )
            return {"ok": True}
        if action == "reorder_navigation":
            self.usage.reorder_navigation(
                str(command["destination"]),
                bool(command.get("before", True)),
            )
            return {"ok": True}
        if action == "reorder_unclassified":
            self.usage.reorder_unclassified(
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
            browser = str(command["browser"]).lower()
            host = str(command["host"])
            target_key = f"site:{browser}:{_site_host(host) or host.lower().strip()}"
            removed_limits = self.usage.delete_browser_site(browser, host)
            limiter = getattr(self, "app_limiter", None)
            if limiter is not None and hasattr(
                limiter, "reload_after_target_deleted"
            ):
                limiter.reload_after_target_deleted(target_key)
            return {"ok": True, "removed_limits": removed_limits}
        target_key = str(command.get("target_key", ""))
        if not target_key.startswith(("app:", "site:", "category:")):
            raise ValueError("Cible de limite non prise en charge.")
        if action == "set_limit":
            requested_settings = dict(command["settings"])
            requested_settings[MANAGED_BY_FIELD] = manager
            create_new = bool(requested_settings.pop("create_new", False))
            measured_target_key = str(requested_settings.get("target_key") or target_key)
            is_existing_rule = target_key in self.app_limiter.policies
            if create_new and is_existing_rule:
                target_key = f"{measured_target_key}#{uuid.uuid4().hex[:8]}"
            requested_settings["target_key"] = measured_target_key
            existed = target_key in self.app_limiter.policies
            was_enabled = (
                bool(self.app_limiter.policies[target_key].get("enabled"))
                if existed else None
            )
            if not existed:
                requested_settings["enabled"] = True
            settings = self.app_limiter.apply_settings(
                target_key, requested_settings, source=source
            )
            if existed and was_enabled != bool(settings.get("enabled")):
                self._notify_limit_toggle(target_key, bool(settings.get("enabled")), command.get("actor"))
            else:
                self._notify_limit_change(target_key, "modifiée" if existed else "créée", command.get("actor"))
            return {"ok": True, "limit": {"key": target_key, **settings}}
        if action == "remove_limit":
            label = self.app_limiter.label_for_key(target_key)
            self.app_limiter.remove_limit(target_key, source=source)
            self._notify_limit_change(target_key, "supprimée", command.get("actor"), label)
            return {"ok": True}
        if action == "reset_limit":
            if target_key not in self.app_limiter.policies:
                raise ValueError("Cette limite n'existe pas.")
            self.app_limiter.reset_today(target_key, source=source)
            return {"ok": True}
        raise ValueError("Commande distante inconnue.")

    def _notify_limit_change(self, target_key, verb, actor=None, label=None):
        actor = self._limit_actor_label(actor)
        label = label or self.app_limiter.label_for_key(target_key)
        rules = [
            rule for rule in self.usage.data.get("notification_rules", [])
            if rule.get("enabled") and rule.get("kind") == "limit_change"
            and (not str(rule.get("target_key", "")) or str(rule.get("target_key")) == target_key)
        ]
        templates = {
            "créée": (
                _("Limite créée par {actor} — Usage Guard"),
                _("{actor} a créé la limite « {label} »."),
            ),
            "modifiée": (
                _("Limite modifiée par {actor} — Usage Guard"),
                _("{actor} a modifié la limite « {label} »."),
            ),
            "supprimée": (
                _("Limite supprimée par {actor} — Usage Guard"),
                _("{actor} a supprimé la limite « {label} »."),
            ),
        }
        title, message = templates.get(verb, templates["modifiée"])
        self._dispatch_notification_rules(
            rules,
            title.format(actor=actor),
            message.format(actor=actor, label=label),
            0,
        )

    def _notify_limit_toggle(self, target_key, enabled, actor=None):
        rules = [
            rule for rule in self.usage.data.get("notification_rules", [])
            if rule.get("enabled") and rule.get("kind") == "limit_change"
            and (not str(rule.get("target_key", "")) or str(rule.get("target_key")) == target_key)
        ]
        if not rules:
            return
        actor = self._limit_actor_label(actor)
        label = self.app_limiter.label_for_key(target_key)
        title = (
            _("Limite activée par {actor} — Usage Guard")
            if enabled else _("Limite désactivée par {actor} — Usage Guard")
        )
        message = (
            _("{actor} a activé la limite « {label} ».")
            if enabled else _("{actor} a désactivé la limite « {label} ».")
        )
        self._dispatch_notification_rules(
            rules, title.format(actor=actor),
            message.format(actor=actor, label=label), 0,
        )

    def _notify_pwa_login(
        self, actor=None, ip=None, windows_only=False, actor_is_admin=False,
        actor_role=None,
    ):
        actor = str(actor or _("Utilisateur inconnu"))
        actor_key = actor.strip().casefold()
        actor_role = str(
            actor_role or ("admin" if actor_is_admin else "user")
        ).strip().lower()
        rules = [
            rule for rule in self.usage.data.get("notification_rules", [])
            if rule.get("enabled") and rule.get("kind") == "pwa_login"
            and not (
                str(rule.get("owner", "")).strip()
                and str(rule.get("owner", "")).strip().casefold() == actor_key
            )
            and actor_role in notification_subject_roles(rule)
        ]
        if windows_only:
            rules = [
                {**rule, "channels": ["windows"]}
                for rule in rules
                if "windows" in (rule.get("channels") or ["windows"])
            ]
        if not rules:
            return
        title = _("{actor} connecté à la PWA — Usage Guard").format(actor=actor)
        message = (
            _("{actor} vient de se connecter à la PWA depuis {ip}.").format(
                actor=actor, ip=ip
            )
            if ip else
            _("{actor} vient de se connecter à la PWA.").format(actor=actor)
        )
        self._dispatch_notification_rules(rules, title, message, 0)

    def _notify_limit_override_login(self, actor=None):
        rules = [
            rule for rule in self.usage.data.get("notification_rules", [])
            if rule.get("enabled")
            and rule.get("kind") == "limit_override_login"
        ]
        if not rules:
            return
        actor = str(actor or _("Administrateur"))
        self._dispatch_notification_rules(
            rules,
            _("Déverrouillage administrateur — Usage Guard"),
            _("{actor} s’est authentifié pendant une limitation et a déverrouillé l’ordinateur.").format(
                actor=actor,
            ),
            0,
        )

    def _dispatch_notification_rules(self, rules, title, message, process_id=0):
        rules = [rule for rule in rules if rule.get("enabled")]
        windows_rule = next((
            rule for rule in rules
            if "windows" in (rule.get("channels") or ["windows"])
        ), None)
        if windows_rule:
            self.notification_requested.emit(
                title,
                str(windows_rule.get("description") or message),
                int(process_id or 0),
            )
        recipient_rules = {}
        for rule in rules:
            recipient = str(rule.get("email_recipient", "")).strip()
            if "email" in (rule.get("channels") or ["windows"]) and recipient:
                recipient_rules.setdefault(recipient, rule)
        for recipient in sorted(recipient_rules):
            rule = recipient_rules[recipient]
            kind = str(rule.get("kind") or "")
            self.email_notification_requested.emit(
                kind, title, str(rule.get("description") or message), recipient
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
        return (
            _("Utilisateur local ({username})").format(username=local_actor)
            if local_actor else _("Utilisateur local")
        )

    def _notify_startup_rules(self):
        weekday = date.today().weekday()
        for rule in self.usage.data.get("notification_rules", []):
            if not rule.get("enabled") or rule.get("kind") != "startup_reminder":
                continue
            if weekday not in {int(value) for value in rule.get("weekdays", [])}:
                continue
            self._dispatch_notification_rules([rule],
                str(rule.get("label") or _("Rappel — Usage Guard")),
                str(rule.get("description") or _("Rappel programmé au démarrage.")),
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
                    label = _("Tout l’ordinateur")
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
                    label = _("Catégorie · {category}").format(category=category)
                else:
                    target_active = bool(current_target and current_target.key == target_key)
                    label = self.app_limiter.label_for_key(target_key)
                reached = bool(after_time) and now.strftime("%H:%M") >= after_time and target_active
                if reached:
                    active_tokens.add(token)
                    if token not in self._notification_thresholds_shown:
                        self._dispatch_notification_rules([rule],
                            str(rule.get("label") or _("Horaire atteint — Usage Guard")),
                            _("{label} est utilisé après l’heure définie ({time}).").format(
                                label=label, time=after_time
                            ),
                            0,
                        )
                continue
            if mode == "duration":
                target_key = str(rule.get("target_key", ""))
                usage = self.usage.usage_for_day()
                if target_key == "computer:all":
                    seconds = sum(entry.seconds for entry in self.usage.presentation(usage))
                    label = _("Tout l’ordinateur")
                elif target_key.startswith("category:"):
                    category = target_key.removeprefix("category:")
                    seconds = sum(
                        entry.seconds for entry in self.usage.presentation(usage)
                        if (
                            category in self.usage.category_lineage(entry.category)
                            or category in self.usage.category_lineage(entry.site_category)
                        )
                    )
                    label = _("Catégorie · {category}").format(category=category)
                else:
                    seconds = float(usage.get(target_key, 0))
                    label = self.app_limiter.label_for_key(target_key)
                threshold_seconds = max(1, int(rule.get("duration_seconds", 3600)))
                token = (rule_id, now.date().isoformat())
                reached = seconds >= threshold_seconds
                if reached:
                    active_tokens.add(token)
                    if token not in self._notification_thresholds_shown:
                        self._dispatch_notification_rules([rule],
                            str(rule.get("label") or _("Durée atteinte — Usage Guard")),
                            _("{label} a atteint {duration} d’utilisation.").format(
                                label=label,
                                duration=self.app_limiter._format_duration(
                                    threshold_seconds
                                ),
                            ),
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
                    self._dispatch_notification_rules([rule],
                        str(rule.get("label") or _("Seuil d’usage atteint")),
                        _("{label} a atteint {threshold} % de sa limite.").format(
                            label=self.app_limiter.label_for_key(target_key),
                            threshold=threshold,
                        ),
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
            )
        )


# Kept as an import-compatible alias for integrations using the old name.
UsageGuardService = MonitoringService
