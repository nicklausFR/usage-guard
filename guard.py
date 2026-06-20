from datetime import datetime
import hashlib

from PySide6.QtCore import QObject, QTimer, Signal

from activity import ActivityProbe, ActiveContext
from usage_guard import JokerStore, Rule, RuleStore, UsageStore, config


class UsageGuardService(QObject):
    state_changed = Signal()
    violation_changed = Signal(str)

    def __init__(self):
        super().__init__()
        self.rules = RuleStore()
        self.usage = UsageStore()
        self.jokers = JokerStore()
        self.probe = ActivityProbe()
        self.current_context = ActiveContext()
        self.current_violation = ""
        self.locked = False
        self._last_tick = datetime.now().astimezone()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.setInterval(1000)

    def start(self):
        if self.usage.reset_detected and getattr(config, "LOCK_ON_USAGE_RESET", True):
            self.locked = True
        self.timer.start()
        self.tick()

    def tick(self):
        now = datetime.now().astimezone()
        elapsed = max(0.0, (now - self._last_tick).total_seconds())
        self._last_tick = now
        self.current_context = self.probe.current()

        matched_rules = self.matching_rules(self.current_context)
        if self.is_activity_countable(self.current_context):
            for rule in matched_rules:
                self.usage.add_seconds(rule.target_type, rule.target, elapsed, now)

        violation = "Security lock: usage storage was deleted or reset" if self.locked else self.first_violation(matched_rules, now)
        if violation != self.current_violation:
            self.current_violation = violation
            self.violation_changed.emit(violation)
        self.state_changed.emit()

    def unlock_with_master_password(self, password: str):
        expected = str(getattr(config, "MASTER_PASSWORD_SHA256", "") or "").strip()
        if not expected:
            return False
        candidate = hashlib.sha256(password.encode("utf-8")).hexdigest()
        if candidate != expected:
            return False
        self.locked = False
        self.usage.reset_detected = False
        self.usage.save()
        self.current_violation = ""
        self.violation_changed.emit("")
        self.state_changed.emit()
        return True

    def grant_joker(self, rule: Rule, minutes: int):
        self.jokers.grant(rule.name, minutes)
        self.current_violation = ""
        self.violation_changed.emit("")
        self.state_changed.emit()

    def matching_rules(self, context: ActiveContext):
        return [
            rule
            for rule in self.rules.rules
            if rule.enabled and self._rule_matches(rule, context)
        ]

    def first_violation(self, rules: list[Rule], now=None):
        now = now or datetime.now().astimezone()
        for rule in rules:
            if self.jokers.active(rule.name, now):
                continue
            for quota in rule.quotas:
                used = self.usage.seconds_for(
                    rule.target_type,
                    rule.target,
                    quota.period,
                    now,
                )
                if used >= quota.limit_minutes * 60:
                    return f"{rule.name}: quota {quota.period} atteint"
            if self._outside_allowed_window(rule, now):
                return f"{rule.name}: hors plage autorisee"
        return ""

    def _rule_matches(self, rule: Rule, context: ActiveContext):
        target = rule.target.lower()
        if not target:
            return False
        if rule.target_type == "computer":
            return True
        if rule.target_type == "app":
            return target in context.app_name.lower()
        if rule.target_type == "site":
            url = context.url.lower()
            if url:
                return target in url
            if bool(getattr(config, "ALLOW_WINDOW_TITLE_SITE_FALLBACK", False)):
                return target in context.window_title.lower()
            return False
        return False

    def is_activity_countable(self, context: ActiveContext):
        if context.is_afk:
            return False
        if not context.app_name and not context.window_title:
            return False
        return True

    def _outside_allowed_window(self, rule: Rule, now):
        allow_windows = [window for window in rule.windows if window.mode == "allow"]
        if not allow_windows:
            return False
        return not any(self._window_matches(window, now) for window in allow_windows)

    def _window_matches(self, window, now):
        day = now.strftime("%a").lower()[:3]
        if window.days and day not in [item.lower()[:3] for item in window.days]:
            return False
        current = now.strftime("%H:%M")
        if window.start <= window.end:
            return window.start <= current <= window.end
        return current >= window.start or current <= window.end
