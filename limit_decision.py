"""Pure, platform-independent decisions for application and web limits."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import date, datetime, timedelta
from typing import Mapping


@dataclass(frozen=True)
class LimitDecision:
    seconds: float
    extension_used: bool
    allowed: float
    remaining: float
    time_remaining: float | None
    time_blocked: bool
    schedule_active: bool
    schedule_pending: bool

    def as_status(self) -> dict:
        return asdict(self)


def evaluate_limit(
    policy: Mapping[str, object],
    state: Mapping[str, object],
    now: datetime,
) -> LimitDecision:
    """Evaluate one limit without storage, Qt, Windows, or network access."""
    seconds = float(state["seconds"])
    extension_used = bool(state["extension_used"])
    allowed = 0 if policy.get("block_during_validity") else (
        float(policy["limit_seconds"])
        + (float(policy["extension_seconds"]) if extension_used else 0)
    )
    duration_remaining = max(0.0, allowed - seconds)
    schedule = schedule_status(policy, now)
    time_remaining = cutoff_remaining(policy, now) if schedule["active"] else None
    remaining = (
        max(0.0, min(duration_remaining, time_remaining))
        if time_remaining is not None
        else duration_remaining
    )
    return LimitDecision(
        seconds=seconds,
        extension_used=extension_used,
        allowed=allowed,
        remaining=remaining,
        time_remaining=time_remaining,
        time_blocked=time_remaining is not None and time_remaining <= 0,
        schedule_active=schedule["active"],
        schedule_pending=schedule["pending"],
    )


def schedule_status(
    policy: Mapping[str, object], now: datetime
) -> dict[str, bool]:
    selected_date = str(policy.get("schedule_date", "")).strip()
    valid_from = str(policy.get("valid_from", "")).strip()
    valid_from_time = str(policy.get("valid_from_time", "00:00")).strip() or "00:00"
    valid_until = str(policy.get("valid_until", "")).strip()
    valid_until_time = str(policy.get("valid_until_time", "23:59")).strip() or "23:59"
    start_text = str(policy.get("schedule_start", "")).strip()
    end_text = str(policy.get("schedule_end", "")).strip()
    if valid_from:
        validity_start = datetime.combine(
            date.fromisoformat(valid_from),
            datetime.strptime(valid_from_time, "%H:%M").time(),
        ).replace(tzinfo=now.tzinfo)
        if now < validity_start:
            return {"active": False, "pending": True}
    if valid_until:
        validity_end = datetime.combine(
            date.fromisoformat(valid_until),
            datetime.strptime(valid_until_time, "%H:%M").time(),
        ).replace(tzinfo=now.tzinfo)
        if now >= validity_end:
            return {"active": False, "pending": False}
    if not selected_date and not start_text:
        return {"active": True, "pending": False}
    if not start_text:
        return {"active": True, "pending": False}
    start_time = datetime.strptime(start_text, "%H:%M").time()
    end_time = datetime.strptime(end_text, "%H:%M").time()
    crosses_midnight = end_time < start_time
    if selected_date:
        occurrence_days = [date.fromisoformat(selected_date)]
    else:
        occurrence_days = [now.date()]
        if crosses_midnight:
            occurrence_days.insert(0, now.date() - timedelta(days=1))
    windows = []
    for occurrence_day in occurrence_days:
        start = datetime.combine(occurrence_day, start_time).replace(tzinfo=now.tzinfo)
        end = datetime.combine(
            occurrence_day + timedelta(days=1) if crosses_midnight else occurrence_day,
            end_time,
        ).replace(tzinfo=now.tzinfo)
        windows.append((start, end))
        if start <= now < end:
            return {"active": True, "pending": False}
    if selected_date:
        return {"active": False, "pending": now < windows[0][0]}
    next_start = datetime.combine(now.date(), start_time).replace(tzinfo=now.tzinfo)
    if next_start <= now:
        next_start += timedelta(days=1)
    if valid_until:
        validity_end = datetime.combine(
            date.fromisoformat(valid_until),
            datetime.strptime(valid_until_time, "%H:%M").time(),
        ).replace(tzinfo=now.tzinfo)
        if next_start >= validity_end:
            return {"active": False, "pending": False}
    return {"active": False, "pending": True}


def cutoff_remaining(
    policy: Mapping[str, object], now: datetime
) -> float | None:
    blocked_after = str(policy.get("blocked_after", "")).strip()
    if not blocked_after:
        return None
    cutoff_time = datetime.strptime(blocked_after, "%H:%M").time()
    cutoff = datetime.combine(now.date(), cutoff_time).replace(tzinfo=now.tzinfo)
    return (cutoff - now).total_seconds()
