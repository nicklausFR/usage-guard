import sys
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import runtime_profile
from app_limiter import AppLimiter
from limit_decision import evaluate_limit, schedule_status


BASE_POLICY = {
    "limit_seconds": 3600,
    "extension_seconds": 900,
    "block_during_validity": False,
    "schedule_date": "",
    "schedule_start": "",
    "schedule_end": "",
    "valid_from": "",
    "valid_from_time": "",
    "valid_until": "",
    "valid_until_time": "",
    "blocked_after": "",
}


class PureLimitDecisionTest(unittest.TestCase):
    def setUp(self):
        self.previous_profile = runtime_profile.current_profile()

    def tearDown(self):
        runtime_profile._set_active_profile_for_tests(self.previous_profile)

    def test_duration_and_extension_are_decided_without_platform_dependencies(self):
        now = datetime.fromisoformat("2026-08-20T12:00:00+02:00")
        normal = evaluate_limit(
            BASE_POLICY, {"seconds": 3500, "extension_used": False}, now
        )
        extended = evaluate_limit(
            BASE_POLICY, {"seconds": 3500, "extension_used": True}, now
        )
        self.assertEqual(normal.allowed, 3600)
        self.assertEqual(normal.remaining, 100)
        self.assertEqual(extended.allowed, 4500)
        self.assertEqual(extended.remaining, 1000)

    def test_period_block_and_cutoff_are_explicit_decisions(self):
        now = datetime.fromisoformat("2026-08-20T18:30:00+02:00")
        blocked_period = evaluate_limit(
            {**BASE_POLICY, "block_during_validity": True},
            {"seconds": 0, "extension_used": False},
            now,
        )
        cutoff = evaluate_limit(
            {**BASE_POLICY, "blocked_after": "18:00"},
            {"seconds": 10, "extension_used": False},
            now,
        )
        self.assertEqual(blocked_period.allowed, 0)
        self.assertEqual(blocked_period.remaining, 0)
        self.assertTrue(cutoff.time_blocked)
        self.assertEqual(cutoff.remaining, 0)

    def test_schedule_crossing_midnight_matches_expected_window(self):
        policy = {
            **BASE_POLICY,
            "schedule_start": "23:00",
            "schedule_end": "02:00",
        }
        self.assertTrue(schedule_status(
            policy, datetime.fromisoformat("2026-08-20T01:30:00+02:00")
        )["active"])
        self.assertFalse(schedule_status(
            policy, datetime.fromisoformat("2026-08-20T12:00:00+02:00")
        )["active"])

    def test_dev_profile_compares_core_with_legacy_without_replacing_it(self):
        runtime_profile._set_active_profile_for_tests(
            runtime_profile.profile_named("dev")
        )
        limiter = AppLimiter.__new__(AppLimiter)
        limiter.policies = {"app:test": dict(BASE_POLICY)}
        limiter.usage = SimpleNamespace(
            app_limit_state_for_day=lambda _key: {
                "seconds": 120,
                "extension_used": False,
            }
        )
        limiter._decision_mirror_checks = 0
        limiter._decision_mirror_mismatches = 0
        limiter._decision_mirror_last_mismatch = None
        limiter._decision_mirror_failures = 0
        limiter._decision_mirror = None

        status = limiter.current_status("app:test")
        mirror = limiter.decision_mirror_status()

        self.assertEqual(status["remaining"], 3480)
        self.assertTrue(mirror["enabled"])
        self.assertEqual(mirror["checks"], 1)
        self.assertEqual(mirror["mismatches"], 0)
        self.assertTrue(mirror["healthy"])
        self.assertEqual(mirror["authority"], "legacy")

    def _dev_limiter(self, decision_mirror):
        runtime_profile._set_active_profile_for_tests(
            runtime_profile.profile_named("dev")
        )
        limiter = AppLimiter.__new__(AppLimiter)
        limiter.policies = {"app:test": dict(BASE_POLICY)}
        limiter.usage = SimpleNamespace(
            app_limit_state_for_day=lambda _key: {
                "seconds": 120,
                "extension_used": False,
            }
        )
        limiter._decision_mirror_checks = 0
        limiter._decision_mirror_mismatches = 0
        limiter._decision_mirror_failures = 0
        limiter._decision_mirror_last_mismatch = None
        limiter._decision_mirror = decision_mirror
        return limiter

    def test_concordant_service_decision_becomes_authoritative_in_dev(self):
        class Service:
            def evaluate(self, policy, state, now):
                return evaluate_limit(policy, state, now).as_status()

            def status(self):
                return {
                    "enabled": True, "connected": True,
                    "pid": 42, "error": "",
                }

        limiter = self._dev_limiter(Service())
        status = limiter.current_status("app:test")
        mirror = limiter.decision_mirror_status()

        self.assertIsInstance(status["allowed"], float)
        self.assertEqual(status["remaining"], 3480)
        self.assertEqual(mirror["authority"], "service")

    def test_mismatch_or_ipc_failure_falls_back_to_legacy(self):
        class MismatchService:
            def evaluate(self, policy, state, now):
                result = evaluate_limit(policy, state, now).as_status()
                result["remaining"] += 1
                return result

            def status(self):
                return {
                    "enabled": True, "connected": True,
                    "pid": 42, "error": "",
                }

        mismatch = self._dev_limiter(MismatchService())
        mismatch_status = mismatch.current_status("app:test")
        self.assertIsInstance(mismatch_status["allowed"], int)
        self.assertEqual(
            mismatch.decision_mirror_status()["authority"], "legacy"
        )

        class FailingService(MismatchService):
            def evaluate(self, policy, state, now):
                raise OSError("pipe unavailable")

            def status(self):
                return {
                    "enabled": True, "connected": False,
                    "pid": 0, "error": "pipe unavailable",
                }

        failing = self._dev_limiter(FailingService())
        failing_status = failing.current_status("app:test")
        self.assertIsInstance(failing_status["allowed"], int)
        self.assertEqual(failing._decision_mirror_failures, 1)
        self.assertEqual(failing.decision_mirror_status()["authority"], "legacy")

    def test_deleted_measured_target_reloads_uuid_rules_and_unblocks(self):
        limiter = AppLimiter.__new__(AppLimiter)
        deleted_rule = "app:test#1234abcd"
        kept_rule = "app:kept"
        kept_policy = {**BASE_POLICY, "target_key": kept_rule}
        limiter.policies = {
            deleted_rule: {**BASE_POLICY, "target_key": "app:test"},
            kept_rule: kept_policy,
        }
        limiter.usage = SimpleNamespace(
            data={"app_limit_settings": {kept_rule: kept_policy}},
            app_limit_settings=lambda key: (
                kept_policy if key == kept_rule else {}
            ),
            prepare_app_limit=lambda *_args, **_kwargs: None,
            save=lambda **_kwargs: None,
        )
        limiter.blocked = True
        limiter.target_key = deleted_rule
        limiter._warning_shown = {
            (deleted_rule, "warning"), (kept_rule, "warning"),
        }
        limiter._notified_handles = {
            (deleted_rule, 10), (kept_rule, 20),
        }
        limiter._playing_seen_at = {deleted_rule: 1.0, kept_rule: 2.0}
        limiter._media_target_keys = {"app:test", kept_rule}
        limiter._running_limits = [
            {"key": deleted_rule}, {"key": kept_rule},
        ]
        limiter._current_web_limit = {"target_key": deleted_rule}
        unblocked = []
        limiter.unblock_target = lambda: unblocked.append(True)

        removed = limiter.reload_after_target_deleted("app:test")

        self.assertEqual(removed, [deleted_rule])
        self.assertEqual(set(limiter.policies), {kept_rule})
        self.assertEqual(unblocked, [True])
        self.assertEqual(limiter._warning_shown, {(kept_rule, "warning")})
        self.assertEqual(limiter._notified_handles, {(kept_rule, 20)})
        self.assertNotIn(deleted_rule, limiter._playing_seen_at)
        self.assertEqual(limiter._running_limits, [{"key": kept_rule}])
        self.assertIsNone(limiter._current_web_limit)


if __name__ == "__main__":
    unittest.main()
