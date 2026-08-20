import json
import sys
import tempfile
import unittest
from datetime import date, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from usage_guard import AppUsageStore, _local_site_category, _site_host
from activity import ActiveContext
from app_limiter import AppLimiter


class AppUsageStoreBackupTest(unittest.TestCase):
    def test_existing_activity_file_gets_daily_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            original = {"version": 2, "days": {"2026-08-12": {"app:test": 42}}}
            path.write_text(json.dumps(original), encoding="utf-8")

            AppUsageStore(path)

            backup = path.parent / "backups" / f"activity-{date.today().isoformat()}.json"
            self.assertTrue(backup.exists())
            self.assertEqual(json.loads(backup.read_text(encoding="utf-8")), original)


class AppUsageStoreSessionsTest(unittest.TestCase):
    def test_renamed_target_label_is_used_for_new_sessions(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.rename_target("app:chatgpt", "Assistant")

            target = store.target_for_context(ActiveContext(
                app_name="chrome.exe", window_title="ChatGPT"
            ))

            self.assertEqual(target.key, "app:chatgpt")
            self.assertEqual(target.label, "Assistant")

    def test_deleted_potplayer_limit_is_never_recreated_on_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            limiter = type("Limiter", (), {"usage": store})()

            AppLimiter._migrate_legacy_potplayer_limit(limiter)
            self.assertNotIn("app:potplayermini64", store.data["app_limit_settings"])

            store.data["app_limit_settings"]["app-limit:potplayer"] = {
                "enabled": True, "limit_seconds": 15,
                "extension_seconds": 15, "warning_seconds": 5,
            }
            AppLimiter._migrate_legacy_potplayer_limit(limiter)
            self.assertIn("app:potplayermini64", store.data["app_limit_settings"])

            store.remove_app_limit_settings("app:potplayermini64")
            AppLimiter._migrate_legacy_potplayer_limit(limiter)
            self.assertNotIn("app:potplayermini64", store.data["app_limit_settings"])

    def test_default_limit_warning_is_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            store = AppUsageStore(path)
            self.assertEqual(store.default_limit_warning_seconds(), 300)
            self.assertEqual(store.set_default_limit_warning_seconds(420), 420)
            self.assertEqual(AppUsageStore(path).default_limit_warning_seconds(), 420)

    def test_notification_rules_only_include_explicit_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            store = AppUsageStore(path)
            store.data["app_limit_settings"]["app:editor"] = {"enabled": True}

            rule = store.set_notification_rule({
                "kind": "usage_threshold", "target_key": "app:editor",
                "threshold_percent": 75, "label": "Editor à 75 %",
            })

            rules = store.notification_rules()
            self.assertEqual(len(rules), 1)
            self.assertNotIn("mandatory", rules[0])
            self.assertEqual(rules[-1]["threshold_percent"], 75)
            self.assertEqual(AppUsageStore(path).notification_rules()[-1]["id"], rule["id"])

            store.remove_notification_rule(rule["id"])
            self.assertEqual(store.notification_rules(), [])

    def test_requested_notification_kinds_are_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["app_limit_settings"] = {
                "app:editor": {
                    "enabled": True, "limit_seconds": 3600,
                    "extension_seconds": 900, "warning_seconds": 300,
                }
            }
            for kind in ("limited_app_start", "limit_warning", "usage_threshold"):
                rule = store.set_notification_rule({
                    "kind": kind, "target_key": "app:editor",
                    "warning_seconds": 420,
                })
                self.assertEqual(rule["kind"], kind)
            login = store.set_notification_rule({"kind": "pwa_login"})
            change = store.set_notification_rule({"kind": "limit_change"})
            computer_warning = store.set_notification_rule({
                "kind": "computer_block_warning", "warning_seconds": 900,
            })
            computer_change = store.set_notification_rule({
                "kind": "computer_block_change",
            })
            self.assertEqual(login["label"], "Connexion à la PWA")
            self.assertIn("Ajout", change["label"])
            self.assertEqual(computer_warning["warning_seconds"], 900)
            self.assertIn("ordinateur", computer_change["label"])

    def test_start_notification_applies_to_all_limited_apps(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["targets"]["app:test"] = {"label": "Test"}
            rule = store.set_notification_rule({
                "kind": "limited_app_start", "target_key": "app:test",
            })
            self.assertEqual(rule["target_key"], "")

    def test_limit_warning_applies_to_all_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["targets"]["app:game"] = {"label": "Jeu", "category": "Jeux"}
            rule = store.set_notification_rule({
                "kind": "limit_warning", "target_key": "category:Jeux",
                "warning_seconds": 900,
            })
            self.assertEqual(rule["target_key"], "")
            self.assertEqual(rule["warning_seconds"], 900)

    def test_multiple_computer_warning_rules_are_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            first = store.set_notification_rule({
                "kind": "limit_warning",
                "warning_seconds": 900,
            })
            second = store.set_notification_rule({
                "kind": "limit_warning",
                "warning_seconds": 300,
            })
            self.assertNotEqual(first["id"], second["id"])
            self.assertEqual(
                [rule["warning_seconds"] for rule in store.notification_rules()],
                [900, 300],
            )

    def test_expiry_removes_only_rules_with_a_reached_end_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["targets"]["app:test"] = {"label": "Test"}
            expired = store.set_notification_rule({
                "kind": "usage_threshold", "threshold_mode": "duration",
                "target_key": "app:test", "duration_seconds": 600,
                "valid_until": "2026-08-15", "valid_until_time": "10:00",
                "enabled": True,
            })
            disabled = store.set_notification_rule({
                "kind": "usage_threshold", "threshold_mode": "duration",
                "target_key": "app:test", "duration_seconds": 600,
                "enabled": False,
            })

            removed = store.prune_expired_notification_rules(
                datetime.fromisoformat("2026-08-15T10:00:00+02:00")
            )

            self.assertEqual(removed, 1)
            ids = {rule["id"] for rule in store.data["notification_rules"]}
            self.assertNotIn(expired["id"], ids)
            self.assertIn(disabled["id"], ids)

    def test_expiry_removes_only_limits_with_a_reached_end_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            expired = store.set_app_limit_settings("app:expired", {
                "enabled": True, "limit_seconds": 600,
                "extension_seconds": 60, "warning_seconds": 60,
                "valid_until": "2026-08-15", "valid_until_time": "10:00",
            })
            disabled = store.set_app_limit_settings("app:disabled", {
                "enabled": False, "limit_seconds": 600,
                "extension_seconds": 60, "warning_seconds": 60,
            })
            limiter = AppLimiter.__new__(AppLimiter)
            limiter.usage = store
            limiter.policies = {"app:expired": expired, "app:disabled": disabled}
            limiter.blocked = False

            removed = limiter.prune_expired_limits(
                datetime.fromisoformat("2026-08-15T10:00:00+02:00")
            )

            self.assertEqual(removed, ["app:expired"])
            self.assertNotIn("app:expired", limiter.policies)
            self.assertIn("app:disabled", limiter.policies)
            self.assertIn("app:disabled", store.data["app_limit_settings"])

    def test_duration_and_hour_threshold_rules_keep_their_validity(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["targets"]["site:brave.exe:example.test"] = {
                "label": "example.test", "category": "Internet",
            }
            duration_rule = store.set_notification_rule({
                "kind": "usage_threshold", "threshold_mode": "duration",
                "target_key": "site:brave.exe:example.test",
                "duration_seconds": 7200,
                "valid_from": "2026-08-15", "valid_from_time": "08:00",
                "valid_until": "2026-08-20", "valid_until_time": "23:00",
            })
            hour_rule = store.set_notification_rule({
                "kind": "usage_threshold", "threshold_mode": "time",
                "target_key": "site:brave.exe:example.test",
                "after_time": "23:00",
            })

            self.assertEqual(duration_rule["duration_seconds"], 7200)
            self.assertEqual(duration_rule["valid_until_time"], "23:00")
            self.assertEqual(hour_rule["after_time"], "23:00")
            self.assertEqual(
                hour_rule["target_key"], "site:brave.exe:example.test"
            )

    def test_limit_settings_support_an_optional_blocked_after_time(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            settings = store.set_app_limit_settings("app:test", {
                "limit_seconds": 3600, "extension_seconds": 900,
                "warning_seconds": 300, "blocked_after": "23:00",
                "schedule_date": "2026-08-20",
                "valid_from": "2026-08-18", "valid_from_time": "09:30",
                "valid_until": "2026-08-25", "valid_until_time": "21:15",
                "schedule_start": "18:00", "schedule_end": "20:00",
            })
            self.assertEqual(settings["blocked_after"], "23:00")
            self.assertEqual(store.app_limit_settings("app:test")["blocked_after"], "23:00")
            self.assertEqual(settings["schedule_date"], "2026-08-20")
            self.assertEqual(settings["valid_from"], "2026-08-18")
            self.assertEqual(settings["valid_from_time"], "09:30")
            self.assertEqual(settings["valid_until"], "2026-08-25")
            self.assertEqual(settings["valid_until_time"], "21:15")
            self.assertEqual(settings["schedule_start"], "18:00")
            self.assertEqual(settings["schedule_end"], "20:00")
            with self.assertRaisesRegex(ValueError, "Heure"):
                store.set_app_limit_settings("app:test", {
                    **settings, "blocked_after": "25:00",
                })
            with self.assertRaisesRegex(ValueError, "début et la fin"):
                store.set_app_limit_settings("app:test", {
                    **settings, "blocked_after": "", "schedule_end": "",
                })
            overnight = store.set_app_limit_settings("app:test", {
                **settings, "blocked_after": "",
                "schedule_start": "20:00", "schedule_end": "18:00",
            })
            self.assertEqual(overnight["schedule_start"], "20:00")
            self.assertEqual(overnight["schedule_end"], "18:00")
            with self.assertRaisesRegex(ValueError, "différentes"):
                store.set_app_limit_settings("app:test", {
                    **settings, "blocked_after": "",
                    "schedule_start": "20:00", "schedule_end": "20:00",
                })
            with self.assertRaisesRegex(ValueError, "fin de validité"):
                store.set_app_limit_settings("app:test", {
                    **settings, "valid_from": "2026-08-26",
                    "valid_from_time": "09:30",
                    "valid_until": "2026-08-25",
                    "valid_until_time": "21:15",
                })

    def test_period_block_is_persisted_without_extension_or_daily_schedule(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            settings = store.set_app_limit_settings("app:test", {
                "block_during_validity": True,
                "limit_seconds": 3600,
                "extension_seconds": 900,
                "warning_seconds": 300,
                "valid_from": "2026-08-15", "valid_from_time": "18:00",
                "valid_until": "2026-08-15", "valid_until_time": "20:00",
                "blocked_after": "23:00",
                "schedule_start": "09:00", "schedule_end": "17:00",
            })

            self.assertTrue(settings["block_during_validity"])
            self.assertEqual(settings["extension_seconds"], 0)
            self.assertEqual(settings["blocked_after"], "")
            self.assertEqual(settings["schedule_start"], "")
            self.assertEqual(settings["schedule_end"], "")
            self.assertTrue(store.app_limit_settings("app:test")["block_during_validity"])

            with self.assertRaisesRegex(ValueError, "borne datée"):
                store.set_app_limit_settings("app:test", {
                    "block_during_validity": True,
                })

    def test_cutoff_remaining_is_computed_for_the_current_day(self):
        now = datetime.fromisoformat("2026-08-15T22:30:00+02:00")
        self.assertEqual(
            AppLimiter._cutoff_remaining({"blocked_after": "23:00"}, now),
            1800,
        )
        self.assertEqual(
            AppLimiter._cutoff_remaining({"blocked_after": "22:00"}, now),
            -1800,
        )
        self.assertIsNone(AppLimiter._cutoff_remaining({"blocked_after": ""}, now))

    def test_limit_schedule_supports_a_precise_day_and_time_range(self):
        before = datetime.fromisoformat("2026-08-20T17:30:00+02:00")
        during = datetime.fromisoformat("2026-08-20T19:00:00+02:00")
        after = datetime.fromisoformat("2026-08-20T20:30:00+02:00")
        policy = {
            "schedule_date": "2026-08-20",
            "schedule_start": "18:00", "schedule_end": "20:00",
        }
        self.assertEqual(
            AppLimiter._schedule_status(policy, before),
            {"active": False, "pending": True},
        )
        self.assertEqual(
            AppLimiter._schedule_status(policy, during),
            {"active": True, "pending": False},
        )
        self.assertEqual(
            AppLimiter._schedule_status(policy, after),
            {"active": False, "pending": False},
        )

    def test_limit_schedule_supports_validity_dates(self):
        policy = {
            "valid_from": "2026-08-20", "valid_from_time": "18:30",
            "valid_until": "2026-08-25", "valid_until_time": "19:30",
            "schedule_start": "18:00", "schedule_end": "20:00",
        }
        before = datetime.fromisoformat("2026-08-19T19:00:00+02:00")
        during = datetime.fromisoformat("2026-08-22T19:00:00+02:00")
        after = datetime.fromisoformat("2026-08-26T19:00:00+02:00")
        self.assertEqual(AppLimiter._schedule_status(policy, before), {
            "active": False, "pending": True,
        })
        self.assertEqual(AppLimiter._schedule_status(policy, during), {
            "active": True, "pending": False,
        })
        self.assertEqual(AppLimiter._schedule_status(policy, after), {
            "active": False, "pending": False,
        })

    def test_builtin_notification_identifiers_remain_reserved(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            self.assertEqual(store.notification_rules(), [])
            with self.assertRaisesRegex(ValueError, "réservé"):
                store.set_notification_rule({
                    "id": "builtin:limit-warning", "kind": "limit_change",
                })
            with self.assertRaisesRegex(ValueError, "réservé"):
                store.remove_notification_rule("builtin:limit-warning")

    def test_startup_reminder_requires_and_persists_weekdays(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            with self.assertRaisesRegex(ValueError, "jour"):
                store.set_notification_rule({"kind": "startup_reminder"})
            rule = store.set_notification_rule({
                "kind": "startup_reminder", "weekdays": [6, 0, 6],
                "description": "Ne pas utiliser l’ordinateur aujourd’hui.",
            })
            self.assertEqual(rule["weekdays"], [0, 6])
            self.assertEqual(rule["kind"], "startup_reminder")

    def test_computer_block_supports_today_and_rolling_24_hours(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            today = store.set_computer_block("today", "alice")
            today_end = datetime.fromisoformat(today["ends_at"])
            self.assertEqual(today_end.hour, 0)
            self.assertEqual(today_end.minute, 0)
            self.assertEqual(today["actor"], "alice")

            rolling = store.set_computer_block("24h")
            start = datetime.fromisoformat(rolling["started_at"])
            end = datetime.fromisoformat(rolling["ends_at"])
            self.assertAlmostEqual((end - start).total_seconds(), 86400, delta=1)
            disabled = store.set_computer_block_enabled(False)
            self.assertFalse(disabled["enabled"])
            self.assertEqual(disabled["started_at"], rolling["started_at"])
            enabled = store.set_computer_block_enabled(True)
            self.assertTrue(enabled["enabled"])
            store.clear_computer_block()
            self.assertEqual(store.data["computer_block"], {})

    def test_computer_block_supports_a_day_and_today_time_range(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            now = datetime.fromisoformat("2026-08-15T10:00:00+02:00")

            scheduled = store.set_computer_block(
                "day", "alice", day="2026-08-15",
                start_time="10:30", now=now,
            )
            self.assertEqual(
                datetime.fromisoformat(scheduled["started_at"]),
                datetime.fromisoformat("2026-08-15T10:30:00+02:00"),
            )
            self.assertEqual(
                datetime.fromisoformat(scheduled["ends_at"]).date(),
                date(2026, 8, 16),
            )

            immediate = store.set_computer_block(
                "day", day="2026-08-15", start_time="09:00", now=now,
            )
            self.assertEqual(datetime.fromisoformat(immediate["started_at"]), now)

            time_range = store.set_computer_block(
                "range", start_time="10:15", end_time="11:45", now=now,
            )
            start = datetime.fromisoformat(time_range["started_at"])
            end = datetime.fromisoformat(time_range["ends_at"])
            self.assertEqual(
                start, datetime.fromisoformat("2026-08-15T10:15:00+02:00")
            )
            self.assertEqual((end - start).total_seconds(), 5400)

            overnight_range = store.set_computer_block(
                "range", start_time="23:00", end_time="00:00", now=now,
            )
            overnight_start = datetime.fromisoformat(overnight_range["started_at"])
            overnight_end = datetime.fromisoformat(overnight_range["ends_at"])
            self.assertEqual(overnight_start.hour, 23)
            self.assertEqual(overnight_end.date(), overnight_start.date() + timedelta(days=1))

            recurring = store.set_computer_block(
                "schedule", start_time="18:00", end_time="20:00",
                valid_from="2026-08-16", valid_from_time="09:30",
                valid_until="2026-08-20", valid_until_time="21:15", now=now,
            )
            self.assertEqual(recurring["daily_start"], "18:00")
            self.assertEqual(recurring["daily_end"], "20:00")
            self.assertEqual(recurring["valid_from"], "2026-08-16")
            self.assertEqual(recurring["valid_from_time"], "09:30")
            self.assertEqual(recurring["valid_until"], "2026-08-20")
            self.assertEqual(recurring["valid_until_time"], "21:15")

            overnight = store.set_computer_block(
                "schedule", start_time="23:00", end_time="00:00", now=now,
            )
            self.assertEqual(overnight["daily_start"], "23:00")
            self.assertEqual(overnight["daily_end"], "00:00")
            self.assertEqual(
                datetime.fromisoformat(overnight["ends_at"]).date(),
                datetime.fromisoformat(overnight["started_at"]).date() + timedelta(days=1),
            )

            with self.assertRaisesRegex(ValueError, "déjà passé"):
                store.set_computer_block("day", day="2026-08-14", now=now)

    def test_categories_never_expose_internal_root(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["browser_categories"] = {"brave.exe": "__root__"}
            store.data["targets"] = {
                "app:test": {"category": "__root__"},
                "app:other": {"category": "Travail"},
            }
            self.assertNotIn("__root__", store.categories())
            self.assertIn("Travail", store.categories())

    def test_limit_usage_resets_at_local_midnight(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            first = datetime.fromisoformat("2026-08-12T10:00:00+02:00")
            recent = datetime.fromisoformat("2026-08-13T09:59:00+02:00")
            after_window = datetime.fromisoformat("2026-08-13T10:01:00+02:00")

            store.add_app_limit_seconds("app:test", 10, first)
            store.add_app_limit_seconds("app:test", 5, recent)

            self.assertEqual(store.app_limit_state_for_day("app:test", recent)["seconds"], 5)
            self.assertEqual(store.app_limit_state_for_day("app:test", after_window)["seconds"], 5)

    def test_new_limit_includes_usage_measured_before_its_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["days"] = {"2026-08-15": {"app:editor": 7200.0}}
            now = datetime.fromisoformat("2026-08-15T12:00:00+02:00")

            store.prepare_app_limit("app:editor", 14400, 900, now)

            self.assertEqual(
                store.app_limit_state_for_day("app:editor", now)["seconds"], 7200
            )

    def test_new_category_limit_includes_child_activity(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["targets"]["app:chatgpt"] = {"category": "Programmation"}
            store.data["category_parents"]["Programmation"] = "Travail"
            store.data["days"] = {"2026-08-15": {"app:chatgpt": 5400.0}}
            now = datetime.fromisoformat("2026-08-15T12:00:00+02:00")

            store.prepare_app_limit("category:Travail", 14400, 900, now)

            self.assertEqual(
                store.app_limit_state_for_day("category:Travail", now)["seconds"],
                5400,
            )

    def test_reset_limit_does_not_restore_prior_usage(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["days"] = {"2026-08-15": {"app:editor": 7200.0}}
            now = datetime.fromisoformat("2026-08-15T12:00:00+02:00")

            store.reset_app_limit_state("app:editor", now)
            store.prepare_app_limit("app:editor", 14400, 900, now)

            self.assertEqual(
                store.app_limit_state_for_day("app:editor", now)["seconds"], 0
            )

    def test_limit_seed_replaces_inaccurate_legacy_buckets_with_daily_total(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["days"] = {"2026-08-15": {"app:editor": 5400.0}}
            store.data["app_limit_rolling"]["app:editor"] = {
                "buckets": {"2026-08-15T09:00+02:00": 9999.0},
                "extension_granted_at": None,
                "usage_seeded_at": "2026-08-15T11:00:00+02:00",
            }
            now = datetime.fromisoformat("2026-08-15T12:00:00+02:00")

            store.prepare_app_limit("app:editor", 14400, 900, now)

            self.assertEqual(
                store.app_limit_state_for_day("app:editor", now)["seconds"],
                5400,
            )
            self.assertEqual(
                store.data["app_limit_rolling"]["app:editor"]["usage_seed_version"],
                4,
            )

    def test_limited_target_remains_visible_at_zero_seconds(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["app_limit_settings"]["app:potplayermini64"] = {"enabled": True}
            store.data["targets"]["app:potplayermini64"] = {"label": "PotPlayer"}

            entries = store.presentation({})

            self.assertEqual([(entry.label, entry.seconds) for entry in entries], [("PotPlayer", 0)])

    def test_news_sites_remain_visible_with_zero_seconds(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            key = "site:brave.exe:example-news.test"
            store.data["targets"][key] = {
                "label": "example-news.test", "category": "Actualités",
                "category_scope": "site",
            }

            entries = store.presentation({})

            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].key, key)
            self.assertEqual(entries[0].category, "Actualités")
            self.assertEqual(entries[0].seconds, 0)

    def test_top_level_categories_remain_known_without_period_activity(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["browser_categories"]["brave.exe"] = "Internet"
            store.data["site_categories"].append("Réseaux sociaux")
            store.data["targets"]["app:vlc"] = {
                "label": "VLC", "category": "Divertissement",
            }
            store.data["targets"]["app:root"] = {
                "label": "Racine", "category": "__root__",
            }
            store.data["targets"]["site:brave.exe:reddit.com"] = {
                "label": "reddit.com", "category": "Internet",
                "site_category": "Réseaux sociaux",
            }

            self.assertEqual(
                store.top_level_categories(),
                ["Divertissement", "Internet"],
            )
            entries = store.presentation({})
            self.assertEqual(
                sorted((entry.key, entry.seconds) for entry in entries),
                [
                    ("app:root", 0.0),
                    ("app:vlc", 0.0),
                    ("site:brave.exe:reddit.com", 0.0),
                ],
            )

    def test_empty_period_category_can_be_nested_without_losing_its_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["browser_categories"]["brave.exe"] = "Jeux"
            store.data["targets"]["app:game"] = {
                "label": "Jeu", "category": "Jeux",
            }
            store.data["targets"]["site:brave.exe:youtube.com"] = {
                "label": "YouTube", "category": "Jeux",
                "category_scope": "site",
            }
            self.assertEqual(
                sorted(entry.key for entry in store.presentation({})),
                ["app:game", "site:brave.exe:youtube.com"],
            )

            store.move_category("Jeux", "Divertissement")

            self.assertEqual(
                store.data["browser_categories"]["brave.exe"],
                "Jeux",
            )
            self.assertEqual(
                store.data["targets"]["app:game"]["category"],
                "Jeux",
            )
            self.assertEqual(
                store.data["targets"]["site:brave.exe:youtube.com"]["category"],
                "Jeux",
            )
            self.assertEqual(
                store.data["category_parents"],
                {"Jeux": "Divertissement"},
            )
            self.assertIn("Jeux", store.top_level_categories())
            self.assertIn("Divertissement", store.top_level_categories())

    def test_categories_support_arbitrary_depth_and_reject_cycles(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.move_category("Jeux", "Divertissement")
            store.move_category("Steam", "Jeux")
            store.move_category("Indépendants", "Steam")

            self.assertEqual(store.data["category_parents"], {
                "Jeux": "Divertissement",
                "Steam": "Jeux",
                "Indépendants": "Steam",
            })
            with self.assertRaisesRegex(ValueError, "propre parent"):
                store.move_category("Divertissement", "Indépendants")

    def test_reordering_categories_changes_only_sibling_display_order(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            for category in ("Travail", "Loisirs", "Lecture"):
                store.data["targets"][f"app:{category}"] = {"category": category}
            store.move_category("Lecture", "Loisirs")
            store.data["targets"]["app:Jeux"] = {"category": "Jeux"}
            store.move_category("Jeux", "Loisirs")

            store.reorder_category("Travail", "Loisirs", before=True)
            store.reorder_category("Jeux", "Lecture", before=True)

            self.assertEqual(
                store.top_level_categories(),
                ["Jeux", "Lecture", "Travail", "Loisirs"],
            )
            self.assertEqual(
                store.data["category_parents"],
                {"Lecture": "Loisirs", "Jeux": "Loisirs"},
            )
            self.assertEqual(
                AppUsageStore(store.path).top_level_categories(),
                ["Jeux", "Lecture", "Travail", "Loisirs"],
            )
            with self.assertRaisesRegex(ValueError, "même niveau"):
                store.reorder_category("Lecture", "Travail")

    def test_site_categories_can_be_reordered_without_changing_assignments(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["site_categories"] = ["Actualité", "Documentation", "Achats"]
            store.data["targets"]["site:brave:test"] = {"site_category": "Actualité"}

            store.reorder_site_category("Achats", "Actualité", before=True)

            self.assertEqual(store.site_categories(), ["Achats", "Actualité", "Documentation"])
            self.assertTrue(store.data["site_category_order_manual"])
            self.assertEqual(store.data["targets"]["site:brave:test"]["site_category"], "Actualité")

    def test_loopback_ports_remain_distinct(self):
        self.assertEqual(_site_host("http://localhost:3000/app"), "localhost:3000")
        self.assertEqual(_site_host("http://localhost:5173/app"), "localhost:5173")
        self.assertTrue(_local_site_category("localhost:3000"))

    def test_other_sites_remain_visible_on_days_without_usage(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["other_site_days"] = {
                "brave.exe": {
                    "2026-08-12": {"example.com": 12.0},
                    "2026-08-13": {"another.example": 8.0},
                }
            }

            self.assertEqual(
                store.other_sites("brave.exe", date(2026, 8, 14)),
                {"example.com": 0.0, "another.example": 0.0},
            )

    def test_usage_guard_local_pwa_has_a_friendly_label_and_keeps_its_port(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            target = store.target_for_context(ActiveContext(
                app_name="brave.exe", url="http://localhost:8766/"
            ))
            self.assertEqual(target.key, "site:brave.exe:localhost:8766")
            self.assertEqual(target.label, "Usage Guard")

    def test_usage_guard_local_pwa_can_move_to_a_top_level_category(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            key = "site:brave.exe:localhost:8766"
            store.data["targets"][key] = {
                "label": "Usage Guard",
                "category": "Applications non classées",
                "category_scope": "site",
            }

            store.set_category(key, "Programmation")

            metadata = store.data["targets"][key]
            self.assertEqual(metadata["category"], "Programmation")
            self.assertNotIn("site_category", metadata)

    def test_regular_site_moves_out_of_browser_into_a_general_category(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            key = "site:brave.exe:data.gouv.fr"
            store.data["browser_categories"]["brave.exe"] = "Internet"
            store.data["site_categories"] = ["Programmation"]
            store.data["targets"][key] = {
                "category": "Internet",
                "site_category": "Programmation",
            }

            store.set_category(key, "Programmation")

            metadata = store.data["targets"][key]
            self.assertEqual(metadata["label"], "data.gouv.fr")
            self.assertEqual(metadata["category"], "Programmation")
            self.assertEqual(metadata["category_scope"], "site")
            self.assertNotIn("site_category", metadata)
            self.assertNotIn("Programmation", store.site_categories())

    def test_legacy_general_category_is_removed_from_the_browser_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["targets"]["app:code"] = {
                "label": "Visual Studio",
                "category": "Programmation",
            }
            store.data["targets"]["site:brave.exe:data.gouv.fr"] = {
                "category": "__root__",
                "site_category": "Programmation",
            }
            store.data["targets"]["site:brave.exe:bbc.com"] = {
                "label": "bbc.com",
                "category": "__root__",
                "site_category": "Actualité",
            }
            store.data["site_categories"] = ["Programmation", "Actualité"]

            store._migrate_legacy_targets()

            promoted = store.data["targets"]["site:brave.exe:data.gouv.fr"]
            self.assertEqual(promoted["category"], "Programmation")
            self.assertEqual(promoted["category_scope"], "site")
            self.assertNotIn("site_category", promoted)
            self.assertNotIn("Programmation", store.site_categories())
            self.assertEqual(
                store.data["targets"]["site:brave.exe:bbc.com"]["site_category"],
                "Actualité",
            )

    def test_moving_a_site_group_to_a_general_category_promotes_every_site(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            keys = ["site:brave.exe:data.gouv.fr", "site:brave.exe:carto.com"]
            store.data["site_categories"] = ["Développement"]
            for key in keys:
                store.data["targets"][key] = {
                    "category": "Internet",
                    "site_category": "Développement",
                }

            store.set_category_for_keys(keys, "Programmation")

            for key in keys:
                metadata = store.data["targets"][key]
                self.assertEqual(metadata["category"], "Programmation")
                self.assertEqual(metadata["category_scope"], "site")
                self.assertNotIn("site_category", metadata)
            self.assertNotIn("Développement", store.site_categories())

    def test_youtube_can_move_out_of_the_browser_category(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            key = "site:brave.exe:youtube.com"
            store.data["browser_categories"]["brave.exe"] = "Internet"
            store.data["targets"][key] = {
                "label": "YouTube",
                "category": "Internet",
            }

            store.set_category(key, "Divertissement")

            metadata = store.data["targets"][key]
            self.assertEqual(metadata["category"], "Divertissement")
            self.assertEqual(metadata["category_scope"], "site")
            self.assertNotIn("site_category", metadata)

    def test_legacy_youtube_subcategory_is_promoted_to_top_level(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            key = "site:brave.exe:youtube.com"
            store.data["browser_categories"]["brave.exe"] = "Internet"
            store.data["targets"][key] = {
                "label": "YouTube",
                "category": "Internet",
                "site_category": "Divertissement",
            }

            store._migrate_legacy_targets()

            metadata = store.data["targets"][key]
            self.assertEqual(metadata["category"], "Divertissement")
            self.assertEqual(metadata["category_scope"], "site")
            self.assertNotIn("site_category", metadata)

    def test_session_can_span_days_and_never_closes_before_opening(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            observed = {"program:app:editor": {"kind": "program", "key": "app:editor", "label": "Editor"}}
            store.update_sessions(observed, at="2026-08-12T23:55:00+02:00")
            store.update_sessions({}, at="2026-08-13T00:05:00+02:00")
            session = store.sessions_for_period(date(2026, 8, 13), date(2026, 8, 13))[0]
            self.assertEqual(session["started_at"], "2026-08-12T23:55:00+02:00")
            self.assertEqual(session["ended_at"], "2026-08-13T00:05:00+02:00")

            store.update_sessions(observed, at="2026-08-13T12:00:00+02:00")
            store.update_sessions({}, at="2026-08-13T11:00:00+02:00")
            self.assertEqual(store.data["sessions"][-1]["ended_at"], "2026-08-13T12:00:00+02:00")

    def test_program_already_open_is_marked_without_inventing_an_earlier_time(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            observed = {
                "program:editor.exe": {
                    "kind": "program",
                    "key": "app:editor",
                    "label": "Editor",
                    "started_before_tracking": True,
                    "source": "windows",
                }
            }
            store.update_sessions(observed, at="2026-08-13T09:00:00+02:00")
            session = store.data["open_sessions"]["program:editor.exe"]
            self.assertEqual(session["started_at"], "2026-08-13T09:00:00+02:00")
            self.assertTrue(session["started_before_tracking"])
            self.assertEqual(session["source"], "windows")

    def test_foreground_activity_is_a_separate_interval_from_open_state(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            opened = {"web:site:example.com": {
                "kind": "web", "key": "site:example.com", "label": "example.com"
            }}
            active = {**opened, "active:site:example.com": {
                "kind": "active", "key": "site:example.com", "label": "example.com"
            }}
            store.update_sessions(opened, at="2026-08-13T09:00:00+02:00")
            store.update_sessions(active, at="2026-08-13T09:01:00+02:00")
            store.update_sessions(opened, at="2026-08-13T09:02:00+02:00")

            self.assertIn("web:site:example.com", store.data["open_sessions"])
            self.assertNotIn("active:site:example.com", store.data["open_sessions"])
            activity = [item for item in store.data["sessions"] if item["kind"] == "active"]
            self.assertEqual(activity[0]["started_at"], "2026-08-13T09:01:00+02:00")
            self.assertEqual(activity[0]["ended_at"], "2026-08-13T09:02:00+02:00")

    def test_distinct_windows_sessions_are_persisted_without_restart_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            first = "2026-08-13T07:27:29+02:00"
            second = "2026-08-14T08:10:00+02:00"
            store.record_windows_session(first)
            store.record_windows_session(first)
            store.record_windows_session(second)

            sessions = store.windows_sessions()
            self.assertEqual(len(sessions), 2)
            self.assertEqual(sessions[0]["started_at"], second)
            self.assertIsNone(sessions[0]["ended_at"])
            self.assertEqual(sessions[1]["ended_at"], first)

    def test_windows_session_ends_at_its_last_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            first = "2026-08-13T07:27:29+02:00"
            last_seen = "2026-08-13T18:42:10+02:00"
            second = "2026-08-14T08:10:00+02:00"
            store.record_windows_session(first)
            store.update_sessions({}, at=last_seen)

            store.record_windows_session(second)

            sessions = store.windows_sessions()
            self.assertEqual(sessions[1]["ended_at"], last_seen)
            self.assertNotEqual(sessions[1]["ended_at"], second)

    def test_new_windows_session_closes_stale_apps_at_last_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            first = "2026-08-13T07:27:29+02:00"
            second = "2026-08-14T08:10:00+02:00"
            observed = {
                "program:editor.exe": {
                    "kind": "program", "key": "app:editor", "label": "Editor",
                }
            }
            store.record_windows_session(first)
            store.update_sessions(observed, at="2026-08-13T07:28:00+02:00")

            store.record_windows_session(second)

            self.assertEqual(store.data["open_sessions"], {})
            app_session = store.data["sessions"][-1]
            self.assertEqual(app_session["started_at"], "2026-08-13T07:28:00+02:00")
            self.assertEqual(app_session["ended_at"], "2026-08-13T07:28:00+02:00")

    def test_legacy_windows_boundary_is_repaired_from_last_active_session(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            first = "2026-08-13T07:27:29+02:00"
            last_active = "2026-08-13T18:42:10+02:00"
            second = "2026-08-14T08:10:00+02:00"
            data = AppUsageStore._empty_data()
            data["windows_sessions"] = [
                {"started_at": second, "ended_at": None},
                {"started_at": first, "ended_at": second},
            ]
            data["sessions"] = [{
                "id": "active:test", "kind": "active", "key": "app:test",
                "label": "Test", "started_at": "2026-08-13T18:40:00+02:00",
                "ended_at": last_active,
            }]
            path.write_text(json.dumps(data), encoding="utf-8")

            store = AppUsageStore(path)

            self.assertEqual(store.windows_sessions()[1]["ended_at"], last_active)

    def test_daily_totals_before_timeline_are_synthesized_as_estimated_sessions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            data = AppUsageStore._empty_data()
            data["days"] = {"2026-08-03": {"app:editor": 3600.0}}
            data["passive_days"] = {"2026-08-03": {"Radio": 900.0}}
            data["targets"] = {"app:editor": {"label": "Editor"}}
            data["sessions"] = [{
                "id": "active:new", "kind": "active", "key": "app:new",
                "label": "New", "started_at": "2026-08-13T09:00:00+02:00",
                "ended_at": "2026-08-13T09:01:00+02:00",
            }]
            path.write_text(json.dumps(data), encoding="utf-8")

            store = AppUsageStore(path)

            legacy_windows = [
                item for item in store.windows_sessions() if item.get("estimated")
            ]
            legacy_activity = [
                item for item in store.data["sessions"]
                if item.get("source") == "legacy-daily-total"
            ]
            self.assertEqual(len(legacy_windows), 1)
            self.assertEqual(legacy_windows[0]["started_at"][:10], "2026-08-03")
            self.assertEqual(
                {(item["kind"], item["label"]) for item in legacy_activity},
                {("program", "Editor"), ("active", "Editor"), ("multimedia", "Radio")},
            )
            self.assertTrue(all(item["estimated"] for item in legacy_activity))

            reloaded = AppUsageStore(path)
            self.assertEqual(
                len([item for item in reloaded.windows_sessions() if item.get("estimated")]),
                1,
            )
            self.assertEqual(
                len([
                    item for item in reloaded.data["sessions"]
                    if item.get("source") == "legacy-daily-total"
                ]),
                3,
            )


if __name__ == "__main__":
    unittest.main()
