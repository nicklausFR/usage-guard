import json
import sqlite3
import sys
import tempfile
import threading
import unittest
from datetime import date, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from usage_guard import AppUsageStore, _local_site_category, _site_host
from activity import ActiveContext
from app_limiter import AppLimiter


class AppUsageStoreBackupTest(unittest.TestCase):
    def test_validated_sqlite_migration_keeps_legacy_json_immutable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            original = json.dumps({
                "version": 2,
                "days": {"2026-08-01": {"app:legacy": 42.0}},
                "targets": {"app:legacy": {"label": "Legacy"}},
            }, ensure_ascii=False, indent=2).encode("utf-8")
            path.write_bytes(original)

            store = AppUsageStore(path)
            store.add_seconds(
                type("Target", (), {
                    "key": "app:new", "label": "New",
                    "category": "", "detail_host": "",
                })(),
                15, when=date(2026, 8, 30),
            )
            store.save()

            self.assertEqual(path.read_bytes(), original)
            self.assertTrue(store.activity_database_path.exists())
            reloaded = AppUsageStore(path)
            self.assertEqual(
                reloaded.data["days"]["2026-08-01"]["app:legacy"], 42.0,
            )
            self.assertEqual(
                reloaded.data["days"]["2026-08-30"]["app:new"], 15.0,
            )

    def test_failed_sqlite_validation_never_modifies_the_legacy_source(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            original = b'{"version":2,"days":{"2026-08-01":{"app:x":1}}}'
            path.write_bytes(original)

            with patch(
                "local_activity_sqlite.LocalActivitySqlite.import_legacy",
                side_effect=RuntimeError("validation failed"),
            ), self.assertRaisesRegex(RuntimeError, "validation failed"):
                AppUsageStore(path)

            self.assertEqual(path.read_bytes(), original)

    def test_current_day_save_never_serializes_older_history(self):
        class HistoryMustNotBeRead(dict):
            def items(self):
                raise AssertionError("historical day was serialized")

            def __iter__(self):
                raise AssertionError("historical day was iterated")

        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            # Inject a sentinel after the validated migration. A current-day
            # row update must not inspect or copy this unrelated old payload.
            store.data["days"]["1900-01-01"] = HistoryMustNotBeRead({
                "app:archive": 500_000_000,
            })
            store.add_seconds(
                type("Target", (), {
                    "key": "app:today", "label": "Today",
                    "category": "", "detail_host": "",
                })(),
                3, when=date(2026, 8, 30),
            )

            store.save()

            self.assertEqual(
                AppUsageStore(store.path).data["days"]["2026-08-30"][
                    "app:today"
                ],
                3.0,
            )

    def test_daily_aggregate_export_is_bounded_and_ack_is_revision_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            target = type("Target", (), {
                "key": "app:kona", "label": "Kona",
                "category": "Jeux", "detail_host": "",
            })()
            store.add_seconds(target, 60, when=date(2026, 8, 29))
            store.save()
            first = store._activity_sqlite.pending_daily_aggregates()

            self.assertEqual(len(first), 1)
            self.assertEqual(first[0]["local_day"], "2026-08-29")
            self.assertEqual(first[0]["metrics"], [{
                "kind": "usage", "key": "app:kona", "seconds": 60.0,
            }])
            self.assertNotIn("sessions", first[0])
            old_id = first[0]["aggregate_id"]

            store.add_seconds(target, 30, when=date(2026, 8, 29))
            store.save()
            current = store._activity_sqlite.pending_daily_aggregates()
            self.assertNotEqual(current[0]["aggregate_id"], old_id)
            store._activity_sqlite.acknowledge_daily_aggregates([old_id])
            self.assertEqual(store._activity_sqlite.pending_daily_count(), 1)
            store._activity_sqlite.acknowledge_daily_aggregates([
                current[0]["aggregate_id"],
            ])
            self.assertEqual(store._activity_sqlite.pending_daily_count(), 0)

    def test_current_day_is_never_exported_and_yesterday_is_stable(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            target = type("Target", (), {
                "key": "app:kona", "label": "Kona",
                "category": "Jeux", "detail_host": "",
            })()
            today = date.today()
            yesterday = today - timedelta(days=1)

            store.add_seconds(target, 10, when=today)
            store.save()
            store.add_seconds(target, 20, when=today)
            store.save()
            self.assertEqual(
                store._activity_sqlite.pending_daily_aggregates(), [],
            )

            store.add_seconds(target, 60, when=yesterday)
            store.save()
            pending = store._activity_sqlite.pending_daily_aggregates()
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0]["local_day"], yesterday.isoformat())
            aggregate_id = pending[0]["aggregate_id"]
            store.add_seconds(target, 5, when=today)
            store.save()
            self.assertEqual(
                store._activity_sqlite.pending_daily_aggregates()[0][
                    "aggregate_id"
                ],
                aggregate_id,
            )

    def test_daily_aggregate_exports_other_site_detail_without_recounting_it(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            yesterday_date = date.today() - timedelta(days=1)
            target = type("Target", (), {
                "key": "site:brave.exe:other-sites", "label": "Autres sites",
                "category": "Navigation Internet", "detail_host": "amazon.fr",
            })()
            store.add_seconds(target, 55, when=yesterday_date)
            target.detail_host = "just4camper.fr"
            store.add_seconds(target, 35, when=yesterday_date)
            store.save()

            metrics = store._activity_sqlite.pending_daily_aggregates()[0][
                "metrics"
            ]
            self.assertEqual(metrics, [
                {
                    "kind": "other_site",
                    "key": "site:brave.exe:amazon.fr",
                    "seconds": 55.0,
                },
                {
                    "kind": "other_site",
                    "key": "site:brave.exe:just4camper.fr",
                    "seconds": 35.0,
                },
                {
                    "kind": "usage",
                    "key": "site:brave.exe:other-sites",
                    "seconds": 90.0,
                },
            ])

    def test_other_site_export_format_upgrade_requeues_all_closed_days(self):
        from local_activity_sqlite import LocalActivitySqlite

        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            yesterday_date = date.today() - timedelta(days=1)
            target = type("Target", (), {
                "key": "site:brave.exe:other-sites", "label": "Autres sites",
                "category": "Navigation Internet", "detail_host": "amazon.fr",
            })()
            store.add_seconds(target, 55, when=yesterday_date)
            store.save()
            aggregate = store._activity_sqlite.pending_daily_aggregates()[0]
            store._activity_sqlite.acknowledge_daily_aggregates([
                aggregate["aggregate_id"],
            ])
            db = sqlite3.connect(store.activity_database_path)
            try:
                payload = json.loads(db.execute(
                    "SELECT payload FROM daily_aggregate_export"
                ).fetchone()[0])
                payload["metrics"] = [
                    item for item in payload["metrics"]
                    if item["kind"] != "other_site"
                ]
                db.execute(
                    "UPDATE daily_aggregate_export SET payload=?,bridge_acked=1",
                    (json.dumps(payload, sort_keys=True, separators=(",", ":")),),
                )
                db.execute(
                    "UPDATE activity_meta SET value='1' "
                    "WHERE key='daily_export_format_version'"
                )
                db.commit()
            finally:
                db.close()

            upgraded = LocalActivitySqlite(store.activity_database_path)
            pending = upgraded.pending_daily_aggregates()

            self.assertEqual(len(pending), 1)
            self.assertIn({
                "kind": "other_site",
                "key": "site:brave.exe:amazon.fr", "seconds": 55.0,
            }, pending[0]["metrics"])

    def test_legacy_site_migration_keeps_each_domain_on_its_source_day(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["days"] = {
                "2026-08-01": {"site:brave.exe:amazon.fr": 10.0},
                "2026-08-02": {"site:brave.exe:bbc.com": 20.0},
            }
            store.data["targets"].update({
                "site:brave.exe:amazon.fr": {"label": "amazon.fr"},
                "site:brave.exe:bbc.com": {"label": "bbc.com"},
            })

            store._migrate_legacy_targets()

            self.assertEqual(
                store.data["other_site_days"]["brave.exe"]["2026-08-01"],
                {"amazon.fr": 10.0},
            )
            self.assertEqual(
                store.data["other_site_days"]["brave.exe"]["2026-08-02"],
                {"bbc.com": 20.0},
            )

    def test_owner_scoped_ack_upgrade_requeues_compact_summaries_once(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            store = AppUsageStore(path)
            target = type("Target", (), {
                "key": "app:kona", "label": "Kona",
                "category": "Jeux", "detail_host": "",
            })()
            yesterday = date.today() - timedelta(days=1)
            store.add_seconds(target, 60, when=yesterday)
            store.save()
            aggregate = store._activity_sqlite.pending_daily_aggregates()[0]
            store.acknowledge_backend_daily_aggregates([
                aggregate["aggregate_id"],
            ])
            self.assertEqual(
                store._activity_sqlite.pending_daily_count(), 0,
            )

            db = sqlite3.connect(store.activity_database_path)
            try:
                db.execute(
                    "UPDATE activity_meta SET value='1' WHERE "
                    "key='daily_export_owner_scope_version'"
                )
                db.commit()
            finally:
                db.close()

            restored = AppUsageStore(path)
            pending = restored.pending_backend_daily_aggregates()
            self.assertEqual(
                [item["aggregate_id"] for item in pending],
                [aggregate["aggregate_id"]],
            )
            restored.acknowledge_backend_daily_aggregates([
                aggregate["aggregate_id"],
            ])
            again = AppUsageStore(path)
            self.assertEqual(again.pending_backend_daily_aggregates(), [])

    def test_existing_activity_file_gets_bounded_metadata_backup_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            original = {
                "version": 2,
                "days": {"2026-08-12": {"app:test": 42}},
                "sessions": [{"archive": "x" * (3 * 1024 * 1024)}],
                "targets": {
                    "app:test": {"label": "Test", "category": "Travail"},
                },
                "category_order": ["Travail"],
                "app_limit_settings": {
                    "app:test": {"limit_seconds": 300},
                },
            }
            path.write_text(json.dumps(original), encoding="utf-8")

            AppUsageStore(path)

            backup = (
                path.parent / "backups"
                / f"activity-metadata-{date.today().isoformat()}.json"
            )
            self.assertTrue(backup.exists())
            self.assertLessEqual(backup.stat().st_size, 2 * 1024 * 1024)
            saved = json.loads(backup.read_text(encoding="utf-8"))
            self.assertEqual(saved["kind"], "usage-guard-metadata-backup")
            self.assertNotIn("days", saved["configuration"])
            self.assertNotIn("sessions", saved["configuration"])
            self.assertEqual(
                saved["configuration"]["targets"]["app:test"]["category"],
                "Travail",
            )
            self.assertEqual(
                saved["configuration"]["app_limit_settings"]["app:test"][
                    "limit_seconds"
                ],
                300,
            )

    def test_metadata_backups_are_rotated_to_seven_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            path.write_text(
                json.dumps({"version": 2, "days": {}}), encoding="utf-8",
            )
            backup_directory = path.parent / "backups"
            backup_directory.mkdir()
            for day in range(1, 10):
                (backup_directory / f"activity-metadata-2026-01-{day:02d}.json").write_text(
                    "{}", encoding="utf-8",
                )

            AppUsageStore(path)

            backups = list(backup_directory.glob("activity-metadata-*.json"))
            self.assertEqual(len(backups), 7)


class ClassificationCatalogTest(unittest.TestCase):
    def test_dismissed_program_waits_for_close_then_a_real_relaunch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            store = AppUsageStore(path)
            store.data["days"] = {"2026-08-28": {"app:test": 42}}
            store.data["targets"] = {
                "app:test": {"label": "Test", "category": "Travail"},
            }
            store.data["app_limit_settings"] = {
                "app:test": {"limit_seconds": 300},
            }
            store.update_sessions({"program:test": {
                "kind": "program", "key": "app:test", "label": "Test",
            }}, at="2026-08-28T10:00:00+02:00")

            store.dismiss_target("app:test")

            self.assertEqual(store.data["dismissed_targets"]["app:test"], "running")
            store.observe_program_inventory(["app:test"])
            self.assertTrue(store.is_target_dismissed("app:test"))
            store.observe_program_inventory([])
            self.assertEqual(
                store.data["dismissed_targets"]["app:test"], "awaiting_launch",
            )
            store.observe_program_inventory([])
            self.assertTrue(store.is_target_dismissed("app:test"))
            store.observe_program_inventory(["app:test"])

            self.assertFalse(store.is_target_dismissed("app:test"))
            self.assertEqual(store.data["days"]["2026-08-28"]["app:test"], 42)
            self.assertEqual(store.data["targets"]["app:test"]["category"], "Travail")
            self.assertEqual(
                store.data["app_limit_settings"]["app:test"]["limit_seconds"],
                300,
            )
            self.assertFalse(AppUsageStore(path).is_target_dismissed("app:test"))

    def test_dismissed_closed_program_waits_for_its_next_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.dismiss_target("app:future")

            self.assertEqual(
                store.data["dismissed_targets"]["app:future"],
                "awaiting_launch",
            )
            store.observe_program_inventory([])
            self.assertTrue(store.is_target_dismissed("app:future"))
            store.observe_program_inventory(["app:future"])
            self.assertFalse(store.is_target_dismissed("app:future"))

    def test_excluded_target_can_be_deleted_permanently(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            store = AppUsageStore(path)
            store.data["days"] = {"2026-08-28": {"app:test": 42}}
            store.data["targets"] = {"app:test": {"label": "Test"}}
            store.data["app_limit_settings"] = {
                "app:test": {"limit_seconds": 300},
            }
            store.data["app_limit_days"] = {
                "2026-08-28": {
                    "app:test": {"seconds": 42, "extension_used": True},
                },
            }
            store.data["app_limit_rolling"] = {
                "app:test": {"buckets": {"2026-08-28T10:00": 42}},
            }
            store.data["app_limit_rolling_migrated"] = ["app:test"]
            store.data["merged_targets"] = {
                "app:alias": "app:test", "app:test": "app:other",
            }
            store.data["sessions"] = [{
                "kind": "active", "key": "app:test", "label": "Test",
                "started_at": "2026-08-28T10:00:00+02:00",
                "ended_at": "2026-08-28T10:00:42+02:00",
            }]
            store.exclude("app:test")

            store.delete_target("app:test")

            self.assertNotIn("app:test", store.data["excluded"])
            self.assertNotIn("app:test", store.data["targets"])
            self.assertNotIn("app:test", store.data["days"]["2026-08-28"])
            self.assertEqual(store.data["sessions"], [])
            self.assertNotIn("app:test", store.data["app_limit_settings"])
            self.assertNotIn(
                "app:test", store.data["app_limit_days"]["2026-08-28"],
            )
            self.assertNotIn("app:test", store.data["app_limit_rolling"])
            self.assertNotIn(
                "app:test", store.data["app_limit_rolling_migrated"],
            )
            self.assertEqual(store.data["merged_targets"], {})

            reloaded = AppUsageStore(path)
            self.assertNotIn("app:test", reloaded.data["app_limit_settings"])
            self.assertNotIn("app:test", reloaded.data["app_limit_rolling"])
            self.assertNotIn(
                "app:test",
                reloaded.data["app_limit_days"]["2026-08-28"],
            )

    def test_permanent_delete_purges_uuid_rules_outbox_and_legacy_source(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            legacy = AppUsageStore._empty_data()
            legacy.update({
                "days": {
                    "2026-08-28": {"app:test": 42, "app:kept": 12},
                },
                "targets": {
                    "app:test": {"label": "Test"},
                    "app:kept": {"label": "Kept"},
                },
                "excluded": ["app:test"],
                "app_limit_settings": {
                    "app:test#first": {
                        "target_key": "app:test", "limit_seconds": 300,
                    },
                    "app:kept": {"limit_seconds": 600},
                },
                "app_limit_days": {"2026-08-28": {
                    "app:test#first": {"seconds": 42},
                    "app:test#offline": {"seconds": 21},
                    "app:kept": {"seconds": 12},
                }},
                "app_limit_rolling": {
                    "app:test#first": {"buckets": {}},
                    "app:test#offline": {"buckets": {}},
                    "app:kept": {"buckets": {}},
                },
                "app_limit_rolling_migrated": [
                    "app:test#first", "app:test#offline", "app:kept",
                ],
                "personal_policy_overlay": {
                    "active": True, "owner": "alice", "revision": 2,
                    "local_settings": {
                        "app:test#offline": {"target_key": "app:test"},
                        "app:kept": {"limit_seconds": 600},
                    },
                },
                "notification_rules": [{
                    "id": "deleted-warning",
                    "target_key": "app:test#first",
                }, {
                    "id": "kept-warning", "target_key": "app:kept",
                }],
                "sessions": [{
                    "kind": "active", "key": "app:test", "label": "Test",
                    "windows_sid": "S-1-5-21-1-2-3-1001",
                    "started_at": "2026-08-28T10:00:00+02:00",
                    "ended_at": "2026-08-28T10:00:42+02:00",
                }],
            })
            path.write_text(
                json.dumps(legacy, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            store = AppUsageStore(path)
            self.assertTrue(store._append_backend_activity_interval({
                "kind": "active", "id": "active:test", "key": "app:test",
                "label": "Test", "windows_sid": "S-1-5-21-1-2-3-1001",
                "started_at": "2026-08-28T10:00:00+02:00",
                "ended_at": "2026-08-28T10:00:42+02:00",
            }))
            self.assertTrue(store._append_backend_activity_interval({
                "kind": "active", "id": "active:kept", "key": "app:kept",
                "label": "Kept", "windows_sid": "S-1-5-21-1-2-3-1001",
                "started_at": "2026-08-28T11:00:00+02:00",
                "ended_at": "2026-08-28T11:00:12+02:00",
            }))

            removed = store.delete_target("app:test")

            self.assertEqual(
                removed, ["app:test#first", "app:test#offline"],
            )
            self.assertEqual(
                set(store.data["app_limit_settings"]), {"app:kept"},
            )
            self.assertEqual(
                set(store.data["app_limit_days"]["2026-08-28"]),
                {"app:kept"},
            )
            self.assertEqual(
                set(store.data["app_limit_rolling"]), {"app:kept"},
            )
            self.assertEqual(
                set(store.data["personal_policy_overlay"]["local_settings"]),
                {"app:kept"},
            )
            self.assertEqual(
                [rule["id"] for rule in store.data["notification_rules"]],
                ["kept-warning"],
            )
            pending = store.pending_backend_activity_intervals()
            self.assertEqual(
                [item["key"] for item in pending["intervals"]],
                ["app:kept"],
            )
            legacy_after = json.loads(path.read_text(encoding="utf-8"))
            self.assertNotIn(
                "app:test", legacy_after["days"]["2026-08-28"],
            )
            self.assertEqual(legacy_after["sessions"], [])
            self.assertNotIn(
                "app:test#first", legacy_after["app_limit_settings"],
            )
            reloaded = AppUsageStore(path)
            self.assertNotIn(
                "app:test", reloaded.data["days"]["2026-08-28"],
            )
            aggregates = reloaded.pending_backend_daily_aggregates()
            deleted_metrics = [
                metric for aggregate in aggregates
                for metric in aggregate["metrics"]
                if metric["key"] == "app:test"
            ]
            self.assertEqual(deleted_metrics, [])

    def test_delete_browser_site_uses_full_target_deletion_guarantee(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            key = "site:brave.exe:youtube.com"
            legacy = AppUsageStore._empty_data()
            legacy.update({
                "days": {"2026-08-28": {
                    "site:brave.exe:other-sites": 100,
                    key: 10,
                }},
                "other_site_days": {"brave.exe": {"2026-08-28": {
                    "youtube.com": 60, "example.com": 40,
                }}},
                "browser_specific_sites": {"brave.exe": ["youtube.com"]},
                "targets": {key: {"label": "YouTube"}},
                "excluded": [key], "excluded_sites": [key],
                "app_limit_settings": {
                    f"{key}#web": {
                        "target_key": key, "limit_seconds": 300,
                    },
                },
                "sessions": [{
                    "kind": "active", "key": key, "label": "YouTube",
                    "started_at": "2026-08-28T10:00:00+02:00",
                    "ended_at": "2026-08-28T10:01:00+02:00",
                }],
            })
            path.write_text(json.dumps(legacy), encoding="utf-8")
            store = AppUsageStore(path)

            removed = store.delete_browser_site(
                "BRAVE.EXE", "https://www.youtube.com/watch?v=1",
            )

            self.assertEqual(removed, [f"{key}#web"])
            self.assertNotIn(key, store.data["targets"])
            self.assertNotIn(key, store.data["excluded"])
            self.assertNotIn(key, store.data["excluded_sites"])
            self.assertEqual(store.data["sessions"], [])
            self.assertEqual(
                store.data["days"]["2026-08-28"],
                {"site:brave.exe:other-sites": 40},
            )
            self.assertEqual(
                store.data["other_site_days"]["brave.exe"]["2026-08-28"],
                {"example.com": 40},
            )
            legacy_after = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                legacy_after["days"]["2026-08-28"],
                {"site:brave.exe:other-sites": 40},
            )

    def test_replace_catalog_preserves_usage_limits_and_sessions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            store = AppUsageStore(path)
            store.data.update({
                "days": {"2026-08-28": {"app:old": 42}},
                "sessions": [{"kind": "active", "key": "app:old"}],
                "app_limit_settings": {"app:old": {"limit_seconds": 300}},
                "computer_block": {"mode": "schedule"},
                "notification_rules": [{"id": "notice"}],
                "targets": {"app:old": {"label": "Old"}},
                "category_order": ["Ancien"],
            })
            before = {
                key: json.loads(json.dumps(store.data[key]))
                for key in (
                    "days", "sessions", "app_limit_settings",
                    "computer_block", "notification_rules",
                )
            }
            replacement = AppUsageStore._empty_data()
            replacement = {
                key: replacement[key] for key in store.catalog_document()
            }
            replacement["targets"] = {
                "app:new": {"label": "New", "category": "Travail"},
            }
            replacement["category_order"] = ["Travail"]

            store.replace_catalog(replacement)
            replacement["targets"]["app:new"]["label"] = "Mutated later"

            self.assertEqual(store.catalog_document()["category_order"], ["Travail"])
            self.assertEqual(store.data["targets"]["app:new"]["label"], "New")
            self.assertNotIn("app:old", store.data["targets"])
            for key, value in before.items():
                self.assertEqual(store.data[key], value)
            reloaded = AppUsageStore(path)
            self.assertEqual(reloaded.data["days"], before["days"])
            self.assertEqual(reloaded.data["category_order"], ["Travail"])

    def test_manual_items_persist_without_creating_usage(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            store = AppUsageStore(path)

            store.add_catalog_item("category", "Travail")
            store.add_catalog_item(
                "application", r"C:\Tools\NeverRun.exe", label="Jamais lancée",
            )
            store.add_catalog_item("site", "https://example.fr/page")

            reloaded = AppUsageStore(path)
            entries = {entry.key: entry for entry in reloaded.presentation({})}
            self.assertIn("Travail", reloaded.top_level_categories())
            self.assertIn("app:neverrun", entries)
            self.assertIn("site:brave.exe:example.fr", entries)
            self.assertEqual(entries["app:neverrun"].seconds, 0)
            self.assertEqual(entries["site:brave.exe:example.fr"].seconds, 0)
            self.assertEqual(reloaded.data["days"], {})

            target = reloaded.target_for_context(ActiveContext(
                app_name="NeverRun.exe", window_title="NeverRun",
            ))
            self.assertEqual(target.key, "app:neverrun")
            self.assertEqual(target.label, "Jamais lancée")

            site = reloaded.target_for_context(ActiveContext(
                app_name="brave.exe", window_title="Example",
                url="https://example.fr/first-visit",
            ))
            self.assertEqual(site.key, "site:brave.exe:example.fr")

    def test_manual_empty_child_category_remains_in_the_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.add_catalog_item("category", "Parent")
            store.add_catalog_item("category", "Enfant", parent="Parent")

            self.assertIn("Enfant", store.categories())
            self.assertEqual(store.data["category_parents"]["Enfant"], "Parent")

    def test_browser_executable_cannot_be_added_as_a_regular_application(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            with self.assertRaisesRegex(ValueError, "navigateur"):
                store.add_catalog_item("application", "brave.exe")


class PersonalPolicyOverlayTest(unittest.TestCase):
    @staticmethod
    def limiter(store):
        limiter = AppLimiter.__new__(AppLimiter)
        limiter.usage = store
        limiter.policies = {}
        limiter.blocked = False
        limiter.target_key = ""
        limiter._personal_usage = {}
        limiter._personal_usage_baselines = {}
        limiter._reload_policies()
        return limiter

    def test_enforced_policy_preserves_and_restores_local_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            store = AppUsageStore(path)
            local = store.set_app_limit_settings("app:local", {
                "enabled": True, "limit_seconds": 600,
                "extension_seconds": 60, "warning_seconds": 30,
            })
            limiter = self.limiter(store)

            limiter.activate_personal_policy("alice", 4, [{
                "key": "app:server", "target_key": "app:server",
                "enabled": False, "limit_seconds": 300,
                "extension_seconds": 0, "warning_seconds": 30,
            }])

            self.assertEqual(set(limiter.policies), {"app:server"})
            self.assertFalse(limiter.policies["app:server"]["enabled"])
            self.assertEqual(
                limiter.policies["app:server"]["managed_by"], "backend",
            )
            reloaded = AppUsageStore(path)
            restored_limiter = self.limiter(reloaded)
            self.assertTrue(restored_limiter.deactivate_personal_policy())
            self.assertEqual(restored_limiter.policies, {"app:local": local})
            self.assertEqual(
                reloaded.data["personal_policy_overlay"], {},
            )

    def test_personal_usage_adds_only_activity_after_server_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            limiter = self.limiter(store)
            limiter.activate_personal_policy("alice", 2, [{
                "key": "app:test", "enabled": True,
                "limit_seconds": 300, "extension_seconds": 0,
                "warning_seconds": 30,
            }])
            store.add_app_limit_seconds("app:test", 20)
            limiter.set_personal_usage({
                "usage_guard_username": "alice", "policy_revision": 2,
                "measured_at": "2026-08-24T08:00:00+02:00",
                "totals": {"app:test": {"seconds": 100}},
            })
            store.add_app_limit_seconds("app:test", 5)

            self.assertEqual(
                limiter.current_status("app:test")["seconds"], 105,
            )


class AppUsageStoreSessionsTest(unittest.TestCase):
    def test_system_events_are_persisted_for_power_timeline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            store = AppUsageStore(path)
            store.record_system_event("sleep", at="2026-08-21T12:00:00+02:00")
            store.record_system_event("resume", at="2026-08-21T12:30:00+02:00")

            reloaded = AppUsageStore(path)

            self.assertEqual(
                [event["type"] for event in reloaded.system_events()],
                ["sleep", "resume"],
            )

    def test_generic_browser_activity_has_no_site_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")

            target = store.target_for_context(ActiveContext(
                app_name="brave.exe", window_title="Browser",
                url="", generic_web=True,
            ))

            self.assertEqual(target.key, "site:brave.exe:other-sites")
            self.assertEqual(target.label, "Autres sites")
            self.assertEqual(target.detail_host, "")

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

    def test_limit_extension_unit_is_persisted_with_its_seconds(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            store = AppUsageStore(path)
            saved = store.set_app_limit_settings("app:editor", {
                "limit_seconds": 7200,
                "extension_seconds": 3600,
                "extension_unit": "minutes",
                "warning_seconds": 300,
            })

            self.assertEqual(saved["extension_unit"], "minutes")
            self.assertEqual(
                AppUsageStore(path).app_limit_settings("app:editor")["extension_unit"],
                "minutes",
            )

    def test_limit_enforcement_action_defaults_to_block_and_persists_warning(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            store = AppUsageStore(path)

            self.assertEqual(
                store.set_app_limit_settings("app:block", {})["enforcement_action"],
                "block",
            )
            warned = store.set_app_limit_settings("app:warn", {
                "enforcement_action": "warn",
            })

            self.assertEqual(warned["enforcement_action"], "warn")
            self.assertEqual(
                AppUsageStore(path).app_limit_settings("app:warn")["enforcement_action"],
                "warn",
            )

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

    def test_notification_channels_and_recipient_are_persisted_per_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")

            email_rule = store.set_notification_rule({
                "kind": "pwa_login", "channels": ["email"],
                "email_recipient": "alice@example.test",
            })
            both_rule = store.set_notification_rule({
                "kind": "limit_change", "channels": ["windows", "email"],
                "email_recipient": "bob@example.test",
            })

            self.assertEqual(email_rule["channels"], ["email"])
            self.assertEqual(email_rule["email_recipient"], "alice@example.test")
            self.assertEqual(both_rule["channels"], ["windows", "email"])
            self.assertNotIn("custom_title", both_rule)
            self.assertNotIn("custom_message", both_rule)
            stored = store.activity_database_path.read_bytes()
            self.assertNotIn(b"alice@example.test", stored)
            self.assertNotIn(b"bob@example.test", stored)
            reloaded = AppUsageStore(Path(directory) / "activity.json")
            self.assertEqual(
                reloaded.notification_rules()[0]["email_recipient"],
                "alice@example.test",
            )
            with self.assertRaisesRegex(ValueError, "destinataire"):
                store.set_notification_rule({
                    "kind": "pwa_login", "channels": ["email"],
                })

    def test_pwa_login_role_scope_and_owner_are_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")

            rule = store.set_notification_rule({
                "kind": "pwa_login", "owner": "admin",
                "login_role_scope": "users",
            })

            self.assertEqual(rule["owner"], "admin")
            self.assertEqual(rule["login_role_scope"], "users")
            self.assertEqual(rule["subject_roles"], ["limited", "user"])
            self.assertEqual(
                AppUsageStore(Path(directory) / "activity.json")
                .notification_rules()[0]["login_role_scope"],
                "users",
            )
            with self.assertRaisesRegex(ValueError, "compte à surveiller"):
                store.set_notification_rule({
                    "kind": "pwa_login", "login_role_scope": "unknown",
                })

            exact = store.set_notification_rule({
                "kind": "access_change",
                "subject_roles": ["admin", "limited"],
            })
            self.assertEqual(exact["subject_roles"], ["limited", "admin"])
            with self.assertRaisesRegex(ValueError, "rôle concerné"):
                store.set_notification_rule({
                    "kind": "access_change", "subject_roles": [],
                })

    def test_requested_notification_kinds_are_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["app_limit_settings"] = {
                "app:editor": {
                    "enabled": True, "limit_seconds": 3600,
                    "extension_seconds": 900, "extension_unit": "minutes",
                    "warning_seconds": 300,
                }
            }
            self.assertEqual(
                store.app_limit_settings("app:editor")["extension_unit"],
                "minutes",
            )
            for kind in (
                "limited_app_start", "limit_warning", "limit_reached",
                "limit_extension", "computer_state",
                "usage_threshold",
            ):
                rule = store.set_notification_rule({
                    "kind": kind, "target_key": "app:editor",
                    "warning_seconds": 420,
                })
                self.assertEqual(rule["kind"], kind)
            login = store.set_notification_rule({"kind": "pwa_login"})
            access_change = store.set_notification_rule({"kind": "access_change"})
            change = store.set_notification_rule({"kind": "limit_change"})
            computer_warning = store.set_notification_rule({
                "kind": "computer_block_warning", "warning_seconds": 900,
            })
            computer_change = store.set_notification_rule({
                "kind": "computer_block_change",
            })
            protection = store.set_notification_rule({
                "kind": "protection_interrupted",
            })
            reached = store.set_notification_rule({"kind": "limit_reached"})
            computer_state = store.set_notification_rule({"kind": "computer_state"})
            self.assertEqual(login["label"], "Connexion à la PWA")
            self.assertEqual(
                access_change["label"],
                "Changement de droits d’un utilisateur",
            )
            self.assertIn("Ajout", change["label"])
            self.assertEqual(reached["label"], "Limite atteinte")
            self.assertEqual(
                computer_state["label"], "Ordinateur allumé, éteint ou en veille"
            )
            self.assertEqual(computer_warning["warning_seconds"], 900)
            self.assertEqual(computer_warning["kind"], "limit_warning")
            self.assertEqual(computer_change["kind"], "limit_change")
            self.assertEqual(
                computer_change["label"],
                "Ajout, modification ou suppression d’une limite",
            )
            self.assertEqual(
                protection["label"], "Interruption de la protection"
            )

    def test_legacy_computer_limit_notifications_merge_on_load(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            store = AppUsageStore(path)
            store.data["notification_rules"] = [{
                "id": "shared", "kind": "limit_change", "owner": "nicklaus",
                "channels": ["email"],
                "email_recipient": "owner@example.test",
            }, {
                "id": "legacy-change", "kind": "computer_block_change",
                "owner": "nicklaus", "channels": ["windows"],
            }, {
                "id": "legacy-warning", "kind": "computer_block_warning",
                "owner": "nicklaus", "channels": ["windows"],
            }]
            store.save(force=True)

            rules = AppUsageStore(path).notification_rules()

            self.assertEqual(
                [rule["kind"] for rule in rules],
                ["limit_change", "limit_warning"],
            )
            self.assertEqual(rules[0]["id"], "shared")
            self.assertEqual(rules[0]["channels"], ["windows", "email"])

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
            retained = store.set_app_limit_settings("app:retained", {
                "enabled": True, "limit_seconds": 600,
                "extension_seconds": 60, "warning_seconds": 60,
                "valid_until": "2026-08-15", "valid_until_time": "10:00",
                "delete_after_expiry": False,
            })
            retained = store.app_limit_settings("app:retained")
            limiter = AppLimiter.__new__(AppLimiter)
            limiter.usage = store
            limiter.policies = {
                "app:expired": expired, "app:disabled": disabled,
                "app:retained": retained,
            }
            limiter.blocked = False

            removed = limiter.prune_expired_limits(
                datetime.fromisoformat("2026-08-15T10:00:00+02:00")
            )

            self.assertEqual(removed, ["app:expired"])
            self.assertNotIn("app:expired", limiter.policies)
            self.assertIn("app:disabled", limiter.policies)
            self.assertIn("app:retained", limiter.policies)
            self.assertIn("app:disabled", store.data["app_limit_settings"])
            self.assertIn("app:retained", store.data["app_limit_settings"])

    def test_duplicate_category_limit_rules_match_the_same_activity(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["targets"]["app:game"] = {
                "label": "Jeu", "category": "Jeux",
            }
            first = store.set_app_limit_settings("category:Jeux", {
                "target_key": "category:Jeux",
                "limit_seconds": 3600,
                "extension_seconds": 900,
                "warning_seconds": 300,
            })
            second = store.set_app_limit_settings("category:Jeux#abc12345", {
                "target_key": "category:Jeux",
                "limit_seconds": 600,
                "extension_seconds": 0,
                "warning_seconds": 60,
            })
            limiter = AppLimiter.__new__(AppLimiter)
            limiter.usage = store
            limiter.policies = {
                "category:Jeux": first,
                "category:Jeux#abc12345": second,
            }

            self.assertEqual(
                limiter._policies_for_key("app:game"),
                ["category:Jeux", "category:Jeux#abc12345"],
            )

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
            self.assertEqual(settings["managed_by"], "local")
            remote = store.set_app_limit_settings("app:remote", {
                "limit_seconds": 60, "managed_by": "backend",
            })
            self.assertEqual(remote["managed_by"], "backend")
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

    def test_period_block_keeps_an_optional_daily_schedule(self):
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
            self.assertEqual(settings["schedule_start"], "09:00")
            self.assertEqual(settings["schedule_end"], "17:00")
            self.assertTrue(store.app_limit_settings("app:test")["block_during_validity"])

            schedule_only = store.set_app_limit_settings("app:test", {
                "block_during_validity": True,
                "schedule_start": "08:00", "schedule_end": "09:00",
            })
            self.assertTrue(schedule_only["block_during_validity"])
            self.assertEqual(schedule_only["schedule_start"], "08:00")

            with self.assertRaisesRegex(ValueError, "borne datée ou un créneau horaire"):
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

            rolling = store.set_computer_block("24h", managed_by="backend")
            start = datetime.fromisoformat(rolling["started_at"])
            end = datetime.fromisoformat(rolling["ends_at"])
            self.assertAlmostEqual((end - start).total_seconds(), 86400, delta=1)
            disabled = store.set_computer_block_enabled(
                False, block_id=rolling["block_id"], managed_by="local",
            )
            self.assertFalse(disabled["enabled"])
            self.assertEqual(disabled["started_at"], rolling["started_at"])
            self.assertEqual(disabled["managed_by"], "local")
            enabled = store.set_computer_block_enabled(
                True, block_id=rolling["block_id"],
            )
            self.assertTrue(enabled["enabled"])
            store.clear_computer_block(rolling["block_id"])
            store.clear_computer_block(today["block_id"])
            self.assertEqual(store.data["computer_block"], {})

    def test_legacy_computer_block_migrates_once_with_stable_id(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            path.write_text(json.dumps({
                "version": 2,
                "days": {},
                "computer_block": {
                    "enabled": True,
                    "mode": "schedule",
                    "name": "Nuit",
                    "daily_start": "22:30",
                    "daily_end": "05:00",
                },
            }), encoding="utf-8")

            migrated = AppUsageStore(path)
            self.assertEqual(len(migrated.computer_blocks()), 1)
            first = migrated.computer_blocks()[0]
            self.assertTrue(first["block_id"])
            self.assertEqual(first["name"], "Nuit")
            self.assertEqual(migrated.data["computer_block"], first)

            reloaded = AppUsageStore(path)
            self.assertEqual(reloaded.computer_blocks(), [first])
            self.assertEqual(reloaded.data["computer_block"], first)

    def test_computer_blocks_coexist_and_return_independent_copies(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            now = datetime.fromisoformat("2026-08-28T12:00:00+02:00")
            first = store.set_computer_block(
                "schedule", name="Pause", start_time="19:30",
                end_time="19:32", now=now,
            )
            second = store.set_computer_block(
                "schedule", name="Nuit", start_time="22:30",
                end_time="05:00", now=now,
            )

            self.assertNotEqual(first["block_id"], second["block_id"])
            self.assertEqual(
                [block["name"] for block in store.computer_blocks()],
                ["Pause", "Nuit"],
            )
            copies = store.computer_blocks()
            copies[0]["name"] = "modifié hors stockage"
            self.assertEqual(store.computer_block(first["block_id"])["name"], "Pause")

    def test_computer_block_edit_toggle_and_delete_target_exact_id(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            now = datetime.fromisoformat("2026-08-28T12:00:00+02:00")
            first = store.set_computer_block(
                "schedule", name="Nuit", start_time="22:30",
                end_time="05:00", now=now,
            )
            second = store.set_computer_block(
                "schedule", name="Pause", start_time="19:30",
                end_time="19:32", now=now,
            )

            edited = store.set_computer_block(
                "schedule", block_id=first["block_id"],
                start_time="23:00", end_time="06:00", now=now,
            )
            self.assertEqual(edited["block_id"], first["block_id"])
            self.assertEqual(edited["name"], "Nuit")
            self.assertEqual(edited["daily_start"], "23:00")
            self.assertEqual(store.computer_block(second["block_id"]), second)

            disabled = store.set_computer_block_enabled(
                False, block_id=first["block_id"], managed_by="backend",
            )
            self.assertFalse(disabled["enabled"])
            self.assertEqual(disabled["name"], "Nuit")
            self.assertTrue(store.computer_block(second["block_id"])["enabled"])

            removed = store.clear_computer_block(first["block_id"])
            self.assertEqual(removed["block_id"], first["block_id"])
            self.assertEqual(store.computer_blocks(), [second])
            self.assertEqual(store.data["computer_block"], second)
            store.set_effective_computer_block({"block": second})
            self.assertEqual(store.data["computer_block"], second)

    def test_computer_warning_action_is_persisted_and_preserved_on_edit(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            now = datetime.fromisoformat("2026-08-28T12:00:00+02:00")
            created = store.set_computer_block(
                "schedule", start_time="22:00", end_time="23:00",
                enforcement_action="warn", now=now,
            )

            self.assertEqual(created["enforcement_action"], "warn")
            edited = store.set_computer_block(
                "schedule", block_id=created["block_id"],
                start_time="22:30", end_time="23:30", now=now,
            )
            self.assertEqual(edited["enforcement_action"], "warn")

    def test_computer_block_commands_without_id_reject_ambiguity(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            first = store.set_computer_block("today", name="Aujourd’hui")
            second = store.set_computer_block("24h", name="24 heures")

            for operation in (
                store.computer_block,
                lambda: store.set_computer_block_enabled(False),
                store.clear_computer_block,
            ):
                with self.assertRaisesRegex(ValueError, "block_id est requis"):
                    operation()
            third = store.set_computer_block("today", name="Nouvelle")
            self.assertEqual(len(store.computer_blocks()), 3)
            self.assertEqual(store.computer_block(first["block_id"])["name"], "Aujourd’hui")
            self.assertEqual(store.computer_block(second["block_id"])["name"], "24 heures")
            self.assertEqual(store.computer_block(third["block_id"])["name"], "Nouvelle")

    def test_replace_computer_blocks_reconciles_backend_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            local = store.set_computer_block("today", name="Locale en attente")
            obsolete = store.set_computer_block(
                "today", name="Ancienne distante", managed_by="backend",
            )
            document = [{
                "block_id": "remote-night", "mode": "schedule",
                "enabled": True, "name": "Nuit",
                "start_time": "22:30", "end_time": "05:00",
                "valid_from": "", "valid_from_time": "",
                "valid_until": "", "valid_until_time": "",
            }, {
                "block_id": "remote-short", "mode": "schedule",
                "enabled": False, "name": "Pause",
                "start_time": "19:30", "end_time": "19:32",
            }]

            first = store.replace_computer_blocks(document)
            second = store.replace_computer_blocks(document)

            self.assertEqual(first, second)
            self.assertEqual(
                [item["block_id"] for item in second],
                ["remote-night", "remote-short", local["block_id"]],
            )
            self.assertNotIn(
                obsolete["block_id"],
                [item["block_id"] for item in second],
            )
            self.assertEqual(second[0]["daily_start"], "22:30")
            self.assertEqual(second[0]["daily_end"], "05:00")
            self.assertEqual(second[0]["managed_by"], "backend")
            self.assertFalse(second[1]["enabled"])
            self.assertEqual(second[2], local)
            self.assertEqual(second[2]["managed_by"], "local")
            self.assertEqual(store.data["computer_block"], {})

    def test_first_server_ack_keeps_second_nearby_local_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            now = datetime.fromisoformat("2026-08-28T18:00:00+02:00")
            first = store.set_computer_block(
                "schedule", name="Première locale",
                start_time="19:30", end_time="19:32", now=now,
            )
            second = store.set_computer_block(
                "schedule", name="Deuxième locale",
                start_time="22:30", end_time="05:00", now=now,
            )

            reconciled = store.replace_computer_blocks([{
                "block_id": first["block_id"],
                "mode": "schedule", "enabled": False,
                "name": "Première confirmée",
                "start_time": "19:30", "end_time": "19:32",
            }], now=now)

            self.assertEqual(
                [block["block_id"] for block in reconciled],
                [first["block_id"], second["block_id"]],
            )
            by_id = {block["block_id"]: block for block in reconciled}
            self.assertEqual(by_id[first["block_id"]]["managed_by"], "backend")
            self.assertEqual(by_id[first["block_id"]]["name"], "Première confirmée")
            self.assertFalse(by_id[first["block_id"]]["enabled"])
            self.assertEqual(by_id[second["block_id"]], second)
            self.assertEqual(by_id[second["block_id"]]["managed_by"], "local")

    def test_duplicate_server_ids_are_rejected_without_touching_local_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            local = store.set_computer_block("today", name="Locale")
            before = store.computer_blocks()
            duplicate = {
                "block_id": local["block_id"], "mode": "schedule",
                "start_time": "19:30", "end_time": "19:32",
            }

            with self.assertRaisesRegex(ValueError, "dupliqué"):
                store.replace_computer_blocks([duplicate, dict(duplicate)])

            self.assertEqual(store.computer_blocks(), before)
            self.assertEqual(
                store.computer_block(local["block_id"])["managed_by"],
                "local",
            )

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

    def test_existing_limit_reconciles_today_after_a_new_day_starts(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["days"] = {"2026-08-16": {"app:editor": 1800.0}}
            store.data["app_limit_rolling"]["app:editor"] = {
                "buckets": {},
                "extension_granted_at": None,
                "usage_seeded_at": "2026-08-15T12:00:00+02:00",
                "usage_seed_version": 4,
            }
            now = datetime.fromisoformat("2026-08-16T09:00:00+02:00")

            store.prepare_app_limit("app:editor", 3600, 900, now)

            self.assertEqual(
                store.app_limit_state_for_day("app:editor", now)["seconds"],
                1800,
            )
            self.assertEqual(
                store.data["app_limit_rolling"]["app:editor"]["usage_seeded_at"],
                "2026-08-16T09:00:00+02:00",
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
                ["Divertissement"],
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

    def test_targets_can_be_reordered_without_changing_their_category(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["targets"] = {
                "app:alpha": {"label": "Alpha", "category": "Travail"},
                "app:beta": {"label": "Beta", "category": "Travail"},
                "app:gamma": {"label": "Gamma", "category": "Travail"},
                "app:game": {"label": "Game", "category": "Loisirs"},
            }

            store.reorder_target(
                "app:gamma", "app:alpha", before=True,
                displayed_siblings=["app:alpha", "app:beta", "app:gamma"],
            )

            self.assertEqual(
                store.data["target_order"],
                ["app:gamma", "app:alpha", "app:beta"],
            )
            self.assertEqual(
                store.data["targets"]["app:gamma"]["category"], "Travail",
            )
            self.assertEqual(
                AppUsageStore(store.path).data["target_order"],
                ["app:gamma", "app:alpha", "app:beta"],
            )
            with self.assertRaisesRegex(ValueError, "même catégorie"):
                store.reorder_target("app:gamma", "app:game")

    def test_navigation_can_be_reordered_without_moving_sites(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["category_parents"] = {
                "Travail": "", "Loisirs": "",
            }
            store.data["category_order"] = ["Travail", "Loisirs"]
            store.data["targets"]["site:brave.exe:example.test"] = {
                "label": "example.test", "site_category": "Actualité",
            }

            store.reorder_navigation("Travail", before=False)

            self.assertEqual(store.data["navigation_position"], {
                "destination": "Travail", "before": False,
            })
            self.assertEqual(
                store.data["targets"]["site:brave.exe:example.test"]
                ["site_category"],
                "Actualité",
            )
            self.assertEqual(
                AppUsageStore(store.path).data["navigation_position"],
                {"destination": "Travail", "before": False},
            )
            store.reorder_unclassified("Loisirs", before=True)
            self.assertEqual(store.data["unclassified_position"], {
                "destination": "Loisirs", "before": True,
            })
            with self.assertRaisesRegex(ValueError, "introuvable"):
                store.reorder_navigation("Inconnue")

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
            self.assertEqual(target.category, "__root__")

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

            store.set_category(key, "")

            metadata = store.data["targets"][key]
            self.assertEqual(metadata["category"], "__root__")
            self.assertNotIn("category_scope", metadata)

    def test_legacy_site_is_removed_from_unclassified_applications(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            key = "site:brave.exe:example.test"
            store.data["browser_categories"]["brave.exe"] = "__root__"
            store.data["targets"][key] = {
                "label": "example.test",
                "category": "Applications non classées",
                "category_scope": "site",
            }

            store._migrate_legacy_targets()

            metadata = store.data["targets"][key]
            self.assertEqual(metadata["category"], "__root__")
            self.assertNotIn("category_scope", metadata)
            self.assertNotIn("Applications non classées", store.top_level_categories())

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

    def test_open_session_started_before_midnight_remains_in_today_period(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.update_sessions({
                "program:app:editor": {
                    "kind": "program", "key": "app:editor", "label": "Editor",
                },
            }, at="2026-08-24T23:55:00+02:00")

            sessions = store.sessions_for_period(
                date(2026, 8, 25), date(2026, 8, 25)
            )

            self.assertEqual(len(sessions), 1)
            self.assertEqual(sessions[0]["started_at"], "2026-08-24T23:55:00+02:00")
            self.assertIsNone(sessions[0]["ended_at"])

    def test_windows_day_returns_the_complete_cross_midnight_session(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["windows_sessions"] = [{
                "started_at": "2026-08-28T07:11:08+02:00",
                "ended_at": "2026-08-29T01:33:35+02:00",
            }]
            kona_before_midnight = {
                "kind": "active", "key": "app:kona", "label": "Kona",
                "started_at": "2026-08-28T22:09:55+02:00",
                "ended_at": "2026-08-28T22:35:46+02:00",
            }
            kona_after_midnight = {
                "kind": "active", "key": "app:kona", "label": "Kona",
                "started_at": "2026-08-29T00:05:00+02:00",
                "ended_at": "2026-08-29T00:15:00+02:00",
            }
            store.data["sessions"] = [
                kona_before_midnight, kona_after_midnight,
            ]

            sessions_before = store.sessions_for_windows_day(
                date(2026, 8, 28),
                now=datetime.fromisoformat("2026-08-29T08:00:00+02:00"),
            )
            sessions_after = store.sessions_for_windows_day(
                date(2026, 8, 29),
                now=datetime.fromisoformat("2026-08-29T08:00:00+02:00"),
            )

            expected = [kona_after_midnight, kona_before_midnight]
            self.assertEqual(sessions_before, expected)
            self.assertEqual(sessions_after, expected)

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

    def test_verified_power_boundary_closes_current_logical_session(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.record_windows_session(
                "2026-08-25T21:51:42+02:00",
                observed_at="2026-08-26T08:00:00+02:00",
            )

            store.close_windows_session(
                "2026-08-25T23:26:23+02:00", reason="sleep",
            )
            store.record_windows_session(
                "2026-08-26T07:01:37+02:00",
                source="extended-modern-standby",
            )

            sessions = store.windows_sessions()
            self.assertEqual(sessions[0]["source"], "extended-modern-standby")
            self.assertEqual(sessions[1]["ended_at"], "2026-08-25T23:26:23+02:00")
            self.assertEqual(sessions[1]["ended_reason"], "sleep")
            self.assertEqual(sessions[1]["last_observed_at"], "2026-08-25T23:26:23+02:00")

    def test_screen_timeout_repairs_adjacent_artificial_windows_sessions(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            identity = {
                "windows_sid": "S-1-5-21-1-2-3-1001",
                "windows_username": "alice",
            }
            store.record_windows_session(
                "2026-08-26T07:01:37+02:00", identity=identity,
            )
            store.close_windows_session(
                "2026-08-26T07:12:13+02:00", reason="sleep",
            )
            store.record_windows_session(
                "2026-08-26T07:20:10+02:00", identity=identity,
                source="extended-modern-standby",
            )

            merged = store.merge_windows_sessions_across_periods([(
                datetime.fromisoformat("2026-08-26T07:12:13+02:00"),
                datetime.fromisoformat("2026-08-26T07:20:10+02:00"),
            )])

            self.assertEqual(merged, 1)
            sessions = store.windows_sessions()
            self.assertEqual(len(sessions), 1)
            self.assertEqual(sessions[0]["started_at"], "2026-08-26T07:01:37+02:00")
            self.assertIsNone(sessions[0]["ended_at"])
            self.assertTrue(sessions[0]["screen_idle_repaired"])

    def test_windows_identity_is_stamped_on_session_and_activity_intervals(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            identity = {
                "session_id": 7,
                "windows_sid": "S-1-5-21-1-2-3-1001",
                "windows_domain": "PC",
                "windows_username": "Alice",
                "is_windows_admin": False,
                "usage_guard_username": "alice",
                "mapped": True,
                "mapping_status": "mapped",
            }
            store.record_windows_session(
                "2026-08-13T07:27:29+02:00", identity=identity
            )
            store.update_sessions({
                "program:editor.exe": {
                    "kind": "program", "key": "app:editor",
                    "label": "Editor",
                },
                "active:editor.exe": {
                    "kind": "active", "key": "app:editor",
                    "label": "Editor", "category": "Programmation",
                    "category_lineage": ["Programmation", "Travail"],
                    "policy_revision": 4,
                }
            }, at="2026-08-13T07:28:00+02:00")

            windows_session = store.windows_sessions()[0]
            activity = store.data["open_sessions"]["program:editor.exe"]
            for item in (windows_session, activity):
                self.assertEqual(item["usage_guard_username"], "alice")
                self.assertEqual(item["windows_sid"], identity["windows_sid"])
                self.assertTrue(item["windows_identity_mapped"])
                self.assertEqual(item["windows_session_id"], 7)
            foreground = store.data["open_sessions"]["active:editor.exe"]
            self.assertEqual(
                foreground["category_lineage"], ["Programmation", "Travail"]
            )
            self.assertEqual(foreground["policy_revision"], 4)

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


    def test_optional_limit_names_are_trimmed_persisted_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            store = AppUsageStore(path)

            limit = store.set_app_limit_settings("category:Jeux", {
                "name": "  Soir sans jeux  ",
                "target_key": "category:Jeux",
                "limit_seconds": 3600,
                "extension_seconds": 300,
                "warning_seconds": 300,
            })
            block = store.set_computer_block(
                "schedule", name="  Nuit  ", start_time="22:30",
                end_time="05:00",
                now=datetime(2026, 8, 28, 18, 0).astimezone(),
            )

            self.assertEqual(limit["name"], "Soir sans jeux")
            self.assertEqual(block["name"], "Nuit")
            reloaded = AppUsageStore(path)
            self.assertEqual(
                reloaded.app_limit_settings("category:Jeux")["name"],
                "Soir sans jeux",
            )
            self.assertEqual(reloaded.data["computer_block"]["name"], "Nuit")
            with self.assertRaisesRegex(ValueError, "120 caractères"):
                store.set_app_limit_settings("app:test", {
                    "name": "x" * 121, "limit_seconds": 60,
                })
            with self.assertRaisesRegex(ValueError, "120 caractères"):
                store.set_computer_block("today", name="x" * 121)

class BackendActivityOutboxTest(unittest.TestCase):
    @staticmethod
    def _session(key, minute):
        return {
            "windows_sid": "S-1-5-21-1-2-3-1001",
            "usage_guard_username": "nicklaus",
            "windows_identity_mapped": True,
            "id": f"active:{key}", "kind": "active", "key": key,
            "label": key,
            "started_at": f"2026-08-30T08:{minute:02d}:00+02:00",
            "ended_at": f"2026-08-30T08:{minute:02d}:30+02:00",
        }

    def test_recent_backfill_is_bounded_and_runs_only_once(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            recent = datetime.now().astimezone() - timedelta(hours=1)
            store.data["sessions"] = []
            for offset in (0, 2):
                session = self._session("app:morning", offset)
                opened = recent + timedelta(minutes=offset)
                session["started_at"] = opened.isoformat(timespec="seconds")
                session["ended_at"] = (
                    opened + timedelta(seconds=30)
                ).isoformat(timespec="seconds")
                store.data["sessions"].append(session)
            store.data["backend_activity_backfill_version"] = 0
            store.activity_outbox_path.unlink(missing_ok=True)

            self.assertTrue(store._ensure_recent_backend_activity_backfill())
            first = store.pending_backend_activity_intervals()["intervals"]
            self.assertEqual(len(first), 2)
            self.assertEqual(
                {item["key"] for item in first}, {"app:morning"},
            )
            size = store.activity_outbox_path.stat().st_size

            self.assertFalse(store._ensure_recent_backend_activity_backfill())
            self.assertEqual(store.activity_outbox_path.stat().st_size, size)

    def test_other_sites_aggregate_closure_is_usage_only_and_recent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            store = AppUsageStore(path)
            store._active_windows_identity = {
                "windows_sid": "S-1-5-21-1-2-3-1001",
                "usage_guard_username": "nicklaus",
                "windows_identity_mapped": True,
            }
            aggregate_key = "site:brave.exe:other-sites"
            neighboring_key = "site:brave.exe:other-sites-extra"
            store.update_sessions({
                "active:aggregate": {
                    "kind": "active", "key": aggregate_key,
                    "label": "Autres sites",
                },
                "active:neighbor": {
                    "kind": "active", "key": neighboring_key,
                    "label": "Other sites extra",
                },
            }, at="2026-09-03T08:00:00+02:00")

            store.update_sessions({}, at="2026-09-03T08:01:00+02:00")

            pending = store.pending_backend_activity_intervals()["intervals"]
            self.assertEqual(
                {item["key"] for item in pending},
                {aggregate_key, neighboring_key},
            )
            self.assertEqual(
                [item["key"] for item in store.data["sessions"]],
                [neighboring_key],
            )
            self.assertEqual(
                [item["key"] for item in store._recent_closed_sessions],
                [aggregate_key, neighboring_key],
            )
            store.save(force=True)
            self.assertEqual(
                [item["key"] for item in AppUsageStore(path).data["sessions"]],
                [neighboring_key],
            )

    def test_other_sites_closure_without_usage_interval_remains_archived(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            aggregate_key = "site:brave.exe:other-sites"
            store.update_sessions({
                "active:aggregate": {
                    "kind": "active", "key": aggregate_key,
                    "label": "Autres sites",
                },
            }, at="2026-09-03T08:00:00+02:00")

            store.update_sessions({}, at="2026-09-03T08:01:00+02:00")

            self.assertEqual(
                [item["key"] for item in store.data["sessions"]],
                [aggregate_key],
            )
            self.assertEqual(
                [item["key"] for item in store._recent_closed_sessions],
                [aggregate_key],
            )
            self.assertEqual(
                store.pending_backend_activity_intervals()["intervals"], [],
            )

    def test_other_sites_session_migration_preserves_usage_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.json"
            store = AppUsageStore(path)
            aggregate_key = "site:brave.exe:other-sites"
            neighboring_key = "site:brave.exe:other-sites-extra"
            opened = datetime.now().astimezone() - timedelta(days=1)
            closed = opened + timedelta(minutes=1)
            day = opened.date().isoformat()
            identity = {
                "windows_sid": "S-1-5-21-1-2-3-1001",
                "usage_guard_username": "nicklaus",
                "windows_identity_mapped": True,
            }
            common = {
                **identity, "kind": "active",
                "started_at": opened.isoformat(timespec="seconds"),
                "ended_at": closed.isoformat(timespec="seconds"),
            }
            store.data["days"] = {
                day: {aggregate_key: 60.0},
            }
            store.data["other_site_days"] = {
                "brave.exe": {day: {"example.org": 60.0}},
            }
            store.data["sessions"] = [
                {
                    **common, "id": "active:aggregate", "key": aggregate_key,
                    "label": "Autres sites",
                },
                {
                    **common, "id": "active:neighbor", "key": neighboring_key,
                    "label": "Other sites extra",
                },
            ]
            store.data["backend_activity_backfill_version"] = 0
            self.assertFalse(store._purge_synthetic_other_sites_sessions())
            self.assertEqual(len(store.data["sessions"]), 2)
            store._dirty = True
            store.save(force=True)
            aggregate_id = store._activity_sqlite.pending_daily_aggregates()[0][
                "aggregate_id"
            ]

            migrated = AppUsageStore(path)
            first_outbox = migrated.pending_backend_activity_intervals()[
                "intervals"
            ]
            self.assertEqual(
                [item["key"] for item in migrated.data["sessions"]],
                [neighboring_key],
            )
            self.assertEqual(
                migrated.data["days"],
                {day: {aggregate_key: 60.0}},
            )
            self.assertEqual(
                migrated.data["other_site_days"],
                {"brave.exe": {day: {"example.org": 60.0}}},
            )
            self.assertEqual(
                {item["key"] for item in first_outbox},
                {aggregate_key, neighboring_key},
            )
            self.assertEqual(
                migrated._activity_sqlite.pending_daily_aggregates()[0][
                    "aggregate_id"
                ],
                aggregate_id,
            )

            restarted = AppUsageStore(path)
            second_outbox = restarted.pending_backend_activity_intervals()[
                "intervals"
            ]
            self.assertEqual(restarted.data["sessions"], migrated.data["sessions"])
            self.assertEqual(
                [item["record_id"] for item in second_outbox],
                [item["record_id"] for item in first_outbox],
            )
            self.assertEqual(restarted.data["days"], migrated.data["days"])
            self.assertEqual(
                restarted.data["other_site_days"],
                migrated.data["other_site_days"],
            )

    def test_failed_compaction_replays_duplicates_instead_of_losing_tail(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            self.assertTrue(store._append_backend_activity_interval(
                self._session("app:first", 0),
            ))
            self.assertTrue(store._append_backend_activity_interval(
                self._session("app:second", 1),
            ))
            page = store.pending_backend_activity_intervals(max_items=1)
            original_replace = Path.replace

            def fail_outbox_replace(path, target):
                if Path(path) == store.activity_outbox_path.with_suffix(".tmp"):
                    raise PermissionError("simulated locked JSONL")
                return original_replace(path, target)

            with patch.object(Path, "replace", fail_outbox_replace):
                with self.assertRaisesRegex(PermissionError, "locked JSONL"):
                    store.acknowledge_backend_activity_intervals(page["cursor"])

            self.assertEqual(
                json.loads(store.activity_outbox_state_path.read_text(
                    encoding="utf-8",
                )),
                {"cursor": 0},
            )
            replay = store.pending_backend_activity_intervals()["intervals"]
            self.assertEqual(
                [item["key"] for item in replay],
                ["app:first", "app:second"],
            )

    def test_cursor_is_durably_zero_before_compacted_tail_is_published(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            self.assertTrue(store._append_backend_activity_interval(
                self._session("app:first", 0),
            ))
            self.assertTrue(store._append_backend_activity_interval(
                self._session("app:second", 1),
            ))
            page = store.pending_backend_activity_intervals(max_items=1)
            # Model a cursor written by a previous runtime where compaction
            # could fail independently from cursor advancement.
            store.activity_outbox_state_path.write_text(
                json.dumps({"cursor": page["cursor"]}), encoding="utf-8",
            )
            remaining = store.pending_backend_activity_intervals(max_items=1)
            original_replace = Path.replace
            observed = []

            def inspect_outbox_replace(path, target):
                if Path(path) == store.activity_outbox_path.with_suffix(".tmp"):
                    observed.append(json.loads(
                        store.activity_outbox_state_path.read_text(
                            encoding="utf-8",
                        )
                    )["cursor"])
                return original_replace(path, target)

            with patch.object(Path, "replace", inspect_outbox_replace):
                store.acknowledge_backend_activity_intervals(
                    remaining["cursor"],
                )

            self.assertEqual(observed, [0])
            self.assertEqual(
                store.pending_backend_activity_intervals()["intervals"], [],
            )

    def test_ack_compaction_cannot_drop_a_concurrent_append(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            identity = {
                "windows_sid": "S-1-5-21-1-2-3-1001",
                "usage_guard_username": "nicklaus",
                "windows_identity_mapped": True,
            }

            def session(key, minute):
                return {
                    **identity,
                    "id": f"active:{key}", "kind": "active", "key": key,
                    "label": key,
                    "started_at": f"2026-08-30T08:{minute:02d}:00+02:00",
                    "ended_at": f"2026-08-30T08:{minute:02d}:30+02:00",
                }

            first = session("app:first", 0)
            second = session("app:second", 1)
            self.assertTrue(store._append_backend_activity_interval(first))
            cursor = store.pending_backend_activity_intervals()["cursor"]

            replace_entered = threading.Event()
            allow_replace = threading.Event()
            append_finished = threading.Event()
            original_replace = Path.replace

            def delayed_replace(path, target):
                if Path(path) == store.activity_outbox_path.with_suffix(".tmp"):
                    replace_entered.set()
                    self.assertTrue(allow_replace.wait(2))
                return original_replace(path, target)

            acknowledger = threading.Thread(
                target=store.acknowledge_backend_activity_intervals,
                args=(cursor,),
            )
            appender = threading.Thread(target=lambda: (
                store._append_backend_activity_interval(second),
                append_finished.set(),
            ))
            with patch.object(Path, "replace", delayed_replace):
                acknowledger.start()
                self.assertTrue(replace_entered.wait(2))
                appender.start()
                self.assertFalse(append_finished.wait(0.1))
                allow_replace.set()
                acknowledger.join(2)
                appender.join(2)

            self.assertFalse(acknowledger.is_alive())
            self.assertFalse(appender.is_alive())
            self.assertTrue(append_finished.is_set())
            pending = store.pending_backend_activity_intervals()["intervals"]
            self.assertEqual([item["key"] for item in pending], ["app:second"])

    def test_windows_session_and_system_event_use_same_durable_timeline_outbox(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            identity = {
                "windows_sid": "S-1-5-21-1-2-3-1001",
                "usage_guard_username": "nicklaus",
                "windows_identity_mapped": True,
            }
            store._active_windows_identity = identity
            store.data["windows_sessions"] = [{
                **identity,
                "started_at": "2026-08-29T23:50:00+02:00",
                "ended_at": None,
            }]

            store.record_system_event(
                "shutdown", at="2026-08-30T00:20:00+02:00",
            )
            store.close_windows_session("2026-08-30T00:20:00+02:00")

            kinds = {
                item["kind"]
                for item in store.pending_backend_activity_intervals()["intervals"]
            }
            self.assertEqual(kinds, {"system_event", "windows_session"})

    def test_outbox_write_failure_keeps_session_open_for_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store._active_windows_identity = {
                "windows_sid": "S-1-5-21-1-2-3-1001",
                "windows_identity_mapped": True,
            }
            store.update_sessions({
                "active": {"kind": "active", "key": "app:kona"},
            }, at="2026-08-30T08:00:00+02:00")

            with patch.object(
                store, "_append_backend_activity_interval", return_value=False,
            ), self.assertRaisesRegex(OSError, "journaliser"):
                store.update_sessions({}, at="2026-08-30T08:01:00+02:00")

            self.assertIn("active", store.data["open_sessions"])
            self.assertFalse(any(
                item.get("key") == "app:kona"
                for item in store.data["sessions"]
            ))

    def test_only_new_closures_enter_bounded_outbox_without_serializing_archive(self):
        class ArchiveMustNotBeSerialized(dict):
            def __deepcopy__(self, _memo):
                raise AssertionError("500 MB archive was copied")

        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["days"] = ArchiveMustNotBeSerialized({
                "1900-01-01": {"app:legacy": 500_000_000},
            })
            store._active_windows_identity = {
                "windows_sid": "S-1-5-21-1-2-3-1001",
                "windows_identity_mapped": True,
                "windows_session_id": 7,
            }
            opened = "2026-08-29T23:55:00+02:00"
            closed = "2026-08-30T00:05:00+02:00"
            store.update_sessions({
                "active": {"kind": "active", "key": "app:kona", "label": "Kona"},
                "program": {"kind": "program", "key": "app:kona", "label": "Kona"},
                "web": {"kind": "web", "key": "site:brave:example", "label": "example"},
                "media": {"kind": "multimedia", "key": "passive:radio", "label": "Radio"},
            }, at=opened)
            store.update_sessions({}, at=closed)

            page = store.pending_backend_activity_intervals()

            self.assertEqual(len(page["intervals"]), 4)
            self.assertLessEqual(page["bytes"], 512 * 1024)
            self.assertEqual(
                {item["kind"] for item in page["intervals"]},
                {"active", "program", "web", "multimedia"},
            )
            active = next(
                item for item in page["intervals"] if item["kind"] == "active"
            )
            self.assertIn("interval_id", active)
            self.assertEqual(active["started_at"], opened)
            self.assertEqual(active["ended_at"], closed)
            self.assertTrue(all(
                "record_id" in item for item in page["intervals"]
            ))

    def test_cursor_ack_does_not_backfill_preexisting_history(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["sessions"] = [{
                "kind": "active", "key": "app:legacy",
                "started_at": "2020-01-01T00:00:00+01:00",
                "ended_at": "2020-01-01T00:01:00+01:00",
            }] * 100_000

            self.assertEqual(
                store.pending_backend_activity_intervals()["intervals"], [],
            )

            store._active_windows_identity = {
                "windows_sid": "S-1-5-21-1-2-3-1001",
                "windows_identity_mapped": True,
            }
            store.update_sessions({
                "active": {"kind": "active", "key": "app:new"},
            }, at="2026-08-30T08:00:00+02:00")
            store.update_sessions({}, at="2026-08-30T08:01:00+02:00")
            page = store.pending_backend_activity_intervals(max_items=1)
            store.acknowledge_backend_activity_intervals(page["cursor"])

            self.assertEqual(
                store.pending_backend_activity_intervals()["intervals"], [],
            )


if __name__ == "__main__":
    unittest.main()
