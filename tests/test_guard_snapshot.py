import sys
import tempfile
import unittest
from datetime import date, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from activity import ActiveContext, ActivityProbe, _host_url_from_title
from guard import MonitoringService
from usage_guard import AppUsageStore


class MonitoringServiceSnapshotTest(unittest.TestCase):
    def test_notification_rules_dispatch_independent_windows_and_email_channels(self):
        windows = []
        emails = []
        service = MonitoringService.__new__(MonitoringService)
        service.notification_requested = SimpleNamespace(
            emit=lambda *args: windows.append(args)
        )
        service.email_notification_requested = SimpleNamespace(
            emit=lambda *args: emails.append(args)
        )
        rules = [
            {"enabled": True, "channels": ["email"],
             "email_recipient": "mail-only@example.test"},
            {"enabled": True, "channels": ["windows", "email"],
             "email_recipient": "both@example.test"},
        ]

        service._dispatch_notification_rules(rules, "Titre", "Message", 42)

        self.assertEqual(windows, [("Titre", "Message", 42)])
        self.assertEqual({item[2] for item in emails}, {
            "mail-only@example.test", "both@example.test",
        })

    def test_global_limit_warning_can_be_created_without_a_specific_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            service = MonitoringService.__new__(MonitoringService)
            service.usage = AppUsageStore(Path(directory) / "activity.json")
            service.app_limiter = SimpleNamespace(policies={})

            result = service._apply_remote_command({
                "action": "set_notification_rule",
                "rule": {
                    "kind": "limit_warning", "warning_seconds": 900,
                    "enabled": True,
                },
            })

            self.assertTrue(result["ok"])
            self.assertEqual(result["rule"]["target_key"], "")
            self.assertEqual(result["rule"]["warning_seconds"], 900)

    def test_computer_block_notifications_name_the_actor(self):
        with tempfile.TemporaryDirectory() as directory:
            emitted = []
            service = MonitoringService.__new__(MonitoringService)
            service.usage = AppUsageStore(Path(directory) / "activity.json")
            service.usage.set_notification_rule({
                "kind": "computer_block_change", "enabled": True,
            })
            service.notification_requested = SimpleNamespace(
                emit=lambda *args: emitted.append(args)
            )
            service.app_limiter = SimpleNamespace(
                refresh_computer_block=lambda: None,
            )

            service._apply_remote_command({
                "action": "set_computer_block", "mode": "duration",
                "duration_seconds": 3600, "delay_seconds": 600,
                "actor": "alice",
            })
            service._apply_remote_command({
                "action": "clear_computer_block", "actor": "bob",
            })

            self.assertEqual(
                emitted[0][0],
                "Limitation planifiée par alice — Usage Guard",
            )
            self.assertIn("alice a planifié", emitted[0][1])
            self.assertEqual(
                emitted[1][0],
                "Limitation levée par bob — Usage Guard",
            )
            self.assertIn("bob a levé", emitted[1][1])

    def test_limit_toggle_notifies_with_actor_only_when_configured(self):
        emitted = []
        policies = {"app:test": {
            "enabled": True, "limit_seconds": 60,
            "extension_seconds": 15, "warning_seconds": 5,
        }}
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(data={"notification_rules": []})
        service.notification_requested = SimpleNamespace(
            emit=lambda *args: emitted.append(args)
        )

        def apply_settings(target_key, settings):
            policies[target_key] = dict(settings)
            return policies[target_key]

        service.app_limiter = SimpleNamespace(
            policies=policies,
            apply_settings=apply_settings,
            label_for_key=lambda _key: "Test",
        )

        service._apply_remote_command({
            "action": "set_limit", "target_key": "app:test",
            "settings": {**policies["app:test"], "enabled": False},
        })
        self.assertEqual(emitted, [])

        service.usage.data["notification_rules"].append({
            "kind": "limit_change", "enabled": True,
        })
        service._apply_remote_command({
            "action": "set_limit", "target_key": "app:test", "actor": "alice",
            "settings": {**policies["app:test"], "enabled": True},
        })
        service._apply_remote_command({
            "action": "set_limit", "target_key": "app:test",
            "settings": {**policies["app:test"], "enabled": False},
        })

        self.assertEqual(len(emitted), 2)
        self.assertEqual(emitted[0][0], "Limite activée par alice — Usage Guard")
        self.assertIn("alice a activé", emitted[0][1])
        self.assertTrue(emitted[1][0].startswith("Limite désactivée par Utilisateur local"))
        self.assertIn("Utilisateur local (", emitted[1][1])
        self.assertIn("a désactivé", emitted[1][1])

    def test_limit_create_update_and_delete_titles_show_the_remote_actor(self):
        emitted = []
        policies = {}
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(data={"notification_rules": [{
            "kind": "limit_change", "enabled": True, "target_key": "",
        }]})
        service.notification_requested = SimpleNamespace(
            emit=lambda *args: emitted.append(args)
        )

        def apply_settings(target_key, settings):
            policies[target_key] = dict(settings)
            return policies[target_key]

        service.app_limiter = SimpleNamespace(
            policies=policies,
            apply_settings=apply_settings,
            remove_limit=lambda target_key: policies.pop(target_key),
            label_for_key=lambda _key: "Test",
        )
        settings = {
            "enabled": True, "limit_seconds": 60,
            "extension_seconds": 15, "warning_seconds": 5,
        }

        service._apply_remote_command({
            "action": "set_limit", "target_key": "app:test",
            "settings": {**settings, "enabled": False}, "actor": "alice",
        })
        self.assertTrue(policies["app:test"]["enabled"])
        service._apply_remote_command({
            "action": "set_limit", "target_key": "app:test",
            "settings": {**settings, "limit_seconds": 120}, "actor": "bob",
        })
        service._apply_remote_command({
            "action": "remove_limit", "target_key": "app:test", "actor": "charlie",
        })

        self.assertEqual([item[0] for item in emitted], [
            "Limite créée par alice — Usage Guard",
            "Limite modifiée par bob — Usage Guard",
            "Limite supprimée par charlie — Usage Guard",
        ])

    def test_creating_a_second_limit_on_same_category_does_not_replace_first(self):
        policies = {}
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(data={"notification_rules": []})
        service.notification_requested = SimpleNamespace(emit=lambda *args: None)

        def apply_settings(target_key, settings):
            policies[target_key] = dict(settings)
            return policies[target_key]

        service.app_limiter = SimpleNamespace(
            policies=policies,
            apply_settings=apply_settings,
            label_for_key=lambda _key: "Catégorie · Jeux",
        )
        settings = {
            "enabled": True, "create_new": True, "target_key": "category:Jeux",
            "limit_seconds": 3600, "extension_seconds": 900,
            "warning_seconds": 300,
        }

        service._apply_remote_command({
            "action": "set_limit", "target_key": "category:Jeux",
            "settings": settings,
        })
        service._apply_remote_command({
            "action": "set_limit", "target_key": "category:Jeux",
            "settings": {**settings, "limit_seconds": 600},
        })

        self.assertEqual(len(policies), 2)
        self.assertIn("category:Jeux", policies)
        duplicate_keys = [key for key in policies if key.startswith("category:Jeux#")]
        self.assertEqual(len(duplicate_keys), 1)
        self.assertEqual(policies["category:Jeux"]["limit_seconds"], 3600)
        self.assertEqual(policies[duplicate_keys[0]]["target_key"], "category:Jeux")
        self.assertEqual(policies[duplicate_keys[0]]["limit_seconds"], 600)

    def test_remote_create_new_limit_is_idempotent_for_same_command(self):
        with tempfile.TemporaryDirectory() as directory:
            policies = {}
            service = MonitoringService.__new__(MonitoringService)
            service.usage = AppUsageStore(Path(directory) / "activity.json")
            service.notification_requested = SimpleNamespace(emit=lambda *args: None)

            def apply_settings(target_key, settings):
                policies[target_key] = dict(settings)
                return policies[target_key]

            service.app_limiter = SimpleNamespace(
                policies=policies,
                apply_settings=apply_settings,
                label_for_key=lambda _key: "Catégorie · Jeux",
            )
            command = {
                "_remote_command_id": "42",
                "action": "set_limit",
                "target_key": "category:Jeux",
                "settings": {
                    "enabled": True, "create_new": True,
                    "target_key": "category:Jeux",
                    "limit_seconds": 3600, "extension_seconds": 900,
                    "warning_seconds": 300,
                },
            }

            first = service._apply_remote_command(dict(command))
            second = service._apply_remote_command(dict(command))

            self.assertTrue(first["ok"])
            self.assertEqual(first, second)
            self.assertEqual(list(policies), ["category:Jeux"])
            self.assertEqual(
                service.usage.data["remote_command_results"]["42"]["limit"]["key"],
                "category:Jeux",
            )

    def test_cached_remote_limit_command_is_reapplied_when_local_limit_is_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            policies = {}
            service = MonitoringService.__new__(MonitoringService)
            service.usage = AppUsageStore(Path(directory) / "activity.json")
            service.notification_requested = SimpleNamespace(emit=lambda *args: None)

            def apply_settings(target_key, settings):
                policies[target_key] = dict(settings)
                return policies[target_key]

            service.app_limiter = SimpleNamespace(
                policies=policies,
                apply_settings=apply_settings,
                label_for_key=lambda _key: "Codex",
            )
            service.usage.data["remote_command_results"]["42"] = {
                "ok": True,
                "limit": {
                    "key": "app:codex",
                    "target_key": "app:codex",
                    "limit_seconds": 600,
                },
            }

            result = service._apply_remote_command({
                "_remote_command_id": "42",
                "action": "set_limit",
                "target_key": "app:codex",
                "settings": {"target_key": "app:codex", "limit_seconds": 600},
            })

            self.assertTrue(result["ok"])
            self.assertIn("app:codex", policies)
            self.assertEqual(policies["app:codex"]["limit_seconds"], 600)

    def test_pwa_login_notification_names_the_connected_user(self):
        emitted = []
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(data={"notification_rules": [{
            "kind": "pwa_login", "enabled": True,
        }]})
        service.notification_requested = SimpleNamespace(
            emit=lambda *args: emitted.append(args)
        )

        service._notify_pwa_login("alice", "192.0.2.10")

        self.assertEqual(len(emitted), 1)
        self.assertIn("alice", emitted[0][0])
        self.assertIn("192.0.2.10", emitted[0][1])

    def test_pwa_login_notification_can_be_sent_by_email_only(self):
        emails = []
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(data={"notification_rules": [{
            "kind": "pwa_login", "enabled": True,
            "channels": ["email"],
            "email_recipient": "owner@example.test",
        }]})
        service.notification_requested = SimpleNamespace(
            emit=lambda *_args: self.fail("Notification Windows inattendue")
        )
        service.email_notification_requested = SimpleNamespace(
            emit=lambda *args: emails.append(args)
        )

        service._notify_pwa_login("alice", "192.0.2.10")

        self.assertEqual(len(emails), 1)
        self.assertEqual(emails[0][2], "owner@example.test")
        self.assertIn("alice", emails[0][0])

    def test_pwa_login_windows_only_does_not_repeat_server_email(self):
        windows = []
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(data={"notification_rules": [{
            "kind": "pwa_login", "enabled": True,
            "channels": ["windows", "email"],
            "email_recipient": "owner@example.test",
        }]})
        service.notification_requested = SimpleNamespace(
            emit=lambda *args: windows.append(args)
        )
        service.email_notification_requested = SimpleNamespace(
            emit=lambda *_args: self.fail("E-mail déjà envoyé par le serveur")
        )

        service._notify_pwa_login("alice", "192.0.2.10", windows_only=True)

        self.assertEqual(len(windows), 1)

    def test_custom_threshold_notifies_once_until_usage_drops_below_it(self):
        emitted = []
        status = {"seconds": 80, "allowed": 100, "extension_used": False}
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(data={"notification_rules": [{
            "id": "threshold", "kind": "usage_threshold", "enabled": True,
            "target_key": "app:test", "threshold_percent": 80,
            "label": "Seuil test",
        }]})
        service.app_limiter = SimpleNamespace(
            policies={"app:test": {}},
            current_status=lambda _key: dict(status),
            label_for_key=lambda _key: "Test",
        )
        service.notification_requested = SimpleNamespace(
            emit=lambda *args: emitted.append(args)
        )
        service._notification_thresholds_shown = set()

        service._check_notification_thresholds()
        service._check_notification_thresholds()
        self.assertEqual(len(emitted), 1)
        self.assertIn("80 %", emitted[0][1])

        status["seconds"] = 10
        service._check_notification_thresholds()
        status["seconds"] = 80
        service._check_notification_thresholds()
        self.assertEqual(len(emitted), 2)

    def test_duration_threshold_counts_a_site_subcategory(self):
        with tempfile.TemporaryDirectory() as directory:
            emitted = []
            store = AppUsageStore(Path(directory) / "activity.json")
            key = "site:brave.exe:example.test"
            store.data["targets"][key] = {
                "label": "example.test", "category": "Internet",
                "site_category": "Actualité",
            }
            store.data["site_categories"] = ["Actualité"]
            store.data["days"][date.today().isoformat()] = {key: 120}
            store.set_notification_rule({
                "kind": "usage_threshold", "threshold_mode": "duration",
                "target_key": "category:Actualité", "duration_seconds": 60,
            })
            service = MonitoringService.__new__(MonitoringService)
            service.usage = store
            service.app_limiter = SimpleNamespace(
                label_for_key=lambda target: target,
                _format_duration=lambda seconds: f"{seconds} s",
            )
            service.notification_requested = SimpleNamespace(
                emit=lambda *args: emitted.append(args)
            )
            service._notification_thresholds_shown = set()

            service._check_notification_thresholds()
            service._check_notification_thresholds()

            self.assertEqual(len(emitted), 1)
            self.assertIn("Actualité", emitted[0][1])

    def test_hour_threshold_waits_for_the_selected_activity(self):
        with tempfile.TemporaryDirectory() as directory:
            emitted = []
            store = AppUsageStore(Path(directory) / "activity.json")
            store.data["targets"]["app:test"] = {"label": "Test"}
            store.set_notification_rule({
                "kind": "usage_threshold", "threshold_mode": "time",
                "target_key": "app:test", "after_time": "00:00",
            })
            service = MonitoringService.__new__(MonitoringService)
            service.usage = store
            service.current_context = ActiveContext(app_name="Other.exe")
            service.app_limiter = SimpleNamespace(
                label_for_key=lambda _target: "Test",
            )
            service.notification_requested = SimpleNamespace(
                emit=lambda *args: emitted.append(args)
            )
            service._notification_thresholds_shown = set()

            service._check_notification_thresholds()
            self.assertEqual(emitted, [])

            service.current_context = ActiveContext(app_name="Test.exe")
            service._check_notification_thresholds()
            self.assertEqual(len(emitted), 1)
            self.assertIn("Test", emitted[0][1])

    def test_startup_reminder_is_notification_only(self):
        emitted = []
        service = MonitoringService.__new__(MonitoringService)
        service.usage = SimpleNamespace(data={"notification_rules": [{
            "kind": "startup_reminder", "enabled": True,
            "weekdays": list(range(7)), "label": "Repos",
            "description": "Ne pas utiliser l’ordinateur aujourd’hui.",
        }]})
        service.notification_requested = SimpleNamespace(
            emit=lambda *args: emitted.append(args)
        )

        service._notify_startup_rules()

        self.assertEqual(emitted, [(
            "Repos", "Ne pas utiliser l’ordinateur aujourd’hui.", 0,
        )])

    def test_foreground_application_remains_active_until_afk_threshold(self):
        reading = ActiveContext(
            app_name="ChatGPT.exe", has_recent_input=False,
            idle_seconds=90, is_afk=False,
        )
        away = ActiveContext(
            app_name="ChatGPT.exe", has_recent_input=False,
            idle_seconds=121, is_afk=True,
        )

        self.assertTrue(MonitoringService.is_activity_countable(reading))
        self.assertFalse(MonitoringService.is_activity_countable(away))

    def test_unclassified_site_keeps_its_host_in_timeline_sessions(self):
        target = SimpleNamespace(
            key="site:brave.exe:other-sites",
            label="Autres sites",
            detail_host="example.com",
        )

        self.assertEqual(
            MonitoringService._session_identity(target),
            ("site:brave.exe:example.com", "example.com"),
        )

    def test_private_browser_title_does_not_expose_a_site(self):
        self.assertEqual(
            _host_url_from_title("example.com - Fenêtre privée - Brave"),
            "",
        )

    def test_private_browser_window_discards_a_stale_regular_url(self):
        probe = ActivityProbe.__new__(ActivityProbe)
        probe._fallback = SimpleNamespace(current=lambda: ActiveContext(
            app_name="brave.exe",
            window_title="Nouvel onglet - Fenêtre privée - Brave",
            is_afk=False,
        ))
        probe._current_bridge_tab = lambda: SimpleNamespace(
            url="https://example.test", title="Example",
            audible=False, generic=False,
        )
        probe.aw = SimpleNamespace(current=lambda: ActiveContext(
            app_name="brave.exe", url="https://example.test",
        ))
        probe._media = SimpleNamespace(
            is_playing_for=lambda *_args: False,
            playing_sources=lambda: [],
        )
        probe._last_browser_url = "https://previous.test"
        probe._last_non_guard_context = None

        result = probe.current()

        self.assertTrue(result.generic_web)
        self.assertEqual(result.url, "")
        self.assertEqual(probe._last_browser_url, "https://previous.test")

    def test_context_keeps_windows_afk_state_instead_of_three_second_input_flag(self):
        probe = ActivityProbe.__new__(ActivityProbe)
        probe._through_usage_guard = lambda context, fallback: context
        probe._media = SimpleNamespace(is_playing_for=lambda app, url: False)
        probe._background_media = lambda context: []
        probe._remember_non_guard_context = lambda context, fallback: None
        context = ActiveContext(app_name="ChatGPT.exe")
        fallback = ActiveContext(
            app_name="ChatGPT.exe", has_recent_input=False,
            idle_seconds=90, is_afk=False,
        )

        result = probe._finish_context(context, fallback)

        self.assertFalse(result.has_recent_input)
        self.assertFalse(result.is_afk)

    def test_session_other_sites_only_include_hosts_seen_in_that_session(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            previous_day = date.today() - timedelta(days=1)
            started_at = datetime.combine(
                previous_day, datetime.min.time()
            ).astimezone()
            key = "site:brave.exe:other-sites"
            store.data["targets"][key] = {
                "label": "Autres sites",
                "category": "Internet",
            }
            store.data["other_site_days"] = {
                "brave.exe": {
                    previous_day.isoformat(): {"carto.com": 600.0},
                }
            }
            store.data["sessions"] = [{
                    "kind": "active",
                    "key": key,
                    "label": "Autres sites",
                    "started_at": started_at.isoformat(),
                    "ended_at": (started_at + timedelta(seconds=600)).isoformat(),
                }, {
                    "kind": "active",
                    "key": "site:brave.exe:example.com",
                    "label": "example.com",
                    "started_at": started_at.isoformat(),
                    "ended_at": (started_at + timedelta(seconds=42)).isoformat(),
                }]

            service = MonitoringService.__new__(MonitoringService)
            service.usage = store
            service.app_limiter = SimpleNamespace(
                policies={}, computer_block_status=lambda: {"active": False}
            )
            service.current_context = ActiveContext(
                app_name="brave.exe", url="https://www.example.com/path"
            )
            service._tracking_started_at = started_at.isoformat()
            service._program_inventory_initialized = True
            service._web_inventory_initialized = True

            snapshot = service.remote_snapshot({"scope": "session"})

            self.assertEqual(
                snapshot["other_sites"],
                [{"browser": "brave.exe", "host": "example.com", "seconds": 42.0}],
            )
            self.assertNotIn("carto.com", {item["host"] for item in snapshot["other_sites"]})
            usage = {item["key"]: item["seconds"] for item in snapshot["usage"]}
            self.assertEqual(usage[key], 42.0)
            self.assertNotIn("site:brave.exe:example.com", usage)
            self.assertEqual(snapshot["current"]["site_host"], "example.com")
            self.assertEqual(
                snapshot["current"]["target_key"], "site:brave.exe:other-sites"
            )

    def test_chrome_pwa_inventory_fuses_program_and_active_target(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppUsageStore(Path(directory) / "activity.json")
            store.update_sessions({"program:chrome.exe": {
                "kind": "program", "key": "app:chrome", "label": "chrome",
                "source": "windows",
            }}, at="2026-08-15T06:05:43+02:00")

            service = MonitoringService.__new__(MonitoringService)
            service.usage = store
            service._tracking_started_at = "2026-08-15T06:00:00+02:00"
            observed = service._resolved_program_sessions({
                "chrome.exe": {
                    "executable": "chrome.exe",
                    "window_titles": ["ChatGPT"],
                }
            })
            store.update_sessions(observed, at="2026-08-15T15:10:00+02:00")

            session = store.data["open_sessions"]["program:chrome.exe"]
            self.assertEqual(session["key"], "app:chatgpt")
            self.assertEqual(session["label"], "ChatGPT")
            self.assertEqual(session["started_at"], "2026-08-15T06:05:43+02:00")



if __name__ == "__main__":
    unittest.main()
