import unittest
from types import SimpleNamespace
from unittest.mock import patch

import windows_identity


class WindowsIdentityTest(unittest.TestCase):
    def test_inventory_merges_existing_sources_by_sid(self):
        local = [{
            "windows_sid": "S-1-5-21-1-2-3-1001",
            "windows_domain": "PC",
            "windows_username": "Alice",
        }]
        profile = [{
            "windows_sid": "s-1-5-21-1-2-3-1001",
            "windows_domain": "DOMAIN",
            "windows_username": "alice",
        }, {
            "windows_sid": "S-1-5-21-1-2-3-1002",
            "windows_domain": "DOMAIN",
            "windows_username": "Bob",
        }]
        with (
            patch.object(windows_identity, "_local_accounts", return_value=local),
            patch.object(windows_identity, "_profile_accounts", return_value=profile),
            patch.object(windows_identity, "_interactive_accounts", return_value=[]),
            patch.object(
                windows_identity, "_administrative_sids",
                return_value={"S-1-5-21-1-2-3-1002"},
            ),
        ):
            accounts = windows_identity.enumerate_windows_accounts()

        self.assertEqual(len(accounts), 2)
        alice = next(item for item in accounts if item["windows_username"].casefold() == "alice")
        bob = next(item for item in accounts if item["windows_username"] == "Bob")
        self.assertEqual(alice["windows_domain"], "DOMAIN")
        self.assertFalse(alice["is_windows_admin"])
        self.assertTrue(bob["is_windows_admin"])
        self.assertEqual(bob["display_name"], "DOMAIN\\Bob")

    def test_non_windows_session_has_no_invented_identity(self):
        with patch.object(windows_identity.sys, "platform", "linux"):
            self.assertIsNone(windows_identity.current_windows_session_identity())
            self.assertEqual(windows_identity.enumerate_windows_accounts(), [])

    def test_orphaned_profile_sid_is_ignored_without_hiding_valid_profiles(self):
        class FakeKey:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        profile_sids = [
            "S-1-5-21-1-2-3-1000",
            "S-1-5-21-1-2-3-1001",
        ]

        def enum_key(_root, index):
            if index >= len(profile_sids):
                raise OSError("done")
            return profile_sids[index]

        def lookup_account_sid(_system, sid):
            if sid.endswith("1000"):
                raise windows_identity.PyWinError(
                    1332, "LookupAccountSid", "Aucun mappage"
                )
            return "Alice", "PC", 1

        fake_registry = SimpleNamespace(
            HKEY_LOCAL_MACHINE=object(),
            OpenKey=lambda *_args: FakeKey(),
            EnumKey=enum_key,
        )
        fake_security = SimpleNamespace(
            SidTypeUser=1,
            ConvertStringSidToSid=lambda value: value,
            LookupAccountSid=lookup_account_sid,
        )
        with (
            patch.object(windows_identity.sys, "platform", "win32"),
            patch.dict(
                "sys.modules",
                {"winreg": fake_registry, "win32security": fake_security},
            ),
        ):
            accounts = windows_identity._profile_accounts()

        self.assertEqual(accounts, [{
            "windows_sid": "S-1-5-21-1-2-3-1001",
            "windows_domain": "PC",
            "windows_username": "Alice",
        }])


if __name__ == "__main__":
    unittest.main()
