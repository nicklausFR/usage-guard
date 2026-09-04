import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from command_policy import (
    COMMAND_SOURCE_FIELD,
    SOURCE_BACKEND,
    SOURCE_LOCAL_ADMIN,
    SOURCE_LOCAL_API,
    rejected_mutation,
    stamp_command,
)


class CommandPolicyTest(unittest.TestCase):
    def test_transport_stamp_discards_spoofed_internal_identity(self):
        command = stamp_command({
            "action": "remove_limit",
            "_usage_guard_source": "backend",
            "_remote_command_id": "999",
        }, SOURCE_LOCAL_API)

        self.assertEqual(command[COMMAND_SOURCE_FIELD], SOURCE_LOCAL_API)
        self.assertNotIn("_remote_command_id", command)

    def test_local_api_cannot_mutate_a_backend_managed_limit_in_dev(self):
        command = stamp_command({
            "action": "reset_limit", "target_key": "app:test",
        }, SOURCE_LOCAL_API)
        error = rejected_mutation(
            command,
            {"app:test": {"managed_by": "backend"}},
            {},
            enforced=True,
        )

        self.assertIn("administrée à distance", error)

    def test_backend_can_mutate_its_managed_limit(self):
        command = stamp_command({
            "action": "remove_limit", "target_key": "app:test",
        }, SOURCE_BACKEND)

        self.assertEqual(rejected_mutation(
            command,
            {"app:test": {"managed_by": "backend"}},
            {},
            enforced=True,
        ), "")

    def test_authenticated_local_admin_can_mutate_a_backend_limit(self):
        command = stamp_command({
            "action": "remove_limit", "target_key": "app:test",
        }, SOURCE_LOCAL_ADMIN)

        self.assertEqual(rejected_mutation(
            command,
            {"app:test": {"managed_by": "backend"}},
            {},
            enforced=True,
        ), "")

    def test_local_rules_and_production_compatibility_remain_mutable(self):
        command = stamp_command({
            "action": "remove_limit", "target_key": "app:test",
        }, SOURCE_LOCAL_API)

        self.assertEqual(rejected_mutation(
            command, {"app:test": {"managed_by": "local"}}, {}, enforced=True,
        ), "")
        self.assertEqual(rejected_mutation(
            command, {"app:test": {"managed_by": "backend"}}, {}, enforced=False,
        ), "")

    def test_local_api_cannot_mutate_a_backend_computer_block_by_id(self):
        command = stamp_command({
            "action": "set_computer_block_enabled",
            "block_id": "remote-night", "enabled": False,
        }, SOURCE_LOCAL_API)

        self.assertIn("administrée à distance", rejected_mutation(
            command, {}, [{
                "block_id": "remote-night", "managed_by": "backend",
            }], enforced=True,
        ))

    def test_local_api_can_add_a_distinct_rule_without_replacing_remote_one(self):
        command = stamp_command({
            "action": "set_computer_block", "mode": "schedule",
        }, SOURCE_LOCAL_API)

        self.assertEqual(rejected_mutation(
            command, {}, [{
                "block_id": "remote-night", "managed_by": "backend",
            }], enforced=True,
        ), "")


if __name__ == "__main__":
    unittest.main()
