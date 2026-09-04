"""Small, deterministic trust policy for control commands.

Transport adapters stamp the source themselves.  Values supplied by an HTTP
payload are deliberately discarded so a local caller cannot claim to be the
backend.
"""

from __future__ import annotations


COMMAND_SOURCE_FIELD = "_usage_guard_source"
SERVICE_ADMIN_TOKEN_FIELD = "_usage_guard_service_admin_token"
SOURCE_LOCAL_API = "local_api"
SOURCE_LOCAL_ADMIN = "local_admin"
SOURCE_BACKEND = "backend"
SOURCE_INTERNAL = "internal"

MANAGED_BY_FIELD = "managed_by"
MANAGER_LOCAL = "local"
MANAGER_BACKEND = "backend"

_RESERVED_FIELDS = {
    COMMAND_SOURCE_FIELD, SERVICE_ADMIN_TOKEN_FIELD, "_remote_command_id",
}
_LIMIT_MUTATIONS = {"set_limit", "remove_limit", "reset_limit"}
_COMPUTER_BLOCK_MUTATIONS = {
    "set_computer_block",
    "set_computer_block_enabled",
    "clear_computer_block",
    "replace_computer_blocks",
}
_CATALOG_MUTATIONS = {
    "replace_catalog",
    "rename_target", "add_catalog_item", "set_category", "make_root",
    "exclude_target", "unexclude_target", "dismiss_target", "delete_target",
    "merge_target",
    "rename_category", "move_category", "reorder_category",
    "reorder_target", "reorder_navigation", "reorder_unclassified",
    "clear_category", "make_category_root", "set_category_for_keys",
    "rename_browser", "make_browser_root", "clear_browser_category",
    "clear_site_category", "rename_site_category", "reorder_site_category",
    "exclude_passive", "make_site_specific", "categorize_site",
    "exclude_site", "delete_site",
}


def is_control_mutation(command):
    action = str(command.get("action") or "")
    return action in _LIMIT_MUTATIONS or action in _COMPUTER_BLOCK_MUTATIONS


def is_catalog_mutation(command):
    """Return whether a command changes the shared activity catalogue."""
    return str(command.get("action") or "") in _CATALOG_MUTATIONS


def stamp_command(payload, source, *, command_id=""):
    """Return a copied command with transport-owned identity fields."""
    command = {
        key: value for key, value in dict(payload).items()
        if key not in _RESERVED_FIELDS
    }
    command[COMMAND_SOURCE_FIELD] = str(source)
    if command_id:
        command["_remote_command_id"] = str(command_id)
    return command


def command_source(command):
    return str(command.get(COMMAND_SOURCE_FIELD) or SOURCE_INTERNAL)


def manager_for_source(source):
    return MANAGER_BACKEND if source == SOURCE_BACKEND else MANAGER_LOCAL


def normalized_manager(value):
    return MANAGER_BACKEND if value == MANAGER_BACKEND else MANAGER_LOCAL


def is_backend_managed(value):
    return isinstance(value, dict) and normalized_manager(
        value.get(MANAGED_BY_FIELD)
    ) == MANAGER_BACKEND


def computer_blocks_by_id(value):
    """Normalize v1 singleton and v2 collections for ownership checks."""
    if isinstance(value, list):
        blocks = value
    elif isinstance(value, dict) and value.get("mode"):
        blocks = [value]
    elif isinstance(value, dict):
        blocks = list(value.values())
    else:
        blocks = []
    return {
        str(block.get("block_id") or ""): block
        for block in blocks
        if isinstance(block, dict) and block
    }


def rejected_mutation(command, limits, computer_block, *, enforced):
    """Return a user-facing error, or an empty string when mutation is valid."""
    if not enforced or command_source(command) != SOURCE_LOCAL_API:
        return ""
    action = str(command.get("action") or "")
    if action in _LIMIT_MUTATIONS:
        target_key = str(command.get("target_key") or "")
        if is_backend_managed(limits.get(target_key, {})):
            return "Cette limite est administrée à distance et ne peut pas être modifiée localement."
    if action in _COMPUTER_BLOCK_MUTATIONS:
        blocks = computer_blocks_by_id(computer_block)
        if action == "replace_computer_blocks":
            if any(is_backend_managed(block) for block in blocks.values()):
                return "Ces limitations de l’ordinateur sont administrées à distance."
            return "Le document de limitations est réservé à la synchronisation distante."
        block_id = str(command.get("block_id") or "")
        target = blocks.get(block_id) if block_id else None
        if not block_id and action != "set_computer_block" and len(blocks) == 1:
            target = next(iter(blocks.values()))
        if is_backend_managed(target):
            return "Cette limitation de l’ordinateur est administrée à distance."
    return ""
