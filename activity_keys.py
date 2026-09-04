"""Shared helpers for activity target identities."""


def is_other_sites_aggregate_key(value):
    """Return whether *value* is exactly ``site:<browser>:other-sites``."""
    parts = str(value or "").split(":")
    return (
        len(parts) == 3
        and parts[0] == "site"
        and bool(parts[1])
        and parts[2] == "other-sites"
    )
