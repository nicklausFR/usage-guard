"""Service-owned registry for remotely managed controls."""

from __future__ import annotations

import json
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from command_policy import (
    SOURCE_BACKEND,
    SOURCE_LOCAL_ADMIN,
    command_source,
    is_backend_managed,
    rejected_mutation,
)


class ControlRegistry:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else None
        self.initialized = False
        self.limits = {}
        self.computer_blocks = {}
        self.computer_block = {}
        self.computer_block_graces = {}
        self.computer_block_grace = {}
        self._load()

    @staticmethod
    def _legacy_block_id(block):
        payload = json.dumps(
            dict(block or {}), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return "legacy-" + hashlib.sha256(payload).hexdigest()[:24]

    @classmethod
    def _normalized_computer_blocks(cls, value):
        if isinstance(value, list):
            candidates = value
        elif isinstance(value, dict) and value.get("mode"):
            candidates = [value]
        elif isinstance(value, dict):
            candidates = list(value.values())
        else:
            candidates = []
        result = {}
        for source in candidates:
            if not isinstance(source, dict) or not is_backend_managed(source):
                continue
            block = dict(source)
            block_id = str(block.get("block_id") or "").strip()
            if not block_id:
                block_id = cls._legacy_block_id(block)
                block["block_id"] = block_id
            result[block_id] = block
        return result

    def _refresh_legacy_mirrors(self):
        self.computer_block = dict(
            self.computer_blocks[sorted(self.computer_blocks)[0]]
        ) if self.computer_blocks else {}
        self.computer_block_grace = dict(max(
            self.computer_block_graces.values(),
            key=lambda item: str(item.get("activated_at") or ""),
            default={},
        ))

    def _load(self):
        if self.path is None:
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8-sig"))
        except (OSError, TypeError, ValueError):
            return
        if not isinstance(data, dict) or data.get("version") not in {1, 2}:
            return
        limits = data.get("limits")
        block = data.get("computer_block")
        if isinstance(limits, dict):
            self.limits = {
                str(key): dict(policy) for key, policy in limits.items()
                if isinstance(policy, dict) and is_backend_managed(policy)
            }
        self.computer_blocks = self._normalized_computer_blocks(
            data.get("computer_blocks")
            if data.get("version") == 2 else block
        )
        graces = data.get("computer_block_graces")
        if isinstance(graces, dict):
            self.computer_block_graces = {
                str(token): dict(record)
                for token, record in graces.items()
                if isinstance(record, dict)
            }
        else:
            grace = data.get("computer_block_grace")
            if isinstance(grace, dict) and grace:
                token = str(grace.get("occurrence_token") or "legacy")
                self.computer_block_graces[token] = dict(grace)
        self._refresh_legacy_mirrors()
        self.initialized = True
        if data.get("version") == 1:
            self._save()

    def _save(self):
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps({
            "version": 2,
            "limits": self.limits,
            "computer_block": self.computer_block,
            "computer_blocks": self.computer_blocks,
            "computer_block_grace": self.computer_block_grace,
            "computer_block_graces": self.computer_block_graces,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(self.path)

    def controls(self):
        return json.loads(json.dumps({
            "initialized": self.initialized,
            "limits": self.limits,
            "computer_block": self.computer_block,
            "computer_blocks": [
                self.computer_blocks[key]
                for key in sorted(self.computer_blocks)
            ],
        }))

    def _computer_block_occurrence(self, occurrence):
        source = dict(occurrence or {})
        try:
            started_at = datetime.fromisoformat(str(source["started_at"]))
            ends_at = datetime.fromisoformat(str(source["ends_at"]))
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("Occurrence de blocage invalide.") from error
        if started_at.tzinfo is None or ends_at.tzinfo is None or started_at >= ends_at:
            raise ValueError("Occurrence de blocage invalide.")
        block_id = str(source.get("block_id") or "")
        if not block_id:
            if len(self.computer_blocks) > 1:
                raise ValueError("block_id requis pour cette occurrence.")
            block_id = (
                next(iter(self.computer_blocks))
                if self.computer_blocks else "legacy"
            )
        canonical = {
            "block_id": block_id,
            "mode": str(source.get("mode") or ""),
            "started_at": started_at.astimezone(timezone.utc).isoformat(timespec="seconds"),
            "ends_at": ends_at.astimezone(timezone.utc).isoformat(timespec="seconds"),
        }
        token = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return canonical, token, started_at, ends_at

    def computer_block_grace_status(self, occurrence, now=None):
        canonical, token, started_at, block_ends_at = self._computer_block_occurrence(
            occurrence
        )
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        record = dict(self.computer_block_graces.get(token, {}))
        if record.get("occurrence_token") != token:
            return {
                "state": "available",
                "available": started_at <= now < block_ends_at,
                "active": False,
                "used": False,
                "occurrence_token": token,
                **canonical,
            }
        try:
            grace_ends_at = datetime.fromisoformat(str(record["ends_at"]))
        except (KeyError, TypeError, ValueError):
            grace_ends_at = now
        active = now < grace_ends_at
        return {
            **record,
            "state": "active" if active else "expired",
            "available": False,
            "active": active,
            "used": True,
            "remaining_seconds": max(0, int((grace_ends_at - now).total_seconds())),
        }

    def start_computer_block_grace(self, occurrence, duration_seconds=300, now=None):
        canonical, token, started_at, block_ends_at = self._computer_block_occurrence(
            occurrence
        )
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        if not started_at <= now < block_ends_at:
            raise ValueError("Le blocage de l’ordinateur n’est pas actif.")
        current = self.computer_block_grace_status(occurrence, now)
        if current.get("used"):
            return current
        duration_seconds = max(300, int(duration_seconds or 300))
        ends_at = now + timedelta(seconds=duration_seconds)
        self.computer_block_grace = {
            "occurrence_token": token,
            **canonical,
            "activated_at": now.astimezone(timezone.utc).isoformat(timespec="seconds"),
            "ends_at": ends_at.astimezone(timezone.utc).isoformat(timespec="seconds"),
            "duration_seconds": duration_seconds,
        }
        self.computer_block_graces[token] = dict(self.computer_block_grace)
        self._save()
        return self.computer_block_grace_status(occurrence, now)

    def bootstrap(self, limits, computer_blocks):
        if not self.initialized:
            self.limits = {
                str(key): dict(policy) for key, policy in dict(limits).items()
                if isinstance(policy, dict) and is_backend_managed(policy)
            }
            self.computer_blocks = self._normalized_computer_blocks(
                computer_blocks
            )
            self._refresh_legacy_mirrors()
            self.initialized = True
            self._save()
        return self.controls()

    def authorize(self, command):
        error = rejected_mutation(
            command, self.limits, self.computer_blocks, enforced=True
        )
        return {"allowed": not bool(error), "error": error}

    def reserve(self, command):
        """Reserve remote ownership before the desktop has applied a command."""
        if command_source(command) != SOURCE_BACKEND:
            return self.controls()
        action = str(command.get("action") or "")
        target_key = str(command.get("target_key") or "")
        if action == "set_limit" and target_key:
            existing = dict(self.limits.get(target_key, {}))
            requested = command.get("settings")
            if isinstance(requested, dict):
                existing.update(requested)
            existing["managed_by"] = "backend"
            self.limits[target_key] = existing
        elif action == "remove_limit":
            self.limits.pop(target_key, None)
        elif action in {"set_computer_block", "set_computer_block_enabled"}:
            block_id = str(command.get("block_id") or "")
            if not block_id and action == "set_computer_block_enabled" and len(self.computer_blocks) == 1:
                block_id = next(iter(self.computer_blocks))
            if block_id:
                self.computer_blocks[block_id] = {
                    **self.computer_blocks.get(block_id, {}),
                    "block_id": block_id,
                    "managed_by": "backend", "pending": True,
                }
        elif action == "replace_computer_blocks":
            requested = command.get("blocks")
            if isinstance(requested, list):
                self.computer_blocks = self._normalized_computer_blocks([
                    {**block, "managed_by": "backend"}
                    for block in requested if isinstance(block, dict)
                ])
        elif action == "clear_computer_block":
            block_id = str(command.get("block_id") or "")
            if not block_id and len(self.computer_blocks) == 1:
                block_id = next(iter(self.computer_blocks))
            if block_id:
                self.computer_blocks.pop(block_id, None)
        self._refresh_legacy_mirrors()
        self.initialized = True
        self._save()
        return self.controls()

    def commit(self, command, result):
        if not isinstance(result, dict) or not result.get("ok"):
            return self.controls()
        source = command_source(command)
        action = str(command.get("action") or "")
        target_key = str(command.get("target_key") or "")
        if source == SOURCE_BACKEND and action == "set_limit":
            limit = result.get("limit")
            if isinstance(limit, dict):
                key = str(limit.get("key") or target_key)
                policy = {name: value for name, value in limit.items() if name != "key"}
                policy["managed_by"] = "backend"
                self.limits[key] = policy
        elif source == SOURCE_LOCAL_ADMIN and action == "set_limit":
            # Authenticated administrators may transfer a remotely-created
            # rule back to local ownership.
            self.limits.pop(target_key, None)
        elif action == "remove_limit":
            self.limits.pop(target_key, None)
        elif source == SOURCE_BACKEND and action in {
            "set_computer_block", "set_computer_block_enabled",
        }:
            block = result.get("computer_block")
            if isinstance(block, dict):
                block_id = str(block.get("block_id") or command.get("block_id") or "")
                if block_id:
                    self.computer_blocks[block_id] = {
                        **block, "block_id": block_id,
                        "managed_by": "backend",
                    }
        elif source == SOURCE_BACKEND and action == "replace_computer_blocks":
            blocks = result.get("computer_blocks")
            if isinstance(blocks, list):
                requested = command.get("blocks")
                requested_ids = set()
                for block in requested if isinstance(requested, list) else []:
                    if not isinstance(block, dict):
                        continue
                    block_id = str(block.get("block_id") or "").strip()
                    if block_id:
                        requested_ids.add(block_id)
                self.computer_blocks = self._normalized_computer_blocks([
                    {**block, "managed_by": "backend"}
                    for block in blocks
                    if (
                        isinstance(block, dict)
                        and str(block.get("block_id") or "").strip()
                        in requested_ids
                    )
                ])
        elif source == SOURCE_LOCAL_ADMIN and action == "set_computer_block":
            block = result.get("computer_block")
            block_id = str(
                (block or {}).get("block_id") or command.get("block_id") or ""
            )
            if block_id:
                self.computer_blocks.pop(block_id, None)
        elif source == SOURCE_LOCAL_ADMIN and action == "set_computer_block_enabled":
            block = result.get("computer_block")
            block_id = str(
                (block or {}).get("block_id") or command.get("block_id") or ""
            )
            if block_id in self.computer_blocks and isinstance(block, dict):
                self.computer_blocks[block_id] = {
                    **block, "block_id": block_id,
                    "managed_by": "backend",
                }
        elif action == "clear_computer_block":
            block_id = str(command.get("block_id") or "")
            if not block_id and len(self.computer_blocks) == 1:
                block_id = next(iter(self.computer_blocks))
            if block_id:
                self.computer_blocks.pop(block_id, None)
        self._refresh_legacy_mirrors()
        self.initialized = True
        self._save()
        return self.controls()
