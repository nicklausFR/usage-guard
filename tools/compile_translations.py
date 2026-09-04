"""Compile PO catalogs and generate Chrome/Brave extension locales."""
import ast
import json
import struct
from pathlib import Path


def read_po(path):
    messages, msgid, msgstr, field = {}, None, None, None
    for raw in path.read_text(encoding="utf-8").splitlines() + [""]:
        line = raw.strip()
        if not line:
            if msgid is not None:
                messages[msgid] = msgstr or ""
            msgid = msgstr = field = None
        elif line.startswith("msgid "):
            msgid, field = ast.literal_eval(line[6:]), "id"
        elif line.startswith("msgstr "):
            msgstr, field = ast.literal_eval(line[7:]), "str"
        elif line.startswith('"') and field == "id":
            msgid += ast.literal_eval(line)
        elif line.startswith('"') and field == "str":
            msgstr = (msgstr or "") + ast.literal_eval(line)
    return messages


def write_mo(messages, path):
    items = sorted((key.encode(), value.encode()) for key, value in messages.items())
    ids = b"\0".join(key for key, _ in items) + b"\0"
    values = b"\0".join(value for _, value in items) + b"\0"
    count, offset = len(items), 28
    id_table, value_table = offset, offset + count * 8
    id_offset, value_offset = value_table + count * 8, value_table + count * 8 + len(ids)
    id_entries, value_entries, position = [], [], 0
    for key, _ in items:
        id_entries.append((len(key), id_offset + position)); position += len(key) + 1
    position = 0
    for _, value in items:
        value_entries.append((len(value), value_offset + position)); position += len(value) + 1
    output = struct.pack("<7I", 0x950412DE, 0, count, id_table, value_table, 0, value_offset + len(values))
    output += b"".join(struct.pack("<2I", *entry) for entry in id_entries)
    output += b"".join(struct.pack("<2I", *entry) for entry in value_entries) + ids + values
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(output)


project = Path(__file__).parents[1]
for po in project.glob("locales/*/LC_MESSAGES/usage-guard.po"):
    write_mo(read_po(po), po.with_suffix(".mo"))
for po in project.glob("locales/*/LC_MESSAGES/browser-extension.po"):
    language = po.parents[1].name
    messages = {
        key: {"message": value or key}
        for key, value in read_po(po).items() if key
    }
    destination = project / "browser_extension" / "_locales" / language / "messages.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(messages, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
