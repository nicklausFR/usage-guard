"""Report untranslated desktop and static PWA strings."""
import argparse
import ast
import json
import re
import sys
from html.parser import HTMLParser
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


def python_messages(root):
    messages = set()
    ignored = {"tests", "usage_guard_backend", "dist", "dist-v2", "build"}
    translated_tools = {
        "tools/install_client_launcher.py",
        "tools/setup_client.py",
        "tools/setup_client_qt.py",
    }
    for path in root.rglob("*.py"):
        if any(part in ignored for part in path.parts):
            continue
        relative = path.relative_to(root).as_posix()
        if "tools" in path.parts and relative not in translated_tools:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeError):
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name) and node.func.id == "_"
                and node.args and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                messages.add(node.args[0].value)
    return messages


def backend_error_messages(root):
    messages = set()
    filenames = (
        "usage_guard.py",
        "guard.py",
        "service_backend.py",
        "backend_client.py",
        "usage_guard_backend/server.py",
    )
    for filename in filenames:
        path = root / filename
        if not path.exists():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Raise) or not isinstance(node.exc, ast.Call):
                continue
            if not isinstance(node.exc.func, ast.Name) or node.exc.func.id not in {
                "ValueError", "RuntimeError", "PermissionError"
            }:
                continue
            if (
                node.exc.args
                and isinstance(node.exc.args[0], ast.Constant)
                and isinstance(node.exc.args[0].value, str)
                and re.search(
                    r"[À-ÿ]|\b(?:Aucun|Appareil|Charge|Choisissez|Cible|Code|"
                    r"Compte|Configuration|Delta|Durée|Heure|Identifiant|"
                    r"Indiquez|Jour|JSON|La|Le|Les|Limite|Liste|Lot|Manifest|"
                    r"Mode|Mot|Mutation|Nom|Objet|Ordinateur|Paquet|Paramètre|"
                    r"Période|Politique|Port|Révision|Session|Taille|Type|Un|"
                    r"Une|Utilisateur)\b",
                    node.exc.args[0].value,
                )
            ):
                messages.add(node.exc.args[0].value)
    return messages


class VisibleHtml(HTMLParser):
    def __init__(self):
        super().__init__()
        self.values = set()
        self.hidden_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.hidden_depth += 1
        for name, value in attrs:
            if name in {"title", "aria-label", "placeholder"} and value:
                self.values.add(" ".join(value.split()))

    def handle_endtag(self, tag):
        if tag in {"script", "style"} and self.hidden_depth:
            self.hidden_depth -= 1

    def handle_data(self, data):
        value = " ".join(data.split())
        if self.hidden_depth or not value or value in {"Usage Guard", "DEV", "—"}:
            return
        if re.search(r"[A-Za-zÀ-ÿ]", value):
            self.values.add(value)


def pwa_exact_keys(path):
    source = path.read_text(encoding="utf-8")
    return {
        json.loads('"' + match.group(1) + '"')
        for match in re.finditer(
            r'^\s*"((?:[^"\\]|\\.)+)"\s*:', source, re.MULTILINE
        )
    }


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    catalog = read_po(root / "locales/en/LC_MESSAGES/usage-guard.po")
    missing_desktop = sorted(
        message for message in python_messages(root) if not catalog.get(message)
    )
    html = VisibleHtml()
    html.feed((root / "pwa/index.html").read_text(encoding="utf-8"))
    exact = pwa_exact_keys(root / "pwa/i18n.js")
    missing_pwa = sorted(value for value in html.values if value not in exact)
    missing_errors = sorted(
        value for value in backend_error_messages(root) if value not in exact
    )
    print(f"Desktop gettext missing: {len(missing_desktop)}")
    for value in missing_desktop:
        print(f"  {value}")
    print(f"PWA static missing: {len(missing_pwa)}")
    for value in missing_pwa:
        print(f"  {value}")
    print(f"PWA backend errors missing: {len(missing_errors)}")
    for value in missing_errors:
        print(f"  {value}")
    raise SystemExit(bool(missing_desktop or missing_pwa or missing_errors))


if __name__ == "__main__":
    main()
