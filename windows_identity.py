"""Enumerate existing Windows accounts and identify the current WTS session."""

from __future__ import annotations

import os
import sys

try:
    from pywintypes import error as PyWinError
except ImportError:  # pragma: no cover - non-Windows test/runtime
    PyWinError = OSError


WINDOWS_PROVIDER_ERRORS = (ImportError, OSError, PyWinError)


def _account_record(domain, username):
    domain = str(domain or "").strip()
    username = str(username or "").strip()
    if not username or sys.platform != "win32":
        return None
    try:
        import win32security

        qualified = f"{domain}\\{username}" if domain else username
        sid, resolved_domain, account_type = win32security.LookupAccountName(
            None, qualified
        )
        if account_type != win32security.SidTypeUser:
            return None
        return {
            "windows_sid": win32security.ConvertSidToStringSid(sid).upper(),
            "windows_domain": str(resolved_domain or domain),
            "windows_username": username,
        }
    except WINDOWS_PROVIDER_ERRORS:
        return None


def _local_accounts():
    if sys.platform != "win32":
        return []
    try:
        import win32net
        import win32netcon

        records, resume = [], 0
        while True:
            users, _total, resume = win32net.NetUserEnum(
                None, 1, win32netcon.FILTER_NORMAL_ACCOUNT, resume
            )
            for user in users:
                if int(user.get("flags", 0)) & win32netcon.UF_ACCOUNTDISABLE:
                    continue
                record = _account_record(os.environ.get("COMPUTERNAME"), user.get("name"))
                if record:
                    records.append(record)
            if not resume:
                return records
    except WINDOWS_PROVIDER_ERRORS:
        return []


def _profile_accounts():
    """Return local/domain accounts that already own a profile on this PC."""
    if sys.platform != "win32":
        return []
    try:
        import win32security
        import winreg

        records = []
        path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as root:
            index = 0
            while True:
                try:
                    sid_text = winreg.EnumKey(root, index)
                except OSError:
                    break
                index += 1
                try:
                    sid = win32security.ConvertStringSidToSid(sid_text)
                    username, domain, account_type = win32security.LookupAccountSid(
                        None, sid
                    )
                    if account_type != win32security.SidTypeUser:
                        continue
                    records.append({
                        "windows_sid": sid_text.upper(),
                        "windows_domain": str(domain or ""),
                        "windows_username": str(username or ""),
                    })
                except (OSError, ValueError, PyWinError):
                    continue
        return records
    except WINDOWS_PROVIDER_ERRORS:
        return []


def _interactive_accounts():
    if sys.platform != "win32":
        return []
    try:
        import win32ts

        records = []
        for session in win32ts.WTSEnumerateSessions(None, 1, 0):
            session_id = int(session.get("SessionId", -1))
            if session_id < 0:
                continue
            username = win32ts.WTSQuerySessionInformation(
                None, session_id, win32ts.WTSUserName
            )
            domain = win32ts.WTSQuerySessionInformation(
                None, session_id, win32ts.WTSDomainName
            )
            record = _account_record(domain, username)
            if record:
                records.append(record)
        return records
    except WINDOWS_PROVIDER_ERRORS:
        return []


def _administrative_sids():
    if sys.platform != "win32":
        return set()
    try:
        import win32net
        import win32security

        administrators_sid = win32security.CreateWellKnownSid(
            win32security.WinBuiltinAdministratorsSid, None
        )
        group_name, _domain, _type = win32security.LookupAccountSid(
            None, administrators_sid
        )
        result, resume = set(), 0
        while True:
            members, _total, resume = win32net.NetLocalGroupGetMembers(
                None, group_name, 2, resume
            )
            for member in members:
                sid = member.get("sid")
                if sid is not None:
                    result.add(
                        win32security.ConvertSidToStringSid(sid).upper()
                    )
            if not resume:
                return result
    except WINDOWS_PROVIDER_ERRORS:
        return set()


def enumerate_windows_accounts():
    """List selectable existing accounts without creating or guessing one."""
    accounts = {}
    for provider in (_local_accounts, _profile_accounts, _interactive_accounts):
        for source in provider():
            sid = str(source.get("windows_sid") or "").strip().upper()
            username = str(source.get("windows_username") or "").strip()
            if not sid or not username:
                continue
            existing = accounts.get(sid, {})
            accounts[sid] = {
                "windows_sid": sid,
                "windows_domain": str(
                    source.get("windows_domain")
                    or existing.get("windows_domain") or ""
                ),
                "windows_username": username,
            }
    administrators = _administrative_sids()
    result = [{
        **account,
        "is_windows_admin": sid in administrators,
        "display_name": (
            f"{account['windows_domain']}\\{account['windows_username']}"
            if account["windows_domain"] else account["windows_username"]
        ),
    } for sid, account in accounts.items()]
    return sorted(
        result,
        key=lambda item: (
            item["windows_domain"].casefold(),
            item["windows_username"].casefold(),
            item["windows_sid"],
        ),
    )


def current_windows_session_identity():
    """Identify the session hosting this process, including its stable SID."""
    if sys.platform != "win32":
        return None
    try:
        import win32ts

        session_id = int(win32ts.ProcessIdToSessionId(os.getpid()))
        username = win32ts.WTSQuerySessionInformation(
            None, session_id, win32ts.WTSUserName
        )
        domain = win32ts.WTSQuerySessionInformation(
            None, session_id, win32ts.WTSDomainName
        )
        account = _account_record(domain, username)
        if not account:
            return None
        return {
            **account,
            "session_id": session_id,
            "is_windows_admin": account["windows_sid"] in _administrative_sids(),
        }
    except WINDOWS_PROVIDER_ERRORS:
        return None
