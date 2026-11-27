# Polymorphism: one interface, many behaviours
#
# POLYMORPHISM ("many shapes") means code can use different kinds of
# objects in the same way, as long as they offer the same methods. The
# calling code doesn't know or care which kind it has:
#
#   for rule in rules:
#       rule.process(event)        each rule does something different
#
# You've used it all along: len() works on strings, lists, dicts and
# sets; `for` works on lists, files and generators. This file shows how
# to make YOUR classes work that way.
#
# Topics covered here:
#   1. Polymorphism through inheritance: rules with one interface
#   2. Duck typing: "if it has the method, it's good enough"
#   3. Protocols: describing an interface without inheritance
#   4. Enums: Severity as a class whose values compare in order
#   5. Operator overloading and container methods: a Timeline that
#      works with len(), in, for, [], slicing and +
#   6. The detection engine: add a rule without touching the engine
#   7. Putting the series together: three log formats -> one timeline
#      -> every rule -> alerts
#   8. Practice, with tests
#
# SECURITY CONNECTION
# -------------------
# Detection platforms (Sigma, Splunk, Elastic, Microsoft Sentinel) all
# work this way: a stream of normalised events, and a library of
# independent rules. Writing a new detection should never mean editing
# the engine; you just add a rule. That's the "open/closed principle":
# open for extension, closed for modification.


import bisect
import heapq
import re
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import IntEnum
from operator import attrgetter
from typing import Protocol, runtime_checkable

from classes_and_objects import LogEvent
from inheritance import detect_parser


# ---------------------------------------------------------------
# 4. Severity: an enum (used by everything below, so it comes first)
# ---------------------------------------------------------------
#
# An Enum is a class with a fixed set of named values. IntEnum values
# are also ints, so they SORT: Severity.CRITICAL > Severity.LOW.
# Using names instead of bare numbers or strings means a typo like
# Severity.HIHG fails immediately instead of silently.

class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self):
        return self.name.lower()


@dataclass
class Alert:
    time: datetime
    rule: str
    severity: Severity
    summary: str
    evidence: list = field(default_factory=list, repr=False)

    def __str__(self):
        return f"[{str(self.severity).upper():<8}] {self.time:%H:%M:%S} {self.rule}: {self.summary}"


# ---------------------------------------------------------------
# 1. Polymorphism through inheritance
# ---------------------------------------------------------------
#
# Every rule has the same two methods:
#   process(event) -> list of alerts   called once per event, in time order
#   finish()       -> list of alerts   called once at the end (default: none)
#
# The engine (section 6) only ever calls those two. Each subclass
# decides what they mean.

class Rule(ABC):
    name = "rule"
    severity = Severity.LOW

    @abstractmethod
    def process(self, event):
        """Look at one event; return a (possibly empty) list of Alerts."""

    def finish(self):
        return []

    def alert(self, event, summary, severity=None, evidence=()):
        return Alert(event.time, self.name, severity or self.severity, summary, list(evidence))


class BruteForceRule(Rule):
    """Many failed logins from one IP in a short time, from ANY source."""
    name = "brute-force"
    severity = Severity.HIGH

    def __init__(self, threshold=5, window=timedelta(minutes=10)):
        self.threshold = threshold
        self.window = window
        self._failures = defaultdict(deque)
        self._flagged = {}                             # ip -> alert
        self._breached = set()

    def process(self, event):
        if event.action != "login" or not event.src_ip:
            return []
        ip = event.src_ip
        if event.failed:
            q = self._failures[ip]
            q.append(event)
            while event.time - q[0].time > self.window:
                q.popleft()
            if len(q) >= self.threshold and ip not in self._flagged:
                users = sorted({e.user for e in q if e.user})
                self._flagged[ip] = self.alert(
                    event, f"{len(q)} failed logins from {ip} in "
                           f"{(event.time - q[0].time).seconds}s (users: {', '.join(users)})",
                    evidence=list(q))
                return [self._flagged[ip]]
        elif ip in self._flagged and ip not in self._breached:
            self._breached.add(ip)
            return [self.alert(event, f"{ip} logged in as {event.user!r} after a brute-force "
                                      f"attempt", Severity.CRITICAL, [event])]
        return []


class SuspiciousRequestRule(Rule):
    """Web requests that look like attacks."""
    name = "suspicious-request"
    severity = Severity.MEDIUM

    PATTERNS = re.compile(r"\.\./|/etc/passwd|\.env\b|wp-admin|union(\s|\+|%20)+select|<script",
                          re.IGNORECASE)

    def process(self, event):
        path = event.detail.get("path", "") if event.action == "http_request" else ""
        if self.PATTERNS.search(path):
            return [self.alert(event, f"{event.src_ip} requested {path}", evidence=[event])]
        return []


class LoginWithoutMFARule(Rule):
    """A successful cloud console login that didn't use MFA."""
    name = "login-without-mfa"
    severity = Severity.HIGH

    def process(self, event):
        if (event.source == "cloudtrail" and event.action == "login"
                and event.outcome == "success" and event.detail.get("mfa") == "No"):
            return [self.alert(event, f"{event.user} logged in from {event.src_ip} without MFA",
                               evidence=[event])]
        return []


class NewSourceIPRule(Rule):
    """A user logs in successfully from an IP they've never used before.

    The first login for each user only teaches the rule what's normal.
    """
    name = "new-source-ip"
    severity = Severity.LOW

    def __init__(self):
        self._seen = defaultdict(set)

    def process(self, event):
        if event.action != "login" or event.outcome != "success" or not event.user:
            return []
        known = self._seen[event.user]
        # bool() matters: `known and ...` would return the (empty) set ITSELF,
        # which the next line then fills, making it truthy. A real bug the
        # tests caught while this file was being written.
        new = bool(known) and event.src_ip not in known
        known.add(event.src_ip)
        if new:
            return [self.alert(event, f"{event.user} logged in from new IP {event.src_ip} "
                                      f"(known: {', '.join(sorted(known - {event.src_ip}))})",
                               evidence=[event])]
        return []


# ---------------------------------------------------------------
# 2. Duck typing
# ---------------------------------------------------------------
#
# "If it walks like a duck and quacks like a duck, it's a duck."
# Python doesn't check an object's CLASS before calling a method; it
# just calls it. So the engine accepts ANY object with process() and
# finish(), even one that doesn't inherit from Rule.
#
# You've relied on this already: open_log() in large_files.py returns a
# plain file, a gzip file or a bz2 file, and the code reading lines
# from it never knows which.

class KeywordRule:                                     # NOT a subclass of Rule
    """Quick, throwaway detection: any event whose raw line contains a keyword."""

    def __init__(self, keyword, severity=Severity.LOW):
        self.name = f"keyword:{keyword}"
        self.keyword = keyword
        self.severity = severity

    def process(self, event):
        if self.keyword in event.raw:
            return [Alert(event.time, self.name, self.severity, event.raw[:70], [event])]
        return []

    def finish(self):
        return []


# ---------------------------------------------------------------
# 3. Protocols
# ---------------------------------------------------------------
#
# A Protocol (typing module) WRITES DOWN what duck typing expects:
# "anything with these methods". Type checkers and editors use it to
# spot mistakes, and @runtime_checkable allows isinstance() checks.
# Unlike an ABC, classes don't have to inherit from it.

@runtime_checkable
class RuleLike(Protocol):
    name: str

    def process(self, event) -> list: ...

    def finish(self) -> list: ...


# ---------------------------------------------------------------
# 5. A Timeline that behaves like a built-in container
# ---------------------------------------------------------------
#
#   method          | makes this work
#   ----------------|--------------------------------------------
#   __len__         | len(timeline), and `if timeline:` (empty is False)
#   __iter__        | for event in timeline
#   __getitem__     | timeline[0], timeline[-1], timeline[2:5]
#   __contains__    | event in timeline
#   __add__         | timeline_a + timeline_b  (merged in time order)
#   __repr__        | a useful printout
#
# Events are kept sorted by time, so + can MERGE two timelines in
# O(n) with heapq.merge (sorting_algorithms.py), and between() can
# find a time range with binary search (binary_search.py).

class Timeline:
    def __init__(self, events=(), _already_sorted=False):
        self._events = list(events) if _already_sorted else sorted(events, key=attrgetter("time"))

    def __len__(self):
        return len(self._events)

    def __iter__(self):
        return iter(self._events)

    def __getitem__(self, index):
        if isinstance(index, slice):
            return Timeline(self._events[index], _already_sorted=True)
        return self._events[index]

    def __contains__(self, event):
        return event in self._events

    def __add__(self, other):
        if not isinstance(other, Timeline):
            return NotImplemented
        merged = heapq.merge(self._events, other._events, key=attrgetter("time"))
        return Timeline(merged, _already_sorted=True)

    def __repr__(self):
        if not self._events:
            return "Timeline(empty)"
        return (f"Timeline({len(self)} events, {self._events[0].time:%Y-%m-%d %H:%M:%S} to "
                f"{self._events[-1].time:%H:%M:%S})")

    def between(self, start, end):
        get_time = attrgetter("time")
        lo = bisect.bisect_left(self._events, start, key=get_time)
        hi = bisect.bisect_right(self._events, end, key=get_time)
        return self[lo:hi]

    @classmethod
    def from_lines(cls, lines, **parser_options):
        lines = list(lines)
        parser = detect_parser(lines, **parser_options)
        return cls(parser.parse(lines))


# ---------------------------------------------------------------
# 6. The detection engine
# ---------------------------------------------------------------
#
# The engine knows NOTHING about specific rules. It hands every event
# to every rule and collects what comes back. Adding a detection means
# adding a class to the list; the engine never changes.

class DetectionEngine:
    def __init__(self, rules):
        rules = list(rules)
        for rule in rules:
            if not isinstance(rule, RuleLike):
                raise TypeError(f"{rule!r} doesn't have process() and finish()")
        self.rules = rules

    def run(self, events):
        alerts = []
        for event in events:
            for rule in self.rules:
                alerts.extend(rule.process(event))
        for rule in self.rules:
            alerts.extend(rule.finish())
        return sorted(alerts, key=lambda a: (-a.severity, a.time))


# ---------------------------------------------------------------
# 7. Putting the series together
# ---------------------------------------------------------------

AUTH_LOG = [
    "Nov 27 10:15:02 web01 sshd[811]: Failed password for root from 198.51.100.7 port 51122 ssh2",
    "Nov 27 10:15:05 web01 sshd[812]: Failed password for root from 198.51.100.7 port 51124 ssh2",
    "Nov 27 10:15:09 web01 sshd[815]: Failed password for invalid user admin from 198.51.100.7 port 51130 ssh2",
    "Nov 27 10:15:12 web01 sshd[816]: Failed password for invalid user test from 198.51.100.7 port 51133 ssh2",
    "Nov 27 10:15:15 web01 sshd[817]: Failed password for root from 198.51.100.7 port 51135 ssh2",
    "Nov 27 10:15:31 web01 sshd[818]: Accepted password for root from 198.51.100.7 port 51140 ssh2",
    "Nov 27 09:00:00 web01 sshd[700]: Accepted publickey for alice from 192.0.2.10 port 50000 ssh2",
    "Nov 27 10:20:00 web01 sshd[901]: Accepted publickey for alice from 203.0.113.200 port 50100 ssh2",
]

ACCESS_LOG = [
    '203.0.113.9 - - [27/Nov/2026:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 1043 "-" "Mozilla/5.0"',
    '203.0.113.9 - - [27/Nov/2026:10:15:40 +0000] "GET /../../etc/passwd HTTP/1.1" 400 0 "-" "curl/8.4"',
    '203.0.113.9 - - [27/Nov/2026:10:15:41 +0000] "GET /.env HTTP/1.1" 404 153 "-" "curl/8.4"',
    '192.0.2.44 - - [27/Nov/2026:10:16:05 +0000] "GET /search?q=1+UNION+SELECT+password HTTP/1.1" 500 12 "-" "sqlmap/1.7"',
]

CLOUDTRAIL = [
    '{"eventTime": "2026-11-27T10:14:00Z", "eventName": "ConsoleLogin", "sourceIPAddress": "203.0.113.77", '
    '"userIdentity": {"userName": "carol"}, "responseElements": {"ConsoleLogin": "Success"}, '
    '"additionalEventData": {"MFAUsed": "No"}}',
    '{"eventTime": "2026-11-27T10:14:40Z", "eventName": "CreateAccessKey", "sourceIPAddress": "203.0.113.77", '
    '"userIdentity": {"userName": "carol"}}',
]


def default_rules():
    return [BruteForceRule(threshold=5, window=timedelta(minutes=1)), SuspiciousRequestRule(),
            LoginWithoutMFARule(), NewSourceIPRule()]


def section_7():
    timeline = (Timeline.from_lines(AUTH_LOG, year=2026) + Timeline.from_lines(ACCESS_LOG)
                + Timeline.from_lines(CLOUDTRAIL))
    print("  ", timeline)
    print("   first event:", timeline[0].source, timeline[0].time.time(), "| last:", timeline[-1].source)
    window = timeline.between(datetime(2026, 11, 27, 10, 15, tzinfo=timezone.utc),
                              datetime(2026, 11, 27, 10, 16, tzinfo=timezone.utc))
    print(f"   10:15-10:16: {len(window)} events from {sorted({e.source for e in window})}")

    rules = default_rules() + [KeywordRule("sqlmap", Severity.MEDIUM)]
    alerts = DetectionEngine(rules).run(timeline)
    print(f"\n   {len(alerts)} alerts from {len(rules)} rules over {len(timeline)} events:")
    for a in alerts:
        print("  ", a)


# ---------------------------------------------------------------
# 8. Practice
# ---------------------------------------------------------------
#
# Write a PortScanRule for firewall events (inheritance.py's practice
# parser) yourself first, then compare:
#   - one src_ip DENIED on `ports` or more DIFFERENT destination ports
#     within `window` -> one MEDIUM alert for that IP
#   - nothing else needs changing: the engine runs it like any rule

class PortScanRule(Rule):
    name = "port-scan"
    severity = Severity.MEDIUM

    def __init__(self, ports=10, window=timedelta(minutes=1)):
        self.ports = ports
        self.window = window
        self._recent = defaultdict(deque)               # ip -> (time, port) in the window
        self._flagged = set()

    def process(self, event):
        if event.source != "firewall" or not event.failed or event.src_ip in self._flagged:
            return []
        q = self._recent[event.src_ip]
        q.append((event.time, event.detail["dst_port"]))
        while event.time - q[0][0] > self.window:
            q.popleft()
        distinct = {port for _, port in q}
        if len(distinct) >= self.ports:
            self._flagged.add(event.src_ip)
            return [self.alert(event, f"{event.src_ip} probed {len(distinct)} ports in "
                                      f"{(event.time - q[0][0]).seconds}s")]
        return []


def run_tests():
    utc = timezone.utc
    t0 = datetime(2026, 11, 27, 10, 0, tzinfo=utc)

    def login(seconds, ip, outcome, user="root", source="sshd", **detail):
        return LogEvent(t0 + timedelta(seconds=seconds), source, "login", outcome,
                        user=user, src_ip=ip, detail=detail)

    # Severity is ordered and prints nicely
    assert Severity.CRITICAL > Severity.HIGH > Severity.LOW
    assert str(Severity.HIGH) == "high" and sorted([Severity.HIGH, Severity.LOW])[0] is Severity.LOW

    # Brute force: alert once at the threshold, then CRITICAL on success
    rule = BruteForceRule(threshold=3, window=timedelta(seconds=30))
    out = []
    for s in (0, 5, 10, 12):
        out += rule.process(login(s, "1.2.3.4", "failure"))
    out += rule.process(login(20, "1.2.3.4", "success"))
    out += rule.process(login(25, "1.2.3.4", "success"))             # no second CRITICAL
    assert [a.severity for a in out] == [Severity.HIGH, Severity.CRITICAL]
    assert len(out[0].evidence) == 3

    # ...but slow failures outside the window don't count
    rule = BruteForceRule(threshold=3, window=timedelta(seconds=30))
    assert not any(rule.process(login(s, "1.2.3.4", "failure")) for s in (0, 40, 80, 120))

    # ...and it works across log SOURCES, because events share one format
    rule = BruteForceRule(threshold=2, window=timedelta(minutes=1))
    rule.process(login(0, "9.9.9.9", "failure", source="sshd"))
    assert rule.process(login(5, "9.9.9.9", "failure", source="cloudtrail"))

    # New source IP: first login only learns
    rule = NewSourceIPRule()
    assert rule.process(login(0, "10.0.0.1", "success", "alice")) == []
    assert rule.process(login(1, "10.0.0.1", "success", "alice")) == []
    assert len(rule.process(login(2, "10.0.0.2", "success", "alice"))) == 1
    assert rule.process(login(3, "10.0.0.9", "success", "bob")) == []   # bob's first

    # Duck typing and the Protocol
    assert isinstance(KeywordRule("x"), RuleLike) and not issubclass(KeywordRule, Rule)
    assert isinstance(BruteForceRule(), RuleLike)
    try:
        DetectionEngine([object()])
        assert False
    except TypeError:
        pass

    # Timeline container behaviour
    a = Timeline([login(30, "a", "failure"), login(10, "a", "failure")])
    b = Timeline([login(20, "b", "failure")])
    merged = a + b
    assert len(merged) == 3 and [e.src_ip for e in merged] == ["a", "b", "a"]
    assert merged[0].time < merged[1].time < merged[2].time
    assert isinstance(merged[1:], Timeline) and len(merged[1:]) == 2
    assert merged[0] in merged and login(99, "z", "failure") not in merged
    assert not Timeline() and bool(merged)
    assert len(merged.between(t0 + timedelta(seconds=15), t0 + timedelta(seconds=30))) == 2
    try:
        merged + [1, 2]
        assert False
    except TypeError:
        pass

    # The whole pipeline
    timeline = (Timeline.from_lines(AUTH_LOG, year=2026) + Timeline.from_lines(ACCESS_LOG)
                + Timeline.from_lines(CLOUDTRAIL))
    assert len(timeline) == len(AUTH_LOG) + len(ACCESS_LOG) + len(CLOUDTRAIL)
    times = [e.time for e in timeline]
    assert times == sorted(times)
    alerts = DetectionEngine(default_rules()).run(timeline)
    by_rule = defaultdict(list)
    for alert in alerts:
        by_rule[alert.rule].append(alert)
    assert alerts[0].severity is Severity.CRITICAL and "198.51.100.7" in alerts[0].summary
    assert len(by_rule["brute-force"]) == 2
    assert len(by_rule["suspicious-request"]) == 3                 # passwd, .env, UNION SELECT
    assert "carol" in by_rule["login-without-mfa"][0].summary
    new_ip = by_rule["new-source-ip"]
    assert len(new_ip) == 1 and "203.0.113.200" in new_ip[0].summary
    assert [a.severity for a in alerts] == sorted((a.severity for a in alerts), reverse=True)

    # Practice: the port-scan rule, fed by the firewall parser, needs no engine changes
    fw_lines = [f"2026-11-27T10:00:{i:02d}Z DENY TCP 198.51.100.66:4{i:04d} -> 10.0.0.5:{port}"
                for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389])]
    fw_lines.append("2026-11-27T10:00:30Z DENY TCP 192.0.2.1:5000 -> 10.0.0.5:22")
    alerts = DetectionEngine([PortScanRule(ports=10)]).run(Timeline.from_lines(fw_lines))
    assert len(alerts) == 1 and "198.51.100.66" in alerts[0].summary
    assert alerts[0].severity is Severity.MEDIUM

    print("All tests passed!")


if __name__ == "__main__":
    print("\n--- 4. Severity ---")
    print("  ", list(Severity), "| HIGH > MEDIUM:", Severity.HIGH > Severity.MEDIUM)
    print("\n--- 2-3. Duck typing and protocols ---")
    print("   KeywordRule is a Rule subclass?", issubclass(KeywordRule, Rule),
          "| but matches RuleLike?", isinstance(KeywordRule("x"), RuleLike))
    print("\n--- 5-7. Timeline, engine, and everything together ---")
    section_7()
    print()
    run_tests()
