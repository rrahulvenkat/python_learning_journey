"""Rules, alerts, the Timeline and the DetectionEngine.

Every rule has process(event) -> alerts and finish() -> alerts. The
engine hands every event to every rule and never needs to know which
rules exist, so adding a detection means adding a class. The design is
copied from python_learning_journey/oop/polymorphism.py, where it's explained step by step.
"""

import bisect
import heapq
import re
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import IntEnum
from operator import attrgetter
from typing import Protocol, runtime_checkable

from .parsers import detect_parser

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


class Rule(ABC):
    name = "rule"
    severity = Severity.LOW

    @abstractmethod
    def process(self, event):
        """Look at one event; return a (possibly empty) list of Alerts."""

    def finish(self):
        return []

    def alert(self, event, summary, severity=None, evidence=()):
        # With no evidence given, keep the event that triggered the alert,
        # so later steps (correlation.py) always know which user and IP
        # it's about.
        return Alert(event.time, self.name, severity or self.severity, summary,
                     list(evidence) or [event])


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
                # Some logs don't say which user was tried (a web login form)
                tried = f" (users: {', '.join(users)})" if users else ""
                self._flagged[ip] = self.alert(
                    event, f"{len(q)} failed logins from {ip} in "
                           f"{(event.time - q[0].time).seconds}s{tried}",
                    evidence=list(q))
                return [self._flagged[ip]]
        elif ip in self._flagged and ip not in self._breached:
            self._breached.add(ip)
            who = f" as {event.user!r}" if event.user else ""
            return [self.alert(event, f"{ip} logged in{who} after a brute-force attempt",
                               Severity.CRITICAL, [event])]
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


@runtime_checkable
class RuleLike(Protocol):
    name: str

    def process(self, event) -> list: ...

    def finish(self) -> list: ...


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


def default_rules():
    return [BruteForceRule(threshold=5, window=timedelta(minutes=1)), SuspiciousRequestRule(),
            LoginWithoutMFARule(), NewSourceIPRule()]
