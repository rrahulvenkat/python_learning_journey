# Baseline Rules: anomaly detection as plug-in rule classes
#
# fundamentals/statistics_and_baselines.py taught the statistics
# (robust z-scores, per-entity baselines, active hours). polymorphism.py
# built a detection engine that runs any Rule. This file joins them:
# two new Rule subclasses, and the engine runs them alongside the
# signature rules WITHOUT CHANGING (the point of polymorphism).
#
#   rule              | flags                                         | severity
#   ------------------|-----------------------------------------------|---------
#   LoginVolumeRule   | a user's logins in one day far above THEIR    | MEDIUM
#                     | normal (robust z-score)                       |
#   UnusualHourRule   | a successful login in an hour the user rarely | MEDIUM
#                     | or never uses                                 |
#
# Both need a LEARNING period per user before they say anything, and
# neither learns from activity it has flagged (so an attack can't
# become the new normal).
#
# LoginVolumeRule shows why Rule.finish() exists: a day's count is only
# known once the day is over, and the LAST day only ends when the
# events run out.


import random
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

from classes_and_objects import LogEvent
from polymorphism import DetectionEngine, Rule, Severity, Timeline, default_rules

# Reuse the statistics from the fundamentals folder. Python only looks
# for imports in this script's own folder (and installed packages), so
# add the other folder to the search path. In a bigger project you'd
# turn the repo into a PACKAGE (folders with __init__.py, installed
# with `pip install -e .`) so imports work from anywhere without this.
sys.path.append(str(Path(__file__).resolve().parent.parent / "fundamentals"))
from statistics_and_baselines import active_hours, robust_z      # noqa: E402


class LoginVolumeRule(Rule):
    name = "login-volume"
    severity = Severity.MEDIUM

    def __init__(self, min_days=7, cutoff=3.5, max_days=60):
        self.min_days = min_days
        self.cutoff = cutoff
        self._history = defaultdict(lambda: deque(maxlen=max_days))   # user -> daily counts
        self._day = None
        self._today = Counter()
        self._last_event = {}

    def process(self, event):
        if event.action != "login" or not event.user:
            return []
        day = event.time.date()
        alerts = []
        if self._day is not None and day != self._day:
            alerts = self._close_day()
        self._day = day
        self._today[event.user] += 1
        self._last_event[event.user] = event
        return alerts

    def finish(self):
        return self._close_day() if self._day is not None else []

    def _close_day(self):
        alerts = []
        for user, count in self._today.items():
            past = self._history[user]
            if len(past) >= self.min_days:
                score = robust_z(count, past)
                if score > self.cutoff:
                    alerts.append(self.alert(
                        self._last_event[user],
                        f"{user} had {count} logins on {self._day}, usually about "
                        f"{sorted(past)[len(past) // 2]} (robust z {score:.1f})"))
                    continue                          # don't learn from the anomaly
            past.append(count)
        self._today.clear()
        return alerts


class UnusualHourRule(Rule):
    """A successful login in an hour this user rarely or never uses.

    Two lessons from writing it (the first version flooded 5,000+ alerts):
      - The learning period is measured in DAYS, not logins. Events
        arrive in time order, so "the first 30 logins" of a busy account
        all fall in the small hours of day one, and every later hour
        then looks unusual.
      - It learns from EVERY login, flagged or not, so a real change in
        someone's schedule becomes normal over time, and it alerts at
        most once per user, day and hour. (LoginVolumeRule does the
        opposite and refuses to learn from anomalies. Which is right
        depends on whether a mistake means "missed attack" or "endless
        noise".)
      - Gaps INSIDE the usual span count as usual. A user with only 3
        logins a day may, by chance, have used 11:00 just once in three
        weeks (under the 2% share), and flagging 11:26 as odd for an
        08:00-17:00 worker is pure noise. (Limitation: a night shift
        that wraps past midnight, like 22:00-06:00, would need the span
        worked out on a 24-hour circle; this simple version doesn't.)
    """
    name = "unusual-hour"
    severity = Severity.MEDIUM

    def __init__(self, min_days=7, min_share=0.02):
        self.min_days = min_days
        self.min_share = min_share
        self._hours = defaultdict(list)               # user -> hours of past logins
        self._days = defaultdict(set)                 # user -> days seen
        self._alerted = set()                         # (user, date, hour)

    def process(self, event):
        if event.action != "login" or event.outcome != "success" or not event.user:
            return []
        user, hour, day = event.user, event.time.hour, event.time.date()
        past = self._hours[user]
        alerts = []
        if len(self._days[user]) >= self.min_days:
            busy = active_hours(past, self.min_share)
            usual = set(range(min(busy), max(busy) + 1))      # fill gaps in the span
            if hour not in usual and (user, day, hour) not in self._alerted:
                self._alerted.add((user, day, hour))
                alerts.append(self.alert(
                    event, f"{user} logged in at {event.time:%H:%M}, outside their usual "
                           f"hours ({min(usual):02d}:00-{max(usual):02d}:59)"))
        past.append(hour)
        self._days[user].add(day)
        return alerts


# ---------------------------------------------------------------
# Demo data: three weeks of normal logins, then one odd day
# ---------------------------------------------------------------
#
#   alice        office worker, ~10 logins a day, 09:00-17:59
#   bob          ~3 logins a day, 08:00-16:59
#   svc-backup   ~300 logins a day, at every hour (normal for it)
#
# On the last day, alice's account logs in 45 times, including at
# 03:12 from an IP she's never used.

START = datetime(2026, 11, 6, tzinfo=timezone.utc)


def make_history(days=21, seed=7):
    rng = random.Random(seed)
    events = []

    def login(when, user, ip):
        return LogEvent(when, "sshd", "login", "success", user=user, src_ip=ip, host="web01")

    for d in range(days - 1):
        day = START + timedelta(days=d)
        for _ in range(rng.randint(8, 12)):
            events.append(login(day + timedelta(hours=rng.randint(9, 17), minutes=rng.randint(0, 59)),
                                "alice", "192.0.2.10"))
        for _ in range(rng.randint(2, 4)):
            events.append(login(day + timedelta(hours=rng.randint(8, 16), minutes=rng.randint(0, 59)),
                                "bob", "192.0.2.11"))
        for _ in range(rng.randint(290, 310)):
            events.append(login(day + timedelta(minutes=rng.randint(0, 24 * 60 - 1)),
                                "svc-backup", "10.0.0.20"))

    last = START + timedelta(days=days - 1)
    events.append(login(last + timedelta(hours=3, minutes=12), "alice", "203.0.113.200"))
    for i in range(44):
        events.append(login(last + timedelta(hours=3, minutes=13 + i), "alice", "203.0.113.200"))
    events.append(login(last + timedelta(hours=10), "bob", "192.0.2.11"))
    for _ in range(300):
        events.append(login(last + timedelta(minutes=rng.randint(0, 24 * 60 - 1)),
                            "svc-backup", "10.0.0.20"))
    return Timeline(events)


def run_tests():
    timeline = make_history()
    alerts = DetectionEngine([LoginVolumeRule(), UnusualHourRule()]).run(timeline)
    by_rule = Counter(a.rule for a in alerts)

    # Only alice is flagged: svc-backup's 300 a day is normal FOR IT
    assert {a.summary.split()[0] for a in alerts} == {"alice"}
    assert by_rule["login-volume"] == 1                         # found by finish()
    assert by_rule["unusual-hour"] == 1                         # once per user, day and hour
    assert "03:12" in [a for a in alerts if a.rule == "unusual-hour"][0].summary

    # finish() matters: without it the last day is never judged
    rule = LoginVolumeRule()
    out = []
    for event in timeline:
        out += rule.process(event)
    assert out == []
    assert len(rule.finish()) == 1

    # Learning periods: nothing is said before there's enough history
    early = Timeline(e for e in timeline if e.time < START + timedelta(days=3))
    assert DetectionEngine([LoginVolumeRule(), UnusualHourRule()]).run(early) == []

    # Flagged days aren't learned: the same spike tomorrow is flagged again
    vol = LoginVolumeRule(min_days=3)
    day = lambda n: START + timedelta(days=n, hours=10)
    events = []
    for n, count in enumerate([5, 6, 5, 50, 50]):
        events += [LogEvent(day(n), "sshd", "login", "success", user="u")] * count
    flagged = DetectionEngine([vol]).run(events)
    assert len(flagged) == 2

    # The baseline rules run next to the signature rules, engine unchanged
    combined = DetectionEngine(default_rules() + [LoginVolumeRule(), UnusualHourRule()])
    names = {a.rule for a in combined.run(timeline)}
    assert {"login-volume", "unusual-hour", "new-source-ip"} <= names

    print("All tests passed!")


if __name__ == "__main__":
    timeline = make_history()
    print(timeline)

    rules = default_rules() + [LoginVolumeRule(), UnusualHourRule()]
    alerts = DetectionEngine(rules).run(timeline)
    print(f"\n{len(alerts)} alerts from {len(rules)} rules:")
    for a in alerts:
        print(" ", a)
    print("\nThree weak signals about one account on one night. Separately each is a LOW or")
    print("MEDIUM alert; together (new IP + 03:12 + 4x the usual logins) they're an incident.")

    print()
    run_tests()
