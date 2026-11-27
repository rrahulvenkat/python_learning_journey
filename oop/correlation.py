# Correlation: turning many alerts into a few incidents
#
# Rules look at ONE event (or one entity) at a time, so a real attack
# shows up as a scatter of separate alerts: a brute-force alert on an
# IP, a login-without-MFA alert on a user, a sensitive-action alert in
# the cloud. CORRELATION joins the alerts that belong to the same
# story into one INCIDENT, scores it, and says why it matters. This is
# what lets an analyst look at 5 incidents instead of 500 alerts.
#
# Topics covered here:
#   1. Entities: which users and IPs an alert is about
#   2. Linking alerts that share entities, even indirectly
#      (union-find, from number_of_islands.py)
#   3. Splitting by time: the same user a week later is a new story
#   4. Risk-based scoring: many small signals add up
#   5. MITRE ATT&CK: labelling WHAT kind of behaviour each alert shows
#   6. Sequences: steps that happen IN ORDER (an "is subsequence"
#      check, the two-pointer idea from palindrome.py)
#   7. The Incident class, and putting it all together
#   8. Practice, with tests
#
# SECURITY CONNECTION
# -------------------
# SIEMs call this correlation searches, risk-based alerting (Splunk
# RBA), or "incidents" built from alerts (Microsoft Sentinel, Elastic).
# Sigma's correlation rules express the same ideas: "event_count",
# "value_count" and "temporal" (ordered) correlations.
#
# The ATT&CK technique IDs below are real (attack.mitre.org), so
# incidents can be compared with threat reports and detection
# coverage maps.


from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from baseline_rules import LoginVolumeRule, UnusualHourRule, make_history
from classes_and_objects import LogEvent
from polymorphism import Alert, DetectionEngine, Rule, Severity, Timeline, default_rules


# ---------------------------------------------------------------
# A rule this file needs: sensitive cloud actions
# ---------------------------------------------------------------
#
# Creating access keys, giving out admin rights, or turning off logging
# are normal admin work AND what attackers do right after getting in
# (to keep access and cover their tracks). Alone they're worth a look;
# after a suspicious login they're serious (section 6).

class SensitiveCloudActionRule(Rule):
    name = "cloud-sensitive-action"
    severity = Severity.MEDIUM

    ACTIONS = {
        "CreateAccessKey": Severity.MEDIUM,
        "CreateUser": Severity.MEDIUM,
        "AttachUserPolicy": Severity.MEDIUM,
        "StopLogging": Severity.HIGH,                 # turning off the audit trail
        "DeleteTrail": Severity.HIGH,
    }

    def process(self, event):
        if event.source != "cloudtrail" or event.action not in self.ACTIONS:
            return []
        return [self.alert(event, f"{event.user} ran {event.action} from {event.src_ip}",
                           self.ACTIONS[event.action])]


def all_rules():
    return default_rules() + [LoginVolumeRule(), UnusualHourRule(), SensitiveCloudActionRule()]


# ---------------------------------------------------------------
# 1. Entities
# ---------------------------------------------------------------
#
# An alert's entities are the users and IPs in its evidence events,
# written as "user:alice" and "ip:203.0.113.200" so a user and an IP
# that happen to share a name can't be confused.
#
# Some entities are too common to link on: a shared NAT address that
# every employee appears behind would glue unrelated alerts together.
# `ignore` lists those.

def entities_of(alert, ignore=frozenset()):
    found = set()
    for event in alert.evidence:
        if event.user:
            found.add(f"user:{event.user}")
        if event.src_ip:
            found.add(f"ip:{event.src_ip}")
    return found - ignore


# ---------------------------------------------------------------
# 2. Linking alerts that share entities
# ---------------------------------------------------------------
#
#   alert A  entities {ip:198.51.100.7}                 (brute force)
#   alert B  entities {ip:198.51.100.7, user:root}      (then logged in)
#   alert C  entities {user:root}                       (unusual hour)
#
# A and C share nothing directly, but A-B share the IP and B-C share
# the user, so all three are one story. That's "connected components",
# solved here with union-find: each entity starts in its own group,
# and every alert MERGES the groups of all its entities.

class UnionFind:
    def __init__(self):
        self.parent = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]      # path compression
            x = self.parent[x]
        return x

    def union(self, a, b):
        self.parent[self.find(b)] = self.find(a)


def link_alerts(alerts, ignore=frozenset()):
    """Group alerts that share entities, directly or through other alerts."""
    uf = UnionFind()
    keyed = []
    for alert in alerts:
        ents = sorted(entities_of(alert, ignore))
        if not ents:
            ents = [f"alert:{id(alert)}"]                     # stands alone
        for other in ents[1:]:
            uf.union(ents[0], other)
        keyed.append((alert, ents[0]))

    groups = defaultdict(list)
    for alert, key in keyed:
        groups[uf.find(key)].append(alert)
    return list(groups.values())


# ---------------------------------------------------------------
# 3. Splitting by time
# ---------------------------------------------------------------
#
# Alerts about alice today and alice next month are probably different
# stories. Within each linked group, sort by time and start a new
# incident whenever the GAP since the previous alert is longer than
# `max_gap`. (The same "consecutive items" idea as merge_intervals.py.)

def split_by_gap(alerts, max_gap):
    alerts = sorted(alerts, key=lambda a: a.time)
    chunks, current = [], []
    for alert in alerts:
        if current and alert.time - current[-1].time > max_gap:
            chunks.append(current)
            current = []
        current.append(alert)
    if current:
        chunks.append(current)
    return chunks


# ---------------------------------------------------------------
# 4. Risk-based scoring
# ---------------------------------------------------------------
#
# Each alert adds RISK points to its incident, by severity. Repeats of
# the SAME rule add less each time (one noisy rule firing 50 times
# shouldn't outweigh three different rules each firing once), and
# covering several DIFFERENT ATT&CK tactics adds a bonus, because
# attacks move through stages.
#
#   severity  | points (first time, then halved for each repeat)
#   ----------|-------
#   LOW       | 10
#   MEDIUM    | 25
#   HIGH      | 50
#   CRITICAL  | 100

POINTS = {Severity.LOW: 10, Severity.MEDIUM: 25, Severity.HIGH: 50, Severity.CRITICAL: 100}


def risk_score(alerts):
    seen = defaultdict(int)
    score = 0.0
    for alert in sorted(alerts, key=lambda a: a.time):
        repeats = seen[alert.rule]
        score += POINTS[alert.severity] / (2 ** repeats)
        seen[alert.rule] += 1
    tactics = {technique_of(a.rule)[1] for a in alerts}
    score += 15 * (len(tactics) - 1)
    return round(score)


def severity_for(score):
    if score >= 150:
        return Severity.CRITICAL
    if score >= 80:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    return Severity.LOW


# ---------------------------------------------------------------
# 5. MITRE ATT&CK labels
# ---------------------------------------------------------------
#
# ATT&CK is a public catalogue of attacker behaviour. TACTICS are the
# goals (Credential Access, Persistence...), TECHNIQUES are how
# (T1110 Brute Force...). Labelling each rule makes an incident read
# like a story: "Credential Access -> Initial Access -> Persistence ->
# Defense Evasion".

ATTACK = {
    "brute-force":            ("T1110", "Credential Access", "Brute Force"),
    "suspicious-request":     ("T1190", "Initial Access", "Exploit Public-Facing Application"),
    "login-without-mfa":      ("T1078.004", "Initial Access", "Valid Accounts: Cloud Accounts"),
    "new-source-ip":          ("T1078", "Initial Access", "Valid Accounts"),
    "unusual-hour":           ("T1078", "Initial Access", "Valid Accounts"),
    "login-volume":           ("T1078", "Initial Access", "Valid Accounts"),
    "port-scan":              ("T1046", "Discovery", "Network Service Discovery"),
    "cloud-sensitive-action": ("T1098", "Persistence", "Account Manipulation"),
}
DEFENSE_EVASION = ("T1562.008", "Defense Evasion", "Impair Defenses: Disable or Modify Cloud Logs")


def technique_of(rule_name, alert=None):
    if alert is not None and rule_name == "cloud-sensitive-action" and \
            any(e.action in ("StopLogging", "DeleteTrail") for e in alert.evidence):
        return DEFENSE_EVASION
    return ATTACK.get(rule_name, ("-", "Unknown", rule_name))


# ---------------------------------------------------------------
# 6. Sequences
# ---------------------------------------------------------------
#
# Some combinations only matter IN ORDER. "Suspicious login, THEN a
# sensitive cloud action" is the classic account takeover; the
# reverse order is usually an admin who then logged in oddly.
#
# A pattern is a list of STEPS; each step is a set of rule names that
# count for it. It matches if the incident's alerts, in time order,
# contain the steps as a SUBSEQUENCE (in order, other alerts allowed in
# between), all within `within`. That's the two-pointer "is
# subsequence" check (LeetCode 392): walk the alerts once, moving to the
# next step whenever the current one is satisfied.

SUSPICIOUS_LOGIN = {"brute-force", "login-without-mfa", "new-source-ip", "unusual-hour"}


@dataclass(frozen=True)
class SequencePattern:
    name: str
    steps: tuple
    within: timedelta

    def matches(self, alerts):
        alerts = sorted(alerts, key=lambda a: a.time)
        for start, first in enumerate(alerts):          # try each possible starting alert
            if first.rule not in self.steps[0]:
                continue
            step = 1
            for alert in alerts[start + 1:]:
                if alert.time - first.time > self.within:
                    break
                if step < len(self.steps) and alert.rule in self.steps[step]:
                    step += 1
            if step == len(self.steps):
                return True
        return False


PATTERNS = [
    SequencePattern("account takeover then persistence",
                    (SUSPICIOUS_LOGIN, {"cloud-sensitive-action"}), timedelta(hours=1)),
]


# ---------------------------------------------------------------
# 7. The Incident class
# ---------------------------------------------------------------

@dataclass
class Incident:
    alerts: list
    entities: set
    score: int
    severity: Severity
    sequences: list = field(default_factory=list)

    @property
    def start(self):
        return self.alerts[0].time

    @property
    def end(self):
        return self.alerts[-1].time

    @property
    def tactics(self):
        ordered = []
        for alert in self.alerts:
            tactic = technique_of(alert.rule, alert)[1]
            if tactic not in ordered:
                ordered.append(tactic)
        return ordered

    @property
    def techniques(self):
        return sorted({technique_of(a.rule, a)[0] for a in self.alerts})

    @property
    def hosts(self):
        return sorted({e.host for a in self.alerts for e in a.evidence if e.host})

    def report(self):
        who = ", ".join(sorted(self.entities)) or "no user or IP recorded"
        lines = [f"[{str(self.severity).upper()}] score {self.score} | "
                 f"{self.start:%Y-%m-%d %H:%M}-{self.end:%H:%M} | {who}",
                 f"  story:      {' -> '.join(self.tactics)}",
                 f"  techniques: {', '.join(self.techniques)}"]
        if self.hosts:
            lines.append(f"  hosts:      {', '.join(self.hosts)}")
        if self.sequences:
            lines.append(f"  sequence:   {'; '.join(self.sequences)}")
        for alert in self.alerts:
            lines.append(f"    {alert.time:%H:%M:%S} {str(alert.severity):<8} {alert.summary}")
        return "\n".join(lines)


class Correlator:
    def __init__(self, max_gap=timedelta(hours=2), patterns=PATTERNS, ignore=frozenset()):
        self.max_gap = max_gap
        self.patterns = patterns
        self.ignore = frozenset(ignore)

    def correlate(self, alerts):
        incidents = []
        for group in link_alerts(alerts, self.ignore):
            for chunk in split_by_gap(group, self.max_gap):
                score = risk_score(chunk)
                severity = severity_for(score)
                matched = [p.name for p in self.patterns if p.matches(chunk)]
                if matched:
                    severity = max(severity, Severity.HIGH)     # an ordered chain is never minor
                if any(a.severity is Severity.CRITICAL for a in chunk):
                    severity = Severity.CRITICAL
                ents = set().union(*(entities_of(a, self.ignore) for a in chunk))
                incidents.append(Incident(chunk, ents, score, severity, matched))
        return sorted(incidents, key=lambda i: (-i.severity, -i.score, i.start))


# ---------------------------------------------------------------
# Demo data: three weeks of normal logins (baseline_rules.py) plus,
# on the last day, a cloud account takeover and a web scanner.
# ---------------------------------------------------------------

LAST_DAY = datetime(2026, 11, 26, tzinfo=timezone.utc)


def cloud_attack():
    t = LAST_DAY + timedelta(hours=14)
    ip = "203.0.113.77"
    events = [LogEvent(t + timedelta(seconds=8 * i), "cloudtrail", "login", "failure",
                       user="carol", src_ip=ip, detail={"event": "ConsoleLogin"})
              for i in range(6)]
    events.append(LogEvent(t + timedelta(minutes=2), "cloudtrail", "login", "success",
                           user="carol", src_ip=ip, detail={"event": "ConsoleLogin", "mfa": "No"}))
    for minutes, action in ((6, "CreateAccessKey"), (9, "AttachUserPolicy"), (12, "StopLogging")):
        events.append(LogEvent(t + timedelta(minutes=minutes), "cloudtrail", action, "success",
                               user="carol", src_ip=ip, detail={"event": action}))
    return events


def web_scanner():
    t = LAST_DAY + timedelta(hours=16)
    return [LogEvent(t + timedelta(seconds=s), "apache", "http_request", "failure",
                     src_ip="192.0.2.44", detail={"path": path, "status": 404})
            for s, path in ((0, "/.env"), (3, "/wp-admin/"), (6, "/../../etc/passwd"))]


def build_scenario():
    return make_history() + Timeline(cloud_attack()) + Timeline(web_scanner())


# ---------------------------------------------------------------
# 8. Practice and tests
# ---------------------------------------------------------------
#
# Practice: add a pattern for "port scan, then a suspicious web
# request from the same IP, within 30 minutes" (reconnaissance then
# exploitation), and a test that it matches. Solution in the tests.

def alert_at(minutes, rule, severity, user=None, ip=None):
    t = LAST_DAY + timedelta(minutes=minutes)
    event = LogEvent(t, "test", "login", "success", user=user, src_ip=ip)
    return Alert(t, rule, severity, f"{rule} {user or ''} {ip or ''}".strip(), [event])


def run_tests():
    L, M, H, C = Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL

    # Entities and indirect linking
    a = alert_at(0, "brute-force", H, ip="1.1.1.1")
    b = alert_at(1, "brute-force", C, user="root", ip="1.1.1.1")
    c = alert_at(5, "unusual-hour", M, user="root")
    d = alert_at(6, "suspicious-request", M, ip="9.9.9.9")
    groups = sorted(link_alerts([a, b, c, d]), key=len)
    assert [len(g) for g in groups] == [1, 3]
    assert entities_of(b) == {"user:root", "ip:1.1.1.1"}

    # A shared NAT IP shouldn't glue two users together
    x = alert_at(0, "unusual-hour", M, user="alice", ip="10.0.0.1")
    y = alert_at(1, "unusual-hour", M, user="bob", ip="10.0.0.1")
    assert len(link_alerts([x, y])) == 1
    assert len(link_alerts([x, y], ignore={"ip:10.0.0.1"})) == 2

    # Splitting by time
    far = alert_at(60 * 24 * 3, "unusual-hour", M, user="root")      # three days later
    assert [len(chunk) for chunk in split_by_gap([a, b, c, far], timedelta(hours=2))] == [3, 1]

    # Scoring: repeats of one rule count less than different rules
    noisy = [alert_at(i, "unusual-hour", M, user="u") for i in range(10)]
    varied = [alert_at(0, "unusual-hour", M, user="u"), alert_at(1, "login-volume", M, user="u"),
              alert_at(2, "new-source-ip", L, user="u")]
    assert risk_score(noisy) <= 2 * POINTS[M]                        # 25 + 12.5 + 6.25 ... never passes 50
    assert risk_score(varied) == 25 + 25 + 10
    takeover = [alert_at(0, "login-without-mfa", H, user="u"),
                alert_at(5, "cloud-sensitive-action", M, user="u")]
    assert risk_score(takeover) == 50 + 25 + 15                      # two tactics: +15

    # Sequences: order matters, and so does the time limit
    takeover_pattern = PATTERNS[0]
    assert takeover_pattern.matches(takeover)
    assert not takeover_pattern.matches([alert_at(0, "cloud-sensitive-action", M, user="u"),
                                         alert_at(5, "login-without-mfa", H, user="u")])
    assert not takeover_pattern.matches([alert_at(0, "login-without-mfa", H, user="u"),
                                         alert_at(90, "cloud-sensitive-action", M, user="u")])
    assert takeover_pattern.matches([alert_at(0, "unusual-hour", M, user="u"),     # other alerts
                                     alert_at(1, "login-volume", M, user="u"),     # in between
                                     alert_at(2, "cloud-sensitive-action", M, user="u")])

    # Practice: recon then exploitation
    recon = SequencePattern("recon then exploitation", ({"port-scan"}, {"suspicious-request"}),
                            timedelta(minutes=30))
    assert recon.matches([alert_at(0, "port-scan", M, ip="5.5.5.5"),
                          alert_at(10, "suspicious-request", M, ip="5.5.5.5")])
    assert not recon.matches([alert_at(0, "suspicious-request", M, ip="5.5.5.5"),
                              alert_at(10, "port-scan", M, ip="5.5.5.5")])

    # The whole scenario
    alerts = DetectionEngine(all_rules()).run(build_scenario())
    incidents = Correlator().correlate(alerts)
    by_entity = {frozenset(i.entities): i for i in incidents}

    carol = by_entity[frozenset({"user:carol", "ip:203.0.113.77"})]
    assert carol.severity is Severity.CRITICAL
    assert "account takeover then persistence" in carol.sequences
    assert carol.tactics == ["Credential Access", "Initial Access", "Persistence", "Defense Evasion"]
    assert {"T1110", "T1078.004", "T1098", "T1562.008"} <= set(carol.techniques)

    alice = by_entity[frozenset({"user:alice", "ip:203.0.113.200"})]
    assert len(alice.alerts) == 3 and alice.severity >= Severity.MEDIUM

    scanner = by_entity[frozenset({"ip:192.0.2.44"})]
    assert len(scanner.alerts) == 3                                  # .env, wp-admin, passwd
    assert scanner.severity is Severity.MEDIUM                       # one rule repeating: capped

    assert incidents[0] is carol                                     # the worst comes first
    assert len(incidents) < len(alerts)

    print("All tests passed!")


if __name__ == "__main__":
    alerts = DetectionEngine(all_rules()).run(build_scenario())
    incidents = Correlator().correlate(alerts)
    print(f"{len(alerts)} alerts correlated into {len(incidents)} incidents:\n")
    for incident in incidents:
        print(incident.report())
        print()
    run_tests()
