# Classes and Objects
#
# A CLASS is a blueprint: it says what data something holds and what
# it can do. An OBJECT (or "instance") is one thing built from that
# blueprint. str, list and dict are classes; "hello" and [1, 2] are
# objects. This file shows how to write your own.
#
# functions.py ended with a small Dog class as a preview. This lesson
# starts properly from there.
#
# Topics covered here:
#   1. Why classes? (a dictionary vs a class)
#   2. Defining a class: __init__ and self
#   3. Methods
#   4. Class attributes vs instance attributes (and a classic bug)
#   5. __str__ and __repr__: how an object prints
#   6. __eq__ and __hash__: comparing objects, using them in sets
#   7. Class methods and static methods (alternative constructors)
#   8. Dataclasses: the same with far less code
#   9. LogEvent: a common format for security events
#  10. Practice, with tests
#
# THE SERIES
# ----------
# The four files in oop/ build one small project:
#   classes_and_objects.py   LogEvent: one shape for every log event
#   encapsulation.py         protecting data: secrets, validated values
#   inheritance.py           one parser class per log format
#   polymorphism.py          detection rules, run by one engine
#
# SECURITY CONNECTION
# -------------------
# Security tools are full of classes: Scapy packets, requests sessions,
# hashlib hash objects, the tools and agents in LLM frameworks. Being
# able to read and write classes is how you use, extend and debug them.


import tracemalloc
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


# ---------------------------------------------------------------
# 1. Why classes?
# ---------------------------------------------------------------
#
# A dictionary works for simple data, but:
#   - a TYPO in a key creates a new key silently instead of failing
#   - nothing checks the values
#   - the behaviour (functions that use the data) lives somewhere else
#
# A class keeps the data and its behaviour together, and can check
# that the data makes sense.

def section_1():
    host = {"name": "web01", "ip": "10.0.0.5", "open_ports": [22, 443]}
    host["opne_ports"] = [22, 443, 3389]            # typo: a NEW key, no error
    print("  dict after a typo:", host)
    print("  the real ports were never changed:", host["open_ports"])


# ---------------------------------------------------------------
# 2. Defining a class: __init__ and self
# ---------------------------------------------------------------
#
#   class Host:
#       def __init__(self, name, ip):     runs when you write Host(...)
#           self.name = name              store data ON this object
#
# `self` is the object being created or used. Python passes it in
# automatically: Host("web01", "10.0.0.5") calls
# __init__(<the new object>, "web01", "10.0.0.5").
#
# Each object has its OWN copy of the data (its "attributes").

class Host:
    def __init__(self, name, ip, open_ports=None):
        self.name = name
        self.ip = ip
        # Never use a list as a default argument (functions.py explains
        # why); make a new one for every object instead.
        self.open_ports = set(open_ports or [])

    # -----------------------------------------------------------
    # 3. Methods: functions that belong to the class
    # -----------------------------------------------------------
    #
    # A method's first parameter is always self, so it can read and
    # change that object's attributes.

    RISKY_PORTS = {21: "FTP", 23: "Telnet", 445: "SMB", 3389: "RDP"}   # (section 4)

    def open_port(self, port):
        self.open_ports.add(port)

    def close_port(self, port):
        self.open_ports.discard(port)

    def risky_services(self):
        return sorted(f"{port}/{self.RISKY_PORTS[port]}"
                      for port in self.open_ports if port in self.RISKY_PORTS)

    # (section 5)
    def __repr__(self):
        return f"Host({self.name!r}, {self.ip!r}, open_ports={sorted(self.open_ports)})"

    def __str__(self):
        return f"{self.name} ({self.ip})"

    # (section 6)
    def __eq__(self, other):
        if not isinstance(other, Host):
            return NotImplemented
        return (self.name, self.ip) == (other.name, other.ip)

    def __hash__(self):
        return hash((self.name, self.ip))

    # (section 7)
    @classmethod
    def from_inventory_line(cls, line):
        """'web01 10.0.0.5 22,443' -> Host"""
        name, ip, *rest = line.split()
        ports = [int(p) for p in rest[0].split(",")] if rest else []
        return cls(name, ip, ports)

    @staticmethod
    def is_valid_port(port):
        return isinstance(port, int) and 0 < port < 65536


def section_2_and_3():
    web = Host("web01", "10.0.0.5", [22, 443])
    db = Host("db01", "10.0.0.9")
    print("  two objects, separate data:", web.open_ports, db.open_ports)

    db.open_port(3389)
    db.open_port(445)
    print("  db01 risky services:", db.risky_services())
    print("  web01 risky services:", web.risky_services())
    print("  type(web) is", type(web).__name__, "| isinstance(web, Host):", isinstance(web, Host))


# ---------------------------------------------------------------
# 4. Class attributes vs instance attributes
# ---------------------------------------------------------------
#
#   RISKY_PORTS above is a CLASS attribute: defined in the class body,
#   SHARED by every Host. Good for constants.
#   self.open_ports is an INSTANCE attribute: one per object.
#
# The classic bug: a MUTABLE class attribute (a list or dict) is shared
# by every object, so changing it through one object changes it for
# all of them.

class BuggyScanner:
    findings = []                                   # shared by ALL scanners!

    def __init__(self, target):
        self.target = target

    def record(self, finding):
        self.findings.append(finding)


class FixedScanner:
    def __init__(self, target):
        self.target = target
        self.findings = []                          # one list per scanner

    def record(self, finding):
        self.findings.append(finding)


def section_4():
    a, b = BuggyScanner("10.0.0.1"), BuggyScanner("10.0.0.2")
    a.record("open telnet")
    print("  buggy: b.findings =", b.findings, "<- b never found anything!")
    a, b = FixedScanner("10.0.0.1"), FixedScanner("10.0.0.2")
    a.record("open telnet")
    print("  fixed: b.findings =", b.findings)


# ---------------------------------------------------------------
# 5. __str__ and __repr__
# ---------------------------------------------------------------
#
# Methods with double underscores ("dunder" methods) let your objects
# work with Python's built-in features.
#
#   __repr__   for DEVELOPERS: unambiguous, ideally looks like the code
#              that recreates the object. Used by the REPL, debuggers,
#              and inside lists.
#   __str__    for PEOPLE: used by print() and f-strings.
#
# Without them, an object prints as <__main__.Host object at 0x10a...>.

def section_5():
    web = Host("web01", "10.0.0.5", [443, 22])
    print("  print(web):", web)
    print("  repr(web): ", repr(web))
    print("  in a list: ", [web])


# ---------------------------------------------------------------
# 6. __eq__ and __hash__
# ---------------------------------------------------------------
#
# By default, two objects are equal only if they're the SAME object.
# __eq__ decides what "equal" means for your class: here, the same
# name and IP, whatever the ports.
#
# If you define __eq__, also define __hash__ (using the same fields),
# so objects can go in sets and be dictionary keys. Returning
# NotImplemented for other types lets Python try the other side.

def section_6():
    a = Host("web01", "10.0.0.5", [22])
    b = Host("web01", "10.0.0.5", [22, 8080])
    print("  a == b:", a == b, "| a is b:", a is b)
    print("  set of hosts from two scans:", {a, b, Host("db01", "10.0.0.9")})


# ---------------------------------------------------------------
# 7. Class methods and static methods
# ---------------------------------------------------------------
#
#   @classmethod   receives the CLASS (cls) instead of an object.
#                  Used for alternative constructors: build an object
#                  from a string, a file, a JSON record...
#   @staticmethod  receives neither. A plain function that lives in
#                  the class because it belongs with it.
#
# datetime.fromisoformat() and dict.fromkeys() are class methods.

def section_7():
    inventory = ["web01 10.0.0.5 22,443", "dc01 10.0.0.2 53,88,389,445,3389", "printer 10.0.0.50"]
    hosts = [Host.from_inventory_line(line) for line in inventory]
    for h in hosts:
        print(f"  {str(h):<20} risky: {h.risky_services()}")
    print("  Host.is_valid_port(70000):", Host.is_valid_port(70000))


# ---------------------------------------------------------------
# 8. Dataclasses
# ---------------------------------------------------------------
#
# Most classes that mainly HOLD DATA need the same boilerplate:
# __init__, __repr__ and __eq__. @dataclass writes them for you from
# the type annotations.
#
#   option              | effect
#   --------------------|------------------------------------------------
#   frozen=True         | attributes can't be changed after creation;
#                       | the object can then be hashed
#   order=True          | adds < <= > >= (compares fields in order)
#   slots=True          | less memory per object, and no new attributes
#                       | can be added by accident (Python 3.10+)
#   field(default_factory=list)   a fresh list for each object
#   field(repr=False)             leave a field out of the repr
#   __post_init__       | runs after __init__: put validation here

@dataclass(frozen=True, order=True)
class Port:
    number: int
    protocol: str = "tcp"

    def __post_init__(self):
        if not 0 < self.number < 65536:
            raise ValueError(f"port must be 1-65535, got {self.number}")
        if self.protocol not in ("tcp", "udp"):
            raise ValueError(f"protocol must be tcp or udp, got {self.protocol!r}")


def section_8():
    ports = [Port(443), Port(53, "udp"), Port(22), Port(443)]
    print("  repr:", ports[0])
    print("  equal:", Port(443) == Port(443))
    print("  sorted, unique:", sorted(set(ports)))
    try:
        Port(70000)
    except ValueError as err:
        print("  validation:", err)
    try:
        ports[0].number = 80
    except AttributeError as err:                    # dataclasses.FrozenInstanceError
        print("  frozen:", type(err).__name__, "-", err)


# ---------------------------------------------------------------
# 9. LogEvent: a common format for security events
# ---------------------------------------------------------------
#
# Every log source writes events differently. Converting each one into
# the SAME shape as soon as it's read means every later step
# (filtering, correlation, detection) only has to understand ONE
# format. Real systems do this too (Elastic Common Schema, OCSF, Splunk
# CIM); these field names are a small version of the same idea.
#
#   field    | example                      | notes
#   ---------|------------------------------|------------------------------
#   time     | 2026-11-27 10:15:32+00:00    | must be AWARE (dates_and_times.py)
#   source   | "sshd", "apache", "cloudtrail" | which log it came from
#   action   | "login", "http_request"      |
#   outcome  | "success", "failure", ""     | checked against OUTCOMES
#   user     | "root"                       | optional
#   src_ip   | "198.51.100.7"               | optional
#   host     | "web01"                      | optional
#   detail   | {"path": "/admin"}           | anything source-specific
#   raw      | the original line            | kept as evidence, hidden from repr
#
# slots=True matters here: an analysis can hold millions of events.

OUTCOMES = {"success", "failure", ""}


@dataclass(slots=True)
class LogEvent:
    time: datetime
    source: str
    action: str
    outcome: str = ""
    user: str | None = None
    src_ip: str | None = None
    host: str | None = None
    detail: dict = field(default_factory=dict)
    raw: str = field(default="", repr=False)

    def __post_init__(self):
        if self.time.tzinfo is None:
            raise ValueError("LogEvent.time must be timezone-aware (use UTC)")
        if self.outcome not in OUTCOMES:
            raise ValueError(f"outcome must be one of {sorted(OUTCOMES)}, got {self.outcome!r}")

    @property
    def failed(self):
        return self.outcome == "failure"

    def to_dict(self):
        record = asdict(self)
        record["time"] = self.time.isoformat()
        return record


@dataclass
class LogEventNoSlots:                               # the same fields, for comparison
    time: datetime
    source: str
    action: str
    outcome: str = ""
    user: str | None = None
    src_ip: str | None = None
    host: str | None = None
    detail: dict = field(default_factory=dict)
    raw: str = field(default="", repr=False)


def memory_for(make, n=50_000):
    tracemalloc.start()
    items = [make() for _ in range(n)]
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    del items
    return peak


def section_9():
    now = datetime(2026, 11, 27, 10, 15, 32, tzinfo=timezone.utc)
    event = LogEvent(now, "sshd", "login", "failure", user="root", src_ip="198.51.100.7",
                     host="web01", raw="Nov 27 10:15:32 web01 sshd[811]: Failed password ...")
    print("  ", event)
    print("   failed?", event.failed, "| as a dict:", event.to_dict()["time"], "...")
    try:
        LogEvent(datetime(2026, 11, 27), "sshd", "login")
    except ValueError as err:
        print("   naive time rejected:", err)
    try:
        event.colour = "red"
    except AttributeError as err:
        print("   slots stop typos:", err)

    as_dict = memory_for(lambda: {"time": now, "source": "sshd", "action": "login",
                                    "outcome": "failure", "user": "root", "src_ip": "10.0.0.1",
                                    "host": "web01", "detail": {}, "raw": ""})
    no_slots = memory_for(lambda: LogEventNoSlots(now, "sshd", "login", "failure",
                                                    "root", "10.0.0.1", "web01"))
    slots = memory_for(lambda: LogEvent(now, "sshd", "login", "failure",
                                          "root", "10.0.0.1", "web01"))
    print(f"   memory for 50,000 events: dict {as_dict / 1e6:.1f} MB, "
          f"dataclass {no_slots / 1e6:.1f} MB, dataclass with slots {slots / 1e6:.1f} MB")


# ---------------------------------------------------------------
# 10. Practice
# ---------------------------------------------------------------
#
# Write a small class yourself first, then compare:
#
#   Vulnerability(cve_id, cvss, host)
#     - cve_id must look like "CVE-2021-44228", cvss must be 0.0-10.0
#     - .severity returns "critical" (9+), "high" (7+), "medium" (4+)
#       or "low"
#     - sorting a list of them puts the highest cvss first

import re

CVE = re.compile(r"CVE-\d{4}-\d{4,}")


@dataclass(frozen=True)
class Vulnerability:
    cve_id: str
    cvss: float
    host: str

    def __post_init__(self):
        if not CVE.fullmatch(self.cve_id):
            raise ValueError(f"not a CVE id: {self.cve_id!r}")
        if not 0.0 <= self.cvss <= 10.0:
            raise ValueError(f"CVSS must be 0-10, got {self.cvss}")

    @property
    def severity(self):
        if self.cvss >= 9.0:
            return "critical"
        if self.cvss >= 7.0:
            return "high"
        if self.cvss >= 4.0:
            return "medium"
        return "low"

    def __lt__(self, other):                         # "less than" = more urgent first
        return (-self.cvss, self.cve_id) < (-other.cvss, other.cve_id)


def run_tests():
    # Host
    h = Host.from_inventory_line("dc01 10.0.0.2 53,445,3389")
    assert h.open_ports == {53, 445, 3389}
    assert h.risky_services() == ["3389/RDP", "445/SMB"]
    h.close_port(3389)
    assert h.risky_services() == ["445/SMB"]
    assert Host.from_inventory_line("printer 10.0.0.50").open_ports == set()
    assert Host("a", "1.1.1.1") == Host("a", "1.1.1.1", [80])
    assert Host("a", "1.1.1.1") != Host("a", "1.1.1.2")
    assert len({Host("a", "1.1.1.1"), Host("a", "1.1.1.1")}) == 1
    assert (Host("a", "1.1.1.1") == "a") is False           # NotImplemented -> False
    assert repr(Host("a", "1.1.1.1", [443, 22])) == "Host('a', '1.1.1.1', open_ports=[22, 443])"
    assert str(Host("a", "1.1.1.1")) == "a (1.1.1.1)"

    # Separate objects never share their lists
    x, y = Host("x", "1"), Host("y", "2")
    x.open_port(80)
    assert y.open_ports == set()

    # The class-attribute bug, and the fix
    BuggyScanner.findings.clear()
    BuggyScanner("a").record("f")
    assert BuggyScanner("b").findings == ["f"]               # shared!
    FixedScanner("a").record("f")
    assert FixedScanner("b").findings == []

    # Port
    assert sorted({Port(443), Port(22), Port(443)}) == [Port(22), Port(443)]
    for args in [(0,), (65536,), (53, "icmp")]:
        try:
            Port(*args)
            assert False, args
        except ValueError:
            pass

    # LogEvent
    t = datetime(2026, 11, 27, tzinfo=timezone.utc)
    e = LogEvent(t, "sshd", "login", "failure", user="root")
    assert e.failed and e.detail == {}
    assert LogEvent(t, "a", "b").detail is not LogEvent(t, "a", "b").detail   # fresh dicts
    assert "raw" not in repr(LogEvent(t, "sshd", "login", raw="secret line"))
    assert e.to_dict()["time"] == "2026-11-27T00:00:00+00:00"
    for kwargs in [dict(time=datetime(2026, 11, 27)), dict(outcome="maybe")]:
        args = dict(time=t, source="sshd", action="login") | kwargs
        try:
            LogEvent(**args)
            assert False, kwargs
        except ValueError:
            pass

    # Vulnerability (the practice)
    vulns = [Vulnerability("CVE-2021-44228", 10.0, "app01"),
             Vulnerability("CVE-2023-4863", 8.8, "ws17"),
             Vulnerability("CVE-2020-1472", 10.0, "dc01"),
             Vulnerability("CVE-2019-0708", 9.8, "rdp01"),
             Vulnerability("CVE-2024-0001", 3.1, "lab")]
    assert [v.cve_id for v in sorted(vulns)] == [
        "CVE-2020-1472", "CVE-2021-44228", "CVE-2019-0708", "CVE-2023-4863", "CVE-2024-0001"]
    assert [v.severity for v in sorted(vulns)] == ["critical", "critical", "critical", "high", "low"]
    for bad in [("log4shell", 10.0, "x"), ("CVE-2021-44228", 11.0, "x")]:
        try:
            Vulnerability(*bad)
            assert False, bad
        except ValueError:
            pass

    print("All tests passed!")


if __name__ == "__main__":
    for number, section in [("1", section_1), ("2-3", section_2_and_3), ("4", section_4),
                            ("5", section_5), ("6", section_6), ("7", section_7),
                            ("8", section_8), ("9", section_9)]:
        print(f"\n--- {number}. {section.__name__} ---")
        section()
    print()
    run_tests()
