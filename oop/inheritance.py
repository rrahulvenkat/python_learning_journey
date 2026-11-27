# Inheritance: one base class, many specialised versions
#
# INHERITANCE lets a class (the SUBCLASS or child) start from another
# class (the BASE class or parent) and keep everything it has, then add
# to it or change parts of it. It models an "is a" relationship: a
# Firewall IS A Device, an ApacheParser IS A LogParser.
#
# Topics covered here:
#   1. A base class and subclasses; overriding methods
#   2. super(): reusing the parent's code
#   3. isinstance, issubclass and the method resolution order (MRO)
#   4. Abstract base classes: forcing subclasses to fill in the gaps
#   5. Custom exception hierarchies
#   6. The real thing: one parser class per log format, all producing
#      LogEvent objects (from classes_and_objects.py)
#   7. Registering subclasses automatically (__init_subclass__) and
#      detecting a file's format
#   8. Mixins, and when NOT to use inheritance (composition)
#   9. Practice, with tests
#
# SECURITY CONNECTION
# -------------------
# Every log source has its own format, but the steps around parsing
# are the same: number the lines, skip blanks, count and keep bad
# lines, stop if too many fail. Inheritance puts those shared steps in
# ONE base class, so each new format (a new firewall, a new cloud
# service) is a small subclass with just its own parsing rule. That's
# how tools like Logstash, Splunk add-ons and Zeek scripts are
# organised.


import json
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone

from classes_and_objects import LogEvent


# ---------------------------------------------------------------
# 1. Base class and subclasses
# ---------------------------------------------------------------
#
#   class Server(Device):       Server inherits from Device
#
# A subclass gets all of the parent's methods. Defining a method with
# the SAME NAME replaces ("overrides") the parent's version for that
# subclass only.

class Device:
    def __init__(self, name, ip):
        self.name = name
        self.ip = ip

    def describe(self):
        return f"{self.name} ({self.ip})"

    def hardening_checks(self):
        return ["default passwords changed", "firmware up to date"]


class Server(Device):
    def __init__(self, name, ip, os_name):
        super().__init__(name, ip)                    # section 2
        self.os_name = os_name

    def describe(self):                               # override
        return f"{super().describe()} running {self.os_name}"

    def hardening_checks(self):                       # extend the parent's list
        return super().hardening_checks() + ["SSH root login disabled", "auto-updates on"]


class Firewall(Device):
    def hardening_checks(self):
        return super().hardening_checks() + ["default rule is deny", "admin UI not on WAN"]


def section_1_and_2():
    for device in [Device("printer", "10.0.0.50"), Server("web01", "10.0.0.5", "Ubuntu 24.04"),
                   Firewall("fw01", "10.0.0.1")]:
        print(f"  {type(device).__name__:<9} {device.describe()}")
        print(f"  {'':<9} checks: {device.hardening_checks()}")


# ---------------------------------------------------------------
# 2. super()
# ---------------------------------------------------------------
#
# super() gives you the PARENT's version of a method. Use it to:
#   - run the parent's __init__ so its attributes get set up
#   - extend a method instead of copying its code
# Forgetting super().__init__() is a common bug: the parent's
# attributes are never created (see the tests).


# ---------------------------------------------------------------
# 3. isinstance, issubclass and the MRO
# ---------------------------------------------------------------
#
#   isinstance(obj, Device)     True for a Device OR any subclass
#   type(obj) is Device         True ONLY for exactly Device (rarely what you want)
#   issubclass(Server, Device)  True
#   Server.__mro__              the order Python searches for a method:
#                               Server -> Device -> object
#
# Every class ultimately inherits from `object`, which provides the
# default __repr__, __eq__ and so on.

def section_3():
    s = Server("web01", "10.0.0.5", "Ubuntu")
    print("  isinstance(s, Device):", isinstance(s, Device), "| type(s) is Device:", type(s) is Device)
    print("  issubclass(Firewall, Device):", issubclass(Firewall, Device))
    print("  Server MRO:", [cls.__name__ for cls in Server.__mro__])


# ---------------------------------------------------------------
# 4. Abstract base classes
# ---------------------------------------------------------------
#
# Sometimes the base class only makes sense as a TEMPLATE: "every
# parser must have a parse_line method, but there's no sensible
# default". Inherit from ABC and mark those methods @abstractmethod:
#   - you can't create the base class itself
#   - a subclass that forgets to implement one can't be created either
# The mistake shows up the moment you create the object, not later in
# the middle of processing a log.

class Check(ABC):
    @abstractmethod
    def run(self, host):
        """Return True if the host passes."""


class SshRootLoginCheck(Check):
    def run(self, host):
        return "PermitRootLogin no" in host.get("sshd_config", "")


class ForgetfulCheck(Check):
    def runn(self, host):                             # typo: run is never implemented
        return True


def section_4():
    for cls in (Check, ForgetfulCheck):
        try:
            cls()
        except TypeError as err:
            print(f"  {cls.__name__}(): {err}")
    print("  SshRootLoginCheck passes?",
          SshRootLoginCheck().run({"sshd_config": "PermitRootLogin no\n"}))


# ---------------------------------------------------------------
# 5. Custom exception hierarchies
# ---------------------------------------------------------------
#
# Exceptions are classes too (exception_handling.py made one). Give
# your tool ONE base exception and specific subclasses, so callers can
# catch exactly what they care about:
#
#   except ParseError         just bad lines
#   except LogToolError       anything from this tool
#
#   LogToolError
#   ├── ParseError            a line couldn't be read (keeps the line and its number)
#   ├── UnknownFormatError    no parser recognises the input
#   └── TooManyErrorsError    so many bad lines the input is probably the wrong format

class LogToolError(Exception):
    """Base class for every error this tool raises."""


class ParseError(LogToolError):
    def __init__(self, message, line="", line_number=None):
        super().__init__(message)
        self.line = line
        self.line_number = line_number

    def __str__(self):
        where = f"line {self.line_number}: " if self.line_number else ""
        return f"{where}{self.args[0]}"


class UnknownFormatError(LogToolError):
    pass


class TooManyErrorsError(LogToolError):
    pass


# ---------------------------------------------------------------
# 6. Log parsers
# ---------------------------------------------------------------
#
# LogParser (the base class) does the parts that are the same for every
# format. This is the TEMPLATE METHOD pattern: parse() is the fixed
# recipe, and it calls parse_line(), the one step each subclass fills in.
#
#   parse_line(line) returns:
#     a LogEvent      the line was understood
#     None            a valid line, but not an event we care about
#   or raises ParseError if the line is broken.
#
#   LogParser (abstract)
#   ├── SyslogSSHParser     Nov 27 10:15:32 web01 sshd[811]: Failed password for ...
#   ├── ApacheParser        203.0.113.9 - - [27/Nov/2026:10:15:32 +0000] "GET / HTTP/1.1" 200 ...
#   └── CloudTrailParser    {"eventTime": "2026-11-27T10:15:32Z", "eventName": "ConsoleLogin", ...}

class LogParser(ABC):
    name = "base"
    registry = {}                                     # filled by __init_subclass__ (section 7)

    def __init__(self, year=None, max_error_rate=0.5, keep_errors=20):
        # The year to assume for formats that leave it out (syslog does).
        self.year = year or datetime.now(timezone.utc).year
        self.max_error_rate = max_error_rate
        self.keep_errors = keep_errors
        self.errors = []
        self.lines_read = 0
        self.error_count = 0

    def __init_subclass__(cls, **kwargs):             # runs once for EVERY subclass
        super().__init_subclass__(**kwargs)
        LogParser.registry[cls.name] = cls

    @classmethod
    @abstractmethod
    def looks_like(cls, line):
        """True if this line appears to be in this parser's format."""

    @abstractmethod
    def parse_line(self, line):
        """Return a LogEvent, None (not interesting), or raise ParseError."""

    def parse(self, lines):
        for number, line in enumerate(lines, start=1):
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            self.lines_read += 1
            try:
                event = self.parse_line(line)
            except ParseError as err:
                err.line, err.line_number = line, number
                self._record_error(err)
                continue
            if event is not None:
                event.raw = line
                yield event

    def _record_error(self, err):
        self.error_count += 1
        if len(self.errors) < self.keep_errors:
            self.errors.append(err)
        if self.lines_read >= 20 and self.error_count / self.lines_read > self.max_error_rate:
            raise TooManyErrorsError(
                f"{self.name}: {self.error_count} of {self.lines_read} lines failed; "
                f"is this really {self.name} format?")

    def __repr__(self):
        return f"{type(self).__name__}(read={self.lines_read}, errors={self.error_count})"


class SyslogSSHParser(LogParser):
    name = "syslog-sshd"

    LINE = re.compile(r"^(?P<time>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (?P<host>\S+) "
                      r"(?P<program>[\w./-]+)(?:\[\d+\])?: (?P<message>.*)$")
    SSH = re.compile(r"^(?P<result>Failed|Accepted) (?P<method>\S+) for (?:invalid user )?"
                     r"(?P<user>\S+) from (?P<ip>\S+) port \d+")

    @classmethod
    def looks_like(cls, line):
        return bool(cls.LINE.match(line))

    def parse_line(self, line):
        m = self.LINE.match(line)
        if not m:
            raise ParseError("not a syslog line")
        if m["program"] != "sshd":
            return None                               # valid syslog, other program
        ssh = self.SSH.match(m["message"])
        if not ssh:
            return None                               # other sshd messages
        try:
            when = datetime.strptime(f"{self.year} {m['time']}", "%Y %b %d %H:%M:%S")
        except ValueError:
            raise ParseError(f"bad timestamp {m['time']!r}")
        return LogEvent(
            time=when.replace(tzinfo=timezone.utc), source="sshd", action="login",
            outcome="success" if ssh["result"] == "Accepted" else "failure",
            user=ssh["user"], src_ip=ssh["ip"], host=m["host"],
            detail={"method": ssh["method"]})


class ApacheParser(LogParser):
    name = "apache"

    LINE = re.compile(r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
                      r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" (?P<status>\d{3}) (?P<size>\d+|-)'
                      r'(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?$')

    @classmethod
    def looks_like(cls, line):
        return bool(cls.LINE.match(line))

    def parse_line(self, line):
        m = self.LINE.match(line)
        if not m:
            raise ParseError("not an Apache log line")
        try:
            when = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            raise ParseError(f"bad timestamp {m['time']!r}")
        status = int(m["status"])
        return LogEvent(
            time=when.astimezone(timezone.utc), source="apache", action="http_request",
            outcome="failure" if status >= 400 else "success",
            user=None if m["user"] == "-" else m["user"], src_ip=m["ip"],
            detail={"method": m["method"], "path": m["path"], "status": status,
                    "agent": m["agent"] or ""})


class CloudTrailParser(LogParser):
    """AWS CloudTrail-style records, one JSON object per line."""
    name = "cloudtrail"

    @classmethod
    def looks_like(cls, line):
        return line.lstrip().startswith("{") and '"eventName"' in line

    def parse_line(self, line):
        try:
            record = json.loads(line)
            when = datetime.fromisoformat(record["eventTime"])
            name = record["eventName"]
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as err:
            raise ParseError(f"bad CloudTrail record: {err}")
        identity = record.get("userIdentity") or {}
        response = record.get("responseElements") or {}
        extra = record.get("additionalEventData") or {}
        if name == "ConsoleLogin":
            action = "login"
            outcome = "success" if response.get("ConsoleLogin") == "Success" else "failure"
        else:
            action = name
            outcome = "failure" if record.get("errorCode") else "success"
        return LogEvent(
            time=when.astimezone(timezone.utc), source="cloudtrail", action=action,
            outcome=outcome, user=identity.get("userName"), src_ip=record.get("sourceIPAddress"),
            detail={"event": name, "mfa": extra.get("MFAUsed"), "region": record.get("awsRegion")})


# ---------------------------------------------------------------
# 7. Automatic registration and format detection
# ---------------------------------------------------------------
#
# __init_subclass__ in LogParser runs every time a subclass is DEFINED,
# and adds it to LogParser.registry. So writing a new parser class is
# all it takes to make the tool support a new format: nothing else
# needs editing.
#
# detect_parser() looks at the first few non-blank lines and picks the
# parser that recognises most of them.

def detect_parser(sample_lines, **kwargs):
    sample = [l for l in sample_lines if l.strip()][:20]
    if not sample:
        raise UnknownFormatError("no lines to look at")
    scores = {name: sum(cls.looks_like(l) for l in sample)
              for name, cls in LogParser.registry.items()}
    best = max(scores, key=scores.get)
    if scores[best] == 0:
        raise UnknownFormatError(f"no parser recognises: {sample[0][:60]!r}")
    return LogParser.registry[best](**kwargs)


def section_6_and_7():
    print("  registered parsers:", sorted(LogParser.registry))
    for name, lines in SAMPLES.items():
        parser = detect_parser(lines, year=2026)
        events = list(parser.parse(lines))
        print(f"\n  {name}: detected {parser.name!r} -> {parser}")
        for e in events:
            print(f"    {e.time:%H:%M:%S} {e.source:<10} {e.action:<12} {e.outcome:<8} "
                  f"user={e.user} ip={e.src_ip}")
        for err in parser.errors:
            print(f"    skipped {err}")
    try:
        detect_parser(["just some text", "nothing to see"])
    except UnknownFormatError as err:
        print(f"\n  unknown input: {err}")


# ---------------------------------------------------------------
# 8. Mixins and composition
# ---------------------------------------------------------------
#
# A MIXIN is a small class that adds one ability to any class that
# inherits from it. Here, ToJSONMixin adds .to_json() to anything with
# attributes in __dict__.
#
# Inheritance is for "IS A". For "HAS A", use COMPOSITION: store the
# other object as an attribute. A Pipeline HAS A parser and HAS rules;
# it isn't a kind of parser. Deep inheritance trees ("a FirewallServer
# is a Server is a Device is a NetworkThing...") get hard to follow
# fast; prefer shallow trees plus composition.

class ToJSONMixin:
    def to_json(self):
        return json.dumps(self.__dict__, default=str, sort_keys=True)


class InventoryServer(ToJSONMixin, Server):          # a Server that can also do to_json()
    pass


class Pipeline:                                       # composition: HAS A parser
    def __init__(self, parser, filters=()):
        self.parser = parser
        self.filters = list(filters)

    def run(self, lines):
        for event in self.parser.parse(lines):
            if all(keep(event) for keep in self.filters):
                yield event


def section_8():
    s = InventoryServer("web01", "10.0.0.5", "Ubuntu")
    print("  mixin:", s.to_json())
    print("  MRO:  ", [c.__name__ for c in InventoryServer.__mro__])
    failures_only = Pipeline(SyslogSSHParser(year=2026), filters=[lambda e: e.failed])
    print("  composition, failures only:",
          [e.src_ip for e in failures_only.run(SAMPLES["auth.log"])])


# ---------------------------------------------------------------
# 9. Practice
# ---------------------------------------------------------------
#
# Add a parser for this firewall format yourself, then compare:
#
#   2026-11-27T10:15:32Z DENY TCP 198.51.100.7:51122 -> 10.0.0.5:22
#
#   - action "connection", outcome "failure" for DENY, "success" for ALLOW
#   - src_ip from the left side; detail holds protocol, src_port,
#     dst_ip and dst_port (ports as ints)
#
# Because of __init_subclass__, detect_parser() picks it up with no
# other changes.

class FirewallParser(LogParser):
    name = "firewall"

    LINE = re.compile(r"^(?P<time>\S+Z) (?P<verdict>ALLOW|DENY) (?P<proto>TCP|UDP) "
                      r"(?P<src>[\d.]+):(?P<sport>\d+) -> (?P<dst>[\d.]+):(?P<dport>\d+)$")

    @classmethod
    def looks_like(cls, line):
        return bool(cls.LINE.match(line))

    def parse_line(self, line):
        m = self.LINE.match(line)
        if not m:
            raise ParseError("not a firewall line")
        return LogEvent(
            time=datetime.fromisoformat(m["time"]), source="firewall", action="connection",
            outcome="success" if m["verdict"] == "ALLOW" else "failure", src_ip=m["src"],
            detail={"protocol": m["proto"].lower(), "src_port": int(m["sport"]),
                    "dst_ip": m["dst"], "dst_port": int(m["dport"])})


SAMPLES = {
    "auth.log": [
        "Nov 27 10:15:02 web01 sshd[811]: Failed password for root from 198.51.100.7 port 51122 ssh2",
        "Nov 27 10:15:09 web01 sshd[815]: Failed password for invalid user admin from 198.51.100.7 port 51130 ssh2",
        "Nov 27 10:15:20 web01 CRON[900]: (root) CMD (run-parts /etc/cron.hourly)",
        "Nov 27 10:16:00 web01 sshd[820]: Accepted publickey for alice from 192.0.2.10 port 50000 ssh2",
        "this line is damaged",
    ],
    "access.log": [
        '203.0.113.9 - - [27/Nov/2026:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 1043 "-" "Mozilla/5.0"',
        '203.0.113.9 - - [27/Nov/2026:10:15:40 +0000] "GET /../../etc/passwd HTTP/1.1" 400 0 "-" "curl/8.4"',
        '198.51.100.7 - bob [27/Nov/2026:05:16:01 -0500] "POST /login HTTP/1.1" 302 - "-" "Mozilla/5.0"',
    ],
    "cloudtrail.jsonl": [
        '{"eventTime": "2026-11-27T10:14:00Z", "eventName": "ConsoleLogin", "sourceIPAddress": "203.0.113.77", '
        '"userIdentity": {"userName": "carol"}, "responseElements": {"ConsoleLogin": "Failure"}}',
        '{"eventTime": "2026-11-27T10:14:30Z", "eventName": "ConsoleLogin", "sourceIPAddress": "203.0.113.77", '
        '"userIdentity": {"userName": "carol"}, "responseElements": {"ConsoleLogin": "Success"}, '
        '"additionalEventData": {"MFAUsed": "No"}}',
        '{"eventTime": "2026-11-27T10:15:00Z", "eventName": "CreateAccessKey", "sourceIPAddress": "203.0.113.77", '
        '"userIdentity": {"userName": "carol"}}',
        '{"eventTime": "broken"',
    ],
}


def run_tests():
    # Inheritance basics
    s = Server("web01", "10.0.0.5", "Ubuntu")
    assert s.describe() == "web01 (10.0.0.5) running Ubuntu"
    assert s.hardening_checks()[:2] == Device("x", "y").hardening_checks()
    assert isinstance(s, Device) and not isinstance(Device("x", "y"), Server)

    class BrokenServer(Device):                      # forgets super().__init__()
        def __init__(self, name, ip, os_name):
            self.os_name = os_name
    try:
        BrokenServer("a", "b", "c").describe()
        assert False
    except AttributeError:                           # self.name was never set
        pass

    # Abstract classes can't be created, nor can incomplete subclasses
    for cls in (Check, ForgetfulCheck, LogParser):
        try:
            cls()
            assert False, cls
        except TypeError:
            pass

    # Exception hierarchy
    assert issubclass(ParseError, LogToolError) and issubclass(TooManyErrorsError, LogToolError)
    err = ParseError("bad", "the line", 7)
    assert str(err) == "line 7: bad" and err.line == "the line"
    try:
        raise UnknownFormatError("x")
    except LogToolError:                             # caught by the base class
        pass

    # Syslog
    p = SyslogSSHParser(year=2026)
    events = list(p.parse(SAMPLES["auth.log"]))
    assert [(e.outcome, e.user, e.src_ip) for e in events] == [
        ("failure", "root", "198.51.100.7"), ("failure", "admin", "198.51.100.7"),
        ("success", "alice", "192.0.2.10")]
    assert events[0].time == datetime(2026, 11, 27, 10, 15, 2, tzinfo=timezone.utc)
    assert events[0].raw.startswith("Nov 27 10:15:02")
    assert p.lines_read == 5 and p.error_count == 1 and p.errors[0].line_number == 5

    # Apache: times converted to UTC, status decides the outcome
    events = list(ApacheParser().parse(SAMPLES["access.log"]))
    assert [e.outcome for e in events] == ["success", "failure", "success"]
    assert events[2].time == datetime(2026, 11, 27, 10, 16, 1, tzinfo=timezone.utc)
    assert events[2].user == "bob" and events[1].detail["path"] == "/../../etc/passwd"

    # CloudTrail
    p = CloudTrailParser()
    events = list(p.parse(SAMPLES["cloudtrail.jsonl"]))
    assert [(e.action, e.outcome) for e in events] == [
        ("login", "failure"), ("login", "success"), ("CreateAccessKey", "success")]
    assert events[1].detail["mfa"] == "No" and p.error_count == 1

    # Detection, including the practice parser added after the others
    assert detect_parser(SAMPLES["auth.log"]).name == "syslog-sshd"
    assert detect_parser(SAMPLES["access.log"]).name == "apache"
    assert detect_parser(SAMPLES["cloudtrail.jsonl"]).name == "cloudtrail"
    fw = ["2026-11-27T10:15:32Z DENY TCP 198.51.100.7:51122 -> 10.0.0.5:22",
          "2026-11-27T10:15:33Z ALLOW UDP 10.0.0.5:5353 -> 224.0.0.251:5353"]
    parser = detect_parser(fw)
    assert parser.name == "firewall" and "firewall" in LogParser.registry
    events = list(parser.parse(fw))
    assert events[0].outcome == "failure" and events[0].detail["dst_port"] == 22
    assert events[1].detail["protocol"] == "udp"
    for bad in ([], ["hello world"]):
        try:
            detect_parser(bad)
            assert False
        except UnknownFormatError:
            pass

    # Too many errors: the wrong parser for the input gives up
    try:
        list(ApacheParser().parse(SAMPLES["auth.log"] * 10))
        assert False
    except TooManyErrorsError as err:
        assert "apache" in str(err)

    # Mixin and composition
    assert json.loads(InventoryServer("a", "b", "c").to_json()) == {"ip": "b", "name": "a", "os_name": "c"}
    only_alice = Pipeline(SyslogSSHParser(year=2026), [lambda e: e.user == "alice"])
    assert [e.user for e in only_alice.run(SAMPLES["auth.log"])] == ["alice"]

    print("All tests passed!")


if __name__ == "__main__":
    print("\n--- 1-2. section_1_and_2 ---")
    section_1_and_2()
    print("\n--- 3. section_3 ---")
    section_3()
    print("\n--- 4. section_4 ---")
    section_4()
    print("\n--- 6-7. section_6_and_7 ---")
    section_6_and_7()
    print("\n--- 8. section_8 ---")
    section_8()
    print()
    run_tests()
