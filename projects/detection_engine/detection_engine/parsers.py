"""Log parsers: one LogParser subclass per format, all producing LogEvents.

The base class does what every format shares (numbering lines, skipping
blanks, keeping bad lines, stopping when too many fail); each subclass
only reads its own line format. Defining a subclass registers it, and
detect_parser() picks the right one for a file. The design is copied from python_learning_journey/oop/inheritance.py, where it's explained step by step.

More parsers live in windows.py and web.py.
"""

import json
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone

from .events import LogEvent


# Errors:
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


# parse_line(line) returns a LogEvent (understood), None (a valid line,
# but not an event we care about), or raises ParseError (broken line).

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
