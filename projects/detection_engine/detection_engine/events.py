"""LogEvent: the one event format every parser produces and every rule reads.

The design (copied from python_learning_journey/oop/classes_and_objects.py, where it's explained step by step):

  field    | example                        | notes
  ---------|--------------------------------|------------------------------
  time     | 2026-11-27 10:15:32+00:00      | must be timezone-aware (UTC)
  source   | "sshd", "web", "cloudtrail"    | which log it came from
  action   | "login", "http_request"        |
  outcome  | "success", "failure", ""       | checked against OUTCOMES
  user     | "root"                         | optional
  src_ip   | "198.51.100.7"                 | optional
  host     | "web01"                        | optional
  detail   | {"path": "/admin"}             | anything source-specific
  raw      | the original line              | kept as evidence, hidden from repr
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime

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
