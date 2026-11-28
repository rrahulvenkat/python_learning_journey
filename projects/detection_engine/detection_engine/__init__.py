"""A small detection engine: parse logs into one event format, run
independent rules over them, and correlate the alerts into incidents.

    events.py       LogEvent, the one format everything shares
    parsers.py      LogParser and the syslog (sshd) and CloudTrail parsers
    rules.py        Rule, Alert, Severity, Timeline, DetectionEngine, core rules
    stats.py        robust statistics for baselines
    baselines.py    rules that learn what's normal (login volume, unusual hours)
    correlation.py  linking alerts into incidents, with MITRE ATT&CK labels
    windows.py      Windows event XML: parser and rules
    web.py          web server access logs: parser and rules
    __main__.py     the command line: python -m detection_engine LOG ...

A parser is registered when its module is imported, so detect_parser()
knows the Windows and web formats only after `import detection_engine.windows`
and `import detection_engine.web` (the command line imports both).
The package itself imports only the core, so each module can also be run
on its own to see its demo: python -m detection_engine.web
"""

from .events import LogEvent
from .parsers import LogParser, detect_parser
from .rules import Alert, DetectionEngine, Rule, Severity, Timeline

__all__ = ["Alert", "DetectionEngine", "LogEvent", "LogParser", "Rule", "Severity",
           "Timeline", "detect_parser"]
