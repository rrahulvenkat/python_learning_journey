"""The command line: detect attacks in one or more log files.

    python -m detection_engine samples/access.log --trust-proxy 10.0.0.2
    python -m detection_engine auth.log security.xml --year 2026

Each file's format is detected on its own (syslog sshd, CloudTrail JSON,
Windows event XML, web access logs), then the events from every file go
through every rule TOGETHER, so an attacker seen in two logs ends up in
one incident.

Exit codes: 0 nothing at HIGH or above, 1 a HIGH or CRITICAL incident,
2 an error (a missing file, or a format nothing recognises).
"""

import argparse
import sys
from pathlib import Path

from .correlation import Correlator
from .parsers import LogToolError, detect_parser
from .rules import DetectionEngine, Severity, Timeline
from .web import WebAccessParser, rules_with_web
from .windows import windows_rules


def read_events(path, year, trusted_proxies, out):
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    parser = detect_parser(lines, year=year)
    if isinstance(parser, WebAccessParser):
        parser = WebAccessParser(trusted_proxies=trusted_proxies, year=year)
    events = list(parser.parse(lines))
    print(f"{path}: {parser.name}, {parser.lines_read} lines, {len(events)} events, "
          f"{parser.error_count} unreadable", file=out)
    for err in parser.errors[:3]:
        print(f"  skipped {err}", file=out)
    return events


def build_parser():
    p = argparse.ArgumentParser(prog="detection_engine",
                                description="Detect attacks in log files and correlate them into incidents.")
    p.add_argument("logs", nargs="+", type=Path, help="log files (formats are detected)")
    p.add_argument("--year", type=int, help="year for syslog lines, which leave it out (default: this year)")
    p.add_argument("--trust-proxy", action="append", default=[], metavar="IP_OR_NETWORK",
                   help="a load balancer or proxy whose X-Forwarded-For can be trusted (repeatable)")
    p.add_argument("--alerts", action="store_true", help="also list every alert, not just incidents")
    return p


def main(argv=None, out=sys.stdout):
    args = build_parser().parse_args(argv)
    events = []
    try:
        for path in args.logs:
            events += read_events(path, args.year, args.trust_proxy, out)
    except (OSError, LogToolError, ValueError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    alerts = DetectionEngine(rules_with_web() + windows_rules()).run(Timeline(events))
    incidents = Correlator().correlate(alerts)
    print(f"\n{len(alerts)} alerts -> {len(incidents)} incidents\n", file=out)
    if args.alerts:
        for alert in alerts:
            print(f"  {alert}", file=out)
        print(file=out)
    for incident in incidents:
        print(incident.report(), file=out)
        print(file=out)
    return 1 if any(i.severity >= Severity.HIGH for i in incidents) else 0


if __name__ == "__main__":
    sys.exit(main())
