# Command-Line Tools (sys.argv, argparse, stdin/stdout/stderr, exit codes)
#
# Security tools are almost all run from a terminal: nmap, grep, jq,
# hashcat, volatility. They take options, read files OR piped input,
# print results others can pipe onward, and report success or failure
# with an exit code so scripts can react. This file shows how to make
# your Python scripts behave the same way.
#
# Topics covered here:
#   1. sys.argv: the raw arguments
#   2. argparse: positional arguments, options, flags, types, choices,
#      defaults, and automatic --help
#   3. Custom argument types (a duration like "10m", a timestamp)
#   4. stdin, stdout and stderr: being a good citizen in a pipeline
#   5. Exit codes: 0, 1 and 2
#   6. Human-readable and machine-readable (JSON lines) output
#   7. Making main() testable
#   8. The whole thing: `logscan`, a brute-force detector for auth logs
#
# HOW TO RUN IT
# -------------
#   python3 command_line_tools.py              the lesson and its tests
#   python3 command_line_tools.py --help       logscan's help
#   python3 command_line_tools.py /var/log/auth.log*
#   zcat auth.log.*.gz | python3 command_line_tools.py - --threshold 3 --window 5m
#   python3 command_line_tools.py auth.log --format json | jq .ip
#
# With NO arguments it runs the lesson; with any arguments, the tool.
# So to read piped input, pass "-" (the usual name for stdin).
#
# It reuses open_log() and parse() from large_files.py and to_utc()
# from dates_and_times.py, so those files must be in the same folder.


import argparse
import io
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict, deque
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dates_and_times import to_utc
from large_files import open_log, parse


# ---------------------------------------------------------------
# 1. sys.argv
# ---------------------------------------------------------------
#
#   python3 tool.py auth.log --threshold 3
#   sys.argv == ["tool.py", "auth.log", "--threshold", "3"]
#
# Everything is a STRING, the program name comes first, and you'd have
# to handle missing values, wrong types and --help yourself. argparse
# does all of that.

def section_1():
    print("  sys.argv right now:", sys.argv)


# ---------------------------------------------------------------
# 2. argparse basics
# ---------------------------------------------------------------
#
#   kind              | example                    | add_argument(...)
#   ------------------|----------------------------|--------------------------------------
#   positional        | tool.py auth.log           | "files", nargs="*"
#   option with value | --threshold 5, -t 5        | "-t", "--threshold", type=int, default=5
#   flag (on/off)     | --verbose                  | "--verbose", action="store_true"
#   limited choices   | --format json              | "--format", choices=["text", "json"]
#
# parse_args() checks everything. A missing or bad value prints a short
# error and exits with code 2, before any of your code runs.
# --help (and -h) is generated from the help= text.

def section_2():
    parser = argparse.ArgumentParser(prog="demo", description="A tiny example.")
    parser.add_argument("host", help="host to check")
    parser.add_argument("-p", "--port", type=int, default=22, help="port (default: %(default)s)")
    parser.add_argument("--proto", choices=["tcp", "udp"], default="tcp")
    parser.add_argument("-v", "--verbose", action="store_true", help="say more")

    args = parser.parse_args(["10.0.0.5", "--port", "443", "-v"])
    print("  parsed:", args)
    print("  args.port is an", type(args.port).__name__, "->", args.port)

    stderr = io.StringIO()
    with redirect_stderr(stderr):
        try:
            parser.parse_args(["10.0.0.5", "--port", "ssh"])
        except SystemExit as exit_:
            print("  bad value -> exit code", exit_.code)
    print("  error message:", stderr.getvalue().strip().splitlines()[-1])

    print("  generated help:")
    for line in parser.format_help().splitlines():
        print("   |", line)


# ---------------------------------------------------------------
# 3. Custom argument types
# ---------------------------------------------------------------
#
# type= can be ANY function that takes a string and returns a value,
# or raises argparse.ArgumentTypeError with a helpful message.

DURATION = re.compile(r"(?P<n>\d+)(?P<unit>[smhd])")
UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}

def duration(text):
    """'90s', '10m', '2h', '1d' -> timedelta"""
    m = DURATION.fullmatch(text.strip().lower())
    if not m:
        raise argparse.ArgumentTypeError(f"expected a duration like 30s, 10m, 2h or 1d, got {text!r}")
    return timedelta(**{UNITS[m["unit"]]: int(m["n"])})


def positive_int(text):
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, got {value}")
    return value


def timestamp(text):
    try:
        return to_utc(text)
    except ValueError as err:
        raise argparse.ArgumentTypeError(str(err))


def section_3():
    for text in ["90s", "10m", "2h", "1d"]:
        print(f"  duration({text!r:<6}) -> {duration(text)}")
    try:
        duration("ten minutes")
    except argparse.ArgumentTypeError as err:
        print("  duration('ten minutes') ->", err)
    print("  timestamp('2026-11-27T10:00:00-05:00') ->", timestamp("2026-11-27T10:00:00-05:00"))


# ---------------------------------------------------------------
# 4. stdin, stdout and stderr
# ---------------------------------------------------------------
#
#   stdin   input. Piped data arrives here:  cat auth.log | tool.py
#   stdout  RESULTS only. This is what gets piped to the next tool.
#   stderr  messages for the PERSON: progress, warnings, errors.
#
# Mixing a warning into stdout would corrupt the data for the next
# tool in the pipe, so warnings always go to stderr:
#   print("warning: ...", file=sys.stderr)
#
# Convention: no file names, or the name "-", means "read stdin".
#
# When the next tool stops reading early (like `| head -3`), Python
# gets a BrokenPipeError on its next write. Real tools exit quietly
# when that happens (see the bottom of this file).

def section_4():
    print("  stdin is a terminal?", sys.stdin.isatty(), "(False when data is piped in)")
    print("  this line went to stdout")
    print("  this line went to stderr", file=sys.stderr)


# ---------------------------------------------------------------
# 5. Exit codes
# ---------------------------------------------------------------
#
#   code | meaning (the grep convention, which logscan follows)
#   -----|--------------------------------------------------------
#    0   | ran fine, nothing found
#    1   | ran fine, FOUND something (alerts)
#    2   | error: bad arguments, missing file
#
# Scripts, cron jobs and CI pipelines check it:
#   python3 logscan.py auth.log -q || send_alert "brute force detected"
# In the shell, `echo $?` shows the last command's exit code.

EXIT_CLEAN, EXIT_ALERTS, EXIT_ERROR = 0, 1, 2


# ---------------------------------------------------------------
# 6. Output formats
# ---------------------------------------------------------------
#
#   text   a table for people
#   json   one JSON object per line ("JSON lines"). Tools like jq,
#          Splunk and Elastic read it directly, and each line can be
#          processed on its own, so it streams.
#
# Timestamps in JSON should be ISO 8601 in UTC (dates_and_times.py).


# ---------------------------------------------------------------
# 7. Making main() testable
# ---------------------------------------------------------------
#
# main(argv, stdin, stdout, stderr) takes everything it uses as
# arguments, and RETURNS the exit code instead of calling sys.exit().
# Tests can then pass a list of arguments and StringIO objects, and
# check the output and the code, without starting a new process.


# ---------------------------------------------------------------
# 8. logscan
# ---------------------------------------------------------------
#
# Reads auth logs (plain, .gz, .bz2, .xz, or stdin), finds failed SSH
# logins, and reports any IP with at least --threshold failures inside
# any --window of time (a sliding window per IP, as in
# longest_substring.py). It also reports if that IP then logged in
# successfully, which is the case that matters most.
#
# It only understands the syslog sshd format for now. Supporting
# Apache, JSON and Windows logs cleanly is a good job for classes,
# which come in the OOP lesson.

EXAMPLES = """\
examples:
  %(prog)s /var/log/auth.log
  %(prog)s /var/log/auth.log* --threshold 3 --window 5m
  zcat auth.log.*.gz | %(prog)s -
  %(prog)s auth.log --since 2026-11-27T00:00Z --format json | jq .ip
  %(prog)s auth.log -q || echo "brute force detected"
"""


def build_parser():
    parser = argparse.ArgumentParser(
        prog="logscan",
        description="Find SSH brute-force attempts in auth logs.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("files", nargs="*", default=["-"],
                        help="log files, plain or compressed (default: read stdin)")
    parser.add_argument("-t", "--threshold", type=positive_int, default=5,
                        help="failures needed to raise an alert (default: %(default)s)")
    parser.add_argument("-w", "--window", type=duration, default=timedelta(minutes=10),
                        help="time window, like 30s, 10m, 1h (default: 10m)")
    parser.add_argument("--since", type=timestamp, help="ignore events before this time")
    parser.add_argument("--until", type=timestamp, help="ignore events after this time")
    parser.add_argument("--year", type=int,
                        help="year for syslog lines, which have none (default: this year)")
    parser.add_argument("--format", choices=["text", "json"], default="text")

    noise = parser.add_mutually_exclusive_group()          # can't use both at once
    noise.add_argument("-q", "--quiet", action="store_true",
                       help="print nothing; only set the exit code")
    noise.add_argument("-v", "--verbose", action="store_true",
                       help="print a summary to stderr")
    return parser


def iter_lines(names, stdin, stderr):
    """Yield lines from every file (or stdin for '-'). Missing files are reported."""
    missing = []
    for name in names:
        if name == "-":
            yield from stdin
            continue
        try:
            with open_log(name) as f:
                yield from f
        except (FileNotFoundError, IsADirectoryError, PermissionError) as err:
            print(f"logscan: {name}: {err.strerror}", file=stderr)
            missing.append(name)
    if missing:
        raise FileNotFoundError(missing)


def scan(lines, threshold, window, since=None, until=None, reference=None):
    """Return (alerts worst first, stats).

    Assumes each IP's events arrive in TIME ORDER, so pass rotated files
    oldest first (auth.log.2.gz auth.log.1 auth.log). Duplicate lines are
    counted again; it doesn't de-duplicate.
    """
    recent = defaultdict(deque)                          # ip -> failure times in the window
    users = defaultdict(set)
    worst = {}                                           # ip -> biggest burst seen
    alerted_at = {}                                      # ip -> time the threshold was crossed
    breached = {}
    stats = Counter()

    for line in lines:
        stats["lines"] += 1
        event = next(parse([line]), None)
        if event is None:
            continue
        try:
            when = to_utc(line[:15], reference=reference)
        except ValueError:
            stats["bad_time"] += 1
            continue
        if (since and when < since) or (until and when > until):
            continue
        ip = event["ip"]

        if event["result"] == "Failed":
            stats["failures"] += 1
            q = recent[ip]
            q.append(when)
            while when - q[0] > window:
                q.popleft()
            users[ip].add(event["user"])
            if len(q) >= threshold:
                alerted_at.setdefault(ip, when)
                if len(q) > worst.get(ip, (0,))[0]:
                    worst[ip] = (len(q), q[0], when)
        elif ip in alerted_at and ip not in breached:
            breached[ip] = (event["user"], when)

    alerts = []
    for ip, (count, start, end) in worst.items():
        alert = {"ip": ip, "failures": count, "first": start.isoformat(),
                 "last": end.isoformat(), "users": sorted(users[ip])}
        if ip in breached:
            user, when = breached[ip]
            alert["success_after"] = {"user": user, "time": when.isoformat()}
        alerts.append(alert)
    alerts.sort(key=lambda a: ("success_after" not in a, -a["failures"], a["ip"]))
    return alerts, stats


def print_text(alerts, out):
    if not alerts:
        print("No brute-force activity found.", file=out)
        return
    print(f"{'IP':<16} {'FAILS':>5}  {'FROM':<20} {'TO':<20} USERS", file=out)
    for a in alerts:
        print(f"{a['ip']:<16} {a['failures']:>5}  {a['first'][:19]:<20} {a['last'][:19]:<20} "
              f"{','.join(a['users'])}", file=out)
        if "success_after" in a:
            s = a["success_after"]
            print(f"{'':<16} !!! then logged in as {s['user']!r} at {s['time'][:19]}", file=out)


def main(argv=None, stdin=None, stdout=None, stderr=None):
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr

    # argparse prints --help to sys.stdout and errors to sys.stderr
    # directly, so point those at the streams we were given.
    try:
        with redirect_stdout(stdout), redirect_stderr(stderr):
            args = build_parser().parse_args(argv)
    except SystemExit as exit_:                         # --help (0) or a bad argument (2)
        return exit_.code

    year = args.year or datetime.now(timezone.utc).year
    reference = datetime(year, 12, 31, 23, 59, tzinfo=timezone.utc)

    try:
        alerts, stats = scan(iter_lines(args.files, stdin, stderr), args.threshold,
                             args.window, args.since, args.until, reference)
    except FileNotFoundError:
        return EXIT_ERROR

    if not args.quiet:
        if args.format == "json":
            for alert in alerts:
                print(json.dumps(alert), file=stdout)
        else:
            print_text(alerts, stdout)
    if args.verbose:
        print(f"logscan: read {stats['lines']:,} lines, {stats['failures']:,} failed logins, "
              f"{len(alerts)} alert(s)", file=stderr)
    return EXIT_ALERTS if alerts else EXIT_CLEAN


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def sample_log(attacker_wins=True):
    lines = []
    for i in range(6):                                   # 6 failures in 50 seconds
        lines.append(f"Nov 27 10:00:{i * 10:02d} web01 sshd[{100 + i}]: Failed password for "
                     f"{'root' if i % 2 else 'invalid user admin'} from 198.51.100.7 port {4000 + i} ssh2")
    if attacker_wins:
        lines.append("Nov 27 10:01:30 web01 sshd[200]: Accepted password for root "
                     "from 198.51.100.7 port 4100 ssh2")
    for i in range(3):                                   # slow failures: 3 in 40 minutes
        lines.append(f"Nov 27 10:{20 * i:02d}:00 web01 sshd[{300 + i}]: Failed password for bob "
                     f"from 192.0.2.50 port 5000 ssh2")
    lines.append("Nov 27 12:00:00 web01 CRON[1]: unrelated line")
    lines.append("garbage \\xff line")
    return "\n".join(lines) + "\n"


def run(argv, stdin_text=""):
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdin=io.StringIO(stdin_text), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def run_tests():
    log = sample_log()

    # Types
    assert duration("10m") == timedelta(minutes=10)
    assert duration("1D") == timedelta(days=1)
    for bad in ["10", "m", "10 minutes", "-5m"]:
        try:
            duration(bad)
            assert False, bad
        except argparse.ArgumentTypeError:
            pass

    # stdin, default options: one alert, with the successful login flagged
    code, out, _ = run(["--year", "2026"], log)
    assert code == EXIT_ALERTS
    assert "198.51.100.7" in out and "logged in as 'root'" in out
    assert "192.0.2.50" not in out                      # too slow to count

    # JSON output is one valid object per line
    code, out, _ = run(["--year", "2026", "--format", "json"], log)
    records = [json.loads(line) for line in out.splitlines()]
    assert len(records) == 1
    alert = records[0]
    assert alert["ip"] == "198.51.100.7" and alert["failures"] == 6
    assert alert["users"] == ["admin", "root"]
    assert alert["first"] == "2026-11-27T10:00:00+00:00"
    assert alert["success_after"]["user"] == "root"

    # A wider window and lower threshold catch the slow attacker too
    code, out, _ = run(["--year", "2026", "-t", "3", "-w", "2h", "--format", "json"], log)
    assert {json.loads(l)["ip"] for l in out.splitlines()} == {"198.51.100.7", "192.0.2.50"}

    # The window really is sliding: 6 failures over 50 s don't fit in 20 s
    code, out, _ = run(["--year", "2026", "-t", "4", "-w", "20s"], log)
    assert code == EXIT_CLEAN and "No brute-force" in out

    # --since cuts out the burst
    code, out, _ = run(["--year", "2026", "--since", "2026-11-27T10:05:00Z"], log)
    assert code == EXIT_CLEAN

    # Quiet: no output, the exit code still says what happened
    code, out, err = run(["--year", "2026", "-q"], log)
    assert code == EXIT_ALERTS and out == "" and err == ""

    # Verbose writes its summary to stderr, keeping stdout clean
    code, out, err = run(["--year", "2026", "-v", "--format", "json"], log)
    assert "read 12 lines" in err and "read" not in out

    # Files, including compressed ones, and a missing file
    import gzip
    with tempfile.TemporaryDirectory() as tmp:
        plain = Path(tmp, "auth.log")                  # the newer, live file
        plain.write_text("Nov 27 11:00:00 web01 sshd[9]: Accepted publickey for alice "
                         "from 192.0.2.10 port 1 ssh2\n", encoding="utf-8")
        packed = Path(tmp, "auth.log.1.gz")
        with gzip.open(packed, "wt", encoding="utf-8") as f:
            f.write(sample_log())
        code, out, _ = run(["--year", "2026", str(packed), str(plain), "--format", "json"])
        assert code == EXIT_ALERTS and json.loads(out)["failures"] == 6

        code, out, err = run([str(plain), str(Path(tmp, "nope.log"))])
        assert code == EXIT_ERROR and "nope.log" in err

    # Argument errors exit with 2 and explain themselves on stderr
    for bad in (["-t", "0"], ["-w", "soon"], ["--format", "xml"], ["-q", "-v"],
                ["--since", "yesterday"]):
        code, out, err = run(bad, log)
        assert code == 2 and out == "" and "error" in err, bad

    # --help exits with 0 and shows the examples
    stdout = io.StringIO()
    with redirect_stdout(stdout):
        code = main(["--help"])
    assert code == 0 and "examples:" in stdout.getvalue()

    print("All tests passed!")


def lesson():
    for number, section in enumerate([section_1, section_2, section_3, section_4], start=1):
        print(f"\n--- {number}. {section.__name__} ---")
        section()

    print("\n--- 5-8. logscan, run as a real program in a pipeline ---")
    script = Path(__file__).resolve()
    for argv in (["-", "--year", "2026"], ["-", "--year", "2026", "--format", "json"],
                 ["-", "--window", "soon"]):
        shown = " ".join(argv)
        result = subprocess.run([sys.executable, str(script), *argv], input=sample_log(),
                                capture_output=True, text=True, cwd=script.parent)
        print(f"\n$ cat auth.log | python3 {script.name} {shown}")
        print(result.stdout + result.stderr, end="")
        print(f"(exit code {result.returncode})")

    print()
    run_tests()


if __name__ == "__main__":
    if len(sys.argv) == 1:
        lesson()                                         # no arguments: the lesson
    else:
        try:
            sys.exit(main())
        except BrokenPipeError:                          # e.g. `| head -3` stopped reading
            sys.stderr.close()
            sys.exit(EXIT_CLEAN)
