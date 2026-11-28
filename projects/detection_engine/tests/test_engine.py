"""Tests for the whole engine.

    pytest                         (from projects/detection_engine)
    python tests/test_engine.py    (after: pip install -e .)

Each module keeps its own detailed tests in run_tests(); this file runs
them all, then checks the pieces that join them: format detection
across files, and the command line.
"""

import io
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from detection_engine import baselines, correlation, web, windows
from detection_engine.__main__ import main
from detection_engine.events import LogEvent
from detection_engine.parsers import detect_parser


# --- each module's own tests ---------------------------------------------

def test_baselines():
    baselines.run_tests()


def test_correlation():
    correlation.run_tests()


def test_windows():
    windows.run_tests()


def test_web():
    web.run_tests()


# --- the pieces that join them ----------------------------------------------

def test_events_must_have_a_timezone():
    try:
        LogEvent(datetime(2026, 11, 27), "sshd", "login")
    except ValueError:
        pass
    else:
        raise AssertionError("a naive time was accepted")
    assert LogEvent(datetime(2026, 11, 27, tzinfo=timezone.utc), "sshd", "login", "failure").failed


def test_every_format_is_detected():
    ssh = ["Nov 27 10:15:02 web01 sshd[811]: Failed password for root from 198.51.100.7 port 51122 ssh2"]
    cloud = ['{"eventTime": "2026-11-27T10:14:00Z", "eventName": "ConsoleLogin", '
             '"sourceIPAddress": "203.0.113.77", "userIdentity": {"userName": "carol"}, '
             '"responseElements": {"ConsoleLogin": "Failure"}}']
    for lines, name in ((ssh, "syslog-sshd"), (cloud, "cloudtrail"),
                        (windows.rdp_intrusion(), "windows-xml"), (web.shop_attack(), "web-access")):
        assert detect_parser(lines).name == name


def write(lines):
    path = Path(tempfile.mkdtemp()) / "log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_command_line_finds_the_web_attack():
    out = io.StringIO()
    code = main([str(write(web.shop_attack())), "--trust-proxy", web.LOAD_BALANCER], out=out)
    text = out.getvalue()
    assert code == 1                                   # a CRITICAL incident
    assert "web-access, 52 lines, 52 events, 0 unreadable" in text
    assert "ip:198.51.100.99" in text and "web recon then attack" in text
    assert "ip:10.0.0.2" not in text                    # the load balancer isn't blamed


def test_command_line_joins_files_and_reports_errors():
    out = io.StringIO()
    code = main([str(write(web.shop_attack())), str(write(windows.rdp_intrusion()))], out=out)
    assert code == 1 and "windows-xml" in out.getvalue() and "web-access" in out.getvalue()
    quiet = write(['192.0.2.5 - - [27/Nov/2026:14:00:00 +0000] "GET / HTTP/1.1" 200 10 "-" "Mozilla/5.0"'])
    assert main([str(quiet)], out=io.StringIO()) == 0
    assert main([str(quiet.with_name("missing.log"))], out=io.StringIO()) == 2
    assert main([str(write(["no format knows this line"]))], out=io.StringIO()) == 2


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    for test in tests:
        test()
        print(f"ok  {test.__name__}")
    print(f"\nAll {len(tests)} tests passed!")
