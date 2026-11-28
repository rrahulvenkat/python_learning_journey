# Testing with pytest: how real projects test their code
#
# Every lesson so far ends with run_tests(): plain assert statements in a
# function. That works, but it stops at the first failure, says little
# about WHY, and doesn't scale. Real projects use pytest: it finds tests
# by name, runs them all, shows exactly what differed, and adds fixtures,
# parametrised tests and mocking. Every project you'll join uses it (or
# unittest, its older standard-library cousin).
#
# For security code, tests are how you prove the PROPERTIES that matter:
# "the password never appears in the log", "only 5 hash characters
# leave the machine", "a framed IP can't fool the parser". This lesson
# tests a few small security functions to show each pytest feature.
#
# Topics covered here:
#   1. Setting up: a virtual environment and requirements.txt
#   2. Test functions and pytest's detailed assert messages
#   3. Testing that errors happen: pytest.raises
#   4. Many cases, one test: @pytest.mark.parametrize
#   5. Fixtures: shared setup (and clean-up with yield)
#   6. Built-in fixtures: tmp_path, monkeypatch, caplog
#   7. Mocking: replacing the network with unittest.mock
#   8. Marks: skip, skipif, xfail (documenting a known limitation)
#   9. Running pytest: -v, -k, -x, --lf, and coverage
#  10. Practice
#
# HOW TO RUN IT (section 1 explains the setup):
#   python3 -m venv .venv                   once, in the repository folder
#   .venv/bin/pip install -r requirements.txt
#   .venv/bin/pytest advanced/testing_with_pytest.py -v
# or  .venv/bin/python advanced/testing_with_pytest.py  (runs pytest for you)


import hashlib
import ipaddress
import logging
import os
import re
import shutil
import sys
from unittest import mock

try:
    import pytest
except ImportError:                                    # not installed: say how to set it up, then stop
    sys.exit("This lesson needs pytest, which isn't installed for this Python.\n"
             "Set up a virtual environment once, from the repository folder:\n"
             "  python3 -m venv .venv\n"
             "  .venv/bin/pip install -r requirements.txt\n"
             "then run:\n"
             "  .venv/bin/pytest advanced/testing_with_pytest.py -v")


# ---------------------------------------------------------------
# 1. Setting up
# ---------------------------------------------------------------
#
# pytest isn't part of Python: it's a PACKAGE, installed with pip. Don't
# install packages into the system Python (macOS's Homebrew Python even
# refuses: "externally-managed-environment", PEP 668). Make a VIRTUAL
# ENVIRONMENT instead: a private copy of Python just for this project,
# in a .venv folder, with its own packages.
#
#   python3 -m venv .venv                    create it (once)
#   .venv/bin/pip install -r requirements.txt   install what the project needs
#   source .venv/bin/activate                (optional) so `python`/`pytest` use it
#
# requirements.txt lists the packages, one per line, so anyone can
# recreate the same environment. .venv itself is git-ignored: it's
# rebuilt, never committed.


# ---------------------------------------------------------------
# The code under test: small security functions, as seen in earlier lessons
# ---------------------------------------------------------------

FAILED = re.compile(r"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>.*) from (?P<ip>\S+) port \d+")


def parse_failed_login(line):
    """(user, ip) from an sshd 'Failed ...' line, or None. The user is
    matched greedily, so the IP is the LAST 'from <ip> port <n>': a fake
    one typed into the username can't frame someone else."""
    m = FAILED.search(line)
    if not m:
        return None
    ip = m["ip"]
    ipaddress.ip_address(ip)                           # raises ValueError if it isn't an IP
    return m["user"], ip


class LoginThrottle:
    """Lock an account after `limit` failures within `window` seconds."""

    def __init__(self, limit=5, window=300, clock=None):
        import time
        self.limit, self.window = limit, window
        self.clock = clock or time.monotonic
        self.failures = {}

    def record_failure(self, user):
        now = self.clock()
        recent = [t for t in self.failures.get(user, []) if now - t < self.window]
        recent.append(now)
        self.failures[user] = recent

    def is_locked(self, user):
        now = self.clock()
        return len([t for t in self.failures.get(user, []) if now - t < self.window]) >= self.limit


def hibp_fetch(prefix):                                # the real one calls the network
    import urllib.request
    with urllib.request.urlopen(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10) as r:
        return r.read().decode()


def times_leaked(password, fetch=None):
    """k-anonymity: only the first 5 characters of the SHA-1 leave the machine."""
    fetch = fetch or hibp_fetch
    digest = hashlib.sha1(password.encode()).hexdigest().upper()
    for line in fetch(digest[:5]).splitlines():
        suffix, _, count = line.partition(":")
        if suffix == digest[5:]:
            return int(count)
    return 0


audit = logging.getLogger("audit")


def login(user, password, throttle):
    if throttle.is_locked(user):
        audit.warning("LOCKED login attempt for %s", user)
        raise PermissionError(f"{user} is locked out")
    ok = password == os.environ.get("LESSON_PASSWORD")
    if not ok:
        throttle.record_failure(user)
        audit.warning("FAILED login for %s", user)       # never log the password itself
    return ok


# ---------------------------------------------------------------
# 2. Test functions
# ---------------------------------------------------------------
#
# pytest runs every function whose name starts with test_. Inside, a
# plain `assert` is enough: when one fails, pytest REWRITES it to show
# both sides, e.g.
#   assert ('root', '203.0.113.5') == ('root', '203.0.113.9')
#     At index 1 diff: '203.0.113.5' != '203.0.113.9'
# No more guessing which part was wrong.

def test_parses_a_failed_login():
    line = "Failed password for root from 203.0.113.9 port 22 ssh2"
    assert parse_failed_login(line) == ("root", "203.0.113.9")


def test_ignores_other_lines():
    assert parse_failed_login("Accepted publickey for alice from 192.0.2.5 port 22 ssh2") is None


# ---------------------------------------------------------------
# 3. Testing that errors happen
# ---------------------------------------------------------------
#
# Code that should REFUSE something needs a test proving it does.
# `with pytest.raises(ErrorType, match="regex")` passes only if that
# error is raised inside the block, with a matching message.

def test_rejects_a_fake_ip():
    with pytest.raises(ValueError, match="does not appear to be"):
        parse_failed_login("Failed password for root from not-an-ip port 22 ssh2")


# ---------------------------------------------------------------
# 4. Many cases, one test: parametrize
# ---------------------------------------------------------------
#
# Attack inputs are exactly where you want MANY cases. Instead of copying
# a test ten times, list the cases; pytest runs the test once per case
# and reports each separately (with the `ids` as names).

@pytest.mark.parametrize("line, expected", [
    ("Failed password for root from 203.0.113.9 port 22 ssh2", ("root", "203.0.113.9")),
    ("Failed password for invalid user admin from 198.51.100.7 port 4 ssh2", ("admin", "198.51.100.7")),
    ("Failed password for invalid user  0101 from 5.188.10.180 port 9 ssh2", (" 0101", "5.188.10.180")),
    ("Failed password for x from 6.6.6.6 port 1 from 10.0.0.1 port 2 ssh2", ("x from 6.6.6.6 port 1", "10.0.0.1")),
    ("Failed publickey for git from 2001:db8::5 port 22 ssh2", ("git", "2001:db8::5")),
], ids=["plain", "invalid user", "leading space", "framing attempt", "IPv6"])
def test_parser_handles_real_and_hostile_lines(line, expected):
    assert parse_failed_login(line) == expected


# ---------------------------------------------------------------
# 5. Fixtures
# ---------------------------------------------------------------
#
# A FIXTURE is setup that tests ask for BY NAME: a test with a parameter
# called `throttle` gets whatever the `throttle` fixture returns. Each
# test gets a fresh one, so tests can't leak state into each other.
# Code after `yield` runs afterwards as clean-up, even if the test failed
# (like the context managers in decorators_and_context_managers.py).
# Fixtures shared by many test files go in a file called conftest.py.

class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def throttle(clock):                                    # fixtures can use other fixtures
    yield LoginThrottle(limit=3, window=60, clock=clock)
    # anything here runs after each test (nothing to clean up in this one)


def test_locks_after_the_limit(throttle):
    for _ in range(3):
        throttle.record_failure("alice")
    assert throttle.is_locked("alice")
    assert not throttle.is_locked("bob")               # per user


def test_unlocks_after_the_window(throttle, clock):
    for _ in range(3):
        throttle.record_failure("alice")
    clock.advance(61)                                   # no real waiting: the clock is fake
    assert not throttle.is_locked("alice")


# ---------------------------------------------------------------
# 6. Built-in fixtures: tmp_path, monkeypatch, caplog
# ---------------------------------------------------------------
#
#   tmp_path      a fresh temporary folder (a pathlib.Path) per test
#   monkeypatch   change an environment variable, attribute or dict for
#                 ONE test; undone automatically afterwards
#   caplog        captures log messages, so a test can check what was
#                 logged, and what WASN'T

def test_reads_a_log_file(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("Failed password for root from 203.0.113.9 port 22 ssh2\nnoise\n")
    found = [parse_failed_login(line) for line in log.read_text().splitlines()]
    assert [f for f in found if f] == [("root", "203.0.113.9")]


def test_password_never_reaches_the_log(monkeypatch, caplog, throttle):
    monkeypatch.setenv("LESSON_PASSWORD", "correct horse battery staple")
    caplog.set_level(logging.WARNING, logger="audit")
    assert login("alice", "hunter2-guess", throttle) is False
    assert "FAILED login for alice" in caplog.text
    assert "hunter2-guess" not in caplog.text          # the security property


def test_lockout_is_logged(monkeypatch, caplog, throttle):
    monkeypatch.setenv("LESSON_PASSWORD", "right")
    for _ in range(3):
        login("alice", "wrong", throttle)
    with pytest.raises(PermissionError):
        login("alice", "right", throttle)               # even the RIGHT password, once locked
    assert "LOCKED login attempt for alice" in caplog.text


# ---------------------------------------------------------------
# 7. Mocking: replacing the network
# ---------------------------------------------------------------
#
# Tests must not call real APIs: they'd be slow, flaky, rate limited, and
# here would send data out. unittest.mock (standard library) builds fake
# objects that record how they were called:
#   fake = mock.Mock(return_value="...")    a stand-in function
#   fake.assert_called_once_with("5BAA6")   check HOW it was called
#   mock.patch.object(module, "name", ...)  swap a real function for the
#                                           length of a `with` block
# Here that proves the k-anonymity property: only 5 characters are sent.

SHA1_OF_PASSWORD = hashlib.sha1(b"password").hexdigest().upper()


def test_breach_check_sends_only_5_characters():
    fake = mock.Mock(return_value=f"{SHA1_OF_PASSWORD[5:]}:9545824\r\nAAAA:1")
    assert times_leaked("password", fetch=fake) == 9545824
    fake.assert_called_once_with(SHA1_OF_PASSWORD[:5])


def test_the_real_fetch_can_be_patched_out():
    this_module = sys.modules[__name__]
    with mock.patch.object(this_module, "hibp_fetch", return_value="") as fake:
        assert times_leaked("something-unique-xyz") == 0
    assert fake.call_count == 1 and len(fake.call_args.args[0]) == 5


# ---------------------------------------------------------------
# 8. Marks: skip, skipif, xfail
# ---------------------------------------------------------------
#
#   @pytest.mark.skip(reason=...)          don't run it (say why)
#   @pytest.mark.skipif(cond, reason=...)  skip on some systems
#   @pytest.mark.xfail(reason=...)         EXPECTED to fail: a known bug or
#                                          limitation, written down as a
#                                          test. If it starts passing,
#                                          pytest tells you (XPASS).
# xfail is an honest way to record a limitation, like the false alarm
# documented in mistakes_and_lessons.md.

@pytest.mark.skipif(shutil.which("git") is None, reason="needs git installed")
def test_git_is_available():
    assert shutil.which("git")


@pytest.mark.xfail(reason="known limit: 'message repeated 5 times: [...]' is 5 attempts, but this "
                          "parser reports it as one login (log-detection-engine counts it properly)",
                   strict=True)
def test_known_limitation_repeated_lines_count_as_one():
    line = "message repeated 5 times: [ Failed password for root from 5.36.59.76 port 42393 ssh2]"
    assert parse_failed_login(line) == ("root", "5.36.59.76", 5)    # it returns no count


# ---------------------------------------------------------------
# 9. Running pytest
# ---------------------------------------------------------------
#
#   pytest FILE -v          every test by name, with PASSED/FAILED
#   pytest FILE -k lockout  only tests whose name contains "lockout"
#   pytest FILE -x          stop at the first failure
#   pytest --lf             re-run only what failed Last time
#   pytest -q               quiet: just the summary
#
# Two plugins worth knowing (pip install them into the venv):
#   pytest-cov    `pytest --cov=mymodule` shows which lines no test runs:
#                 untested code is where bugs hide
#   hypothesis    PROPERTY-BASED testing: you state a rule ("parsing never
#                 crashes on any string") and it invents thousands of
#                 inputs, including nasty ones. A cousin of fuzzing, which
#                 finds many real security bugs.
#
# And in CI (log-detection-engine's GitHub Actions), the same `pytest`
# command runs on every push.


# ---------------------------------------------------------------
# 10. Practice
# ---------------------------------------------------------------
#
# Practice: write a parametrised test that the parser returns None for
# lines that LOOK similar but aren't failed logins (an Accepted line, a
# "Failed" line from a different program, an empty line, random junk).
# Solution below.

@pytest.mark.parametrize("line", [
    "Accepted password for root from 203.0.113.9 port 22 ssh2",
    "Failed to start nginx.service",
    "",
    "\x00\xff garbage \U0001F4A9",
    "Failed password for root",                         # no "from ... port"
])
def test_parser_returns_none_for_lookalikes(line):
    assert parse_failed_login(line) is None


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
