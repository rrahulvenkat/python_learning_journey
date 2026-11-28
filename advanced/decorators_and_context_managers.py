# Decorators and Context Managers (plus logging and generator extras)
#
# fundamentals/functions.py showed a first decorator, and
# fundamentals/file_handling.py USED `with open(...)`. This lesson goes
# further: writing decorators that take arguments, keeping the wrapped
# function's identity, writing your OWN `with` blocks, and what happens
# when an exception flies through them.
#
# Both tools are everywhere in real code. Web frameworks put access
# rules on routes with decorators (Flask's @app.route, Django's
# @login_required); every database connection, lock and temporary file
# is a `with`. And both are natural places to put SECURITY checks: once,
# around the code, instead of copied into every function.
#
# Topics covered here:
#   1. Functions are objects, and closures remember
#   2. A decorator, and why functools.wraps matters
#   3. Decorators that take arguments: @retry(times=3)
#   4. Access control: @require_role("admin")
#   5. Rate limiting: @rate_limit(calls=3, per=60)
#   6. The logging module, and an @audit_log decorator
#   7. Stacking decorators: the ORDER matters
#   8. What `with` really does: __enter__ and __exit__
#   9. Writing context managers the easy way: @contextmanager
#  10. contextlib extras: suppress and ExitStack
#  11. Generator extras: yield from, and following a growing log file
#  12. Practice, with tests
#
# HOW TO RUN IT
#   python3 decorators_and_context_managers.py


import contextlib
import functools
import io
import logging
import os
import shutil
import stat
import sys
import tempfile
import time
from collections import deque
from pathlib import Path


# ---------------------------------------------------------------
# 1. Functions are objects, and closures remember
# ---------------------------------------------------------------
#
# A function can be stored in a variable, passed to another function,
# and RETURNED from one. A function defined inside another remembers the
# outer function's variables even after the outer one has finished:
# that's a CLOSURE. Every decorator below is built from these two facts.

def make_counter():
    count = 0

    def increment():
        nonlocal count            # "count" belongs to make_counter, not to increment
        count += 1
        return count
    return increment


def section_1():
    counter = make_counter()
    counter(), counter()
    print(f"  a closure kept its own count: {counter()}")    # 3


# ---------------------------------------------------------------
# 2. A decorator, and why functools.wraps matters
# ---------------------------------------------------------------
#
#   @timed
#   def scan(): ...
#
# is exactly the same as  scan = timed(scan) : timed receives the
# function and returns a REPLACEMENT that runs some code around it.
#
# The trap: the replacement is the inner `wrapper` function, so the
# decorated function now reports its name as "wrapper" and loses its
# docstring. That breaks error messages, logs, help() and tools like
# pytest. @functools.wraps(func) copies the original's name, docstring
# and more onto the wrapper. Use it on EVERY decorator you write.

def timed_without_wraps(func):
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper


def timed(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        try:
            return func(*args, **kwargs)
        finally:
            wrapper.last_seconds = time.perf_counter() - start   # a function can carry attributes
    wrapper.last_seconds = None
    return wrapper


@timed_without_wraps
def hash_file_v1(path):
    """Return the SHA-256 of a file."""


@timed
def hash_file_v2(path):
    """Return the SHA-256 of a file."""


def section_2():
    print(f"  without wraps: name={hash_file_v1.__name__!r}, doc={hash_file_v1.__doc__!r}")
    print(f"  with wraps:    name={hash_file_v2.__name__!r}, doc={hash_file_v2.__doc__!r}")


# ---------------------------------------------------------------
# 3. Decorators that take arguments
# ---------------------------------------------------------------
#
#   @retry(times=3)
#   def fetch(): ...
#
# means  fetch = retry(times=3)(fetch) . So retry(...) isn't the
# decorator: it RETURNS the decorator. That's three nested functions:
#   retry(times)          -> remembers the settings, returns...
#     decorator(func)     -> remembers the function, returns...
#       wrapper(*args)    -> what actually runs on each call
#
# Retrying is useful for flaky NETWORK calls (a threat-intel API that
# times out now and then). Only retry errors that might go away: a
# timeout, yes; "wrong password", no, or you've written a brute-forcer.

def retry(times=3, delay=0.0, on=(ConnectionError, TimeoutError)):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(1, times + 1):
                try:
                    return func(*args, **kwargs)
                except on:
                    if attempt == times:
                        raise                        # out of attempts: let the error through
                    time.sleep(delay * attempt)      # wait a little longer each time
        return wrapper
    return decorator


# ---------------------------------------------------------------
# 4. Access control: @require_role("admin")
# ---------------------------------------------------------------
#
# Checking permissions inside every function means one forgotten check
# is a hole. A decorator puts the rule ON the function, where a reviewer
# sees it at a glance. Here the first argument is the user making the
# request, a dict like {"name": "alice", "roles": {"user"}}.

def require_role(role):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(user, *args, **kwargs):
            if role not in user.get("roles", set()):
                raise PermissionError(f"{user.get('name')} needs the {role!r} role for {func.__name__}")
            return func(user, *args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------
# 5. Rate limiting: @rate_limit(calls=3, per=60)
# ---------------------------------------------------------------
#
# The defence against online password guessing (projects/
# password_analyzer) and code guessing (projects/totp_generator): allow
# only so many calls per user per time window. The same sliding window
# with a deque as the brute-force detector in log-detection-engine, used
# here to PREVENT rather than detect. Each decorated function gets its
# own `history`, kept in the closure.

class RateLimited(Exception):
    pass


def rate_limit(calls, per, clock=time.monotonic):
    def decorator(func):
        history = {}                                 # user name -> deque of call times

        @functools.wraps(func)
        def wrapper(user, *args, **kwargs):
            now = clock()
            recent = history.setdefault(user["name"], deque())
            while recent and now - recent[0] >= per:
                recent.popleft()
            if len(recent) >= calls:
                raise RateLimited(f"{user['name']}: more than {calls} calls in {per}s")
            recent.append(now)
            return func(user, *args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------
# 6. The logging module, and @audit_log
# ---------------------------------------------------------------
#
# print() is fine for lessons, but real tools LOG:
#   * levels: DEBUG < INFO < WARNING < ERROR < CRITICAL, so you can turn
#     detail up or down without editing code
#   * named loggers: logging.getLogger("audit") is the same object
#     everywhere in the program
#   * handlers decide WHERE messages go (the terminal, a file, a SIEM),
#     and formatters decide what they look like
#
# An audit log records who did what, and whether it was allowed.
# Two rules for logging in security code:
#   * NEVER log secrets: a password in a log file is a leaked password.
#     So arguments with sensitive names are written as "***".
#   * Log failures too: denied attempts are exactly what an
#     investigator needs. A call that RETURNS False (a wrong password)
#     is a failure as well, not "OK", even though nothing was raised.

audit = logging.getLogger("audit")
SENSITIVE = {"password", "token", "secret", "api_key", "code"}


def audit_log(func):
    @functools.wraps(func)
    def wrapper(user, *args, **kwargs):
        shown = {k: ("***" if k in SENSITIVE else v) for k, v in kwargs.items()}
        try:
            result = func(user, *args, **kwargs)
        except Exception as err:
            audit.warning("DENIED %s by %s %s: %s", func.__name__, user.get("name"), shown, err)
            raise
        if result is False:
            audit.warning("FAILED %s by %s %s", func.__name__, user.get("name"), shown)
        else:
            audit.info("OK %s by %s %s", func.__name__, user.get("name"), shown)
        return result
    return wrapper


# ---------------------------------------------------------------
# 7. Stacking decorators: the ORDER matters
# ---------------------------------------------------------------
#
#   @audit_log              applied LAST, so it runs FIRST (outermost)
#   @require_role("admin")
#   def delete_user(...)
#
# is  delete_user = audit_log(require_role("admin")(delete_user)) .
# With audit_log on the outside, a refused call still passes THROUGH it,
# so the refusal is logged. Swap them, and require_role raises before
# audit_log is ever reached: the attempts you most want to see vanish
# from the log.

@audit_log
@require_role("admin")
def delete_user(user, target):
    return f"deleted {target}"


@require_role("admin")
@audit_log
def delete_user_wrong_order(user, target):
    return f"deleted {target}"


@audit_log
@rate_limit(calls=3, per=60)
def login(user, password):
    return password == "correct horse battery staple"


# ---------------------------------------------------------------
# 8. What `with` really does
# ---------------------------------------------------------------
#
#   with EXPRESSION as name:
#       body
#
# calls  name = EXPRESSION.__enter__()  before the body, and
# EXPRESSION.__exit__(exc_type, exc_value, traceback)  after it, ALWAYS:
# whether the body finished, returned, or raised. If the body raised,
# __exit__ gets the exception's details; if it returns True, the
# exception is SWALLOWED. That's almost always a bug in security code: a
# failed check must not be silently ignored. Return False (or nothing).
#
# A class with those two methods is a context manager. A timer:

class Timer:
    def __enter__(self):
        self.start = time.perf_counter()
        self.seconds = None
        return self                                   # what "as t" receives

    def __exit__(self, exc_type, exc_value, traceback):
        self.seconds = time.perf_counter() - self.start
        return False                                  # never hide an exception


# ---------------------------------------------------------------
# 9. Writing context managers the easy way: @contextmanager
# ---------------------------------------------------------------
#
# contextlib.contextmanager turns a GENERATOR into a context manager:
# the code before `yield` is __enter__, the yielded value is what "as"
# receives, and the code after `yield` is __exit__. Put the cleanup in a
# `finally`, or it won't run when the body raises.
#
# A private temporary folder for sensitive work (decrypted files, a
# cloned repo being scanned): only you can read it (0o700), and it's
# deleted however the block ends.

@contextlib.contextmanager
def private_temp_dir():
    path = Path(tempfile.mkdtemp(prefix="private-"))
    path.chmod(stat.S_IRWXU)                          # 0o700: owner only
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)       # always cleaned up


# Setting environment variables for a moment (a test, a child process)
# and putting them back exactly as they were afterwards, including ones
# that didn't exist before.
@contextlib.contextmanager
def temporary_env(**values):
    saved = {name: os.environ.get(name) for name in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for name, old in saved.items():
            if old is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = old


# ---------------------------------------------------------------
# 10. contextlib extras
# ---------------------------------------------------------------
#
#   contextlib.suppress(FileNotFoundError)
#       ignore ONE specific, expected error, by name. Much safer than a
#       bare "except: pass", which hides every bug.
#
#   contextlib.ExitStack()
#       when you don't know in advance how many things to open (every
#       log file in a folder), push each one onto a stack; they're ALL
#       closed at the end, even if opening the fifth one fails.

def first_lines(paths):
    with contextlib.ExitStack() as stack:
        files = [stack.enter_context(open(p, encoding="utf-8")) for p in paths]
        return [f.readline().rstrip("\n") for f in files]


# ---------------------------------------------------------------
# 11. Generator extras
# ---------------------------------------------------------------
#
# `yield from other` hands over to another generator until it's done:
# a clean way to chain sources (every rotated log, oldest first).
#
# And a generator doesn't have to end. follow() works like `tail -f`:
# it yields lines as they're APPENDED to a growing log, waiting between
# checks. Real monitoring agents read logs this way. (`max_idle` stops it
# after a quiet spell, so tests and demos finish.)

def lines_of(*paths):
    for path in paths:
        with open(path, encoding="utf-8") as f:
            yield from (line.rstrip("\n") for line in f)


def follow(path, poll=0.05, max_idle=None, sleep=time.sleep):
    idle = 0.0
    with open(path, encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)                        # start at the end, like tail -f
        while max_idle is None or idle < max_idle:
            line = f.readline()
            if line:
                idle = 0.0
                yield line.rstrip("\n")
            else:
                sleep(poll)
                idle += poll


# ---------------------------------------------------------------
# The lesson
# ---------------------------------------------------------------

def lesson():
    print("--- 1-2. Closures, and functools.wraps ---")
    section_1()
    section_2()

    print("\n--- 4-7. Access control, rate limits and an audit log ---")
    handler = logging.StreamHandler(sys.stdout)      # stdout, so it prints in order with the rest
    handler.setFormatter(logging.Formatter("  [audit] %(levelname)s %(message)s"))
    audit.addHandler(handler)
    audit.setLevel(logging.INFO)
    alice = {"name": "alice", "roles": {"user"}}
    root = {"name": "root", "roles": {"user", "admin"}}
    try:
        print(f"  {delete_user(root, target='bob')}")
        delete_user(alice, target="bob")
    except PermissionError as e:
        print(f"  refused: {e}")
    try:
        delete_user_wrong_order(alice, target="bob")
    except PermissionError:
        print("  (wrong order: refused too, but notice NOTHING was logged for it)")
    for _ in range(4):
        try:
            login(alice, password="guess")
        except RateLimited as e:
            print(f"  {e}")
    audit.removeHandler(handler)

    print("\n--- 8-9. Context managers ---")
    with Timer() as t:
        sum(range(1_000_000))
    print(f"  Timer: {t.seconds * 1000:.1f} ms")
    with private_temp_dir() as tmp:
        (tmp / "decrypted.txt").write_text("sensitive")
        print(f"  private folder {tmp.name}, mode {oct(tmp.stat().st_mode & 0o777)}")
    print(f"  after the block, does it still exist? {tmp.exists()}")


# ---------------------------------------------------------------
# 12. Practice and tests
# ---------------------------------------------------------------
#
# Practice: write @cache_for(seconds), a decorator that remembers each
# result for a while, like a DNS or threat-intel cache: the same
# question within `seconds` returns the saved answer without calling the
# function again. It takes an argument (section 3), so it's three levels
# deep. Solution below.

def cache_for(seconds, clock=time.monotonic):
    def decorator(func):
        saved = {}                                    # args -> (time, result)

        @functools.wraps(func)
        def wrapper(*args):
            now = clock()
            if args in saved and now - saved[args][0] < seconds:
                return saved[args][1]
            result = func(*args)
            saved[args] = (now, result)
            return result
        return wrapper
    return decorator


def run_tests():
    # 1. Closures keep separate state
    a, b = make_counter(), make_counter()
    assert (a(), a(), b()) == (1, 2, 1)

    # 2. wraps keeps the name and docstring
    assert hash_file_v1.__name__ == "wrapper" and hash_file_v1.__doc__ is None
    assert hash_file_v2.__name__ == "hash_file_v2" and "SHA-256" in hash_file_v2.__doc__
    hash_file_v2("x")
    assert hash_file_v2.last_seconds is not None and hash_file_v2.__wrapped__ is not None

    # 3. retry: succeeds after flaky failures, gives up eventually, never retries other errors
    calls = []

    @retry(times=3)
    def flaky():
        calls.append(1)
        if len(calls) < 3:
            raise TimeoutError("slow API")
        return "ok"
    assert flaky() == "ok" and len(calls) == 3

    @retry(times=2)
    def always_down():
        raise ConnectionError("down")
    try:
        always_down()
    except ConnectionError:
        pass
    else:
        raise AssertionError("should have given up")

    wrong = []

    @retry(times=5)
    def bad_password():
        wrong.append(1)
        raise PermissionError("wrong password")
    try:
        bad_password()
    except PermissionError:
        assert len(wrong) == 1                        # not retried: retrying would be guessing
    else:
        raise AssertionError("PermissionError should pass straight through")

    # 4. require_role
    alice = {"name": "alice", "roles": {"user"}}
    root = {"name": "root", "roles": {"admin"}}

    @require_role("admin")
    def wipe(user):
        return "wiped"
    assert wipe(root) == "wiped"
    try:
        wipe(alice)
    except PermissionError as e:
        assert "alice" in str(e) and "admin" in str(e)
    else:
        raise AssertionError("alice isn't an admin")

    # 5. rate_limit, with a fake clock so the test doesn't wait
    now = [0.0]

    @rate_limit(calls=2, per=60, clock=lambda: now[0])
    def check_code(user, code):
        return False
    check_code(alice, "1"), check_code(alice, "2")
    try:
        check_code(alice, "3")
    except RateLimited:
        pass
    else:
        raise AssertionError("third call within a minute should be limited")
    check_code(root, "1")                             # limits are per user
    now[0] = 61
    check_code(alice, "4")                            # the window moved on

    # 6-7. The audit log: secrets hidden, refusals recorded, and order matters
    captured = io.StringIO()
    handler = logging.StreamHandler(captured)
    audit.addHandler(handler)
    audit.setLevel(logging.INFO)
    try:
        assert delete_user(root, target="bob") == "deleted bob"
        for f in (delete_user, delete_user_wrong_order):
            try:
                f(alice, target="bob")
            except PermissionError:
                pass
        login({"name": "carol"}, password="hunter2")
    finally:
        audit.removeHandler(handler)
    log = captured.getvalue()
    assert "OK delete_user by root" in log and "DENIED delete_user by alice" in log
    assert "delete_user_wrong_order" not in log         # refused BEFORE reaching audit_log
    assert "hunter2" not in log and "'password': '***'" in log
    assert "FAILED login by carol" in log               # a wrong password is a failure, not "OK"

    # 8. Timer runs __exit__ even when the body raises, and doesn't hide the error
    t = Timer()
    try:
        with t:
            raise ValueError("boom")
    except ValueError:
        pass
    else:
        raise AssertionError("the exception was swallowed")
    assert t.seconds is not None

    # 9. private_temp_dir: owner-only, and deleted even after an error
    try:
        with private_temp_dir() as tmp:
            assert tmp.stat().st_mode & 0o777 == 0o700
            (tmp / "x").write_text("secret")
            raise RuntimeError("crash mid-way")
    except RuntimeError:
        pass
    assert not tmp.exists()

    os.environ.pop("LESSON_VAR", None)
    with temporary_env(LESSON_VAR="1", HOME="/tmp/elsewhere"):
        assert os.environ["LESSON_VAR"] == "1"
    assert "LESSON_VAR" not in os.environ and os.environ.get("HOME") != "/tmp/elsewhere"

    # 10-11. suppress, ExitStack, yield from, follow
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        with contextlib.suppress(FileNotFoundError):
            (tmpdir / "missing").unlink()
        old, new = tmpdir / "auth.log.1", tmpdir / "auth.log"
        old.write_text("line 1\nline 2\n")
        new.write_text("line 3\n")
        assert first_lines([old, new]) == ["line 1", "line 3"]
        assert list(lines_of(old, new)) == ["line 1", "line 2", "line 3"]

        growing = tmpdir / "live.log"
        growing.write_text("before we started\n")
        appended = iter(["Failed password for root", "Accepted publickey for alice"])

        def fake_sleep(_):                            # each "wait", another line arrives
            line = next(appended, None)
            if line:
                with open(growing, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
        seen = list(follow(growing, poll=1, max_idle=2, sleep=fake_sleep))
        assert seen == ["Failed password for root", "Accepted publickey for alice"]

    # Practice: cache_for
    lookups, clock = [], [0.0]

    @cache_for(60, clock=lambda: clock[0])
    def reputation(ip):
        lookups.append(ip)
        return "bad" if ip.startswith("203.0.113.") else "ok"
    assert reputation("203.0.113.9") == "bad" and reputation("203.0.113.9") == "bad"
    assert lookups == ["203.0.113.9"]                 # second answer came from the cache
    clock[0] = 61
    reputation("203.0.113.9")
    assert len(lookups) == 2                          # expired: asked again
    assert reputation.__name__ == "reputation"

    print("All tests passed!")


if __name__ == "__main__":
    lesson()
    print()
    run_tests()
