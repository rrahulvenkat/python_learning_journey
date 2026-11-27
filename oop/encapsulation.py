# Encapsulation: protecting an object's data
#
# ENCAPSULATION means an object controls its own data. Other code uses
# its PUBLIC methods and properties, and doesn't reach in and change
# the internals. That way the object can guarantee its data always
# makes sense (its "invariants"): a port is always 1-65535, a lockout
# counter can't be reset by accident, a password never ends up in a
# log file.
#
# Topics covered here:
#   1. Public, "internal" (_name) and "mangled" (__name) attributes
#   2. Why Python's privacy is NOT a security boundary
#   3. @property: computed values and read-only attributes
#   4. Setters that validate (an IP address you can't set wrongly)
#   5. A Secret class: keeping credentials out of logs and tracebacks
#   6. Comparing secrets safely (timing attacks)
#   7. Keeping state consistent: an account lockout class
#   8. Defensive copies: don't hand out your internal lists
#   9. Practice, with tests
#
# SECURITY CONNECTION
# -------------------
# Leaked secrets in logs are one of the most common real-world
# findings: a debug log prints a request object, and the API key inside
# goes with it. A class that refuses to print its secret (section 5)
# prevents a whole category of mistakes. Validating at the boundary
# (section 4) stops bad data before it spreads.


import hmac
import ipaddress
import time
from datetime import datetime, timedelta, timezone


# ---------------------------------------------------------------
# 1. Public, internal and mangled names
# ---------------------------------------------------------------
#
#   name       public: part of the class's interface, use freely
#   _name      "internal": a CONVENTION meaning "don't touch from outside;
#              it may change". Python doesn't stop you.
#   __name     "name mangling": Python renames it to _ClassName__name,
#              mostly so SUBCLASSES don't clash with it by accident.
#
# Python has no truly private attributes. The philosophy is "we're all
# consenting adults": the underscore says "here be dragons".

class ApiClient:
    def __init__(self, base_url, token):
        self.base_url = base_url        # public
        self._session_count = 0         # internal
        self.__token = token            # mangled


def section_1():
    client = ApiClient("https://api.example", "tok_live_123")
    print("  public:   ", client.base_url)
    print("  internal: ", client._session_count, "(works, but you were warned)")
    try:
        client.__token
    except AttributeError as err:
        print("  mangled:  ", err)
    print("  ...but it's still there:", client._ApiClient__token)


# ---------------------------------------------------------------
# 2. Not a security boundary
# ---------------------------------------------------------------
#
# Section 1 just read a "private" token in one line. Any code running
# in the same Python process can read ANY object's data (and vars(),
# gc, debuggers and memory dumps can too).
#
#   Underscores protect against MISTAKES, not against ATTACKERS.
#
# Real protection comes from keeping secrets OUT of the process when
# possible (a secrets manager, environment variables read only when
# needed), limiting what a process can access (least privilege), and
# not logging or printing them (section 5).

def section_2():
    client = ApiClient("https://api.example", "tok_live_123")
    print("  vars(client):", vars(client))


# ---------------------------------------------------------------
# 3. @property: computed values and read-only attributes
# ---------------------------------------------------------------
#
# A property LOOKS like an attribute (no brackets) but runs a method.
# Without a setter it's READ-ONLY.
#
#   host.risk_score       not host.risk_score()
#
# Use it for values worked out from other data, so they can never be
# out of date.

class ScannedHost:
    RISKY = {21, 23, 445, 3389}

    def __init__(self, name, open_ports):
        self.name = name
        self._open_ports = frozenset(open_ports)

    @property
    def open_ports(self):
        return self._open_ports

    @property
    def risk_score(self):
        return 10 * len(self._open_ports & self.RISKY) + len(self._open_ports)


def section_3():
    h = ScannedHost("dc01", [53, 88, 445, 3389])
    print("  risk_score:", h.risk_score)
    try:
        h.risk_score = 0
    except AttributeError as err:
        print("  can't set it:", err)


# ---------------------------------------------------------------
# 4. Setters that validate
# ---------------------------------------------------------------
#
# @x.setter runs whenever someone ASSIGNS to x, including inside
# __init__. Put the check there once, and the object can never hold
# an invalid value, however it's changed.

class FirewallRule:
    def __init__(self, source, port, action="deny"):
        self.source = source            # these go through the setters below
        self.port = port
        self.action = action

    @property
    def source(self):
        return self._source

    @source.setter
    def source(self, value):
        # ip_network accepts single IPs too ("10.0.0.5" -> 10.0.0.5/32)
        self._source = ipaddress.ip_network(value, strict=True)

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, value):
        if not isinstance(value, int) or isinstance(value, bool) or not 0 < value < 65536:
            raise ValueError(f"port must be an int from 1 to 65535, got {value!r}")
        self._port = value

    @property
    def action(self):
        return self._action

    @action.setter
    def action(self, value):
        if value not in ("allow", "deny"):
            raise ValueError(f"action must be 'allow' or 'deny', got {value!r}")
        self._action = value

    def matches(self, ip, port):
        return port == self._port and ipaddress.ip_address(ip) in self._source

    def __repr__(self):
        return f"FirewallRule({str(self._source)!r}, {self._port}, {self._action!r})"


def section_4():
    rule = FirewallRule("203.0.113.0/24", 22)
    print("  ", rule, "| matches 203.0.113.9:22?", rule.matches("203.0.113.9", 22))
    for attempt in [("source", "203.0.113.0/33"), ("source", "10.0.0.1/24"),
                    ("port", 0), ("port", "22"), ("action", "drop")]:
        try:
            setattr(rule, *attempt)
        except ValueError as err:
            print(f"   {attempt[0]} = {attempt[1]!r:<18} rejected: {err}")
    print("   still valid:", rule)


# ---------------------------------------------------------------
# 5. A Secret class
# ---------------------------------------------------------------
#
# Wrap credentials in a class whose repr and str NEVER show the value.
# Then print(), f-strings, logging, error messages and tracebacks all
# show "Secret('********')", and you must call .reveal() on purpose
# to get the real value. (pydantic's SecretStr works the same way.)
#
# __slots__ stops extra attributes, and there's no __dict__ for
# vars() to dump. As section 2 says, this guards against ACCIDENTS:
# code that really wants the value can still call .reveal().

class Secret:
    __slots__ = ("_value",)

    def __init__(self, value):
        if not isinstance(value, str) or not value:
            raise ValueError("a secret must be a non-empty string")
        self._value = value

    def reveal(self):
        return self._value

    def __repr__(self):
        return "Secret('********')"

    __str__ = __repr__

    def __format__(self, spec):                       # f"{secret}" and f"{secret:>20}"
        return format(repr(self), spec)

    def __eq__(self, other):
        if not isinstance(other, Secret):
            return NotImplemented
        return hmac.compare_digest(self._value.encode(), other._value.encode())

    __hash__ = None                                    # don't put secrets in sets

    def __reduce__(self):                              # stop pickle writing it to disk
        raise TypeError("Secret objects can't be pickled")


class Credentials:
    def __init__(self, username, password):
        self.username = username
        self.password = Secret(password)

    def __repr__(self):
        return f"Credentials(username={self.username!r}, password={self.password!r})"


def section_5():
    creds = Credentials("svc-backup", "Winter2026!")
    print("  print:     ", creds)
    print(f"  f-string:   password is {creds.password}")
    print("  in a dict: ", {"user": creds.username, "pw": creds.password})
    try:
        raise RuntimeError(f"login failed for {creds}")
    except RuntimeError as err:
        print("  error msg: ", err)
    print("  on purpose:", creds.password.reveal())


# ---------------------------------------------------------------
# 6. Comparing secrets safely
# ---------------------------------------------------------------
#
# a == b on strings stops at the FIRST different character. So
# comparing a guess with a real token takes slightly longer the more
# leading characters are right. Over many network requests an attacker
# can measure that and recover the token one character at a time (a
# TIMING ATTACK, the same "yes/no leak" idea as first_bad_version.py).
#
# hmac.compare_digest() takes the same time wherever the difference
# is. Secret.__eq__ above uses it.
#
# The demo uses very long strings so the difference is easy to see
# on one machine. For a short token it's tiny, but real attacks
# average over thousands of requests to pull it out of the noise.

def time_compare(compare, secret, guess, rounds=2_000):
    start = time.perf_counter()
    for _ in range(rounds):
        compare(secret, guess)
    return time.perf_counter() - start


def section_6():
    n = 100_000
    real = "a" * n + "Z"
    early = "b" + "a" * n                              # wrong at the first character
    late = "a" * n + "Y"                               # wrong at the last character
    plain = lambda a, b: a == b
    safe = lambda a, b: hmac.compare_digest(a, b)
    for name, compare in (("==", plain), ("compare_digest", safe)):
        t_early = time_compare(compare, real, early)
        t_late = time_compare(compare, real, late)
        print(f"  {name:<15} wrong early {t_early:.4f}s, wrong late {t_late:.4f}s, "
              f"ratio {t_late / t_early:.2f}")


# ---------------------------------------------------------------
# 7. Keeping state consistent: account lockout
# ---------------------------------------------------------------
#
# The rules: after `max_failures` failed logins within `window`, the
# account locks for `lockout`. A success resets the count.
#
# The counter and lock time are INTERNAL. Outside code can only call
# record_failure() and record_success(), and read is_locked, so it can't
# get the object into a state the rules don't allow (like a locked
# account with zero failures, or a reset counter during a lock).
#
# `now` is passed in instead of reading the clock inside, which makes
# the class easy to test (the same idea as main() taking its streams in
# command_line_tools.py).

class LockoutPolicy:
    def __init__(self, max_failures=5, window=timedelta(minutes=15),
                 lockout=timedelta(minutes=30)):
        if max_failures < 1:
            raise ValueError("max_failures must be at least 1")
        self._max = max_failures
        self._window = window
        self._lockout = lockout
        self._failures = []
        self._locked_until = None

    def is_locked(self, now):
        return self._locked_until is not None and now < self._locked_until

    @property
    def failure_count(self):
        return len(self._failures)

    def record_failure(self, now):
        if self.is_locked(now):
            return "locked"                           # attempts during a lock don't count
        self._failures = [t for t in self._failures if now - t <= self._window] + [now]
        if len(self._failures) >= self._max:
            self._locked_until = now + self._lockout
            self._failures = []
            return "locked"
        left = self._max - len(self._failures)
        return f"{left} attempt{'s' if left != 1 else ''} left"

    def record_success(self, now):
        if self.is_locked(now):
            raise PermissionError("account is locked")
        self._failures = []


def section_7():
    policy = LockoutPolicy(max_failures=3)
    t = datetime(2026, 11, 27, 10, 0, tzinfo=timezone.utc)
    for minute in (0, 1, 2):
        print(f"  10:0{minute} failure ->", policy.record_failure(t + timedelta(minutes=minute)))
    try:
        policy.record_success(t + timedelta(minutes=3))
    except PermissionError as err:
        print("  10:03 correct password ->", err)
    print("  10:40 locked?", policy.is_locked(t + timedelta(minutes=40)))


# ---------------------------------------------------------------
# 8. Defensive copies
# ---------------------------------------------------------------
#
# Returning your internal LIST lets the caller change your data
# without going through your methods. Return a copy, a tuple, or a
# frozenset instead.

class LeakyAllowlist:
    def __init__(self, ips):
        self._ips = list(ips)

    def ips(self):
        return self._ips                              # the real list!


class SafeAllowlist:
    def __init__(self, ips):
        self._ips = frozenset(ipaddress.ip_address(ip) for ip in ips)

    def ips(self):
        return self._ips                              # frozenset: can't be changed

    def allows(self, ip):
        return ipaddress.ip_address(ip) in self._ips


def section_8():
    leaky = LeakyAllowlist(["10.0.0.5"])
    leaky.ips().append("0.0.0.0")                     # changed from outside
    print("  leaky allowlist now:", leaky.ips())
    safe = SafeAllowlist(["10.0.0.5"])
    try:
        safe.ips().add("0.0.0.0")
    except AttributeError as err:
        print("  safe allowlist:", err)


# ---------------------------------------------------------------
# 9. Practice
# ---------------------------------------------------------------
#
# Write an ApiKey class yourself first, then compare:
#   - built from a string like "sk_live_" + 24 or more letters/digits
#   - .environment is "live" or "test", from the prefix
#   - repr shows only the last 4 characters: ApiKey('sk_live_...WXYZ')
#   - == compares in constant time
#   - the value can't be changed after creation

import re

API_KEY = re.compile(r"sk_(live|test)_[A-Za-z0-9]{24,}")


class ApiKey:
    __slots__ = ("_value",)

    def __init__(self, value):
        if not API_KEY.fullmatch(value):
            raise ValueError("not a valid API key")
        object.__setattr__(self, "_value", value)

    def __setattr__(self, name, value):
        raise AttributeError("ApiKey is read-only")

    @property
    def environment(self):
        return API_KEY.fullmatch(self._value).group(1)

    def reveal(self):
        return self._value

    def __repr__(self):
        return f"ApiKey('sk_{self.environment}_...{self._value[-4:]}')"

    def __eq__(self, other):
        if not isinstance(other, ApiKey):
            return NotImplemented
        return hmac.compare_digest(self._value, other._value)

    __hash__ = None


def run_tests():
    # FirewallRule validation
    rule = FirewallRule("10.0.0.0/8", 443, "allow")
    assert rule.matches("10.20.30.40", 443) and not rule.matches("11.0.0.1", 443)
    assert not rule.matches("10.0.0.1", 80)
    assert FirewallRule("10.0.0.5", 22).source == ipaddress.ip_network("10.0.0.5/32")
    for kwargs in [dict(source="10.0.0.1/24"), dict(source="nonsense"), dict(port=0),
                   dict(port=True), dict(port=22.0), dict(action="DROP")]:
        args = dict(source="10.0.0.0/8", port=22, action="deny") | kwargs
        try:
            FirewallRule(**args)
            assert False, kwargs
        except ValueError:
            pass

    # Secret never shows its value
    s = Secret("hunter2")
    for text in (repr(s), str(s), f"{s}", f"{s:>30}", repr([s]), repr({"k": s}),
                 repr(Credentials("u", "hunter2"))):
        assert "hunter2" not in text, text
    assert s.reveal() == "hunter2"
    assert Secret("a") == Secret("a") and Secret("a") != Secret("b")
    try:
        {s}
        assert False
    except TypeError:
        pass
    import pickle
    try:
        pickle.dumps(s)
        assert False
    except TypeError:
        pass
    try:
        s.extra = 1                                    # __slots__
        assert False
    except AttributeError:
        pass

    # Lockout policy
    t0 = datetime(2026, 11, 27, 10, 0, tzinfo=timezone.utc)
    p = LockoutPolicy(max_failures=3, window=timedelta(minutes=10), lockout=timedelta(minutes=30))
    assert p.record_failure(t0) == "2 attempts left"
    assert p.record_failure(t0 + timedelta(minutes=20)) == "2 attempts left"   # old one expired
    p.record_failure(t0 + timedelta(minutes=21))
    assert p.record_failure(t0 + timedelta(minutes=22)) == "locked"
    assert p.is_locked(t0 + timedelta(minutes=30))
    assert p.record_failure(t0 + timedelta(minutes=31)) == "locked"            # doesn't extend it
    try:
        p.record_success(t0 + timedelta(minutes=40))
        assert False
    except PermissionError:
        pass
    assert not p.is_locked(t0 + timedelta(minutes=52))
    p.record_success(t0 + timedelta(minutes=53))
    assert p.failure_count == 0
    try:
        p.failure_count = 99
        assert False
    except AttributeError:
        pass

    # Defensive copies
    safe = SafeAllowlist(["10.0.0.5", "10.0.0.6"])
    assert safe.allows("10.0.0.5") and not safe.allows("10.0.0.7")
    assert isinstance(safe.ips(), frozenset)

    # ApiKey (the practice)
    key = ApiKey("sk_live_" + "A1b2C3d4" * 3 + "WXYZ")
    assert key.environment == "live"
    assert repr(key) == "ApiKey('sk_live_...WXYZ')" and "A1b2" not in repr(key)
    assert ApiKey("sk_test_" + "x" * 24).environment == "test"
    assert key == ApiKey(key.reveal()) and key != ApiKey("sk_live_" + "z" * 24)
    for bad in ["sk_live_short", "pk_live_" + "x" * 24, "sk_prod_" + "x" * 24]:
        try:
            ApiKey(bad)
            assert False, bad
        except ValueError:
            pass
    try:
        key._value = "sk_live_" + "h" * 24
        assert False
    except AttributeError:
        pass

    print("All tests passed!")


if __name__ == "__main__":
    for number, section in enumerate([section_1, section_2, section_3, section_4, section_5,
                                      section_6, section_7, section_8], start=1):
        print(f"\n--- {number}. {section.__name__} ---")
        section()
    print()
    run_tests()
