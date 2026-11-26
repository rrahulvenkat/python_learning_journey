# Log Parsing with Regular Expressions
#
# PROBLEM
# -------
# Given raw log text, solve five common problems:
#   1. Extract indicators: IPv4 addresses, emails, URLs, MD5/SHA-1/
#      SHA-256 hashes.
#   2. VALIDATE an IPv4 address with a regex, correctly.
#   3. Parse web server log lines into dictionaries with named groups.
#   4. Count failed SSH logins per IP from an auth log.
#   5. Redact secrets (passwords, API keys, card numbers) before a log
#      is shared.
#
# KEY IDEAS
# ---------
#   - EXTRACTING and VALIDATING are different jobs:
#       extract  -> re.findall / finditer with boundaries
#       validate -> re.fullmatch, so nothing extra can sneak in
#   - A loose pattern is easy to write and wrong. \d+\.\d+\.\d+\.\d+
#     "finds" 999.999.999.999 and pieces of version numbers. Tighten
#     the pattern, then CHECK it against a trusted library
#     (ipaddress) in the tests.
#   - Named groups (?P<name>...) plus m.groupdict() turn each log line
#     into a dictionary, ready for the Counter and defaultdict tools
#     from data_structures/dictionaries.py.
#   - Compile patterns ONCE at the top of the file, not inside loops.
#
# WHAT'S NEW HERE
# ---------------
# regex_fundamentals.py taught the syntax. This file uses it on real
# log formats (the Apache/Nginx "combined" format and Linux auth.log)
# and shows how to test a regex against edge cases.
#
# SECURITY CONNECTION
# -------------------
# This is the core of a log analyzer, and of threat-intel work:
# pulling indicators of compromise (IOCs) out of text, summarising
# who did what, and spotting brute-force attempts. Redaction matters
# because logs often leak secrets, and they get pasted into tickets,
# chats and reports.


import ipaddress
import re
from collections import Counter, defaultdict


# ---------------------------------------------------------------
# Part 1: extracting indicators
# ---------------------------------------------------------------
#
# OCTET matches one number 0-255, written without leading zeros:
#   25[0-5]        250-255
#   2[0-4]\d       200-249
#   1\d\d          100-199
#   [1-9]?\d       0-99
# The order matters: alternation takes the FIRST option that works,
# so the longer forms must come first.
#
# The (?<![\d.]) and (?![\d.]) lookarounds stop matches inside longer
# runs, like part of "1.2.3.4.5" or "1234.1.1.1". The one exception
# is a full stop ending a sentence: (?!\.\d) allows "...at 1.2.3.4."
#
# Hashes are told apart by LENGTH: MD5 = 32 hex digits, SHA-1 = 40,
# SHA-256 = 64. \b on both sides stops a 64-digit hash also matching
# as a 32-digit one.

OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4 = re.compile(rf"(?<![\d.]){OCTET}(?:\.{OCTET}){{3}}(?!\d|\.\d)")

EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
URL = re.compile(r"\bhttps?://[^\s\"'<>]+")
HASHES = {
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
}


def extract_iocs(text):
    found = {
        "ipv4": sorted(set(IPV4.findall(text))),
        "email": sorted(set(EMAIL.findall(text))),
        "url": sorted({u.rstrip(".,);") for u in URL.findall(text)}),
    }
    for name, pattern in HASHES.items():
        found[name] = sorted({h.lower() for h in pattern.findall(text)})
    return found


# ---------------------------------------------------------------
# Part 2: validating an IPv4 address
# ---------------------------------------------------------------
#
#   pattern                  | "1.2.3.4" | "999.1.1.1" | "1.2.3.4x" | "01.2.3.4"
#   -------------------------|-----------|-------------|------------|-----------
#   loose, search            |   yes     |    yes      |   yes      |   yes
#   strict OCTET, fullmatch  |   yes     |    no       |   no       |   no
#
# Leading zeros are rejected on purpose: some systems read "010" as
# OCTAL (8), so "010.0.0.1" can mean 8.0.0.1. Attackers use that
# ambiguity to slip past filters.

LOOSE_IPV4 = re.compile(r"\d+\.\d+\.\d+\.\d+")
STRICT_IPV4 = re.compile(rf"{OCTET}(?:\.{OCTET}){{3}}", re.ASCII)

def is_valid_ipv4_loose(text):
    return LOOSE_IPV4.search(text) is not None          # the WRONG way

def is_valid_ipv4(text):
    return STRICT_IPV4.fullmatch(text) is not None


# ---------------------------------------------------------------
# Part 3: parsing web server logs (the "combined" format)
# ---------------------------------------------------------------
#
# A line looks like this:
#   203.0.113.9 - - [27/Nov/2026:10:15:32 +0000] "GET /admin HTTP/1.1" 403 512 "-" "curl/8.4"
#
#   ip  -  user  [time]  "method path protocol"  status  size  "referrer"  "user agent"
#
# re.VERBOSE lets the pattern be split over lines with comments. In
# VERBOSE mode plain spaces are ignored, so real spaces are written
# as \s.

ACCESS_LOG = re.compile(r"""
    ^(?P<ip>\S+) \s \S+ \s (?P<user>\S+) \s
    \[(?P<time>[^\]]+)\] \s
    "(?P<method>[A-Z]+) \s (?P<path>\S+) \s (?P<protocol>[^"]+)" \s
    (?P<status>\d{3}) \s (?P<size>\d+|-) \s
    "(?P<referrer>[^"]*)" \s
    "(?P<agent>[^"]*)"$
""", re.VERBOSE)


def parse_access_log(lines):
    """Return (parsed entries, lines that didn't match)."""
    entries, bad = [], []
    for line in lines:
        m = ACCESS_LOG.match(line.strip())
        if m:
            entry = m.groupdict()
            entry["status"] = int(entry["status"])
            entry["size"] = 0 if entry["size"] == "-" else int(entry["size"])
            entries.append(entry)
        elif line.strip():
            bad.append(line)                             # never silently drop lines
    return entries, bad


SUSPICIOUS_PATHS = re.compile(
    r"(\.\./|/etc/passwd|wp-admin|\.env\b|union\W+select|<script)", re.I)

def suspicious_requests(entries):
    return [e for e in entries if SUSPICIOUS_PATHS.search(e["path"])]


# ---------------------------------------------------------------
# Part 4: failed SSH logins per IP (Linux auth.log)
# ---------------------------------------------------------------
#
# Lines look like:
#   Nov 27 10:01:02 web01 sshd[811]: Failed password for root from 198.51.100.7 port 51122 ssh2
#   Nov 27 10:01:09 web01 sshd[815]: Failed password for invalid user admin from 198.51.100.7 port 51130 ssh2
#   Nov 27 10:02:00 web01 sshd[820]: Accepted publickey for alice from 192.0.2.10 port 50000 ssh2
#
# "(?:invalid user )?" makes that phrase optional, so one pattern
# handles both kinds of failure.

SSH_EVENT = re.compile(
    r"sshd\[\d+\]: (?P<result>Failed|Accepted) \w+ for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+) port \d+")


def ssh_summary(lines, threshold=5):
    failures = Counter()
    users_tried = defaultdict(set)
    accepted = []
    for line in lines:
        m = SSH_EVENT.search(line)
        if not m:
            continue
        if m["result"] == "Failed":                      # m["name"] is m.group("name")
            failures[m["ip"]] += 1
            users_tried[m["ip"]].add(m["user"])
        else:
            accepted.append((m["user"], m["ip"]))

    flagged = {ip: {"failures": n, "users": sorted(users_tried[ip])}
               for ip, n in failures.items() if n >= threshold}
    # The worst case: a flagged IP that then got IN
    breaches = [(user, ip) for user, ip in accepted if ip in flagged]
    return flagged, breaches


# ---------------------------------------------------------------
# Part 5: redacting secrets
# ---------------------------------------------------------------
#
# re.sub can take a FUNCTION instead of a replacement string. It's
# called with each Match and returns the replacement. Here it keeps
# the label ("password=") and hides only the value.
#
# Card numbers are checked with the Luhn algorithm before being
# hidden, so ordinary long numbers (order IDs) are left alone.

SECRET_PAIRS = re.compile(
    r"(?P<key>\b(?:password|passwd|pwd|secret|token|api[_-]?key)\b\s*[=:]\s*)"
    r"(?P<value>\"[^\"]*\"|'[^']*'|\S+)", re.I)
AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
BEARER = re.compile(r"(?<=Bearer )[\w.~+/-]+=*")
CARD = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")


def luhn_valid(number):
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:                                   # every second digit from the right
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return len(digits) >= 13 and total % 10 == 0


def redact(text):
    text = SECRET_PAIRS.sub(lambda m: m["key"] + "[REDACTED]", text)
    text = AWS_KEY.sub("[AWS-KEY]", text)
    text = BEARER.sub("[TOKEN]", text)
    text = CARD.sub(lambda m: "[CARD]" if luhn_valid(m.group()) else m.group(), text)
    return text


# ---------------------------------------------------------------
# COMPLEXITY
# ---------------------------------------------------------------
#
# These patterns run in roughly O(n) time on the text, because none
# of them can backtrack badly. Patterns with NESTED quantifiers, like
# (a+)+, can take exponential time on hostile input: see
# regex_engine.py.
#
# For production log parsing, prefer a structured format (JSON logs)
# when you control the source, and regex when you don't.


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

SAMPLE_REPORT = """
Phishing mail from billing@pay-secure.example.net linked to
http://203.0.113.9/login.php?id=7, and a backup at https://cdn.bad.example/x.exe.
Dropper MD5 44d88612fea8a8f36de82e1278abb02f, SHA-256
275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F.
C2 at 198.51.100.77:4444. Not IPs: version 1.2.3.4.5, 999.1.1.1, 1234.1.1.1.
Seen again at 192.0.2.200.
"""

ACCESS_LINES = [
    '203.0.113.9 - - [27/Nov/2026:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 1043 "-" "Mozilla/5.0"',
    '203.0.113.9 - - [27/Nov/2026:10:15:40 +0000] "GET /../../etc/passwd HTTP/1.1" 400 0 "-" "curl/8.4"',
    '198.51.100.7 - bob [27/Nov/2026:10:16:01 +0000] "POST /login HTTP/1.1" 302 - "https://site/" "Mozilla/5.0"',
    '198.51.100.7 - - [27/Nov/2026:10:16:05 +0000] "GET /search?q=1%27+UNION+SELECT+password HTTP/1.1" 500 12 "-" "sqlmap/1.7"',
    'this line is garbage',
    '192.0.2.44 - - [27/Nov/2026:10:17:00 +0000] "GET /.env HTTP/1.1" 404 153 "-" "python-requests/2.31"',
]

AUTH_LINES = [
    "Nov 27 10:01:02 web01 sshd[811]: Failed password for root from 198.51.100.7 port 51122 ssh2",
    "Nov 27 10:01:05 web01 sshd[812]: Failed password for root from 198.51.100.7 port 51124 ssh2",
    "Nov 27 10:01:09 web01 sshd[815]: Failed password for invalid user admin from 198.51.100.7 port 51130 ssh2",
    "Nov 27 10:01:12 web01 sshd[816]: Failed password for invalid user test from 198.51.100.7 port 51133 ssh2",
    "Nov 27 10:01:15 web01 sshd[817]: Failed password for root from 198.51.100.7 port 51135 ssh2",
    "Nov 27 10:01:20 web01 sshd[818]: Accepted password for root from 198.51.100.7 port 51140 ssh2",
    "Nov 27 10:02:00 web01 sshd[820]: Accepted publickey for alice from 192.0.2.10 port 50000 ssh2",
    "Nov 27 10:03:00 web01 sshd[821]: Failed password for bob from 192.0.2.99 port 50100 ssh2",
    "Nov 27 10:03:30 web01 CRON[900]: session opened for user root",
]


def run_tests():
    # Part 1
    iocs = extract_iocs(SAMPLE_REPORT)
    assert iocs["ipv4"] == ["192.0.2.200", "198.51.100.77", "203.0.113.9"], iocs["ipv4"]
    assert iocs["email"] == ["billing@pay-secure.example.net"]
    assert iocs["url"] == ["http://203.0.113.9/login.php?id=7", "https://cdn.bad.example/x.exe"]
    assert iocs["md5"] == ["44d88612fea8a8f36de82e1278abb02f"]
    assert iocs["sha256"] == ["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"]
    assert iocs["sha1"] == []

    # Part 2: the strict regex agrees with the ipaddress module
    candidates = ["1.2.3.4", "0.0.0.0", "255.255.255.255", "192.168.1.1", "10.0.0.255",
                  "256.1.1.1", "999.1.1.1", "1.2.3", "1.2.3.4.5", "1.2.3.4x", " 1.2.3.4",
                  "01.2.3.4", "1.2.3.04", "a.b.c.d", "", "1..2.3", "1.2.3.-4"]
    for text in candidates:
        try:
            ipaddress.IPv4Address(text)
            expected = True
        except ValueError:
            expected = False
        assert is_valid_ipv4(text) == expected, text
    assert is_valid_ipv4_loose("999.1.1.1") is True         # the loose version is fooled
    assert is_valid_ipv4_loose("1.2.3.4x") is True

    # Part 3
    entries, bad = parse_access_log(ACCESS_LINES)
    assert len(entries) == 5 and bad == ["this line is garbage"]
    first = entries[0]
    assert first["ip"] == "203.0.113.9" and first["method"] == "GET"
    assert first["status"] == 200 and first["size"] == 1043
    assert entries[2]["user"] == "bob" and entries[2]["size"] == 0
    flagged_paths = [e["path"] for e in suspicious_requests(entries)]
    assert flagged_paths == ["/../../etc/passwd",
                             "/search?q=1%27+UNION+SELECT+password",
                             "/.env"], flagged_paths

    # Part 4
    flagged, breaches = ssh_summary(AUTH_LINES)
    assert flagged == {"198.51.100.7": {"failures": 5, "users": ["admin", "root", "test"]}}
    assert breaches == [("root", "198.51.100.7")]
    assert ssh_summary(AUTH_LINES, threshold=1)[0].keys() == {"198.51.100.7", "192.0.2.99"}

    # Part 5
    assert luhn_valid("4111 1111 1111 1111") is True        # a standard test card number
    assert luhn_valid("4111 1111 1111 1112") is False
    line = ("login ok password=hunter2 token: 'abc 123' key=AKIAIOSFODNN7EXAMPLE "
            "Authorization: Bearer eyJhbGciOi.eyJzdWIi.sig== card 4111-1111-1111-1111 "
            "order 1234567890123")
    cleaned = redact(line)
    assert "hunter2" not in cleaned and "abc 123" not in cleaned
    assert "password=[REDACTED]" in cleaned and "token: [REDACTED]" in cleaned
    assert "[AWS-KEY]" in cleaned and "Bearer [TOKEN]" in cleaned
    assert "card [CARD]" in cleaned
    assert "order 1234567890123" in cleaned                 # fails Luhn: not a card
    assert redact("nothing secret here") == "nothing secret here"

    print("All tests passed!")


if __name__ == "__main__":
    print("--- 1. Indicators found in a threat report ---")
    for kind, values in extract_iocs(SAMPLE_REPORT).items():
        if values:
            print(f"  {kind:<7} {', '.join(values)}")

    print("\n--- 2. IPv4 validation: loose vs strict ---")
    for text in ["192.168.1.1", "999.1.1.1", "1.2.3.4x", "010.0.0.1"]:
        print(f"  {text!r:<14} loose={is_valid_ipv4_loose(text)!s:<6} strict={is_valid_ipv4(text)}")

    print("\n--- 3. Web server log ---")
    entries, bad = parse_access_log(ACCESS_LINES)
    print(f"  parsed {len(entries)} lines, {len(bad)} could not be parsed")
    print(f"  status codes: {dict(Counter(e['status'] for e in entries))}")
    print(f"  requests per IP: {dict(Counter(e['ip'] for e in entries))}")
    print("  suspicious requests:")
    for e in suspicious_requests(entries):
        print(f"    {e['ip']:<14} {e['method']} {e['path']}   [{e['agent']}]")

    print("\n--- 4. SSH brute force ---")
    flagged, breaches = ssh_summary(AUTH_LINES)
    for ip, info in flagged.items():
        print(f"  {ip}: {info['failures']} failed logins, tried users {info['users']}")
    for user, ip in breaches:
        print(f"  ALERT: {ip} then logged in successfully as {user!r}")

    print("\n--- 5. Redaction ---")
    line = "user=alice password=hunter2 api_key=sk_live_51Hx Authorization: Bearer abc.def.ghi"
    print(f"  before: {line}")
    print(f"  after:  {redact(line)}")

    print()
    run_tests()
