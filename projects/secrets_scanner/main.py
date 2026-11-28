# Secrets Scanner: find passwords and API keys before attackers do
#
# Developers paste credentials into code all the time: an AWS key "just
# to test", a database password in config.py, a token in a notebook.
# Then it's committed, pushed, and public. Attackers run bots that watch
# public pushes and try leaked cloud keys within MINUTES, to mine
# cryptocurrency on your bill or steal data.
#
# A secrets scanner reads files (and git history) and flags anything
# that looks like a credential, so it's caught before the push.
# gitleaks, truffleHog, detect-secrets and GitHub's own secret scanning
# all work the way this one does.
#
# Topics covered here:
#   1. Known key formats: most providers give their keys a recognisable
#      prefix (AKIA..., ghp_..., sk_live_...)
#   2. Suspicious assignments: password = "..." and friends
#   3. Entropy: measuring how random a string looks
#   4. False positives: placeholders, environment variables, binaries,
#      and an inline "ignore" marker
#   5. Reporting without leaking: never print the whole secret
#   6. Git history: a deleted secret is still in the old commits
#   7. Found one? Revoke it FIRST. And using this as a pre-commit check
#   8. Practice, with tests
#
# HOW TO RUN IT
#   python3 main.py                          the lesson, a demo and the tests
#   python3 main.py scan ~/code/myproject    scan the files
#   python3 main.py scan . --history         also scan every commit in git history
#   python3 main.py scan . --entropy         also flag any very random string (noisier)
#
# Exit codes: 0 nothing found, 1 something found, 2 an error. So it can
# block a commit or fail a CI build (section 7).
#
# A NOTE ON THIS FILE: it must not contain anything that LOOKS like a
# real secret, or this scanner, GitHub's push protection and every other
# scanner would flag it. So the fake secrets in the demo and tests are
# assembled from pieces at runtime ("ghp_" + "..."), and a test scans
# this very file and expects zero findings.


import argparse
import hashlib
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


# ---------------------------------------------------------------
# 1. Known key formats
# ---------------------------------------------------------------
#
# Providers put a fixed prefix on their keys on purpose, so scanners
# (theirs and yours) can spot them with few false alarms. A match here
# is high confidence. Each rule: a name, a pattern, and what it unlocks.

KNOWN = [
    ("AWS access key ID", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "an Amazon Web Services account"),
    ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "repositories, and maybe write access"),
    ("Slack token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b", "a Slack workspace"),
    ("Stripe live key", r"\b[sr]k_live_[A-Za-z0-9]{20,}\b", "payments, refunds, customer data"),
    ("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "Google Cloud APIs, billed to the owner"),
    ("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}", "the Claude API, billed to the owner"),
    ("Private key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----",
     "whatever trusts this key: servers, signed releases"),
    ("JSON Web Token", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
     "a logged-in session, until it expires"),
]
KNOWN = [(name, re.compile(pattern), unlocks) for name, pattern, unlocks in KNOWN]


# ---------------------------------------------------------------
# 2. Suspicious assignments
# ---------------------------------------------------------------
#
# A homemade password or an unknown provider's token has no prefix to
# match. But it's usually ASSIGNED to a telling name:
#   password = "<some literal>"      DB_PASSWORD: "<some literal>"
#   api_key = "<some literal>"       "client_secret": "<some literal>"
# So look for a suspicious name, then := or :, then a QUOTED value of 8+
# characters. Quoted, because unquoted values are usually code
# (password = request.form["password"]), not literals.

ASSIGNMENT = re.compile(
    r"""(?ix)
    (?P<name>[\w.\-]*(?:password|passwd|pwd|secret|api[_\-]?key|access[_\-]?key|auth[_\-]?token
                       |token|credential|private[_\-]?key)[\w.\-]*)
    ["']?\s*(?::=|=|:)\s*
    (?P<quote>["'])(?P<value>[^"'\n]{8,})(?P=quote)
    """)


# ---------------------------------------------------------------
# 3. Entropy
# ---------------------------------------------------------------
#
# How do you tell "hunter2hunter2" from "q8Zr2LxV9mTk4wNs"? Shannon
# entropy: the average number of bits each character carries,
#   H = -sum(p * log2(p)) over each distinct character's share p.
# "aaaa" is 0 bits per character; English words are about 2.5-3.5; a
# random base64 string is close to 6. Machine-generated keys are random,
# so high entropy plus a suspicious name means "very likely a real key".
#
# A trap: a string of length n can't score more than log2(n) bits per
# character (16 characters: at most 4.0). So almost ANY short string
# with few repeats scores near its maximum and "looks random". The first
# version of this file called the password "Summer2024-prod!" a random
# key for exactly that reason. Entropy only means something on longer
# strings, so "random-looking" here needs 20+ characters AND 4.0+ bits.
#
# Entropy ALONE is noisy: hashes in lock files, test fixtures, minified
# code and UUIDs are random too. That's why the stand-alone entropy check
# (--entropy) is opt-in, and the default only uses entropy to decide how
# CONFIDENT a suspicious assignment is.

def entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


RANDOM_STRING = re.compile(r"""["']([A-Za-z0-9+/=_\-]{32,})["']""")


# ---------------------------------------------------------------
# 4. False positives
# ---------------------------------------------------------------
#
# A scanner that cries wolf gets switched off. The usual culprits:
#   * PLACEHOLDERS in docs and examples: "changeme", "<your-key>", "xxxx"
#   * values read from somewhere ELSE: os.environ[...], ${DB_PASSWORD},
#     {{ secrets.TOKEN }}: that's the RIGHT way, not a leak
#   * BINARY files (images, archives): random bytes match everything
#   * generated folders: .git, node_modules, virtual environments
# Two more found by scanning this repository itself:
#   * f-string and template FIELDS: password = '{password}' is a
#     variable dropped into a string, not a literal
#   * DOCUMENTED EXAMPLE KEYS: AWS's documentation uses one example
#     access key ending in "EXAMPLE", and it appears in countless
#     tutorials. Known-format matches containing EXAMPLE are skipped.
# And for a reviewed false alarm, a marker at the end of the line:
#   test_password = "not-a-real-one"   # secrets-scanner: ignore

PLACEHOLDER = re.compile(
    r"(?i)^(?:x+|\*+|\.+|-+|changeme|change_me|example|sample|dummy|placeholder|redacted|password|"
    r"secret|your[_\- ].*|<.*>|\$\{.*\}|\{\{.*\}\}|\{[\w.\[\]'\"]+\}|%\(.*\)s|.*example.*|"
    r"test(ing)?|todo|none|null)$")
FROM_ELSEWHERE = re.compile(r"(?i)os\.environ|getenv|\$\{|\{\{|process\.env|secrets\.")
IGNORE_MARK = "secrets-scanner: ignore"
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache", "dist", "build"}
MAX_BYTES = 1_000_000


def is_placeholder(value):
    return bool(PLACEHOLDER.match(value.strip())) or len(set(value)) <= 2


def looks_binary(data):
    return b"\0" in data[:8192]


# ---------------------------------------------------------------
# 5. Reporting without leaking
# ---------------------------------------------------------------
#
# The report itself goes into terminals, CI logs and tickets, so it must
# not spread the secret further. Show only enough to find it: the first
# 4 characters and the length. A FINGERPRINT (a hash of the finding)
# lets people refer to one finding, or accept it as reviewed, without
# ever writing the secret down (the practice exercise uses this).

def redact(secret):
    return f"{secret[:4]}... ({len(secret)} chars)"


def fingerprint(rule, secret):
    return hashlib.sha256(f"{rule}:{secret}".encode()).hexdigest()[:12]


@dataclass
class Finding:
    rule: str
    where: str            # file:line, or commit:file for history
    secret: str           # kept in memory only; never printed
    confidence: str
    note: str

    @property
    def fingerprint(self):
        return fingerprint(self.rule, self.secret)

    def __str__(self):
        return (f"[{self.confidence:<6}] {self.where}  {self.rule}: {redact(self.secret)}"
                f"  ({self.note})  id={self.fingerprint}")


def scan_line(line, where, use_entropy=False):
    """All findings on one line of text."""
    if IGNORE_MARK in line:
        return []
    found, taken = [], []
    for name, pattern, unlocks in KNOWN:
        for m in pattern.finditer(line):
            if "EXAMPLE" in m.group(0).upper():
                taken.append(m.span())                # a documented example: not a finding
                continue
            found.append(Finding(name, where, m.group(0), "HIGH", f"unlocks {unlocks}"))
            taken.append(m.span())

    def overlaps(span):
        return any(a < span[1] and span[0] < b for a, b in taken)

    for m in ASSIGNMENT.finditer(line):
        value = m["value"]
        if overlaps(m.span("value")) or is_placeholder(value) or FROM_ELSEWHERE.search(value):
            continue
        bits = entropy(value)
        if len(value) >= 20 and bits >= 4.0:                    # see the trap in section 3
            found.append(Finding("Hardcoded key", where, value, "HIGH",
                                 f"{m['name']!r} is set to a random-looking value ({bits:.1f} bits/char)"))
        else:
            found.append(Finding("Hardcoded password", where, value, "MEDIUM",
                                 f"{m['name']!r} is set to a literal"))
        taken.append(m.span("value"))

    if use_entropy:
        for m in RANDOM_STRING.finditer(line):
            value = m.group(1)
            if not overlaps(m.span(1)) and entropy(value) >= 4.5:
                found.append(Finding("High-entropy string", where, value, "LOW",
                                     f"{entropy(value):.1f} bits/char: a key, or just a hash?"))
    return found


def scan_file(path, root, use_entropy=False):
    try:
        if path.stat().st_size > MAX_BYTES:
            return []
        data = path.read_bytes()
    except OSError:
        return []
    if looks_binary(data):
        return []
    text = data.decode("utf-8", errors="replace")
    relative = path.relative_to(root).as_posix()
    found = []
    for number, line in enumerate(text.splitlines(), start=1):
        found += scan_line(line, f"{relative}:{number}", use_entropy)
    return found


def scan_tree(root, use_entropy=False):
    root = Path(root)
    if root.is_file():
        return scan_file(root, root.parent, use_entropy)
    found = []
    for folder, subfolders, files in os.walk(root):
        subfolders[:] = sorted(d for d in subfolders if d not in SKIP_DIRS)
        for name in sorted(files):
            path = Path(folder) / name
            if not path.is_symlink():
                found += scan_file(path, root, use_entropy)
    return found


# ---------------------------------------------------------------
# 6. Git history
# ---------------------------------------------------------------
#
# Deleting a secret in a new commit doesn't remove it: every earlier
# commit still holds it, and anyone who clones the repository gets them
# all. `git log -p` prints every commit's changes; scanning the ADDED
# lines (starting with "+") finds every secret ever committed, even ones
# no longer in any file. This is why a leaked key must be REVOKED, not
# just deleted (section 7).

def scan_git_history(repo, use_entropy=False):
    if shutil.which("git") is None:
        raise RuntimeError("git isn't installed")
    result = subprocess.run(
        ["git", "-C", str(repo), "log", "-p", "--all", "--no-color", "--format=commit %H"],
        capture_output=True, text=True, errors="replace")
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "not a git repository")
    found, seen = [], set()
    commit = path = None
    for line in result.stdout.splitlines():
        if line.startswith("commit "):
            commit = line.split()[1][:8]
        elif line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else None
        elif line.startswith("+") and path:
            for f in scan_line(line[1:], f"{commit}:{path}", use_entropy):
                key = (f.rule, f.secret, path)
                if key not in seen:                   # the same secret in many commits: report once
                    seen.add(key)
                    found.append(f)
    return found


# ---------------------------------------------------------------
# 7. Found one? Revoke it first
# ---------------------------------------------------------------
#
# The order matters:
#   1. REVOKE or ROTATE the key at the provider (AWS console, GitHub
#      settings...). Assume it's already been copied: bots are fast.
#   2. Check the provider's logs for use you didn't make.
#   3. Only then remove it from the code (and, if needed, from history
#      with git filter-repo). Removing it without revoking does nothing:
#      every clone and fork still has it.
#   4. Move it to an environment variable or a secrets manager.
#
# To stop it happening again, run the scanner BEFORE each commit. Git
# runs .git/hooks/pre-commit if it exists, and cancels the commit if it
# exits non-zero:
#
#   #!/bin/sh
#   python3 /path/to/main.py scan . || {
#       echo "Possible secret found: commit cancelled."; exit 1; }
#
# (The pre-commit framework, https://pre-commit.com, manages hooks like
# this for a whole team, and CI can run the same scan on every push.)


# ---------------------------------------------------------------
# The command line
# ---------------------------------------------------------------

def main(argv=None, out=sys.stdout):
    p = argparse.ArgumentParser(prog="main.py", description="Find hardcoded secrets in files and git history.")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan")
    s.add_argument("path", type=Path)
    s.add_argument("--history", action="store_true", help="also scan every commit (needs git)")
    s.add_argument("--entropy", action="store_true", help="also flag any very random string (noisier)")
    args = p.parse_args(argv)
    if not args.path.exists():
        print(f"error: {args.path} doesn't exist", file=sys.stderr)
        return 2
    found = scan_tree(args.path, args.entropy)
    if args.history:
        try:
            found += scan_git_history(args.path, args.entropy)
        except RuntimeError as err:
            print(f"error: {err}", file=sys.stderr)
            return 2
    for f in found:
        print(f, file=out)
    print(f"{len(found)} possible secret(s) found" if found else "no secrets found", file=out)
    return 1 if found else 0


# ---------------------------------------------------------------
# Fake secrets for the demo and tests, assembled at runtime so this
# file never contains one (see the note at the top). None are real.
# ---------------------------------------------------------------

FAKE = {
    "aws": "AKIA" + "Q3VZ" + "T7XK" + "M2PL" + "R8WN",
    "github": "ghp" + "_" + "x1Y2z3W4v5U6t7S8r9Q0p1O2n3M4l5K6j7I8",
    "stripe": "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "pem": "-----BEGIN " + "RSA PRIVATE KEY-----",
    "random": "q8Zr2LxV" + "9mTk4wNs" + "Hy6PbJ3c",
}


def build_demo_project(root):
    root = Path(root)
    (root / "app").mkdir(parents=True)
    (root / "app" / "config.py").write_text(
        "import os\n"
        f"AWS_ACCESS_KEY_ID = \"{FAKE['aws']}\"\n"
        "DB_PASSWORD = \"Summer2024-prod!\"\n"
        "DB_HOST = \"db.internal\"\n"
        "SMTP_PASSWORD = os.environ[\"SMTP_PASSWORD\"]\n")
    (root / "app" / "billing.py").write_text(f"stripe_key = '{FAKE['stripe']}'\n")
    (root / ".env.example").write_text("API_KEY=\"<your-api-key>\"\nPASSWORD=\"changeme\"\n")
    (root / "deploy_key").write_text(FAKE["pem"] + "\nMIIEow...\n")
    (root / "tests.py").write_text(f"service_token = \"{FAKE['random']}\"\n")
    (root / "fixtures.py").write_text("admin_password = \"not-a-real-one\"  # " + IGNORE_MARK + "\n")
    (root / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\0\0" + FAKE["aws"].encode())
    return root


def lesson():
    with tempfile.TemporaryDirectory() as tmp:
        project = build_demo_project(Path(tmp) / "project")
        print("  A small project with some mistakes in it. The scanner finds:\n")
        for f in scan_tree(project):
            print(f"    {f}")
        print("\n  ...and correctly stays quiet about: the placeholders in .env.example,")
        print("  SMTP_PASSWORD (read from the environment: the right way), the reviewed")
        print("  line in fixtures.py, and the key-shaped bytes inside logo.png (binary).")

        if shutil.which("git"):
            repo = Path(tmp) / "repo"
            repo.mkdir()
            git = ["git", "-C", str(repo), "-c", "user.name=demo", "-c", "user.email=demo@example.invalid"]
            subprocess.run(git[:3] + ["init", "-q"], check=True)
            (repo / "deploy.sh").write_text(f"export GITHUB_TOKEN={FAKE['github']}\n")
            subprocess.run(git + ["add", "."], check=True)
            subprocess.run(git + ["commit", "-qm", "add deploy script"], check=True)
            (repo / "deploy.sh").write_text("export GITHUB_TOKEN=\"${GITHUB_TOKEN}\"\n")
            subprocess.run(git + ["commit", "-qam", "remove the token"], check=True)
            print("\n  A token committed, then 'removed' in the next commit.")
            print(f"    scanning the files now:   {len(scan_tree(repo))} findings")
            history = scan_git_history(repo)
            print(f"    scanning the history:     {len(history)} finding: it's still there")
            for f in history:
                print(f"      {f}")
            print("    So: revoke the token first. Deleting it protects nothing.")


# ---------------------------------------------------------------
# 8. Practice and tests
# ---------------------------------------------------------------
#
# Practice: real projects have reviewed false alarms that can't take an
# inline comment (a JSON file, a vendored library). Write
# without_accepted(findings, accepted) that drops findings whose
# fingerprint is in `accepted`, a set read from a file like
# .secrets-accepted. Fingerprints (section 5) mean that file never holds
# the secrets themselves. Solution below.

def without_accepted(findings, accepted):
    return [f for f in findings if f.fingerprint not in accepted]


def assign(name, value):
    """'name = "value"', built at runtime (see the note at the top)."""
    return name + ' = "' + value + '"'


def run_tests():
    # 1. Known formats, with the exact rule and full match
    for key, rule in (("aws", "AWS access key ID"), ("github", "GitHub token"),
                      ("stripe", "Stripe live key"), ("pem", "Private key")):
        found = scan_line(f"value = {FAKE[key]}", "x:1")
        assert [f.rule for f in found] == [rule] and found[0].confidence == "HIGH", (key, found)
    assert scan_line("AKIA" + "SHORT", "x:1") == []                        # wrong length: no match

    # 2-3. Assignments, rated by entropy
    pw = scan_line(assign("DB_PASSWORD", "Summer2024-prod!"), "x:1")
    assert [(f.rule, f.confidence) for f in pw] == [("Hardcoded password", "MEDIUM")]
    key = scan_line(f'"client_secret": "{FAKE["random"]}"', "x:1")
    assert [(f.rule, f.confidence) for f in key] == [("Hardcoded key", "HIGH")]
    assert entropy("aaaa") == 0.0 and entropy("abcd") == 2.0
    assert entropy(FAKE["random"]) > 4 > entropy("passwordpassword")
    assert entropy("Summer2024-prod!") <= math.log2(16)                    # the short-string ceiling
    long_phrase = scan_line(assign("password", "correct horse battery staple"), "x:1")
    assert [f.rule for f in long_phrase] == ["Hardcoded password"]        # long, but not random

    # 4. False positives stay quiet
    for quiet in ('password = "changeme"', 'API_KEY="<your-api-key>"', 'token = "xxxxxxxxxxxx"',
                  'password = os.environ["DB_PASSWORD"]', 'secret: "${DB_SECRET}"',
                  'token = "{{ secrets.DEPLOY_TOKEN }}"', 'password = request.form["password"]',
                  'aws_key = "AKIAEXAMPLEEXAMPLE"',                        # placeholder word
                  "key=AKIA" + "IOSFODNN7" + "EXAMPLE",                    # AWS's documented example key
                  "WHERE password = '{password}'",                         # an f-string field
                  assign("admin_password", "hunter2hunter2") + "  # " + IGNORE_MARK,
                  'description = "a perfectly ordinary sentence"'):
        assert scan_line(quiet, "x:1") == [], quiet

    # The demo project: exactly the real problems, and nothing else
    with tempfile.TemporaryDirectory() as tmp:
        project = build_demo_project(Path(tmp) / "p")
        (project / "node_modules").mkdir()
        (project / "node_modules" / "lib.js").write_text(f"var k = '{FAKE['aws']}'")   # skipped folder
        found = scan_tree(project)
        got = sorted((f.where.split(":")[0], f.rule) for f in found)
        assert got == [("app/billing.py", "Stripe live key"),
                       ("app/config.py", "AWS access key ID"),
                       ("app/config.py", "Hardcoded password"),
                       ("deploy_key", "Private key"),
                       ("tests.py", "Hardcoded key")], got

        # 5. The report never contains a whole secret
        for f in found:
            assert f.secret not in str(f) and f.secret[:4] in str(f)

        # The command line: exit codes, and the output doesn't leak either
        import io
        out = io.StringIO()
        assert main(["scan", str(project)], out=out) == 1
        assert FAKE["aws"] not in out.getvalue() and "5 possible secret(s)" in out.getvalue()
        clean = Path(tmp) / "clean"
        clean.mkdir()
        (clean / "ok.py").write_text("print('hello')\n")
        assert main(["scan", str(clean)], out=io.StringIO()) == 0
        assert main(["scan", str(Path(tmp) / "missing")], out=io.StringIO()) == 2

        # --entropy finds random strings that have no telling name (and is noisier)
        (clean / "data.py").write_text(f'BLOB = "{FAKE["random"]}{FAKE["random"]}"\n')
        assert scan_tree(clean) == [] and [f.rule for f in scan_tree(clean, True)] == ["High-entropy string"]

        # 6. Git history: a removed secret is still found
        if shutil.which("git"):
            repo = Path(tmp) / "repo"
            repo.mkdir()
            git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
            subprocess.run(git[:3] + ["init", "-q"], check=True)
            (repo / "a.sh").write_text(f"TOKEN={FAKE['github']}\n")
            subprocess.run(git + ["add", "."], check=True)
            subprocess.run(git + ["commit", "-qm", "1"], check=True)
            (repo / "a.sh").write_text("TOKEN=$TOKEN\n")
            subprocess.run(git + ["commit", "-qam", "2"], check=True)
            assert scan_tree(repo) == []
            history = scan_git_history(repo)
            assert [f.rule for f in history] == ["GitHub token"] and history[0].where.endswith(":a.sh")
            assert main(["scan", str(repo), "--history"], out=io.StringIO()) == 1

    # Dogfooding: this file must not trip its own scanner (see the note at the top)
    assert scan_tree(Path(__file__).resolve()) == [], scan_tree(Path(__file__).resolve())

    # Practice
    findings = scan_line(f"x = {FAKE['aws']}; y = {FAKE['stripe']}", "x:1")
    accepted = {findings[0].fingerprint}
    assert [f.rule for f in without_accepted(findings, accepted)] == ["Stripe live key"]

    print("All tests passed!")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("--- Hardcoded secrets: found in files, and in git history ---")
        lesson()
        print()
        run_tests()
    else:
        sys.exit(main())
