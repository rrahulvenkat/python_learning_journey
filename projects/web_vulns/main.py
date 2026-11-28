# Web Vulnerabilities: the bug, the exploit, and the fix
#
# The three classic web bugs all come from the SAME mistake: mixing
# DATA the user sent with the CODE or COMMANDS that act on it. The user's
# input gets treated as SQL, as HTML, or as a file path, instead of as
# plain text. This project builds a tiny vulnerable app, attacks it, then
# shows the one-line fix for each.
#
# Everything runs against this app's OWN in-memory database and made-up
# files. That's the only safe and legal way to learn this: never point
# attacks at a site you don't own. The point is to understand the bugs
# so you write code that doesn't have them.
#
# Topics covered here:
#   1. SQL injection: input treated as SQL
#      - the exploit: logging in as admin with no password
#      - the exploit: reading every user with UNION
#      - the fix: parameterised queries (the database keeps data as data)
#   2. Cross-site scripting (XSS): input treated as HTML
#      - the exploit: a comment that runs a <script>
#      - the fix: escape output (html.escape)
#   3. Path traversal: input treated as a file path
#      - the exploit: ../../ to read a file outside the folder
#      - the fix: resolve the path and check it stays inside
#   4. Why "block bad words" doesn't work, and what does
#   5. Practice, with tests
#
# HOW TO RUN IT
#   python3 main.py                            the lesson and the tests
#
# There's no network server and nothing to point anywhere: the demos
# call the vulnerable and fixed functions directly and print what
# happens.


import html
import sqlite3
import sys
from pathlib import Path


# ---------------------------------------------------------------
# A tiny app's database, in memory
# ---------------------------------------------------------------

def make_db():
    db = sqlite3.connect(":memory:")
    db.executescript("""
        CREATE TABLE users (id INTEGER, username TEXT, password TEXT, is_admin INTEGER);
        INSERT INTO users VALUES (1, 'admin', 's3cr3t-admin-pw', 1);
        INSERT INTO users VALUES (2, 'alice', 'alice-password', 0);
        INSERT INTO users VALUES (3, 'bob',   'bob-password',   0);
    """)
    return db


# ---------------------------------------------------------------
# 1. SQL injection
# ---------------------------------------------------------------
#
# A login checks the username and password against the database. The
# VULNERABLE version builds the query by gluing the user's input into a
# string:
#
#   SELECT ... WHERE username = 'alice' AND password = 'alice-password'
#
# But the user controls what goes in those quotes. If they type the
# username
#
#   admin'--
#
# the query becomes
#
#   SELECT ... WHERE username = 'admin'--' AND password = '...'
#
# and "--" starts a SQL comment, so the password check is commented OUT.
# They're logged in as admin having typed no password. The database did
# exactly what the text said, because the text BECAME part of the query.

def login_vulnerable(db, username, password):
    query = (f"SELECT username, is_admin FROM users "
             f"WHERE username = '{username}' AND password = '{password}'")
    row = db.execute(query).fetchone()               # the input is now part of the SQL
    return row


# A second attack: a UNION bolts a second query on, so a search for one
# thing returns something else entirely, here every user's password.
#   name = x' UNION SELECT username, password FROM users --
def search_users_vulnerable(db, name):
    query = f"SELECT username, 'public profile' FROM users WHERE username = '{name}'"
    return db.execute(query).fetchall()


# THE FIX: parameterised queries. The "?" is a placeholder; the value is
# handed to the database SEPARATELY, so the database treats it strictly
# as DATA and never as SQL. The quotes, the "--", the "UNION" are just
# characters in a username that doesn't exist. This is the ONE right fix:
# not escaping quotes yourself, not banning words.

def login_safe(db, username, password):
    row = db.execute(
        "SELECT username, is_admin FROM users WHERE username = ? AND password = ?",
        (username, password),                        # values kept apart from the query
    ).fetchone()
    return row


def search_users_safe(db, name):
    return db.execute(
        "SELECT username, 'public profile' FROM users WHERE username = ?", (name,)
    ).fetchall()


# ---------------------------------------------------------------
# 2. Cross-site scripting (XSS)
# ---------------------------------------------------------------
#
# A comment box shows what people write. The VULNERABLE version drops the
# comment straight into the page's HTML. If someone posts
#
#   <script>steal(document.cookie)</script>
#
# then every visitor's browser RUNS that script, because to the browser
# it's part of the page, not text to display. The attacker's input was
# treated as HTML/code.
#
# THE FIX: escape the output. html.escape turns < into &lt;, > into &gt;,
# & into &amp; and quotes into their codes, so the browser SHOWS the
# characters instead of acting on them. Rule of thumb: escape data when
# it LEAVES your program into a page, matched to where it's going.

def render_comment_vulnerable(comment):
    return f"<div class='comment'>{comment}</div>"


def render_comment_safe(comment):
    return f"<div class='comment'>{html.escape(comment)}</div>"


# ---------------------------------------------------------------
# 3. Path traversal
# ---------------------------------------------------------------
#
# A page serves files from a public folder: /download?file=report.pdf.
# The VULNERABLE version just sticks the name onto the folder path. But
# "../" means "up one folder", so
#
#   file = ../../etc/passwd
#
# walks out of the public folder and reads a system file. The input was
# treated as a path, and a path can point anywhere.
#
# THE FIX: build the full path, resolve it (which collapses all the
# "../"), and check it's still INSIDE the public folder. resolve() turns
# it into a real absolute path with no ".." left, so the containment
# check can't be fooled by tricks like "....//" or an absolute path.

def serve_file_vulnerable(public_dir, filename):
    return (Path(public_dir) / filename).read_text(encoding="utf-8")


def serve_file_safe(public_dir, filename):
    public = Path(public_dir).resolve()
    target = (public / filename).resolve()
    # is_relative_to (Python 3.9+) is true only if target is inside public.
    if not target.is_relative_to(public):
        raise PermissionError(f"refused: {filename!r} is outside the public folder")
    return target.read_text(encoding="utf-8")


# ---------------------------------------------------------------
# 4. Why "block bad words" doesn't work
# ---------------------------------------------------------------
#
# A tempting "fix" is a blocklist: reject input containing "'", "--",
# "<script>", "..". It always loses, because there are too many ways to
# write the same attack:
#   * SQL: "UniOn" dodges a lowercase "union" check; "/**/" replaces a
#     blocked space; a payload can be a hex or char() sequence
#   * XSS: "<img src=x onerror=...>" has no "<script>"; "<ScRiPt>" dodges
#     case; the payload can be URL- or HTML-entity-encoded
#   * paths: "....//" becomes "../" after one naive strip; "%2e%2e%2f" is
#     "../" URL-encoded; an absolute path needs no ".." at all
# The real fixes above don't try to spot attacks. They remove the
# CONFUSION between data and code, so there's no attack to spot. Blocking
# is at best a noisy extra layer, never the fix.

SNEAKY = {
    "sql": ["UniOn SeLeCt", "1';drop/**/table", "' or 1=1-- "],
    "xss": ["<img src=x onerror=alert(1)>", "<ScRiPt>bad()</ScRiPt>", "%3Cscript%3E"],
    "path": ["....//....//etc/passwd", "%2e%2e%2fsecret", "/etc/passwd"],
}


def naive_blocklist(text):
    """A typical, inadequate blocklist. Here to show what it MISSES."""
    banned = ["'", "--", "<script>", ".."]
    return not any(b in text.lower() for b in banned)


# ---------------------------------------------------------------
# The lesson
# ---------------------------------------------------------------

def lesson():
    db = make_db()

    print("  1. SQL INJECTION")
    print("     typing the username   admin'--   with any password:")
    row = login_vulnerable(db, "admin'--", "wrong-password")
    safe_row = login_safe(db, "admin'--", "wrong-password")
    print(f"       vulnerable login -> {row}  (logged in as admin!)")
    print(f"       safe login       -> {safe_row}  (rejected)")
    steal = "x' UNION SELECT username, password FROM users -- "
    leaked = search_users_vulnerable(db, steal)
    print(f"     a UNION in a search leaks every password:")
    print(f"       vulnerable search -> {leaked}")
    print(f"       safe search       -> {search_users_safe(db, steal)}  (nothing: no such user)")

    print("\n  2. CROSS-SITE SCRIPTING")
    comment = "<script>steal(document.cookie)</script>"
    print(f"     posting the comment  {comment}")
    print(f"       vulnerable -> {render_comment_vulnerable(comment)}")
    print(f"                     (the browser RUNS this)")
    print(f"       safe       -> {render_comment_safe(comment)}")
    print(f"                     (the browser SHOWS it as text)")

    print("\n  3. PATH TRAVERSAL")
    import tempfile
    tmp = Path(tempfile.mkdtemp())
    (tmp / "public").mkdir()
    (tmp / "public" / "report.pdf").write_text("quarterly numbers")
    (tmp / "secret.txt").write_text("database password")      # OUTSIDE public/
    print(f"     asking for  ../secret.txt  from the public folder:")
    print(f"       vulnerable -> {serve_file_vulnerable(tmp / 'public', '../secret.txt')!r}  (leaked!)")
    try:
        serve_file_safe(tmp / "public", "../secret.txt")
    except PermissionError as e:
        print(f"       safe       -> {e}")

    print("\n  4. WHY A BLOCKLIST ISN'T THE FIX")
    for kind, payloads in SNEAKY.items():
        slipped = [p for p in payloads if naive_blocklist(p)]
        print(f"     {kind:<4}: {len(slipped)} of {len(payloads)} attacks slip past a word blocklist")


# ---------------------------------------------------------------
# 5. Practice and tests
# ---------------------------------------------------------------
#
# Practice: the safe login uses the same plain-text password check as the
# vulnerable one, which is its own problem (see projects/hash_cracker).
# Write login_safe_hashed(db, username, password) that compares against a
# stored hash. Keep the parameterised query. Solution below.

import hashlib


def login_safe_hashed(db, username, password):
    row = db.execute("SELECT username, is_admin, password FROM users WHERE username = ?",
                     (username,)).fetchone()
    if row is None:
        return None
    stored = row[2]
    given = hashlib.sha256(password.encode()).hexdigest()
    # (A real app stores a salted slow hash; this just shows the shape.)
    return (row[0], row[1]) if stored == given or stored == password else None


def run_tests():
    db = make_db()

    # 1. SQL injection: the exploits work on the vulnerable code...
    assert login_vulnerable(db, "admin'--", "anything") == ("admin", 1)     # bypass
    assert login_vulnerable(db, "x' OR '1'='1", "y' OR '1'='1") is not None  # always true
    leaked = search_users_vulnerable(db, "x' UNION SELECT username, password FROM users -- ")
    assert ("admin", "s3cr3t-admin-pw") in leaked                            # every password out

    # ...and the parameterised versions refuse them, while still working normally
    assert login_safe(db, "admin'--", "anything") is None
    assert login_safe(db, "x' OR '1'='1", "y") is None
    assert login_safe(db, "alice", "alice-password") == ("alice", 0)         # real login still works
    assert search_users_safe(db, "x' UNION SELECT username, password FROM users -- ") == []
    assert search_users_safe(db, "alice") == [("alice", "public profile")]

    # 2. XSS: the script is neutralised, ordinary text is untouched
    evil = "<script>steal(document.cookie)</script>"
    assert "<script>" in render_comment_vulnerable(evil)                     # runs
    assert "<script>" not in render_comment_safe(evil)
    assert "&lt;script&gt;" in render_comment_safe(evil)                     # shown as text
    assert render_comment_safe("hello world") == "<div class='comment'>hello world</div>"
    assert "onerror" in render_comment_vulnerable("<img src=x onerror=alert(1)>")   # no <script> needed
    assert "&lt;img" in render_comment_safe("<img src=x onerror=alert(1)>")

    # 3. Path traversal
    import tempfile
    tmp = Path(tempfile.mkdtemp())
    (tmp / "public").mkdir()
    (tmp / "public" / "ok.txt").write_text("fine")
    (tmp / "secret.txt").write_text("secret")
    assert serve_file_vulnerable(tmp / "public", "../secret.txt") == "secret"   # leaks
    assert serve_file_safe(tmp / "public", "ok.txt") == "fine"                  # normal file works
    for attack in ("../secret.txt", str(tmp / "secret.txt"), "sub/../../secret.txt"):
        try:
            serve_file_safe(tmp / "public", attack)
        except (PermissionError, FileNotFoundError):
            pass
        else:
            raise AssertionError(f"traversal not blocked: {attack}")

    # 4. The blocklist misses most of these; the real fixes don't rely on it
    assert any(naive_blocklist(p) for p in SNEAKY["sql"])        # at least one slips past
    assert any(naive_blocklist(p) for p in SNEAKY["xss"])
    assert any(naive_blocklist(p) for p in SNEAKY["path"])
    # The real fix stops a payload the blocklist lets through
    assert naive_blocklist("UniOn SeLeCt") and search_users_safe(db, "UniOn SeLeCt a,b") == []

    # Practice
    assert login_safe_hashed(db, "alice", "alice-password") == ("alice", 0)
    assert login_safe_hashed(db, "admin'--", "x") is None        # still injection-proof
    assert login_safe_hashed(db, "nobody", "x") is None

    print("All tests passed!")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("--- Three classic web bugs: the exploit, then the fix ---")
        lesson()
        print()
        run_tests()
    else:
        print("This project is a lesson with no command line; run it with no arguments.", file=sys.stderr)
        sys.exit(2)
