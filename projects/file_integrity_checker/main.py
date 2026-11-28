# File Integrity Checker: notice when files change behind your back
#
# An attacker who gets onto a server almost always CHANGES FILES: drops
# a web shell into the website's folder, adds their key to
# ~/.ssh/authorized_keys, edits a cron job or sshd_config, replaces a
# program with a trojaned copy. Ransomware changes every file at once.
#
# File integrity monitoring (FIM) catches this: take a fingerprint of
# every file while the system is known to be clean (a BASELINE), then
# later compare and report what was added, deleted or modified. Tripwire,
# AIDE, OSSEC and Wazuh do this, and standards like PCI DSS require it.
# This project builds a small one.
#
# Topics covered here:
#   1. Fingerprints: hashing a file with hashlib, in chunks
#   2. Why not just the modified time? (timestomping)
#   3. Walking a folder safely: symlinks, unreadable files, ignore rules
#   4. The baseline: JSON, written atomically
#   5. Comparing: added, deleted, modified, moved, and permission changes
#   6. Protecting the baseline itself: an HMAC signature
#   7. The tool: init and check, with exit codes for cron and scripts
#   8. A demo: a website, then an attacker
#   9. Practice, with tests
#
# HOW TO RUN IT
# -------------
#   python3 main.py                                   the lesson, the demo and the tests
#   python3 main.py init ~/site --baseline site.json  fingerprint a folder (while it's clean)
#   python3 main.py check ~/site --baseline site.json compare it now
#   FIM_KEY=... python3 main.py init ...              sign the baseline (section 6)
#   python3 main.py check ~/site --baseline site.json --ignore '*.log' --ignore 'cache/*'
#
# Exit codes: 0 nothing changed, 1 something changed, 2 an error
# (including a baseline whose signature doesn't match).


import argparse
import fnmatch
import hashlib
import hmac
import json
import os
import stat
import sys
import tempfile
from pathlib import Path


# ---------------------------------------------------------------
# 1. Fingerprints
# ---------------------------------------------------------------
#
# A cryptographic HASH turns any amount of data into a short, fixed-size
# fingerprint. Change one bit of the file and the hash changes
# completely, and no one can make a DIFFERENT file with the same SHA-256
# hash. So if the hash is the same, the content is the same.
#
# Two details matter:
#   * Read in CHUNKS. f.read() on a 4 GB file needs 4 GB of memory;
#     reading 1 MB at a time and feeding each piece to the hash doesn't
#     (the same idea as fundamentals/large_files.py).
#   * Use SHA-256, not MD5 or SHA-1. Both are broken: people CAN make two
#     different files with the same MD5, which is exactly what an
#     attacker hiding a modified file would want.

CHUNK = 1024 * 1024


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------
# 2. Why not just the modified time?
# ---------------------------------------------------------------
#
# Every file has a "modified" time, and checking it would be much faster
# than hashing. But attackers know that: `touch -r /bin/ls /bin/ls.evil`
# copies one file's timestamps onto another, so a replaced file looks
# untouched. That's TIMESTOMPING (MITRE ATT&CK T1070.006). The size can
# stay the same too, if the attacker pads the file. Only the content
# hash can't be faked, so it's what decides "modified". Size and
# permissions are recorded as well, because they're cheap and say WHAT
# kind of change it was.


# ---------------------------------------------------------------
# 3. Walking a folder safely
# ---------------------------------------------------------------
#
# os.walk() visits every folder below a starting point. Three traps:
#
#   * SYMLINKS. A symbolic link points somewhere else. Following it could
#     leave the folder being checked (a link to /), or loop forever (a
#     link to its own parent). So links are recorded AS links, with
#     where they point, and never followed. An attacker repointing a
#     link (say, config.php -> /tmp/evil.php) still shows up, because
#     the target changed.
#   * UNREADABLE FILES. A file you can't read shouldn't stop the whole
#     check. It's recorded as an error, and reported.
#   * EXPECTED CHANGES. Logs and caches change all the time; reporting
#     them every run teaches people to ignore the report. Ignore rules
#     use shell-style patterns ("*.log", "cache/*") with fnmatch.

def is_ignored(relative, patterns):
    return any(fnmatch.fnmatch(relative, p) or fnmatch.fnmatch(Path(relative).name, p)
               for p in patterns)


def fingerprint(path):
    """What we record about one file, link or unreadable thing."""
    info = os.lstat(path)                             # lstat: about the link itself, not its target
    mode = oct(stat.S_IMODE(info.st_mode))
    if stat.S_ISLNK(info.st_mode):
        return {"type": "link", "target": os.readlink(path), "mode": mode}
    if not stat.S_ISREG(info.st_mode):
        return {"type": "other", "mode": mode}        # sockets, devices, pipes: never read them
    try:
        digest = sha256_of(path)
    except OSError as err:
        return {"type": "file", "error": err.strerror or str(err), "size": info.st_size, "mode": mode}
    return {"type": "file", "sha256": digest, "size": info.st_size, "mode": mode}


def scan(root, ignore=()):
    """Fingerprint everything under root. Keys are paths relative to root, with "/"."""
    root = Path(root)
    found = {}
    for folder, subfolders, files in os.walk(root, followlinks=False):
        here = Path(folder)
        # Prune ignored folders now, so we don't even walk into them.
        subfolders[:] = sorted(d for d in subfolders
                               if not is_ignored((here / d).relative_to(root).as_posix() + "/", ignore)
                               and not is_ignored((here / d).relative_to(root).as_posix(), ignore))
        # os.walk lists links to folders as folders; record those as links too.
        for name in sorted(files) + [d for d in subfolders if (here / d).is_symlink()]:
            relative = (here / name).relative_to(root).as_posix()
            if not is_ignored(relative, ignore):
                found[relative] = fingerprint(here / name)
        subfolders[:] = [d for d in subfolders if not (here / d).is_symlink()]
    return found


# ---------------------------------------------------------------
# 4. The baseline
# ---------------------------------------------------------------
#
# The baseline is plain JSON, so a person can read it. It's written
# ATOMICALLY: to a temporary file first, then renamed over the old one
# with os.replace(). A rename is all-or-nothing, so a crash halfway
# through can never leave a half-written baseline (which would make the
# next check report everything as changed, or fail).
#
# Keep the baseline OFF the machine being watched if you can (or on
# read-only media): an attacker who can edit it can hide their changes.
# Section 6 makes edits detectable, at least.

def write_atomically(path, text):
    path = Path(path)
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(temp, path)
    except BaseException:
        os.unlink(temp)
        raise


# ---------------------------------------------------------------
# 5. Comparing
# ---------------------------------------------------------------
#
# With both scans as dictionaries, set operations do most of the work:
#   added    = now.keys() - before.keys()
#   deleted  = before.keys() - now.keys()
#   in both  = before.keys() & now.keys()   -> compare their fingerprints
#
# A file that was MOVED shows up as one deletion and one addition with
# the same hash; pairing those up makes the report clearer.
#
# Permission changes get their own warnings, because some are classic
# attacker moves:
#   setuid/setgid   the program runs as its OWNER (often root) for
#                   whoever starts it: a backdoor to root
#   world-writable  anyone on the machine can now change the file

SETID = stat.S_ISUID | stat.S_ISGID


def permission_warnings(old_mode, new_mode):
    old, new = int(old_mode, 8), int(new_mode, 8)
    warnings = []
    if new & SETID and not old & SETID:
        warnings.append("became setuid/setgid (runs with its owner's rights)")
    if new & stat.S_IWOTH and not old & stat.S_IWOTH:
        warnings.append("became writable by everyone")
    return warnings


def compare(before, now):
    report = {"added": [], "deleted": [], "modified": [], "moved": [], "permissions": [], "unreadable": []}
    added = sorted(now.keys() - before.keys())
    deleted = sorted(before.keys() - now.keys())

    # Pair deletions and additions with the same content: moves.
    by_hash = {}
    for path in deleted:
        digest = before[path].get("sha256")
        if digest:
            by_hash.setdefault(digest, []).append(path)
    for path in list(added):
        digest = now[path].get("sha256")
        if digest and by_hash.get(digest):
            old = by_hash[digest].pop(0)
            report["moved"].append((old, path))
            added.remove(path)
            deleted.remove(old)
    report["added"], report["deleted"] = added, deleted

    for path in sorted(before.keys() & now.keys()):
        a, b = before[path], now[path]
        if b.get("error"):
            report["unreadable"].append((path, b["error"]))
            continue
        what = []
        if a.get("type") != b.get("type"):
            what.append(f"was a {a.get('type')}, now a {b.get('type')}")
        elif a.get("type") == "link" and a.get("target") != b.get("target"):
            what.append(f"link now points to {b['target']!r} (was {a['target']!r})")
        elif a.get("sha256") != b.get("sha256"):
            same_size = " (same size: padded or carefully replaced)" if a.get("size") == b.get("size") else ""
            what.append(f"content changed{same_size}")
        if what:
            report["modified"].append((path, "; ".join(what)))
        if a.get("mode") != b.get("mode"):
            warnings = permission_warnings(a["mode"], b["mode"])
            report["permissions"].append((path, f"{a['mode']} -> {b['mode']}", warnings))
    for path in report["added"]:
        if now[path].get("error"):
            report["unreadable"].append((path, now[path]["error"]))
    return report


def changed(report):
    return any(report[k] for k in ("added", "deleted", "modified", "moved", "permissions"))


# ---------------------------------------------------------------
# 6. Protecting the baseline itself
# ---------------------------------------------------------------
#
# If an attacker can edit the baseline, they replace their web shell's
# hash in it and the check says "nothing changed". A plain hash of the
# baseline doesn't help: they'd just recompute that too.
#
# An HMAC does help. It's a hash mixed with a SECRET KEY: without the
# key, nobody can produce the right value for edited content. Keep the
# key somewhere the attacker can't read (another machine, a secrets
# manager, an environment variable set only when the check runs).
#
# Two details:
#   * The JSON is signed in a CANONICAL form (sorted keys, no extra
#     spaces), so the same content always gives the same bytes.
#   * Signatures are compared with hmac.compare_digest(), which takes
#     the same time however many characters match. A normal == stops at
#     the first difference, and that timing difference can leak the
#     right answer one character at a time (oop/encapsulation.py).

def canonical(files):
    return json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(files, key):
    return hmac.new(key, canonical(files), hashlib.sha256).hexdigest()


class BaselineError(Exception):
    pass


def save_baseline(path, root, files, key=None):
    data = {"root": str(Path(root).resolve()), "files": files}
    if key:
        data["hmac_sha256"] = sign(files, key)
    write_atomically(path, json.dumps(data, indent=1, sort_keys=True) + "\n")


def load_baseline(path, key=None):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        files = data["files"]
    except (OSError, ValueError, KeyError, TypeError) as err:
        raise BaselineError(f"can't read baseline {path}: {err}") from None
    signature = data.get("hmac_sha256")
    if key and not signature:
        raise BaselineError("the baseline isn't signed, but a key was given: it may have been replaced")
    if signature and not key:
        raise BaselineError("the baseline is signed: set FIM_KEY (or --key-file) to check it")
    if key and not hmac.compare_digest(signature, sign(files, key)):
        raise BaselineError("the baseline's signature doesn't match: it was edited, or the key is wrong")
    return files


# ---------------------------------------------------------------
# 7. The tool
# ---------------------------------------------------------------

def format_report(report):
    lines = []
    for path in report["added"]:
        lines.append(f"ADDED     {path}")
    for path in report["deleted"]:
        lines.append(f"DELETED   {path}")
    for old, new in report["moved"]:
        lines.append(f"MOVED     {old} -> {new}")
    for path, what in report["modified"]:
        lines.append(f"MODIFIED  {path}: {what}")
    for path, change, warnings in report["permissions"]:
        extra = f"  ** {'; '.join(warnings)}" if warnings else ""
        lines.append(f"MODE      {path}: {change}{extra}")
    for path, error in report["unreadable"]:
        lines.append(f"UNREADABLE {path}: {error}")
    return "\n".join(lines) if lines else "no changes"


def read_key(key_file):
    if key_file:
        return Path(key_file).read_bytes().strip()
    value = os.environ.get("FIM_KEY")
    return value.encode("utf-8") if value else None


def main(argv=None, out=sys.stdout, err=sys.stderr):
    p = argparse.ArgumentParser(prog="main.py", description="Detect added, deleted and modified files.")
    p.add_argument("command", choices=["init", "check"], help="init: save a baseline; check: compare with it")
    p.add_argument("folder", type=Path)
    p.add_argument("--baseline", type=Path, required=True, help="the baseline JSON file")
    p.add_argument("--ignore", action="append", default=[], metavar="PATTERN",
                   help="skip paths matching this (e.g. '*.log', 'cache/*'); repeatable")
    p.add_argument("--key-file", help="sign/verify the baseline with this key (default: $FIM_KEY)")
    args = p.parse_args(argv)
    if not args.folder.is_dir():
        print(f"error: {args.folder} is not a folder", file=err)
        return 2
    try:
        key = read_key(args.key_file)
        if args.command == "init":
            files = scan(args.folder, args.ignore)
            save_baseline(args.baseline, args.folder, files, key)
            signed = "signed" if key else "UNSIGNED (set FIM_KEY to sign it)"
            print(f"baseline of {len(files)} entries saved to {args.baseline}, {signed}", file=out)
            return 0
        before = load_baseline(args.baseline, key)
    except (BaselineError, OSError) as e:
        print(f"error: {e}", file=err)
        return 2
    report = compare(before, scan(args.folder, args.ignore))
    print(format_report(report), file=out)
    return 1 if changed(report) else 0


# ---------------------------------------------------------------
# 8. A demo: a website, then an attacker
# ---------------------------------------------------------------

def build_site(root):
    root = Path(root)
    (root / "uploads").mkdir(parents=True)
    (root / "logs").mkdir()
    (root / "index.php").write_text("<?php echo 'Welcome to the shop'; ?>\n")
    (root / "config.php").write_text("<?php $db_host = 'localhost'; $db_user = 'shop'; ?>\n")
    (root / "about.html").write_text("<h1>About us</h1>\n")
    (root / "uploads" / "cat.jpg").write_bytes(b"\xff\xd8\xff fake jpeg bytes")
    (root / "logs" / "access.log").write_text("192.0.2.1 GET /\n")
    (root / "run.sh").write_text("#!/bin/sh\necho backup\n")
    (root / "run.sh").chmod(0o755)
    os.symlink("config.php", root / "settings.php")
    return root


def attack(root):
    root = Path(root)
    # A web shell, dropped where uploads go
    (root / "uploads" / "cache.php").write_text("<?php system($_GET['c']); ?>\n")
    # The config edited to send the database somewhere else, timestomped
    # so its modified time and size look untouched
    config = root / "config.php"
    old = config.stat()
    text = config.read_text().replace("localhost", "evil.test")
    config.write_text(text[: old.st_size].ljust(old.st_size))
    os.utime(config, (old.st_atime, old.st_mtime))
    # A script made world-writable and setuid
    (root / "run.sh").chmod(0o4777)
    # A link repointed, a page moved, and the logs grow (expected noise)
    (root / "settings.php").unlink()
    os.symlink("/tmp/evil.php", root / "settings.php")
    (root / "about.html").rename(root / "about-us.html")
    with open(root / "logs" / "access.log", "a") as f:
        f.write("198.51.100.7 GET /uploads/cache.php?c=id\n")


def demo():
    with tempfile.TemporaryDirectory() as tmp:
        site = build_site(Path(tmp) / "site")
        baseline = Path(tmp) / "site.json"
        key = b"demo-key-keep-this-somewhere-else"
        save_baseline(baseline, site, scan(site, ["logs/*"]), key)
        print("  baseline saved (signed), then the attacker gets in...\n")
        attack(site)
        report = compare(load_baseline(baseline, key), scan(site, ["logs/*"]))
        print("  " + format_report(report).replace("\n", "\n  "))

        print("\n  ...and if the attacker edits the baseline to hide the web shell:")
        data = json.loads(baseline.read_text())
        data["files"]["uploads/cache.php"] = scan(site)["uploads/cache.php"]
        baseline.write_text(json.dumps(data))
        try:
            load_baseline(baseline, key)
        except BaselineError as e:
            print(f"  error: {e}")


# ---------------------------------------------------------------
# 9. Practice and tests
# ---------------------------------------------------------------
#
# Practice: attackers often add a key to ~/.ssh/authorized_keys. Write
# watch_list_alerts(report, watch) that returns the changes (added,
# modified, permission) to paths matching any pattern in `watch`, such
# as ["*authorized_keys", "*sshd_config", "*.php"], so they can be
# shown first. Solution: watch_list_alerts() below.

def watch_list_alerts(report, watch):
    paths = report["added"] + [p for p, _ in report["modified"]] + [p for p, _, _ in report["permissions"]]
    return sorted({p for p in paths if any(fnmatch.fnmatch(p, w) for w in watch)})


def run_tests():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        # 1. Hashing in chunks gives the same answer as hashing all at once
        big = tmp / "big.bin"
        big.write_bytes(os.urandom(3 * CHUNK + 17))
        assert sha256_of(big) == hashlib.sha256(big.read_bytes()).hexdigest()

        # 5. The demo attack: every change is caught, the logs are ignored
        site = build_site(tmp / "site")
        before = scan(site, ["logs/*"])
        assert "logs/access.log" not in before and before["settings.php"]["type"] == "link"
        attack(site)
        report = compare(before, scan(site, ["logs/*"]))
        assert report["added"] == ["uploads/cache.php"]
        assert report["moved"] == [("about.html", "about-us.html")] and report["deleted"] == []
        modified = dict(report["modified"])
        assert "same size" in modified["config.php"]                    # timestomped AND padded: hash still catches it
        assert "/tmp/evil.php" in modified["settings.php"]
        perms = {p: w for p, _, w in report["permissions"]}
        assert any("setuid" in w for w in perms["run.sh"]) and any("everyone" in w for w in perms["run.sh"])
        assert changed(report)
        assert not changed(compare(before, before))
        assert format_report(compare(before, before)) == "no changes"

        # 3. Symlinks aren't followed out of the folder, and loops don't hang
        loop = tmp / "loop"
        loop.mkdir()
        (loop / "a.txt").write_text("a")
        os.symlink("..", loop / "up")                                 # points at its own parent
        os.symlink("/", loop / "root")
        found = scan(loop)
        assert set(found) == {"a.txt", "up", "root"} and found["root"] == {"type": "link", "target": "/",
                                                                           "mode": found["root"]["mode"]}

        # Unreadable files are reported, not fatal (skipped when running as root)
        secret = loop / "secret.txt"
        secret.write_text("x")
        secret.chmod(0)
        if hasattr(os, "geteuid") and os.geteuid() != 0:          # root can read anything
            assert "error" in scan(loop)["secret.txt"]
        secret.chmod(0o600)

        # Ignore rules: patterns, folders pruned
        assert is_ignored("logs/access.log", ["logs/*"]) and is_ignored("x/debug.log", ["*.log"])
        assert not is_ignored("index.php", ["*.log"])

        # 4 and 6. Baselines: atomic, signed, and edits are detected
        key = b"k" * 32
        path = tmp / "b.json"
        save_baseline(path, site, before, key)
        assert load_baseline(path, key) == before
        assert [p.name for p in tmp.iterdir() if p.name.startswith(".b.json.")] == []   # no temp left behind
        data = json.loads(path.read_text())
        data["files"]["index.php"]["sha256"] = "0" * 64
        path.write_text(json.dumps(data))
        for k, problem in ((key, "doesn't match"), (None, "is signed"), (b"wrong", "doesn't match")):
            try:
                load_baseline(path, k)
            except BaselineError as e:
                assert problem in str(e), e
            else:
                raise AssertionError("an edited baseline was accepted")
        save_baseline(path, site, before)                              # unsigned
        try:
            load_baseline(path, key)
        except BaselineError as e:
            assert "isn't signed" in str(e)
        else:
            raise AssertionError("a key was given but an unsigned baseline was accepted")

        # 7. The tool: init, check, exit codes
        import io
        clean = build_site(tmp / "clean")
        bl = tmp / "clean.json"
        out = io.StringIO()
        assert main(["init", str(clean), "--baseline", str(bl), "--ignore", "logs/*"], out=out) == 0
        assert main(["check", str(clean), "--baseline", str(bl), "--ignore", "logs/*"], out=io.StringIO()) == 0
        (clean / "index.php").write_text("<?php hacked ?>")
        out = io.StringIO()
        assert main(["check", str(clean), "--baseline", str(bl), "--ignore", "logs/*"], out=out) == 1
        assert "MODIFIED  index.php" in out.getvalue()
        assert main(["check", str(tmp / "nope"), "--baseline", str(bl)], err=io.StringIO()) == 2

        # Practice
        assert watch_list_alerts(report, ["*.php"]) == ["config.php", "settings.php", "uploads/cache.php"]

    print("All tests passed!")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("--- A website is fingerprinted, then attacked ---")
        demo()
        print()
        run_tests()
    else:
        sys.exit(main())
