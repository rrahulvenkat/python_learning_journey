# Working with Large Files (logs, evidence, anything too big for memory)
#
# file_handling.py showed how to open, read and write files. That's
# enough for small files. Real logs are often GIGABYTES, compressed,
# split across rotated files, full of odd bytes, and still being
# written to while you read them. This file covers those problems.
#
# functions.py introduced generators (yield). Here they become the main
# tool: a generator handles one line at a time, so a 50 GB log uses no
# more memory than a 50 KB one.
#
# Topics covered here:
#   1. Why readlines() breaks on big files (measured with tracemalloc)
#   2. Generator pipelines: read -> parse -> filter -> count
#   3. Generator expressions vs list comprehensions
#   4. itertools for streams: islice, chain, takewhile, dropwhile, groupby
#   5. Compressed logs: gzip, bz2, lzma, detected by their magic bytes
#   6. Rotated logs: reading auth.log.3.gz ... auth.log in time order
#   7. Bad bytes: encoding errors without crashing or losing evidence
#   8. Binary files in chunks: hashing a large file
#   9. The last N lines, fast (like `tail`)
#  10. Following a file that's still growing (like `tail -f`)
#  11. Practice: a streaming failed-login counter, with tests
#
# This script creates its sample files in a temporary folder and
# deletes them at the end.
#
# SECURITY CONNECTION
# -------------------
# Incident responders work with huge logs and disk images on laptops
# with limited memory. Streaming is what makes that possible. Evidence
# must be hashed (section 8) to prove it wasn't changed, and a parser
# that crashes on one bad byte can make an attacker's injected garbage
# hide everything after it.


import bz2
import gzip
import hashlib
import itertools
import lzma
import os
import re
import tempfile
import time
import tracemalloc
from collections import Counter, deque
from pathlib import Path


# Set when the lesson runs (see the bottom of the file), so that
# importing this module from another file creates nothing on disk.
WORK_DIR = None

AUTH_LINE = "Nov 27 {h:02d}:{m:02d}:{s:02d} web01 sshd[{pid}]: {msg}\n"


def make_sample_log(path, lines=100_000):
    """Write a fake auth log: mostly successful logins, some failures."""
    with open(path, "w", encoding="utf-8") as f:
        for i in range(lines):
            h, m, s = (i // 3600) % 24, (i // 60) % 60, i % 60
            if i % 50 == 0:
                msg = f"Failed password for root from 198.51.100.{i % 7} port {40000 + i % 999} ssh2"
            elif i % 333 == 0:
                msg = f"Failed password for invalid user admin from 203.0.113.9 port {50000 + i % 999} ssh2"
            else:
                msg = f"Accepted publickey for alice from 192.0.2.10 port {30000 + i % 999} ssh2"
            f.write(AUTH_LINE.format(h=h, m=m, s=s, pid=1000 + i % 5000, msg=msg))


# ---------------------------------------------------------------
# 1. Why readlines() breaks on big files
# ---------------------------------------------------------------
#
#   f.read()          the WHOLE file as one string
#   f.readlines()     the WHOLE file as a list of strings
#   for line in f:    ONE line at a time (the file object is an iterator)
#
# tracemalloc (standard library) measures how much memory Python
# allocates. The peak for readlines() grows with the file; the peak
# for the loop stays tiny.

def count_failed_readlines(path):
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()                       # everything in memory at once
    return sum("Failed password" in line for line in lines)


def count_failed_streaming(path):
    with open(path, encoding="utf-8") as f:
        return sum("Failed password" in line for line in f)


def peak_memory(func, *args):
    tracemalloc.start()
    result = func(*args)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return result, peak


def section_1(sample):
    size = sample.stat().st_size
    for func in (count_failed_readlines, count_failed_streaming):
        result, peak = peak_memory(func, sample)
        print(f"  {func.__name__:<24} found {result:,} | peak memory {peak / 1_000_000:6.2f} MB"
              f"  (file is {size / 1_000_000:.1f} MB)")


# ---------------------------------------------------------------
# 2. Generator pipelines
# ---------------------------------------------------------------
#
# Split the work into small generators, each taking a stream and
# yielding a new one, like Unix pipes (cat | grep | cut | sort | uniq -c):
#
#   read_lines(path)  ->  parse(lines)  ->  only_failures(events)  ->  Counter
#
# Nothing runs until the last step asks for values. Then each line
# flows through every stage before the next line is read. Each stage
# is easy to test on its own, and swapping one stage (a different
# parser, a different filter) doesn't touch the others.

SSH = re.compile(r"sshd\[\d+\]: (?P<result>Failed|Accepted) \w+ for "
                 r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")


def read_lines(path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            yield line.rstrip("\n")


def parse(lines):
    for line in lines:
        m = SSH.search(line)
        if m:
            yield m.groupdict()


def only_failures(events):
    return (e for e in events if e["result"] == "Failed")       # a generator expression


def section_2(sample):
    pipeline = only_failures(parse(read_lines(sample)))
    print("  pipeline object:", type(pipeline).__name__, "(nothing has been read yet)")
    top = Counter(e["ip"] for e in pipeline).most_common(3)
    print("  top failing IPs:", top)


# ---------------------------------------------------------------
# 3. Generator expressions vs list comprehensions
# ---------------------------------------------------------------
#
#   [x * 2 for x in data]   builds the whole list now
#   (x * 2 for x in data)   builds nothing; produces values on demand
#
# A generator can only be used ONCE. After it's exhausted it yields
# nothing, which is a common surprise.

def section_3():
    import sys
    as_list = [n * n for n in range(1_000_000)]
    as_gen = (n * n for n in range(1_000_000))
    print(f"  list: {sys.getsizeof(as_list):>10,} bytes")
    print(f"  gen:  {sys.getsizeof(as_gen):>10,} bytes")
    print("  sum(gen) first time: ", sum(as_gen))
    print("  sum(gen) second time:", sum(as_gen), "<- already used up")


# ---------------------------------------------------------------
# 4. itertools for streams
# ---------------------------------------------------------------
#
#   islice(stream, n)         the first n items (like `head`)
#   chain(a, b, c)            one stream after another (several files as one)
#   dropwhile(cond, stream)   skip items WHILE cond is true, then yield the rest
#   takewhile(cond, stream)   yield items WHILE cond is true, then stop
#   groupby(stream, key)      group CONSECUTIVE items with the same key
#
# dropwhile + takewhile pull a time window out of a sorted log without
# reading past the end of the window. groupby only groups neighbours,
# so it suits logs already in time order (per-hour summaries).

def section_4(sample):
    print("  first 2 lines:")
    for line in itertools.islice(read_lines(sample), 2):
        print("   ", line)

    def hhmm(line):
        return line[7:12]                           # "Nov 27 HH:MM:SS ..." -> "HH:MM"

    window = itertools.takewhile(lambda l: hhmm(l) < "01:05",
                                 itertools.dropwhile(lambda l: hhmm(l) < "01:00",
                                                     read_lines(sample)))
    print("  lines from 01:00 to 01:05:", sum(1 for _ in window))

    per_hour = [(hour, sum(1 for _ in group))
                for hour, group in itertools.groupby(read_lines(sample), key=lambda l: l[7:9])]
    print("  lines per hour (first 4):", per_hour[:4])


# ---------------------------------------------------------------
# 5. Compressed logs
# ---------------------------------------------------------------
#
# Old logs are usually compressed. gzip, bz2 and lzma each have an
# open() that works just like the built-in one. Use mode "rt" (read
# TEXT) to get strings instead of bytes.
#
# Decide the format from the file's MAGIC BYTES, not its name (the
# same idea as hex_and_bytes.py): a renamed or extension-less file
# still opens correctly.
#
#   gzip  1f 8b       bz2  42 5a 68 ("BZh")       xz  fd 37 7a 58 5a 00

COMPRESSED = [
    (b"\x1f\x8b", gzip.open),
    (b"BZh", bz2.open),
    (b"\xfd7zXZ\x00", lzma.open),
]


def open_log(path, errors="backslashreplace"):
    """Open a plain or compressed log as text, whatever its name."""
    with open(path, "rb") as f:
        start = f.read(6)
    for magic, opener in COMPRESSED:
        if start.startswith(magic):
            return opener(path, "rt", encoding="utf-8", errors=errors)
    return open(path, encoding="utf-8", errors=errors)


def section_5(sample):
    text = sample.read_bytes()
    for name, opener in [("auth.log.gz", gzip.open), ("auth.log.bz2", bz2.open),
                         ("auth.log.xz", lzma.open), ("no_extension", gzip.open)]:
        path = WORK_DIR / name
        with opener(path, "wb") as f:
            f.write(text)
        with open_log(path) as f:
            count = sum(1 for _ in f)
        print(f"  {name:<14} {path.stat().st_size / 1_000_000:5.2f} MB on disk, {count:,} lines")


# ---------------------------------------------------------------
# 6. Rotated logs
# ---------------------------------------------------------------
#
# Linux rotates logs like this (newest last):
#   auth.log.4.gz  auth.log.3.gz  auth.log.2.gz  auth.log.1  auth.log
#
# A BIGGER number is OLDER. Sort by that number, biggest first, and
# chain them so the rest of the program sees one stream in time order.
# Sorting the file NAMES as text would put auth.log.10 before auth.log.2.

def rotation_number(path):
    m = re.search(r"\.(\d+)(?:\.gz|\.bz2|\.xz)?$", path.name)
    return int(m.group(1)) if m else 0              # the live file counts as 0


def rotated_files(folder, base="auth.log"):
    files = [p for p in Path(folder).iterdir() if p.name.startswith(base)]
    return sorted(files, key=rotation_number, reverse=True)      # oldest first


def read_rotated(folder, base="auth.log"):
    for path in rotated_files(folder, base):
        with open_log(path) as f:
            for line in f:
                yield line.rstrip("\n")


def section_6():
    folder = WORK_DIR / "rotated"
    folder.mkdir()
    for n in range(12, -1, -1):                     # day 12 is oldest, 0 is today
        name = "auth.log" if n == 0 else f"auth.log.{n}"
        opener = gzip.open if n >= 2 else open
        if n >= 2:
            name += ".gz"
        with opener(folder / name, "wt", encoding="utf-8") as f:
            f.write(f"day -{n}: first line\nday -{n}: last line\n")

    print("  order:", [p.name for p in rotated_files(folder)][:5], "...")
    lines = list(read_rotated(folder))
    print(f"  {len(lines)} lines; first: {lines[0]!r}, last: {lines[-1]!r}")


# ---------------------------------------------------------------
# 7. Bad bytes
# ---------------------------------------------------------------
#
# Logs contain whatever was sent to the server, including bytes that
# aren't valid UTF-8 (binary junk, Latin-1 text, attack payloads). By
# default Python raises UnicodeDecodeError and stops. The `errors`
# argument decides what happens instead:
#
#   errors=             | b"user \xff\xfe" becomes  | notes
#   --------------------|---------------------------|------------------------------
#   "strict" (default)  | (crash)                   | fine for files you control
#   "ignore"            | "user "                   | SILENTLY DELETES evidence
#   "replace"           | "user ��"                 | keeps the place, loses the bytes
#   "backslashreplace"  | "user \xff\xfe"           | keeps the exact bytes visible
#
# For logs, "backslashreplace" is usually best: nothing crashes and
# nothing is lost.

def section_7():
    path = WORK_DIR / "dirty.log"
    path.write_bytes(b"login ok user=alice\nlogin fail user=\xff\xfe\x00evil\nlogin ok user=bob\n")
    try:
        with open(path, encoding="utf-8") as f:
            f.read()
    except UnicodeDecodeError as err:
        print("  strict:", type(err).__name__, "-", err.reason, "at byte", err.start)
    for mode in ("ignore", "replace", "backslashreplace"):
        with open(path, encoding="utf-8", errors=mode) as f:
            print(f"  {mode:<17}", repr(f.read().splitlines()[1]))


# ---------------------------------------------------------------
# 8. Binary files in chunks: hashing evidence
# ---------------------------------------------------------------
#
# A disk image or memory dump may be bigger than your RAM. Read it in
# fixed-size CHUNKS (here 1 MB) and feed each chunk to the hash.
# The result is identical to hashing the whole file at once.
#
# Python 3.11+ has hashlib.file_digest(f, "sha256"), which does this
# for you. The loop shows what it does inside.
#
# The `:=` "walrus" operator reads a chunk AND checks it in one line:
# the loop stops when read() returns b"" at the end of the file.

def sha256_of(path, chunk_size=1024 * 1024):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def section_8(sample):
    print("  chunked:     ", sha256_of(sample))
    with open(sample, "rb") as f:
        print("  file_digest: ", hashlib.file_digest(f, "sha256").hexdigest())


# ---------------------------------------------------------------
# 9. The last N lines (like `tail`)
# ---------------------------------------------------------------
#
# Simple: a deque with maxlen=N keeps only the newest N items as you
# loop. Correct, but it still READS the whole file.
#
# Fast: jump to the END of the file with seek() and read backwards in
# blocks until you have N line breaks. A 20 GB file takes the same
# time as a 20 KB one. (Works on plain files, not compressed ones,
# since you can't jump around inside a gzip stream cheaply.)

def tail_simple(path, n=10):
    with open_log(path) as f:
        return [line.rstrip("\n") for line in deque(f, maxlen=n)]


def tail_fast(path, n=10, block=8192):
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        position = f.tell()
        data = b""
        while position > 0 and data.count(b"\n") <= n:
            step = min(block, position)
            position -= step
            f.seek(position)
            data = f.read(step) + data
    lines = data.decode("utf-8", errors="backslashreplace").splitlines()
    return lines[-n:]


def section_9(sample):
    for func in (tail_simple, tail_fast):
        start = time.perf_counter()
        last = func(sample, 3)
        print(f"  {func.__name__:<12} {time.perf_counter() - start:.5f} s  last line: {last[-1][:50]}...")


# ---------------------------------------------------------------
# 10. Following a growing file (like `tail -f`)
# ---------------------------------------------------------------
#
# Live monitoring: keep the file open, and when there's no new line,
# wait a little and try again. `max_idle_polls` lets the demo and
# tests stop; a real monitor would loop forever (and should also notice
# when the log is rotated and reopen it).
#
# A half-written line (no "\n" yet) is held back until it's complete,
# so you never parse half a line.

def follow(path, poll_seconds=0.05, max_idle_polls=None, from_start=False):
    with open(path, encoding="utf-8", errors="backslashreplace") as f:
        if not from_start:
            f.seek(0, os.SEEK_END)
        partial = ""
        idle = 0
        while max_idle_polls is None or idle < max_idle_polls:
            chunk = f.readline()
            if not chunk:
                idle += 1
                time.sleep(poll_seconds)
                continue
            idle = 0
            partial += chunk
            if partial.endswith("\n"):
                yield partial.rstrip("\n")
                partial = ""


def section_10():
    import threading
    path = WORK_DIR / "live.log"
    path.write_text("old line, already there\n", encoding="utf-8")

    def writer():
        with open(path, "a", encoding="utf-8") as f:
            for i in range(3):
                time.sleep(0.1)
                f.write(f"new event {i}\n")
                f.flush()
            f.write("half a li")                    # incomplete...
            f.flush()
            time.sleep(0.1)
            f.write("ne, now finished\n")
            f.flush()

    threading.Thread(target=writer).start()
    for line in follow(path, max_idle_polls=8):
        print("  got:", line)


# ---------------------------------------------------------------
# 11. Practice: streaming failed-login counter
# ---------------------------------------------------------------
#
# Combine the pieces: read every rotated file (plain or compressed),
# survive bad bytes, parse lazily, and count failures per IP, with
# memory use independent of the log size.

def failed_logins(lines):
    counts = Counter()
    for event in parse(lines):
        if event["result"] == "Failed":
            counts[event["ip"]] += 1
    return counts


def run_tests():
    with tempfile.TemporaryDirectory() as tmp:
        _run_tests_in(Path(tmp))
    print("All tests passed!")


def _run_tests_in(folder):
    fail ="Nov 27 10:00:00 h sshd[1]: Failed password for root from {ip} port 1 ssh2\n"
    ok = "Nov 27 10:00:00 h sshd[1]: Accepted publickey for alice from {ip} port 1 ssh2\n"

    with gzip.open(folder / "auth.log.2.gz", "wt", encoding="utf-8") as f:
        f.write(fail.format(ip="10.0.0.1") * 3)
    (folder / "auth.log.1").write_bytes(
        fail.format(ip="10.0.0.2").encode() + b"junk \xff\xfe line\n" + ok.format(ip="10.0.0.1").encode())
    (folder / "auth.log").write_text(fail.format(ip="10.0.0.1"), encoding="utf-8")
    (folder / "other.log").write_text(fail.format(ip="9.9.9.9"), encoding="utf-8")

    # Rotation order, and only the right base name
    assert [p.name for p in rotated_files(folder)] == ["auth.log.2.gz", "auth.log.1", "auth.log"]
    assert rotation_number(Path("auth.log.10.gz")) == 10
    assert sorted(["auth.log.10", "auth.log.2"]) == ["auth.log.10", "auth.log.2"]   # why text sort is wrong

    # The full pipeline
    assert failed_logins(read_rotated(folder)) == {"10.0.0.1": 4, "10.0.0.2": 1}

    # The junk line survives as visible text
    lines = list(read_rotated(folder))
    assert "junk \\xff\\xfe line" in lines

    # open_log detects compression from content, not name
    disguised = folder / "looks_plain.txt"
    with gzip.open(disguised, "wt", encoding="utf-8") as f:
        f.write("hidden\n")
    with open_log(disguised) as f:
        assert f.read() == "hidden\n"

    # Chunked hashing matches hashing everything at once, for any chunk size
    blob = folder / "blob.bin"
    blob.write_bytes(os.urandom(300_000))
    expected = hashlib.sha256(blob.read_bytes()).hexdigest()
    for size in (7, 4096, 65_536, 10_000_000):      # odd sizes too, and bigger than the file
        assert sha256_of(blob, size) == expected

    # tail: both versions agree, including short files and no final newline
    for content in ["a\nb\nc\nd\n", "a\nb\nc\nd", "only\n", ""]:
        p = folder / "t.log"
        p.write_text(content, encoding="utf-8")
        assert tail_fast(p, 2) == tail_simple(p, 2), content
    big = folder / "big.log"
    big.write_text("".join(f"line {i}\n" for i in range(50_000)), encoding="utf-8")
    assert tail_fast(big, 3, block=100) == ["line 49997", "line 49998", "line 49999"]

    # follow() picks up a line appended after it starts
    live = folder / "live.log"
    live.write_text("", encoding="utf-8")
    with open(live, "a", encoding="utf-8") as f:
        f.write("first\n")
    assert list(follow(live, poll_seconds=0.01, max_idle_polls=3, from_start=True)) == ["first"]

    # Generators are single-use
    gen = (x for x in range(3))
    assert list(gen) == [0, 1, 2] and list(gen) == []


if __name__ == "__main__":
    import shutil

    WORK_DIR = Path(tempfile.mkdtemp(prefix="large_files_"))
    sample = WORK_DIR / "auth.log"
    make_sample_log(sample)
    try:
        for number, (section, needs_sample) in enumerate([
                (section_1, True), (section_2, True), (section_3, False), (section_4, True),
                (section_5, True), (section_6, False), (section_7, False), (section_8, True),
                (section_9, True), (section_10, False)], start=1):
            print(f"\n--- {number}. {section.__name__} ---")
            section(sample) if needs_sample else section()

        print()
        run_tests()
    finally:
        shutil.rmtree(WORK_DIR)                     # clean up the temporary files
