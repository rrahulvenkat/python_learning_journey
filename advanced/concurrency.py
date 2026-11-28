# Concurrency: threads, thread pools, processes, and the GIL
#
# Security tools spend most of their time WAITING: for a server to
# answer, a DNS lookup, an API, a disk. Checking 1,000 IPs against a
# threat-intel API one at a time, at 0.2 s each, takes over three
# minutes; doing 20 at once takes ten seconds. That's what concurrency is
# for. Some tools are busy COMPUTING instead (cracking hashes, scanning
# huge files), and that needs a different tool.
#
# Topics covered here:
#   1. Two kinds of slow: waiting (I/O-bound) vs computing (CPU-bound)
#   2. Threads: threading.Thread, start and join
#   3. Race conditions, and locks (a `with` block, from the last lesson)
#   4. Thread pools: concurrent.futures.ThreadPoolExecutor
#   5. Errors and timeouts in pool tasks
#   6. Producer and consumers: queue.Queue
#   7. The GIL, and why threads don't speed up pure-Python computing
#   8. Processes: ProcessPoolExecutor (and the __main__ guard it needs)
#   9. Which to use when
#  10. Practice, with tests
#
# HOW TO RUN IT
#   python3 concurrency.py
#
# The timings printed depend on your machine; the tests check results,
# not speed.


import hashlib
import os
import queue
import threading
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed, wait
from pathlib import Path


# ---------------------------------------------------------------
# 1. Two kinds of slow
# ---------------------------------------------------------------
#
#   I/O-BOUND: the program waits on something outside it (network, disk,
#   a database). While one request waits, others could be sent.
#   -> threads, or asyncio (next lesson)
#
#   CPU-BOUND: the program is busy calculating (hashing, brute force,
#   compression). It isn't waiting on anything; it needs more CPUs.
#   -> processes (section 8)
#
# A fake reputation lookup stands in for a slow network API here, so the
# lesson works offline and never sends anything anywhere.

KNOWN_BAD = {"203.0.113.9", "198.51.100.23", "192.0.2.66"}


def check_reputation(ip, latency=0.1):
    time.sleep(latency)                               # waiting on "the network"
    return ip, ("malicious" if ip in KNOWN_BAD else "clean")


IPS = [f"203.0.113.{i}" for i in range(1, 21)]        # 20 documentation-range addresses


# ---------------------------------------------------------------
# 2. Threads
# ---------------------------------------------------------------
#
# A thread is a separate line of execution inside the same program,
# sharing the same memory. threading.Thread(target=f, args=(...)) makes
# one, .start() runs it, and .join() waits for it to finish. While one
# thread sleeps (waits on I/O), Python runs another.

def sequential(ips):
    return dict(check_reputation(ip) for ip in ips)


def with_threads(ips):
    results = {}

    def worker(ip):
        ip, verdict = check_reputation(ip)
        results[ip] = verdict                         # each thread writes a DIFFERENT key: safe

    threads = [threading.Thread(target=worker, args=(ip,)) for ip in ips]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


# ---------------------------------------------------------------
# 3. Race conditions, and locks
# ---------------------------------------------------------------
#
# Threads share memory, so two of them can change the same thing at the
# same moment. "count += 1" is really three steps: read count, add 1,
# write it back. If two threads both READ 5 before either WRITES, both
# write 6: one update is lost. That's a RACE CONDITION, and it's a real
# security bug class too: check a balance, then spend it, while another
# thread spends it in between (a "time-of-check to time-of-use" bug,
# TOCTOU).
#
# The fix: a LOCK. Only one thread at a time can hold it, so the three
# steps happen together. threading.Lock is a context manager:
#   with lock:
#       count += 1
# (The demo forces the bad timing with time.sleep(0), which lets another
# thread run between the read and the write. Without it, the race still
# exists; it just shows up less often, which makes it worse: it passes
# testing and fails in production.)

class Counter:
    def __init__(self):
        self.value = 0
        self.lock = threading.Lock()

    def unsafe_add(self):
        current = self.value
        time.sleep(0)                                 # let another thread in, mid-update
        self.value = current + 1

    def safe_add(self):
        with self.lock:
            current = self.value
            time.sleep(0)
            self.value = current + 1


def hammer(add, threads=8, each=200):
    def run():
        for _ in range(each):
            add()
    workers = [threading.Thread(target=run) for _ in range(threads)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()


# ---------------------------------------------------------------
# 4. Thread pools
# ---------------------------------------------------------------
#
# Starting one thread per task doesn't scale: 100,000 IPs would mean
# 100,000 threads. A POOL keeps a fixed number of worker threads and
# feeds them tasks. concurrent.futures.ThreadPoolExecutor does this:
#   * pool.map(f, items)     results in the SAME ORDER as items
#   * pool.submit(f, item)   returns a Future: a placeholder for a result
#                            that isn't ready yet
#   * as_completed(futures)  yields each future as soon as it FINISHES
#
# max_workers matters: too many, and you hammer the API (and get rate
# limited or blocked). Pick a number the other side can handle.

def with_pool(ips, workers=10):
    with ThreadPoolExecutor(max_workers=workers) as pool:   # `with` waits for all, then cleans up
        return dict(pool.map(check_reputation, ips))


def first_results(ips, workers=10):
    """Results in the order they FINISH, for showing progress."""
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(check_reputation, ip, 0.01 * (i % 5)): ip for i, ip in enumerate(ips)}
        return [f.result()[0] for f in as_completed(futures)]


# ---------------------------------------------------------------
# 5. Errors and timeouts in pool tasks
# ---------------------------------------------------------------
#
# An exception inside a task doesn't crash the program: it's stored in
# the Future, and raised again when you call .result(). So one bad host
# doesn't stop the scan, but you MUST look at each result, or failures
# disappear silently. And .result(timeout=...) / wait(timeout=...) stop
# a hung server from stalling everything.

def flaky_lookup(ip):
    if ip.endswith(".13"):
        raise ConnectionError(f"{ip}: connection reset")
    if ip.endswith(".14"):
        time.sleep(1.0)                               # a server that hangs
    return ip, "clean"


def robust_scan(ips, timeout=0.3):
    results, errors = {}, {}
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(flaky_lookup, ip): ip for ip in ips}
        done, not_done = wait(futures, timeout=timeout)
        for f in done:
            try:
                ip, verdict = f.result()
                results[ip] = verdict
            except ConnectionError as err:
                errors[futures[f]] = str(err)
        for f in not_done:
            errors[futures[f]] = "timed out"
            f.cancel()                                # stop it if it hasn't started yet
    return results, errors


# ---------------------------------------------------------------
# 6. Producer and consumers: queue.Queue
# ---------------------------------------------------------------
#
# A common shape for log processing: one thread READS lines (the
# producer), several threads ANALYSE them (the consumers). queue.Queue
# is the safe way to hand work between threads: it does its own locking.
# A SENTINEL (here None) tells each consumer there's no more work.

def analyse_lines(lines, consumers=3):
    work = queue.Queue(maxsize=100)                   # a full queue makes the producer wait
    failed = Counter()

    def consumer():
        while True:
            line = work.get()
            if line is None:
                break
            if "Failed password" in line:
                failed.safe_add()

    threads = [threading.Thread(target=consumer) for _ in range(consumers)]
    for t in threads:
        t.start()
    for line in lines:                                # the producer: this thread
        work.put(line)
    for _ in threads:
        work.put(None)                                # one stop signal per consumer
    for t in threads:
        t.join()
    return failed.value


# ---------------------------------------------------------------
# 7. The GIL
# ---------------------------------------------------------------
#
# CPython (the usual Python) has a Global Interpreter Lock: only ONE
# thread runs Python code at a time. Threads still help with I/O,
# because a thread that's waiting gives the lock up. But for pure-Python
# COMPUTING, threads take turns on one CPU, so there's no speed-up.
#
# Two footnotes:
#   * C code that releases the GIL runs in parallel: hashlib does this
#     for large inputs, which is why hashing files with threads DOES get
#     faster (the practice).
#   * Python 3.13 has an optional "free-threaded" build without the GIL.
#     It's experimental, and the usual python3 still has the lock.
#
# The CPU-bound task: brute-forcing a PIN from its SHA-256 hash, split
# into one chunk per worker. Each guess is mostly Python work (a loop, a
# string format, a tiny hash: hashlib only releases the GIL for inputs
# of 2 KB or more), so threads take turns.
#
# The size of the job matters. A 4-digit PIN takes ~30 ms in total, LESS
# than the ~100 ms it costs to start worker processes, so processes come
# out slower. The first version of this lesson did exactly that, and
# "proved" the opposite of the point. Parallelism only pays off when the
# work outweighs the cost of setting it up; the demo uses 6 digits.

def crack_pin_chunk(args):
    target, start, stop, digits = args
    for pin in range(start, stop):
        candidate = f"{pin:0{digits}d}"
        if hashlib.sha256(candidate.encode()).hexdigest() == target:
            return candidate
    return None


def crack_pin(target, executor_cls=None, workers=4, digits=4):
    space = 10 ** digits
    if executor_cls is None:                          # one thread, no pool: the baseline
        return crack_pin_chunk((target, 0, space, digits))
    size = -(-space // workers)                       # ceiling division
    chunks = [(target, i * size, min(space, (i + 1) * size), digits) for i in range(workers)]
    with executor_cls(max_workers=workers) as pool:
        for found in pool.map(crack_pin_chunk, chunks):
            if found:
                return found
    return None


# ---------------------------------------------------------------
# 8. Processes
# ---------------------------------------------------------------
#
# ProcessPoolExecutor has the same interface as the thread pool, but
# runs each worker as a separate PROCESS with its own Python and its own
# GIL, so they compute in parallel on separate CPU cores. The costs:
#   * data is copied between processes (pickled), so send small inputs
#   * starting processes is slower than starting threads
#   * on macOS and Windows, each worker starts a fresh Python that
#     IMPORTS this file. So the task must be a top-level function (not a
#     lambda or nested function), and the code that starts the pool must
#     sit under  if __name__ == "__main__":  or every worker would start
#     its own pool, forever.


# ---------------------------------------------------------------
# 9. Which to use when
# ---------------------------------------------------------------
#
#   waiting on network/disk, up to hundreds at once  -> ThreadPoolExecutor
#   waiting on thousands of connections              -> asyncio (next lesson)
#   pure-Python computing                            -> ProcessPoolExecutor
#   sharing data between threads                     -> queue.Queue, or a Lock
#
# And whatever you use: limit how many requests you send at once. A scan
# without limits is a denial-of-service attack on whoever answers it.


# ---------------------------------------------------------------
# The lesson
# ---------------------------------------------------------------

def timed(label, func, *args):
    start = time.perf_counter()
    result = func(*args)
    print(f"  {label:<34} {time.perf_counter() - start:6.2f}s")
    return result


def lesson():
    print("--- 1-4. Checking 20 IPs against a slow (fake) API ---")
    a = timed("one at a time", sequential, IPS)
    b = timed("a thread per IP", with_threads, IPS)
    c = timed("a pool of 10 threads", with_pool, IPS)
    assert a == b == c
    print(f"  same answers; malicious: {sorted(ip for ip, v in c.items() if v == 'malicious')}")

    print("\n--- 3. A race condition, then a lock ---")
    unsafe, safe = Counter(), Counter()
    hammer(unsafe.unsafe_add)
    hammer(safe.safe_add)
    print(f"  8 threads x 200 adds should give 1600: without a lock {unsafe.value}, with one {safe.value}")

    print("\n--- 5. A scan with a failing host and a hung one ---")
    results, errors = robust_scan([f"192.0.2.{i}" for i in range(10, 16)])
    print(f"  finished: {len(results)}, problems: {errors}")

    print("\n--- 7-8. CPU-bound: cracking a 6-digit PIN from its hash (1,000,000 guesses) ---")
    target = hashlib.sha256(b"987654").hexdigest()     # in the last chunk: every chunk must run
    timed("one thread", crack_pin, target, None, 4, 6)
    timed("4 threads (the GIL: no real gain)", crack_pin, target, ThreadPoolExecutor, 4, 6)
    found = timed(f"4 processes ({os.cpu_count()} CPUs here)", crack_pin, target, ProcessPoolExecutor, 4, 6)
    print(f"  the PIN was {found}")


# ---------------------------------------------------------------
# 10. Practice and tests
# ---------------------------------------------------------------
#
# Practice: hash every file in a folder (projects/file_integrity_checker
# does this one file at a time). Write hash_folder(path, workers) using a
# ThreadPoolExecutor, returning {relative path: sha256}. Threads help
# here even with the GIL: reading files waits on the disk, and hashlib
# releases the GIL while it hashes. Solution below.

def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def hash_folder(folder, workers=8):
    folder = Path(folder)
    files = [p for p in folder.rglob("*") if p.is_file() and not p.is_symlink()]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        digests = pool.map(sha256_file, files)
        return {p.relative_to(folder).as_posix(): d for p, d in zip(files, digests)}


def run_tests():
    import tempfile

    # 2 and 4: threads and pools give the same answers as doing it one by one, faster
    ips = IPS[:10]
    expected = sequential(ips)
    assert with_threads(ips) == expected and with_pool(ips) == expected
    assert expected["203.0.113.9"] == "malicious"
    start = time.perf_counter()
    with_pool(IPS, workers=20)
    assert time.perf_counter() - start < 1.0          # 20 x 0.1s of waiting, overlapped
    assert sorted(first_results(ips)) == sorted(ips)

    # 3. The lock makes the count exact; without it, updates are lost
    safe = Counter()
    hammer(safe.safe_add)
    assert safe.value == 1600
    unsafe = Counter()
    hammer(unsafe.unsafe_add)
    assert unsafe.value < 1600                        # sleep(0) mid-update forces the race

    # 5. One failure and one hang don't stop the rest
    results, errors = robust_scan([f"192.0.2.{i}" for i in range(10, 16)])
    assert set(results) == {"192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.15"}
    assert "connection reset" in errors["192.0.2.13"] and errors["192.0.2.14"] == "timed out"

    # 6. Producer and consumers
    lines = ["Failed password for root"] * 50 + ["Accepted publickey for alice"] * 20
    assert analyse_lines(lines) == 50

    # 7-8. Threads and processes both find the PIN
    target = hashlib.sha256(b"0042").hexdigest()
    for executor in (None, ThreadPoolExecutor, ProcessPoolExecutor):
        assert crack_pin(target, executor) == "0042", executor
    assert crack_pin(hashlib.sha256(b"9999").hexdigest(), ThreadPoolExecutor, workers=3) == "9999"  # uneven chunks
    assert crack_pin(hashlib.sha256(b"no").hexdigest(), ThreadPoolExecutor) is None

    # Practice
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "sub").mkdir()
        for i in range(12):
            (tmp / ("sub" if i % 2 else ".") / f"f{i}.txt").write_text(f"file {i}")
        digests = hash_folder(tmp)
        assert len(digests) == 12
        assert digests["sub/f1.txt"] == hashlib.sha256(b"file 1").hexdigest()
        assert digests == {k: sha256_file(tmp / k) for k in digests}

    print("All tests passed!")


if __name__ == "__main__":                            # REQUIRED for ProcessPoolExecutor (section 8)
    lesson()
    print()
    run_tests()
