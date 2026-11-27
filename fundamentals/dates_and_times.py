# Dates and Times in Python (datetime, zoneinfo)
#
# Every log line starts with a timestamp, and most log analysis
# questions are about time: "what happened between 02:10 and 02:50?",
# "were these two events less than 60 seconds apart?", "which source
# saw it first?". Getting timestamps right is the foundation.
#
# modules_and_imports.py showed datetime.now() and timedelta. This
# file covers the rest.
#
# Topics covered here:
#   1. The four types: date, time, datetime, timedelta
#   2. Naive vs aware datetimes (the most important idea here)
#   3. Time zones with zoneinfo, and daylight saving traps
#   4. Formatting with strftime
#   5. Parsing with strptime and fromisoformat
#   6. Common log timestamp formats (Apache, syslog, ISO 8601,
#      Unix epoch, Windows FILETIME)
#   7. Arithmetic and comparisons
#   8. Bucketing events by minute or hour
#   9. Measuring durations: time.monotonic vs the wall clock
#  10. Security pitfalls: clock skew and faked timestamps
#  11. Practice: one function that normalises any of these formats,
#      with tests
#
# THE RULE TO REMEMBER
# --------------------
# Turn every timestamp into an AWARE datetime in UTC as soon as you
# read it. Do all comparisons, sorting and maths in UTC. Convert to
# local time only when showing it to a person.


import os
import tempfile
import time
from collections import Counter
from datetime import date, datetime, time as dtime, timedelta, timezone
from zoneinfo import ZoneInfo


# ---------------------------------------------------------------
# 1. The four types
# ---------------------------------------------------------------
#
#   type       | holds                         | example
#   -----------|-------------------------------|----------------------------
#   date       | year, month, day              | date(2026, 11, 27)
#   time       | hour, minute, second, micro   | time(10, 15, 32)
#   datetime   | a date AND a time             | datetime(2026, 11, 27, 10, 15, 32)
#   timedelta  | a length of time              | timedelta(minutes=5)
#
# All of them are immutable: methods like .replace() return a NEW
# object.

def section_1():
    d = date(2026, 11, 27)
    t = dtime(10, 15, 32)
    dt = datetime(2026, 11, 27, 10, 15, 32)
    gap = timedelta(hours=1, minutes=30)

    print("date:     ", d, "| weekday:", d.strftime("%A"), "| ISO week:", d.isocalendar().week)
    print("time:     ", t)
    print("datetime: ", dt, "| hour:", dt.hour, "| date part:", dt.date())
    print("timedelta:", gap, "| in seconds:", gap.total_seconds())
    print("combine:  ", datetime.combine(d, t))
    print("replace:  ", dt.replace(hour=0, minute=0, second=0), "(dt itself is unchanged:", dt, ")")


# ---------------------------------------------------------------
# 2. Naive vs aware
# ---------------------------------------------------------------
#
#   NAIVE  datetime has no time zone (tzinfo is None). "10:15" could be
#          10:15 in London, Indiana or Mumbai. Python can't tell.
#   AWARE  datetime knows its offset from UTC, so it's one exact moment.
#
# Python REFUSES to compare naive and aware datetimes, which is good:
# it stops you mixing them up by accident.
#
#   datetime.now()                -> naive local time  (avoid in logs)
#   datetime.now(timezone.utc)    -> aware UTC         (use this)
#   datetime.utcnow()             -> NAIVE, despite the name; deprecated
#                                    since Python 3.12. Don't use it.

def section_2():
    naive = datetime(2026, 11, 27, 10, 15)
    aware = datetime(2026, 11, 27, 10, 15, tzinfo=timezone.utc)
    print("naive:", naive, "| tzinfo:", naive.tzinfo)
    print("aware:", aware, "| tzinfo:", aware.tzinfo)
    print("now in UTC:", datetime.now(timezone.utc).isoformat(timespec="seconds"))

    try:
        naive < aware
    except TypeError as err:
        print("compare naive with aware -> TypeError:", err)

    # If you KNOW what zone a naive time is in, attach it with replace().
    # If it's a different zone, convert with astimezone() (section 3).
    print("attach UTC:", naive.replace(tzinfo=timezone.utc))


# ---------------------------------------------------------------
# 3. Time zones (zoneinfo) and daylight saving
# ---------------------------------------------------------------
#
# A fixed offset like +05:30 is just a number. A TIME ZONE like
# "America/New_York" is a set of rules, including when daylight saving
# starts and ends. zoneinfo (Python 3.9+) uses the system's time zone
# database. (On Windows, `pip install tzdata` may be needed.)
#
#   aware.astimezone(ZoneInfo("Asia/Kolkata"))   same moment, other zone
#
# Two daylight saving traps, using New York in 2026:
#   - 8 March, clocks jump 02:00 -> 03:00. 02:30 NEVER HAPPENS.
#   - 1 November, clocks go 02:00 -> 01:00. 01:30 happens TWICE.
#     The `fold` attribute picks which one: fold=0 first, fold=1 second.
#
# Local times in logs can therefore be missing, or repeat out of order.
# That's one more reason to store UTC.

NEW_YORK = ZoneInfo("America/New_York")
INDIANA = ZoneInfo("America/Indiana/Indianapolis")
KOLKATA = ZoneInfo("Asia/Kolkata")

def section_3():
    moment = datetime(2026, 11, 27, 15, 0, tzinfo=timezone.utc)
    for zone in (NEW_YORK, INDIANA, KOLKATA):
        local = moment.astimezone(zone)
        print(f"{str(zone):<30} {local.isoformat()}  ({local.tzname()})")

    first = datetime(2026, 11, 1, 1, 30, tzinfo=NEW_YORK)            # fold=0
    second = first.replace(fold=1)
    print("\n01:30 on 1 Nov 2026 in New York happens twice:")
    print("  first: ", first.astimezone(timezone.utc), first.tzname())
    print("  second:", second.astimezone(timezone.utc), second.tzname())


# ---------------------------------------------------------------
# 4. Formatting with strftime ("string FROM time")
# ---------------------------------------------------------------
#
#   code | meaning              | example
#   -----|----------------------|---------
#   %Y   | 4-digit year         | 2026
#   %m   | month 01-12          | 11
#   %d   | day 01-31            | 27
#   %H   | hour 00-23           | 10
#   %M   | minute 00-59         | 15
#   %S   | second 00-59         | 32
#   %f   | microseconds         | 000000
#   %b   | month name, short    | Nov
#   %a   | weekday, short       | Fri
#   %z   | UTC offset           | +0000
#   %Z   | zone name            | UTC
#   %j   | day of the year      | 331
#
# isoformat() gives the standard ISO 8601 form, which sorts correctly
# as plain text. Prefer it for anything you write out.

def section_4():
    dt = datetime(2026, 11, 27, 10, 15, 32, tzinfo=timezone.utc)
    print("ISO 8601:     ", dt.isoformat())
    print("Apache style: ", dt.strftime("%d/%b/%Y:%H:%M:%S %z"))
    print("syslog style: ", dt.strftime("%b %d %H:%M:%S"))
    print("for filenames:", dt.strftime("%Y%m%dT%H%M%SZ"))
    print("for people:   ", dt.strftime("%a %d %B %Y, %H:%M %Z"))


# ---------------------------------------------------------------
# 5. Parsing with strptime ("string PARSE time") and fromisoformat
# ---------------------------------------------------------------
#
# strptime uses the same codes as strftime, and the format must match
# the text EXACTLY or it raises ValueError.
#
# fromisoformat() is faster and handles most ISO 8601 text, including
# a trailing "Z" (since Python 3.11).
#
# Note: %b and %a depend on the computer's LOCALE (language setting).
# Logs are almost always in English, which is the default.

def section_5():
    print(datetime.strptime("2026-11-27 10:15:32", "%Y-%m-%d %H:%M:%S"))
    print(datetime.strptime("27/Nov/2026:10:15:32 +0530", "%d/%b/%Y:%H:%M:%S %z"))
    print(datetime.fromisoformat("2026-11-27T10:15:32Z"))
    print(datetime.fromisoformat("2026-11-27T10:15:32.123456+01:00"))
    try:
        datetime.strptime("2026/11/27", "%Y-%m-%d")
    except ValueError as err:
        print("wrong format -> ValueError:", err)


# ---------------------------------------------------------------
# 6. Common log timestamp formats
# ---------------------------------------------------------------
#
#   source                         | looks like
#   -------------------------------|-------------------------------------
#   Apache / Nginx access logs     | 27/Nov/2026:10:15:32 +0000
#   Linux syslog / auth.log        | Nov 27 10:15:32           (NO YEAR, no zone)
#   JSON logs, cloud services      | 2026-11-27T10:15:32.123Z  (ISO 8601)
#   Unix epoch seconds             | 1795774532
#   Epoch milliseconds (JavaScript)| 1795774532123
#   Windows FILETIME               | 134402481320000000        (100 ns since 1601)
#
# Two special cases:
#   - SYSLOG HAS NO YEAR. Assume the year of a reference date (often
#     the file's modification time). If that puts the event in the
#     future, it must be from LAST year: a December line read in
#     January.
#   - Windows FILETIME counts 100-nanosecond steps since 1 January
#     1601 UTC. It shows up in the registry, NTFS file records and
#     Active Directory attributes like lastLogonTimestamp.

APACHE_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

def parse_apache(text):
    return datetime.strptime(text, APACHE_FORMAT).astimezone(timezone.utc)


def parse_syslog(text, reference, zone=timezone.utc):
    """`reference` is an aware datetime (for example, when the log was written)."""
    parsed = datetime.strptime(f"{reference.year} {text}", "%Y %b %d %H:%M:%S")
    parsed = parsed.replace(tzinfo=zone).astimezone(timezone.utc)
    if parsed > reference + timedelta(days=1):           # in the future: last year
        parsed = parsed.replace(year=parsed.year - 1)
    return parsed


def from_epoch(value):
    """Seconds or milliseconds since 1970-01-01 UTC."""
    value = float(value)
    if value > 1e11:                                     # far too big for seconds: ms
        value /= 1000
    return datetime.fromtimestamp(value, tz=timezone.utc)


def from_filetime(value):
    return FILETIME_EPOCH + timedelta(microseconds=int(value) // 10)


def to_filetime(dt):
    return (dt - FILETIME_EPOCH) // timedelta(microseconds=1) * 10


def section_6():
    print("Apache  ->", parse_apache("27/Nov/2026:10:15:32 +0530"))
    jan_2nd = datetime(2027, 1, 2, tzinfo=timezone.utc)
    print("syslog  ->", parse_syslog("Dec 31 23:59:58", reference=jan_2nd), "(year rolled back)")
    print("ISO     ->", datetime.fromisoformat("2026-11-27T10:15:32.123Z"))
    print("epoch s ->", from_epoch(1795774532))
    print("epoch ms->", from_epoch(1795774532123))
    ft = to_filetime(datetime(2026, 11, 27, 10, 15, 32, tzinfo=timezone.utc))
    print("FILETIME->", ft, "=", from_filetime(ft))


# ---------------------------------------------------------------
# 7. Arithmetic and comparisons
# ---------------------------------------------------------------
#
#   datetime - datetime  -> timedelta
#   datetime + timedelta -> datetime
#   timedelta / timedelta -> float     (how many fit)
#   timedelta // timedelta -> int
#
# Aware datetimes in DIFFERENT zones compare correctly, because
# Python compares the actual moments.
#
# timedelta has no "months" or "years", because their length varies.
# For "same day next month", change the fields with replace() and
# handle short months yourself.

def section_7():
    login = datetime(2026, 11, 27, 10, 15, tzinfo=timezone.utc)
    upload = datetime(2026, 11, 27, 10, 22, 30, tzinfo=timezone.utc)
    gap = upload - login
    print("gap:", gap, "=", gap.total_seconds(), "seconds")
    print("within 10 minutes?", gap <= timedelta(minutes=10))
    print("how many 5-minute blocks:", gap // timedelta(minutes=5))

    same_moment = datetime(2026, 11, 27, 15, 45, tzinfo=KOLKATA)     # = 10:15 UTC
    print("10:15 UTC == 15:45 Kolkata?", login == same_moment)

    events = [upload, same_moment, login - timedelta(hours=1)]
    print("sorted:", [e.astimezone(timezone.utc).strftime("%H:%M:%S") for e in sorted(events)])


# ---------------------------------------------------------------
# 8. Bucketing events by minute or hour
# ---------------------------------------------------------------
#
# To count events per hour, round each timestamp DOWN to the hour with
# replace(), then count with Counter. For other bucket sizes (like 5
# minutes), use integer division on the time since midnight.

def floor_to(dt, step):
    midnight = dt.replace(hour=0, minute=0, second=0, microsecond=0)
    return midnight + (dt - midnight) // step * step


def section_8():
    stamps = ["2026-11-27T10:01:05Z", "2026-11-27T10:03:59Z", "2026-11-27T10:04:10Z",
              "2026-11-27T10:07:00Z", "2026-11-27T11:15:00Z"]
    times = [datetime.fromisoformat(s) for s in stamps]

    per_hour = Counter(t.replace(minute=0, second=0, microsecond=0) for t in times)
    for hour, n in sorted(per_hour.items()):
        print(f"  {hour:%H:00}  {'#' * n}  {n}")

    per_5_min = Counter(floor_to(t, timedelta(minutes=5)) for t in times)
    print("  per 5 minutes:", {f"{k:%H:%M}": v for k, v in sorted(per_5_min.items())})


# ---------------------------------------------------------------
# 9. Measuring durations
# ---------------------------------------------------------------
#
#   time.time()          wall-clock seconds since 1970. Can JUMP when
#                        the clock is adjusted (NTP, a user, an attacker).
#   time.monotonic()     only ever goes forward. Use it for timeouts and
#                        "how long did this take?".
#   time.perf_counter()  monotonic with the highest resolution. Use it
#                        for timing code (as the speed tests here do).

def section_9():
    start = time.monotonic()
    sum(range(1_000_000))
    print(f"took {time.monotonic() - start:.4f} s (monotonic)")
    print(f"wall clock now: {time.time():.0f} s since 1970")


# ---------------------------------------------------------------
# 10. Security pitfalls
# ---------------------------------------------------------------
#
#   - CLOCK SKEW: machines' clocks drift. If the firewall is 90 seconds
#     ahead of the web server, events seem to happen in the wrong order.
#     When correlating, allow a tolerance, and record each source's
#     known offset if you can measure it.
#   - MISSING ZONES: a log written in local time with no offset becomes
#     ambiguous the moment you combine it with another source. Find out
#     the zone and attach it when you parse.
#   - FAKED TIMESTAMPS ("timestomping"): a file's modification time is
#     just a number the OS stores, and any program can change it with
#     os.utime(). Attackers do this to make a dropped file look old. Don't
#     treat file times as proof; compare them with other evidence (logs,
#     NTFS $MFT records, backups).

def section_10():
    with tempfile.TemporaryDirectory() as folder:
        path = os.path.join(folder, "dropper.exe")
        with open(path, "w") as f:
            f.write("not really malware")
        real = datetime.fromtimestamp(os.stat(path).st_mtime, tz=timezone.utc)

        fake = datetime(2019, 3, 14, 9, 0, tzinfo=timezone.utc).timestamp()
        os.utime(path, (fake, fake))                    # set access and modify times
        shown = datetime.fromtimestamp(os.stat(path).st_mtime, tz=timezone.utc)

    print(f"file really written: {real:%Y-%m-%d %H:%M} UTC")
    print(f"after os.utime():    {shown:%Y-%m-%d %H:%M} UTC  <- looks years old")


# ---------------------------------------------------------------
# 11. Practice: normalise any of these formats to aware UTC
# ---------------------------------------------------------------
#
# Try each known format in turn and return the first that works.
# Anything unrecognised raises ValueError, so bad lines are never
# silently given a wrong time.

def to_utc(text, reference=None, assume_zone=timezone.utc):
    """Turn a log timestamp in any format from section 6 into aware UTC."""
    text = text.strip()
    if reference is None:
        reference = datetime.now(timezone.utc)

    if text.isdigit():
        if len(text) >= 17:                                  # FILETIME is 18 digits
            return from_filetime(text)
        return from_epoch(text)

    try:
        return parse_apache(text)
    except ValueError:
        pass

    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=assume_zone)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        pass

    try:
        return parse_syslog(" ".join(text.split()), reference, assume_zone)
    except ValueError:
        pass

    raise ValueError(f"unrecognised timestamp: {text!r}")


def within(a, b, limit):
    """True if two aware datetimes are at most `limit` apart, in either order."""
    return abs(a - b) <= limit


def run_tests():
    utc = timezone.utc
    expected = datetime(2026, 11, 27, 10, 15, 32, tzinfo=utc)
    ref = datetime(2026, 11, 28, tzinfo=utc)

    # Every format lands on the same moment
    samples = [
        "27/Nov/2026:10:15:32 +0000",
        "27/Nov/2026:15:45:32 +0530",            # same moment, Indian time
        "Nov 27 10:15:32",
        "Nov  27 10:15:32",                       # syslog pads single-digit days
        "2026-11-27T10:15:32Z",
        "2026-11-27T05:15:32-05:00",
        "2026-11-27 10:15:32",                    # naive: assumed UTC
        str(int(expected.timestamp())),
        str(int(expected.timestamp() * 1000)),
        str(to_filetime(expected)),
    ]
    for text in samples:
        assert to_utc(text, reference=ref) == expected, text
        assert to_utc(text, reference=ref).tzinfo is not None

    # A naive time in a known zone
    assert to_utc("2026-11-27 05:15:32", assume_zone=NEW_YORK) == expected

    # Syslog year rollover
    jan = datetime(2027, 1, 2, tzinfo=utc)
    assert parse_syslog("Dec 31 23:59:58", jan).year == 2026
    assert parse_syslog("Jan  1 00:00:05", jan).year == 2027

    # Bad input is rejected, not guessed
    for bad in ["", "yesterday", "2026-13-01T00:00:00Z", "32/Nov/2026:10:00:00 +0000"]:
        try:
            to_utc(bad, reference=ref)
            assert False, f"accepted {bad!r}"
        except ValueError:
            pass

    # Arithmetic helpers
    t = expected
    assert within(t, t + timedelta(seconds=59), timedelta(minutes=1))
    assert within(t + timedelta(seconds=59), t, timedelta(minutes=1))      # either order
    assert not within(t, t + timedelta(minutes=2), timedelta(minutes=1))
    assert floor_to(t, timedelta(minutes=5)) == datetime(2026, 11, 27, 10, 15, tzinfo=utc)
    assert floor_to(t, timedelta(hours=1)) == datetime(2026, 11, 27, 10, 0, tzinfo=utc)

    # FILETIME round trip and a known value: the Unix epoch
    assert from_filetime(116444736000000000) == datetime(1970, 1, 1, tzinfo=utc)
    assert from_filetime(to_filetime(expected)) == expected

    # Daylight saving: the repeated hour is two different moments, an hour apart
    first = datetime(2026, 11, 1, 1, 30, tzinfo=NEW_YORK)
    assert first.replace(fold=1).astimezone(utc) - first.astimezone(utc) == timedelta(hours=1)

    print("All tests passed!")


if __name__ == "__main__":
    for number, section in enumerate([section_1, section_2, section_3, section_4, section_5,
                                      section_6, section_7, section_8, section_9, section_10],
                                     start=1):
        print(f"\n--- {number}. {section.__name__} ---")
        section()

    print("\n--- 11. Practice: normalising mixed log timestamps ---")
    ref = datetime(2026, 11, 28, tzinfo=timezone.utc)
    mixed = [
        ("web",      "27/Nov/2026:10:16:40 +0000"),
        ("auth",     "Nov 27 10:15:58"),
        ("cloud",    "2026-11-27T10:17:05.250Z"),
        ("edr",      "1795774590"),
        ("windows",  str(to_filetime(datetime(2026, 11, 27, 10, 16, 2, tzinfo=timezone.utc)))),
        ("vpn",      "2026-11-27T05:15:50-05:00"),
    ]
    events = sorted((to_utc(stamp, reference=ref), source, stamp) for source, stamp in mixed)
    for when, source, raw in events:
        print(f"  {when:%H:%M:%S.%f}"[:-3] + f"  {source:<8} (raw: {raw})")

    print()
    run_tests()
