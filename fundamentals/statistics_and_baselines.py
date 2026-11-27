# Statistics and Baselines: deciding what "unusual" means
#
# A fixed threshold ("alert on 10 failed logins") is easy but blunt. A
# service account might fail 40 times an hour every day because of a
# stale password, while 3 failures for the CEO's account would be
# very unusual. A BASELINE learns what's normal for EACH user, host or
# IP, and flags what's far from it.
#
# This file covers the statistics behind that, using only the standard
# library (`statistics`, `collections`, `math`).
#
# Topics covered here:
#   1. Why fixed thresholds fail
#   2. The statistics module: mean, median, mode, stdev, quantiles
#   3. Mean vs median: why one outlier ruins the average
#   4. Z-scores: "how many standard deviations from normal?"
#   5. Robust z-scores (median and MAD): when the attack is IN the
#      training data
#   6. Percentiles: thresholds for skewed data (bytes, durations)
#   7. Per-entity baselines, and the cold-start problem
#   8. Time-of-day patterns
#   9. Streaming baselines: Welford's algorithm and moving averages
#  10. Rarity: first-seen and rare categorical values
#  11. The base rate problem: why "99% accurate" can still drown you
#  12. Practice: unusual upload volumes, with tests
#
# SECURITY CONNECTION
# -------------------
# This is "anomaly detection" or UEBA (user and entity behaviour
# analytics), a standard feature of SIEMs and EDR products. It catches
# things signature rules can't: a real user's stolen credentials used
# at 3 AM, a slow data leak, a server suddenly talking to a new
# country. It also produces false alarms, and section 11 shows why
# managing those matters as much as the maths.


import math
import random
import statistics
from collections import Counter, defaultdict, deque
from statistics import NormalDist


random.seed(42)                                     # same "random" data every run


# ---------------------------------------------------------------
# 1. Why fixed thresholds fail
# ---------------------------------------------------------------
#
# Failed logins per hour, for two accounts over the same day:
#
#   svc-backup:  38 41 40 39 42 37 40 ...    (normal: a broken cron job)
#   ceo:          0  0  0  1  0  0  0 ...    then suddenly 6
#
# A threshold of 10 alerts on svc-backup EVERY hour (noise), and never
# on the CEO (missed). The same number means different things for
# different entities.

def section_1():
    svc = [random.randint(36, 44) for _ in range(24)]
    ceo = [random.choice([0, 0, 0, 0, 1]) for _ in range(23)] + [6]
    threshold = 10
    print(f"  svc-backup hours over {threshold}: {sum(x > threshold for x in svc)} of 24 (all noise)")
    print(f"  ceo hours over {threshold}:        {sum(x > threshold for x in ceo)} of 24 "
          f"(missed the 6 at the end)")


# ---------------------------------------------------------------
# 2. The statistics module
# ---------------------------------------------------------------
#
#   function                | what it is
#   ------------------------|-----------------------------------------------
#   mean(data), fmean(data) | the average (fmean is faster, always a float)
#   median(data)            | the middle value when sorted
#   mode(data)              | the most common value
#   stdev(data)             | SAMPLE standard deviation: typical distance from the mean
#   pstdev(data)            | POPULATION standard deviation (when you have ALL the data)
#   quantiles(data, n=100)  | the cut points that split data into n equal groups
#   NormalDist(mu, sigma)   | a bell curve: probabilities for z-scores
#
# stdev needs at least 2 values; median and mean need at least 1. Both
# raise StatisticsError otherwise, so handle short histories.

def section_2():
    logins_per_day = [12, 15, 11, 14, 13, 12, 16, 14, 13, 15]
    print("  data:   ", logins_per_day)
    print("  mean:   ", statistics.fmean(logins_per_day))
    print("  median: ", statistics.median(logins_per_day))
    print("  mode:   ", statistics.mode(logins_per_day))
    print("  stdev:  ", round(statistics.stdev(logins_per_day), 2))
    print("  quartiles (25%, 50%, 75%):", statistics.quantiles(logins_per_day, n=4))
    try:
        statistics.stdev([5])
    except statistics.StatisticsError as err:
        print("  stdev([5]):", err)


# ---------------------------------------------------------------
# 3. Mean vs median
# ---------------------------------------------------------------
#
# The mean uses every value's SIZE, so one huge value drags it up.
# The median only cares about ORDER, so it barely moves. Security data
# is full of huge one-off values (a backup job, a scan, an attack), so
# the median is usually the safer summary of "typical".

def section_3():
    mb_uploaded = [20, 22, 19, 25, 21, 23, 20, 24]
    with_spike = mb_uploaded + [4_800]               # one exfiltration day
    print(f"  normal days:  mean {statistics.fmean(mb_uploaded):7.1f} MB, "
          f"median {statistics.median(mb_uploaded):5.1f} MB")
    print(f"  plus 1 spike: mean {statistics.fmean(with_spike):7.1f} MB, "
          f"median {statistics.median(with_spike):5.1f} MB")


# ---------------------------------------------------------------
# 4. Z-scores
# ---------------------------------------------------------------
#
#   z = (value - mean) / stdev
#
# z says how many standard deviations a value is from normal: 0 is
# exactly average, 2 is unusual, 3 or more is very unusual. For data
# shaped like a bell curve, |z| > 3 happens about 0.27% of the time by
# chance (NormalDist tells you exactly).
#
# Two traps:
#   - stdev 0 (every value identical): z is undefined. Treat ANY change
#     as unusual, or use a minimum spread.
#   - most security data is NOT bell-shaped (it's skewed: lots of small
#     values, a few huge ones), so treat the probabilities as rough.

def zscore(value, history):
    mean = statistics.fmean(history)
    spread = statistics.stdev(history)
    if spread == 0:
        return 0.0 if value == mean else math.inf
    return (value - mean) / spread


def section_4():
    history = [12, 15, 11, 14, 13, 12, 16, 14, 13, 15]
    for today in (14, 18, 25):
        print(f"  today {today:>2}: z = {zscore(today, history):5.2f}")
    print(f"  chance of |z| > 3 by luck (bell curve): {2 * (1 - NormalDist().cdf(3)):.2%}")
    print("  all-identical history, today differs: z =", zscore(6, [5, 5, 5, 5]))


# ---------------------------------------------------------------
# 5. Robust z-scores: median and MAD
# ---------------------------------------------------------------
#
# PROBLEM: if the attack already happened during the learning period,
# it's IN the history. It inflates the mean and stdev, so a repeat of
# the same attack no longer looks unusual. This is called MASKING (or
# baseline POISONING when an attacker does it on purpose, by "warming
# up" slowly).
#
# FIX: use statistics the outlier can't drag around.
#   centre: the MEDIAN instead of the mean
#   spread: the MAD (median absolute deviation) instead of stdev
#           MAD = median of |value - median|
#
#   modified z = 0.6745 * (value - median) / MAD
#
# The 0.6745 makes it comparable to an ordinary z-score for bell-shaped
# data. A common cut-off is 3.5 (Iglewicz and Hoaglin).
#
# THE MAD = 0 TRAP: if MORE THAN HALF the history is the same value
# (very common for small counts: "1 login a day, sometimes 2"), the MAD
# is 0 even though the data does vary, and every other value scores as
# infinitely unusual, including perfectly normal ones. The usual fix is
# to fall back to the MEAN absolute deviation (scaled by 1.2533 to
# match) when the MAD is 0. Only if that's 0 too (every value
# identical) is any change truly "infinitely" unusual.

def mad(history):
    centre = statistics.median(history)
    return statistics.median(abs(x - centre) for x in history)


def robust_z(value, history):
    centre = statistics.median(history)
    spread = mad(history)
    if spread:
        return 0.6745 * (value - centre) / spread
    mean_ad = statistics.fmean(abs(x - centre) for x in history)
    if mean_ad:
        return (value - centre) / (1.2533 * mean_ad)
    return 0.0 if value == centre else math.inf


def section_5():
    clean = [20, 22, 19, 25, 21, 23, 20, 24, 22, 21]
    poisoned = clean + [900, 950]                    # two attack days in the history
    today = 920
    print(f"  today {today} MB vs CLEAN history:    z {zscore(today, clean):8.1f}  "
          f"robust z {robust_z(today, clean):8.1f}")
    print(f"  today {today} MB vs POISONED history: z {zscore(today, poisoned):8.1f}  "
          f"robust z {robust_z(today, poisoned):8.1f}")
    print("  the ordinary z-score drops below 3 (missed); the robust one still flags it")


# ---------------------------------------------------------------
# 6. Percentiles
# ---------------------------------------------------------------
#
# For skewed data, "above the 99th percentile of this user's history"
# is often more honest than a z-score. quantiles(data, n=100) returns
# 99 cut points; index 94 is the 95th percentile, 98 the 99th.
#
# The method="inclusive" option treats the data as the whole
# population, so the result never goes beyond the largest value seen.

def percentile(history, p):
    if not 1 <= p <= 99:
        raise ValueError("p must be 1-99")
    return statistics.quantiles(history, n=100, method="inclusive")[p - 1]


def section_6():
    # Session lengths: mostly short, a few long (a "log-normal" shape)
    sessions = [round(random.lognormvariate(3, 0.8), 1) for _ in range(500)]
    print(f"  mean {statistics.fmean(sessions):.1f} min, median {statistics.median(sessions):.1f} min "
          f"(skewed: the mean is pulled up)")
    for p in (50, 95, 99):
        print(f"  p{p}: {percentile(sessions, p):6.1f} min")


# ---------------------------------------------------------------
# 7. Per-entity baselines and cold start
# ---------------------------------------------------------------
#
# Keep a SEPARATE history for each entity (user, host, IP). Compare
# each new value only with that entity's own past.
#
# COLD START: a brand-new user has no history. Don't score them until
# there's enough (here, `min_history` values); fall back to a fixed
# rule or a team-wide baseline instead.

class EntityBaseline:
    def __init__(self, min_history=7, cutoff=3.5, max_history=60):
        self.min_history = min_history
        self.cutoff = cutoff
        self.history = defaultdict(lambda: deque(maxlen=max_history))   # forget very old data

    def check(self, entity, value):
        """Return (status, score). Learns the value unless it's anomalous."""
        past = self.history[entity]
        if len(past) < self.min_history:
            past.append(value)
            return "learning", None
        score = robust_z(value, past)
        if score > self.cutoff:
            return "ANOMALY", score                  # NOT added: don't poison the baseline
        past.append(value)
        return "normal", score


def section_7():
    baseline = EntityBaseline(min_history=5)
    daily_logins = {
        "alice": [12, 14, 13, 15, 12, 14, 13, 41],
        "svc-backup": [300, 310, 295, 305, 298, 302, 301, 309],
        "newhire": [3, 40],
    }
    for user, values in daily_logins.items():
        results = [baseline.check(user, v) for v in values]
        last_status, last_score = results[-1]
        score = "" if last_score is None else f" (robust z {last_score:.1f})"
        print(f"  {user:<10} last day {values[-1]:>3}: {last_status}{score}")


# ---------------------------------------------------------------
# 8. Time-of-day patterns
# ---------------------------------------------------------------
#
# Behaviour depends on the hour. 50 logins at 10:00 is normal; 50 at
# 03:00 is not. Either keep a baseline per (entity, hour), or, simpler,
# learn which HOURS each user is normally active in and flag activity
# in an hour they've rarely or never used.

def active_hours(login_hours, min_share=0.02):
    """Hours that make up at least `min_share` of this user's logins."""
    counts = Counter(login_hours)
    total = sum(counts.values())
    return {h for h, n in counts.items() if n / total >= min_share}


def section_8():
    # 60 days of a 9-to-6 worker, with the odd late evening
    hours = [random.choice(range(9, 18)) for _ in range(600)] + [20, 21, 20]
    normal = active_hours(hours)
    print("  usual hours:", sorted(normal))
    for h in (10, 21, 3):
        print(f"  login at {h:02d}:00 ->", "normal" if h in normal else "UNUSUAL HOUR")


# ---------------------------------------------------------------
# 9. Streaming baselines
# ---------------------------------------------------------------
#
# Storing every value forever isn't possible for millions of entities.
#
# WELFORD'S ALGORITHM updates the mean and variance one value at a
# time, keeping only three numbers (count, mean, M2). It gives the same
# answer as statistics.mean/stdev on the full list, without the list,
# and without the rounding errors of the "sum of squares" shortcut.
#
# An EXPONENTIALLY WEIGHTED MOVING AVERAGE (EWMA) gives recent values
# more weight, so the baseline adapts as behaviour slowly changes:
#   ewma = alpha * value + (1 - alpha) * ewma
# alpha near 1 adapts fast; near 0 remembers longer. (Adapting is
# double-edged: an attacker who ramps up slowly is adapted to as well.)

class RunningStats:
    __slots__ = ("count", "mean", "_m2")

    def __init__(self):
        self.count, self.mean, self._m2 = 0, 0.0, 0.0

    def add(self, value):
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        self._m2 += delta * (value - self.mean)

    @property
    def stdev(self):
        return math.sqrt(self._m2 / (self.count - 1)) if self.count > 1 else 0.0


def ewma(values, alpha=0.3):
    average = None
    for value in values:
        average = value if average is None else alpha * value + (1 - alpha) * average
        yield average


def section_9():
    data = [random.gauss(100, 15) for _ in range(10_000)]
    stats = RunningStats()
    for x in data:
        stats.add(x)
    print(f"  Welford: mean {stats.mean:.4f}, stdev {stats.stdev:.4f}  (3 numbers stored)")
    print(f"  full:    mean {statistics.fmean(data):.4f}, stdev {statistics.stdev(data):.4f}  "
          f"({len(data):,} numbers stored)")
    drift = [10] * 5 + [20] * 5
    print("  EWMA adapting to a change 10 -> 20:", [round(v, 1) for v in ewma(drift)])


# ---------------------------------------------------------------
# 10. Rarity
# ---------------------------------------------------------------
#
# Not everything is a number. For CATEGORIES (user agent, country,
# process name, destination port), ask "how often have we seen this
# value before?"
#
#   first-seen    never seen for this entity before
#   rare          seen in less than `max_share` of past events
#
# The classic: a server that only ever runs nginx and python3 suddenly
# runs "nc" (netcat). Rare-process detection catches that.

def rare_values(history, candidates, max_share=0.01):
    counts = Counter(history)
    total = len(history)
    return {value: counts[value] for value in candidates if counts[value] / total < max_share}


def section_10():
    processes = ["nginx"] * 9_000 + ["python3"] * 950 + ["logrotate"] * 49 + ["bash"]
    today = ["nginx", "python3", "logrotate", "bash", "nc", "curl"]
    print("  rare or new processes today (seen this many times before):",
          rare_values(processes, today))


# ---------------------------------------------------------------
# 11. The base rate problem
# ---------------------------------------------------------------
#
# Suppose a detector catches 99% of real attacks, and wrongly flags
# only 1% of normal events. Sounds great. But if 1 in 100,000 events is
# really malicious, then for 1,000,000 events a day:
#
#   real attacks:        10       -> caught: 9.9
#   normal events:  999,990       -> false alarms: 9,999.9
#
# Only about 0.1% of alerts are real (this is the PRECISION). Analysts
# drown, and real alerts get ignored ("alert fatigue"). The rarer the
# thing you hunt, the lower the false-alarm rate you need. That's why
# baselines are usually COMBINED with other signals (new IP AND unusual
# hour AND large upload) before anyone gets paged.

def precision(events, attack_rate, detection_rate, false_positive_rate):
    attacks = events * attack_rate
    normal = events - attacks
    true_alerts = attacks * detection_rate
    false_alerts = normal * false_positive_rate
    return true_alerts / (true_alerts + false_alerts), true_alerts + false_alerts


def section_11():
    for fp in (0.01, 0.001, 0.0001, 0.00001):
        p, alerts = precision(1_000_000, 1 / 100_000, 0.99, fp)
        print(f"  false-alarm rate {fp:>8.3%}: {alerts:>9,.0f} alerts/day, {p:6.1%} of them real")


# ---------------------------------------------------------------
# 12. Practice: unusual upload volumes
# ---------------------------------------------------------------
#
# Given each user's MB uploaded per day, return the (user, day, MB,
# score) of every day that's anomalous FOR THAT USER, using
# EntityBaseline (robust z > 3.5, at least 7 days of history).
# Write it yourself first, then compare.

def unusual_uploads(daily_mb, min_history=7, cutoff=3.5):
    baseline = EntityBaseline(min_history=min_history, cutoff=cutoff)
    findings = []
    for user, days in daily_mb.items():
        for day, mb in enumerate(days, start=1):
            status, score = baseline.check(user, mb)
            if status == "ANOMALY":
                findings.append((user, day, mb, round(score, 1)))
    return findings


def run_tests():
    # Basics and edge cases
    assert statistics.median([1, 100, 2]) == 2
    assert zscore(10, [10, 10, 10]) == 0.0 and zscore(11, [10, 10, 10]) == math.inf
    assert robust_z(5, [5, 5, 5]) == 0.0 and robust_z(6, [5, 5, 5]) == math.inf
    assert mad([1, 2, 3, 4, 100]) == 1

    # The MAD = 0 trap: mostly-identical history, but it does vary
    mostly_ones = [1, 2, 1, 1, 2, 1, 2, 1, 1, 1]
    assert mad(mostly_ones) == 0
    assert robust_z(2, mostly_ones) < 3.5                          # normal, not infinite
    assert robust_z(60, mostly_ones) > 3.5

    # Masking: the robust score survives a poisoned history; the plain one doesn't
    clean = [20, 22, 19, 25, 21, 23, 20, 24, 22, 21]
    poisoned = clean + [900, 950]
    assert zscore(920, clean) > 3 and robust_z(920, clean) > 3.5
    assert zscore(920, poisoned) < 3 and robust_z(920, poisoned) > 3.5

    # Percentiles
    data = list(range(1, 101))
    assert percentile(data, 50) == 50.5 and percentile(data, 99) <= 100

    # Baseline: learning, normal, anomaly, and anomalies aren't learned
    b = EntityBaseline(min_history=3)
    assert [b.check("u", v)[0] for v in (10, 11, 9)] == ["learning"] * 3
    assert b.check("u", 10)[0] == "normal"
    assert b.check("u", 500)[0] == "ANOMALY"
    assert 500 not in b.history["u"]
    assert b.check("u", 500)[0] == "ANOMALY"                       # still flagged next time
    assert b.check("other", 500)[0] == "learning"                  # separate history

    # Active hours
    assert active_hours([9] * 50 + [10] * 49 + [3]) == {9, 10}

    # Welford matches the statistics module
    values = [random.uniform(-1000, 1000) for _ in range(5_000)]
    rs = RunningStats()
    for v in values:
        rs.add(v)
    assert math.isclose(rs.mean, statistics.fmean(values), rel_tol=1e-9)
    assert math.isclose(rs.stdev, statistics.stdev(values), rel_tol=1e-9)
    assert RunningStats().stdev == 0.0

    # EWMA
    assert list(ewma([10, 10, 10])) == [10, 10, 10]
    assert list(ewma([0, 10], alpha=0.5)) == [0, 5]

    # Rarity
    assert rare_values(["a"] * 99 + ["b"], ["a", "b", "c"], max_share=0.05) == {"b": 1, "c": 0}

    # Base rates: lower false-alarm rates mean more of the alerts are real
    p1, _ = precision(1_000_000, 1e-5, 0.99, 0.01)
    p2, _ = precision(1_000_000, 1e-5, 0.99, 0.00001)
    assert p1 < 0.01 < 0.4 < p2

    # Practice
    uploads = {
        "alice": [20, 22, 19, 25, 21, 23, 20, 24, 22, 900, 21],
        "svc-backup": [5000, 5200, 4900, 5100, 5050, 4980, 5120, 5070, 5010, 5090],
        "bob": [1, 2, 1, 1, 2, 1, 2, 1, 1, 1, 60, 2],
        "newhire": [0, 300],
    }
    found = unusual_uploads(uploads)
    assert [(user, day, mb) for user, day, mb, _ in found] == [("alice", 10, 900), ("bob", 11, 60)]
    assert all(score > 3.5 for *_, score in found)

    print("All tests passed!")


if __name__ == "__main__":
    for number, section in enumerate([section_1, section_2, section_3, section_4, section_5,
                                      section_6, section_7, section_8, section_9, section_10,
                                      section_11], start=1):
        print(f"\n--- {number}. {section.__name__} ---")
        section()

    print("\n--- 12. Practice: unusual uploads ---")
    uploads = {
        "alice": [20, 22, 19, 25, 21, 23, 20, 24, 22, 900, 21],
        "svc-backup": [5000, 5200, 4900, 5100, 5050, 4980, 5120, 5070, 5010, 5090],
        "bob": [1, 2, 1, 1, 2, 1, 2, 1, 1, 1, 60, 2],
    }
    for user, day, mb, score in unusual_uploads(uploads):
        print(f"  {user} on day {day}: {mb} MB (robust z {score})")
    print("  svc-backup uploads 5 GB a day, which is normal FOR IT, so it isn't flagged.")

    print()
    run_tests()
