# Binary Search (LeetCode 704) and its lower/upper bound forms
# (includes LeetCode 35 Search Insert Position, and
#  LeetCode 34 Find First and Last Position)
#
# PROBLEM
# -------
# Given a SORTED list of numbers and a target, return the target's
# index, or -1 if it isn't there.
#
#   nums = [-1, 0, 3, 5, 9, 12], target = 9  ->  4
#   nums = [-1, 0, 3, 5, 9, 12], target = 2  ->  -1
#
# Must run in O(log n).
#
# KEY IDEAS
# ---------
#   - Look at the MIDDLE item. Because the list is sorted:
#       middle == target  -> found it
#       middle <  target  -> the target can only be in the RIGHT half
#       middle >  target  -> the target can only be in the LEFT half
#     Each step throws away half of what's left.
#   - Halving is why it's fast: 1,000,000 items need at most 20 looks
#     (2^20 is about a million). A linear scan might need 1,000,000.
#   - The hard part is the edges, not the idea. Pick ONE template,
#     know exactly what lo and hi mean, and stick to it:
#
#       TEMPLATE A (find an exact match)
#         lo, hi = 0, len - 1        search the CLOSED range [lo, hi]
#         while lo <= hi             stop when the range is empty
#         lo = mid + 1 / hi = mid - 1
#
#       TEMPLATE B (find a boundary, "the first position where ...")
#         lo, hi = 0, len            search the HALF-OPEN range [lo, hi)
#         while lo < hi              stop when lo == hi: that's the answer
#         lo = mid + 1 / hi = mid    (hi = mid, NOT mid - 1)
#
# WHAT'S NEW HERE
# ---------------
# The membership test `x in list` from data_structures/lists.py is a
# linear scan, O(n). Sorting once (sorting_algorithms.py) and then
# binary searching makes every later lookup O(log n). Python's bisect
# module provides template B ready-made.
#
# SECURITY CONNECTION
# -------------------
# Threat-intel feeds and GeoIP databases list IP RANGES: millions of
# (start, end, label) rows sorted by start. Finding the range an IP
# falls in is a binary search on the starts, using the "IP as a
# number" idea from number_bases.py (variation 3).


import bisect
import ipaddress


# ---------------------------------------------------------------
# Solution 1: linear scan (the baseline)
# ---------------------------------------------------------------

def search_linear(nums, target):
    for i, num in enumerate(nums):
        if num == target:
            return i
    return -1


# ---------------------------------------------------------------
# Solution 2: iterative binary search (template A)
# ---------------------------------------------------------------
#
# Trace for nums = [-1, 0, 3, 5, 9, 12], target = 9:
#
#   lo | hi | mid | nums[mid] | action
#   ---|----|-----|-----------|---------------------------
#    0 |  5 |  2  |     3     | 3 < 9   -> lo = 3
#    3 |  5 |  4  |     9     | found   -> return 4
#
# Trace for target = 2:
#
#    0 |  5 |  2  |     3     | 3 > 2   -> hi = 1
#    0 |  1 |  0  |    -1     | -1 < 2  -> lo = 1
#    1 |  1 |  1  |     0     | 0 < 2   -> lo = 2
#    lo (2) > hi (1): the range is empty -> return -1
#
# mid = lo + (hi - lo) // 2 gives the same result as (lo + hi) // 2.
# In Python both are fine, but in languages with fixed-size integers
# (C, Java) lo + hi can OVERFLOW, which was a real bug in Java's
# library for years. The first form is the habit worth having.

def search(nums, target):
    lo, hi = 0, len(nums) - 1
    while lo <= hi:
        mid = lo + (hi - lo) // 2
        if nums[mid] == target:
            return mid
        if nums[mid] < target:
            lo = mid + 1                      # target is to the right
        else:
            hi = mid - 1                      # target is to the left
    return -1


# ---------------------------------------------------------------
# Solution 3: recursive binary search
# ---------------------------------------------------------------
#
# The same thing, written as "search the left half or the right half".
# It uses O(log n) stack space, so the loop version is usually better.

def search_recursive(nums, target, lo=0, hi=None):
    if hi is None:
        hi = len(nums) - 1
    if lo > hi:
        return -1
    mid = lo + (hi - lo) // 2
    if nums[mid] == target:
        return mid
    if nums[mid] < target:
        return search_recursive(nums, target, mid + 1, hi)
    return search_recursive(nums, target, lo, mid - 1)


# ---------------------------------------------------------------
# Variation 1: Search Insert Position (LeetCode 35)  -  template B
# ---------------------------------------------------------------
#
# Return the index of target if present, otherwise the index where it
# WOULD go to keep the list sorted.
#
#   [1, 3, 5, 6], 5 -> 2      [1, 3, 5, 6], 2 -> 1      [1, 3, 5, 6], 7 -> 4
#
# This is the LOWER BOUND: the first index whose value is >= target.
# hi starts at len(nums), because the answer can be "after the end".
#
# Trace for [1, 3, 5, 6], target = 2:
#
#   lo | hi | mid | nums[mid] | nums[mid] < 2? | action
#   ---|----|-----|-----------|----------------|---------
#    0 |  4 |  2  |     5     |      no        | hi = 2
#    0 |  2 |  1  |     3     |      no        | hi = 1
#    0 |  1 |  0  |     1     |      yes       | lo = 1
#   lo == hi == 1 -> answer 1

def lower_bound(nums, target):
    lo, hi = 0, len(nums)
    while lo < hi:
        mid = lo + (hi - lo) // 2
        if nums[mid] < target:
            lo = mid + 1
        else:
            hi = mid                          # mid might BE the answer, so keep it
    return lo


# UPPER BOUND: the first index whose value is > target.
# Only one character differs from lower_bound: <= instead of <.

def upper_bound(nums, target):
    lo, hi = 0, len(nums)
    while lo < hi:
        mid = lo + (hi - lo) // 2
        if nums[mid] <= target:
            lo = mid + 1
        else:
            hi = mid
    return lo


# Python's bisect module has both:
#   bisect.bisect_left(nums, x)   == lower_bound(nums, x)
#   bisect.bisect_right(nums, x)  == upper_bound(nums, x)
#   bisect.insort(nums, x)        inserts x in sorted position


# ---------------------------------------------------------------
# Variation 2: Find First and Last Position (LeetCode 34)
# ---------------------------------------------------------------
#
#   [5, 7, 7, 8, 8, 10], 8  ->  [3, 4]
#   [5, 7, 7, 8, 8, 10], 6  ->  [-1, -1]
#
# first = lower_bound(target), last = upper_bound(target) - 1.
# Template A would find SOME 8, but not necessarily the first one.
# The count of a value is upper_bound - lower_bound, in O(log n).

def search_range(nums, target):
    first = lower_bound(nums, target)
    if first == len(nums) or nums[first] != target:
        return [-1, -1]
    return [first, upper_bound(nums, target) - 1]


def count_in_sorted(nums, target):
    return upper_bound(nums, target) - lower_bound(nums, target)


# ---------------------------------------------------------------
# Variation 3: which IP range is this address in?
# ---------------------------------------------------------------
#
# The ranges are sorted by start and don't overlap. Find the LAST
# range whose start is <= the IP: that's upper_bound(starts, ip) - 1.
# Then check the IP isn't past that range's end (it could be in a gap).
#
#   ranges:  [10.0.0.0 - 10.255.255.255], [192.168.0.0 - 192.168.255.255]
#   192.168.4.2 -> upper_bound gives 2, so look at range 1 -> inside
#   11.0.0.1    -> range 0 ends at 10.255.255.255 -> in a gap -> None

class IPRangeTable:
    def __init__(self, rows):
        """rows: (first_ip, last_ip, label) as strings."""
        parsed = sorted((int(ipaddress.IPv4Address(a)), int(ipaddress.IPv4Address(b)), label)
                        for a, b, label in rows)
        for (_, prev_end, _), (start, _, _) in zip(parsed, parsed[1:]):
            if start <= prev_end:
                raise ValueError("ranges overlap")
        self.starts = [start for start, _, _ in parsed]
        self.rows = parsed

    def lookup(self, ip):
        value = int(ipaddress.IPv4Address(ip))
        i = bisect.bisect_right(self.starts, value) - 1
        if i >= 0 and value <= self.rows[i][1]:
            return self.rows[i][2]
        return None


# ---------------------------------------------------------------
# COMPLEXITY (n = length of nums)
# ---------------------------------------------------------------
#
#   Solution                    | Time      | Extra space
#   ----------------------------|-----------|------------------
#   1. Linear scan              | O(n)      | O(1)
#   2. Iterative binary search  | O(log n)  | O(1)
#   3. Recursive binary search  | O(log n)  | O(log n) call stack
#   lower/upper bound, bisect   | O(log n)  | O(1)
#   Search range, count         | O(log n)  | O(1)
#   IP range lookup             | O(log n)  | O(n) for the table
#
# Binary search needs the data SORTED. Sorting costs O(n log n) once,
# so it pays off when you search many times. For a single lookup, a
# linear scan is cheaper. For many lookups of exact values, a set
# (O(1) each) beats both; binary search wins when you need ranges,
# "closest", or "first after".


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    import random

    nums = [-1, 0, 3, 5, 9, 12]
    for solve in [search_linear, search, search_recursive]:
        assert solve(nums, 9) == 4                    # LeetCode example 1
        assert solve(nums, 2) == -1                   # LeetCode example 2
        assert solve(nums, -1) == 0                   # first
        assert solve(nums, 12) == 5                   # last
        assert solve(nums, 13) == -1                  # past the end
        assert solve(nums, -5) == -1                  # before the start
        assert solve([], 1) == -1
        assert solve([7], 7) == 0

    # Bounds agree with bisect on random sorted lists with duplicates
    random.seed(7)
    for _ in range(300):
        data = sorted(random.randint(0, 20) for _ in range(random.randint(0, 25)))
        for target in range(-1, 22):
            assert lower_bound(data, target) == bisect.bisect_left(data, target)
            assert upper_bound(data, target) == bisect.bisect_right(data, target)
            assert count_in_sorted(data, target) == data.count(target)
            if target in data:
                assert data[search(data, target)] == target

    # LeetCode 35
    assert lower_bound([1, 3, 5, 6], 5) == 2
    assert lower_bound([1, 3, 5, 6], 2) == 1
    assert lower_bound([1, 3, 5, 6], 7) == 4
    assert lower_bound([1, 3, 5, 6], 0) == 0

    # LeetCode 34
    assert search_range([5, 7, 7, 8, 8, 10], 8) == [3, 4]
    assert search_range([5, 7, 7, 8, 8, 10], 6) == [-1, -1]
    assert search_range([], 0) == [-1, -1]
    assert search_range([2, 2, 2], 2) == [0, 2]

    # IP ranges
    table = IPRangeTable([
        ("192.168.0.0", "192.168.255.255", "private (192.168/16)"),
        ("10.0.0.0", "10.255.255.255", "private (10/8)"),
        ("203.0.113.0", "203.0.113.255", "known bad: botnet C2"),
    ])
    assert table.lookup("10.1.2.3") == "private (10/8)"
    assert table.lookup("192.168.4.2") == "private (192.168/16)"
    assert table.lookup("203.0.113.9") == "known bad: botnet C2"
    assert table.lookup("11.0.0.1") is None            # in a gap
    assert table.lookup("1.1.1.1") is None             # before every range
    assert table.lookup("255.255.255.255") is None     # after every range
    assert table.lookup("10.0.0.0") == "private (10/8)"         # exact start
    assert table.lookup("10.255.255.255") == "private (10/8)"   # exact end
    try:
        IPRangeTable([("10.0.0.0", "10.0.0.10", "a"), ("10.0.0.5", "10.0.0.20", "b")])
        assert False, "expected ValueError"
    except ValueError:
        pass

    print("All tests passed!")


if __name__ == "__main__":
    import math
    import time
    import random

    nums = [-1, 0, 3, 5, 9, 12]
    print(f"nums = {nums}")
    print(f"  search(9) = {search(nums, 9)}, search(2) = {search(nums, 2)}")
    print(f"  insert position for 4: {lower_bound(nums, 4)}")

    dupes = [5, 7, 7, 8, 8, 8, 10]
    print(f"\n{dupes}: 8 runs from {search_range(dupes, 8)}, count {count_in_sorted(dupes, 8)}")

    print("\nMost looks binary search can need:")
    for n in (10, 1_000, 1_000_000, 1_000_000_000):
        print(f"  {n:>13,} items -> {math.floor(math.log2(n)) + 1} looks")

    # A big blocklist of IP ranges
    random.seed(1)
    starts = sorted(random.sample(range(0, 2**32 - 300), 100_000))
    rows = [(str(ipaddress.IPv4Address(s)), str(ipaddress.IPv4Address(s + 255)), f"range {i}")
            for i, s in enumerate(starts)]
    # Drop any rows that would overlap, so the table is valid
    clean = [rows[0]]
    for row in rows[1:]:
        if int(ipaddress.IPv4Address(row[0])) > int(ipaddress.IPv4Address(clean[-1][1])):
            clean.append(row)
    table = IPRangeTable(clean)
    probe = [str(ipaddress.IPv4Address(random.randrange(2**32))) for _ in range(2_000)]

    start = time.perf_counter()
    hits = sum(table.lookup(ip) is not None for ip in probe)
    fast = time.perf_counter() - start

    def linear_lookup(ip):
        value = int(ipaddress.IPv4Address(ip))
        for s, e, label in table.rows:
            if s <= value <= e:
                return label
        return None

    start = time.perf_counter()
    for ip in probe[:20]:
        linear_lookup(ip)
    slow = (time.perf_counter() - start) / 20 * len(probe)

    print(f"\nLooking up {len(probe):,} IPs in {len(clean):,} blocklist ranges "
          f"({hits} matched):")
    print(f"  binary search: {fast:.4f} s")
    print(f"  linear scan:   about {slow:.1f} s (estimated from 20 lookups)")

    print()
    run_tests()
