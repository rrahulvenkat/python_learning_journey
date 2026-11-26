# Merge Intervals (LeetCode 56)
#
# PROBLEM
# -------
# Given a list of intervals [start, end], merge all the ones that
# overlap and return the result.
#
#   [[1, 3], [2, 6], [8, 10], [15, 18]]  ->  [[1, 6], [8, 10], [15, 18]]
#   [[1, 4], [4, 5]]                     ->  [[1, 5]]   touching counts
#
# KEY IDEAS
# ---------
#   - Two intervals overlap when each one starts before the other ends:
#         a_start <= b_end  and  b_start <= a_end
#   - SORT BY START first. Then an interval can only overlap the one
#     you merged most recently, so a single pass is enough:
#       * if it starts before (or when) the last merged one ends,
#         extend the last one:  last_end = max(last_end, end)
#       * otherwise, it starts a new merged interval
#   - max() matters: [1, 10] followed by [2, 3] must stay [1, 10],
#     not shrink to [1, 3].
#
# WHAT'S NEW HERE
# ---------------
# "Sort first, then one pass" is one of the most useful patterns
# there is. Sorting costs O(n log n), but it puts related items next
# to each other so the rest of the work is a simple O(n) scan (the
# same idea as contains_duplicate_sort() in contains_duplicate.py).
#
# SECURITY CONNECTION
# -------------------
#   - Several sensors raise alerts for the same attack, each with its
#     own start and end time. Merging the overlapping windows turns
#     dozens of alerts into a few INCIDENTS.
#   - "How long were we under attack?" is the total length of the
#     merged intervals (total_covered).
#   - "When was the suspicious IP active during the maintenance
#     window?" is an interval INTERSECTION (variation 2).


# ---------------------------------------------------------------
# Solution 1: compare every pair until nothing changes (slow)
# ---------------------------------------------------------------
#
# Keep merging any two overlapping intervals until no pair overlaps.
# Correct, but each round is O(n^2) and there can be n rounds.
# Shown so the sorted version's speed-up is clear.

def overlaps(a, b):
    return a[0] <= b[1] and b[0] <= a[1]


def merge_brute_force(intervals):
    result = [list(iv) for iv in intervals]
    changed = True
    while changed:
        changed = False
        for i in range(len(result)):
            for j in range(i + 1, len(result)):
                if overlaps(result[i], result[j]):
                    result[i] = [min(result[i][0], result[j][0]),
                                 max(result[i][1], result[j][1])]
                    del result[j]
                    changed = True
                    break
            if changed:
                break
    return sorted(result)


# ---------------------------------------------------------------
# Solution 2: sort by start, then one pass (the optimal answer)
# ---------------------------------------------------------------
#
# Trace for [[8, 10], [1, 3], [15, 18], [2, 6]]:
#
#   sorted: [1, 3], [2, 6], [8, 10], [15, 18]
#
#   interval | last merged | overlaps? | merged list
#   ---------|-------------|-----------|------------------------------
#   [1, 3]   |  -          |  -        | [[1, 3]]
#   [2, 6]   | [1, 3]      | 2 <= 3 yes| [[1, 6]]
#   [8, 10]  | [1, 6]      | 8 <= 6 no | [[1, 6], [8, 10]]
#   [15, 18] | [8, 10]     | no        | [[1, 6], [8, 10], [15, 18]]

def merge_intervals(intervals):
    merged = []
    for start, end in sorted(intervals, key=lambda iv: iv[0]):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)       # extend the last one
        else:
            merged.append([start, end])                   # start a new one
    return merged


# ---------------------------------------------------------------
# Variation 1: Insert Interval (LeetCode 57)
# ---------------------------------------------------------------
#
# The list is ALREADY sorted and non-overlapping. Insert one new
# interval, merging where needed, in O(n) without sorting again.
#
#   [[1, 2], [3, 5], [6, 7], [8, 10], [12, 16]], new [4, 8]
#   -> [[1, 2], [3, 10], [12, 16]]
#
# Three phases:
#   1. copy intervals that end BEFORE the new one starts
#   2. merge every interval that overlaps the new one into it
#   3. copy the rest

def insert_interval(intervals, new):
    result = []
    start, end = new
    i = 0
    n = len(intervals)

    while i < n and intervals[i][1] < start:              # 1. entirely before
        result.append(list(intervals[i]))
        i += 1

    while i < n and intervals[i][0] <= end:               # 2. overlapping
        start = min(start, intervals[i][0])
        end = max(end, intervals[i][1])
        i += 1
    result.append([start, end])

    while i < n:                                          # 3. entirely after
        result.append(list(intervals[i]))
        i += 1

    return result


# ---------------------------------------------------------------
# Variation 2: Interval List Intersections (LeetCode 986)
# ---------------------------------------------------------------
#
# Two lists, each sorted and non-overlapping. Return where they
# overlap.
#
#   a = [[0, 2], [5, 10], [13, 23], [24, 25]]
#   b = [[1, 5], [8, 12], [15, 24], [25, 26]]
#   -> [[1, 2], [5, 5], [8, 10], [15, 23], [24, 24], [25, 25]]
#
# Two pointers, one per list. The overlap of two intervals is
#   [max(starts), min(ends)]   if that's a real interval.
# Then move past whichever interval ENDS first: it can't overlap
# anything else in the other list.

def interval_intersection(a, b):
    result = []
    i = j = 0
    while i < len(a) and j < len(b):
        low = max(a[i][0], b[j][0])
        high = min(a[i][1], b[j][1])
        if low <= high:
            result.append([low, high])
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return result


# ---------------------------------------------------------------
# Variation 3: total time covered
# ---------------------------------------------------------------
#
# Merge first, so overlapping time isn't counted twice, then add up
# the lengths.
#   [[1, 4], [2, 6], [10, 12]] -> merged [[1, 6], [10, 12]] -> 5 + 2 = 7

def total_covered(intervals):
    return sum(end - start for start, end in merge_intervals(intervals))


# ---------------------------------------------------------------
# COMPLEXITY (n = number of intervals)
# ---------------------------------------------------------------
#
#   Solution                   | Time        | Extra space
#   ---------------------------|-------------|-------------------
#   1. Brute force             | O(n^3)      | O(n)
#   2. Sort + one pass         | O(n log n)  | O(n) output
#   Insert Interval            | O(n)        | O(n) output
#   Intersections (a, b)       | O(a + b)    | O(a + b) output
#   Total covered              | O(n log n)  | O(n)
#
# In solution 2, the sort is the expensive part. The merging pass
# itself is only O(n).


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    import random

    test_cases = [
        # (intervals, expected)
        ([[1, 3], [2, 6], [8, 10], [15, 18]], [[1, 6], [8, 10], [15, 18]]),   # LeetCode 1
        ([[1, 4], [4, 5]], [[1, 5]]),                                         # LeetCode 2
        ([[4, 7], [1, 4]], [[1, 7]]),                                         # unsorted input
        ([[1, 10], [2, 3]], [[1, 10]]),                                       # inside another
        ([], []),
        ([[5, 5]], [[5, 5]]),                                                 # zero length
        ([[1, 2], [3, 4]], [[1, 2], [3, 4]]),                                 # gap of 1
        ([[2, 3], [4, 5], [6, 7], [1, 10]], [[1, 10]]),                       # one covers all
    ]

    for solve in [merge_brute_force, merge_intervals]:
        for intervals, expected in test_cases:
            result = solve(intervals)
            assert result == expected, (
                f"{solve.__name__}({intervals}) returned {result}, expected {expected}"
            )

    # The two solutions agree on random input
    random.seed(5)
    for _ in range(200):
        ivs = []
        for _ in range(random.randint(0, 12)):
            s = random.randint(0, 50)
            ivs.append([s, s + random.randint(0, 8)])
        assert merge_brute_force(ivs) == merge_intervals(ivs), ivs

    # Insert Interval (LeetCode 57 examples)
    assert insert_interval([[1, 3], [6, 9]], [2, 5]) == [[1, 5], [6, 9]]
    assert insert_interval([[1, 2], [3, 5], [6, 7], [8, 10], [12, 16]], [4, 8]) == \
        [[1, 2], [3, 10], [12, 16]]
    assert insert_interval([], [5, 7]) == [[5, 7]]
    assert insert_interval([[1, 5]], [6, 8]) == [[1, 5], [6, 8]]     # after everything
    assert insert_interval([[3, 5]], [1, 2]) == [[1, 2], [3, 5]]     # before everything

    # Intersections (LeetCode 986 example)
    a = [[0, 2], [5, 10], [13, 23], [24, 25]]
    b = [[1, 5], [8, 12], [15, 24], [25, 26]]
    assert interval_intersection(a, b) == [[1, 2], [5, 5], [8, 10], [15, 23], [24, 24], [25, 25]]
    assert interval_intersection([[1, 3]], []) == []
    assert interval_intersection([[1, 2]], [[3, 4]]) == []

    # Total covered
    assert total_covered([[1, 4], [2, 6], [10, 12]]) == 7
    assert total_covered([]) == 0

    print("All tests passed!")


if __name__ == "__main__":
    import time
    import random

    def hhmm(minutes):
        return f"{minutes // 60:02d}:{minutes % 60:02d}"

    # Alerts from different sensors, as (start, end) in minutes after midnight
    alerts = {
        "IDS: port scan":         [130, 145],
        "WAF: SQL injection":     [140, 170],
        "EDR: suspicious process":[165, 200],
        "Firewall: outbound spike":[480, 495],
        "IDS: brute force SSH":   [490, 520],
        "DLP: large upload":      [900, 910],
    }
    print("Alerts:")
    for name, (s, e) in alerts.items():
        print(f"  {hhmm(s)}-{hhmm(e)}  {name}")

    incidents = merge_intervals(list(alerts.values()))
    print(f"\n{len(alerts)} alerts merge into {len(incidents)} incidents:")
    for s, e in incidents:
        print(f"  {hhmm(s)}-{hhmm(e)}  ({e - s} minutes)")
    print(f"Total time under attack: {total_covered(list(alerts.values()))} minutes")

    maintenance = [[120, 180], [470, 500]]
    attacker_active = [[100, 150], [175, 190], [495, 600]]
    print("\nAttacker activity during maintenance windows:")
    for s, e in interval_intersection(maintenance, attacker_active):
        print(f"  {hhmm(s)}-{hhmm(e)}")

    # Speed comparison
    random.seed(0)
    big = []
    for _ in range(600):
        s = random.randint(0, 100_000)
        big.append([s, s + random.randint(0, 50)])
    print(f"\nSpeed test with {len(big):,} intervals:")
    for solve in [merge_brute_force, merge_intervals]:
        start = time.perf_counter()
        solve(big)
        print(f"  {solve.__name__:<18} {time.perf_counter() - start:.4f} s")

    print()
    run_tests()
