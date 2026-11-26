# Meeting Rooms I and II (LeetCode 252 and 253)  -  heaps and sweep lines
#
# PROBLEM
# -------
# Each meeting is [start, end]. A meeting ending at 10 and another
# starting at 10 do NOT clash.
#
#   I.  Can one person attend every meeting (do any overlap)?
#         [[0, 30], [5, 10], [15, 20]]  ->  False
#         [[7, 10], [2, 4]]             ->  True
#
#   II. What is the smallest number of rooms needed to hold them all?
#         [[0, 30], [5, 10], [15, 20]]  ->  2
#
# KEY IDEAS
# ---------
#   - Part I: sort by start. If any meeting starts before the previous
#     one ends, there's a clash. (Sort first, then one pass, as in
#     merge_intervals.py.)
#   - Part II: the answer is the largest number of meetings happening
#     AT THE SAME TIME. Two ways to find it:
#       * HEAP: go through meetings by start time, keeping the end
#         times of meetings in progress in a min-heap. Before adding a
#         meeting, free any room whose meeting has already ended. The
#         heap's size is the rooms in use.
#       * SWEEP LINE: turn every meeting into two EVENTS, +1 at its
#         start and -1 at its end. Sort the events and walk through
#         them, keeping a running total. The highest total is the
#         answer.
#
# WHAT'S NEW HERE
# ---------------
#   - The HEAP (heapq module): always gives you its SMALLEST item in
#     O(log n). Here, "which room frees up first?"
#   - The SWEEP LINE: replace intervals with start/end events and scan
#     them in time order. It turns many interval problems into a
#     simple running count.
#   - GREEDY choices (variation 2): make the locally best choice at
#     each step and prove it's also best overall.
#
# SECURITY CONNECTION
# -------------------
# Replace "meetings" with "login sessions". If one account has 6
# sessions open AT THE SAME TIME from different IP addresses, the
# password has probably been shared or stolen. The maximum number of
# concurrent sessions is exactly the Meeting Rooms II answer
# (variation 1). The same counting detects too many simultaneous
# connections from one source.


import heapq


# ---------------------------------------------------------------
# Part I: can attend all meetings?
# ---------------------------------------------------------------

def can_attend_all(meetings):
    ordered = sorted(meetings, key=lambda m: m[0])
    for i in range(1, len(ordered)):
        if ordered[i][0] < ordered[i - 1][1]:     # starts before the previous ends
            return False
    return True


# ---------------------------------------------------------------
# Part II, solution 1: brute force (check every moment)
# ---------------------------------------------------------------
#
# The busiest moment is always at some meeting's START. So for each
# start time, count the meetings running then. O(n^2).

def min_rooms_brute_force(meetings):
    best = 0
    for start, _ in meetings:
        running = sum(1 for s, e in meetings if s <= start < e)
        best = max(best, running)
    return best


# ---------------------------------------------------------------
# Part II, solution 2: min-heap of end times
# ---------------------------------------------------------------
#
#   heapq.heappush(heap, x)   add x                 O(log n)
#   heapq.heappop(heap)       remove the smallest   O(log n)
#   heap[0]                   look at the smallest  O(1)
#
# Trace for [[0, 30], [5, 10], [15, 20]] (sorted by start):
#
#   meeting  | earliest end in heap | free a room? | heap after    | rooms
#   ---------|----------------------|--------------|---------------|------
#   [0, 30]  |  -                   |  -           | [30]          |  1
#   [5, 10]  | 30                   | 30 > 5, no   | [10, 30]      |  2
#   [15, 20] | 10                   | 10 <= 15 yes | [20, 30]      |  2
#
# The largest heap size seen is the answer.

def min_rooms_heap(meetings):
    ends = []                                     # end times of meetings in progress
    best = 0
    for start, end in sorted(meetings, key=lambda m: m[0]):
        while ends and ends[0] <= start:          # those rooms are free again
            heapq.heappop(ends)
        heapq.heappush(ends, end)
        best = max(best, len(ends))
    return best


# ---------------------------------------------------------------
# Part II, solution 3: sweep line
# ---------------------------------------------------------------
#
# Events for [[0, 30], [5, 10], [15, 20]]:
#   (0, +1) (5, +1) (10, -1) (15, +1) (20, -1) (30, -1)
#
#   time | change | running total
#   -----|--------|--------------
#    0   |  +1    |  1
#    5   |  +1    |  2   <- highest
#   10   |  -1    |  1
#   15   |  +1    |  2
#   20   |  -1    |  1
#   30   |  -1    |  0
#
# TIES: a meeting ending at 10 and one starting at 10 don't clash, so
# at the same time the END (-1) must come first. Sorting the tuples
# (time, change) does that automatically, because -1 < +1.

def min_rooms_sweep(meetings):
    events = []
    for start, end in meetings:
        events.append((start, 1))
        events.append((end, -1))
    events.sort()

    running = best = 0
    for _, change in events:
        running += change
        best = max(best, running)
    return best


# ---------------------------------------------------------------
# Variation 1: peak concurrent sessions, and WHEN it happens
# ---------------------------------------------------------------
#
# Each session is (start, end, ip). Return the peak count, the time
# it started, and which IPs were active then. A real detector would
# alert when the peak is above a limit.

def peak_concurrent_sessions(sessions):
    events = []
    for start, end, ip in sessions:
        events.append((start, 1, ip))
        events.append((end, -1, ip))
    events.sort(key=lambda e: (e[0], e[1]))       # ends before starts at a tie

    active = {}                                   # ip -> sessions open from it
    running = best = 0
    best_time = None
    best_ips = set()
    for time, change, ip in events:
        running += change
        active[ip] = active.get(ip, 0) + change
        if active[ip] == 0:
            del active[ip]
        if running > best:
            best, best_time, best_ips = running, time, set(active)
    return best, best_time, best_ips


# ---------------------------------------------------------------
# Variation 2: Non-overlapping Intervals (LeetCode 435)  -  greedy
# ---------------------------------------------------------------
#
# What is the FEWEST intervals to remove so the rest don't overlap?
#   [[1, 2], [2, 3], [3, 4], [1, 3]]  ->  1   (remove [1, 3])
#
# Greedy rule: sort by END time, and always keep the interval that
# ends EARLIEST. Ending early leaves the most room for the rest, so
# this choice is never worse than any other. Everything that clashes
# with a kept interval is removed.

def min_removals(intervals):
    removed = 0
    last_end = float("-inf")
    for start, end in sorted(intervals, key=lambda iv: iv[1]):
        if start >= last_end:
            last_end = end                        # keep it
        else:
            removed += 1                          # clashes: remove it
    return removed


# ---------------------------------------------------------------
# COMPLEXITY (n = number of meetings)
# ---------------------------------------------------------------
#
#   Solution                   | Time        | Extra space
#   ---------------------------|-------------|------------
#   I. Sort + neighbours       | O(n log n)  | O(n)
#   II-1. Brute force          | O(n^2)      | O(1)
#   II-2. Min-heap             | O(n log n)  | O(n)
#   II-3. Sweep line           | O(n log n)  | O(n)
#   Peak concurrent sessions   | O(n log n)  | O(n)
#   Min removals (greedy)      | O(n log n)  | O(n)


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    import random

    # Part I
    assert can_attend_all([[0, 30], [5, 10], [15, 20]]) is False
    assert can_attend_all([[7, 10], [2, 4]]) is True
    assert can_attend_all([[1, 5], [5, 10]]) is True       # touching is fine
    assert can_attend_all([]) is True

    # Part II
    test_cases = [
        # (meetings, expected)
        ([[0, 30], [5, 10], [15, 20]], 2),                 # LeetCode example 1
        ([[7, 10], [2, 4]], 1),                            # LeetCode example 2
        ([[1, 5], [5, 10], [10, 15]], 1),                  # back to back
        ([[1, 10], [2, 9], [3, 8], [4, 7]], 4),            # all at once
        ([], 0),
        ([[1, 2]], 1),
        ([[9, 10], [4, 9], [4, 17]], 2),
    ]
    for solve in [min_rooms_brute_force, min_rooms_heap, min_rooms_sweep]:
        for meetings, expected in test_cases:
            result = solve(meetings)
            assert result == expected, (
                f"{solve.__name__}({meetings}) returned {result}, expected {expected}"
            )

    # The three agree on random input
    random.seed(6)
    for _ in range(300):
        ms = []
        for _ in range(random.randint(0, 15)):
            s = random.randint(0, 40)
            ms.append([s, s + random.randint(1, 10)])
        answers = {min_rooms_brute_force(ms), min_rooms_heap(ms), min_rooms_sweep(ms)}
        assert len(answers) == 1, (ms, answers)

    # Peak sessions
    sessions = [(0, 10, "a"), (2, 6, "b"), (3, 8, "c"), (6, 9, "d"), (12, 14, "a")]
    peak, when, ips = peak_concurrent_sessions(sessions)
    assert (peak, when, ips) == (3, 3, {"a", "b", "c"})
    assert peak_concurrent_sessions([]) == (0, None, set())

    # Min removals (LeetCode 435 examples)
    assert min_removals([[1, 2], [2, 3], [3, 4], [1, 3]]) == 1
    assert min_removals([[1, 2], [1, 2], [1, 2]]) == 2
    assert min_removals([[1, 2], [2, 3]]) == 0
    assert min_removals([]) == 0

    print("All tests passed!")


if __name__ == "__main__":
    meetings = [[0, 30], [5, 10], [15, 20]]
    print(f"Meetings {meetings}")
    print(f"  can attend all? {can_attend_all(meetings)}")
    print(f"  rooms needed:   {min_rooms_heap(meetings)}")

    # Sessions for one account: (start minute, end minute, source IP)
    sessions = [
        (540, 600, "10.0.0.15"),        # office laptop, 09:00-10:00
        (545, 900, "10.0.0.15"),        # second tab
        (610, 700, "198.51.100.23"),
        (615, 690, "203.0.113.77"),
        (620, 680, "192.0.2.140"),
        (625, 660, "203.0.113.9"),
    ]
    LIMIT = 3
    peak, when, ips = peak_concurrent_sessions(sessions)
    print(f"\nAccount 'alice': peak of {peak} concurrent sessions at "
          f"{when // 60:02d}:{when % 60:02d}")
    print(f"  from {len(ips)} different IPs: {', '.join(sorted(ips))}")
    if peak > LIMIT:
        print(f"  ALERT: more than {LIMIT} sessions at once; possible shared or stolen password")

    print(f"\nFewest meetings to cancel so none overlap in "
          f"[[1, 2], [2, 3], [3, 4], [1, 3]]: {min_removals([[1, 2], [2, 3], [3, 4], [1, 3]])}")

    print()
    run_tests()
