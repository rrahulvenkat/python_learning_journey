# Sorting Algorithms: how sorted() actually works
#
# PROBLEM
# -------
# Sort a list of numbers into ascending order WITHOUT sort() or
# sorted(), using three classic algorithms:
#
#   [5, 2, 9, 1, 5, 6]  ->  [1, 2, 5, 5, 6, 9]
#
# Then use the key idea of merge sort to merge two already-sorted log
# files into one timeline.
#
# KEY IDEAS
# ---------
#   - INSERTION SORT: take each item and slide it left into place, like
#     sorting playing cards in your hand. O(n^2), but very fast on
#     small or nearly-sorted lists.
#   - MERGE SORT: split the list in half, sort each half, then MERGE
#     the two sorted halves. Merging is easy: repeatedly take the
#     smaller of the two front items. O(n log n), always.
#   - QUICKSORT: pick a "pivot", put smaller items to its left and
#     larger to its right, then sort each side. O(n log n) on average,
#     O(n^2) if the pivot keeps being the smallest or largest item.
#   - STABLE sorting keeps items with EQUAL keys in their original
#     order. Python's sorted() is stable (it uses Timsort, a mix of
#     merge sort and insertion sort).
#
# WHAT'S NEW HERE
# ---------------
# data_structures/lists.py showed how to CALL sort() and sorted(),
# including key=. This file shows what happens INSIDE, and introduces
# "divide and conquer": split a problem in half, solve each half, and
# combine the answers.
#
# SECURITY CONNECTION
# -------------------
#   - Incident response means building a TIMELINE from many sources:
#     firewall logs, web server logs, login records. Each is already
#     sorted by time, so you MERGE them instead of re-sorting
#     everything (merge_sorted_logs below).
#   - Stability matters when you sort by one field after another, for
#     example by severity, keeping events in time order within each
#     severity.
#   - Algorithmic complexity attacks: if an attacker can choose input
#     that makes your code hit its WORST case (like a naive quicksort
#     on already-sorted data), they can slow a server to a crawl.
#     That's why real libraries use algorithms with guaranteed limits.


import heapq
import random


# ---------------------------------------------------------------
# Algorithm 1: insertion sort
# ---------------------------------------------------------------
#
# Trace for [5, 2, 9, 1]:
#
#   step        | list          | what happened
#   ------------|---------------|------------------------------------
#   start       | [5, 2, 9, 1]  |
#   insert 2    | [2, 5, 9, 1]  | 2 < 5, slide 5 right, put 2 first
#   insert 9    | [2, 5, 9, 1]  | 9 > 5, already in place
#   insert 1    | [1, 2, 5, 9]  | slide 9, 5, 2 right, put 1 first
#
# It works on a copy so the caller's list isn't changed.

def insertion_sort(items):
    result = list(items)
    for i in range(1, len(result)):
        current = result[i]
        j = i - 1
        while j >= 0 and result[j] > current:     # > (not >=) keeps it stable
            result[j + 1] = result[j]             # slide right
            j -= 1
        result[j + 1] = current
    return result


# ---------------------------------------------------------------
# Algorithm 2: merge sort
# ---------------------------------------------------------------
#
# The MERGE step combines two sorted lists in O(n):
#
#   left = [2, 5, 9]   right = [1, 5, 6]
#
#   compare | take | merged so far
#   --------|------|------------------
#   2 vs 1  |  1   | [1]
#   2 vs 5  |  2   | [1, 2]
#   5 vs 5  |  5 (from LEFT, keeps it stable) | [1, 2, 5]
#   9 vs 5  |  5   | [1, 2, 5, 5]
#   9 vs 6  |  6   | [1, 2, 5, 5, 6]
#   right is empty: add the rest of left -> [1, 2, 5, 5, 6, 9]
#
# The split: [5, 2, 9, 1, 5, 6]
#            [5, 2, 9]        [1, 5, 6]
#            [5] [2, 9]       [1] [5, 6]
#                [2] [9]          [5] [6]
#   then merge back up. There are log2(n) levels, and each level does
#   O(n) merging work, so the total is O(n log n).

def merge(left, right, key=lambda x: x):
    merged = []
    i = j = 0
    while i < len(left) and j < len(right):
        if key(left[i]) <= key(right[j]):         # <= takes from left on ties: stable
            merged.append(left[i])
            i += 1
        else:
            merged.append(right[j])
            j += 1
    merged.extend(left[i:])                       # one of these is empty
    merged.extend(right[j:])
    return merged


def merge_sort(items, key=lambda x: x):
    if len(items) <= 1:
        return list(items)
    middle = len(items) // 2
    left = merge_sort(items[:middle], key)
    right = merge_sort(items[middle:], key)
    return merge(left, right, key)


# ---------------------------------------------------------------
# Algorithm 3: quicksort
# ---------------------------------------------------------------
#
# Pick a pivot and split into three groups: smaller, equal, larger.
# Then sort the smaller and larger groups the same way.
#
#   [5, 2, 9, 1, 5, 6], pivot 5
#   smaller [2, 1]   equal [5, 5]   larger [9, 6]
#   -> quicksort([2, 1]) + [5, 5] + quicksort([9, 6])
#   -> [1, 2] + [5, 5] + [6, 9]
#
# A RANDOM pivot makes the O(n^2) worst case extremely unlikely, even
# if an attacker chooses the input. The "first item" pivot version
# below is there to show the problem: on already-sorted input, every
# split is lopsided.
#
# This version is short and clear but builds new lists. The classic
# version partitions in place to save memory.

def quicksort(items):
    if len(items) <= 1:
        return list(items)
    pivot = random.choice(items)
    smaller = [x for x in items if x < pivot]
    equal = [x for x in items if x == pivot]
    larger = [x for x in items if x > pivot]
    return quicksort(smaller) + equal + quicksort(larger)


def quicksort_first_pivot(items, counter):
    """Naive pivot choice. counter[0] counts comparisons."""
    if len(items) <= 1:
        return list(items)
    pivot = items[0]
    counter[0] += len(items)
    smaller = [x for x in items[1:] if x < pivot]
    larger = [x for x in items[1:] if x >= pivot]
    return quicksort_first_pivot(smaller, counter) + [pivot] + quicksort_first_pivot(larger, counter)


# ---------------------------------------------------------------
# Application 1: merge sorted log files into one timeline
# ---------------------------------------------------------------
#
# Each log is a list of (timestamp, source, message), already in time
# order. Merging two is the merge step above. For MANY logs, use a
# heap: heapq.merge() always takes the smallest front item across all
# the lists, in O(total * log(number of logs)).
#
# A HEAP is a structure that always gives you its smallest item
# quickly. heapq.heappush and heapq.heappop are O(log n). You'll use
# heaps again in meeting_rooms.py.

def merge_two_logs(log_a, log_b):
    return merge(log_a, log_b, key=lambda event: event[0])


def merge_many_logs(*logs):
    return list(heapq.merge(*logs, key=lambda event: event[0]))


# ---------------------------------------------------------------
# Application 2: stability, sorting by two keys
# ---------------------------------------------------------------
#
# Goal: sort alerts by severity, and within each severity keep them in
# time order. Because the sort is stable, you can sort by time FIRST,
# then by severity, and the time order survives inside each severity.
# (Or sort once with a tuple key: key=lambda a: (a.severity, a.time).)

SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}

def triage(alerts):
    by_time = merge_sort(alerts, key=lambda a: a[0])
    return merge_sort(by_time, key=lambda a: SEVERITY[a[1]])


# ---------------------------------------------------------------
# COMPLEXITY (n = number of items)
# ---------------------------------------------------------------
#
#   Algorithm       | Best        | Average     | Worst       | Stable? | Extra space
#   ----------------|-------------|-------------|-------------|---------|------------
#   Insertion sort  | O(n)        | O(n^2)      | O(n^2)      | yes     | O(1) in place
#   Merge sort      | O(n log n)  | O(n log n)  | O(n log n)  | yes     | O(n)
#   Quicksort       | O(n log n)  | O(n log n)  | O(n^2)      | no*     | O(log n) in place
#   Python sorted() | O(n)        | O(n log n)  | O(n log n)  | yes     | O(n)
#
#   * This list-building version happens to be stable for plain
#     numbers, but in-place quicksort is not stable in general.
#
# No comparison sort can beat O(n log n) in general. To go faster,
# you need to know something about the data, like a small range of
# values (see counting sort in sort_colors.py).


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    test_cases = [
        [],
        [1],
        [2, 1],
        [5, 2, 9, 1, 5, 6],
        [1, 2, 3, 4, 5],                  # already sorted
        [5, 4, 3, 2, 1],                  # reversed
        [3, 3, 3],                        # all equal
        [-2, 0, -5, 7, 0],                # negatives and zeros
    ]
    random.seed(3)
    test_cases += [[random.randint(-100, 100) for _ in range(n)] for n in (10, 100, 500)]

    for solve in [insertion_sort, merge_sort, quicksort]:
        for items in test_cases:
            original = list(items)
            result = solve(items)
            assert result == sorted(items), f"{solve.__name__} failed on {items}"
            assert items == original, f"{solve.__name__} changed its input"

    # Stability: equal keys keep their original order
    cards = [(5, "a"), (2, "b"), (5, "c"), (2, "d"), (1, "e")]
    expected = [(1, "e"), (2, "b"), (2, "d"), (5, "a"), (5, "c")]
    assert merge_sort(cards, key=lambda c: c[0]) == expected
    assert sorted(cards, key=lambda c: c[0]) == expected

    # Merging logs
    web = [(1, "web", "GET /"), (4, "web", "POST /login"), (9, "web", "GET /admin")]
    fw = [(2, "fw", "allow 203.0.113.9"), (4, "fw", "allow 203.0.113.9"), (10, "fw", "deny")]
    auth = [(3, "auth", "fail admin"), (5, "auth", "success admin")]
    two = merge_two_logs(web, fw)
    assert [e[0] for e in two] == [1, 2, 4, 4, 9, 10]
    assert two[2][1] == "web"                          # tie at 4: first log wins
    many = merge_many_logs(web, fw, auth)
    assert [e[0] for e in many] == [1, 2, 3, 4, 4, 5, 9, 10]
    assert merge_many_logs() == []

    # Triage keeps time order within each severity
    alerts = [(5, "low", "x"), (1, "high", "y"), (3, "critical", "z"),
              (2, "low", "w"), (4, "high", "v")]
    assert triage(alerts) == [(3, "critical", "z"), (1, "high", "y"), (4, "high", "v"),
                              (2, "low", "w"), (5, "low", "x")]

    # The naive pivot is quadratic on sorted input
    counter = [0]
    quicksort_first_pivot(list(range(300)), counter)
    assert counter[0] == sum(range(2, 301))            # n + (n-1) + ... + 2

    print("All tests passed!")


if __name__ == "__main__":
    import sys
    import time

    nums = [5, 2, 9, 1, 5, 6]
    print(f"input:          {nums}")
    for solve in [insertion_sort, merge_sort, quicksort]:
        print(f"{solve.__name__ + ':':<16}{solve(nums)}")

    print("\nIncident timeline, merged from three sorted logs:")
    web = [(1, "web", "GET /"), (4, "web", "POST /login"), (9, "web", "GET /admin")]
    fw = [(2, "fw", "allow 203.0.113.9:443"), (10, "fw", "deny 203.0.113.9:22")]
    auth = [(3, "auth", "failed login: admin"), (5, "auth", "successful login: admin")]
    for t, source, message in merge_many_logs(web, fw, auth):
        print(f"  t={t:<3} [{source:<4}] {message}")

    # Worst-case input for a naive quicksort
    sys.setrecursionlimit(10_000)
    for name, data in [("random", random.sample(range(2_000), 2_000)),
                       ("already sorted", list(range(2_000)))]:
        counter = [0]
        quicksort_first_pivot(data, counter)
        print(f"\nNaive quicksort on {name} input (2,000 items): {counter[0]:,} comparisons")

    # Speed comparison
    random.seed(0)
    big = [random.randint(0, 1_000_000) for _ in range(5_000)]
    print(f"\nSpeed test with {len(big):,} random numbers:")
    for name, solve in [("insertion_sort", insertion_sort), ("merge_sort", merge_sort),
                        ("quicksort", quicksort), ("sorted (built-in)", sorted)]:
        start = time.perf_counter()
        solve(big)
        print(f"  {name:<18} {time.perf_counter() - start:.4f} s")

    print()
    run_tests()
