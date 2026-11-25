# Contains Duplicate (LeetCode 217)
#
# PROBLEM
# -------
# Given a list of integers, return True if any value appears at least
# twice, and False if every value is different.
#
#   [1, 2, 3, 1]  ->  True
#   [1, 2, 3, 4]  ->  False
#
# KEY IDEAS
# ---------
#   - Brute force compares every pair: O(n^2).
#   - Sorting puts equal values NEXT TO each other, so you only need
#     to compare neighbours.
#   - A set remembers what you've seen. Checking "have I seen this?"
#     is O(1), and you can STOP at the first repeat.
#
# WHAT'S NEW HERE
# ---------------
# data_structures/sets.py already showed the one-liner
#     len(items) != len(set(items))
# It's correct, but it always builds the WHOLE set, even when the
# duplicate is in the first two items. This file teaches:
#   - EARLY EXIT: stop as soon as you know the answer
#   - SORT, THEN SCAN NEIGHBOURS: a technique used in many problems
#   - Remembering the LAST POSITION of each value (Contains Duplicate
#     II), which leads into the sliding window technique
#
# SECURITY CONNECTION
# -------------------
# "Have I seen this before?" is one of the most common questions in
# security: a reused password, a repeated session ID, a replayed
# request, a file hash that's already known. "Seen again within k
# events" is the basis of detecting repeated logins or alerts close
# together.


# ---------------------------------------------------------------
# Solution 1: brute force (compare every pair)
# ---------------------------------------------------------------

def contains_duplicate_brute_force(nums):
    for i in range(len(nums)):
        for j in range(i + 1, len(nums)):
            if nums[i] == nums[j]:
                return True
    return False


# ---------------------------------------------------------------
# Solution 2: sort, then compare neighbours
# ---------------------------------------------------------------
#
# After sorting, any duplicates sit side by side:
#   [3, 1, 4, 1, 5]  ->  sorted  ->  [1, 1, 3, 4, 5]
#                                     ^  ^  equal neighbours
#
# sorted() makes a copy so the caller's list isn't changed.
# nums.sort() would sort in place with no extra list, but it changes
# the input, which is a side effect callers may not expect.

def contains_duplicate_sort(nums):
    ordered = sorted(nums)
    for i in range(1, len(ordered)):
        if ordered[i] == ordered[i - 1]:
            return True
    return False


# ---------------------------------------------------------------
# Solution 3: set with early exit (the optimal answer)
# ---------------------------------------------------------------
#
# Walk through the list once. If the value is already in `seen`,
# you've found a duplicate and can stop immediately.
#
# Trace for nums = [1, 2, 3, 1]:
#
#   num | seen before | action
#   ----|-------------|-----------------
#    1  | {}          | add 1
#    2  | {1}         | add 2
#    3  | {1, 2}      | add 3
#    1  | {1, 2, 3}   | 1 is in seen -> return True

def contains_duplicate(nums):
    seen = set()
    for num in nums:
        if num in seen:
            return True
        seen.add(num)
    return False


# ---------------------------------------------------------------
# Variation 1: return the first repeated value
# ---------------------------------------------------------------
#
# Often you need to know WHICH value repeated, not just whether one
# did. Same loop, different return value. Returns None if there's no
# repeat.
#   [2, 5, 1, 5, 2]  ->  5   (5 repeats before 2 does)

def first_duplicate(items):
    seen = set()
    for item in items:
        if item in seen:
            return item
        seen.add(item)
    return None


# ---------------------------------------------------------------
# Variation 2: Contains Duplicate II (LeetCode 219)
# ---------------------------------------------------------------
#
# Return True if the same value appears twice with the two indexes
# at most k apart:  abs(i - j) <= k
#
#   nums = [1, 2, 3, 1], k = 3  ->  True   (indexes 0 and 3)
#   nums = [1, 2, 3, 1], k = 2  ->  False  (3 apart, more than 2)
#
# Approach A: a dictionary of each value's LAST index.
#   If the value was seen before and i - last_index <= k, return True.
#   Otherwise, update its last index to i. Keeping the LATEST index
#   matters: it's always the closest one to future positions.

def contains_nearby_duplicate(nums, k):
    last_index = {}                                # value -> latest index
    for i, num in enumerate(nums):
        if num in last_index and i - last_index[num] <= k:
            return True
        last_index[num] = i
    return False


# Approach B: a sliding window set holding only the last k values.
#   Before checking position i, remove the value that is now too far
#   back (position i - k - 1). The set never holds more than k items,
#   so the extra space is O(k) instead of O(n).
#
#   nums = [1, 2, 3, 1], k = 2
#
#   i | num | window before | action
#   --|-----|---------------|------------------------------
#   0 |  1  | {}            | add 1
#   1 |  2  | {1}           | add 2
#   2 |  3  | {1, 2}        | add 3
#   3 |  1  | {1, 2, 3}     | remove nums[0]=1 -> {2, 3}; 1 not in it; add 1
#   -> False

def contains_nearby_duplicate_window(nums, k):
    window = set()
    for i, num in enumerate(nums):
        if i > k:
            window.remove(nums[i - k - 1])         # drop the value that fell out
        if num in window:
            return True
        window.add(num)
    return False


# ---------------------------------------------------------------
# COMPLEXITY (n = length of nums)
# ---------------------------------------------------------------
#
#   Solution                     | Time        | Extra space
#   -----------------------------|-------------|-------------------
#   1. Brute force               | O(n^2)      | O(1)
#   2. Sort + neighbours         | O(n log n)  | O(n) copy (O(1) with .sort())
#   3. Set, early exit           | O(n)        | O(n)
#   len(set(nums)) != len(nums)  | O(n)        | O(n), no early exit
#   II-A. Last index dictionary  | O(n)        | O(n)
#   II-B. Sliding window set     | O(n)        | O(k)
#
# Both the one-liner and solution 3 are O(n), but O(n) is the WORST
# case. With early exit, a duplicate near the start finishes almost
# instantly. The speed test below shows the difference.


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    test_cases = [
        # (nums, expected)
        ([1, 2, 3, 1], True),                     # LeetCode example 1
        ([1, 2, 3, 4], False),                    # LeetCode example 2
        ([1, 1, 1, 3, 3, 4, 3, 2, 4, 2], True),   # LeetCode example 3
        ([], False),                              # empty list
        ([7], False),                             # one item
        ([5, 5], True),                           # duplicate right away
        ([-1, 0, 1, -1], True),                   # negative numbers
        ([0, -0], True),                          # 0 and -0 are equal
    ]

    solutions = [contains_duplicate_brute_force,
                 contains_duplicate_sort,
                 contains_duplicate]

    for solve in solutions:
        for nums, expected in test_cases:
            result = solve(nums)
            assert result == expected, (
                f"{solve.__name__}({nums}) returned {result}, expected {expected}"
            )

    # The input list must not be changed by the sort solution
    original = [3, 1, 2, 1]
    contains_duplicate_sort(original)
    assert original == [3, 1, 2, 1]

    # First duplicate
    assert first_duplicate([2, 5, 1, 5, 2]) == 5
    assert first_duplicate(["a", "b", "a"]) == "a"   # works on any hashable items
    assert first_duplicate([1, 2, 3]) is None

    # Contains Duplicate II: both approaches must agree
    nearby_cases = [
        # (nums, k, expected)
        ([1, 2, 3, 1], 3, True),                 # LeetCode example 1
        ([1, 0, 1, 1], 1, True),                 # LeetCode example 2
        ([1, 2, 3, 1, 2, 3], 2, False),          # LeetCode example 3
        ([1, 2, 3, 1], 2, False),                # just too far apart
        ([1, 2, 1], 0, False),                   # k = 0: never possible
        ([], 5, False),
    ]
    for solve in [contains_nearby_duplicate, contains_nearby_duplicate_window]:
        for nums, k, expected in nearby_cases:
            result = solve(nums, k)
            assert result == expected, (
                f"{solve.__name__}({nums}, {k}) returned {result}, expected {expected}"
            )

    print("All tests passed!")


if __name__ == "__main__":
    import time

    nums = [1, 2, 3, 1]
    print(f"{nums} contains a duplicate? {contains_duplicate(nums)}")
    print(f"First repeated value in [2, 5, 1, 5, 2]: {first_duplicate([2, 5, 1, 5, 2])}")
    print(f"[1, 2, 3, 1] with k=3: {contains_nearby_duplicate([1, 2, 3, 1], 3)}")
    print(f"[1, 2, 3, 1] with k=2: {contains_nearby_duplicate([1, 2, 3, 1], 2)}")

    # Early exit vs the one-liner from sets.py.
    # The duplicate is at the very start, followed by a million values.
    big = [0, 0] + list(range(1, 1_000_000))
    print(f"\nSpeed test: {len(big):,} numbers, duplicate in the first two:")

    start = time.perf_counter()
    contains_duplicate(big)
    early = time.perf_counter() - start

    start = time.perf_counter()
    len(big) != len(set(big))
    whole = time.perf_counter() - start

    print(f"  set with early exit   {early:.6f} s")
    print(f"  len(set(...)) check   {whole:.6f} s")

    print()
    run_tests()
