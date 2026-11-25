# Longest Substring Without Repeating Characters (LeetCode 3)
# (variable-size sliding window)
#
# PROBLEM
# -------
# Given a string, return the length of the longest substring (a run of
# CONSECUTIVE characters) in which no character appears twice.
#
#   "abcabcbb"  ->  3   ("abc")
#   "bbbbb"     ->  1   ("b")
#   "pwwkew"    ->  3   ("wke"; "pwke" doesn't count because it
#                        isn't consecutive)
#
# KEY IDEAS
# ---------
#   - Brute force checks every substring: O(n^2) substrings, each one
#     checked for repeats.
#   - A VARIABLE window: keep a window with no repeats in it.
#       * GROW it by moving the right edge forward one character.
#       * If the new character is already in the window, SHRINK it by
#         moving the left edge forward until the repeat is gone.
#     Each character enters the window once and leaves at most once,
#     so the whole thing is O(n).
#   - Even better: remember the LAST INDEX of each character, and
#     jump the left edge straight past the old copy instead of
#     shrinking one step at a time.
#
# FIXED vs VARIABLE WINDOWS
# -------------------------
# max_sum_subarray.py uses a FIXED window: it's always k wide, and the
# left edge moves whenever the right one does. Here the window size
# is the ANSWER, so the left edge only moves when a rule is broken.
#
#   VARIABLE WINDOW TEMPLATE
#   ------------------------
#   left = 0
#   for right in range(len(items)):
#       add items[right] to the window
#       while the window breaks the rule:
#           remove items[left] from the window
#           left += 1
#       the window is valid again: record the answer
#
# The "last index" trick is the same one contains_nearby_duplicate()
# in contains_duplicate.py uses.
#
# SECURITY CONNECTION
# -------------------
# Variable windows answer questions like "the shortest time span that
# contains 5 failed logins" or "the longest period without a repeated
# event". Variation 2 below, the shortest window reaching a total, is
# the core of a brute-force login detector.


# ---------------------------------------------------------------
# Solution 1: brute force (try every starting point)
# ---------------------------------------------------------------
#
# From each start, extend to the right with a set until a character
# repeats. This is already better than checking every substring
# separately, but it's still O(n^2) in the worst case.

def longest_brute_force(s):
    best = 0
    for start in range(len(s)):
        seen = set()
        for ch in s[start:]:
            if ch in seen:
                break
            seen.add(ch)
        best = max(best, len(seen))
    return best


# ---------------------------------------------------------------
# Solution 2: sliding window with a set (grow and shrink)
# ---------------------------------------------------------------
#
# Trace for s = "abcabcbb" (window = s[left:right+1]):
#
#   right | ch | repeat? | shrink (remove from left) | window | best
#   ------|----|---------|---------------------------|--------|-----
#     0   | a  |   no    |                           | a      |  1
#     1   | b  |   no    |                           | ab     |  2
#     2   | c  |   no    |                           | abc    |  3
#     3   | a  |   yes   | remove a                  | bca    |  3
#     4   | b  |   yes   | remove b                  | cab    |  3
#     5   | c  |   yes   | remove c                  | abc    |  3
#     6   | b  |   yes   | remove a, remove b        | cb     |  3
#     7   | b  |   yes   | remove c, remove b        | b      |  3

def longest_sliding_set(s):
    window = set()
    left = 0
    best = 0

    for right, ch in enumerate(s):
        while ch in window:                 # the rule is broken: shrink
            window.remove(s[left])
            left += 1
        window.add(ch)                      # grow
        best = max(best, right - left + 1)  # window length

    return best


# ---------------------------------------------------------------
# Solution 3: sliding window with last indexes (jump, don't crawl)
# ---------------------------------------------------------------
#
# Instead of removing characters one at a time, remember where each
# character was last seen. When ch repeats inside the window, move
# `left` to one past its previous position in a single step.
#
# The check  last_seen[ch] >= left  matters: an old copy of ch that
# is already OUTSIDE the window (to the left of `left`) isn't a
# repeat. Without it, "abba" gives the wrong answer:
#   at the final 'a', its old index 0 is outside the window "b",
#   so `left` must stay put, not jump backwards.

def longest_substring(s):
    last_seen = {}                          # character -> latest index
    left = 0
    best = 0

    for right, ch in enumerate(s):
        if ch in last_seen and last_seen[ch] >= left:
            left = last_seen[ch] + 1        # jump past the old copy
        last_seen[ch] = right
        best = max(best, right - left + 1)

    return best


# ---------------------------------------------------------------
# Variation 1: return the substring itself
# ---------------------------------------------------------------

def longest_substring_text(s):
    last_seen = {}
    left = 0
    best_start, best_len = 0, 0

    for right, ch in enumerate(s):
        if ch in last_seen and last_seen[ch] >= left:
            left = last_seen[ch] + 1
        last_seen[ch] = right
        if right - left + 1 > best_len:
            best_start, best_len = left, right - left + 1

    return s[best_start:best_start + best_len]


# ---------------------------------------------------------------
# Variation 2: Minimum Size Subarray Sum (LeetCode 209)
# ---------------------------------------------------------------
#
# Given a list of POSITIVE numbers and a target, return the length of
# the SHORTEST consecutive run whose sum is at least target, or 0 if
# none exists.
#
#   nums = [2, 3, 1, 2, 4, 3], target = 7  ->  2   ([4, 3])
#
# This flips solution 2: grow until the window is valid (sum >=
# target), then shrink while it stays valid, recording the length
# each time. The shortest valid window is the answer.
#
# It only works because the numbers are positive: removing one always
# makes the sum smaller, so shrinking is safe.

def min_subarray_len(nums, target):
    left = 0
    window_sum = 0
    best = float("inf")

    for right, num in enumerate(nums):
        window_sum += num                         # grow
        while window_sum >= target:               # valid: try to shrink
            best = min(best, right - left + 1)
            window_sum -= nums[left]
            left += 1

    return 0 if best == float("inf") else best


# ---------------------------------------------------------------
# Variation 3: Longest Substring with At Most K Distinct Characters
# (LeetCode 340)
# ---------------------------------------------------------------
#
#   s = "eceba", k = 2  ->  3   ("ece")
#
# The rule changes from "no repeats" to "at most k different
# characters", so the window holds COUNTS instead of a set. When a
# count drops to 0, delete the key, so len(counts) is always the
# number of distinct characters in the window.

def longest_k_distinct(s, k):
    counts = {}
    left = 0
    best = 0

    for right, ch in enumerate(s):
        counts[ch] = counts.get(ch, 0) + 1
        while len(counts) > k:                    # too many distinct: shrink
            left_ch = s[left]
            counts[left_ch] -= 1
            if counts[left_ch] == 0:
                del counts[left_ch]
            left += 1
        best = max(best, right - left + 1)

    return best


# ---------------------------------------------------------------
# COMPLEXITY (n = length of the input)
# ---------------------------------------------------------------
#
#   Solution                      | Time    | Extra space
#   ------------------------------|---------|--------------------------
#   1. Brute force                | O(n^2)  | O(m)  m = distinct chars
#   2. Sliding window + set       | O(n)    | O(m)
#   3. Sliding window + last index| O(n)    | O(m)
#   Variation 2 (min length)      | O(n)    | O(1)
#   Variation 3 (k distinct)      | O(n)    | O(k)
#
# Why is solution 2 O(n) when it has a loop inside a loop? Because
# `left` only ever moves forward. Across the whole run, the inner
# while loop runs at most n times IN TOTAL, not n times per character.
# This "each item enters once and leaves once" argument is how you
# prove any sliding window is O(n).


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    test_cases = [
        # (s, expected)
        ("abcabcbb", 3),        # LeetCode example 1
        ("bbbbb", 1),           # LeetCode example 2
        ("pwwkew", 3),          # LeetCode example 3
        ("", 0),                # empty string
        ("a", 1),
        ("abcdef", 6),          # no repeats at all
        ("abba", 2),            # old copy outside the window
        ("dvdf", 3),            # "vdf": left must not jump too far
        ("a b!a", 4),           # spaces and symbols count too: "a b!" / " b!a"
    ]

    solutions = [longest_brute_force, longest_sliding_set, longest_substring]

    for solve in solutions:
        for s, expected in test_cases:
            result = solve(s)
            assert result == expected, (
                f"{solve.__name__}({s!r}) returned {result}, expected {expected}"
            )

    # The three solutions agree on random strings
    import random
    random.seed(2)
    for _ in range(200):
        s = "".join(random.choice("abcde") for _ in range(random.randint(0, 30)))
        answers = {solve(s) for solve in solutions}
        assert len(answers) == 1, f"solutions disagree on {s!r}: {answers}"

    # The substring itself
    assert longest_substring_text("abcabcbb") == "abc"
    assert longest_substring_text("pwwkew") == "wke"
    assert longest_substring_text("") == ""

    # Minimum size subarray sum (LeetCode 209 examples)
    assert min_subarray_len([2, 3, 1, 2, 4, 3], 7) == 2
    assert min_subarray_len([1, 4, 4], 4) == 1
    assert min_subarray_len([1, 1, 1, 1, 1, 1, 1, 1], 11) == 0

    # At most k distinct characters
    assert longest_k_distinct("eceba", 2) == 3
    assert longest_k_distinct("aa", 1) == 2
    assert longest_k_distinct("abc", 0) == 0
    assert longest_k_distinct("abaccc", 2) == 4      # "accc"

    print("All tests passed!")


if __name__ == "__main__":
    import time

    for s in ["abcabcbb", "pwwkew", "abba"]:
        print(f"{s!r:<12} longest without repeats: "
              f"{longest_substring_text(s)!r} (length {longest_substring(s)})")

    nums, target = [2, 3, 1, 2, 4, 3], 7
    print(f"\nShortest run in {nums} with sum >= {target}: "
          f"length {min_subarray_len(nums, target)}")
    print(f"Longest part of 'eceba' with at most 2 distinct letters: "
          f"{longest_k_distinct('eceba', 2)}")

    # Speed comparison on a long string with many different characters
    import random
    import string
    random.seed(0)
    big = "".join(random.choice(string.printable) for _ in range(20_000))
    print(f"\nSpeed test with a {len(big):,}-character string:")
    for solve in [longest_brute_force, longest_sliding_set, longest_substring]:
        start = time.perf_counter()
        solve(big)
        print(f"  {solve.__name__:<20} {time.perf_counter() - start:.4f} s")

    print()
    run_tests()
