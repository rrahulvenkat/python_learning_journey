# Maximum Sum Subarray of Size K  (fixed-size sliding window)
#
# PROBLEM
# -------
# Given a list of numbers and a window size k, find the largest sum of
# any k CONSECUTIVE numbers.
#
#   nums = [2, 1, 5, 1, 3, 2], k = 3
#
#   windows:  [2, 1, 5] = 8
#                [1, 5, 1] = 7
#                   [5, 1, 3] = 9   <- largest
#                      [1, 3, 2] = 6
#   answer: 9
#
# KEY IDEAS
# ---------
#   - Brute force re-adds all k numbers for every window: O(n * k).
#   - Two neighbouring windows share k - 1 numbers. So instead of
#     re-adding everything, SLIDE the window one step:
#         new_sum = old_sum + number_entering - number_leaving
#     Each step is O(1), so the whole thing is O(n).
#
# THE SLIDING WINDOW TECHNIQUE
# ----------------------------
# A "window" is a run of consecutive items, marked by a left and a
# right edge. There are two kinds:
#
#   FIXED size     (this file)              always exactly k items wide
#   VARIABLE size  (longest_substring.py)   grows and shrinks as needed
#
# You've already used fixed windows without the name:
#   - find_anagrams() in valid_anagram.py slides a window of letter
#     COUNTS
#   - contains_nearby_duplicate_window() in contains_duplicate.py
#     slides a window SET
# This file uses the simplest version, a running SUM, and shows the
# template they all follow.
#
# SECURITY CONNECTION
# -------------------
# Monitoring is full of fixed windows: "requests in the last 5
# minutes", "the busiest hour of traffic", "the average over the last
# 10 samples". A sudden jump above the recent average is one of the
# simplest ways to spot unusual activity (variation 3 below).


# ---------------------------------------------------------------
# Solution 1: brute force (add up every window from scratch)
# ---------------------------------------------------------------

def max_sum_brute_force(nums, k):
    if k <= 0 or k > len(nums):
        return None

    best = float("-inf")                       # smaller than any real sum
    for start in range(len(nums) - k + 1):
        window_sum = sum(nums[start:start + k])   # k additions each time
        best = max(best, window_sum)
    return best


# ---------------------------------------------------------------
# Solution 2: sliding window (the optimal answer)
# ---------------------------------------------------------------
#
#   1. Add up the first k numbers. That's the first window.
#   2. For each next position i:
#        add nums[i]        (enters on the right)
#        subtract nums[i-k] (leaves on the left)
#   3. Keep track of the best sum seen.
#
# Trace for nums = [2, 1, 5, 1, 3, 2], k = 3:
#
#   i | enters | leaves | window_sum      | best
#   --|--------|--------|-----------------|-----
#   - |   -    |   -    | 2+1+5 = 8       |  8   first window
#   3 |   1    |   2    | 8 + 1 - 2 = 7   |  8
#   4 |   3    |   1    | 7 + 3 - 1 = 9   |  9
#   5 |   2    |   5    | 9 + 2 - 5 = 6   |  9
#
# Note: when all the numbers are negative, the answer is negative
# too. Starting `best` at the first window (not at 0) handles that.

def max_sum_sliding(nums, k):
    if k <= 0 or k > len(nums):
        return None

    window_sum = sum(nums[:k])                 # first window
    best = window_sum

    for i in range(k, len(nums)):
        window_sum += nums[i] - nums[i - k]    # slide one step
        best = max(best, window_sum)

    return best


# ---------------------------------------------------------------
# THE FIXED WINDOW TEMPLATE
# ---------------------------------------------------------------
#
#   build the first window from items 0 .. k-1
#   record the answer for it
#   for i from k to the end:
#       add item i           (enters)
#       remove item i - k    (leaves)
#       record the answer for this window
#
# "Add" and "remove" depend on what the window holds:
#   - a sum:           += and -=
#   - letter counts:   counts[ch] += 1 and -= 1
#   - a set:           .add() and .remove()


# ---------------------------------------------------------------
# Variation 1: return WHERE the best window is
# ---------------------------------------------------------------
#
# Knowing the best sum is often not enough; you want to know which
# items made it. Track the start index whenever `best` improves.
#   [2, 1, 5, 1, 3, 2], k = 3  ->  (9, 2)   window starts at index 2

def max_sum_with_position(nums, k):
    if k <= 0 or k > len(nums):
        return None

    window_sum = sum(nums[:k])
    best, best_start = window_sum, 0

    for i in range(k, len(nums)):
        window_sum += nums[i] - nums[i - k]
        if window_sum > best:
            best = window_sum
            best_start = i - k + 1             # left edge of this window

    return best, best_start


# ---------------------------------------------------------------
# Variation 2: Maximum Average Subarray I (LeetCode 643)
# ---------------------------------------------------------------
#
# Same problem, but return the largest AVERAGE. Since every window has
# exactly k items, the window with the largest sum also has the
# largest average. Reuse the solution and divide once at the end.

def max_average(nums, k):
    best = max_sum_sliding(nums, k)
    return None if best is None else best / k


# ---------------------------------------------------------------
# Variation 3: spot spikes against a moving average
# ---------------------------------------------------------------
#
# Given a list of counts (for example, requests per minute), flag
# every position whose value is more than `factor` times the average
# of the k values BEFORE it.
#
#   counts = [10, 12, 11, 9, 50, 10, 11], k = 3, factor = 2
#   at index 4: the previous 3 values are [12, 11, 9], average ~10.7
#               50 > 2 * 10.7  -> spike
#
# The window here is "the k values before i", so it's built from
# items 0 .. k-1 and the first value checked is index k.

def find_spikes(counts, k, factor=2):
    if k <= 0 or k >= len(counts):
        return []

    window_sum = sum(counts[:k])
    spikes = []

    for i in range(k, len(counts)):
        average = window_sum / k
        if counts[i] > factor * average:
            spikes.append(i)
        window_sum += counts[i] - counts[i - k]   # slide AFTER checking

    return spikes


# ---------------------------------------------------------------
# COMPLEXITY (n = length of nums, k = window size)
# ---------------------------------------------------------------
#
#   Solution                  | Time      | Extra space
#   --------------------------|-----------|------------
#   1. Brute force            | O(n * k)  | O(1)*
#   2. Sliding window         | O(n)      | O(1)
#   Variations 1, 2, 3        | O(n)      | O(1) (plus the result list)
#
#   * nums[start:start + k] makes a copy of k items, so it's really
#     O(k) extra space.
#
# For n = 1,000,000 and k = 1,000: brute force does about a billion
# additions, the sliding window does about two million.


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    test_cases = [
        # (nums, k, expected)
        ([2, 1, 5, 1, 3, 2], 3, 9),           # example above
        ([2, 3, 4, 1, 5], 2, 7),              # 3 + 4
        ([1, 2, 3], 3, 6),                    # window is the whole list
        ([4], 1, 4),                          # one item
        ([-3, -1, -4, -2], 2, -4),            # all negative: -3 + -1
        ([5, -10, 6, 7, -1], 2, 13),          # 6 + 7
        ([1, 2, 3], 0, None),                 # k too small
        ([1, 2, 3], 4, None),                 # k bigger than the list
        ([], 1, None),                        # empty list
    ]

    for solve in [max_sum_brute_force, max_sum_sliding]:
        for nums, k, expected in test_cases:
            result = solve(nums, k)
            assert result == expected, (
                f"{solve.__name__}({nums}, {k}) returned {result}, expected {expected}"
            )

    # The two solutions agree on a longer random list
    import random
    random.seed(1)
    data = [random.randint(-50, 50) for _ in range(500)]
    for k in (1, 7, 50, 500):
        assert max_sum_brute_force(data, k) == max_sum_sliding(data, k)

    # Position of the best window
    assert max_sum_with_position([2, 1, 5, 1, 3, 2], 3) == (9, 2)
    assert max_sum_with_position([9, 1, 1, 9], 1) == (9, 0)   # first one wins a tie

    # Maximum average (LeetCode 643 example)
    assert max_average([1, 12, -5, -6, 50, 3], 4) == 12.75

    # Spikes
    assert find_spikes([10, 12, 11, 9, 50, 10, 11], 3) == [4]
    assert find_spikes([10, 10, 10, 10], 2) == []
    assert find_spikes([5, 5, 30, 5, 40], 2) == [2, 4]

    print("All tests passed!")


if __name__ == "__main__":
    import time

    nums, k = [2, 1, 5, 1, 3, 2], 3
    best, start = max_sum_with_position(nums, k)
    print(f"nums = {nums}, k = {k}")
    print(f"Largest sum: {best}, from window {nums[start:start + k]} at index {start}")

    # Spike detection on made-up requests-per-minute counts
    per_minute = [42, 38, 45, 40, 41, 39, 160, 44, 43, 41, 210, 40]
    print(f"\nRequests per minute: {per_minute}")
    for i in find_spikes(per_minute, k=5, factor=2):
        print(f"  minute {i}: {per_minute[i]} requests is more than 2x the "
              f"average of the 5 minutes before it")

    # Speed comparison
    import random
    random.seed(0)
    big = [random.randint(-100, 100) for _ in range(200_000)]
    k = 1_000
    print(f"\nSpeed test: {len(big):,} numbers, k = {k:,}")
    for solve in [max_sum_brute_force, max_sum_sliding]:
        start = time.perf_counter()
        solve(big, k)
        print(f"  {solve.__name__:<20} {time.perf_counter() - start:.4f} s")

    print()
    run_tests()
