# Two Sum (LeetCode 1)
#
# PROBLEM
# -------
# Given a list of integers `nums` and an integer `target`, return the
# INDEXES of the two numbers that add up to `target`.
#
#   - Each input has exactly one solution.
#   - You can't use the same element twice.
#   - The answer can be in any order.
#
# Example:
#   nums = [2, 7, 11, 15], target = 9
#   nums[0] + nums[1] = 2 + 7 = 9   ->   return [0, 1]
#
# KEY IDEAS
# ---------
#   - Brute force: try every pair. Simple but slow, O(n^2).
#   - The trick: for each number x, the number you NEED is
#     target - x (its "complement"). Instead of searching the list for
#     it, remember every number you've seen in a dictionary
#     {number: index}. Checking a dictionary is O(1), so the whole
#     thing becomes O(n).
#   - Watch out for duplicates (nums = [3, 3], target = 6) and for
#     using the same element twice (nums = [3, 4], target = 6 must
#     NOT return [0, 0]).
#
# This problem teaches the most common interview pattern of all:
# trading memory (a dictionary or set) for speed.


# ---------------------------------------------------------------
# Solution 1: brute force (check every pair)
# ---------------------------------------------------------------
#
# For each index i, check every index j after it.
# j starts at i + 1, so an element is never paired with itself and
# no pair is checked twice.

def two_sum_brute_force(nums, target):
    for i in range(len(nums)):
        for j in range(i + 1, len(nums)):
            if nums[i] + nums[j] == target:
                return [i, j]
    return []


# ---------------------------------------------------------------
# Solution 2: hash map, one pass (the optimal answer)
# ---------------------------------------------------------------
#
# Walk through the list once. For each number:
#   1. Work out the complement: target - number
#   2. If the complement is already in `seen`, you've found the pair.
#   3. Otherwise, store this number and its index in `seen`.
#
# Trace for nums = [2, 7, 11, 15], target = 9:
#
#   i | num | complement | seen before        | action
#   --|-----|------------|-------------------|------------------
#   0 |  2  |     7      | {}                | store 2 -> 0
#   1 |  7  |     2      | {2: 0}            | found! return [0, 1]
#
# Checking BEFORE storing is what stops an element being used twice.

def two_sum(nums, target):
    seen = {}                                 # number -> index

    for i, num in enumerate(nums):
        complement = target - num
        if complement in seen:
            return [seen[complement], i]
        seen[num] = i

    return []


# ---------------------------------------------------------------
# Solution 3: sort + two pointers
# ---------------------------------------------------------------
#
# If the list is sorted, put one pointer at each end:
#   - sum too small -> move left pointer right (bigger number)
#   - sum too big   -> move right pointer left (smaller number)
#
# Sorting would lose the original indexes, so sort (value, index)
# pairs instead. This is O(n log n) because of the sort, so it's
# slower than Solution 2 here, but it's THE answer for
# "Two Sum II" (LeetCode 167), where the input is already sorted.

def two_sum_two_pointers(nums, target):
    pairs = sorted((num, i) for i, num in enumerate(nums))
    left, right = 0, len(pairs) - 1

    while left < right:
        current = pairs[left][0] + pairs[right][0]
        if current == target:
            return sorted([pairs[left][1], pairs[right][1]])
        if current < target:
            left += 1
        else:
            right -= 1

    return []


# ---------------------------------------------------------------
# Variation: return ALL unique pairs of VALUES that add up to target
# ---------------------------------------------------------------
#
#   nums = [1, 5, 3, 3, 2, 4, 1], target = 6  ->  [(1, 5), (2, 4), (3, 3)]
#
# Uses a set to remember seen numbers and another set to avoid
# reporting the same pair twice.

def all_pairs(nums, target):
    seen = set()
    pairs = set()

    for num in nums:
        complement = target - num
        if complement in seen:
            pairs.add((min(num, complement), max(num, complement)))
        seen.add(num)

    return sorted(pairs)


# ---------------------------------------------------------------
# COMPLEXITY (n = length of nums)
# ---------------------------------------------------------------
#
#   Solution                  | Time        | Extra space
#   --------------------------|-------------|-------------------
#   1. Brute force            | O(n^2)      | O(1)
#   2. Hash map (one pass)    | O(n)        | O(n)  the dictionary
#   3. Sort + two pointers    | O(n log n)  | O(n)  the sorted pairs
#   All pairs variation       | O(n)        | O(n)
#
# For n = 10,000: brute force does about 50 million checks, the hash
# map does 10,000.


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    test_cases = [
        # (nums, target, expected)
        ([2, 7, 11, 15], 9, [0, 1]),          # LeetCode example 1
        ([3, 2, 4], 6, [1, 2]),               # must not return [0, 0]
        ([3, 3], 6, [0, 1]),                  # duplicates
        ([-3, 4, 3, 90], 0, [0, 2]),          # negative numbers
        ([0, 4, 3, 0], 0, [0, 3]),            # zeros
        ([1, 5, 9, 14, 20], 34, [3, 4]),      # pair at the end
        ([1, 2], 4, []),                      # no solution
    ]

    solutions = [two_sum_brute_force, two_sum, two_sum_two_pointers]

    for solve in solutions:
        for nums, target, expected in test_cases:
            result = solve(nums, target)
            assert sorted(result) == expected, (
                f"{solve.__name__}({nums}, {target}) returned {result}, expected {expected}"
            )

    # A big input: the answer is at the very end
    big = list(range(10_000))
    assert two_sum(big, 19_997) == [9_998, 9_999]

    # All pairs variation
    assert all_pairs([1, 5, 3, 3, 2, 4, 1], 6) == [(1, 5), (2, 4), (3, 3)]
    assert all_pairs([1, 2, 3], 100) == []
    assert all_pairs([3], 6) == []            # one 3 can't pair with itself

    print("All tests passed!")


if __name__ == "__main__":
    import time

    nums = [2, 7, 11, 15]
    target = 9
    i, j = two_sum(nums, target)
    print(f"nums = {nums}, target = {target}")
    print(f"Answer: [{i}, {j}] because {nums[i]} + {nums[j]} = {target}")

    print("\nAll value pairs adding to 6 in [1, 5, 3, 3, 2, 4, 1]:",
          all_pairs([1, 5, 3, 3, 2, 4, 1], 6))

    # Speed comparison on a list of 5,000 numbers, answer at the end
    big = list(range(5_000))
    big_target = big[-1] + big[-2]
    print(f"\nSpeed test with {len(big):,} numbers:")
    for solve in [two_sum_brute_force, two_sum, two_sum_two_pointers]:
        start = time.perf_counter()
        solve(big, big_target)
        elapsed = time.perf_counter() - start
        print(f"  {solve.__name__:<22} {elapsed:.4f} s")

    print()
    run_tests()
