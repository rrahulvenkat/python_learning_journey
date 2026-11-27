# Permutations (LeetCode 46 and 47)
#
# PROBLEM
# -------
# Given a list of DISTINCT numbers, return every possible ordering.
#
#   [1, 2, 3]  ->  [1,2,3] [1,3,2] [2,1,3] [2,3,1] [3,1,2] [3,2,1]
#
# n items have n! orderings: n choices for the first position, n - 1
# for the second, and so on.
#
# KEY IDEAS
# ---------
#   - Same backtracking template as subsets.py (choose, explore,
#     un-choose), with one difference: ORDER MATTERS now. So each
#     level loops over ALL the numbers, not just the ones after
#     `start`, and skips numbers already USED in the current path.
#   - Record the path only when it's FULL (a leaf of the tree), not at
#     every node.
#   - With duplicates (LeetCode 47), sort first and skip a number if
#     it equals the previous one AND that previous one isn't in use.
#     That stops two identical 1s producing the same ordering twice.
#
# WHAT'S NEW HERE
# ---------------
# A `used` list that marks which items are taken, and the "swap in
# place" alternative that needs no extra list at all.
#
# SECURITY CONNECTION
# -------------------
# SMUDGE ATTACKS: grease marks on a phone screen or keypad show WHICH
# digits are in a PIN, but not their order. If 4 different digits are
# smudged, there are only 4! = 24 possible PINs instead of 10,000.
# With 3 smudged digits (one used twice) there are 36. Counting
# arrangements is how you measure how much a leak like this weakens a
# secret (variation 1). The same counting explains why a password
# made by shuffling a few known words is weak.


from itertools import permutations as itertools_permutations, product
from math import factorial


# ---------------------------------------------------------------
# Solution 1: backtracking with a `used` list
# ---------------------------------------------------------------
#
# Trace for [1, 2, 3] (first few steps):
#
#   path      | used        | action
#   ----------|-------------|---------------------------------
#   []        | F F F       | try 1
#   [1]       | T F F       | try 2 (1 is used, skip it)
#   [1, 2]    | T T F       | try 3
#   [1, 2, 3] | T T T       | full: record it, go back
#   [1, 2]    | T T F       | pop 3; nothing left at this level, go back
#   [1]       | T F F       | pop 2; try 3
#   [1, 3]    | T F T       | try 2
#   [1, 3, 2] | T T T       | full: record it
#   ...

def permute(nums):
    result = []
    path = []
    used = [False] * len(nums)

    def backtrack():
        if len(path) == len(nums):
            result.append(path[:])
            return
        for i in range(len(nums)):
            if used[i]:
                continue
            used[i] = True                   # choose
            path.append(nums[i])
            backtrack()                      # explore
            path.pop()                       # un-choose
            used[i] = False

    backtrack()
    return result


# ---------------------------------------------------------------
# Solution 2: swap in place
# ---------------------------------------------------------------
#
# Positions 0 .. first-1 are already decided. For position `first`,
# swap each remaining item into it, recurse for the rest, then swap
# back. No `path` or `used` list is needed.
#
#   first = 0:  swap 1<->1 [1,2,3], swap 1<->2 [2,1,3], swap 1<->3 [3,2,1]
#   then for each, first = 1 does the same with the remaining items.

def permute_swap(nums):
    nums = list(nums)
    result = []

    def backtrack(first):
        if first == len(nums):
            result.append(nums[:])
            return
        for i in range(first, len(nums)):
            nums[first], nums[i] = nums[i], nums[first]   # choose
            backtrack(first + 1)                          # explore
            nums[first], nums[i] = nums[i], nums[first]   # un-choose

    backtrack(0)
    return result


# ---------------------------------------------------------------
# Variation 1: Permutations II (LeetCode 47)  -  with duplicates
# ---------------------------------------------------------------
#
#   [1, 1, 2]  ->  [1,1,2] [1,2,1] [2,1,1]     (3, not 3! = 6)
#
# After sorting, equal values are neighbours. The rule
#     skip nums[i] if nums[i] == nums[i-1] and nums[i-1] is NOT used
# means the identical copies are always used left to right, so each
# distinct ordering is built exactly once.

def permute_unique(nums):
    nums = sorted(nums)
    result = []
    path = []
    used = [False] * len(nums)

    def backtrack():
        if len(path) == len(nums):
            result.append(path[:])
            return
        for i in range(len(nums)):
            if used[i]:
                continue
            if i > 0 and nums[i] == nums[i - 1] and not used[i - 1]:
                continue                     # an identical copy wasn't used yet
            used[i] = True
            path.append(nums[i])
            backtrack()
            path.pop()
            used[i] = False

    backtrack()
    return result


# ---------------------------------------------------------------
# Variation 2: PIN candidates from a smudge pattern
# ---------------------------------------------------------------
#
# Return every PIN of `length` digits that uses EVERY smudged digit
# at least once and no other digits.
#
#   4 smudged digits, length 4: each digit exactly once -> 4! = 24
#   3 smudged digits, length 4: one digit appears twice -> 36
#   2 smudged digits, length 4:                          -> 14
#
# This is backtracking with a CONSTRAINT checked at the leaf, plus
# PRUNING: if the digits still missing outnumber the positions left,
# stop early.

def smudge_candidates(smudged, length=4):
    smudged = sorted(set(smudged))
    result = []
    path = []

    def backtrack():
        missing = len(set(smudged) - set(path))
        if missing > length - len(path):
            return                           # prune: can't fit them all in
        if len(path) == length:
            result.append("".join(path))
            return
        for digit in smudged:
            path.append(digit)
            backtrack()
            path.pop()

    backtrack()
    return result


# ---------------------------------------------------------------
# COMPLEXITY (n = number of items)
# ---------------------------------------------------------------
#
#   Solution                 | Time          | Output size
#   -------------------------|---------------|--------------
#   1. Backtracking + used   | O(n * n!)     | n! orderings
#   2. Swap in place         | O(n * n!)     |
#   Permutations II          | O(n * n!)     | fewer with duplicates
#   Smudge candidates        | O(k^L) before pruning, k digits, length L
#
#   n  |  n!
#   ---|---------------
#   5  |  120
#   10 |  3,628,800
#   15 |  1,307,674,368,000
#
# n! grows even faster than 2^n. itertools.permutations generates
# them one at a time (a generator), so it doesn't have to hold them
# all in memory.


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    import random

    for nums in [[], [1], [0, 1], [1, 2, 3], [5, 3, 8, 1], list(range(6))]:
        expected = sorted(list(p) for p in itertools_permutations(nums))
        for solve in [permute, permute_swap]:
            result = solve(nums)
            assert len(result) == factorial(len(nums))
            assert sorted(result) == expected, (solve.__name__, nums)

    # LeetCode 46 example
    assert sorted(permute([1, 2, 3])) == [[1, 2, 3], [1, 3, 2], [2, 1, 3],
                                         [2, 3, 1], [3, 1, 2], [3, 2, 1]]
    assert permute_swap([7]) == [[7]]

    # LeetCode 47
    assert sorted(permute_unique([1, 1, 2])) == [[1, 1, 2], [1, 2, 1], [2, 1, 1]]
    assert len(permute_unique([1, 2, 3])) == 6
    assert permute_unique([2, 2, 2]) == [[2, 2, 2]]
    random.seed(9)
    for _ in range(100):
        nums = [random.randint(0, 2) for _ in range(random.randint(0, 6))]
        expected = sorted(set(itertools_permutations(nums)))
        result = [tuple(p) for p in permute_unique(nums)]
        assert len(result) == len(set(result))           # no duplicates
        assert sorted(result) == expected

    # Smudges: check against brute force over every possible PIN
    for smudged in ["1379", "258", "05", "7"]:
        brute = sorted("".join(p) for p in product("0123456789", repeat=4)
                       if set(p) == set(smudged))
        assert smudge_candidates(smudged) == brute, smudged
    assert len(smudge_candidates("1379")) == 24
    assert len(smudge_candidates("258")) == 36
    assert len(smudge_candidates("05")) == 14
    assert smudge_candidates("7") == ["7777"]
    assert smudge_candidates("12345") == []              # 5 digits can't fit in 4

    print("All tests passed!")


if __name__ == "__main__":
    print(f"Permutations of [1, 2, 3]: {permute([1, 2, 3])}")
    print(f"Unique permutations of [1, 1, 2]: {permute_unique([1, 1, 2])}")

    print("\nSmudge attack on a 4-digit PIN (10,000 possible PINs):")
    for smudged in ["1379", "258", "05"]:
        candidates = smudge_candidates(smudged)
        print(f"  smudges on {', '.join(smudged):<10} -> {len(candidates):>2} candidates, "
              f"e.g. {', '.join(candidates[:4])}")
    print("  Fewer distinct digits is NOT safer here: 4 different digits "
          "leave the fewest options.")

    print("\nn! grows fast:")
    for n in (5, 10, 15, 20):
        print(f"  {n:>2}! = {factorial(n):,}")

    print()
    run_tests()
