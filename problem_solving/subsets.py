# Subsets (LeetCode 78)  -  the backtracking template
# (includes LeetCode 90 Subsets II, and LeetCode 39 Combination Sum)
#
# PROBLEM
# -------
# Given a list of DISTINCT numbers, return every possible subset
# (the "power set"), including the empty set and the full set.
#
#   [1, 2, 3]  ->  [], [1], [2], [3], [1, 2], [1, 3], [2, 3], [1, 2, 3]
#
# A list of n items has 2^n subsets: each item is either IN or OUT.
#
# KEY IDEAS
# ---------
# BACKTRACKING is a way to try every possibility systematically:
#
#   1. CHOOSE   make one choice and add it to the current path
#   2. EXPLORE  recurse to make the remaining choices
#   3. UN-CHOOSE  undo the choice (pop it off) and try the next one
#
# Picture a tree of decisions. Backtracking walks it depth-first,
# undoing each step on the way back up so the SAME path list can be
# reused for every branch.
#
#                         []
#            /            |           \
#          [1]           [2]          [3]
#        /     \          |
#     [1,2]   [1,3]     [2,3]
#       |
#    [1,2,3]
#
# Every node in this tree is a subset, so record the path at EVERY
# node. Starting each level from `start` (not 0) means [2, 1] is never
# built after [1, 2]: order doesn't matter in a subset.
#
# PRUNING: if a branch can't possibly lead to an answer, stop
# exploring it. That's what keeps backtracking usable (Combination Sum
# below stops as soon as the total is too big).
#
# WHAT'S NEW HERE
# ---------------
# fundamentals/functions.py showed recursion with ONE recursive call.
# Backtracking makes a recursive call for EACH choice, in a loop, and
# undoes its change after each one. You'll use this template in
# permutations.py, letter_combinations.py and generate_parentheses.py.
#
# SECURITY CONNECTION
# -------------------
#   - LEAST PRIVILEGE: "what is the SMALLEST set of roles that gives a
#     user exactly the permissions they need?" means searching subsets
#     of roles (variation 3).
#   - 2^n is why exhaustive search breaks down fast: 20 roles have about
#     a million subsets, 40 have about a trillion. That same growth is
#     why longer passwords and keys are so much stronger.


from itertools import combinations


# ---------------------------------------------------------------
# Solution 1: iterative (start from [] and keep doubling)
# ---------------------------------------------------------------
#
# For each new number, copy every subset you have so far and add the
# number to the copy.
#
#   start:        [[]]
#   add 1:        [[], [1]]
#   add 2:        [[], [1], [2], [1, 2]]
#   add 3:        [[], [1], [2], [1, 2], [3], [1, 3], [2, 3], [1, 2, 3]]

def subsets_iterative(nums):
    result = [[]]
    for num in nums:
        result += [subset + [num] for subset in result]
    return result


# ---------------------------------------------------------------
# Solution 2: backtracking (the template)
# ---------------------------------------------------------------
#
# Trace for [1, 2, 3] (path is the current subset):
#
#   call (start) | path      | record | loop tries
#   -------------|-----------|--------|-------------------------
#   0            | []        | []     | 1, 2, 3
#   1            | [1]       | [1]    | 2, 3
#   2            | [1, 2]    | [1, 2] | 3
#   3            | [1, 2, 3] | [1,2,3]| (nothing left)
#   back to [1, 2], pop 2 ->  [1], try 3
#   3            | [1, 3]    | [1, 3] | (nothing left)
#   ...and so on for [2], [2, 3], [3]
#
# path[:] (a COPY) is recorded, because `path` keeps changing. Storing
# `path` itself would store the same list 8 times, and it ends empty.

def subsets(nums):
    result = []
    path = []

    def backtrack(start):
        result.append(path[:])               # every node is a subset
        for i in range(start, len(nums)):
            path.append(nums[i])             # 1. choose
            backtrack(i + 1)                 # 2. explore
            path.pop()                       # 3. un-choose

    backtrack(0)
    return result


# ---------------------------------------------------------------
# Solution 3: bitmasks (counting from 0 to 2^n - 1)
# ---------------------------------------------------------------
#
# Each number from 0 to 2^n - 1 is a different pattern of n bits. Bit
# i says whether nums[i] is in the subset (the masks from
# counting_bits.py):
#
#   mask | bits | subset
#   -----|------|---------
#    0   | 000  | []
#    1   | 001  | [1]
#    2   | 010  | [2]
#    3   | 011  | [1, 2]
#    ... | ...  | ...
#    7   | 111  | [1, 2, 3]

def subsets_bitmask(nums):
    n = len(nums)
    return [[nums[i] for i in range(n) if mask & (1 << i)]
            for mask in range(1 << n)]


# ---------------------------------------------------------------
# Variation 1: Subsets II (LeetCode 90)  -  input WITH duplicates
# ---------------------------------------------------------------
#
#   [1, 2, 2]  ->  [], [1], [1, 2], [1, 2, 2], [2], [2, 2]
#   (only one [1, 2] and one [2], even though there are two 2s)
#
# Sort first so equal numbers sit together. Then, at each level of
# the tree, skip a number if it's the same as the one just tried AT
# THIS LEVEL (i > start). Using a duplicate deeper down is still fine:
# that's how [2, 2] gets built.

def subsets_with_dup(nums):
    nums = sorted(nums)
    result = []
    path = []

    def backtrack(start):
        result.append(path[:])
        for i in range(start, len(nums)):
            if i > start and nums[i] == nums[i - 1]:
                continue                     # same choice at the same level
            path.append(nums[i])
            backtrack(i + 1)
            path.pop()

    backtrack(0)
    return result


# ---------------------------------------------------------------
# Variation 2: Combination Sum (LeetCode 39)  -  pruning
# ---------------------------------------------------------------
#
# Given distinct positive candidates, find every combination that
# adds up to target. Each number may be used ANY number of times.
#
#   candidates = [2, 3, 6, 7], target = 7  ->  [[2, 2, 3], [7]]
#
# Two changes to the template:
#   - recurse with i, not i + 1, so the same number can be used again
#   - PRUNE: candidates are sorted, so once one is too big, every
#     later one is too, and the loop can stop (break, not continue)

def combination_sum(candidates, target):
    candidates = sorted(candidates)
    result = []
    path = []

    def backtrack(start, remaining):
        if remaining == 0:
            result.append(path[:])
            return
        for i in range(start, len(candidates)):
            if candidates[i] > remaining:
                break                        # prune this and every bigger one
            path.append(candidates[i])
            backtrack(i, remaining - candidates[i])   # i: reuse allowed
            path.pop()

    backtrack(0, target)
    return result


# ---------------------------------------------------------------
# Variation 3: the smallest set of roles that covers the needed permissions
# ---------------------------------------------------------------
#
# Each role grants a set of permissions. Find the FEWEST roles whose
# permissions together include everything `needed`, and among those,
# the one granting the fewest EXTRA permissions (least privilege).
#
# Try subsets in order of size (itertools.combinations gives every
# subset of size k). The first size with any answer is the smallest.
# This is the "set cover" problem, which has no known fast solution in
# general, so exhaustive search is the honest approach for small
# inputs.

def smallest_role_set(roles, needed):
    names = sorted(roles)
    for size in range(len(names) + 1):
        best = None
        for combo in combinations(names, size):
            granted = set().union(*(roles[r] for r in combo))
            if needed <= granted:
                extra = len(granted - needed)
                if best is None or extra < best[1]:
                    best = (list(combo), extra)
        if best:
            return best
    return None                              # impossible even with every role


# ---------------------------------------------------------------
# COMPLEXITY (n = number of items)
# ---------------------------------------------------------------
#
#   Solution                 | Time           | Output size
#   -------------------------|----------------|-------------------
#   1. Iterative             | O(n * 2^n)     | 2^n subsets
#   2. Backtracking          | O(n * 2^n)     |
#   3. Bitmask               | O(n * 2^n)     |
#   Subsets II               | O(n * 2^n)     | fewer if duplicates
#   Combination Sum          | exponential, cut down by pruning
#   Smallest role set        | O(2^r * p)     | r roles, p permissions
#
# Nothing can be faster than the size of the output, and the output
# itself is 2^n subsets. n = 20 is about a million; n = 30 is about a
# billion.


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def canonical(list_of_lists):
    """Sort each inner list and the outer list, so order doesn't matter."""
    return sorted(sorted(x) for x in list_of_lists)


def run_tests():
    import random

    # All three agree, and match itertools
    for nums in [[], [0], [1, 2], [1, 2, 3], [4, 1, 9, 7], list(range(8))]:
        expected = canonical(list(c) for k in range(len(nums) + 1)
                             for c in combinations(nums, k))
        for solve in [subsets_iterative, subsets, subsets_bitmask]:
            result = solve(nums)
            assert len(result) == 2 ** len(nums)
            assert canonical(result) == expected, (solve.__name__, nums)

    # LeetCode 78 examples
    assert canonical(subsets([1, 2, 3])) == canonical(
        [[], [1], [2], [1, 2], [3], [1, 3], [2, 3], [1, 2, 3]])
    assert subsets([0]) == [[], [0]]

    # Subsets II: no duplicate subsets
    assert canonical(subsets_with_dup([1, 2, 2])) == canonical(
        [[], [1], [1, 2], [1, 2, 2], [2], [2, 2]])
    assert subsets_with_dup([0]) == [[], [0]]
    random.seed(8)
    for _ in range(100):
        nums = [random.randint(0, 3) for _ in range(random.randint(0, 7))]
        expected = {tuple(sorted(s)) for s in subsets(nums)}     # dedupe the slow way
        result = [tuple(s) for s in subsets_with_dup(nums)]
        assert len(result) == len(set(result)) == len(expected)
        assert set(result) == expected

    # Combination Sum (LeetCode 39 examples)
    assert canonical(combination_sum([2, 3, 6, 7], 7)) == [[2, 2, 3], [7]]
    assert canonical(combination_sum([2, 3, 5], 8)) == [[2, 2, 2, 2], [2, 3, 3], [3, 5]]
    assert combination_sum([2], 1) == []
    for combo in combination_sum([3, 4, 5, 7], 20):
        assert sum(combo) == 20

    # Roles
    roles = {
        "viewer":   {"read"},
        "editor":   {"read", "write"},
        "auditor":  {"read", "read_logs"},
        "operator": {"restart", "read_logs"},
        "admin":    {"read", "write", "delete", "restart", "read_logs", "manage_users"},
    }
    assert smallest_role_set(roles, {"read"}) == (["viewer"], 0)
    # admin alone covers these with 1 role, which beats any pair, even
    # though a pair would grant fewer extra permissions
    assert smallest_role_set(roles, {"write", "read_logs"}) == (["admin"], 4)
    assert smallest_role_set(roles, {"write", "restart"}) == (["admin"], 4)
    roles_no_admin = {k: v for k, v in roles.items() if k != "admin"}
    assert smallest_role_set(roles_no_admin, {"write", "restart"}) == (["editor", "operator"], 2)
    assert smallest_role_set(roles_no_admin, {"manage_users"}) is None
    assert smallest_role_set(roles, set()) == ([], 0)

    print("All tests passed!")


if __name__ == "__main__":
    nums = [1, 2, 3]
    print(f"Subsets of {nums}:")
    for s in subsets(nums):
        print("  ", s)

    print(f"\nWith duplicates, subsets of [1, 2, 2]: {subsets_with_dup([1, 2, 2])}")
    print(f"Combinations of [2, 3, 6, 7] adding to 7: {combination_sum([2, 3, 6, 7], 7)}")

    roles = {
        "viewer":   {"read"},
        "editor":   {"read", "write"},
        "auditor":  {"read", "read_logs"},
        "operator": {"restart", "read_logs"},
        "deployer": {"write", "restart", "deploy"},
    }
    needed = {"write", "read_logs", "restart"}
    combo, extra = smallest_role_set(roles, needed)
    print(f"\nA user needs {sorted(needed)}.")
    print(f"  Smallest role set: {combo}, granting {extra} extra permission(s)")

    print("\nHow fast 2^n grows:")
    for n in (10, 20, 30, 40):
        print(f"  {n} items -> {2 ** n:,} subsets")

    print()
    run_tests()
