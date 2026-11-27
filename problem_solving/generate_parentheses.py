# Generate Parentheses (LeetCode 22)  -  pruning, and fuzzing with generated input
#
# PROBLEM
# -------
# Given n, return every string of n pairs of WELL-FORMED parentheses.
#
#   n = 1  ->  ()
#   n = 2  ->  (()) ()()
#   n = 3  ->  ((())) (()()) (())() ()(()) ()()()
#
# KEY IDEAS
# ---------
#   - Brute force: generate all 2^(2n) strings of ( and ), then keep
#     the valid ones. Most are invalid, so most of the work is wasted.
#   - Backtracking with PRUNING: build the string one character at a
#     time, and only ever add a character that can still lead to a
#     valid string:
#       add "(" only if fewer than n have been opened
#       add ")" only if it closes something (closed < opened)
#     Every leaf the search reaches is a valid answer, so nothing is
#     wasted.
#   - The number of answers is the CATALAN number C(n):
#       1, 1, 2, 5, 14, 42, 132, 429, ...
#
# WHAT'S NEW HERE
# ---------------
# valid_parentheses.py CHECKED strings. This file GENERATES them, and
# shows how pruning turns an exponential search into one that only
# visits useful branches. It also reuses valid_parentheses.py as a
# module (the `if __name__ == "__main__":` guard from
# fundamentals/modules_and_imports.py is what makes that safe).
#
# SECURITY CONNECTION
# -------------------
# FUZZING means feeding a program huge numbers of generated inputs to
# find the ones that break it. Two common styles:
#   - EXHAUSTIVE: every input up to a small size. Bugs usually show up
#     on small inputs, and you find the SMALLEST failing one.
#   - DIFFERENTIAL: run two implementations on the same input and flag
#     any disagreement.
# The demo fuzzes a deliberately buggy bracket checker and finds the
# shortest input that fools it. Real fuzzers (AFL, libFuzzer, Python's
# Atheris) find security bugs in parsers this way.


from itertools import product
from math import comb

from valid_parentheses import is_valid as reference_is_valid


# ---------------------------------------------------------------
# Solution 1: brute force (generate everything, then filter)
# ---------------------------------------------------------------

def generate_brute_force(n):
    return ["".join(chars) for chars in product("()", repeat=2 * n)
            if reference_is_valid("".join(chars))]


# ---------------------------------------------------------------
# Solution 2: backtracking with pruning (the optimal answer)
# ---------------------------------------------------------------
#
# Trace for n = 2 (opened, closed in brackets):
#
#   ""        (0,0)  can open
#   "("       (1,0)  can open, can close
#   "(("      (2,0)  can only close
#   "(()"     (2,1)  can only close
#   "(())"    (2,2)  full: record
#   back to "(" ... close instead:
#   "()"      (1,1)  can open (can't close: nothing open)
#   "()("     (2,1)  can only close
#   "()()"    (2,2)  full: record

def generate_parentheses(n):
    result = []
    path = []

    def backtrack(opened, closed):
        if len(path) == 2 * n:
            result.append("".join(path))
            return
        if opened < n:
            path.append("(")
            backtrack(opened + 1, closed)
            path.pop()
        if closed < opened:
            path.append(")")
            backtrack(opened, closed + 1)
            path.pop()

    backtrack(0, 0)
    return result


# ---------------------------------------------------------------
# Counting the work, and the Catalan formula
# ---------------------------------------------------------------
#
#   catalan(n) = comb(2n, n) / (n + 1)
#
# count_nodes() runs the same search but counts every node visited,
# so you can compare it with the 2^(2n) strings brute force builds.

def catalan(n):
    return comb(2 * n, n) // (n + 1)


def count_nodes(n):
    visited = 0

    def backtrack(opened, closed):
        nonlocal visited
        visited += 1
        if opened + closed == 2 * n:
            return
        if opened < n:
            backtrack(opened + 1, closed)
        if closed < opened:
            backtrack(opened, closed + 1)

    backtrack(0, 0)
    return visited


# ---------------------------------------------------------------
# Variation 1: exhaustive differential fuzzing
# ---------------------------------------------------------------
#
# Generate EVERY string over an alphabet up to max_length, shortest
# first, and return the first one where `candidate` disagrees with
# `reference`. Shortest first means the failing input you get back is
# as small as possible, which makes the bug easy to understand.

def fuzz(candidate, reference, alphabet="()[]{}", max_length=6):
    for length in range(max_length + 1):
        for chars in product(alphabet, repeat=length):
            text = "".join(chars)
            if candidate(text) != reference(text):
                return text
    return None


# Three checkers to fuzz. Each has a realistic bug.

def buggy_counts_only(s):
    """Checks each bracket type is balanced, but ignores ORDER."""
    return all(s.count(o) == s.count(c) for o, c in ("()", "[]", "{}"))


def buggy_no_empty_check(s):
    """Uses a stack, but forgets to check it's empty at the end."""
    pairs = {")": "(", "]": "[", "}": "{"}
    stack = []
    for ch in s:
        if ch in pairs:
            if not stack or stack.pop() != pairs[ch]:
                return False
        else:
            stack.append(ch)
    return True                              # bug: should be `not stack`


def buggy_peek_only(s):
    """Checks the top matches, but never POPS it, so nothing ever closes."""
    pairs = {")": "(", "]": "[", "}": "{"}
    stack = []
    for ch in s:
        if ch in pairs:
            if not stack or stack[-1] != pairs[ch]:
                return False                 # bug: missing stack.pop() after this check
        else:
            stack.append(ch)
    return not stack


# ---------------------------------------------------------------
# COMPLEXITY
# ---------------------------------------------------------------
#
#   Solution             | Strings / nodes visited     | n = 10
#   ---------------------|-----------------------------|---------------
#   1. Brute force       | 2^(2n) strings, each O(n)   | 1,048,576
#   2. Backtracking      | about 4^n / n^1.5 nodes     | 82,499
#   Answers (Catalan)    | C(n)                        | 16,796
#
# Pruning doesn't change the size of the OUTPUT, but it stops the
# search from wandering into branches that can never become answers.


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    # LeetCode examples
    assert sorted(generate_parentheses(3)) == sorted(
        ["((()))", "(()())", "(())()", "()(())", "()()()"])
    assert generate_parentheses(1) == ["()"]
    assert generate_parentheses(0) == [""]

    for n in range(0, 9):
        result = generate_parentheses(n)
        assert len(result) == catalan(n), n
        assert len(set(result)) == len(result)           # no duplicates
        assert all(reference_is_valid(s) for s in result)
        if n <= 6:
            assert sorted(result) == sorted(generate_brute_force(n))

    assert [catalan(n) for n in range(8)] == [1, 1, 2, 5, 14, 42, 132, 429]
    assert count_nodes(10) < 2 ** 20

    # The fuzzer finds the smallest input each buggy checker gets wrong
    assert fuzz(reference_is_valid, reference_is_valid) is None      # agrees with itself
    assert fuzz(buggy_counts_only, reference_is_valid) == ")("
    assert fuzz(buggy_no_empty_check, reference_is_valid) == "("
    assert fuzz(buggy_peek_only, reference_is_valid) == "()"         # rejects valid input

    print("All tests passed!")


if __name__ == "__main__":
    print(f"n = 3: {generate_parentheses(3)}")

    print(f"\n{'n':>3} {'answers':>9} {'nodes visited':>14} {'brute-force strings':>20}")
    for n in (4, 6, 8, 10, 12):
        print(f"{n:>3} {catalan(n):>9,} {count_nodes(n):>14,} {2 ** (2 * n):>20,}")

    print("\nFuzzing three buggy bracket checkers against the correct one:")
    for checker in [buggy_counts_only, buggy_no_empty_check, buggy_peek_only]:
        bad = fuzz(checker, reference_is_valid)
        print(f"  {checker.__name__:<22} smallest failing input: {bad!r:<8} "
              f"(says {checker(bad)}, should be {reference_is_valid(bad)})")

    print()
    run_tests()
