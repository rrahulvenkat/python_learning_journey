# How a Regex Engine Works, and Why Some Patterns Freeze
# (includes LeetCode 10, Regular Expression Matching)
#
# PROBLEM
# -------
#   1. Write a tiny regex matcher supporting   c  .  *  ^  $
#   2. LeetCode 10: does the pattern match the WHOLE string, where
#        .  matches any single character
#        *  matches zero or more of the character before it
#
#        ("aa", "a")        ->  False
#        ("aa", "a*")       ->  True
#        ("ab", ".*")       ->  True
#        ("aab", "c*a*b")   ->  True    c* matches nothing, a* matches "aa"
#
#   3. See why a pattern like (a+)+$ can take seconds on a short
#      string, and how to fix it.
#
# KEY IDEAS
# ---------
#   - Python's `re` is a BACKTRACKING engine. At every choice ("should
#     this * take one more character or stop?") it tries one option,
#     and if the rest fails it goes back and tries the other. That's
#     recursion, exactly like the matchers below.
#   - Backtracking can explode: if a pattern can match the same text
#     in MANY different ways, a failing match tries every one of them.
#     (a+)+ can split "aaaa" into a+ groups 2^(n-1) ways.
#   - MEMOIZATION fixes the explosion for LeetCode 10: the answer only
#     depends on two positions (i in the text, j in the pattern), so
#     remember each (i, j) answer and never work it out twice. That
#     turns exponential time into O(len(text) * len(pattern)). This
#     "remember the answers to sub-problems" idea is DYNAMIC
#     PROGRAMMING, which you first saw in counting_bits.py.
#
# WHAT'S NEW HERE
# ---------------
# regex_fundamentals.py and log_parsing.py USED regex. This file
# BUILDS one, which explains the behaviour you've seen (greedy *,
# anchors) and introduces memoization with functools.lru_cache.
#
# SECURITY CONNECTION
# -------------------
# ReDoS (Regular expression Denial of Service): if an attacker can
# send input to a vulnerable pattern, one short request can keep a
# CPU busy for seconds or forever. Real incidents:
#   - Stack Overflow (July 2016): a regex that trimmed whitespace hit
#     a post with about 20,000 spaces and took the site down.
#   - Cloudflare (July 2019): one WAF rule containing .*(?:.*=.*)
#     maxed out CPUs worldwide and caused a global outage.
# Defences: avoid nested quantifiers, use atomic groups or
# possessive quantifiers, limit input length, or use an engine
# without backtracking (like Google's RE2).


import re
import time
from functools import lru_cache


# ---------------------------------------------------------------
# Part 1: a tiny regex matcher (after Rob Pike and Brian Kernighan)
# ---------------------------------------------------------------
#
# Supports:  c (literal)  .  (any char)  *  (zero or more of previous)
#            ^ (start)   $  (end)
# Like re.search, it finds a match ANYWHERE unless the pattern starts
# with ^.
#
#   match_here(p, t)  does pattern p match at the START of text t?
#   match_star(c, p, t)  c* followed by p, at the start of t
#
# match_star is SHORTEST-first (lazy): it tries zero copies of c,
# then one, then two... Real engines are greedy (longest first), but
# both give the same True/False answer.

def tiny_search(pattern, text):
    if pattern.startswith("^"):
        return match_here(pattern[1:], text)
    for start in range(len(text) + 1):          # +1: an empty pattern matches at the end
        if match_here(pattern, text[start:]):
            return True
    return False


def match_here(pattern, text):
    if not pattern:
        return True                             # nothing left to match: success
    if len(pattern) >= 2 and pattern[1] == "*":
        return match_star(pattern[0], pattern[2:], text)
    if pattern == "$":
        return text == ""                       # $ only matches at the very end
    if text and pattern[0] in (".", text[0]):
        return match_here(pattern[1:], text[1:])
    return False


def match_star(ch, pattern, text):
    i = 0
    while True:
        if match_here(pattern, text[i:]):       # try the rest with i copies of ch
            return True
        if i < len(text) and ch in (".", text[i]):
            i += 1                              # take one more copy
        else:
            return False


# ---------------------------------------------------------------
# Part 2: LeetCode 10, solution 1: plain recursion
# ---------------------------------------------------------------
#
# Look at the first pattern character, and whether a * follows it:
#
#   first_ok = text is not empty and pattern[0] is "." or text[0]
#
#   pattern[1] == "*":   two choices, try both
#       skip "x*" entirely           -> is_match(text, pattern[2:])
#       use it for one character     -> first_ok and is_match(text[1:], pattern)
#   otherwise:
#       first_ok and is_match(text[1:], pattern[1:])
#
# Correct, but the two choices branch again and again: exponential in
# the worst case. `calls` counts how much work it does.

def is_match_recursive(text, pattern, calls=None):
    if calls is not None:
        calls[0] += 1
    if not pattern:
        return not text
    first_ok = bool(text) and pattern[0] in (".", text[0])
    if len(pattern) >= 2 and pattern[1] == "*":
        return (is_match_recursive(text, pattern[2:], calls) or
                (first_ok and is_match_recursive(text[1:], pattern, calls)))
    return first_ok and is_match_recursive(text[1:], pattern[1:], calls)


# ---------------------------------------------------------------
# Part 2, solution 2: memoized recursion (top-down DP)
# ---------------------------------------------------------------
#
# Same logic, but with positions i (in text) and j (in pattern)
# instead of slicing. Every call is decided by (i, j) alone, so
# @lru_cache stores each answer the first time and returns it
# instantly after that. There are only (len(text)+1) * (len(pattern)+1)
# different (i, j) pairs, so that's the most work it can ever do.

def is_match(text, pattern):
    @lru_cache(maxsize=None)
    def dp(i, j):
        if j == len(pattern):
            return i == len(text)
        first_ok = i < len(text) and pattern[j] in (".", text[i])
        if j + 1 < len(pattern) and pattern[j + 1] == "*":
            return dp(i, j + 2) or (first_ok and dp(i + 1, j))
        return first_ok and dp(i + 1, j + 1)

    return dp(0, 0)


# ---------------------------------------------------------------
# Part 2, solution 3: bottom-up DP table
# ---------------------------------------------------------------
#
# table[i][j] answers "does text[i:] match pattern[j:]?". Fill it from
# the END backwards, so every cell the formula needs is already done.
# No recursion at all, so no recursion limit.
#
# For text "aab", pattern "c*a*b", the answer is table[0][0] = True.

def is_match_table(text, pattern):
    t, p = len(text), len(pattern)
    table = [[False] * (p + 1) for _ in range(t + 1)]
    table[t][p] = True                          # empty text, empty pattern

    for i in range(t, -1, -1):
        for j in range(p - 1, -1, -1):
            first_ok = i < t and pattern[j] in (".", text[i])
            if j + 1 < p and pattern[j + 1] == "*":
                table[i][j] = table[i][j + 2] or (first_ok and table[i + 1][j])
            else:
                table[i][j] = first_ok and table[i + 1][j + 1]
    return table[0][0]


# ---------------------------------------------------------------
# Part 3: ReDoS, catastrophic backtracking in Python's re
# ---------------------------------------------------------------
#
# ^(a+)+$ on "aaaa...a!" (ending in a character that can't match):
# the engine tries every way to split the a's between the inner and
# outer +, finds the "!" each time, and backtracks. Each extra "a"
# DOUBLES the work.
#
#   ^a+$         one way to match: instant
#   ^(a+)+$      2^(n-1) ways: exponential
#   ^(?>a+)+$    atomic group (Python 3.11+): once a+ has matched, the
#                engine may not go back inside it. Instant.
#   ^(a+)++$     possessive quantifier (Python 3.11+): same effect.
#
# The patterns that cause this in real life look harmless:
#   (\w+\s?)+$           "words separated by spaces"
#   ^([a-zA-Z0-9]+\.)+com$
#   (.*a){12}

def time_match(pattern, text):
    start = time.perf_counter()
    re.match(pattern, text)
    return time.perf_counter() - start


def safe_match(pattern, text, max_length=1_000):
    """A simple defence: refuse very long input before matching."""
    if len(text) > max_length:
        raise ValueError(f"input longer than {max_length} characters")
    return re.match(pattern, text)


# ---------------------------------------------------------------
# COMPLEXITY (t = text length, p = pattern length)
# ---------------------------------------------------------------
#
#   Solution                      | Time               | Extra space
#   ------------------------------|--------------------|-------------
#   Tiny matcher                  | exponential worst  | O(t + p) recursion
#   LC 10, plain recursion        | exponential worst  | O(t + p) recursion
#   LC 10, memoized               | O(t * p)           | O(t * p) cache
#   LC 10, DP table               | O(t * p)           | O(t * p) table
#
# Python's re works like the plain recursion: fast for normal
# patterns, exponential for patterns that can match one string many
# ways. Engines like RE2 guarantee O(t * p) by never backtracking,
# but can't support backreferences.


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    # The tiny matcher agrees with re.search on its supported syntax
    tiny_cases = [
        ("abc", "xxabcxx"), ("^abc", "abcxx"), ("^abc", "xabc"),
        ("abc$", "xxabc"), ("abc$", "abcx"), ("a.c", "abc"), ("a.c", "ac"),
        ("ab*c", "ac"), ("ab*c", "abbbbc"), ("^a*$", ""), ("^a*$", "aaa"),
        ("^a*$", "aab"), ("x*", "anything"), ("^.*$", "any text"),
        ("c*a*b", "aab"), ("", ""), ("$", "abc"),
    ]
    for pattern, text in tiny_cases:
        expected = re.search(pattern, text) is not None
        assert tiny_search(pattern, text) == expected, (pattern, text)

    # LeetCode 10
    lc_cases = [
        # (text, pattern, expected)
        ("aa", "a", False),                       # LeetCode example 1
        ("aa", "a*", True),                       # LeetCode example 2
        ("ab", ".*", True),                       # LeetCode example 3
        ("aab", "c*a*b", True),
        ("mississippi", "mis*is*p*.", False),
        ("mississippi", "mis*is*ip*.", True),
        ("", "", True),
        ("", "a*b*", True),                       # stars can match nothing
        ("a", "", False),
        ("ab", ".*c", False),
        ("aaa", "a*a", True),
        ("aaa", "ab*a*c*a", True),
    ]
    for solve in [is_match_recursive, is_match, is_match_table]:
        for text, pattern, expected in lc_cases:
            result = solve(text, pattern)
            assert result == expected, (
                f"{solve.__name__}({text!r}, {pattern!r}) returned {result}, expected {expected}"
            )
        # ...and agree with re.fullmatch
        for text, pattern, _ in lc_cases:
            assert solve(text, pattern) == (re.fullmatch(pattern, text) is not None)

    # Memoization does far less work on a nasty case
    text, pattern = "a" * 18, "a*" * 9 + "b"
    calls = [0]
    assert is_match_recursive(text, pattern, calls) is False
    assert calls[0] > 100_000                              # exponential
    assert is_match(text, pattern) is False                # at most 19 * 20 states

    # The safe patterns really are fast, and still correct
    bad = "a" * 24 + "!"
    assert time_match(r"^(?>a+)+$", bad) < 0.01
    assert time_match(r"^(a+)++$", bad) < 0.01
    assert re.match(r"^(?>a+)+$", "aaaa") and re.match(r"^(a+)++$", "aaaa")

    try:
        safe_match(r"^(a+)+$", "a" * 5_000)
        assert False, "expected ValueError"
    except ValueError:
        pass

    print("All tests passed!")


if __name__ == "__main__":
    print("Tiny matcher:")
    for pattern, text in [("^ab*c$", "abbbc"), ("a.c", "xxabcxx"), ("^abc", "xabc")]:
        print(f"  {pattern!r:<10} on {text!r:<10} -> {tiny_search(pattern, text)}")

    text, pattern = "a" * 18, "a*" * 9 + "b"
    calls = [0]
    is_match_recursive(text, pattern, calls)
    print(f"\nLeetCode 10 on text={text!r}, pattern={pattern!r}:")
    print(f"  plain recursion: {calls[0]:,} calls")
    print(f"  memoized:        at most {(len(text) + 1) * (len(pattern) + 1)} states")

    print("\nReDoS: matching 'aaa...a!' (never matches)")
    print(f"  {'n':>3}  {'^(a+)+$':>10}  {'^(?>a+)+$':>10}  {'^a+$':>10}")
    for n in (16, 18, 20, 22, 24):
        s = "a" * n + "!"
        print(f"  {n:>3}  {time_match(r'^(a+)+$', s):>9.4f}s"
              f"  {time_match(r'^(?>a+)+$', s):>9.6f}s"
              f"  {time_match(r'^a+$', s):>9.6f}s")
    print("  Each extra 2 characters makes the nested pattern about 4x slower.")
    print("  At 40 characters (2^16 times the work of 24) it would take about 16 hours.")

    print()
    run_tests()
