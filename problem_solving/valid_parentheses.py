# Valid Parentheses (LeetCode 20)
#
# PROBLEM
# -------
# Given a string containing only the brackets ( ) [ ] { }, return True
# if it is valid:
#   - every opening bracket is closed by the SAME type of bracket
#   - brackets close in the right ORDER (the most recent one first)
#
#   "()[]{}"  ->  True
#   "([]{})"  ->  True
#   "(]"      ->  False   wrong type
#   "([)]"    ->  False   wrong order
#   "(("      ->  False   never closed
#
# KEY IDEAS
# ---------
#   - The bracket that must close NEXT is always the most recently
#     opened one. "Most recent first" is exactly what a stack gives
#     you: Last In, First Out.
#   - Opening bracket -> push it.
#     Closing bracket -> the top of the stack must be its partner.
#     Pop it if so; otherwise the string is invalid.
#   - At the end, the stack must be empty (nothing left unclosed).
#
# WHAT'S NEW HERE
# ---------------
# data_structures/lists.py showed a list used as a stack with
# append() and pop(). This file uses that stack to solve a problem:
# MATCHING NESTED PAIRS. You'll also see a stack of INDEXES, which
# remembers where each bracket was so you can report errors.
#
# SECURITY CONNECTION
# -------------------
# Every parser (JSON, HTML, SQL, a shell) tracks nesting like this.
# Many injection attacks work by closing a bracket or quote early to
# "break out" of the context the input was meant to stay in, as in
#     ') OR 1=1 --
# Deep nesting is also an attack in its own right: a JSON document
# nested 100,000 levels deep can crash a parser that has no limit
# (variation 3).


# ---------------------------------------------------------------
# Solution 1: repeatedly remove matched pairs (simple but slow)
# ---------------------------------------------------------------
#
# A valid string always contains at least one pair with nothing
# inside it, like "()" or "[]". Remove those over and over. If the
# string ends up empty, it was valid.
#
#   "{[()]}" -> "{[]}" -> "{}" -> ""   valid
#   "([)]"   -> no "()", "[]" or "{}" to remove -> stuck -> invalid
#
# Each pass scans the whole string, and there can be n/2 passes, so
# this is O(n^2).

def is_valid_replace(s):
    while "()" in s or "[]" in s or "{}" in s:
        s = s.replace("()", "").replace("[]", "").replace("{}", "")
    return s == ""


# ---------------------------------------------------------------
# Solution 2: stack (the optimal answer)
# ---------------------------------------------------------------
#
# PAIRS maps each CLOSING bracket to the opening one it needs.
#
# Trace for s = "{[()]}":
#
#   ch | action                       | stack after
#   ---|------------------------------|------------
#   {  | push                         | {
#   [  | push                         | { [
#   (  | push                         | { [ (
#   )  | top is ( -> matches, pop     | { [
#   ]  | top is [ -> matches, pop     | {
#   }  | top is { -> matches, pop     | (empty)  -> valid
#
# Trace for s = "([)]":
#
#   (  | push                         | (
#   [  | push                         | ( [
#   )  | top is [ but ) needs (       | -> invalid
#
# Quick exit: a string of odd length can never be valid.

PAIRS = {")": "(", "]": "[", "}": "{"}

def is_valid(s):
    if len(s) % 2 == 1:
        return False

    stack = []
    for ch in s:
        if ch in PAIRS:                               # closing bracket
            if not stack or stack[-1] != PAIRS[ch]:   # empty, or wrong partner
                return False
            stack.pop()
        else:                                         # opening bracket
            stack.append(ch)

    return not stack                                  # empty means all closed


# ---------------------------------------------------------------
# Why a counter isn't enough
# ---------------------------------------------------------------
#
# With only ONE type of bracket, you don't need a stack: count +1 for
# "(" and -1 for ")". The count must never go below 0 and must end at
# 0. But with several types, counting can't see the ORDER: "([)]"
# has balanced counts of each type and is still invalid.

def is_valid_counter_only(s):
    """Correct for '(' and ')' only."""
    depth = 0
    for ch in s:
        depth += 1 if ch == "(" else -1
        if depth < 0:                     # closed before it was opened
            return False
    return depth == 0


def is_valid_counters_wrong(s):
    """WRONG for several bracket types: ignores order."""
    return all(s.count(o) == s.count(c) for c, o in PAIRS.items())


# ---------------------------------------------------------------
# Variation 1: report WHERE the first error is
# ---------------------------------------------------------------
#
# A real parser has to say "error at position 7", not just "invalid".
# Push the INDEX of each opening bracket instead of the character.
# Returns None if the string is valid, otherwise the index of the
# first bracket that's wrong.
#
#   "(a[b)c]"  ->  4   the ')' at index 4 doesn't match '[' at 2
#   "((x)"     ->  0   the '(' at index 0 is never closed
#
# Characters that aren't brackets are skipped, so this works on real
# text and code, not just bracket-only strings.

OPENERS = set(PAIRS.values())

def first_error(text):
    stack = []                                       # indexes of open brackets
    for i, ch in enumerate(text):
        if ch in OPENERS:
            stack.append(i)
        elif ch in PAIRS:
            if not stack or text[stack[-1]] != PAIRS[ch]:
                return i                             # unexpected closer
            stack.pop()

    return stack[0] if stack else None               # earliest unclosed opener


# ---------------------------------------------------------------
# Variation 2: Minimum Add to Make Parentheses Valid (LeetCode 921)
# ---------------------------------------------------------------
#
# How many brackets must you add to make a string of ( and ) valid?
#   "())"  ->  1    add one "("
#   "((("  ->  3    add three ")"
#
# Track two numbers: unmatched "(" still open, and ")" that had no
# partner. One type only, so counters are enough.

def min_add_to_make_valid(s):
    open_count = 0                # "(" waiting for a ")"
    missing_open = 0              # ")" that came with no "(" open
    for ch in s:
        if ch == "(":
            open_count += 1
        elif open_count > 0:
            open_count -= 1
        else:
            missing_open += 1
    return open_count + missing_open


# ---------------------------------------------------------------
# Variation 3: maximum nesting depth with a safety limit
# (based on LeetCode 1614)
# ---------------------------------------------------------------
#
# Return the deepest nesting level. If it goes past `limit`, raise an
# error instead of continuing. Parsers for JSON, XML and similar
# formats need a limit like this, or a deeply nested document can
# exhaust memory or crash the program.
#
#   "(1+(2*3)+((8)/4))+1"  ->  3

def max_depth(text, limit=None):
    depth = best = 0
    for ch in text:
        if ch in OPENERS:
            depth += 1
            best = max(best, depth)
            if limit is not None and depth > limit:
                raise ValueError(f"nesting deeper than {limit} levels")
        elif ch in PAIRS:
            depth -= 1
    return best


# ---------------------------------------------------------------
# COMPLEXITY (n = length of the string)
# ---------------------------------------------------------------
#
#   Solution                     | Time    | Extra space
#   -----------------------------|---------|-------------------
#   1. Repeated replace          | O(n^2)  | O(n)  new strings
#   2. Stack                     | O(n)    | O(n)  the stack
#   One-type counter             | O(n)    | O(1)
#   Variation 1 (error index)    | O(n)    | O(n)
#   Variations 2 and 3           | O(n)    | O(1)
#
# The stack's worst case is a string of only opening brackets, where
# every character gets pushed.


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    test_cases = [
        # (s, expected)
        ("()", True),                 # LeetCode example 1
        ("()[]{}", True),             # LeetCode example 2
        ("(]", False),                # LeetCode example 3
        ("([])", True),               # LeetCode example 4
        ("([)]", False),              # wrong order
        ("{[()]}", True),             # deeply nested
        ("", True),                   # nothing to close
        ("(", False),                 # odd length
        ("((", False),                # never closed
        ("))", False),                # closed before opened
        ("){", False),                # closer first
        ("[({})](]", False),          # fine until the end
    ]

    for solve in [is_valid_replace, is_valid]:
        for s, expected in test_cases:
            result = solve(s)
            assert result == expected, (
                f"{solve.__name__}({s!r}) returned {result}, expected {expected}"
            )

    # One type: the counter is correct
    assert is_valid_counter_only("(()())") is True
    assert is_valid_counter_only("())(") is False

    # Several types: plain counting gets "([)]" wrong
    assert is_valid_counters_wrong("([)]") is True        # wrong answer!

    # Error position
    assert first_error("(a[b)c]") == 4
    assert first_error("((x)") == 0
    assert first_error("print(items[0])") is None
    assert first_error("x = {'a': [1, 2}") == 15
    assert first_error("") is None

    # Minimum additions (LeetCode 921 examples)
    assert min_add_to_make_valid("())") == 1
    assert min_add_to_make_valid("(((") == 3
    assert min_add_to_make_valid("()))((") == 4

    # Depth and the safety limit
    assert max_depth("(1+(2*3)+((8)/4))+1") == 3
    assert max_depth("no brackets") == 0
    try:
        max_depth("[" * 1_000 + "]" * 1_000, limit=100)
        assert False, "expected ValueError"
    except ValueError:
        pass

    print("All tests passed!")


if __name__ == "__main__":
    import time

    for s in ["{[()]}", "([)]", "(("]:
        print(f"{s!r:<10} valid? {is_valid(s)}")

    # Error reporting on lines of "code"
    print("\nFirst error positions:")
    for line in ["print(items[0])", "x = {'a': [1, 2}", "if (a and (b or c):"]:
        pos = first_error(line)
        if pos is None:
            print(f"  {line!r}: OK")
        else:
            print(f"  {line!r}: error at index {pos}")
            print(f"   {' ' * pos}^")         # 3 spaces line up with "  '" above

    # The parser-safety limit
    payload = "[" * 10_000 + "]" * 10_000
    try:
        max_depth(payload, limit=500)
    except ValueError as err:
        print(f"\nRejected a {len(payload):,}-character input: {err}")

    # Speed comparison on a deeply nested valid string
    big = "({[" * 5_000 + "]})" * 5_000
    print(f"\nSpeed test with a {len(big):,}-character string:")
    for solve in [is_valid_replace, is_valid]:
        start = time.perf_counter()
        solve(big)
        print(f"  {solve.__name__:<18} {time.perf_counter() - start:.4f} s")

    print()
    run_tests()
