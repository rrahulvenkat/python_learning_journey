# Letter Combinations of a Phone Number (LeetCode 17)
#
# PROBLEM
# -------
# Each digit 2-9 on a phone keypad maps to letters. Given a string of
# digits, return every letter combination it could spell.
#
#   2: abc  3: def  4: ghi  5: jkl  6: mno  7: pqrs  8: tuv  9: wxyz
#
#   "23"  ->  ad ae af bd be bf cd ce cf
#   ""    ->  []
#
# KEY IDEAS
# ---------
#   - Each position has its OWN list of options, and you pick exactly
#     one from each. That's a "Cartesian product". The number of
#     results is the options at each position MULTIPLIED together:
#       "23" -> 3 * 3 = 9      "79" -> 4 * 4 = 16
#   - Backtracking: position by position, try each option for this
#     position, recurse for the next, then remove it.
#   - itertools.product does the same thing in one call.
#
# WHAT'S NEW HERE
# ---------------
# subsets.py chose IN or OUT for each item; permutations.py chose
# which item goes next. Here the choices at each step come from a
# LOOKUP TABLE, different for each position. This shape (one choice
# per slot from a per-slot list) is the most common in real
# generators.
#
# SECURITY CONNECTION
# -------------------
# Password crackers don't just try dictionary words; they apply
# MANGLING RULES: a -> @ or 4, o -> 0, s -> $ or 5, capitalise the
# first letter. Each letter becomes a small list of options, so
# generating every variant of a word is exactly this problem
# (variation 1). The takeaway for defenders: "P@ssw0rd!" adds almost
# no strength, because it sits in a few thousand variants of
# "password". Length and randomness matter; clever substitutions
# don't. Only run cracking-style tools against hashes and systems you
# own or are authorised to test.


from itertools import product
from math import prod


KEYPAD = {
    "2": "abc", "3": "def", "4": "ghi", "5": "jkl",
    "6": "mno", "7": "pqrs", "8": "tuv", "9": "wxyz",
}


# ---------------------------------------------------------------
# Solution 1: iterative (build the combinations up digit by digit)
# ---------------------------------------------------------------
#
#   start:      [""]
#   digit 2:    ["a", "b", "c"]
#   digit 3:    ["ad", "ae", "af", "bd", ..., "cf"]

def letter_combinations_iterative(digits):
    if not digits:
        return []
    result = [""]
    for digit in digits:
        result = [prefix + letter for prefix in result for letter in KEYPAD[digit]]
    return result


# ---------------------------------------------------------------
# Solution 2: backtracking
# ---------------------------------------------------------------
#
# The decision tree for "23":
#
#                    ""
#          /         |         \
#         a          b          c          <- choose a letter for "2"
#       / | \      / | \      / | \
#      ad ae af   bd be bf   cd ce cf      <- choose a letter for "3"
#
# Every LEAF (path as long as digits) is an answer.

def letter_combinations(digits):
    if not digits:
        return []
    result = []
    path = []

    def backtrack(index):
        if index == len(digits):
            result.append("".join(path))
            return
        for letter in KEYPAD[digits[index]]:
            path.append(letter)              # choose
            backtrack(index + 1)             # explore
            path.pop()                       # un-choose

    backtrack(0)
    return result


# ---------------------------------------------------------------
# Solution 3: itertools.product
# ---------------------------------------------------------------
#
# product("abc", "def") gives ('a','d'), ('a','e'), ... in the same
# order as the solutions above. The * unpacks the list of letter
# strings into separate arguments.

def letter_combinations_product(digits):
    if not digits:
        return []
    return ["".join(combo) for combo in product(*(KEYPAD[d] for d in digits))]


# ---------------------------------------------------------------
# Variation 1: password mangling variants
# ---------------------------------------------------------------
#
# The same problem with a different table: each character maps to a
# list of substitutes. The first letter may also be capitalised.
#
#   "pass" -> pass, p@ss, p4ss, pa$s, ..., P@$$, ...
#
# variant_count() works out HOW MANY there are without generating
# them: the product of the option counts.

SUBSTITUTIONS = {
    "a": "a@4", "e": "e3", "i": "i1!", "o": "o0", "s": "s$5", "t": "t7", "l": "l1",
}

def options_for(word):
    options = [SUBSTITUTIONS.get(ch, ch) for ch in word.lower()]
    first = options[0] if options else ""
    if first and first[0].isalpha():
        options[0] = first + first[0].upper()       # also allow a capital first letter
    return options


def mangle_variants(word):
    if not word:
        return []
    return ["".join(combo) for combo in product(*options_for(word))]


def variant_count(word, suffixes=1):
    return prod(len(o) for o in options_for(word)) * suffixes


def is_weak_variant(password, base_words, suffixes=("", "!", "1", "123", "2026")):
    """True if the password is a mangled base word plus a common suffix."""
    for word in base_words:
        variants = set(mangle_variants(word))
        for suffix in suffixes:
            if password.endswith(suffix) and password[:len(password) - len(suffix)] in variants:
                return True
    return False


# ---------------------------------------------------------------
# COMPLEXITY (n = number of digits)
# ---------------------------------------------------------------
#
#   Solution              | Time         | Output size
#   ----------------------|--------------|-----------------------
#   1. Iterative          | O(n * 4^n)   | up to 4^n combinations
#   2. Backtracking       | O(n * 4^n)   |
#   3. itertools.product  | O(n * 4^n)   |
#   variant_count         | O(n)         | just a number
#
# 4^n because the biggest keys (7 and 9) have 4 letters. Counting the
# results (a product of small numbers) is O(n) and tells you whether
# generating them all is even feasible.


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    test_cases = [
        # (digits, expected)
        ("23", ["ad", "ae", "af", "bd", "be", "bf", "cd", "ce", "cf"]),   # LeetCode 1
        ("", []),                                                         # LeetCode 2
        ("2", ["a", "b", "c"]),                                           # LeetCode 3
        ("7", ["p", "q", "r", "s"]),
    ]
    for solve in [letter_combinations_iterative, letter_combinations,
                  letter_combinations_product]:
        for digits, expected in test_cases:
            result = solve(digits)
            assert result == expected, (solve.__name__, digits, result)

    # The three agree, in the same order, and have the right size
    for digits in ["79", "234", "2345", "999"]:
        a = letter_combinations_iterative(digits)
        b = letter_combinations(digits)
        c = letter_combinations_product(digits)
        assert a == b == c
        assert len(a) == prod(len(KEYPAD[d]) for d in digits)
        assert len(set(a)) == len(a)                     # no duplicates

    # Mangling
    variants = mangle_variants("pass")
    assert "pass" in variants and "P@$$" in variants and "p4s5" in variants
    assert len(variants) == variant_count("pass") == 2 * 3 * 3 * 3
    assert len(set(variants)) == len(variants)
    assert variant_count("password") == len(mangle_variants("password"))
    assert mangle_variants("") == []
    assert mangle_variants("x2") == ["x2", "X2"]

    assert is_weak_variant("P@ssw0rd!", ["password"]) is True
    assert is_weak_variant("p4$$w0rd2026", ["password"]) is True
    assert is_weak_variant("Adm1n123", ["admin"]) is True
    assert is_weak_variant("correct horse battery staple", ["password"]) is False
    assert is_weak_variant("P@ssw0rd!x", ["password"]) is False   # unusual suffix

    print("All tests passed!")


if __name__ == "__main__":
    print(f'"23" -> {letter_combinations("23")}')
    print(f'"79" has {len(letter_combinations("79"))} combinations')

    word = "password"
    print(f"\nMangled variants of {word!r}: {variant_count(word):,}")
    variants = mangle_variants(word)
    print(f"  e.g. {', '.join(variants[::len(variants) // 6][:6])}")
    with_suffixes = variant_count(word, suffixes=5)
    print(f"  with 5 common suffixes: {with_suffixes:,} guesses")
    print(f"  a modern GPU can test billions of fast hashes per second, "
          f"so this list is gone in well under a second")

    print("\nIs each password just a mangled common word?")
    common = ["password", "admin", "welcome", "letmein"]
    for pw in ["P@ssw0rd!", "W3lc0me2026", "L3tm3!n123", "violet-tractor-61-glide"]:
        print(f"  {pw:<26} weak variant? {is_weak_variant(pw, common)}")

    print()
    run_tests()
