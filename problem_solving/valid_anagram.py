# Valid Anagram (LeetCode 242)
#
# PROBLEM
# -------
# Given two strings s and t, return True if t is an anagram of s.
# An anagram uses exactly the same letters, the same number of times,
# in any order.
#
#   "anagram", "nagaram"  ->  True
#   "rat",     "car"      ->  False
#
# KEY IDEAS
# ---------
#   - Two strings are anagrams when they have the same LETTER COUNTS.
#     The order doesn't matter, so either remove the order (sort) or
#     ignore it (count).
#   - Quick exit: strings of different lengths can never be anagrams.
#   - Trap: comparing set(s) == set(t) is WRONG. "aacc" and "ccac"
#     have the same set {a, c} but different counts.
#
# WHAT'S NEW HERE
# ---------------
# You already know Counter from data_structures/dictionaries.py and
# ord()/chr() from data_structures/strings.py. This file uses them
# for a new technique: a FREQUENCY COUNT as a fingerprint, so you can
# compare two things without caring about their order.
#
# SECURITY CONNECTION
# -------------------
# Letter frequency is the basis of classical cryptanalysis. A
# transposition cipher only rearranges letters, so the ciphertext is
# an anagram of the plaintext and the letter counts stay the same.
# Comparing frequency counts is how analysts tell a transposition
# cipher from a substitution cipher.


# ---------------------------------------------------------------
# Solution 1: sort both strings and compare
# ---------------------------------------------------------------
#
# Sorting puts the letters in a fixed order, so anagrams become
# identical:   sorted("listen") == sorted("silent")
#              ['e','i','l','n','s','t'] on both sides

def is_anagram_sort(s, t):
    return sorted(s) == sorted(t)


# ---------------------------------------------------------------
# Solution 2: one dictionary, count up then count down
# ---------------------------------------------------------------
#
# Add 1 for each character in s and subtract 1 for each character in
# t. If they're anagrams, everything cancels out to 0.
#
# This uses ONE dictionary instead of two, and it can stop early: as
# soon as a count goes below 0, t has a character that s doesn't have
# enough of.

def is_anagram_count(s, t):
    if len(s) != len(t):
        return False

    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1

    for ch in t:
        counts[ch] = counts.get(ch, 0) - 1
        if counts[ch] < 0:                # t has an extra ch
            return False

    return True                           # same length + no negatives = all zero


# ---------------------------------------------------------------
# Solution 3: a fixed list of 26 counters (lowercase a-z only)
# ---------------------------------------------------------------
#
# When the input is only 'a' to 'z', a plain list of 26 numbers is
# faster than a dictionary. Each letter maps to a position:
#
#   ord(ch) - ord("a")     'a' -> 0, 'b' -> 1, ... 'z' -> 25
#
# The list is always 26 long, however long the strings are, so the
# extra space is O(1). This "array as a tiny dictionary" trick shows
# up again in sliding window problems.

def is_anagram_array(s, t):
    if len(s) != len(t):
        return False

    counts = [0] * 26
    for a, b in zip(s, t):                # walk both strings together
        counts[ord(a) - ord("a")] += 1
        counts[ord(b) - ord("a")] -= 1

    return all(c == 0 for c in counts)


# ---------------------------------------------------------------
# Solution 4: Counter (the Pythonic one-liner)
# ---------------------------------------------------------------
#
# Two Counters are equal when every key has the same count.
# Use this in real code. Know solutions 2 and 3 for interviews,
# because interviewers usually ask you to do it without Counter.

from collections import Counter

def is_anagram_counter(s, t):
    return Counter(s) == Counter(t)


# ---------------------------------------------------------------
# The WRONG answer (so you can recognise it)
# ---------------------------------------------------------------

def is_anagram_wrong(s, t):
    return set(s) == set(t)               # ignores how MANY of each letter


# ---------------------------------------------------------------
# Variation 1: Group Anagrams (LeetCode 49)
# ---------------------------------------------------------------
#
# Given a list of words, group the anagrams together.
#   ["eat","tea","tan","ate","nat","bat"]
#   -> [["eat","tea","ate"], ["tan","nat"], ["bat"]]
#
# Idea: give every word a KEY that is the same for all its anagrams,
# then use a dictionary {key: [words]}. Here the key is the sorted
# letters as a tuple (lists can't be dictionary keys, tuples can).

from collections import defaultdict

def group_anagrams(words):
    groups = defaultdict(list)
    for word in words:
        key = tuple(sorted(word))         # "eat" -> ('a', 'e', 't')
        groups[key].append(word)
    return list(groups.values())


# ---------------------------------------------------------------
# Variation 2: Find All Anagrams in a String (LeetCode 438)
# ---------------------------------------------------------------
#
# Return every starting index in `text` where an anagram of `pattern`
# begins.
#   text = "cbaebabacd", pattern = "abc"  ->  [0, 6]
#   ("cba" starts at 0, "bac" starts at 6)
#
# This is a preview of the SLIDING WINDOW technique. Instead of
# recounting every window from scratch, slide a window of
# len(pattern) along the text and update the counts:
#   - add the character that enters on the right
#   - remove the character that leaves on the left
#
# Each step is O(1), so the whole thing is O(n) instead of O(n * m).

def find_anagrams(text, pattern):
    m = len(pattern)
    if m > len(text):
        return []

    need = [0] * 26
    window = [0] * 26
    for ch in pattern:
        need[ord(ch) - ord("a")] += 1

    result = []
    for i, ch in enumerate(text):
        window[ord(ch) - ord("a")] += 1               # char enters on the right

        if i >= m:                                    # window too big:
            left_ch = text[i - m]                     # char leaves on the left
            window[ord(left_ch) - ord("a")] -= 1

        if window == need:                            # comparing 26 items: O(1)
            result.append(i - m + 1)

    return result


# ---------------------------------------------------------------
# COMPLEXITY (n = length of the strings)
# ---------------------------------------------------------------
#
#   Solution                  | Time        | Extra space
#   --------------------------|-------------|-----------------------
#   1. Sort and compare       | O(n log n)  | O(n)  the sorted lists
#   2. One dictionary         | O(n)        | O(k)  k = distinct chars
#   3. List of 26             | O(n)        | O(1)  always 26 slots
#   4. Counter                | O(n)        | O(k)
#
# Follow-up interviewers like: "What if the input has Unicode, like
# emoji or accented letters?" Solutions 1, 2 and 4 still work.
# Solution 3 breaks, because it only has room for 'a' to 'z'.


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    test_cases = [
        # (s, t, expected)
        ("anagram", "nagaram", True),     # LeetCode example 1
        ("rat", "car", False),            # LeetCode example 2
        ("listen", "silent", True),
        ("", "", True),                   # two empty strings
        ("a", "a", True),
        ("a", "ab", False),               # different lengths
        ("aacc", "ccac", False),          # same letters, different counts
        ("abc", "abd", False),            # one letter differs
    ]

    solutions = [is_anagram_sort, is_anagram_count,
                 is_anagram_array, is_anagram_counter]

    for solve in solutions:
        for s, t, expected in test_cases:
            result = solve(s, t)
            assert result == expected, (
                f"{solve.__name__}({s!r}, {t!r}) returned {result}, expected {expected}"
            )

    # The set version fails the counts trap
    assert is_anagram_wrong("aacc", "ccac") is True       # wrong answer!

    # Unicode: works with the general solutions
    assert is_anagram_count("café", "éfac") is True
    assert is_anagram_counter("café", "éfac") is True

    # Group anagrams (sort groups so the order doesn't matter)
    groups = group_anagrams(["eat", "tea", "tan", "ate", "nat", "bat"])
    assert sorted(sorted(g) for g in groups) == [
        ["ate", "eat", "tea"], ["bat"], ["nat", "tan"]
    ]
    assert group_anagrams([]) == []

    # Find all anagrams
    assert find_anagrams("cbaebabacd", "abc") == [0, 6]
    assert find_anagrams("abab", "ab") == [0, 1, 2]
    assert find_anagrams("a", "abc") == []

    print("All tests passed!")


if __name__ == "__main__":
    s, t = "anagram", "nagaram"
    print(f"Is {t!r} an anagram of {s!r}? {is_anagram_count(s, t)}")

    # Show the letter-count fingerprint side by side
    print("\nLetter counts (the 'fingerprint'):")
    print(f"  {'letter':<7}{s:>8}{t:>8}")
    cs, ct = Counter(s), Counter(t)
    for letter in sorted(cs | ct):
        print(f"  {letter:<7}{cs[letter]:>8}{ct[letter]:>8}")

    print("\nWhy set() comparison is wrong:")
    print(f"  set('aacc') == set('ccac')  -> {is_anagram_wrong('aacc', 'ccac')}")
    print(f"  real answer                 -> {is_anagram_count('aacc', 'ccac')}")

    words = ["eat", "tea", "tan", "ate", "nat", "bat"]
    print(f"\nGroup anagrams {words}:")
    for group in group_anagrams(words):
        print("  ", group)

    print("\nAnagrams of 'abc' in 'cbaebabacd' start at:",
          find_anagrams("cbaebabacd", "abc"))

    print()
    run_tests()
