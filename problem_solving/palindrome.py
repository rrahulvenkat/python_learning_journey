# Palindrome
#
# PROBLEM
# -------
# A palindrome reads the same forwards and backwards.
#
#   "racecar"  -> True
#   "hello"    -> False
#
# Variation (LeetCode 125, "Valid Palindrome"): ignore case, spaces and
# punctuation, so only letters and digits count.
#
#   "A man, a plan, a canal: Panama"  -> True
#   "race a car"                      -> False
#
# Related problems are at the bottom: numbers (LeetCode 9) and
# "palindrome if you delete at most one character" (LeetCode 680).
#
# KEY IDEAS
# ---------
#   - Reverse and compare: text == text[::-1]
#   - Two pointers: compare the first and last characters, then move
#     both pointers inwards. Stop at the first mismatch.
#   - Clean the input first (lowercase, keep only letters/digits) when
#     the problem says to ignore case and punctuation.
#   - Edge cases: an empty string and a single character are palindromes.


# ---------------------------------------------------------------
# Solution 1: reverse with slicing (simplest)
# ---------------------------------------------------------------

def is_palindrome_simple(text):
    return text == text[::-1]


# ---------------------------------------------------------------
# Solution 2: clean, then reverse (LeetCode 125)
# ---------------------------------------------------------------
#
# Keep only letters and digits, all in lowercase, then compare.

def is_palindrome_clean(text):
    cleaned = "".join(ch.lower() for ch in text if ch.isalnum())
    return cleaned == cleaned[::-1]


# ---------------------------------------------------------------
# Solution 3: two pointers (no extra string)
# ---------------------------------------------------------------
#
#   "A man, a plan..."
#    ^              ^
#   left          right
#
# Skip anything that isn't a letter or digit, compare the two
# characters, then move both pointers towards the middle.
# This is the answer interviewers usually want: it uses O(1) extra
# space and stops early at the first mismatch.

def is_palindrome_two_pointers(text):
    left, right = 0, len(text) - 1

    while left < right:
        if not text[left].isalnum():
            left += 1
        elif not text[right].isalnum():
            right -= 1
        elif text[left].lower() != text[right].lower():
            return False
        else:
            left += 1
            right -= 1

    return True


# ---------------------------------------------------------------
# Solution 4: recursion
# ---------------------------------------------------------------
#
# A string is a palindrome if its first and last characters match AND
# the middle part is also a palindrome.
# Good for practising recursion, but uses O(n) stack space and fails
# for very long strings (Python's recursion limit is about 1000).

def is_palindrome_recursive(text):
    if len(text) <= 1:                        # base case
        return True
    if text[0] != text[-1]:
        return False
    return is_palindrome_recursive(text[1:-1])


# ---------------------------------------------------------------
# Related problem 1: palindrome number (LeetCode 9)
# ---------------------------------------------------------------
#
# 121 -> True, -121 -> False (reads "121-" backwards), 10 -> False.
# The follow-up asks you to solve it WITHOUT converting to a string,
# by reversing the digits with % and //.

def is_palindrome_number(x):
    if x < 0:
        return False

    original = x
    reversed_num = 0
    while x > 0:
        last_digit = x % 10                   # 123 % 10  -> 3
        reversed_num = reversed_num * 10 + last_digit
        x //= 10                              # 123 // 10 -> 12
    return original == reversed_num


# ---------------------------------------------------------------
# Related problem 2: valid palindrome II (LeetCode 680)
# ---------------------------------------------------------------
#
# Can the string become a palindrome by deleting AT MOST one character?
#   "aba"  -> True (already one)
#   "abca" -> True (delete "b" or "c")
#   "abc"  -> False
#
# Use two pointers. At the first mismatch, try skipping the left
# character OR the right character, and check if what's left is a
# palindrome.

def valid_palindrome_one_deletion(text):
    def is_range_palindrome(left, right):
        while left < right:
            if text[left] != text[right]:
                return False
            left += 1
            right -= 1
        return True

    left, right = 0, len(text) - 1
    while left < right:
        if text[left] != text[right]:
            return (is_range_palindrome(left + 1, right)
                    or is_range_palindrome(left, right - 1))
        left += 1
        right -= 1
    return True


# ---------------------------------------------------------------
# COMPLEXITY (n = length of the string)
# ---------------------------------------------------------------
#
#   Solution                  | Time | Extra space
#   --------------------------|------|----------------------------
#   1. Reverse                | O(n) | O(n)  reversed copy
#   2. Clean + reverse        | O(n) | O(n)  cleaned copy
#   3. Two pointers           | O(n) | O(1)  just two indexes
#   4. Recursion              | O(n^2) because each slice copies the string
#   Palindrome number         | O(d) | O(1)  d = number of digits
#   One deletion              | O(n) | O(1)


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    # Exact match (case and punctuation matter)
    for solve in [is_palindrome_simple, is_palindrome_recursive]:
        assert solve("racecar")
        assert solve("abba")
        assert solve("")
        assert solve("a")
        assert not solve("hello")
        assert not solve("Racecar")           # "R" != "r"

    # Ignoring case and punctuation (LeetCode 125)
    for solve in [is_palindrome_clean, is_palindrome_two_pointers]:
        assert solve("A man, a plan, a canal: Panama")
        assert solve("Was it a car or a cat I saw?")
        assert solve("No 'x' in Nixon")
        assert solve("Racecar")
        assert solve(" ")                     # nothing left -> palindrome
        assert solve(".,!")
        assert not solve("race a car")
        assert not solve("0P")                # digits count too

    # Palindrome number (LeetCode 9)
    assert is_palindrome_number(121)
    assert is_palindrome_number(0)
    assert is_palindrome_number(12321)
    assert not is_palindrome_number(-121)
    assert not is_palindrome_number(10)
    assert not is_palindrome_number(123)

    # One deletion allowed (LeetCode 680)
    assert valid_palindrome_one_deletion("aba")
    assert valid_palindrome_one_deletion("abca")
    assert valid_palindrome_one_deletion("deeee")
    assert not valid_palindrome_one_deletion("abc")
    assert not valid_palindrome_one_deletion("abcda")

    print("All tests passed!")


if __name__ == "__main__":
    examples = [
        "racecar",
        "hello",
        "A man, a plan, a canal: Panama",
        "race a car",
        "Was it a car or a cat I saw?",
    ]

    print(f"{'Text':<34}{'Exact':<8}{'Ignoring case/punctuation'}")
    print("-" * 67)
    for text in examples:
        exact = is_palindrome_simple(text)
        relaxed = is_palindrome_two_pointers(text)
        print(f"{text!r:<34}{exact!s:<8}{relaxed}")

    print("\nNumbers:", {n: is_palindrome_number(n) for n in [121, -121, 10, 1221]})
    print("One deletion:", {s: valid_palindrome_one_deletion(s) for s in ["abca", "abc"]})

    print()
    run_tests()
