# First Bad Version (LeetCode 278)  -  binary search on a yes/no question
# (includes LeetCode 69, Sqrt(x))
#
# PROBLEM
# -------
# Versions 1 to n of a product were released in order. At some
# version a bug was introduced, and EVERY version after it is also
# bad. You have a function is_bad(version). Find the FIRST bad
# version using as few calls as possible.
#
#   n = 5, first bad = 4
#   is_bad(3) -> False, is_bad(5) -> True, is_bad(4) -> True  ->  4
#
# KEY IDEAS
# ---------
#   - There's no list to search here. Instead there's a yes/no
#     question whose answers look like this:
#         version:  1  2  3  4  5  6  7
#         is_bad:   F  F  F  T  T  T  T
#     All the Falses come before all the Trues. Whenever answers are
#     "sorted" like that (the question is MONOTONIC), you can binary
#     search for the first True.
#   - This is template B from binary_search.py, with the comparison
#     replaced by the question:
#         if is_bad(mid): hi = mid      (mid could be the first bad one)
#         else:           lo = mid + 1
#   - "Binary search on the ANSWER": for many problems ("smallest x
#     that works"), you can't search a list, but you can check whether
#     a guess works. If "x works" implies "x + 1 works", binary search
#     the guesses (Sqrt(x) below).
#
# WHAT'S NEW HERE
# ---------------
# binary_search.py searched a sorted LIST. This file searches a sorted
# QUESTION, which is far more common in practice and in interviews.
#
# SECURITY CONNECTION
# -------------------
#   - `git bisect` is exactly this algorithm. To find which of 1,000
#     commits introduced a vulnerability, it takes about 10 tests.
#     Incident responders do the same with backups: "which nightly
#     backup is the first one containing the web shell?"
#   - BLIND EXTRACTION: if a system only answers yes/no ("is the
#     secret's first character greater than 'm'?"), a secret can
#     still leak one character at a time, about 7 questions per
#     character. This is how blind SQL injection works, and why even
#     a yes/no difference in an error message or response time is a
#     real vulnerability. The demo runs against a local function only.


# ---------------------------------------------------------------
# Solution 1: check every version in order (the baseline)
# ---------------------------------------------------------------

def first_bad_linear(n, is_bad):
    for version in range(1, n + 1):
        if is_bad(version):
            return version
    return None


# ---------------------------------------------------------------
# Solution 2: binary search on the question (the optimal answer)
# ---------------------------------------------------------------
#
# Search the half-open range [lo, hi). hi = n + 1 means "no bad
# version at all" if every answer is False.
#
# Trace for n = 7, first bad = 4:
#
#   lo | hi | mid | is_bad(mid) | action
#   ---|----|-----|-------------|----------
#    1 |  8 |  4  |    True     | hi = 4
#    1 |  4 |  2  |    False    | lo = 3
#    3 |  4 |  3  |    False    | lo = 4
#   lo == hi == 4 -> answer 4  (3 calls instead of 4)

def first_bad_version(n, is_bad):
    lo, hi = 1, n + 1
    while lo < hi:
        mid = lo + (hi - lo) // 2
        if is_bad(mid):
            hi = mid
        else:
            lo = mid + 1
    return lo if lo <= n else None


# A helper that counts calls, so the tests can check efficiency.
def make_checker(first_bad):
    calls = [0]
    def is_bad(version):
        calls[0] += 1
        return first_bad is not None and version >= first_bad
    return is_bad, calls


# ---------------------------------------------------------------
# Variation 1: the first version whose file hash changed
# ---------------------------------------------------------------
#
# Nightly backups each store a hash of a web server's index.php.
# The known-good hash is from the first backup. Find the first backup
# where the file was changed, assuming once changed it stays changed.
#
# The question "has the file changed by backup i?" is monotonic, so
# it's the same binary search.

def first_changed_backup(backup_hashes, good_hash):
    lo, hi = 0, len(backup_hashes)
    while lo < hi:
        mid = lo + (hi - lo) // 2
        if backup_hashes[mid] != good_hash:
            hi = mid
        else:
            lo = mid + 1
    return lo if lo < len(backup_hashes) else None


# ---------------------------------------------------------------
# Variation 2: Sqrt(x) (LeetCode 69)  -  binary search on the answer
# ---------------------------------------------------------------
#
# Return the square root of x rounded DOWN, without ** or math.sqrt.
#   sqrt(8) -> 2   (2*2 = 4 <= 8, but 3*3 = 9 > 8)
#
# The question "is r * r > x?" is False, False, ..., True, True as r
# grows. Find the first r where it's True; the answer is one less.

def int_sqrt(x):
    if x < 0:
        raise ValueError("x must not be negative")
    lo, hi = 0, x + 1
    while lo < hi:
        mid = lo + (hi - lo) // 2
        if mid * mid > x:
            hi = mid
        else:
            lo = mid + 1
    return lo - 1


# ---------------------------------------------------------------
# Variation 3: blind extraction with yes/no questions
# ---------------------------------------------------------------
#
# The only thing we can call is  oracle(position, value), which says
# whether the secret's character at `position` has a code GREATER
# than `value`. That's a monotonic question about the character's
# code (0 to 127 for ASCII), so each character takes about
# log2(128) = 7 questions instead of up to 128.
#
# We also need the length: ask "is there a character at position i?"
# until the answer is no.
#
# This runs only against a secret defined in this file. Never point
# techniques like this at a system you don't own or aren't explicitly
# authorised to test.

def make_oracle(secret):
    calls = [0]
    def oracle(position, value):
        calls[0] += 1
        return position < len(secret) and ord(secret[position]) > value
    return oracle, calls


def extract_secret(oracle, max_length=64):
    chars = []
    for position in range(max_length):
        if not oracle(position, 0):              # nothing here: we've reached the end
            break
        # Find the first code c where "code > c" is False, i.e. code == c.
        lo, hi = 0, 128
        while lo < hi:
            mid = lo + (hi - lo) // 2
            if oracle(position, mid):            # code > mid
                lo = mid + 1
            else:
                hi = mid
        chars.append(chr(lo))
    return "".join(chars)


# ---------------------------------------------------------------
# COMPLEXITY
# ---------------------------------------------------------------
#
#   Solution                   | Calls / time    | Extra space
#   ---------------------------|-----------------|------------
#   1. Linear check            | O(n) calls      | O(1)
#   2. Binary search           | O(log n) calls  | O(1)
#   First changed backup       | O(log n)        | O(1)
#   Sqrt(x)                    | O(log x)        | O(1)
#   Blind extraction           | about 8 calls per character
#
# When each check is EXPENSIVE (building and testing a whole
# version, restoring a backup, a network request), the difference
# between n and log n checks is hours versus minutes.


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    import math

    # Every possible first-bad position for several n
    for n in [1, 2, 3, 10, 100, 1_000]:
        for first in list(range(1, n + 1)) + [None]:
            is_bad, calls = make_checker(first)
            assert first_bad_version(n, is_bad) == first, (n, first)
            assert calls[0] <= math.ceil(math.log2(n + 1)) + 1, (n, first, calls[0])
            is_bad, _ = make_checker(first)
            assert first_bad_linear(n, is_bad) == first

    # LeetCode examples
    is_bad, _ = make_checker(4)
    assert first_bad_version(5, is_bad) == 4
    is_bad, _ = make_checker(1)
    assert first_bad_version(1, is_bad) == 1

    # Big n: only about 31 calls for 2 billion versions
    is_bad, calls = make_checker(1_702_766_719)
    assert first_bad_version(2_126_753_390, is_bad) == 1_702_766_719
    assert calls[0] <= 32

    # Backups
    good = "a1" * 32
    bad = "ff" * 32
    assert first_changed_backup([good] * 5 + [bad] * 3, good) == 5
    assert first_changed_backup([good] * 4, good) is None
    assert first_changed_backup([bad] * 3, good) == 0
    assert first_changed_backup([], good) is None

    # Sqrt (LeetCode 69 examples, then many more)
    assert int_sqrt(4) == 2
    assert int_sqrt(8) == 2
    assert int_sqrt(0) == 0
    assert int_sqrt(1) == 1
    for x in range(2_000):
        assert int_sqrt(x) == math.isqrt(x), x
    assert int_sqrt(10**30) == 10**15                 # exact, no float rounding

    # Blind extraction
    for secret in ["", "a", "hunter2", "Tr0ub4dor&3", "s3cr3t-API-key_99"]:
        oracle, calls = make_oracle(secret)
        assert extract_secret(oracle) == secret
        assert calls[0] <= 8 * len(secret) + 1        # 7 per char + 1 length check each

    print("All tests passed!")


if __name__ == "__main__":
    n, first = 1_000, 613
    is_bad, calls = make_checker(first)
    found = first_bad_version(n, is_bad)
    linear_bad, linear_calls = make_checker(first)
    first_bad_linear(n, linear_bad)
    print(f"{n:,} versions, first bad = {found}")
    print(f"  binary search: {calls[0]} checks")
    print(f"  checking in order: {linear_calls[0]} checks")

    good = "9b74c9897bac770ffc029102a200c5de"
    backups = [good] * 23 + ["e3b0c44298fc1c149afbf4c8996fb924"] * 7
    i = first_changed_backup(backups, good)
    print(f"\n{len(backups)} nightly backups: index.php first changed in backup #{i + 1}")

    print(f"\nint_sqrt(8) = {int_sqrt(8)},  int_sqrt(10**30) = {int_sqrt(10**30)}")

    secret = "Tr0ub4dor&3"
    oracle, calls = make_oracle(secret)
    recovered = extract_secret(oracle)
    print(f"\nBlind extraction from a yes/no oracle (local demo):")
    print(f"  recovered {recovered!r} using {calls[0]} yes/no questions")
    print(f"  ({calls[0] / len(secret):.1f} per character; guessing each one in "
          f"order could take up to {128 * len(secret):,})")

    print()
    run_tests()
