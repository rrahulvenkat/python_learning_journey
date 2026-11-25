# Number of 1 Bits (LeetCode 191) and related bit tricks
#
# PROBLEM
# -------
# Given a non-negative integer, return how many 1s are in its binary
# form. (This count is also called the "Hamming weight" or
# "population count".)
#
#   11   = 1011        ->  3
#   128  = 10000000    ->  1
#   255  = 11111111    ->  8
#
# KEY IDEAS
# ---------
#   - n & 1 is the LAST bit of n (1 if n is odd, 0 if even).
#   - n >> 1 throws the last bit away, moving the next one into place.
#     Repeat both to read every bit, one at a time.
#   - The best trick:  n & (n - 1)  turns off the LOWEST 1 bit.
#       n       = 1011 0100
#       n - 1   = 1011 0011     (the lowest 1 becomes 0, the 0s after it become 1s)
#       n & n-1 = 1011 0000     (that lowest 1 is gone)
#     So you can count 1s by turning them off one at a time: the loop
#     runs once per 1 bit, not once per bit.
#
# WHAT'S NEW HERE
# ---------------
# fundamentals/operators.py introduced & and >>. This file uses them
# to READ, COUNT and CHANGE individual bits, with three techniques:
#   - read bits one at a time:     n & 1, then n >>= 1
#   - n & (n - 1):                 remove the lowest 1 bit
#   - bit masks:                   check, set, clear and flip one bit
#
# SECURITY CONNECTION
# -------------------
#   - Permission flags: Unix file permissions (chmod 755) and many
#     access-control systems store each permission as one bit.
#     Checking "can this user write?" is a bit mask (variation 3).
#   - Hamming distance (variation 2) counts how many bits differ. A
#     good hash function changes about HALF its output bits when one
#     input character changes (the "avalanche effect"). The demo shows
#     this with SHA-256.


import hashlib


# ---------------------------------------------------------------
# Solution 1: convert to a binary string and count the "1"s
# ---------------------------------------------------------------
#
# bin(11) == "0b1011". Simple and fine in real code.
# Python 3.10+ also has int.bit_count(), which does the same thing.

def count_ones_string(n):
    return bin(n).count("1")


# ---------------------------------------------------------------
# Solution 2: check the last bit, then shift
# ---------------------------------------------------------------
#
# Trace for n = 11 (1011):
#
#   n (binary) | n & 1 | count
#   -----------|-------|------
#   1011       |   1   |  1
#   101        |   1   |  2
#   10         |   0   |  2
#   1          |   1   |  3
#   0          | stop
#
# The loop runs once for EVERY bit, so about 32 times for a 32-bit
# number.

def count_ones_shift(n):
    count = 0
    while n:
        count += n & 1
        n >>= 1
    return count


# ---------------------------------------------------------------
# Solution 3: n & (n - 1)  (Brian Kernighan's trick)
# ---------------------------------------------------------------
#
# Trace for n = 11 (1011):
#
#   n    | n - 1 | n & (n - 1) | count
#   -----|-------|-------------|------
#   1011 | 1010  | 1010        |  1
#   1010 | 1001  | 1000        |  2
#   1000 | 0111  | 0000        |  3
#
# The loop runs once per 1 bit: 3 times here instead of 4. For a
# number like 2**31 (one 1 bit and 31 zeros) it runs ONCE.

def count_ones(n):
    count = 0
    while n:
        n &= n - 1                # remove the lowest 1 bit
        count += 1
    return count


# ---------------------------------------------------------------
# Variation 1: Power of Two (LeetCode 231)
# ---------------------------------------------------------------
#
# A power of two has exactly ONE 1 bit:  1, 10, 100, 1000, ...
# So n & (n - 1) removes it and leaves 0. One line, no loop.
#
#   16 = 10000,  15 = 01111,  16 & 15 = 0   -> power of two
#   12 = 01100,  11 = 01011,  12 & 11 = 8   -> not
#
# n > 0 is needed, because 0 & -1 is also 0.

def is_power_of_two(n):
    return n > 0 and n & (n - 1) == 0


# ---------------------------------------------------------------
# Variation 2: Hamming Distance (LeetCode 461)
# ---------------------------------------------------------------
#
# How many bit positions differ between x and y? XOR leaves a 1
# exactly where they differ (single_number.py), so count those 1s.
#
#   x = 1 = 0001
#   y = 4 = 0100
#   x ^ y = 0101  -> 2 bits differ

def hamming_distance(x, y):
    return count_ones(x ^ y)


# The same idea for two byte strings of equal length, such as two
# hashes: compare them byte by byte and add up the differing bits.

def bit_difference(a: bytes, b: bytes) -> int:
    return sum(count_ones(x ^ y) for x, y in zip(a, b))


# ---------------------------------------------------------------
# Variation 3: bit masks as permission flags
# ---------------------------------------------------------------
#
# Give each permission its own bit. A user's permissions are all their
# bits OR-ed together into one number.
#
#   READ    = 0b100  (4)
#   WRITE   = 0b010  (2)
#   EXECUTE = 0b001  (1)
#   rwx = 7, rw- = 6, r-x = 5, r-- = 4
#
#   check:  perms & FLAG != 0     is the bit on?
#   set:    perms | FLAG          turn it on
#   clear:  perms & ~FLAG         turn it off
#   flip:   perms ^ FLAG          switch it
#
# chmod 754 is three of these 3-bit groups: owner 7 (rwx),
# group 5 (r-x), others 4 (r--).

READ, WRITE, EXECUTE = 0b100, 0b010, 0b001

def has_permission(perms, flag):
    return perms & flag != 0

def grant(perms, flag):
    return perms | flag

def revoke(perms, flag):
    return perms & ~flag

def toggle(perms, flag):
    return perms ^ flag

def to_rwx(perms):
    """7 -> 'rwx', 5 -> 'r-x'"""
    return "".join(letter if perms & flag else "-"
                   for letter, flag in (("r", READ), ("w", WRITE), ("x", EXECUTE)))

def chmod_to_text(mode):
    """0o754 -> 'rwxr-xr--'. Each octal digit is 3 bits."""
    owner = (mode >> 6) & 0b111
    group = (mode >> 3) & 0b111
    others = mode & 0b111
    return to_rwx(owner) + to_rwx(group) + to_rwx(others)


# ---------------------------------------------------------------
# Variation 4: Counting Bits (LeetCode 338)
# ---------------------------------------------------------------
#
# Return the count of 1 bits for EVERY number from 0 to n.
#   n = 5  ->  [0, 1, 1, 2, 1, 2]
#
# Calling count_ones() for each is O(n log n). Faster: reuse answers
# you already have. i >> 1 is i with its last bit removed, and it's
# smaller than i, so its count is already known:
#   bits[i] = bits[i >> 1] + (i & 1)
# This "build on smaller answers" idea is called dynamic programming.

def counting_bits(n):
    bits = [0] * (n + 1)
    for i in range(1, n + 1):
        bits[i] = bits[i >> 1] + (i & 1)
    return bits


# ---------------------------------------------------------------
# COMPLEXITY (b = number of bits, k = number of 1 bits)
# ---------------------------------------------------------------
#
#   Solution                     | Time        | Extra space
#   -----------------------------|-------------|-------------
#   1. bin().count("1")          | O(b)        | O(b) the string
#   2. Check and shift           | O(b)        | O(1)
#   3. n & (n - 1)               | O(k)        | O(1)
#   Power of Two                 | O(1)        | O(1)
#   Hamming Distance             | O(k)        | O(1)
#   Permission masks             | O(1)        | O(1)
#   Counting Bits (0..n)         | O(n)        | O(n)


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    test_cases = [
        # (n, expected)
        (11, 3),                  # LeetCode example 1: 1011
        (128, 1),                 # LeetCode example 2: 10000000
        (2147483645, 30),         # LeetCode example 3: 31 bits, one 0
        (0, 0),
        (1, 1),
        (255, 8),
        (2**64 - 1, 64),          # Python ints have no fixed size
    ]

    for solve in [count_ones_string, count_ones_shift, count_ones]:
        for n, expected in test_cases:
            result = solve(n)
            assert result == expected, (
                f"{solve.__name__}({n}) returned {result}, expected {expected}"
            )

    # All three agree with Python's built-in on lots of numbers
    for n in range(2_000):
        assert count_ones_shift(n) == count_ones(n) == n.bit_count()

    # Power of Two
    assert [n for n in range(-4, 70) if is_power_of_two(n)] == [1, 2, 4, 8, 16, 32, 64]

    # Hamming distance
    assert hamming_distance(1, 4) == 2            # LeetCode example 1
    assert hamming_distance(3, 1) == 1            # LeetCode example 2
    assert hamming_distance(7, 7) == 0
    assert bit_difference(b"\x00\xff", b"\xff\xff") == 8

    # Permissions
    perms = READ | WRITE                          # rw-
    assert has_permission(perms, READ)
    assert not has_permission(perms, EXECUTE)
    assert to_rwx(grant(perms, EXECUTE)) == "rwx"
    assert to_rwx(revoke(perms, WRITE)) == "r--"
    assert to_rwx(revoke(perms, EXECUTE)) == "rw-"  # revoking an unset bit is harmless
    assert to_rwx(toggle(perms, WRITE)) == "r--"
    assert chmod_to_text(0o754) == "rwxr-xr--"
    assert chmod_to_text(0o644) == "rw-r--r--"
    assert chmod_to_text(0o777) == "rwxrwxrwx"

    # Counting Bits (LeetCode 338 examples)
    assert counting_bits(2) == [0, 1, 1]
    assert counting_bits(5) == [0, 1, 1, 2, 1, 2]
    assert counting_bits(0) == [0]

    print("All tests passed!")


if __name__ == "__main__":
    print("n & (n - 1) removes the lowest 1 bit, one at a time:")
    n = 0b10110100
    while n:
        print(f"  {n:08b}  ({n})")
        n &= n - 1
    print(f"  {n:08b}  -> {count_ones(0b10110100)} ones in total")

    print("\nPowers of two below 100:",
          [n for n in range(100) if is_power_of_two(n)])

    print("\nFile permissions:")
    for mode in (0o755, 0o644, 0o600):
        print(f"  chmod {mode:o}  ->  {chmod_to_text(mode)}")

    perms = READ | WRITE
    print(f"\n  user has {to_rwx(perms)}; can execute? {has_permission(perms, EXECUTE)}")
    perms = grant(perms, EXECUTE)
    print(f"  after grant(EXECUTE):  {to_rwx(perms)}")
    perms = revoke(perms, WRITE)
    print(f"  after revoke(WRITE):   {to_rwx(perms)}")

    # The avalanche effect: one character changes about half the bits
    a = hashlib.sha256(b"transfer $100 to alice").digest()
    b = hashlib.sha256(b"transfer $900 to alice").digest()
    total = len(a) * 8
    diff = bit_difference(a, b)
    print("\nSHA-256 of two messages that differ by ONE character:")
    print(f"  {a.hex()}")
    print(f"  {b.hex()}")
    print(f"  {diff} of {total} bits differ ({diff / total:.0%}); about 50% is expected")

    print()
    run_tests()
