# Single Number (LeetCode 136)  -  the XOR tricks
#
# PROBLEM
# -------
# Every number in a non-empty list appears exactly TWICE, except one
# number that appears once. Find that number.
#
#   [2, 2, 1]        ->  1
#   [4, 1, 2, 1, 2]  ->  4
#
# Follow-up: do it in O(n) time and O(1) extra space.
#
# KEY IDEAS
# ---------
# XOR (^) compares two numbers bit by bit: 1 where the bits DIFFER,
# 0 where they're the same. Three rules make it useful:
#
#   x ^ 0 == x          XOR with 0 changes nothing
#   x ^ x == 0          anything XORed with itself cancels out
#   order doesn't matter: a ^ b ^ a == a ^ a ^ b == b
#
# So XOR every number together. Each pair cancels to 0, and only the
# single number is left. No set, no dictionary: O(1) extra space.
#
# WHAT'S NEW HERE
# ---------------
# fundamentals/operators.py showed what ^ does to two numbers. This
# file uses those three rules as a TECHNIQUE: making pairs cancel
# out. The same rules are why XOR is everywhere in cryptography.
#
# SECURITY CONNECTION
# -------------------
#   plaintext ^ key = ciphertext
#   ciphertext ^ key = plaintext       (the key cancels out)
#
# That's the XOR cipher in variation 3. It's also why reusing an XOR
# key is fatal: if an attacker knows (or guesses) part of the
# plaintext, plaintext ^ ciphertext gives them the key. Stream
# ciphers, one-time pads and parts of AES all use XOR. The Cryptopals
# challenges start with exactly these attacks.


from collections import Counter
from functools import reduce
import operator


# ---------------------------------------------------------------
# Solution 1: count with a dictionary
# ---------------------------------------------------------------
#
# The obvious answer, using the hash map pattern from two_sum.py.
# O(n) time, but O(n) extra space for the counts.

def single_number_counter(nums):
    counts = Counter(nums)
    for num, count in counts.items():
        if count == 1:
            return num


# ---------------------------------------------------------------
# Solution 2: a set that adds and removes
# ---------------------------------------------------------------
#
# Add a number the first time you see it, remove it the second time.
# Only the single number is left. Still O(n) space in the worst case.

def single_number_set(nums):
    seen = set()
    for num in nums:
        if num in seen:
            seen.remove(num)
        else:
            seen.add(num)
    return seen.pop()


# ---------------------------------------------------------------
# Solution 3: maths trick
# ---------------------------------------------------------------
#
# If every number appeared twice, the total would be 2 * sum(set).
# The difference from the real total is the single number.
#   [4, 1, 2, 1, 2]: 2 * (4 + 1 + 2) - (4 + 1 + 2 + 1 + 2) = 14 - 10 = 4
# Clever, but set(nums) still uses O(n) space.

def single_number_math(nums):
    return 2 * sum(set(nums)) - sum(nums)


# ---------------------------------------------------------------
# Solution 4: XOR (the optimal answer)
# ---------------------------------------------------------------
#
# Trace for [4, 1, 2, 1, 2], in binary:
#
#   step     | value | result (binary) | result
#   ---------|-------|-----------------|-------
#   start    |       | 000             | 0
#   ^ 4      | 100   | 100             | 4
#   ^ 1      | 001   | 101             | 5
#   ^ 2      | 010   | 111             | 7
#   ^ 1      | 001   | 110             | 6     the 1s cancel
#   ^ 2      | 010   | 100             | 4     the 2s cancel
#
# Works for negative numbers too, because Python's XOR works on the
# two's complement form of the number.

def single_number(nums):
    result = 0
    for num in nums:
        result ^= num
    return result


# The same thing in one line: reduce() applies ^ across the list.
def single_number_reduce(nums):
    return reduce(operator.xor, nums, 0)


# ---------------------------------------------------------------
# Variation 1: Missing Number (LeetCode 268)
# ---------------------------------------------------------------
#
# A list holds n different numbers from 0 to n, with one missing.
#   [3, 0, 1]  ->  2
#
# XOR all the indexes 0..n AND all the values. Every number that's
# present appears twice (once as an index, once as a value) and
# cancels. The missing one appears only once.

def missing_number(nums):
    result = len(nums)                    # n itself, which has no index
    for i, num in enumerate(nums):
        result ^= i ^ num
    return result


# ---------------------------------------------------------------
# Variation 2: swap two variables without a temporary one
# ---------------------------------------------------------------
#
#   a ^= b      a now holds a ^ b
#   b ^= a      b = b ^ (a ^ b) = a
#   a ^= b      a = (a ^ b) ^ a = b
#
# In Python, just write a, b = b, a. This is here because it's a
# classic interview question and shows the cancelling rule clearly.

def xor_swap(a, b):
    a ^= b
    b ^= a
    a ^= b
    return a, b


# ---------------------------------------------------------------
# Variation 3: the repeating-key XOR cipher
# ---------------------------------------------------------------
#
# XOR each byte of the message with a byte of the key, repeating the
# key as needed. Encrypting and decrypting are the SAME function,
# because XORing with the key twice cancels it out.
#
# bytes are lists of numbers 0-255, so ^ works on each one directly.
# Bytes and encodings get their own lesson next.
#
# FOR LEARNING ONLY. A short repeating key is easy to break; use a
# real library (like the `cryptography` package) for anything real.

def xor_cipher(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


# Known-plaintext attack: if you know how the message STARTS, XOR it
# with the start of the ciphertext and the key falls out.
#   ciphertext ^ plaintext = (plaintext ^ key) ^ plaintext = key

def recover_key(ciphertext: bytes, known_start: bytes) -> bytes:
    return bytes(c ^ p for c, p in zip(ciphertext, known_start))


# ---------------------------------------------------------------
# COMPLEXITY (n = length of nums)
# ---------------------------------------------------------------
#
#   Solution                  | Time  | Extra space
#   --------------------------|-------|-----------------
#   1. Counter                | O(n)  | O(n)
#   2. Add/remove set         | O(n)  | O(n)
#   3. Maths trick            | O(n)  | O(n)  set(nums)
#   4. XOR                    | O(n)  | O(1)
#   Missing Number (XOR)      | O(n)  | O(1)
#   XOR cipher                | O(n)  | O(n)  the output


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    test_cases = [
        # (nums, expected)
        ([2, 2, 1], 1),                    # LeetCode example 1
        ([4, 1, 2, 1, 2], 4),              # LeetCode example 2
        ([1], 1),                          # LeetCode example 3
        ([0, 7, 7], 0),                    # the single number is 0
        ([-1, 3, 3], -1),                  # negative numbers
        ([10**9, -5, -5], 10**9),          # big numbers
    ]

    solutions = [single_number_counter, single_number_set, single_number_math,
                 single_number, single_number_reduce]

    for solve in solutions:
        for nums, expected in test_cases:
            result = solve(nums)
            assert result == expected, (
                f"{solve.__name__}({nums}) returned {result}, expected {expected}"
            )

    # The three XOR rules
    for x in [0, 5, -3, 1234]:
        assert x ^ 0 == x
        assert x ^ x == 0
        assert 9 ^ x ^ 9 == x

    # Missing Number (LeetCode 268 examples)
    assert missing_number([3, 0, 1]) == 2
    assert missing_number([0, 1]) == 2
    assert missing_number([9, 6, 4, 2, 3, 5, 7, 0, 1]) == 8
    assert missing_number([1]) == 0

    # Swap
    assert xor_swap(3, 10) == (10, 3)
    assert xor_swap(-4, 4) == (4, -4)

    # Cipher: encrypting twice gives the original back
    message = b"attack at dawn"
    key = b"KEY"
    encrypted = xor_cipher(message, key)
    assert encrypted != message
    assert xor_cipher(encrypted, key) == message

    # Known-plaintext attack recovers the key
    assert recover_key(encrypted, b"att") == key

    print("All tests passed!")


if __name__ == "__main__":
    nums = [4, 1, 2, 1, 2]
    print(f"Single number in {nums}: {single_number(nums)}")

    print("\nXOR step by step:")
    result = 0
    for num in nums:
        print(f"  {result:03b} ^ {num:03b} = {result ^ num:03b}   ({result} ^ {num} = {result ^ num})")
        result ^= num

    print(f"\nMissing number in [3, 0, 1]: {missing_number([3, 0, 1])}")

    # XOR cipher and the known-plaintext attack
    message = b"Meeting at 9pm. Password is hunter2."
    key = b"S3cr"
    encrypted = xor_cipher(message, key)
    print(f"\nMessage:    {message}")
    print(f"Key:        {key}")
    print(f"Encrypted:  {encrypted.hex()}")
    print(f"Decrypted:  {xor_cipher(encrypted, key)}")

    # The attacker guesses the message starts with "Meet"
    guessed_key = recover_key(encrypted, b"Meet")
    print(f"\nAttacker guesses the message starts with b'Meet'")
    print(f"Recovered key: {guessed_key}")
    print(f"Whole message: {xor_cipher(encrypted, guessed_key)}")

    print()
    run_tests()
