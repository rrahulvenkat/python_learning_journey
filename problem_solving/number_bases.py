# Number Bases: binary, hex and decimal by hand
# (includes LeetCode 405, Convert a Number to Hexadecimal)
#
# PROBLEM
# -------
#   1. Convert a non-negative integer to a string in any base from 2
#      to 16, WITHOUT using bin(), hex() or format().
#         255 -> base 2:  "11111111"
#         255 -> base 16: "ff"
#   2. Convert such a string back to an integer, without int(s, base).
#   3. Then apply it: IPv4 addresses and subnet masks are 32-bit
#      numbers in disguise.
#
# KEY IDEAS
# ---------
#   - In base b, each digit is worth b times the digit to its right:
#         "2f" in base 16 = 2 * 16 + 15 = 47
#   - Number -> digits: repeatedly divide by b. The REMAINDERS are the
#     digits, from right to left.   divmod(n, b) gives both at once.
#   - Digits -> number: read left to right, and for each digit do
#         value = value * b + digit
#     (the same idea as building "12" from "1" and "2" in
#     decode_string.py, but for any base).
#   - In base 16, one digit is exactly 4 bits, so hex is a short way
#     to write binary:  1111 1111 = f f.
#
# WHAT'S NEW HERE
# ---------------
# You've printed numbers with format codes like {n:08b}. This file
# shows the ALGORITHMS behind them, then uses shifts and masks
# (counting_bits.py) on real network data.
#
# SECURITY CONNECTION
# -------------------
#   - Hex is everywhere: hashes, memory addresses, MAC addresses,
#     packet dumps and shellcode. Reading it quickly matters.
#   - An IPv4 address is one 32-bit number. A subnet like
#     192.168.1.0/24 means "the first 24 bits must match". Checking if
#     an IP is in an allowed range is a single AND with the mask.
#   - Attackers sometimes write IPs in odd forms to slip past filters:
#     http://3232235777 and http://0xC0A80101 are both 192.168.1.1.
#     A filter that only checks the dotted form can be bypassed.


import ipaddress


DIGITS = "0123456789abcdef"


# ---------------------------------------------------------------
# Part 1: integer -> string in any base (repeated division)
# ---------------------------------------------------------------
#
# Trace for n = 47, base = 16:
#
#   n  | divmod(n, 16) | digit | digits so far (reversed)
#   ---|---------------|-------|--------------------------
#   47 | (2, 15)       |  f    | f
#    2 | (0, 2)        |  2    | f 2
#    0 | stop
#
# Reverse at the end: "2f".
#
# Trace for n = 13, base = 2:
#   13 -> (6, 1) -> 6 -> (3, 0) -> 3 -> (1, 1) -> 1 -> (0, 1)
#   remainders 1 0 1 1, reversed: "1101"

def to_base(n, base):
    if not 2 <= base <= 16:
        raise ValueError("base must be between 2 and 16")
    if n < 0:
        return "-" + to_base(-n, base)
    if n == 0:
        return "0"

    digits = []
    while n > 0:
        n, remainder = divmod(n, base)
        digits.append(DIGITS[remainder])
    return "".join(reversed(digits))


# ---------------------------------------------------------------
# Part 2: string -> integer (multiply and add, left to right)
# ---------------------------------------------------------------
#
# Trace for "2f", base 16:
#
#   ch | digit | value * 16 + digit
#   ---|-------|-------------------
#   2  |   2   |  0 * 16 + 2 = 2
#   f  |  15   |  2 * 16 + 15 = 47
#
# It accepts upper or lower case, and rejects digits that don't exist
# in the base (like "2" in binary).

def from_base(text, base):
    if not 2 <= base <= 16:
        raise ValueError("base must be between 2 and 16")
    text = text.strip().lower()
    negative = text.startswith("-")
    if negative:
        text = text[1:]
    if not text:
        raise ValueError("no digits")

    value = 0
    for ch in text:
        digit = DIGITS.find(ch)                     # -1 if not a digit at all
        if digit == -1 or digit >= base:
            raise ValueError(f"{ch!r} is not a digit in base {base}")
        value = value * base + digit
    return -value if negative else value


# ---------------------------------------------------------------
# Part 3: Convert a Number to Hexadecimal (LeetCode 405)
# ---------------------------------------------------------------
#
# Like to_base(n, 16), but NEGATIVE numbers must use 32-bit two's
# complement, the way a computer stores them:
#   -1  ->  "ffffffff"
#
# Python integers have no fixed size, so first force n into 32 bits
# with a mask:  n & 0xFFFFFFFF  (32 ones). For -1 that gives
# 4294967295, which is ffffffff.
#
# Then read 4 bits (one hex digit) at a time with  n & 0xF  and
# n >> 4, instead of dividing. Shifting and masking by powers of two
# is the bit-level version of divmod.

def to_hex(num):
    if num == 0:
        return "0"
    num &= 0xFFFFFFFF                       # 32-bit two's complement
    digits = []
    while num:
        digits.append(DIGITS[num & 0xF])    # lowest 4 bits
        num >>= 4                           # drop them
    return "".join(reversed(digits))


# ---------------------------------------------------------------
# Part 4: IPv4 address <-> 32-bit integer
# ---------------------------------------------------------------
#
# Each of the 4 parts is one byte (8 bits). Shift each into place:
#
#   192.168.1.1
#   192 << 24 | 168 << 16 | 1 << 8 | 1
#   = 11000000 10101000 00000001 00000001
#   = 3232235777
#
# Going back: shift right and keep the lowest 8 bits with & 0xFF.

def ip_to_int(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        raise ValueError(f"{ip!r} does not have 4 parts")
    value = 0
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            raise ValueError(f"{part!r} is not a number from 0 to 255")
        value = (value << 8) | int(part)            # make room, then add
    return value


def int_to_ip(value):
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("not a 32-bit number")
    return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))


# ---------------------------------------------------------------
# Part 5: subnets (CIDR) with masks
# ---------------------------------------------------------------
#
# "/24" means the first 24 bits are the NETWORK part. The mask is
# 24 ones followed by 8 zeros:
#
#   /24 mask = 11111111 11111111 11111111 00000000 = 255.255.255.0
#
# An IP is in the subnet when its network bits match:
#   (ip & mask) == (network & mask)
#
#   192.168.1.77 & 255.255.255.0 = 192.168.1.0   -> in 192.168.1.0/24
#   192.168.2.5  & 255.255.255.0 = 192.168.2.0   -> not in it

def prefix_to_mask(prefix):
    if not 0 <= prefix <= 32:
        raise ValueError("prefix must be 0 to 32")
    # 32 ones, then shift left to push zeros in from the right
    return (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF


def in_subnet(ip, cidr):
    network, prefix = cidr.split("/")
    mask = prefix_to_mask(int(prefix))
    return ip_to_int(ip) & mask == ip_to_int(network) & mask


def subnet_size(prefix):
    """How many addresses a /prefix holds: 2 to the number of host bits."""
    return 1 << (32 - prefix)


# ---------------------------------------------------------------
# COMPLEXITY (d = number of digits in the result)
# ---------------------------------------------------------------
#
#   Function          | Time   | Notes
#   ------------------|--------|-------------------------------------
#   to_base           | O(d)   | d = log_base(n)
#   from_base         | O(d)   |
#   to_hex            | O(1)   | at most 8 hex digits (32 bits)
#   ip_to_int         | O(1)   | always 4 parts
#   in_subnet         | O(1)   | one AND and one comparison
#
# In real code, use the built-ins: bin(), hex(), int(s, base) and the
# ipaddress module. They handle more edge cases (IPv6 too). The tests
# check these versions against them.


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    # to_base agrees with Python's format codes
    for n in [0, 1, 2, 7, 10, 47, 255, 256, 1_000_000, -42]:
        assert to_base(n, 2) == format(n, "b")
        assert to_base(n, 8) == format(n, "o")
        assert to_base(n, 16) == format(n, "x")
        assert to_base(n, 10) == str(n)

    # from_base agrees with int(text, base)
    for text, base in [("2f", 16), ("FF", 16), ("1101", 2), ("777", 8),
                       ("0", 2), ("-ff", 16), ("10", 3)]:
        assert from_base(text, base) == int(text, base), (text, base)

    # Round trip in every base
    for base in range(2, 17):
        for n in range(0, 500, 7):
            assert from_base(to_base(n, base), base) == n

    # Bad input
    for text, base in [("2", 2), ("g", 16), ("", 10), ("12", 1)]:
        try:
            from_base(text, base)
            assert False, f"expected ValueError for {text!r} in base {base}"
        except ValueError:
            pass

    # LeetCode 405
    assert to_hex(26) == "1a"
    assert to_hex(-1) == "ffffffff"
    assert to_hex(0) == "0"
    assert to_hex(-2) == "fffffffe"
    for n in [1, 255, 4096, 2**31 - 1, -(2**31)]:
        assert to_hex(n) == format(n & 0xFFFFFFFF, "x")

    # IPs
    assert ip_to_int("192.168.1.1") == 3232235777
    assert int_to_ip(3232235777) == "192.168.1.1"
    assert int_to_ip(0xC0A80101) == "192.168.1.1"            # the hex disguise
    for ip in ["0.0.0.0", "10.0.0.1", "172.16.254.3", "255.255.255.255"]:
        assert int_to_ip(ip_to_int(ip)) == ip
        assert ip_to_int(ip) == int(ipaddress.IPv4Address(ip))
    for bad in ["256.1.1.1", "1.2.3", "a.b.c.d", "1.2.3.-4"]:
        try:
            ip_to_int(bad)
            assert False, f"expected ValueError for {bad!r}"
        except ValueError:
            pass

    # Masks and subnets
    assert int_to_ip(prefix_to_mask(24)) == "255.255.255.0"
    assert int_to_ip(prefix_to_mask(16)) == "255.255.0.0"
    assert int_to_ip(prefix_to_mask(0)) == "0.0.0.0"
    assert int_to_ip(prefix_to_mask(32)) == "255.255.255.255"
    assert subnet_size(24) == 256
    assert subnet_size(32) == 1

    checks = [
        ("192.168.1.77", "192.168.1.0/24", True),
        ("192.168.2.5", "192.168.1.0/24", False),
        ("10.20.30.40", "10.0.0.0/8", True),
        ("11.0.0.1", "10.0.0.0/8", False),
        ("172.16.5.4", "172.16.0.0/12", True),
        ("172.32.0.1", "172.16.0.0/12", False),
        ("8.8.8.8", "0.0.0.0/0", True),               # /0 matches everything
    ]
    for ip, cidr, expected in checks:
        assert in_subnet(ip, cidr) == expected, (ip, cidr)
        assert (ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)) == expected

    print("All tests passed!")


if __name__ == "__main__":
    print(f"{'decimal':>8} {'binary':>10} {'octal':>6} {'hex':>5}")
    for n in [5, 10, 47, 127, 255]:
        print(f"{n:>8} {to_base(n, 2):>10} {to_base(n, 8):>6} {to_base(n, 16):>5}")

    print(f"\nfrom_base('2f', 16) = {from_base('2f', 16)}")
    print(f"to_hex(-1) = {to_hex(-1)!r}  (32-bit two's complement)")

    ip = "192.168.1.1"
    value = ip_to_int(ip)
    print(f"\n{ip} as one number:")
    print(f"  decimal: {value}")
    print(f"  hex:     0x{to_base(value, 16).upper()}")
    print(f"  binary:  {' '.join(format((value >> s) & 0xFF, '08b') for s in (24, 16, 8, 0))}")
    print(f"  So http://{value} and http://0x{to_base(value, 16).upper()} "
          f"point to the same machine as http://{ip}")

    print("\nIs this IP in the allowed range?")
    allowed = "10.0.0.0/8"
    mask = prefix_to_mask(8)
    print(f"  allowed: {allowed}  (mask {int_to_ip(mask)}, {subnet_size(8):,} addresses)")
    for test_ip in ["10.4.2.1", "192.168.1.1", "10.255.255.255"]:
        print(f"  {test_ip:<16} -> {'yes' if in_subnet(test_ip, allowed) else 'no'}")

    print()
    run_tests()
