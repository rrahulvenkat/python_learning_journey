# Base64 and URL Encoding by Hand
#
# PROBLEM
# -------
#   1. Write a Base64 encoder and decoder WITHOUT the base64 module.
#         b"Man"  <->  "TWFu"
#   2. Write URL percent-encoding and decoding WITHOUT urllib.
#         "a b/c"  <->  "a%20b%2Fc"
#
# KEY IDEAS: BASE64
# -----------------
# Base64 turns ANY bytes into 64 safe, printable characters:
#   A-Z (0-25)  a-z (26-51)  0-9 (52-61)  + (62)  / (63)
#
# 64 = 2^6, so each character holds 6 bits. 3 bytes = 24 bits =
# exactly 4 characters:
#
#   text      M          a          n
#   bytes     77         97         110
#   bits      01001101   01100001   01101110
#   regroup   010011  010110  000101  101110
#   values    19      22      5       46
#   chars     T       W       F       u          -> "TWFu"
#
# Join the 3 bytes into one 24-bit number with shifts, then cut it
# into four 6-bit pieces with >> and & 0x3F (the tools from
# counting_bits.py).
#
# If the data doesn't divide into 3s, pad with zero bits and mark the
# missing bytes with "=":
#   b"Ma" -> "TWE="     b"M" -> "TQ=="
#
# KEY IDEAS: URL ENCODING
# -----------------------
# URLs may only contain certain characters. Anything else becomes
# "%" plus its byte in hex, using the UTF-8 bytes for non-ASCII:
#   " " -> %20     "/" -> %2F     "é" -> %C3%A9 (two bytes)
# Letters, digits and - . _ ~ ("unreserved") are left alone.
#
# WHAT'S NEW HERE
# ---------------
# This file combines hex (hex_and_bytes.py), UTF-8 (utf8_encoding.py)
# and bit shifting (counting_bits.py) into two encoders you'll see
# every day in web and security work.
#
# SECURITY CONNECTION
# -------------------
#   - Base64 is NOT encryption. Anyone can decode it. HTTP Basic
#     authentication sends "user:password" in Base64, so without HTTPS
#     the password is effectively plain text. The demo decodes one.
#   - Attackers Base64-encode payloads to hide them from simple
#     filters (for example PowerShell's -EncodedCommand). Decoding
#     suspicious Base64 is a routine part of log analysis.
#   - DOUBLE ENCODING: "../" -> "%2e%2e%2f" -> "%252e%252e%252f".
#     A filter that decodes once and checks for "../" sees nothing; a
#     later step that decodes AGAIN produces "../". Decode fully
#     before checking, and reject input that's still encoded.


import base64
import urllib.parse


ALPHABET = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/")


# ---------------------------------------------------------------
# Part 1: Base64 encode
# ---------------------------------------------------------------
#
# For each group of up to 3 bytes:
#   1. Pad the group with zero bytes to 3.
#   2. value = b0 << 16 | b1 << 8 | b2           (24 bits)
#   3. Four 6-bit pieces: value >> 18, >> 12, >> 6, >> 0, each & 0x3F
#   4. A full group gives 4 characters. A group of 2 bytes gives 3
#      real characters + "=", and 1 byte gives 2 + "==".
#
# Trace for b"Ma" (only 2 bytes):
#   padded     77 97 0
#   bits       010011 010110 000100 000000
#   values     19     22     4      (padding)
#   chars      T      W      E      =          -> "TWE="

def b64_encode(data: bytes) -> str:
    out = []
    for i in range(0, len(data), 3):
        group = data[i:i + 3]
        missing = 3 - len(group)                    # 0, 1 or 2
        b0, b1, b2 = group + bytes(missing)         # pad with zero bytes

        value = (b0 << 16) | (b1 << 8) | b2
        chars = [ALPHABET[(value >> shift) & 0x3F] for shift in (18, 12, 6, 0)]

        out.extend(chars[:4 - missing])             # drop the padding characters
        out.append("=" * missing)                   # and mark them with "="
    return "".join(out)


# ---------------------------------------------------------------
# Part 2: Base64 decode
# ---------------------------------------------------------------
#
# The reverse: 4 characters -> 24 bits -> 3 bytes, then drop one byte
# for each "=".
#
# Strict checks, because decoders that accept junk cause bugs:
#   - length must be a multiple of 4
#   - only ALPHABET characters, with "=" only at the very end (max 2)

LOOKUP = {ch: i for i, ch in enumerate(ALPHABET)}   # "A" -> 0, ..., "/" -> 63

def b64_decode(text: str) -> bytes:
    text = "".join(text.split())                    # ignore line breaks
    if len(text) % 4 != 0:
        raise ValueError("Base64 length must be a multiple of 4")

    padding = len(text) - len(text.rstrip("="))
    if padding > 2:
        raise ValueError("too much '=' padding")

    out = bytearray()
    for i in range(0, len(text), 4):
        group = text[i:i + 4]
        is_last = i + 4 == len(text)
        if not is_last and "=" in group:
            raise ValueError("'=' is only allowed at the end")

        value = 0
        for ch in group.rstrip("=") + "A" * (group.count("=")):   # treat "=" as 0
            if ch not in LOOKUP:
                raise ValueError(f"invalid Base64 character {ch!r}")
            value = (value << 6) | LOOKUP[ch]

        three = [(value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF]
        keep = 3 - (padding if is_last else 0)
        out.extend(three[:keep])
    return bytes(out)


# ---------------------------------------------------------------
# Part 3: URL-safe Base64
# ---------------------------------------------------------------
#
# "+" and "/" mean something in URLs, so the URL-safe variant uses
# "-" and "_" instead. JSON Web Tokens (JWTs) use this form, usually
# with the "=" padding removed.

def b64url_encode(data: bytes) -> str:
    return b64_encode(data).replace("+", "-").replace("/", "_").rstrip("=")

def b64url_decode(text: str) -> bytes:
    text = text.replace("-", "+").replace("_", "/")
    text += "=" * (-len(text) % 4)                  # put the padding back
    return b64_decode(text)


# ---------------------------------------------------------------
# Part 4: URL percent-encoding
# ---------------------------------------------------------------
#
# Encode the text as UTF-8, then for each BYTE:
#   unreserved (A-Z a-z 0-9 - . _ ~) -> keep it
#   anything else                    -> "%" + two upper-case hex digits
#
#   "a b/é" -> bytes 61 20 62 2f c3 a9 -> "a%20b%2F%C3%A9"

UNRESERVED = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")

def url_encode(text: str) -> str:
    out = []
    for byte in text.encode("utf-8"):
        if byte in UNRESERVED:
            out.append(chr(byte))
        else:
            out.append(f"%{byte:02X}")
    return "".join(out)


# Decode: collect BYTES (because %C3%A9 is two bytes of one
# character), then decode them as UTF-8 at the end.

def url_decode(text: str) -> str:
    out = bytearray()
    i = 0
    while i < len(text):
        if text[i] == "%":
            pair = text[i + 1:i + 3]
            if len(pair) != 2 or not all(c in "0123456789abcdefABCDEF" for c in pair):
                raise ValueError(f"bad escape at position {i}: {text[i:i + 3]!r}")
            out.append(int(pair, 16))
            i += 3
        else:
            out.extend(text[i].encode("utf-8"))
            i += 1
    return out.decode("utf-8")                      # strict: rejects bad UTF-8


# ---------------------------------------------------------------
# Part 5: the double-encoding trap
# ---------------------------------------------------------------
#
# A NAIVE filter decodes once and looks for "../".
# A SAFER filter keeps decoding until nothing changes, then checks.

def naive_is_safe(path):
    return "../" not in url_decode(path)

def fully_decode(text, max_rounds=5):
    for _ in range(max_rounds):
        decoded = url_decode(text)
        if decoded == text:
            return decoded
        text = decoded
    raise ValueError("too many layers of encoding")  # suspicious in itself

def safer_is_safe(path):
    return "../" not in fully_decode(path)


# ---------------------------------------------------------------
# COMPLEXITY (n = input length)
# ---------------------------------------------------------------
#
#   Function        | Time  | Output size
#   ----------------|-------|------------------------------------
#   b64_encode      | O(n)  | 4/3 of the input (33% bigger)
#   b64_decode      | O(n)  | 3/4 of the input
#   url_encode      | O(n)  | up to 3x (every byte -> %XX)
#   url_decode      | O(n)  |
#
# In real code use base64.b64encode / b64decode(validate=True),
# base64.urlsafe_b64encode, and urllib.parse.quote / unquote.


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    samples = [b"", b"M", b"Ma", b"Man", b"Hello, World!", bytes(range(256)),
               b"\xff\xfe\xfd", "café ₹".encode()]

    # Base64 by hand agrees with the base64 module, both ways
    for data in samples:
        expected = base64.b64encode(data).decode()
        assert b64_encode(data) == expected, data
        assert b64_decode(expected) == data, data

    # The examples from the comments
    assert b64_encode(b"Man") == "TWFu"
    assert b64_encode(b"Ma") == "TWE="
    assert b64_encode(b"M") == "TQ=="

    # Strict decoding
    for bad in ["TWF", "TW=u", "T===", "TW!u", "TQ==TWFu"]:
        try:
            b64_decode(bad)
            assert False, f"expected ValueError for {bad!r}"
        except ValueError:
            pass

    # URL-safe Base64
    for data in samples:
        expected = base64.urlsafe_b64encode(data).decode().rstrip("=")
        assert b64url_encode(data) == expected
        assert b64url_decode(expected) == data
    assert b64url_encode(b"\xfb\xff") == "-_8"       # would be "+/8=" normally

    # URL encoding agrees with urllib
    texts = ["", "abc", "a b/c", "café", "x=1&y=2", "100% sure?", "~user_name-1.0",
             "<script>alert(1)</script>"]
    for text in texts:
        assert url_encode(text) == urllib.parse.quote(text, safe=""), text
        assert url_decode(url_encode(text)) == text
        assert url_decode(url_encode(text)) == urllib.parse.unquote(url_encode(text))

    assert url_decode("%c3%a9") == "é"               # lower-case hex is fine
    for bad in ["%", "%2", "%zz", "%C3"]:            # last one: cut-off UTF-8
        try:
            url_decode(bad)
            assert False, f"expected an error for {bad!r}"
        except (ValueError, UnicodeDecodeError):
            pass

    # Double encoding
    once = url_encode("../")
    twice = url_encode(once)
    assert once == "..%2F" and twice == "..%252F"
    assert naive_is_safe("%252e%252e%252f") is True  # fooled!
    assert safer_is_safe("%252e%252e%252f") is False
    assert safer_is_safe("docs/report.pdf") is True

    print("All tests passed!")


if __name__ == "__main__":
    data = b"Man"
    print("Base64 step by step for b'Man':")
    value = (data[0] << 16) | (data[1] << 8) | data[2]
    print(f"  24 bits: {value:024b}")
    pieces = [(value >> s) & 0x3F for s in (18, 12, 6, 0)]
    print(f"  6-bit:   {' '.join(format(p, '06b') for p in pieces)}")
    print(f"  values:  {pieces}")
    print(f"  chars:   {b64_encode(data)}")

    # Base64 is not encryption
    header = "Authorization: Basic " + b64_encode(b"admin:Summer2026!")
    print(f"\nA captured HTTP header:\n  {header}")
    secret = header.split()[-1]
    print(f"Decoded by anyone who sees it: {b64_decode(secret).decode()!r}")

    # A JWT's first two parts are just URL-safe Base64 JSON
    jwt_header = b64url_encode(b'{"alg":"HS256","typ":"JWT"}')
    print(f"\nJWT header part: {jwt_header}")
    print(f"Decoded:         {b64url_decode(jwt_header).decode()}")

    print(f"\nURL encoding: {'name=Ravi & Co/é'!r} -> {url_encode('name=Ravi & Co/é')!r}")

    print("\nDouble-encoding attack on a '../' filter:")
    attack = "%252e%252e%252fetc%252fpasswd"
    print(f"  input:          {attack}")
    print(f"  decoded once:   {url_decode(attack)}")
    print(f"  decoded fully:  {fully_decode(attack)}")
    print(f"  naive filter says safe?  {naive_is_safe(attack)}")
    print(f"  safer filter says safe?  {safer_is_safe(attack)}")

    print()
    run_tests()
