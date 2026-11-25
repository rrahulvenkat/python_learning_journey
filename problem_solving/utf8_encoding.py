# UTF-8 by Hand: encoding, decoding, and the bugs attackers use
#
# PROBLEM
# -------
#   1. Encode a string to UTF-8 bytes WITHOUT str.encode().
#   2. Decode UTF-8 bytes back to a string WITHOUT bytes.decode(), and
#      REJECT invalid input the way a careful decoder must.
#   3. Spot two Unicode tricks: mojibake (decoding with the wrong
#      encoding) and lookalike characters in domain names.
#
# KEY IDEAS
# ---------
# Every character has a number called its CODE POINT:  ord("A") == 65,
# ord("é") == 233, ord("₹") == 8377. UTF-8 stores each code point in
# 1 to 4 bytes. The first byte's leading bits say how many:
#
#   code point range     | bytes | bit pattern
#   ---------------------|-------|---------------------------------------------
#   0 - 127 (ASCII)      |   1   | 0xxxxxxx
#   128 - 2,047          |   2   | 110xxxxx 10xxxxxx
#   2,048 - 65,535       |   3   | 1110xxxx 10xxxxxx 10xxxxxx
#   65,536 - 1,114,111   |   4   | 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
#
# The x's hold the code point's bits, 6 per CONTINUATION byte
# (10xxxxxx). Encoding fills them in with shifts and masks; decoding
# pulls them out again.
#
# Example: "é" is 233 = 000 1110 1001 in binary (11 bits, so 2 bytes)
#   first byte:   110 + top 5 bits  00011  -> 11000011 = 0xC3
#   second byte:  10  + low 6 bits  101001 -> 10101001 = 0xA9
#   "é".encode() == b"\xc3\xa9"
#
# Plain ASCII text is unchanged in UTF-8, which is why it took over.
#
# WHAT'S NEW HERE
# ---------------
# data_structures/strings.py showed that "café ₹" is 6 characters but
# 9 bytes. This file shows WHY, by building the bytes yourself with
# the shifts and masks from counting_bits.py.
#
# SECURITY CONNECTION
# -------------------
#   - OVERLONG ENCODINGS: "/" is 0x2F, one byte. A sloppy decoder also
#     accepts the 2-byte form C0 AF. Old web servers checked for "../"
#     BEFORE decoding, so "..%c0%af" slipped past and became "../"
#     afterwards (a real path traversal bug in Microsoft IIS, 2000).
#     A correct decoder must reject overlong forms.
#   - HOMOGLYPHS: Cyrillic "а" (U+0430) looks identical to Latin "a".
#     "pаypal.com" with a Cyrillic а is a different domain, used for
#     phishing. Browsers show such domains in "punycode" (xn--...) to
#     expose the trick.
#   - Always decode input ONCE, early, with a strict decoder, and only
#     THEN check it.


import unicodedata


# ---------------------------------------------------------------
# Part 1: encode one code point
# ---------------------------------------------------------------
#
#   0x80 = 10000000    continuation marker
#   0x3F = 00111111    "keep the low 6 bits"
#   0xC0 = 11000000    2-byte lead marker
#   0xE0 = 11100000    3-byte lead marker
#   0xF0 = 11110000    4-byte lead marker
#
# Code points 0xD800-0xDFFF ("surrogates") are reserved for UTF-16
# and are not allowed in UTF-8.

def encode_code_point(cp):
    if cp < 0 or cp > 0x10FFFF:
        raise ValueError(f"{cp:#x} is outside the Unicode range")
    if 0xD800 <= cp <= 0xDFFF:
        raise ValueError(f"{cp:#x} is a surrogate and can't be encoded")

    if cp < 0x80:                                   # 1 byte: 0xxxxxxx
        return bytes([cp])
    if cp < 0x800:                                  # 2 bytes
        return bytes([0xC0 | (cp >> 6),
                      0x80 | (cp & 0x3F)])
    if cp < 0x10000:                                # 3 bytes
        return bytes([0xE0 | (cp >> 12),
                      0x80 | ((cp >> 6) & 0x3F),
                      0x80 | (cp & 0x3F)])
    return bytes([0xF0 | (cp >> 18),                # 4 bytes
                  0x80 | ((cp >> 12) & 0x3F),
                  0x80 | ((cp >> 6) & 0x3F),
                  0x80 | (cp & 0x3F)])


def utf8_encode(text: str) -> bytes:
    return b"".join(encode_code_point(ord(ch)) for ch in text)


# ---------------------------------------------------------------
# Part 2: decode, strictly
# ---------------------------------------------------------------
#
# For each lead byte:
#   1. Work out how many continuation bytes follow, and the SMALLEST
#      code point that length is allowed to hold.
#   2. Each continuation byte must look like 10xxxxxx. Add its 6 bits:
#          cp = (cp << 6) | (byte & 0x3F)
#   3. Reject the result if it's OVERLONG (could have used fewer
#      bytes), a surrogate, or above 0x10FFFF.
#
# Trace for b"\xe2\x82\xb9" ("₹"):
#
#   byte | binary   | role               | cp so far
#   -----|----------|--------------------|---------------------------
#   e2   | 11100010 | lead, 2 more bytes | 0010            (low 4 bits)
#   82   | 10000010 | continuation       | 0010 000010
#   b9   | 10111001 | continuation       | 0010 000010 111001 = 8377
#
#   chr(8377) == "₹"

def utf8_decode(data: bytes) -> str:
    chars = []
    i = 0
    while i < len(data):
        lead = data[i]

        if lead < 0x80:                              # 0xxxxxxx
            extra, cp, smallest = 0, lead, 0
        elif lead & 0xE0 == 0xC0:                    # 110xxxxx
            extra, cp, smallest = 1, lead & 0x1F, 0x80
        elif lead & 0xF0 == 0xE0:                    # 1110xxxx
            extra, cp, smallest = 2, lead & 0x0F, 0x800
        elif lead & 0xF8 == 0xF0:                    # 11110xxx
            extra, cp, smallest = 3, lead & 0x07, 0x10000
        else:
            raise ValueError(f"invalid lead byte {lead:#04x} at position {i}")

        for k in range(1, extra + 1):
            if i + k >= len(data):
                raise ValueError(f"sequence at position {i} is cut off")
            byte = data[i + k]
            if byte & 0xC0 != 0x80:                  # must be 10xxxxxx
                raise ValueError(f"expected a continuation byte at position {i + k}")
            cp = (cp << 6) | (byte & 0x3F)

        if cp < smallest:
            raise ValueError(f"overlong encoding at position {i}")
        if 0xD800 <= cp <= 0xDFFF:
            raise ValueError(f"surrogate at position {i}")
        if cp > 0x10FFFF:
            raise ValueError(f"code point too large at position {i}")

        chars.append(chr(cp))
        i += extra + 1

    return "".join(chars)


# A deliberately SLOPPY decoder, to show the bug. It skips the
# overlong check, so C0 AF becomes "/". Never write one of these.

def sloppy_decode_2byte(data: bytes) -> str:
    out = []
    i = 0
    while i < len(data):
        b = data[i]
        if b & 0xE0 == 0xC0 and i + 1 < len(data):
            out.append(chr(((b & 0x1F) << 6) | (data[i + 1] & 0x3F)))
            i += 2
        else:
            out.append(chr(b))
            i += 1
    return "".join(out)


# ---------------------------------------------------------------
# Part 3: mojibake (decoding with the wrong encoding)
# ---------------------------------------------------------------
#
# Latin-1 treats EVERY byte as one character, so it never fails, but
# UTF-8 text decoded as Latin-1 turns into garbage:
#
#   "café" -> UTF-8 bytes 63 61 66 c3 a9 -> as Latin-1: "cafÃ©"
#
# This "mojibake" shows up in logs and databases all the time. The fix
# is to reverse the mistake: encode as Latin-1, decode as UTF-8.

def make_mojibake(text):
    return text.encode("utf-8").decode("latin-1")

def fix_mojibake(text):
    return text.encode("latin-1").decode("utf-8")


# ---------------------------------------------------------------
# Part 4: spot lookalike characters (homoglyphs)
# ---------------------------------------------------------------
#
# unicodedata.name() tells you what a character really is:
#   unicodedata.name("a")       == "LATIN SMALL LETTER A"
#   unicodedata.name("а")  == "CYRILLIC SMALL LETTER A"
#
# The first word is roughly the writing system (script). A domain that
# mixes scripts, like Latin and Cyrillic, is a strong warning sign.

def scripts_used(text):
    scripts = set()
    for ch in text:
        if ch.isalpha():
            scripts.add(unicodedata.name(ch).split()[0])
    return scripts


def is_suspicious_domain(domain):
    return len(scripts_used(domain)) > 1


# ---------------------------------------------------------------
# COMPLEXITY (n = number of characters or bytes)
# ---------------------------------------------------------------
#
#   Function             | Time   | Notes
#   ---------------------|--------|-------------------------------
#   utf8_encode          | O(n)   | output is 1-4 bytes per character
#   utf8_decode          | O(n)   | each byte is read once
#   scripts_used         | O(n)   |
#
# In real code use text.encode("utf-8") and data.decode("utf-8"),
# which are strict by default. Use errors="replace" only for display,
# never before a security check.


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    samples = ["", "A", "hello", "café", "₹100", "naïve résumé",
               "日本語", "😀 emoji", "mixed: a é ₹ 😀",
               "".join(chr(cp) for cp in (0x7F, 0x80, 0x7FF, 0x800, 0xFFFF,
                                          0x10000, 0x10FFFF))]   # range edges

    # Encoding and decoding agree with Python, both ways
    for text in samples:
        expected = text.encode("utf-8")
        assert utf8_encode(text) == expected, text
        assert utf8_decode(expected) == text, text

    # Byte counts from the table
    assert len(utf8_encode("A")) == 1
    assert len(utf8_encode("é")) == 2
    assert len(utf8_encode("₹")) == 3
    assert len(utf8_encode("😀")) == 4
    assert utf8_encode("é") == b"\xc3\xa9"

    # Invalid input is rejected (and Python rejects the same input)
    invalid = [
        b"\xc0\xaf",            # overlong "/"
        b"\xe0\x80\xaf",        # overlong "/" in 3 bytes
        b"\xc3",                # cut off
        b"\xe2\x82",            # cut off
        b"\x80",                # continuation byte with no lead
        b"\xc3\x28",            # second byte isn't a continuation
        b"\xed\xa0\x80",        # surrogate D800
        b"\xf4\x90\x80\x80",    # above 0x10FFFF
        b"\xff",                # never valid in UTF-8
    ]
    for data in invalid:
        try:
            utf8_decode(data)
            assert False, f"utf8_decode accepted {data!r}"
        except ValueError:
            pass
        try:
            data.decode("utf-8")
            assert False, f"Python accepted {data!r}"
        except UnicodeDecodeError:
            pass

    # The sloppy decoder falls for the overlong trick
    assert sloppy_decode_2byte(b"..\xc0\xaf") == "../"

    # Surrogates can't be encoded
    try:
        encode_code_point(0xD800)
        assert False
    except ValueError:
        pass

    # Mojibake
    assert make_mojibake("café") == "cafÃ©"
    assert fix_mojibake("cafÃ©") == "café"
    assert fix_mojibake(make_mojibake("₹ naïve")) == "₹ naïve"

    # Homoglyphs
    assert scripts_used("paypal.com") == {"LATIN"}
    assert scripts_used("pаypal.com") == {"LATIN", "CYRILLIC"}
    assert is_suspicious_domain("pаypal.com") is True
    assert is_suspicious_domain("paypal.com") is False
    assert is_suspicious_domain("яндекс.рф") is False      # all Cyrillic is fine

    print("All tests passed!")


if __name__ == "__main__":
    print(f"{'char':<6}{'code point':<12}{'UTF-8 bytes':<14}binary")
    for ch in ["A", "é", "₹", "😀"]:
        data = utf8_encode(ch)
        bits = " ".join(format(b, "08b") for b in data)
        print(f"{ch:<6}U+{ord(ch):04X}{'':<6}{data.hex(' '):<14}{bits}")

    # The overlong path traversal trick
    attack = b"..\xc0\xaf..\xc0\xafetc/passwd"
    print(f"\nInput bytes: {attack!r}")
    print(f"  contains b'../' before decoding? {b'../' in attack}")
    print(f"  sloppy decoder gives:  {sloppy_decode_2byte(attack)!r}")
    try:
        utf8_decode(attack)
    except ValueError as err:
        print(f"  strict decoder: rejected ({err})")

    print(f"\nMojibake: 'café' decoded as Latin-1 -> {make_mojibake('café')!r}")
    print(f"Fixed:    {fix_mojibake(make_mojibake('café'))!r}")

    print("\nLookalike domains:")
    for domain in ["paypal.com", "pаypal.com"]:
        print(f"  {domain:<12} scripts={sorted(scripts_used(domain))}  "
              f"suspicious={is_suspicious_domain(domain)}  "
              f"punycode={domain.encode('idna').decode()}")

    print()
    run_tests()
