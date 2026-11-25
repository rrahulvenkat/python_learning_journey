# Hex and Raw Bytes: hex encoding, hexdump, file signatures, strings
#
# PROBLEM
# -------
#   1. Convert bytes to a hex string and back, WITHOUT bytes.hex() or
#      bytes.fromhex().
#         b"Hi!"  <->  "486921"
#   2. Print a "hexdump" of any bytes, like the xxd and hexdump tools.
#   3. Identify a file's real type from its first bytes (its "magic
#      number"), whatever its name says.
#   4. Pull readable text out of binary data, like the Unix `strings`
#      tool.
#
# KEY IDEAS
# ---------
#   - A byte is 8 bits, a number from 0 to 255. One hex digit is 4
#     bits, so every byte is EXACTLY two hex digits:
#         0x48 = 0100 1000 -> "4" "8"
#     High digit: byte >> 4.   Low digit: byte & 0xF.
#     (You used these in number_bases.py.)
#   - bytes behave like a list of numbers 0-255:
#         data[0]   -> an int, like 72
#         data[0:2] -> bytes, like b"Hi"
#     bytes can't be changed; bytearray can.
#   - Text is just bytes that happen to be printable. Codes 32 to 126
#     are the printable ASCII characters; everything else is shown as
#     "." in a hexdump.
#
# WHAT'S NEW HERE
# ---------------
# data_structures/strings.py showed encode() and decode() between str
# and bytes. This file works with the bytes THEMSELVES: reading them,
# printing them, and searching them for patterns.
#
# SECURITY CONNECTION
# -------------------
#   - Hexdumps are how you look at packets, memory, malware and file
#     formats. Every hex editor and debugger shows one.
#   - Attackers rename files to get past filters: an executable called
#     invoice.pdf. Checking the magic number, not the extension, is
#     how upload filters and analysts spot this.
#   - Running `strings` on an unknown binary is a standard first step
#     in malware analysis: it often reveals URLs, IP addresses,
#     file paths and commands hidden inside.


HEX_DIGITS = "0123456789abcdef"


# ---------------------------------------------------------------
# Part 1: bytes, bytearray and str in one minute
# ---------------------------------------------------------------
#
#   str        text, made of characters        "Hi"
#   bytes      raw data, numbers 0-255, fixed  b"Hi" == bytes([72, 105])
#   bytearray  like bytes, but changeable      bytearray(b"Hi")
#
# Indexing bytes gives an INT, not a one-character bytes object. This
# surprises everyone at first:
#   b"Hi"[0]   == 72
#   b"Hi"[0:1] == b"H"

def bytes_basics():
    data = b"Hi!"
    print("data         :", data)
    print("list(data)   :", list(data))              # [72, 105, 33]
    print("data[0]      :", data[0], "(an int)")
    print("data[0:1]    :", data[0:1], "(bytes)")
    print("bytes([72])  :", bytes([72]))

    changeable = bytearray(data)
    changeable[0] = ord("h")                         # bytes would raise TypeError
    print("bytearray    :", changeable)


# ---------------------------------------------------------------
# Part 2: bytes -> hex string (by hand)
# ---------------------------------------------------------------
#
# Trace for b"Hi!":
#
#   byte | decimal | byte >> 4 | byte & 0xF | hex
#   -----|---------|-----------|------------|----
#   H    |   72    |     4     |     8      | 48
#   i    |  105    |     6     |     9      | 69
#   !    |   33    |     2     |     1      | 21
#
#   -> "486921"

def to_hex(data: bytes) -> str:
    pieces = []
    for byte in data:
        pieces.append(HEX_DIGITS[byte >> 4])         # high 4 bits
        pieces.append(HEX_DIGITS[byte & 0xF])        # low 4 bits
    return "".join(pieces)


# ---------------------------------------------------------------
# Part 3: hex string -> bytes (by hand)
# ---------------------------------------------------------------
#
# Take two characters at a time; the first is worth 16 times the
# second:  "4" "8" -> 4 * 16 + 8 = 72.
#
# It ignores spaces (hex is often written "48 69 21"), accepts upper
# case, and rejects an odd number of digits or non-hex characters.

def from_hex(text: str) -> bytes:
    text = "".join(text.split()).lower()             # remove all whitespace
    if len(text) % 2 != 0:
        raise ValueError("hex string must have an even number of digits")

    result = bytearray()
    for i in range(0, len(text), 2):
        high = HEX_DIGITS.find(text[i])
        low = HEX_DIGITS.find(text[i + 1])
        if high == -1 or low == -1:
            raise ValueError(f"not hex: {text[i:i + 2]!r}")
        result.append(high * 16 + low)               # same as (high << 4) | low
    return bytes(result)


# ---------------------------------------------------------------
# Part 4: hexdump
# ---------------------------------------------------------------
#
# Each line shows:
#   offset (where this line starts, in hex) | 16 bytes in hex | as text
#
#   00000000  48 65 6c 6c 6f 0a 00 ff  ...  |Hello...|
#
# Printable ASCII (32 to 126) is shown as itself; anything else is ".".
# The hex part is padded on the last line so the text column lines up.

def is_printable(byte):
    return 32 <= byte <= 126


def hexdump(data: bytes, width=16) -> str:
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(to_hex(bytes([b])) for b in chunk)
        text_part = "".join(chr(b) if is_printable(b) else "." for b in chunk)
        lines.append(f"{offset:08x}  {hex_part:<{width * 3 - 1}}  |{text_part}|")
    return "\n".join(lines)


# ---------------------------------------------------------------
# Part 5: file signatures (magic numbers)
# ---------------------------------------------------------------
#
# Most file formats start with fixed bytes. Some well-known ones:
#
#   PNG image          89 50 4e 47 0d 0a 1a 0a   .PNG....
#   JPEG image         ff d8 ff
#   GIF image          47 49 46 38               GIF8
#   PDF document       25 50 44 46               %PDF
#   ZIP (also .docx,
#        .xlsx, .apk)  50 4b 03 04               PK..
#   Windows program    4d 5a                     MZ
#   Linux program      7f 45 4c 46               .ELF
#
# Check the LONGEST signatures first, so a short one can't match by
# accident when a longer, more specific one exists.

SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "png",
    b"\xff\xd8\xff": "jpeg",
    b"GIF8": "gif",
    b"%PDF": "pdf",
    b"PK\x03\x04": "zip",
    b"\x7fELF": "elf",
    b"MZ": "exe",
}

def detect_file_type(data: bytes):
    for signature in sorted(SIGNATURES, key=len, reverse=True):
        if data.startswith(signature):
            return SIGNATURES[signature]
    return None


EXTENSION_TYPES = {
    "png": "png", "jpg": "jpeg", "jpeg": "jpeg", "gif": "gif",
    "pdf": "pdf", "zip": "zip", "docx": "zip", "xlsx": "zip",
    "exe": "exe", "dll": "exe",
}

def extension_matches(filename: str, data: bytes) -> bool:
    """True if the file's real type matches what its extension claims."""
    extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    claimed = EXTENSION_TYPES.get(extension)
    actual = detect_file_type(data)
    return claimed is not None and claimed == actual


# ---------------------------------------------------------------
# Part 6: extract readable strings from binary data
# ---------------------------------------------------------------
#
# Find every run of at least `min_length` printable bytes in a row.
# It's a run-length scan: keep a "current run", extend it while bytes
# are printable, and save it when a non-printable byte ends it.
#
# Returns (offset, text) pairs, so you know WHERE each string was.

def extract_strings(data: bytes, min_length=4):
    found = []
    start = None                                     # where the current run began

    for i, byte in enumerate(data):
        if is_printable(byte):
            if start is None:
                start = i                            # a new run starts here
        else:
            if start is not None and i - start >= min_length:
                found.append((start, data[start:i].decode("ascii")))
            start = None                             # the run is over

    if start is not None and len(data) - start >= min_length:
        found.append((start, data[start:].decode("ascii")))   # run at the very end
    return found


# ---------------------------------------------------------------
# COMPLEXITY (n = number of bytes)
# ---------------------------------------------------------------
#
#   Function            | Time   | Notes
#   --------------------|--------|-----------------------------------
#   to_hex / from_hex   | O(n)   | output is twice / half the size
#   hexdump             | O(n)   |
#   detect_file_type    | O(1)   | only looks at the first few bytes
#   extract_strings     | O(n)   | one pass, like a sliding window
#
# In real code, use data.hex(), bytes.fromhex() and data.hex(" ").
# For file types, the `file` command on Linux and macOS knows
# thousands of signatures.


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    samples = [b"", b"Hi!", bytes(range(256)), b"\x00\xff\x10", "café".encode()]

    # Hex by hand agrees with the built-ins, both ways
    for data in samples:
        assert to_hex(data) == data.hex()
        assert from_hex(to_hex(data)) == data
        assert from_hex(data.hex()) == bytes.fromhex(data.hex())

    assert to_hex(b"Hi!") == "486921"
    assert from_hex("48 69 21") == b"Hi!"            # spaces allowed
    assert from_hex("DEADBEEF") == b"\xde\xad\xbe\xef"   # upper case allowed

    for bad in ["abc", "zz", "4g"]:
        try:
            from_hex(bad)
            assert False, f"expected ValueError for {bad!r}"
        except ValueError:
            pass

    # Hexdump layout
    dump = hexdump(b"Hello\n\x00\xff")
    assert dump == "00000000  48 65 6c 6c 6f 0a 00 ff" + " " * 24 + "  |Hello...|"
    assert len(hexdump(bytes(40)).splitlines()) == 3      # 16 + 16 + 8 bytes
    assert hexdump(b"") == ""

    # File types
    assert detect_file_type(b"\x89PNG\r\n\x1a\n" + bytes(20)) == "png"
    assert detect_file_type(b"%PDF-1.7\n...") == "pdf"
    assert detect_file_type(b"MZ\x90\x00") == "exe"
    assert detect_file_type(b"PK\x03\x04rest") == "zip"
    assert detect_file_type(b"just text") is None
    assert detect_file_type(b"") is None

    assert extension_matches("photo.PNG", b"\x89PNG\r\n\x1a\n") is True
    assert extension_matches("report.docx", b"PK\x03\x04") is True     # docx is a zip
    assert extension_matches("invoice.pdf", b"MZ\x90\x00") is False    # disguised program
    assert extension_matches("notes", b"%PDF") is False                # no extension

    # Strings
    blob = b"\x00\x01http://evil.example/x\x00\xffab\x00/bin/sh\x00\x00tail"
    assert extract_strings(blob) == [
        (2, "http://evil.example/x"),
        (28, "/bin/sh"),                             # "ab" (2 chars) is skipped
        (37, "tail"),                                # run at the very end
    ]
    assert extract_strings(b"\x00ab\x00") == []      # too short
    assert extract_strings(b"abcd", min_length=4) == [(0, "abcd")]

    print("All tests passed!")


if __name__ == "__main__":
    print("--- bytes basics ---")
    bytes_basics()

    print("\n--- hex by hand ---")
    print(f'to_hex(b"Hi!")      = {to_hex(b"Hi!")!r}')
    print(f'from_hex("48 69 21") = {from_hex("48 69 21")!r}')

    # A fake "program" pretending to be a PDF, with some text inside
    fake_pdf = (b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
                b"\x00\x00connect 203.0.113.9:4444\x00\x00\x01\x02"
                b"C:\\Windows\\Temp\\run.bat\x00\x00\xde\xad\xbe\xef")
    filename = "invoice.pdf"

    print(f"\n--- hexdump of {filename} ---")
    print(hexdump(fake_pdf))

    print(f"\n--- what is {filename} really? ---")
    print(f"  extension says: pdf")
    print(f"  magic bytes say: {detect_file_type(fake_pdf)}")
    if not extension_matches(filename, fake_pdf):
        print("  MISMATCH: this file is not what its name claims")

    print(f"\n--- readable strings inside {filename} ---")
    for offset, text in extract_strings(fake_pdf):
        print(f"  offset {offset:#06x}: {text}")

    print()
    run_tests()
