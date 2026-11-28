# Cipher Cracker: classic ciphers, and why they fall
#
# Long before computers, people hid messages by shifting or substituting
# letters. These ciphers are broken now, but they teach the ideas modern
# cryptanalysis still uses: a key space small enough to search, and
# patterns in the plaintext that survive into the ciphertext.
#
# None of these protect anything today. The point is the ATTACK: given
# only ciphertext, recover the message with no key. That's what makes it
# a cryptanalysis lesson, not a toy.
#
# Topics covered here:
#   1. Caesar: shift every letter by the same amount
#   2. Breaking Caesar: only 25 keys, so try them all (brute force)
#   3. Scoring "how English is this?" with letter frequencies (chi-squared)
#   4. Vigenere: a repeating keyword, so the shift changes per letter
#   5. Breaking Vigenere, part 1: find the key LENGTH (Index of Coincidence)
#   6. Breaking Vigenere, part 2: each position is just a Caesar
#   7. Why this works on these and not on modern ciphers
#   8. Practice, with tests
#
# HOW TO RUN IT
#   python3 main.py                            the lesson and the tests
#   python3 main.py caesar --shift 3 "attack at dawn"
#   echo "khoor" | python3 main.py break-caesar
#   python3 main.py vigenere --key lemon "attack at dawn"
#   python3 main.py break-vigenere --text "$(cat secret.txt)"


import argparse
import string
import sys
from collections import Counter

LOWER = string.ascii_lowercase

# How often each letter appears in ordinary English text, as a percentage.
# These are the fingerprint everything below leans on.
ENGLISH = {
    "a": 8.17, "b": 1.49, "c": 2.78, "d": 4.25, "e": 12.70, "f": 2.23, "g": 2.02,
    "h": 6.09, "i": 6.97, "j": 0.15, "k": 0.77, "l": 4.03, "m": 2.41, "n": 6.75,
    "o": 7.51, "p": 1.93, "q": 0.10, "r": 5.99, "s": 6.33, "t": 9.06, "u": 2.76,
    "v": 0.98, "w": 2.36, "x": 0.15, "y": 1.97, "z": 0.07,
}


# ---------------------------------------------------------------
# 1. Caesar
# ---------------------------------------------------------------
#
# Shift each letter forward by `shift`, wrapping z->a. "abc" shift 1 is
# "bcd". ord(c) - ord('a') turns a letter into 0..25; % 26 wraps it;
# chr(... + ord('a')) turns it back. Non-letters are left alone, so
# spaces and punctuation pass through.

def caesar(text, shift):
    out = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


# ---------------------------------------------------------------
# 3. Scoring how English a text is (chi-squared)
# ---------------------------------------------------------------
#
# To break a cipher automatically, the computer needs to tell "real
# English" from "gibberish" without a human reading it. Count how often
# each letter appears, and compare with how often it SHOULD in English.
#
# The chi-squared statistic sums (observed - expected)^2 / expected over
# the 26 letters. A perfect match is 0; the more the counts disagree,
# the bigger it grows. So LOWER is more English-like. English's lumpy
# letter distribution (lots of E and T, almost no Q and Z) is what gives
# every letter-shuffling cipher away.

def chi_squared(text):
    letters = [c for c in text.lower() if c in LOWER]
    n = len(letters)
    if n == 0:
        return float("inf")
    counts = Counter(letters)
    score = 0.0
    for letter, pct in ENGLISH.items():
        expected = pct / 100 * n
        score += (counts.get(letter, 0) - expected) ** 2 / expected
    return score


# ---------------------------------------------------------------
# 2. Breaking Caesar: try all 25 keys
# ---------------------------------------------------------------
#
# There are only 25 non-zero shifts. Decrypt with each, score each with
# chi-squared, and the lowest score is almost certainly the message.
# A key space this small is the whole weakness: no cleverness needed,
# just try everything.

def break_caesar(ciphertext):
    candidates = [(chi_squared(caesar(ciphertext, -shift)), shift) for shift in range(26)]
    _, shift = min(candidates)
    return shift, caesar(ciphertext, -shift)


# ---------------------------------------------------------------
# 4. Vigenere: a keyword instead of one shift
# ---------------------------------------------------------------
#
# Vigenere uses a keyword, say "lemon". The first letter is shifted by
# l (11), the second by e (4), and so on, repeating the key. Because the
# same plaintext letter becomes different ciphertext letters, a single
# letter-frequency count of the whole thing looks flat, and for 300
# years people thought it unbreakable ("le chiffre indechiffrable").
#
# Only letters advance the key position, so spaces don't shift the key.

def _key_shifts(key):
    return [ord(k) - ord("a") for k in key.lower() if k.isalpha()]


def vigenere(text, key, decrypt=False):
    shifts = _key_shifts(key)
    if not shifts:
        raise ValueError("the key must contain letters")
    out, i = [], 0
    for ch in text:
        if ch.isalpha():
            s = shifts[i % len(shifts)]
            out.append(caesar(ch, -s if decrypt else s))
            i += 1
        else:
            out.append(ch)
    return "".join(out)


# ---------------------------------------------------------------
# 5. Breaking Vigenere, part 1: the key LENGTH
# ---------------------------------------------------------------
#
# The trick (Friedrich Kasiski, William Friedman): if we knew the key
# length K, then letters 0, K, 2K, ... were all shifted by the SAME key
# letter, so each such group is a plain Caesar, which we can already
# break. So the whole job reduces to finding K.
#
# INDEX OF COINCIDENCE: the chance that two letters picked at random
# from a text are the same. For English it's about 0.067 (because E
# collides with E so often); for random letters, 1/26 = 0.038. When we
# split the ciphertext into K columns and K is RIGHT, each column is a
# shifted English text, so its IC is near 0.067. When K is wrong, the
# columns are mixtures and the IC is near 0.038. So try each K and look
# for the one whose columns score most English-like.

def index_of_coincidence(text):
    letters = [c for c in text.lower() if c in LOWER]
    n = len(letters)
    if n < 2:
        return 0.0
    counts = Counter(letters)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def guess_key_length(ciphertext, max_len=16):
    letters = [c for c in ciphertext.lower() if c in LOWER]
    best = []
    for k in range(1, min(max_len, len(letters) // 2) + 1):
        columns = ["".join(letters[i::k]) for i in range(k)]
        avg_ic = sum(index_of_coincidence(col) for col in columns) / k
        best.append((avg_ic, k))
    # The right length, and multiples of it, both score high; prefer the
    # SHORTEST length that is close to the best score.
    top = max(ic for ic, _ in best)
    for k in range(1, max_len + 1):
        for ic, length in best:
            if length == k and ic >= top - 0.01:
                return k
    return max(best)[1]


# ---------------------------------------------------------------
# 6. Breaking Vigenere, part 2: each column is a Caesar
# ---------------------------------------------------------------
#
# With K in hand, break each column as a Caesar (section 2). The shift
# that makes a column most English-like is that key letter. Put the key
# letters together and we have the keyword, and decrypt.

def break_vigenere(ciphertext, max_len=16):
    letters = [c for c in ciphertext.lower() if c in LOWER]
    k = guess_key_length(ciphertext, max_len)
    key = []
    for i in range(k):
        column = "".join(letters[i::k])
        shift, _ = break_caesar(column)
        key.append(chr(shift + ord("a")))
    key = "".join(key)
    return key, vigenere(ciphertext, key, decrypt=True)


# ---------------------------------------------------------------
# 7. Why modern ciphers don't fall to this
# ---------------------------------------------------------------
#
# Every attack above relied on one of two things:
#   * a tiny key space (Caesar's 25), so you can try them all; or
#   * plaintext patterns surviving into the ciphertext (letter
#     frequencies, the Index of Coincidence).
# A modern cipher like AES closes both doors. Its key space (2^128 and
# up) is far too large to search, and its output is statistically flat:
# every output bit depends on every key and input bit, so counting
# symbols tells you nothing. The lesson isn't these ciphers; it's the
# two properties any real cipher must have.


# ---------------------------------------------------------------
# The command line
# ---------------------------------------------------------------

def read_text(args):
    if args.text is not None:
        return args.text
    data = sys.stdin.read()
    if not data.strip():
        raise SystemExit("error: no text given (as an argument or on stdin)")
    return data.rstrip("\n")


def main(argv=None, out=sys.stdout):
    p = argparse.ArgumentParser(prog="main.py", description="Classic ciphers, and breaking them.")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("caesar", "vigenere", "break-caesar", "break-vigenere"):
        s = sub.add_parser(name)
        s.add_argument("text", nargs="?", help="the text (or piped on stdin)")
        if name == "caesar":
            s.add_argument("--shift", type=int, default=3)
        if name == "vigenere":
            s.add_argument("--key", required=True)
    args = p.parse_args(argv)
    text = read_text(args)

    if args.command == "caesar":
        print(caesar(text, args.shift), file=out)
    elif args.command == "vigenere":
        print(vigenere(text, args.key), file=out)
    elif args.command == "break-caesar":
        shift, plain = break_caesar(text)
        print(f"shift {shift}: {plain}", file=out)
    else:
        key, plain = break_vigenere(text)
        print(f"key {key!r}: {plain}", file=out)
    return 0


# ---------------------------------------------------------------
# The lesson
# ---------------------------------------------------------------

# Statistical cryptanalysis needs a fair amount of natural text: a short
# or repetitive sentence doesn't match English letter frequencies closely
# enough. This is a public-domain passage (the opening of Jane Austen's
# "Pride and Prejudice"), long enough for the attacks to be reliable.
SAMPLE = ("it is a truth universally acknowledged that a single man in "
          "possession of a good fortune must be in want of a wife however "
          "little known the feelings or views of such a man may be on his "
          "first entering a neighbourhood this truth is so well fixed in "
          "the minds of the surrounding families that he is considered as "
          "the rightful property of some one or other of their daughters "
          "my dear mr bennet said his lady to him one day have you heard "
          "that netherfield park is let at last mr bennet replied that he "
          "had not but it is returned she for mrs long has just been here "
          "and she told me all about it do you not want to know who has "
          "taken it cried his wife impatiently you want to tell me and i "
          "have no objection to hearing it this was invitation enough")


def lesson():
    print("  Caesar, shift 3:")
    secret = caesar(SAMPLE, 3)
    print(f"    cipher: {secret[:60]}...")
    shift, plain = break_caesar(secret)
    print(f"    broken with no key -> shift {shift}: {plain[:60]}...\n")

    print("  Vigenere, key 'lemon':")
    secret = vigenere(SAMPLE, "lemon")
    print(f"    cipher: {secret[:60]}...")
    print(f"    key length guessed: {guess_key_length(secret)} (real: 5)")
    key, plain = break_vigenere(secret)
    print(f"    broken with no key -> key {key!r}: {plain[:60]}...")


def run_tests():
    # 1. Caesar shifts and wraps, keeps case and punctuation
    assert caesar("abc", 1) == "bcd" and caesar("xyz", 3) == "abc"
    assert caesar("Attack at Dawn!", 5) == "Fyyfhp fy Ifbs!"
    assert caesar(caesar("Hello, World", 7), -7) == "Hello, World"

    # 3. Chi-squared: English scores far lower than gibberish
    assert chi_squared(SAMPLE) < chi_squared(caesar(SAMPLE, 7))
    assert chi_squared("") == float("inf")

    # 2. Breaking Caesar recovers any shift
    for shift in range(1, 26):
        found, plain = break_caesar(caesar(SAMPLE, shift))
        assert found == shift and plain == SAMPLE, shift

    # 4. Vigenere round-trips, and "aaaa" is just Caesar 0 (no change)
    assert vigenere(SAMPLE, "lemon") != SAMPLE
    assert vigenere(vigenere(SAMPLE, "lemon"), "lemon", decrypt=True) == SAMPLE
    assert vigenere("hello", "a") == "hello"
    try:
        vigenere("hi", "123")
    except ValueError:
        pass
    else:
        raise AssertionError("a key with no letters should be rejected")

    # 5. Index of coincidence: English is near 0.067, random much lower
    assert index_of_coincidence(SAMPLE) > 0.06
    assert index_of_coincidence(vigenere(SAMPLE, "lemon")) < 0.05      # flattened by the key

    # 6. The whole break, with no key, for several keys
    for key in ("lemon", "key", "secret", "python"):
        secret = vigenere(SAMPLE, key)
        found_key, plain = break_vigenere(secret)
        assert found_key == key and plain == SAMPLE, (key, found_key)

    # The command line
    import io
    out = io.StringIO()
    assert main(["caesar", "--shift", "3", "abc"], out=out) == 0 and out.getvalue().strip() == "def"
    out = io.StringIO()
    main(["break-caesar", caesar(SAMPLE, 11)], out=out)
    assert "shift 11" in out.getvalue() and SAMPLE[:20] in out.getvalue()

    print("All tests passed!")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("--- Two classic ciphers, broken with no key ---")
        lesson()
        print()
        run_tests()
    else:
        sys.exit(main())
