# Hash Cracker: how stolen password hashes get cracked, and what stops it
#
# When a site's database leaks, it doesn't (usually) hold passwords in
# plain text. It holds HASHES: one-way fingerprints. You can't reverse a
# hash. So attackers don't reverse it: they GUESS a password, hash the
# guess, and check whether it matches. Fast hardware does billions of
# guesses a second.
#
# This project builds that attack against hashes YOU make yourself, then
# adds, one at a time, the defences that beat it: salts, then slow hashes.
# Seeing each defence stop the attack is the point.
#
# Everything here runs on your own made-up hashes. Cracking other
# people's hashes without permission is illegal; this is to understand
# how storing passwords safely works.
#
# Topics covered here:
#   1. A one-way hash, and why "one-way" doesn't mean "safe"
#   2. The dictionary attack: hash a wordlist, compare
#   3. Precomputation: hash the wordlist ONCE, crack a whole dump
#   4. Salt: a random value per password, which breaks precomputation
#   5. Slow hashes (PBKDF2): make each guess cost thousands of times more
#   6. Putting numbers on it: guesses per second, time to crack
#   7. Practice, with tests
#
# HOW TO RUN IT
#   python3 main.py                            the lesson and the tests
#   python3 main.py hash hunter2               make a SHA-256 hash to crack
#   python3 main.py crack <hex-hash> --wordlist rockyou.txt
#   python3 main.py crack-salted <salt>:<hash> --wordlist rockyou.txt


import argparse
import hashlib
import hmac
import secrets
import sys
import time


# A tiny built-in wordlist: common passwords, the first thing any
# attacker tries. Real ones (RockYou, SecLists) have millions; pass one
# with --wordlist.
COMMON = """
123456 password 123456789 12345678 12345 qwerty abc123 football
monkey letmein dragon 111111 baseball iloveyou master sunshine
ashley bailey passw0rd shadow 123123 654321 superman qazwsx
hunter2 trustno1 whatever starwars corvette hello computer
""".split()


# ---------------------------------------------------------------
# 1. A one-way hash
# ---------------------------------------------------------------
#
# SHA-256 turns any input into a fixed 64-hex-character fingerprint.
# It's "one-way": given the hash, there's no formula to get the input
# back. That sounds safe for storing passwords. It isn't, because the
# attacker doesn't need a formula: passwords aren't random, so they can
# just try the likely ones. One-way stops REVERSING; it does nothing
# against GUESSING.

def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------
# 2. The dictionary attack
# ---------------------------------------------------------------
#
# Hash each word in a list and compare with the target. If a user's
# password is in the list, it's found in as many steps as its position.
# No reversing: just guessing fast.

def load_wordlist(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return [line.strip() for line in f if line.strip()]


def crack(target_hash, words):
    target = target_hash.lower()
    for word in words:
        if sha256(word) == target:
            return word
    return None


# ---------------------------------------------------------------
# 3. Precomputation: crack a whole dump at once
# ---------------------------------------------------------------
#
# A site's leak isn't one hash, it's millions. If every user's password
# is hashed the same plain way, the attacker hashes the wordlist ONCE
# into a lookup table (word by hash), then every matching hash in the
# dump is cracked instantly. This is the idea behind rainbow tables and
# "hash lookup" websites: the work is done once and reused forever.

def build_table(words):
    return {sha256(word): word for word in words}


def crack_dump(hashes, table):
    return {h: table.get(h.lower()) for h in hashes}


# ---------------------------------------------------------------
# 4. Salt: break precomputation
# ---------------------------------------------------------------
#
# A SALT is a random value stored next to each hash, and mixed in before
# hashing: hash(salt + password). It's not secret; it's there to make
# every stored hash unique even when two users share a password. So:
#   * the attacker's precomputed table is useless: it was built without
#     the salt, so none of its hashes match
#   * two users with password "123456" now have DIFFERENT hashes, so
#     cracking one doesn't reveal the other
# The attacker can still guess, but now has to redo the whole wordlist
# for EACH salt, i.e. each user. Salt turns one big job into millions of
# separate ones.

def make_salted(password, salt=None):
    salt = salt or secrets.token_hex(8)
    return salt, hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def crack_salted(salt, target_hash, words):
    target = target_hash.lower()
    for word in words:
        if hashlib.sha256((salt + word).encode("utf-8")).hexdigest() == target:
            return word
    return None


# ---------------------------------------------------------------
# 5. Slow hashes: make each guess expensive
# ---------------------------------------------------------------
#
# Salt stops reuse, but a GPU still does billions of SHA-256 a second, so
# guessing one user's weak password is quick. The fix: a hash built to be
# SLOW. PBKDF2 just repeats the hash a set number of times (iterations);
# bcrypt, scrypt and Argon2 go further and also need lots of memory.
#
# At 200,000 iterations, each guess costs 200,000 times more. The real
# user notices nothing (one login, a few milliseconds), but the attacker
# doing billions of guesses now does a few thousand, so a weak password
# that fell in a second now takes hours. Salt is built in.
#
# (Iterations are kept low here so the tests run fast. Real systems use
# hundreds of thousands, raised as hardware gets faster.)

def make_pbkdf2(password, salt=None, iterations=200_000):
    salt = salt or secrets.token_hex(8)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
    return salt, iterations, digest.hex()


def verify_pbkdf2(password, salt, iterations, target_hash):
    _, _, digest = make_pbkdf2(password, salt, iterations)
    return hmac.compare_digest(digest, target_hash.lower())   # constant-time compare


# ---------------------------------------------------------------
# 6. Putting numbers on it
# ---------------------------------------------------------------
#
# Measure how long the wordlist takes with a fast hash and with a slow
# one, on THIS machine, and scale it up. The ratio is what matters: the
# same wordlist, the same password, just a hash chosen to be slow.

def time_guesses(hash_fn, words):
    start = time.perf_counter()
    for word in words:
        hash_fn(word)
    return time.perf_counter() - start


# ---------------------------------------------------------------
# The command line
# ---------------------------------------------------------------

def main(argv=None, out=sys.stdout):
    p = argparse.ArgumentParser(prog="main.py", description="Crack password hashes you made yourself.")
    sub = p.add_subparsers(dest="command", required=True)
    h = sub.add_parser("hash"); h.add_argument("password")
    c = sub.add_parser("crack"); c.add_argument("hash"); c.add_argument("--wordlist")
    cs = sub.add_parser("crack-salted"); cs.add_argument("salted", help="salt:hash")
    cs.add_argument("--wordlist")
    args = p.parse_args(argv)
    words = load_wordlist(args.wordlist) if getattr(args, "wordlist", None) else COMMON

    if args.command == "hash":
        print(sha256(args.password), file=out)
        return 0
    if args.command == "crack":
        found = crack(args.hash, words)
    else:
        salt, _, target = (args.salted.split(":", 1)[0], None, args.salted.split(":", 1)[1])
        found = crack_salted(salt, target, words)
    if found is None:
        print("not found in the wordlist", file=out)
        return 1
    print(f"cracked: {found}", file=out)
    return 0


# ---------------------------------------------------------------
# The lesson
# ---------------------------------------------------------------

def lesson():
    # A small leaked "database": four users, some sharing a weak password.
    users = {"alice": "123456", "bob": "password", "carol": "123456", "dave": "hunter2"}

    print("  1-3. Plain SHA-256, the way too many sites store passwords:")
    dump = {name: sha256(pw) for name, pw in users.items()}
    print(f"       alice and carol both chose '123456', so their hashes are IDENTICAL:")
    print(f"         {dump['alice'][:32]}...  == {dump['carol'][:32]}...")
    table = build_table(COMMON)                       # hash the wordlist ONCE
    cracked = crack_dump(dump.values(), table)
    cracked_users = sum(cracked[h] is not None for h in dump.values())
    print(f"       one precomputed table cracks the whole dump: "
          f"{cracked_users}/{len(users)} users instantly (only 3 hashes to look up)\n")

    print("  4. With a salt per user, the same password gives different hashes:")
    salted = {name: make_salted(pw) for name, pw in users.items()}
    print(f"         alice: {salted['alice'][1][:24]}...")
    print(f"         carol: {salted['carol'][1][:24]}...  (different now)")
    print(f"       the precomputed table is useless; the attacker must redo the")
    print(f"       wordlist per user, but weak passwords still fall:")
    for name, (salt, h) in salted.items():
        print(f"         {name}: {crack_salted(salt, h, COMMON)}")

    print("\n  5. A slow hash (PBKDF2) makes each guess thousands of times dearer:")
    fast = time_guesses(sha256, COMMON)
    slow = time_guesses(lambda w: make_pbkdf2(w, "salt", 200_000), COMMON)
    print(f"       the same {len(COMMON)}-word list: SHA-256 {fast*1000:.1f} ms, "
          f"PBKDF2 {slow*1000:.0f} ms ({slow/fast:.0f}x slower)")
    print(f"       a billion-guess-a-second GPU drops to a few thousand a second.")


# ---------------------------------------------------------------
# 7. Practice and tests
# ---------------------------------------------------------------
#
# Practice: write crack_dump_salted(records, words) where each record is
# (salt, hash). Because the salts differ, it can't precompute: it must
# try the wordlist against each record. Return {hash: word or None}.
# Solution below.

def crack_dump_salted(records, words):
    return {h: crack_salted(salt, h, words) for salt, h in records}


def run_tests():
    # 1-2. Plain hashing and the dictionary attack
    assert sha256("hunter2") == "f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7"
    assert crack(sha256("qwerty"), COMMON) == "qwerty"
    assert crack(sha256("not-in-list-xyz"), COMMON) is None
    assert crack(sha256("PASSWORD").upper(), COMMON) is None     # hashes are case-sensitive data

    # 3. Precompute once, crack many
    table = build_table(COMMON)
    dump = [sha256("123456"), sha256("dragon"), sha256("zzz-unknown")]
    result = crack_dump(dump, table)
    assert result[sha256("123456")] == "123456" and result[sha256("dragon")] == "dragon"
    assert result[sha256("zzz-unknown")] is None

    # 4. Salt: same password, different hash; precomputed table defeated
    s1, h1 = make_salted("123456", "aaaa")
    s2, h2 = make_salted("123456", "bbbb")
    assert h1 != h2                                              # same password, different salt
    assert all(word_hash not in table for word_hash in (h1, h2))   # not in the plain table
    assert crack_salted("aaaa", h1, COMMON) == "123456"
    assert crack_salted("aaaa", h1, COMMON) and crack_salted("zzzz", h1, COMMON) is None  # wrong salt fails

    # 5. Slow hash: verifies the right password, rejects the wrong one
    salt, iterations, target = make_pbkdf2("hunter2", "salt123", iterations=1000)
    assert verify_pbkdf2("hunter2", salt, iterations, target)
    assert not verify_pbkdf2("hunter3", salt, iterations, target)
    # ...and it really is far slower per guess than plain SHA-256
    small = COMMON[:16]
    assert time_guesses(lambda w: make_pbkdf2(w, "s", 50_000), small) > time_guesses(sha256, small)

    # The command line
    import io
    out = io.StringIO()
    assert main(["hash", "qwerty"], out=out) == 0 and out.getvalue().strip() == sha256("qwerty")
    out = io.StringIO()
    assert main(["crack", sha256("dragon")], out=out) == 0 and "dragon" in out.getvalue()
    out = io.StringIO()
    assert main(["crack", sha256("nope-xyz")], out=out) == 1 and "not found" in out.getvalue()
    salt, h = make_salted("letmein", "cafe")
    out = io.StringIO()
    assert main(["crack-salted", f"{salt}:{h}"], out=out) == 0 and "letmein" in out.getvalue()

    # Practice
    records = [make_salted("123456", "s1"), make_salted("dragon", "s2")]
    cracked = crack_dump_salted(records, COMMON)
    assert set(cracked.values()) == {"123456", "dragon"}

    print("All tests passed!")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("--- A stolen password database, cracked, then defended ---")
        lesson()
        print()
        run_tests()
    else:
        sys.exit(main())
