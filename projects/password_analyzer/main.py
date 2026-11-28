# Password Analyzer: how strong is a password, REALLY?
#
# Most sign-up forms judge passwords by rules: 8+ characters, a capital,
# a digit, a symbol. By those rules "P@ssw0rd!" is perfect. It's also
# one of the first things any password cracker tries.
#
# Strength isn't about which characters you used. It's about how many
# GUESSES an attacker needs before they hit yours. Attackers don't guess
# randomly: they try the most common passwords first, then common words
# with predictable changes (a capital first letter, @ for a, 1! on the
# end), then patterns like keyboard rows and years, and only after all
# that, every possible combination. This project estimates guesses the
# same way, and turns them into crack times.
#
# Topics covered here:
#   1. The rules approach, and "entropy": length x log2(character pool)
#   2. How attackers really guess: wordlists, then mangling rules
#   3. Undoing the mangling: lower case, leetspeak (@ -> a), stripped
#      digits and symbols
#   4. Patterns: keyboard walks, sequences, repeats
#   5. Passphrases: why four random words beat eight random symbols
#   6. Guesses -> crack times, for online and offline attacks
#   7. Has it been leaked? Checking without sending the password
#      (k-anonymity, the Have I Been Pwned range API)
#   8. Reading a password safely: getpass, never a command-line argument
#   9. Practice, with tests
#
# HOW TO RUN IT
# -------------
#   python3 main.py                            the lesson and its tests
#   python3 main.py --check                    type a password (not shown) and analyse it
#   python3 main.py --check --wordlist 10k-most-common.txt
#   python3 main.py --check --breach-check     also ask Have I Been Pwned (needs internet)
#
# A bigger wordlist makes the estimate more realistic: SecLists has
# lists of the most common passwords, one per line, most common first
# (https://github.com/danielmiessler/SecLists, Passwords/Common-Credentials).
#
# This is for checking your OWN passwords, and for learning how cracking
# works so you can defend against it.


import argparse
import getpass
import hashlib
import math
import re
import string
import sys
import urllib.request


# ---------------------------------------------------------------
# 1. The rules approach, and naive entropy
# ---------------------------------------------------------------
#
# If every character were chosen at RANDOM from a pool of N characters,
# a password of length L would be one of N**L possibilities. Security
# people measure that in bits: log2(N**L) = L * log2(N). Each extra bit
# doubles the work.
#
#   pool                       | N  | bits per character
#   ---------------------------|----|-------------------
#   digits                     | 10 | 3.3
#   lower case                 | 26 | 4.7
#   lower + upper              | 52 | 5.7
#   lower + upper + digits     | 62 | 5.95
#   all printable ASCII        | 95 | 6.6
#
# Notice: going from 26 to 95 characters adds under 2 bits per
# character, but each extra character adds 4.7 or more. LENGTH matters
# far more than variety.
#
# The catch: this formula assumes the characters were random. People's
# passwords aren't, so it hugely overrates "P@ssw0rd!" (59 bits by this
# formula; it's cracked in well under a second).

CLASSES = {
    "lower case": set(string.ascii_lowercase),
    "upper case": set(string.ascii_uppercase),
    "digits": set(string.digits),
    "symbols": set(string.punctuation + " "),
}


def pool_size(password):
    """How many characters the password's character classes contain."""
    size = sum(len(chars) for chars in CLASSES.values() if set(password) & chars)
    if any(ord(c) > 127 for c in password):
        size += 100                                   # accented letters, emoji: a rough allowance
    return size


def naive_entropy(password):
    """Bits IF every character had been chosen at random."""
    if not password:
        return 0.0
    return len(password) * math.log2(pool_size(password))


def rule_check(password):
    """The usual sign-up form rules. Passing them proves very little."""
    return {"8+ characters": len(password) >= 8,
            **{f"has {name}": bool(set(password) & chars) for name, chars in CLASSES.items()}}


# ---------------------------------------------------------------
# 2. How attackers really guess
# ---------------------------------------------------------------
#
# When a website's password database leaks, attackers run a cracker like
# hashcat or John the Ripper over it. Both work the same way:
#   1. a WORDLIST of real passwords from earlier leaks, most common first
#      (the 2009 RockYou leak alone gave 14 million)
#   2. RULES that mangle each word the way people do: capitalise it, swap
#      letters for look-alike digits, add 1, 123, ! or a year
#   3. only then MASKS and brute force: every combination of a length
#
# So a password's strength is roughly: how far down that process is it?
#
# Below is a tiny wordlist, around 100 of the most common passwords from
# public breach lists (roughly in order). Real ones have millions; pass
# one with --wordlist to see how much worse many passwords look.

COMMON = """
123456 password 123456789 12345678 12345 qwerty 1234567 111111 1234567890
123123 abc123 1234 password1 iloveyou 1q2w3e4r 000000 qwerty123 zaq12wsx
dragon sunshine princess letmein 654321 monkey 1qaz2wsx 123321 qwertyuiop
superman asdfghjkl trustno1 football baseball welcome admin master shadow
michael jennifer hello charlie freedom whatever starwars computer killer
pepper ginger summer winter login passw0rd flower hottie loveme jordan
hunter buster soccer harley batman andrew tigger robert thomas hockey
ranger daniel hannah maggie jessica joshua cheese secret access mustang
dallas austin orange banana pokemon naruto samsung google matrix qazwsx
asdf zxcvbnm qwe123 abcd1234 q1w2e3r4 test guest root changeme default
""".split()


def load_wordlist(path):
    """One password per line, most common first. Returns word -> rank (0 = most common)."""
    ranks = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            word = line.strip().lower()
            if word and word not in ranks:
                ranks[word] = len(ranks)
    return ranks


DEFAULT_RANKS = {word: rank for rank, word in enumerate(COMMON)}


# ---------------------------------------------------------------
# 3. Undoing the mangling
# ---------------------------------------------------------------
#
# To see whether "P@ssw0rd!" is really "password", undo what a cracker's
# rules would do, in reverse:
#   * lower case everything
#   * strip digits and symbols off the START and END (1, 123, !, 2024)
#   * undo leetspeak: @ -> a, 0 -> o, $ -> s, and so on
#
# Some look-alikes are ambiguous: "1" could be i or l. So unleet() returns
# every reading (capped, so a password full of 1s can't explode).
#
# Each change makes the attacker's job only a little bigger:
#   capitalising       x2   (first letter, or all of it)
#   leetspeak          x4   (only a handful of common swaps)
#   added digits/symbols: every possible affix of that length

LEET = {"@": "a", "4": "a", "8": "b", "(": "c", "3": "e", "6": "g", "#": "h",
        "!": "i", "1": "il", "|": "il", "0": "o", "$": "s", "5": "s", "7": "t",
        "+": "t", "2": "z"}
AFFIX = re.compile(r"^(?P<before>[\W\d_]*)(?P<word>.*?)(?P<after>[\W\d_]*)$")


def unleet(text, limit=64):
    """Every way to read the look-alike characters back as letters."""
    readings = [""]
    for ch in text:
        options = LEET.get(ch, ch)
        readings = [r + o for r in readings for o in options][:limit]
    return readings


SYMBOLS = len(string.punctuation) + 1                 # 32 punctuation marks, and space


def affix_guesses(affix):
    """How many affixes like this one an attacker would try.

    Crackers add digits and symbols as separate steps, so "2024!" is a
    4-digit number THEN a symbol: about 200 x 33 guesses, not every
    5-character string. Four digits are usually a year, and years are
    tried first, so they're charged ~200 rather than 10,000.
    """
    total = 1
    for run in re.findall(r"\d+|\D+", affix):
        if run.isdigit():
            total *= 200 if len(run) == 4 else 10 ** len(run)
        else:
            total *= SYMBOLS ** len(run)
    return total


def as_mangled_word(password, ranks):
    """If the password is a known word plus predictable changes, return
    (guesses, explanation). Otherwise None."""
    m = AFFIX.match(password)
    core = m["word"]
    if len(core) < 3:
        return None
    best = None
    for reading in unleet(core.lower()):
        if reading not in ranks:
            continue
        changes, guesses = [], ranks[reading] + 1
        if core != core.lower():
            changes.append("capital letters")
            guesses *= 2
        if core.lower() != reading:
            changes.append("look-alike characters")
            guesses *= 4
        for part, where in ((m["before"], "start"), (m["after"], "end")):
            if part:
                changes.append(f"{part!r} at the {where}")
                guesses *= affix_guesses(part)
        if best is None or guesses < best[0]:
            how = f" with {', '.join(changes)}" if changes else ""
            best = (guesses, f"the common password {reading!r} (#{ranks[reading] + 1}){how}")
    return best


# ---------------------------------------------------------------
# 4. Patterns
# ---------------------------------------------------------------
#
# Crackers also try what people TYPE without thinking: rows of the
# keyboard (qwerty, asdf), sequences (abcd, 4321) and repeats (aaaa,
# abcabc). These need very few guesses whatever their length.

KEYBOARD_ROWS = ["`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./"]


def is_keyboard_walk(text):
    t = text.lower()
    return len(t) >= 4 and any(t in row or t in row[::-1] for row in KEYBOARD_ROWS)


def is_sequence(text):
    if len(text) < 4:
        return False
    steps = {ord(b) - ord(a) for a, b in zip(text, text[1:])}
    return steps in ({1}, {-1})


def repeated_unit(text):
    """'abcabcabc' -> ('abc', 3); 'abcd' -> None."""
    m = re.fullmatch(r"(.+?)\1+", text)
    return (m[1], len(text) // len(m[1])) if m else None


def as_pattern(password):
    m = AFFIX.match(password)
    core, extra = m["word"] or password, affix_guesses(m["before"]) * affix_guesses(m["after"])
    if is_keyboard_walk(core):
        return 100 * len(core) * extra, f"a row of keys on the keyboard ({core!r})"
    if is_sequence(core):
        return 50 * len(core) * extra, f"a sequence ({core!r})"
    unit = repeated_unit(password)
    if unit:
        inner = estimate_guesses(unit[0])[0]
        return inner * unit[1], f"{unit[0]!r} repeated {unit[1]} times"
    return None


# ---------------------------------------------------------------
# 5. Passphrases
# ---------------------------------------------------------------
#
# "correct horse battery staple" (from the xkcd comic "Password
# Strength") is four common words. An attacker who knows that's how it
# was made still has to guess the words. Picked at random from a list of
# 7,776 words (the Diceware list, rolled with dice), each word adds
# log2(7776) = 12.9 bits:
#
#   4 words: 51.7 bits    5 words: 64.6 bits    6 words: 77.5 bits
#
# That's why the estimate for a passphrase assumes the attacker KNOWS
# it's words, and still comes out strong: its strength comes from the
# number of words, and the words have to be chosen randomly, not as a
# sentence you'd say.

DICEWARE_WORDS = 7776


def as_passphrase(password):
    words = [w for w in re.split(r"[\s\-_.]+", password) if w]
    if len(words) >= 3 and all(w.isalpha() for w in words):
        return DICEWARE_WORDS ** len(words), f"a passphrase of {len(words)} words"
    return None


# ---------------------------------------------------------------
# Putting it together: the estimate is the CHEAPEST way to crack it
# ---------------------------------------------------------------

def estimate_guesses(password, ranks=None):
    """(guesses an attacker would need, how they'd get there)."""
    ranks = DEFAULT_RANKS if ranks is None else ranks
    if not password:
        return 1, "empty"
    if password.lower() in ranks:
        rank = ranks[password.lower()]
        return rank + 1, f"#{rank + 1} on the list of most common passwords"
    options = [(pool_size(password) ** len(password),
                f"every combination of {len(password)} characters from {pool_size(password)}")]
    for found in (as_mangled_word(password, ranks), as_pattern(password), as_passphrase(password)):
        if found:
            options.append(found)
    return min(options)


# ---------------------------------------------------------------
# 6. Guesses -> crack times
# ---------------------------------------------------------------
#
# How fast an attacker can guess depends on WHERE they're guessing:
#
#   attack                                | guesses per second
#   --------------------------------------|-------------------
#   online, the site limits attempts       | 100 per hour
#   online, no limits                      | 10
#   offline, a slow hash (bcrypt, scrypt)  | 10,000
#   offline, a fast hash (MD5, SHA-1)      | 10,000,000,000 (one good GPU)
#
# "Offline" means the attacker has stolen the password database and
# guesses on their own hardware, as fast as it goes. That's why sites
# must store passwords with a SLOW hash: the same password survives a
# million times longer. (Rates are rough orders of magnitude, the same
# ones the zxcvbn strength meter uses.)

SCENARIOS = [("online, limited", 100 / 3600), ("online, unlimited", 10),
             ("offline, slow hash", 1e4), ("offline, fast hash", 1e10)]


def human_time(seconds):
    if seconds < 1:
        return "instantly"
    for unit, size in (("centuries", 3.15e9), ("years", 3.15e7), ("days", 86400),
                       ("hours", 3600), ("minutes", 60), ("seconds", 1)):
        if seconds >= size:
            amount = seconds / size
            if unit == "centuries" and amount >= 1e6:
                return "millions of centuries"
            return f"{amount:,.0f} {unit}"
    return "instantly"


def crack_times(guesses):
    # On average an attacker finds it halfway through: guesses / 2.
    return {name: human_time(guesses / 2 / rate) for name, rate in SCENARIOS}


VERDICTS = [(1e3, "very weak"), (1e6, "weak"), (1e8, "fair"), (1e10, "good")]


def verdict(guesses):
    for limit, word in VERDICTS:
        if guesses < limit:
            return word
    return "strong"


def advice(password, how):
    tips = []
    words = re.match(r"a passphrase of (\d+) words", how)
    if words and int(words[1]) < 6:
        tips.append("use 6 random words: 4 are fine online, but fall in days if a site's "
                    "fast-hashed database leaks")
    elif len(password) < 14:
        tips.append("make it longer: 14+ characters, or 4+ random words")
    if "common password" in how or "keyboard" in how or "sequence" in how or "repeated" in how:
        tips.append("avoid common words and patterns, even with substitutions: crackers try those first")
    if not tips:
        tips.append("good: keep it unique to this one site, and use a password manager")
    return tips


def analyse(password, ranks=None):
    guesses, how = estimate_guesses(password, ranks)
    return {"length": len(password), "naive_bits": round(naive_entropy(password), 1),
            "rules_passed": sum(rule_check(password).values()), "guesses": guesses,
            "bits": round(math.log2(guesses), 1) if guesses > 1 else 0.0, "how": how,
            "verdict": verdict(guesses), "crack_times": crack_times(guesses),
            "advice": advice(password, how)}


# ---------------------------------------------------------------
# 7. Has it been leaked? (k-anonymity)
# ---------------------------------------------------------------
#
# Have I Been Pwned (HIBP) keeps hashes of over 900 million passwords
# from real breaches. Sending it your password, or even its full hash,
# would be a bad idea. Its "range" API avoids that:
#   1. hash the password with SHA-1, locally:  5BAA61E4C9B93F3F...
#   2. send only the FIRST 5 hex characters:   5BAA6
#   3. HIBP returns every leaked hash starting with those 5 (hundreds)
#   4. look for the rest of yours in that list, locally
# HIBP never learns which of the hundreds you were checking. That's
# K-ANONYMITY: you're hidden among k others. "Add-Padding" asks it to
# pad the reply with fake entries, so even the reply's size gives
# nothing away.
#
# (SHA-1 is fine HERE: it's used as a lookup key, not to protect the
# password. For storing passwords it's far too fast; see section 6.)

HIBP_RANGE = "https://api.pwnedpasswords.com/range/"


def hibp_fetch(prefix):
    request = urllib.request.Request(HIBP_RANGE + prefix, headers={
        "User-Agent": "password-analyzer-learning-project", "Add-Padding": "true"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.read().decode("utf-8")


def times_leaked(password, fetch=hibp_fetch):
    """How many times this password appears in known breaches (0 = not found)."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, rest = digest[:5], digest[5:]
    for line in fetch(prefix).splitlines():
        suffix, _, count = line.partition(":")
        if suffix.strip() == rest:
            return int(count)                         # padding entries have count 0
    return 0


# ---------------------------------------------------------------
# 8. Reading a password safely
# ---------------------------------------------------------------
#
# NEVER take a password as a command-line argument ("main.py hunter2"):
#   * it's saved in your shell history (~/.bash_history, ~/.zsh_history)
#   * while it runs, any user on the machine can see it with `ps aux`
# getpass.getpass() reads it from the terminal without showing it, the
# way sudo and ssh do. And the report never prints the password itself.

def report(result, leaked=None):
    lines = [f"  verdict:      {result['verdict'].upper()}",
             f"  length:       {result['length']} characters, passes {result['rules_passed']} of 5 "
             f"sign-up rules",
             f"  cheapest way: {result['how']}",
             f"  guesses:      about {result['guesses']:.3g} ({result['bits']} bits; "
             f"the naive formula says {result['naive_bits']})"]
    for name, when in result["crack_times"].items():
        lines.append(f"    {name:<20} {when}")
    if leaked is not None:
        lines.append(f"  leaked:       {'seen ' + format(leaked, ',') + ' times in breaches: never use it' if leaked else 'not in known breaches'}")
    lines += [f"  tip:          {tip}" for tip in result["advice"]]
    return "\n".join(lines)


def main(argv=None, ask=getpass.getpass, fetch=hibp_fetch, out=sys.stdout):
    p = argparse.ArgumentParser(description="Estimate how many guesses a password would take to crack.")
    p.add_argument("--check", action="store_true", help="type a password to analyse (it isn't shown)")
    p.add_argument("--wordlist", help="common passwords, one per line, most common first")
    p.add_argument("--breach-check", action="store_true",
                   help="also check Have I Been Pwned (sends only 5 characters of a hash)")
    args = p.parse_args(argv)
    if not args.check:
        p.print_help(out)
        return 0
    ranks = load_wordlist(args.wordlist) if args.wordlist else None
    password = ask("Password (not shown): ")
    leaked = None
    if args.breach_check:
        try:
            leaked = times_leaked(password, fetch)
        except OSError as err:
            print(f"  (breach check failed: {err})", file=sys.stderr)
    print(report(analyse(password, ranks), leaked), file=out)
    return 0


# ---------------------------------------------------------------
# The lesson: a few passwords, compared
# ---------------------------------------------------------------

SAMPLES = ["password", "P@ssw0rd!", "Summer2024!", "qwerty123", "poiuytrewq",
           "abcabcabcabc", "Tr0ub4dor&3", "correct horse battery staple",
           "orbit lemon cactus velvet harbor quilt", "kX9#mQ2$vL7!pR4&"]


def lesson():
    print(f"  {'password':<40} {'rules':>5} {'naive bits':>10} {'real bits':>9}  "
          f"{'offline, fast hash':<22} cheapest way")
    for pw in SAMPLES:
        r = analyse(pw)
        print(f"  {pw:<40} {r['rules_passed']:>3}/5 {r['naive_bits']:>10} {r['bits']:>9}  "
              f"{r['crack_times']['offline, fast hash']:<22} {r['how']}")
    print("""
  Notice:
  * "P@ssw0rd!" passes all 5 rules and still falls instantly: it's the
    common password "password" with the changes crackers try first.
  * "Tr0ub4dor&3" looks strong here only because "troubador" isn't in
    this tiny wordlist. A real cracker's dictionary has it; with
    --wordlist and a real list, its estimate collapses. An estimate is
    only as good as the attacker model behind it.
  * The 4-word passphrase is easy to remember, and safe from online
    guessing, but if a site stores passwords with a FAST hash and its
    database leaks, it falls in days. 6 random words survive even that.
    Random matters: words from a sentence you'd say are much weaker.""")


# ---------------------------------------------------------------
# 9. Practice and tests
# ---------------------------------------------------------------
#
# Practice: years are a favourite suffix ("Summer2024"). Write
# looks_like_year(text) that's True for "1950" to "2039" and False for
# other 4-digit numbers, and make affix_guesses() charge only ~90 guesses
# for a year. Solution: looks_like_year() below (affix_guesses already
# charges 200 for any 4 digits, a simpler stand-in).

def looks_like_year(text):
    return bool(re.fullmatch(r"(19[5-9]\d|20[0-3]\d)", text))


def run_tests():
    # 1. Naive entropy overrates human passwords
    assert pool_size("abc") == 26 and pool_size("aB3!") == 95
    assert naive_entropy("P@ssw0rd!") > 55
    assert all(rule_check("P@ssw0rd!").values())

    # 2-3. Common passwords and their mangled versions
    assert estimate_guesses("password")[0] == 2                       # #2 on the list
    assert estimate_guesses("PASSWORD")[0] == 2
    guesses, how = estimate_guesses("P@ssw0rd!")
    assert guesses < 1e4 and "'password'" in how and "look-alike" in how and "'!' at the end" in how
    assert "il" not in unleet("1")[0] and set(unleet("1")) == {"i", "l"}
    assert len(unleet("1" * 20)) == 64                                 # capped
    assert affix_guesses("2024!") == 200 * 33                          # a year, then a symbol
    assert estimate_guesses("Summer2024!")[0] < 1e7                   # "summer" + year + !
    assert verdict(estimate_guesses("Summer2024!")[0]) in ("weak", "fair")

    # 4. Patterns
    assert is_keyboard_walk("asdfghjkl;") and is_keyboard_walk("poiuy") and not is_keyboard_walk("qwas")
    assert is_sequence("abcdef") and is_sequence("4321") and not is_sequence("abce")
    assert repeated_unit("abcabcabc") == ("abc", 3) and repeated_unit("abcd") is None
    assert "keyboard" in estimate_guesses("poiuytrewq")[1]             # a row, backwards
    assert estimate_guesses("abcabcabcabc")[0] < 1e5

    # 5. Passphrases stay strong even when the attacker knows they're words
    guesses, how = estimate_guesses("correct horse battery staple")
    assert "4 words" in how and verdict(guesses) == "strong"
    assert crack_times(guesses)["offline, fast hash"].endswith("days")   # ...but not against a fast-hash leak
    assert any("6 random words" in tip for tip in advice("correct horse battery staple", how))
    six = estimate_guesses("orbit lemon cactus velvet harbor quilt")[0]
    assert crack_times(six)["offline, fast hash"].endswith("centuries")
    assert verdict(estimate_guesses("kX9#mQ2$vL7!pR4&")[0]) == "strong"

    # A bigger wordlist finds what the tiny one misses
    assert verdict(estimate_guesses("Tr0ub4dor&3")[0]) == "strong"
    assert verdict(estimate_guesses("Tr0ub4dor&3", {"troubador": 5000})[0]) in ("very weak", "weak", "fair")

    # 6. Crack times
    assert crack_times(2)["offline, fast hash"] == "instantly"
    assert human_time(90) == "2 minutes" and human_time(3 * 86400) == "3 days"
    assert crack_times(1e20)["offline, fast hash"].endswith("centuries")

    # 7. The breach check sends only 5 characters, and finds the rest locally
    sha1 = hashlib.sha1(b"password").hexdigest().upper()               # 5BAA61E4...
    sent = []

    def fake_fetch(prefix):
        sent.append(prefix)
        return f"0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{sha1[5:]}:9545824\r\n{'F' * 35}:0"

    assert times_leaked("password", fake_fetch) == 9545824
    assert sent == ["5BAA6"]                                           # never the password or full hash
    assert times_leaked("something-else", fake_fetch) == 0

    # 8. The tool: reads with getpass, never prints the password
    import io
    out = io.StringIO()
    code = main(["--check", "--breach-check"], ask=lambda prompt: "P@ssw0rd!", fetch=fake_fetch, out=out)
    assert code == 0 and "VERY WEAK" in out.getvalue() and "P@ssw0rd!" not in out.getvalue()

    # Practice
    assert looks_like_year("2024") and looks_like_year("1987")
    assert not looks_like_year("1234") and not looks_like_year("2099")

    print("All tests passed!")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("--- How strong are these passwords, really? ---")
        lesson()
        print()
        run_tests()
    else:
        sys.exit(main())
