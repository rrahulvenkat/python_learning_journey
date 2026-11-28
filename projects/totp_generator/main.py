# TOTP: the six-digit codes in Google Authenticator, built from scratch
#
# Two-factor authentication (2FA) asks for something you KNOW (your
# password) and something you HAVE (your phone). The six-digit codes in
# Google Authenticator, Microsoft Authenticator, Authy and 1Password are
# TOTP: Time-based One-Time Passwords, defined in RFC 6238. A stolen
# password alone is no longer enough: the attacker also needs a code
# that changes every 30 seconds.
#
# How it works, in one line: your phone and the server share a SECRET
# once (that's the QR code), and from then on both compute
#   code = HMAC(secret, number of 30-second steps since 1970) -> 6 digits
# No network needed: the phone and the server just agree on the time.
#
# This builds it from the standard library only, and checks it against
# the official test values printed in the RFCs, so you know it's right.
#
# Topics covered here:
#   1. The shared secret, and base32 (why secrets look like JBSWY3DP...)
#   2. HOTP (RFC 4226): HMAC of a counter, then "dynamic truncation"
#   3. TOTP (RFC 6238): the counter is the time, in 30-second steps
#   4. The otpauth:// link that a QR code holds
#   5. Verifying on the server: clock drift, constant-time compare,
#      replays, and rate limits
#   6. What TOTP does NOT protect against (phishing proxies) and what does
#   7. Practice, with tests
#
# HOW TO RUN IT
#   python3 main.py                        the lesson and the tests
#   python3 main.py new --account alice@example.com --issuer MyApp
#   python3 main.py code                   asks for the secret (not shown)
#   TOTP_SECRET=JBSWY3DPEHPK3PXP python3 main.py code
#
# The secret is read from a prompt or the TOTP_SECRET variable, never a
# command-line argument (shell history and `ps` would show it; see
# projects/password_analyzer section 8).
#
# Only add secrets from YOUR OWN accounts. A TOTP secret is as sensitive
# as a password: anyone who has it can make your codes.


import argparse
import base64
import getpass
import hashlib
import hmac
import os
import secrets
import struct
import sys
import time
import urllib.parse


# ---------------------------------------------------------------
# 1. The shared secret, and base32
# ---------------------------------------------------------------
#
# The secret is random BYTES: 20 of them (160 bits) is the usual size
# for HMAC-SHA1. Made with the `secrets` module, which uses the
# operating system's cryptographic random source. Never `random`: its
# output can be predicted from earlier output.
#
# People sometimes type secrets in by hand, so they're shown in BASE32:
# only A-Z and 2-7, no 0/O or 1/l to confuse. 5 bytes become 8
# characters. Apps also show it in groups and lower case, so decoding
# must ignore spaces and case, and add back the "=" padding that's
# usually left off.

def new_secret(nbytes=20):
    return base64.b32encode(secrets.token_bytes(nbytes)).decode("ascii").rstrip("=")


def decode_secret(text):
    cleaned = text.replace(" ", "").replace("-", "").upper()
    padded = cleaned + "=" * (-len(cleaned) % 8)
    try:
        return base64.b32decode(padded, casefold=False)
    except (ValueError, base64.binascii.Error) as err:
        raise ValueError(f"not a valid base32 secret: {err}") from None


# ---------------------------------------------------------------
# 2. HOTP: an HMAC of a counter
# ---------------------------------------------------------------
#
# HOTP (RFC 4226) turns a counter into a code:
#   1. HMAC-SHA1(secret, counter as 8 bytes, big-endian) -> 20 bytes
#   2. DYNAMIC TRUNCATION: the low 4 bits of the LAST byte give an
#      offset (0-15); take the 4 bytes starting there, and drop the top
#      bit (so the number is never negative in any language)
#   3. that 31-bit number, mod 10**6, padded to 6 digits
#
# HMAC (also used in projects/file_integrity_checker) mixes the secret
# into the hash, so without the secret nobody can compute the code, and
# seeing old codes doesn't reveal the secret.

def hotp(key, counter, digits=6, algorithm="sha1"):
    message = struct.pack(">Q", counter)              # 8 bytes, big-endian
    digest = hmac.new(key, message, getattr(hashlib, algorithm)).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10 ** digits).zfill(digits)


# ---------------------------------------------------------------
# 3. TOTP: the counter is the time
# ---------------------------------------------------------------
#
# TOTP is HOTP with counter = number of 30-second steps since 1 January
# 1970 (Unix time). Phone and server compute the same counter from their
# clocks, so they get the same code with no messages between them.
# Google Authenticator's defaults: SHA-1, 6 digits, 30 seconds. (The RFC
# also allows SHA-256 and SHA-512, which few apps support.)

STEP = 30


def time_step(at=None, step=STEP):
    return int((time.time() if at is None else at) // step)


def totp(key, at=None, digits=6, step=STEP, algorithm="sha1"):
    return hotp(key, time_step(at, step), digits, algorithm)


def seconds_left(at=None, step=STEP):
    now = time.time() if at is None else at
    return step - int(now % step)


# ---------------------------------------------------------------
# 4. The otpauth:// link (what the QR code holds)
# ---------------------------------------------------------------
#
# The QR code a site shows during 2FA setup is just this text:
#   otpauth://totp/Issuer:account?secret=...&issuer=Issuer&algorithm=SHA1&digits=6&period=30
# Scanning it gives the phone the secret and the settings. So the QR code
# IS the secret: anyone who photographs it can make your codes forever.
# (To show one, the third-party `qrcode` package can draw this text.)

def otpauth_uri(secret, account, issuer):
    label = urllib.parse.quote(f"{issuer}:{account}")
    query = urllib.parse.urlencode({"secret": secret, "issuer": issuer, "algorithm": "SHA1",
                                    "digits": 6, "period": STEP})
    return f"otpauth://totp/{label}?{query}"


# ---------------------------------------------------------------
# 5. Verifying on the server
# ---------------------------------------------------------------
#
# Four details separate a toy from something safe:
#
#   CLOCK DRIFT: phones' clocks are a few seconds off, and the user takes
#     time to type. So accept the codes for the previous and next step too
#     (a "window" of 1). Not more: every extra step accepted is another
#     code an attacker could guess.
#
#   CONSTANT-TIME COMPARE: hmac.compare_digest, not ==, so the time taken
#     doesn't leak how many digits were right.
#
#   REPLAYS: a code is valid for ~90 seconds with a window of 1. If
#     someone watches you type it, they could use it again. So remember
#     the last step each user logged in with, and refuse that step or
#     any earlier one.
#
#   RATE LIMITS: 6 digits is only 1,000,000 codes, and with a window of 1,
#     3 of them are right at any moment. Unlimited guessing would get in
#     in about 333,000 tries: minutes for a script. So lock out after a
#     few failures (the practice below).

def verify(key, code, at=None, window=1, last_step=None, digits=6):
    """Returns the matching time step (to store as last_step), or None."""
    if not (isinstance(code, str) and code.isdigit() and len(code) == digits):
        return None
    now = time_step(at)
    for step in range(now - window, now + window + 1):
        if last_step is not None and step <= last_step:
            continue                                  # already used, or older: a replay
        if hmac.compare_digest(hotp(key, step, digits), code):
            return step
    return None


# ---------------------------------------------------------------
# 6. What TOTP does NOT protect against
# ---------------------------------------------------------------
#
#   * PHISHING PROXIES. A fake login page (tools like Evilginx automate
#     this) passes your password AND your code to the real site as you
#     type them, within the 30 seconds. TOTP stops a stolen password
#     database; it doesn't stop a live phishing relay. WebAuthn / passkeys
#     do, because the browser signs for the REAL site's name, so a code
#     typed into a fake site is useless there.
#   * A STOLEN SECRET. Unlike passwords, the server can't store only a
#     hash: it needs the secret itself to compute codes. A server breach
#     can leak every user's TOTP secret, so they must be encrypted at rest.
#   * SIM swaps and SMS codes are a different (weaker) system; TOTP isn't
#     affected, which is one reason it's preferred over SMS.


# ---------------------------------------------------------------
# The command line
# ---------------------------------------------------------------

def read_secret(ask):
    value = os.environ.get("TOTP_SECRET") or ask("TOTP secret (not shown): ")
    return decode_secret(value)


def main(argv=None, ask=getpass.getpass, now=None, out=sys.stdout):
    p = argparse.ArgumentParser(prog="main.py", description="Generate and check TOTP 2FA codes.")
    sub = p.add_subparsers(dest="command", required=True)
    n = sub.add_parser("new", help="make a new secret and its otpauth:// link")
    n.add_argument("--account", required=True)
    n.add_argument("--issuer", required=True)
    sub.add_parser("code", help="show the current code (secret from a prompt or $TOTP_SECRET)")
    v = sub.add_parser("verify", help="check a code (secret from a prompt or $TOTP_SECRET)")
    v.add_argument("code")
    args = p.parse_args(argv)

    if args.command == "new":
        secret = new_secret()
        print(f"secret: {secret}", file=out)
        print(f"link:   {otpauth_uri(secret, args.account, args.issuer)}", file=out)
        print("Keep both private: either one lets anyone make your codes.", file=out)
        return 0
    try:
        key = read_secret(ask)
    except ValueError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    at = time.time() if now is None else now
    if args.command == "code":
        print(f"{totp(key, at)}  ({seconds_left(at)}s left)", file=out)
        return 0
    ok = verify(key, args.code, at) is not None
    print("valid" if ok else "INVALID", file=out)
    return 0 if ok else 1


# ---------------------------------------------------------------
# The lesson
# ---------------------------------------------------------------

def lesson():
    secret = "JBSWY3DPEHPK3PXP"                       # a well-known demo secret, never use it for real
    key = decode_secret(secret)
    at = 1_700_000_000                                # a fixed moment, so the output doesn't change
    print(f"  secret {secret!r} is {len(key)} bytes: {key!r}")
    print(f"  at Unix time {at}, the step is {time_step(at)} "
          f"(= {at} // 30), so the code is {totp(key, at)}")
    print(f"  30 seconds later it's {totp(key, at + 30)}; 30 before, {totp(key, at - 30)}")
    print(f"\n  the QR code during setup holds:\n    {otpauth_uri(secret, 'alice@example.com', 'MyApp')}")

    code = totp(key, at)
    step = verify(key, code, at)
    print(f"\n  server checks {code}: accepted (step {step})")
    print(f"  the same code again: {'accepted' if verify(key, code, at, last_step=step) else 'refused (a replay)'}")
    print(f"  a code from 2 minutes ago: "
          f"{'accepted' if verify(key, totp(key, at - 120), at) else 'refused (outside the window)'}")
    print(f"\n  6 digits = 1,000,000 codes; 3 are valid at once, so ~333,000 guesses")
    print(f"  on average: why the server must lock out after a few failures.")


# ---------------------------------------------------------------
# 7. Practice and tests
# ---------------------------------------------------------------
#
# Practice: write a Verifier class that wraps verify() for one user. It
# remembers last_step (to stop replays) and counts failures, refusing
# everything after `max_failures` wrong codes in a row until reset.
# Solution below.

class Verifier:
    def __init__(self, key, max_failures=5):
        self.key = key
        self.max_failures = max_failures
        self.last_step = None
        self.failures = 0

    @property
    def locked(self):
        return self.failures >= self.max_failures

    def check(self, code, at=None):
        if self.locked:
            return False
        step = verify(self.key, code, at, last_step=self.last_step)
        if step is None:
            self.failures += 1
            return False
        self.last_step, self.failures = step, 0
        return True


def run_tests():
    # 2. HOTP: RFC 4226, Appendix D (secret "12345678901234567890", counters 0-9)
    rfc_key = b"12345678901234567890"
    expected = ["755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"]
    assert [hotp(rfc_key, c) for c in range(10)] == expected

    # 3. TOTP: RFC 6238, Appendix B (8 digits; SHA-1, SHA-256 and SHA-512 keys)
    keys = {"sha1": b"12345678901234567890",
            "sha256": b"12345678901234567890123456789012",
            "sha512": b"1234567890123456789012345678901234567890123456789012345678901234"}
    vectors = [(59, "94287082", "46119246", "90693936"),
               (1111111109, "07081804", "68084774", "25091201"),
               (1111111111, "14050471", "67062674", "99943326"),
               (1234567890, "89005924", "91819424", "93441116"),
               (2000000000, "69279037", "90698825", "38618901"),
               (20000000000, "65353130", "77737706", "47863826")]
    for at, *codes in vectors:
        for algorithm, code in zip(("sha1", "sha256", "sha512"), codes):
            assert totp(keys[algorithm], at, digits=8, algorithm=algorithm) == code, (at, algorithm)
    assert time_step(59) == 1 and seconds_left(59) == 1 and seconds_left(60) == 30

    # 1. Secrets: random, base32, decoded leniently
    s = new_secret()
    assert len(s) == 32 and set(s) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    assert len(decode_secret(s)) == 20 and new_secret() != s
    assert decode_secret("jbsw y3dp ehpk 3pxp") == decode_secret("JBSWY3DPEHPK3PXP") == b"Hello!\xde\xad\xbe\xef"
    try:
        decode_secret("not base32 0189!")
    except ValueError:
        pass
    else:
        raise AssertionError("a bad secret was accepted")

    # 4. The otpauth link
    uri = otpauth_uri("JBSWY3DPEHPK3PXP", "alice@example.com", "My App")
    assert uri.startswith("otpauth://totp/My%20App%3Aalice%40example.com?")
    assert "secret=JBSWY3DPEHPK3PXP" in uri and "period=30" in uri and "issuer=My+App" in uri

    # 5. Verifying: window, replays, bad input
    key = decode_secret("JBSWY3DPEHPK3PXP")
    at = 1_700_000_000
    assert verify(key, totp(key, at), at) == time_step(at)
    assert verify(key, totp(key, at - 30), at) is not None            # one step late: drift is fine
    assert verify(key, totp(key, at + 30), at) is not None            # one step early
    assert verify(key, totp(key, at - 60), at) is None                # two steps: too old
    step = verify(key, totp(key, at), at)
    assert verify(key, totp(key, at), at, last_step=step) is None     # replay refused
    assert verify(key, totp(key, at + 30), at + 30, last_step=step) is not None   # the next code is fine
    for bad in ("12345", "1234567", "12a456", "", None, 123456):
        assert verify(key, bad, at) is None, bad

    # The command line: secret from a prompt or the environment, never an argument
    import io
    out = io.StringIO()
    assert main(["code"], ask=lambda _: "JBSWY3DPEHPK3PXP", now=at, out=out) == 0
    assert out.getvalue().startswith(totp(key, at)) and "s left" in out.getvalue()
    out = io.StringIO()
    assert main(["verify", totp(key, at)], ask=lambda _: "JBSWY3DPEHPK3PXP", now=at, out=out) == 0
    valid_now = {totp(key, at + d) for d in (-30, 0, 30)}            # the 3 codes the window accepts
    wrong = next(c for c in ("000000", "111111", "222222", "333333") if c not in valid_now)
    out = io.StringIO()
    assert main(["verify", wrong], ask=lambda _: "JBSWY3DPEHPK3PXP", now=at, out=out) == 1
    assert out.getvalue().strip() == "INVALID"
    out = io.StringIO()
    assert main(["new", "--account", "a@example.com", "--issuer", "X"], out=out) == 0
    assert "otpauth://totp/" in out.getvalue()
    saved = os.environ.get("TOTP_SECRET")
    os.environ["TOTP_SECRET"] = "JBSWY3DPEHPK3PXP"
    try:
        out = io.StringIO()
        assert main(["code"], ask=lambda _: 1 / 0, now=at, out=out) == 0          # prompt never used
    finally:
        if saved is None:                                               # put the environment back as it was
            del os.environ["TOTP_SECRET"]
        else:
            os.environ["TOTP_SECRET"] = saved

    # Practice: replays and lockout
    v = Verifier(key, max_failures=3)
    assert v.check(totp(key, at), at) and not v.check(totp(key, at), at)  # second use is a replay
    v = Verifier(key, max_failures=3)
    for _ in range(3):
        assert not v.check(wrong, at)
    assert v.locked and not v.check(totp(key, at), at)                    # locked: even the right code fails

    print("All tests passed!")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("--- Six-digit 2FA codes, from a shared secret and the clock ---")
        lesson()
        print()
        run_tests()
    else:
        sys.exit(main())
