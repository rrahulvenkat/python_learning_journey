# JWT Tampering: how login tokens get forged, and how to check them properly
#
# After you log in, many websites and APIs give you a JSON Web Token
# (JWT) and you send it with every request instead of your password. It
# says who you are ("sub": "alice") and what you may do ("role": "user").
# The server trusts it because it's SIGNED: change one character and the
# signature no longer matches.
#
# That's the theory. In practice, JWT bugs are among the most common
# serious API vulnerabilities, and almost all of them are the SERVER
# checking the token wrongly: not checking the signature at all,
# letting the token choose its own algorithm, using a guessable key, or
# ignoring the expiry. This project builds a JWT signer from the standard
# library, a deliberately vulnerable checker, the attacks that beat it,
# and a checker that stops each one.
#
# Everything runs on tokens this program makes for itself. Testing
# someone else's API is only legal with their permission (a bug bounty
# or a pentest contract).
#
# Topics covered here:
#   1. What a JWT is: three base64url parts, and NOT encrypted
#   2. Signing with HS256 (HMAC-SHA256), checked against RFC 7515
#   3. Attack: decoding without verifying ("role": "admin")
#   4. Attack: "alg": "none" (the token turns off its own check)
#   5. Attack: cracking a weak signing key offline
#   6. Attack: algorithm confusion (RS256 -> HS256 with the PUBLIC key)
#   7. Attack: expired tokens accepted forever
#   8. The safe checker, and what real code should use (PyJWT)
#   9. Practice: revoking tokens (the "logout" problem), with tests
#
# HOW TO RUN IT
#   python3 main.py                         the lesson and the tests


import base64
import hashlib
import hmac
import json
import secrets
import sys
import time


# ---------------------------------------------------------------
# 1. What a JWT is
# ---------------------------------------------------------------
#
#   header . payload . signature       (three parts, joined by dots)
#
#   header:     {"alg": "HS256", "typ": "JWT"}       how it's signed
#   payload:    {"sub": "alice", "role": "user", "exp": 1700003600}
#   signature:  HMAC-SHA256(key, "header.payload")
#
# Each part is BASE64URL: base64 with - and _ instead of + and /, and the
# "=" padding dropped, so it fits in a URL (problem_solving/
# base64_and_url_encoding.py).
#
# The key point: the payload is ENCODED, not ENCRYPTED. Anyone holding
# the token can read it (decode_unverified below, or paste it into
# jwt.io). So never put a password, card number or anything secret in a
# JWT. The signature only stops CHANGES, not reading.

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def encode_part(obj):
    return b64url_encode(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def decode_unverified(token):
    """Read a token's header and payload WITHOUT checking anything."""
    header, payload, _signature = token.split(".")
    return json.loads(b64url_decode(header)), json.loads(b64url_decode(payload))


# ---------------------------------------------------------------
# 2. Signing with HS256
# ---------------------------------------------------------------
#
# HS256 = HMAC with SHA-256. The same secret key signs and checks, so
# only the server should have it. The signature covers the EXACT text of
# "header.payload", so changing anything in either part changes it.

def hs256(key, signing_input):
    return b64url_encode(hmac.new(key, signing_input.encode("ascii"), hashlib.sha256).digest())


def sign(payload, key, header=None):
    header = header or {"alg": "HS256", "typ": "JWT"}
    signing_input = encode_part(header) + "." + encode_part(payload)
    return signing_input + "." + hs256(key, signing_input)


# ---------------------------------------------------------------
# A deliberately VULNERABLE checker
# ---------------------------------------------------------------
#
# Each bug below is real and has been found in production APIs and in
# early versions of JWT libraries.

class Rejected(Exception):
    pass


def check_vulnerable(token, key, now=None):
    header, payload = decode_unverified(token)
    alg = header.get("alg")                      # BUG (4, 6): the TOKEN picks the algorithm
    if alg == "none":
        return payload                           # BUG (4): "unsigned" accepted as valid
    if alg == "HS256":
        signing_input = token.rsplit(".", 1)[0]
        if hs256(key, signing_input) != token.rsplit(".", 1)[1]:   # BUG: == leaks timing
            raise Rejected("bad signature")
        return payload                           # BUG (7): exp never checked
    raise Rejected(f"unsupported alg {alg!r}")


# ---------------------------------------------------------------
# 3. Attack: decoding without verifying
# ---------------------------------------------------------------
#
# The simplest and most common bug: the server READS the token (most
# libraries have a "decode" that skips the check, for debugging) and
# never VERIFIES it. Then anyone can write their own payload:
#   {"sub": "alice", "role": "admin"}
# with any signature at all. Shown by forging, then calling the
# decode-only path below.

def check_decode_only(token):
    return decode_unverified(token)[1]           # BUG: no signature check at all


def tamper(token, **changes):
    """Change payload fields, keeping the OLD signature (which no longer matches)."""
    header, payload, signature = token.split(".")
    claims = json.loads(b64url_decode(payload))
    claims.update(changes)
    return f"{header}.{encode_part(claims)}.{signature}"


# ---------------------------------------------------------------
# 4. Attack: "alg": "none"
# ---------------------------------------------------------------
#
# The JWT standard (RFC 7519) allows "alg": "none" for tokens that are
# deliberately unsigned. A checker that reads the algorithm FROM THE
# TOKEN and supports "none" lets the attacker simply say "this token
# isn't signed" and leave the signature empty. In 2015 several major JWT
# libraries accepted these by default.
#
# THE FIX: the server decides which algorithms it accepts, in its own
# configuration, and rejects everything else. Never let the token
# choose how it's checked.

def forge_none(payload):
    return encode_part({"alg": "none", "typ": "JWT"}) + "." + encode_part(payload) + "."


# ---------------------------------------------------------------
# 5. Attack: cracking a weak key
# ---------------------------------------------------------------
#
# An HS256 token is its own cracking target: the attacker has the signed
# text AND the signature, so they can try candidate keys offline, as fast
# as their hardware allows, with no requests to the server (hashcat has a
# mode just for this: 16500). If the key is "secret" or the app's name,
# it falls in seconds, and then the attacker can sign ANY token.
# Tutorials and frameworks have shipped with keys like "secret",
# "changeme" or "your-256-bit-secret" that people never replaced.
#
# THE FIX: a long RANDOM key, at least 32 bytes from `secrets`, kept out
# of the code (projects/secrets_scanner), never a word.

COMMON_KEYS = ["secret", "password", "123456", "changeme", "jwt", "jwtsecret", "key", "admin",
               "your-256-bit-secret", "supersecret", "s3cr3t", "default", "test", "dev"]


def crack_key(token, candidates):
    signing_input, signature = token.rsplit(".", 1)
    for word in candidates:
        if hmac.compare_digest(hs256(word.encode("utf-8"), signing_input), signature):
            return word
    return None


# ---------------------------------------------------------------
# 6. Attack: algorithm confusion
# ---------------------------------------------------------------
#
# Many systems sign with RS256 instead: an RSA PRIVATE key signs, and a
# PUBLIC key checks. The public key isn't secret (it's often published
# at /.well-known/jwks.json).
#
# Now take a checker written as `check(token, key)`, where `key` is the
# server's PUBLIC key and the algorithm comes from the token's header.
# The attacker sends a token with "alg": "HS256", signed by HMAC using
# the PUBLIC KEY TEXT as the HMAC secret. The checker sees HS256, runs
# HMAC with the key it was given (the public key), and it matches. The
# attacker never needed the private key.
#
# This one is shown without any RSA maths: the vulnerable checker above
# never looks at what KIND of key it holds, which is the whole bug.
#
# THE FIX: the same as for "none": the server fixes the algorithm. A
# server that expects RS256 rejects an HS256 token before using any key.

def public_key_text():
    # A stand-in for a real PEM public key: what matters is that it's PUBLIC.
    return "-----BEGIN " + "PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1L\n-----END PUBLIC KEY-----\n"


# ---------------------------------------------------------------
# 7. Attack: expired tokens accepted forever
# ---------------------------------------------------------------
#
# A JWT can't be "logged out" (section 9): once issued, it's valid until
# it expires. So "exp" (expiry, in Unix seconds) is the main limit on
# how long a STOLEN token works. A checker that doesn't check it makes
# every token, from every leaked log file, valid forever. Same for "nbf"
# (not before), "aud" (which service it's for) and "iss" (who issued it).


# ---------------------------------------------------------------
# 8. The safe checker
# ---------------------------------------------------------------
#
# Every fix together, in the order a careful library does them:
#   1. three parts, or reject
#   2. the algorithm must be one the SERVER allows (never "none")
#   3. the signature must match, compared in constant time
#      (hmac.compare_digest: == stops at the first wrong character, and
#      that timing difference can be measured; oop/encapsulation.py)
#   4. only THEN read the payload, and check exp / nbf / aud / iss, with
#      a little leeway for clocks that disagree by a few seconds
#
# In real code, don't hand-roll this: use a maintained library and STILL
# say what you expect, e.g. with PyJWT:
#   jwt.decode(token, key, algorithms=["HS256"], audience="my-api")
# The `algorithms=` argument is required in current PyJWT precisely
# because of attacks 4 and 6.

def check_safe(token, key, algorithms=("HS256",), now=None, audience=None, issuer=None, leeway=30):
    parts = token.split(".")
    if len(parts) != 3:
        raise Rejected("not a JWT")
    try:
        header = json.loads(b64url_decode(parts[0]))
    except ValueError:
        raise Rejected("unreadable header") from None
    alg = header.get("alg")
    if alg not in algorithms or alg == "none":
        raise Rejected(f"algorithm {alg!r} not allowed (expected one of {list(algorithms)})")
    if alg != "HS256":
        raise Rejected(f"{alg} needs a real crypto library to verify")   # e.g. RS256: PyJWT + cryptography
    if not hmac.compare_digest(hs256(key, parts[0] + "." + parts[1]), parts[2]):
        raise Rejected("bad signature")
    payload = json.loads(b64url_decode(parts[1]))           # trusted only now
    now = time.time() if now is None else now
    if "exp" in payload and now > payload["exp"] + leeway:
        raise Rejected("expired")
    if "nbf" in payload and now < payload["nbf"] - leeway:
        raise Rejected("not valid yet")
    if audience is not None and payload.get("aud") != audience:
        raise Rejected(f"meant for {payload.get('aud')!r}, not {audience!r}")
    if issuer is not None and payload.get("iss") != issuer:
        raise Rejected(f"issued by {payload.get('iss')!r}, not {issuer!r}")
    return payload


# ---------------------------------------------------------------
# The lesson
# ---------------------------------------------------------------

def outcome(check, token):
    try:
        claims = check(token)
        return f"ACCEPTED as {claims.get('sub')} (role: {claims.get('role')})"
    except Rejected as e:
        return f"rejected: {e}"


def lesson():
    key = secrets.token_bytes(32)                                  # a properly random key
    now = 1_700_000_000
    alice = sign({"sub": "alice", "role": "user", "exp": now + 3600}, key)
    header, payload = decode_unverified(alice)
    print(f"  alice's token has {len(alice)} characters in 3 parts. Anyone can read it:")
    print(f"    header  {header}")
    print(f"    payload {payload}")

    vuln = lambda t: check_vulnerable(t, key, now)
    safe = lambda t: check_safe(t, key, now=now)

    print("\n  3. alice edits her role to admin, keeping the old signature:")
    edited = tamper(alice, role="admin")
    print(f"     decode-only server: {outcome(check_decode_only, edited)}")
    print(f"     safe server:        {outcome(safe, edited)}")

    print("\n  4. alice makes an UNSIGNED token, \"alg\": \"none\":")
    unsigned = forge_none({"sub": "alice", "role": "admin", "exp": now + 3600})
    print(f"     vulnerable server:  {outcome(vuln, unsigned)}")
    print(f"     safe server:        {outcome(safe, unsigned)}")

    print("\n  5. a server signing with the weak key \"changeme\":")
    weak = "change" + "me"
    token = sign({"sub": "alice", "role": "user", "exp": now + 3600}, weak.encode())
    found = crack_key(token, COMMON_KEYS)
    print(f"     cracked offline from ONE token: the key is {found!r}")
    forged = sign({"sub": "alice", "role": "admin", "exp": now + 3600}, found.encode())
    print(f"     re-signed as admin, even the safe checker: "
          f"{outcome(lambda t: check_safe(t, weak.encode(), now=now), forged)}")
    print(f"     (no checker can save a guessable key; the random one above isn't in any list: "
          f"{crack_key(alice, COMMON_KEYS)})")

    print("\n  6. a server meant to use RS256, checking with its PUBLIC key:")
    public = public_key_text().encode()
    confused = sign({"sub": "alice", "role": "admin", "exp": now + 3600}, public)
    print(f"     vulnerable server:  {outcome(lambda t: check_vulnerable(t, public, now), confused)}")
    print(f"     safe server (RS256 only): "
          f"{outcome(lambda t: check_safe(t, public, algorithms=('RS256',), now=now), confused)}")

    print("\n  7. alice's token, a day after it expired:")
    later = now + 86400
    print(f"     vulnerable server:  {outcome(lambda t: check_vulnerable(t, key, later), alice)}")
    print(f"     safe server:        {outcome(lambda t: check_safe(t, key, now=later), alice)}")


# ---------------------------------------------------------------
# 9. Practice and tests
# ---------------------------------------------------------------
#
# Practice: a JWT can't be "logged out": the server doesn't store it, so
# a stolen token works until it expires. The usual fix is a "jti" (JWT
# ID) claim: a random ID per token, and a DENYLIST of IDs revoked at
# logout, kept until each would have expired anyway. Write a
# TokenService with issue(sub, role), check(token) and revoke(token).
# Solution below.

class TokenService:
    def __init__(self, lifetime=900, key=None):
        self.key = key or secrets.token_bytes(32)
        self.lifetime = lifetime
        self.revoked = {}                        # jti -> its exp, so old entries can be dropped

    def issue(self, sub, role, now=None):
        now = time.time() if now is None else now
        return sign({"sub": sub, "role": role, "jti": secrets.token_hex(16),
                     "iat": int(now), "exp": int(now) + self.lifetime}, self.key)

    def check(self, token, now=None):
        claims = check_safe(token, self.key, now=now)
        if claims.get("jti") in self.revoked:
            raise Rejected("revoked (logged out)")
        return claims

    def revoke(self, token, now=None):
        claims = self.check(token, now)
        self.revoked[claims["jti"]] = claims["exp"]
        now = time.time() if now is None else now
        self.revoked = {j: e for j, e in self.revoked.items() if e >= now}   # forget expired ones


def run_tests():
    # 2. HS256 against RFC 7515, Appendix A.1: its exact header and payload
    #    bytes (with \r\n inside), its key, and its published signature.
    rfc_key = b64url_decode("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")
    rfc_header = b64url_encode(b'{"typ":"JWT",\r\n "alg":"HS256"}')
    rfc_payload = b64url_encode(b'{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}')
    assert hs256(rfc_key, rfc_header + "." + rfc_payload) == "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

    # 1. base64url round trips, and the payload is readable by anyone
    for data in (b"", b"a", b"ab", b"abc", b"\xfb\xff\xfe"):
        assert b64url_decode(b64url_encode(data)) == data
    assert "+" not in b64url_encode(b"\xfb\xff") and "=" not in b64url_encode(b"a")
    key = secrets.token_bytes(32)
    now = 1_700_000_000
    token = sign({"sub": "alice", "role": "user", "exp": now + 3600}, key)
    assert token.count(".") == 2 and decode_unverified(token)[1]["role"] == "user"

    # The safe checker accepts a genuine token
    assert check_safe(token, key, now=now)["sub"] == "alice"

    # 3. Tampering: the decode-only bug lets it through; the safe checker doesn't
    edited = tamper(token, role="admin")
    assert check_decode_only(edited)["role"] == "admin"
    for bad in (edited, token[:-1] + ("A" if token[-1] != "A" else "B")):
        try:
            check_safe(bad, key, now=now)
        except Rejected as e:
            assert "signature" in str(e)
        else:
            raise AssertionError("a tampered token was accepted")

    def refused(check, t, why):
        try:
            check(t)
        except Rejected as e:
            assert why in str(e), (why, str(e))
        else:
            raise AssertionError(f"accepted, expected: {why}")

    # 4. alg none: accepted by the vulnerable checker, refused by the safe one
    unsigned = forge_none({"sub": "alice", "role": "admin"})
    assert check_vulnerable(unsigned, key, now)["role"] == "admin"
    refused(lambda t: check_safe(t, key, now=now), unsigned, "not allowed")
    refused(lambda t: check_safe(t, key, algorithms=("HS256", "none"), now=now), unsigned, "not allowed")

    # 5. A weak key falls to a wordlist; a random one doesn't
    weak = sign({"sub": "x"}, ("jwt" + "secret").encode())
    assert crack_key(weak, COMMON_KEYS) == "jwtsecret"
    assert crack_key(token, COMMON_KEYS) is None

    # 6. Algorithm confusion: the public key used as an HMAC secret
    public = public_key_text().encode()
    confused = sign({"sub": "alice", "role": "admin"}, public)
    assert check_vulnerable(confused, public, now)["role"] == "admin"
    refused(lambda t: check_safe(t, public, algorithms=("RS256",), now=now), confused, "not allowed")

    # 7. Time claims, with leeway
    assert check_vulnerable(token, key, now + 86400)["sub"] == "alice"              # never expires
    refused(lambda t: check_safe(t, key, now=now + 86400), token, "expired")
    assert check_safe(token, key, now=now + 3600 + 10)["sub"] == "alice"          # within the leeway
    future = sign({"sub": "a", "nbf": now + 600}, key)
    refused(lambda t: check_safe(t, key, now=now), future, "not valid yet")
    scoped = sign({"sub": "a", "aud": "billing-api", "iss": "auth.example"}, key)
    assert check_safe(scoped, key, now=now, audience="billing-api", issuer="auth.example")
    refused(lambda t: check_safe(t, key, now=now, audience="admin-api"), scoped, "meant for")
    refused(lambda t: check_safe(t, key, now=now, issuer="evil.example"), scoped, "issued by")

    # Junk input never crashes the safe checker
    for junk in ("", "a.b", "a.b.c.d", "!!!.x.y"):
        refused(lambda t: check_safe(t, key, now=now), junk, "")

    # Practice: logout by revoking the token's ID
    service = TokenService(lifetime=900)
    t1 = service.issue("alice", "user", now=now)
    t2 = service.issue("alice", "user", now=now)
    assert decode_unverified(t1)[1]["jti"] != decode_unverified(t2)[1]["jti"]
    assert service.check(t1, now=now)["sub"] == "alice"
    service.revoke(t1, now=now)
    refused(lambda t: service.check(t, now=now), t1, "revoked")
    assert service.check(t2, now=now)["sub"] == "alice"            # other sessions unaffected
    refused(lambda t: service.check(t, now=now + 2000), t2, "expired")   # expiry ends every session
    t3 = service.issue("bob", "user", now=now + 2000)
    service.revoke(t3, now=now + 2000)
    # The denylist forgets IDs once their token has expired, so it can't grow forever
    assert decode_unverified(t1)[1]["jti"] not in service.revoked and len(service.revoked) == 1

    print("All tests passed!")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("--- Forging login tokens, and checking them properly ---")
        lesson()
        print()
        run_tests()
    else:
        print("This project is a lesson with no command line; run it with no arguments.", file=sys.stderr)
        sys.exit(2)
