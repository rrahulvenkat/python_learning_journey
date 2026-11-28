# Mistakes and Lessons

Real mistakes from building the code in this repo and my security
projects, and what each one taught. Some were mine, some were in code
written with an AI assistant; all of them were caught by a test, a
measurement or real data, which is the point.

Each entry: **what went wrong**, **why**, and **the lesson**.

---

## Password analyzer (`projects/password_analyzer/`)

### Scoring "2024!" as five random characters
- **What went wrong:** `Summer2024!` was rated much stronger than it is.
  The ending `2024!` was scored as any 5-character string, about 130
  million options.
- **Why:** password crackers add digits and symbols as *separate* steps:
  a year (about 200 likely ones), then a symbol (33). That's about 6,600
  guesses.
- **Lesson:** to estimate how hard something is to attack, copy how the
  attacker actually works, step by step, not the maths of random choice.

### Claiming four random words are "strong against everything"
- **What went wrong:** the lesson text first said the 4-word passphrase
  `correct horse battery staple` stays strong even when the attacker
  knows it's words. The program's own table said it falls in **2 days**
  if a site with a fast hash is breached.
- **Why:** I wrote the conclusion before reading the numbers.
- **Lesson:** check every claim against your own output. Four random words
  are fine against online guessing; six survive a database leak.

### A test that tested something else
- **What went wrong:** a test for keyboard-pattern detection used
  `asdfghjkl;`. It's also on the common-passwords list, so a different
  check answered first and the keyboard check was never really tested.
- **Lesson:** a test should only be passable by the behaviour it's about.
  Pick inputs that can't be explained any other way (here, the row
  typed backwards: `poiuytrewq`).

---

## Cipher cracker (`projects/cipher_cracker/`)

### Statistical attacks need enough text
- **What went wrong:** the Vigenère break recovered the key `memen` instead
  of `lemon`, and the sample's own Index of Coincidence (0.052) didn't even
  look like English (0.067).
- **Why:** the sample was a short, repetitive sentence ("the quick brown
  fox..."). Letter-frequency and IC attacks need a few hundred letters of
  natural text to be reliable; 150 repetitive ones aren't enough.
- **Lesson:** an attack built on statistics is only as good as its sample
  size. Swapping in a longer natural passage (a paragraph of *Pride and
  Prejudice*) made the IC 0.066 and every key break cleanly.

### Passing a list where a string was expected
- **What went wrong:** `guess_key_length` built columns as lists of letters
  and handed them to `index_of_coincidence`, which did `text.lower()` and
  crashed.
- **Lesson:** decide whether a helper takes a string or a list and keep to
  it; `"".join(column)` at the boundary is clearer than a function that
  accepts both.

## Hash cracker (`projects/hash_cracker/`)

### Counting hashes instead of users
- **What went wrong:** the demo said "3/4 cracked" when all four users were
  cracked. Two users shared the password `123456`, so the dump had only 3
  distinct hashes, and I counted hashes.
- **Lesson:** that identical passwords collapse to one hash is the whole
  point being shown, so the count has to be over users, not hashes. Count
  the thing your sentence claims to count.

## File integrity checker (`projects/file_integrity_checker/`)

### A test that only ran on Unix
- **What went wrong:** a test called `os.geteuid()`, which doesn't exist on
  Windows.
- **Lesson:** guard platform-specific calls (`hasattr(os, "geteuid")`), or
  say clearly that the code is Unix-only.

## Attack paths (`projects/attack_paths/`)

### The "obvious" cut that doesn't cut anything
- **What went wrong:** I expected the best link to cut on `internet -> db`
  to be `app -> db`, the edge next to the database. The code said
  `web -> app` instead, and I assumed the code was wrong.
- **Why:** the code was right. Cutting `app -> db` leaves `db` reachable
  through a side door (`app -> fileserver -> backup -> db`), so it
  achieves nothing. The real choke point is earlier.
- **Lesson:** two things. In security, closing the obvious door rarely
  helps if a side door is open: look at ALL paths, not the one you first
  see. And when your code and your expectation disagree, check which is
  right before "fixing" the code; here the code had found something I'd
  missed.

## Web vulnerabilities (`projects/web_vulns/`)

### A backslash inside an f-string expression
- **What went wrong:** `f"... {login_safe(db, \"admin'--\", ...)}"` was a
  syntax error.
- **Why:** before Python 3.12 the `{...}` part of an f-string can't
  contain a backslash, so the escaped quotes were rejected.
- **Lesson:** compute the awkward value into a variable on the line above,
  then interpolate the plain name. Clearer anyway, and works on every
  version.

### The lesson's own "fix" had the next bug in it
- **What I watched for:** the safe login fixes SQL injection but still
  compares the password in plain text, which is exactly what
  `projects/hash_cracker` warns against. Rather than hide that, the
  practice exercise is to add hashing, so one project's fix doesn't
  quietly teach another project's bug.
- **Lesson:** fixing one vulnerability class can leave another in plain
  sight. Name it, don't let the "after" code look flawless when it isn't.

## TOTP generator (`projects/totp_generator/`)

### A test that could never fail
- **What went wrong:** one test was
  `assert main(["verify", "000000"], ...) in (0, 1)`. The command returns
  0 or 1 for every code, so the test passed whatever the code did.
- **Why:** I didn't know whether `000000` happened to be a valid code at
  that moment, so I accepted both answers instead of choosing an input
  whose answer I DID know.
- **Lesson:** a test that accepts every outcome tests nothing. Build an
  input with a known answer (here: a code outside the 3 the window
  accepts) and assert that exact answer.

### Trusting known answers over my own reasoning
- **What went right:** HOTP and TOTP were checked against the test values
  printed in RFC 4226 and RFC 6238, not against codes my own code
  produced. All 28 matched first time, across SHA-1, SHA-256 and SHA-512.
- **Lesson:** when a standard publishes test vectors, use them. Testing
  your code against its own output only proves it's consistent, not that
  it's right.

## JWT tampering (`projects/jwt_tampering/`)

### A test that tried to do something meaningless
- **What went wrong:** the last test revoked a token that had already
  expired, and crashed: revoking first CHECKS the token, and an expired
  token fails the check.
- **Why:** the code was right; the test was. An expired token needs no
  revoking, since expiry already ends it.
- **Lesson:** when a test fails, ask whether the test describes something
  sensible before changing the code. The rewritten test checks what I
  actually meant: expiry ends every session, and the revocation list
  forgets entries once they've expired, so it can't grow forever.

### Using the projects on each other
- **What went right:** the new file was checked with
  `projects/secrets_scanner` before committing (no findings: every token
  is made at runtime), and the HS256 code was checked against the
  signature published in RFC 7515.
- **Lesson:** small tools pay off when you use them on your own work.

## Secrets scanner (`projects/secrets_scanner/`)

### Entropy can't tell on short strings
- **What went wrong:** the human password `Summer2024-prod!` was rated a
  random machine-made key (3.6 bits per character).
- **Why:** a string of length n can't score more than log2(n) bits per
  character, so 16 characters top out at 4.0, and almost any 16 with few
  repeats lands near that ceiling. The measurement just can't separate
  "random" from "varied" at that length.
- **Lesson:** know the limits of a metric before trusting a threshold.
  "Random-looking" now needs 20+ characters and 4.0+ bits.

### The scanner flagged itself
- **What went wrong:** a test that scans the scanner's own file found 6
  "secrets": example assignments in comments, test inputs, and a
  dictionary key named `private_key`.
- **Lesson:** run your tool on its own code (dogfooding). Code ABOUT
  secrets is full of secret-shaped text. Anything meant to be found is
  now assembled at runtime, so the source holds none, which also keeps
  GitHub's push protection from blocking it.

### The first real scan found two scanner bugs
- **What went wrong:** scanning this whole repo flagged AWS's documented
  example key (ending in `EXAMPLE`) and an f-string field,
  `password = '{password}'`, as leaks.
- **Lesson:** the same as with log-detection-engine: real input finds what
  made-up tests don't. Both are fixed and tested. One false alarm is
  left, on a `print` line, and is documented rather than patched with a
  fragile special case: no scanner is perfect, and a person reviews the
  MEDIUM findings.

---

## log-detection-engine: testing on real logs

These came from running my
[log-detection-engine](https://github.com/rrahulvenkat/log-detection-engine)
on public real-world logs, after it had passed all its tests on made-up
data.

### A fix that never reached the copy
- **What went wrong:** the engine counted `message repeated 5 times:
  [ Failed password ... ]` as 1 attempt, and missed 2 of 11 attackers.
  My SSH tools had found and fixed this bug weeks earlier.
- **Why:** the engine was built from copies of lesson code, made before
  the fix.
- **Lesson:** copied code drifts. When you fix a bug, look for its copies;
  a test for the bug, copied too, catches it.

### Trusting attacker-chosen data
- **What went wrong:** correlation merged 9 unrelated attackers into one
  incident, because they had all *guessed* the username `root`.
- **Lesson:** anything an attacker types (usernames in failed logins, user
  agents, X-Forwarded-For headers) is a claim, not a fact. Don't use it to
  link, trust or identify.

### False alarms from real browsers
- **What went wrong:** both web alerts on 10,000 real requests were wrong.
  Phone browsers' user agents contain `; id)` (the language code for
  Indonesian), which matched my "command injection" pattern `; id`.
- **Lesson:** run detection patterns on real *normal* traffic before
  trusting them. Real data is full of things that look like attacks.

### Missing values crash code built on made-up data
- **What went wrong:** the engine crashed on real Windows logs. Console
  logins have no IP, a `None` went into a set, and `", ".join(...)` failed.
- **Lesson:** real data has missing fields that made-up data doesn't.
  Decide what `None` means for every field you read.

### Working only on the Python I happened to use
- **What went wrong:** on Python 3.10, every CloudTrail and Windows time
  failed to parse. `datetime.fromisoformat()` only learned to read a
  trailing `Z` in Python 3.11.
- **Lesson:** test on the oldest Python version you claim to support.
  Continuous integration (GitHub Actions) can run several versions on
  every push.

### Grading myself on the data I tuned on
- **What went wrong:** after fixing rules to suit two datasets, scoring
  them again on the same datasets proved little.
- **Lesson:** keep some data you don't look at until the end (a
  HELD-OUT set). Choose it before you start, and use it once.

### A score that could hide its own alert
- **What went wrong:** one HIGH alert scored as a MEDIUM incident, so a
  server with 11 attackers came out as "nothing serious".
- **Lesson:** when you combine signals into a score, check the edge
  cases, like a single strong signal. A summary should never be milder
  than its worst part.

---

## Shell and tooling

### `zsh` doesn't split variables into words
- **What went wrong:** a loop like `for ref in "checkout v7"; do set -- $ref`
  worked in bash but sent malformed requests in zsh: `$1` was the whole
  string.
- **Lesson:** zsh (the default shell on macOS) doesn't word-split unquoted
  variables the way bash does. Pass separate arguments to a function
  instead.
