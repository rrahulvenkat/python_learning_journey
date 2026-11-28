# Python Learning Journey 🐍

This repository documents my journey learning and improving Python through
hands-on coding, problem-solving, and practical projects.

I'm a Cybersecurity student at Purdue University interested in software
engineering, AI, cybersecurity, and Forward Deployed Engineering.

## Goals

- Strengthen Python programming fundamentals
- Develop problem-solving skills
- Learn data structures and algorithms
- Write clean, maintainable code
- Build practical applications
- Apply Python to cybersecurity and AI

## Learning Roadmap

### 1. Python Fundamentals
- Variables and data types
- Operators
- Conditional statements
- Loops
- Functions
- Exception handling

### 2. Data Structures
- Lists
- Tuples
- Dictionaries
- Sets
- Strings

### 3. Object-Oriented Programming
- Classes and objects
- Inheritance
- Encapsulation
- Polymorphism

### 4. Problem Solving
- Basic algorithmic problems
- Searching and sorting
- Time and space complexity
- LeetCode practice

### 5. Advanced Python (in `advanced/`)

The parts of the language the fundamentals only introduce, with security
examples throughout:

| Lesson | What it covers |
|---|---|
| [decorators_and_context_managers](advanced/decorators_and_context_managers.py) | Decorators with arguments and `functools.wraps`; access control, rate limiting and an audit log as decorators; `logging`; writing context managers (`__enter__`/`__exit__`, `@contextmanager`, `ExitStack`); `yield from` and a `tail -f` log follower |
| [concurrency](advanced/concurrency.py) | Threads, race conditions and locks, thread pools, `queue.Queue`, the GIL, process pools: checking IPs against a slow API, and cracking a PIN on several CPU cores |
| [asyncio_basics](advanced/asyncio_basics.py) | `async`/`await`, `gather`, timeouts, semaphores, a real local server and client, banner grabbing, and a port check that refuses anything but your own machine |
| [testing_with_pytest](advanced/testing_with_pytest.py) | Virtual environments, `pytest` tests, `raises`, `parametrize`, fixtures, `tmp_path`/`monkeypatch`/`caplog`, mocking with `unittest.mock`, `skipif` and `xfail`: proving security properties with tests |

The pytest lesson needs a package, so set up a virtual environment once:
`python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`, then
`.venv/bin/pytest advanced/testing_with_pytest.py -v`. The other lessons
use only the standard library: `python3 advanced/<lesson>.py`.

### 6. Practical Projects (cybersecurity, in `projects/`)

Small tools, each one runnable file with a lesson, a demo and tests
(`python3 main.py`).

| Project | What it does | What it teaches |
|---|---|---|
| [password_analyzer](projects/password_analyzer/) | Estimates how many guesses a password needs, the way crackers guess, and checks leaks with k-anonymity | Why length beats complexity; wordlists and mangling rules; `getpass`, `hashlib` |
| [file_integrity_checker](projects/file_integrity_checker/) | Fingerprints a folder and reports added, deleted, moved and modified files, with a signed baseline | Hashing in chunks; timestomping; symlinks; HMAC; atomic writes; exit codes |
| [cipher_cracker](projects/cipher_cracker/) | Caesar and Vigenère ciphers, then breaks them with no key using letter frequencies | `ord`/`chr`, `Counter`, chi-squared, Index of Coincidence |
| [hash_cracker](projects/hash_cracker/) | A dictionary attack on hashes you make yourself, then the defences that beat it | Why salts and slow hashes (PBKDF2) matter |
| [attack_paths](projects/attack_paths/) | Which machines an attacker can reach, the shortest path to the database, and the best link to cut | Graphs, BFS, reachability, choke points |
| [web_vulns](projects/web_vulns/) | A deliberately vulnerable mini-app: SQL injection, XSS and path traversal, each exploited then fixed | Parameterised queries, output escaping, path containment; why data must stay data |
| [totp_generator](projects/totp_generator/) | The six-digit 2FA codes in Google Authenticator, built from scratch and checked against the RFC test values | HMAC, base32, `struct`; clock drift, replays, rate limits; why passkeys beat TOTP against phishing |
| [jwt_tampering](projects/jwt_tampering/) | Login tokens (JWTs) signed from scratch, then forged five ways against a vulnerable checker, and stopped by a safe one | base64url, HMAC; `alg: none`, weak keys, algorithm confusion, expiry; why the server must choose the algorithm |
| [secrets_scanner](projects/secrets_scanner/) | Finds API keys and hardcoded passwords in files and in git history, like a small gitleaks | Regex rules, Shannon entropy, false positives, redaction, `subprocess` + `git log`; revoke before you delete |

Bigger projects built from these lessons live in their own repos:
[log-detection-engine](https://github.com/rrahulvenkat/log-detection-engine)
and an SSH brute-force detection series, starting with
[ssh-log-analyzer](https://github.com/rrahulvenkat/ssh-log-analyzer).

## Repository Structure

- `fundamentals/` — Python basics
- `data_structures/` — Python data structures
- `oop/` — Object-oriented programming
- `advanced/` — Advanced Python: decorators, context managers, concurrency, asyncio, pytest
- `problem_solving/` — Coding challenges
- `projects/` — Small cybersecurity tools (see above)
- `notes/` — Learning notes and reflections
- [`mistakes_and_lessons.md`](mistakes_and_lessons.md) — real mistakes from
  building these, and what each one taught

## Progress

I'm learning by building, experimenting, solving problems, and documenting
what I learn.

---

**Always learning. Always building.**
