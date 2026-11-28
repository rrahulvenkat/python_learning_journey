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

### 5. Practical Projects (cybersecurity, in `projects/`)

Small tools, each one runnable file with a lesson, a demo and tests
(`python3 main.py`).

| Project | What it does | What it teaches |
|---|---|---|
| [password_analyzer](projects/password_analyzer/) | Estimates how many guesses a password needs, the way crackers guess, and checks leaks with k-anonymity | Why length beats complexity; wordlists and mangling rules; `getpass`, `hashlib` |
| [file_integrity_checker](projects/file_integrity_checker/) | Fingerprints a folder and reports added, deleted, moved and modified files, with a signed baseline | Hashing in chunks; timestomping; symlinks; HMAC; atomic writes; exit codes |
| cipher cracker (next) | Caesar and Vigenère ciphers, and breaking them by letter frequency | `ord`/`chr`, `Counter`, brute force |
| hash cracker (planned) | A dictionary attack on hashes you make yourself | Why salts and slow hashes matter |
| attack paths (planned) | Which machines an attacker can reach, and the shortest path to the database | Graphs, BFS |

Bigger projects built from these lessons live in their own repos:
[log-detection-engine](https://github.com/rrahulvenkat/log-detection-engine)
and an SSH brute-force detection series, starting with
[ssh-log-analyzer](https://github.com/rrahulvenkat/ssh-log-analyzer).

## Repository Structure

- `fundamentals/` — Python basics
- `data_structures/` — Python data structures
- `oop/` — Object-oriented programming
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
