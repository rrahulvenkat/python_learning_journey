# Cybersecurity Problem-Solving Plan (for a future, separate project)

Plan made on 2026-11-25. These problems use the usual interview patterns on
security tasks. They belong in their own cybersecurity project, not in
python_learning_journey. Finish the Python problem-solving basics first.

## Beginner: strings and parsing
| Problem | What you build | Pattern it teaches |
|---|---|---|
| Validate IP address (LeetCode 468) | Check whether a string is a valid IPv4 or IPv6 address | String splitting, edge cases |
| Defang IP address (LeetCode 1108) | `1.1.1.1` -> `1[.]1[.]1[.]1`, as used in threat reports | String replacement |
| Unique email addresses (LeetCode 929) | Normalise emails by ignoring `.` and `+tag` | Cleaning input, sets |
| Caesar and Vigenère ciphers, plus cracking | Encrypt, decrypt, then break by trying every shift or counting letter frequency | `ord`/`chr`, brute force, `Counter` |
| Password strength checker (LeetCode 420 is the hard version) | Score passwords against rules | Checking conditions, sets |

## Intermediate: hash maps, sliding windows, sorting
| Problem | What you build | Pattern it teaches |
|---|---|---|
| Brute-force login detector | Flag an IP with 5+ failed logins within 60 seconds | Sliding window, `deque` |
| Logger rate limiter / hit counter (LeetCode 359 / 362) | The basis of rate limiting | Hash map with timestamps |
| Top K IPs or URLs in a log (LeetCode 347) | Find the noisiest traffic sources | `Counter`, heaps |
| Port scan detector | Flag an IP that touches 20+ different ports | Dictionary of sets |
| Merge intervals (LeetCode 56) | Combine overlapping sessions or alert windows | Sorting, interval merging |
| File integrity checker | Hash every file, report which were added, changed or deleted | `hashlib`, set differences |

## Advanced: graphs and search
| Problem | What you build | Pattern it teaches |
|---|---|---|
| Network reachability (LeetCode 547) | Which machines an attacker can reach from a compromised host | BFS/DFS |
| Shortest attack path | Fewest hops from the internet to the database server | BFS shortest path |
| Dictionary attack on a hash | Crack a SHA-256 hash you made yourself using a wordlist | Hashing, fast lookups |
| Wildcard domain blocklist (LeetCode 208, Trie) | Match domains against rules like `*.evil.com` | Tries, prefix matching |

## Practice sites
- OverTheWire Bandit: https://overthewire.org/wargames/bandit/ (start here)
- picoCTF: https://picoctf.org/
- Cryptopals: https://cryptopals.com/
- Advent of Code: https://adventofcode.com/
- TryHackMe: https://tryhackme.com/ and Hack The Box: https://www.hackthebox.com/

## Suggested order
1. IP validator, then Caesar cipher cracking.
2. Brute-force login detector and port scan detector, which lead into the log analyzer project.
3. File integrity checker.
4. Graph problems, once BFS and DFS are covered.

Only run cracking, scanning and attack-path code against data, files and
machines you own, or inside CTF and lab environments.
