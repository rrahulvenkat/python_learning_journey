# detection_engine

A small detection engine in plain Python (no dependencies). It reads
SSH, web server, Windows and AWS CloudTrail logs, turns every line into
one shared event format, runs independent detection rules over all of
them together, and links the alerts into incidents labelled with MITRE
ATT&CK techniques.

```
log files ──> parsers ──> LogEvents ──> rules ──> alerts ──> correlation ──> incidents
              (format     (one shared   (each rule            (by shared user/IP,
               detected)   format)       is a class)            time gaps, sequences)
```

## What it detects

| Log | Parser | Detections |
|---|---|---|
| SSH (syslog `auth.log`) | `SyslogSSHParser` | brute force, login after brute force, login from a new IP |
| Web access logs (Apache/Nginx "combined") | `WebAccessParser` | SQL injection, path traversal, XSS, command injection, Log4Shell, Shellshock, sensitive files (rated by the response status), scanner tools, wordlist scanning, login-form brute force |
| Windows event XML (`wevtutil`) | `WindowsEventParser` | RDP brute force, cleared logs, new admins, suspicious services, encoded PowerShell |
| AWS CloudTrail (JSON lines) | `CloudTrailParser` | console login without MFA, sensitive actions (new keys, policies, logging turned off) |
| any | | unusual login volume and unusual hours, against each user's own baseline |

The rules don't care where an event came from: the same `BruteForceRule`
catches SSH, RDP, cloud console and website password guessing.

## Running it

```bash
pip install -e .                                    # from this folder
detection-engine access.log --trust-proxy 10.0.0.2  # or: python -m detection_engine ...
detection-engine auth.log security.xml --year 2026 --alerts
python -m detection_engine.web                      # the web demo: an attack on a shop
python -m detection_engine.windows                  # the Windows demo: an RDP intrusion
pytest                                              # or: python tests/test_engine.py
```

Each file's format is detected on its own, then events from every file go
through the rules together, so one attacker seen in two logs becomes one
incident. Exit codes: `0` nothing HIGH or above, `1` a HIGH or CRITICAL
incident, `2` an error.

`--trust-proxy` names your load balancers. Without it, `X-Forwarded-For`
is ignored, because from the internet it's a header anyone can type.

## Layout

| Module | What's in it |
|---|---|
| `events.py` | `LogEvent`, the shared format |
| `parsers.py` | `LogParser` (the shared parsing steps), SSH and CloudTrail parsers, `detect_parser()` |
| `rules.py` | `Rule`, `Alert`, `Severity`, `Timeline`, `DetectionEngine`, the core rules |
| `stats.py` | robust z-scores (median and MAD) for baselines |
| `baselines.py` | rules that learn what's normal per user |
| `correlation.py` | linking alerts (union-find), splitting by time gaps, risk scores, ATT&CK labels, sequences |
| `windows.py`, `web.py` | a parser and rules for each, with a demo and tests |
| `__main__.py` | the command line |

## Where it came from

The design is taught step by step in this repo's lessons:
[oop/](../../oop/) (classes, inheritance, polymorphism) and
[fundamentals/statistics_and_baselines.py](../../fundamentals/statistics_and_baselines.py).
`events.py`, `parsers.py`, `rules.py` and `stats.py` started as **copies**
of the parts the engine needs, so the engine runs on its own and editing
a lesson can't break it. The copies are the engine's now: fix bugs here,
and expect the lessons and the engine to differ over time.

## Limits

- Every file is read into memory; it isn't built for gigabytes of logs.
- Access logs don't record POST bodies or most headers, so attacks sent
  there are invisible (see section 8 of `web.py`).
- Signatures catch the bulk of automated attacks, not a patient attacker.
- The demos use made-up logs (documentation and private IP ranges only).
  The rules haven't been measured against real traffic yet.
