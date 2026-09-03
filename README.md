# AuthGuard — Authentication Log Analyzer

A lightweight, transparent Python tool for parsing OpenSSH authentication logs and detecting suspicious login activity. Built for the Software Development Club, Session 2026–27 — Cybersecurity Intermediate Option C.

---

## Overview & Problem Statement

Authentication logs contain vital security event data. However, raw syslog files are large, unstructured, and noisy, making manual inspection impractical. Attackers often attempt brute-force password guessing, username enumeration, or unauthorized access from new IP addresses or unusual hours.

**AuthGuard** parses raw OpenSSH authentication logs (`sshd`), normalizes events into structured records, applies four rule-based security detectors, and generates a clear, prioritized terminal report with security explanations and recommended mitigations.

---

## Features — Four Core Detection Rules

AuthGuard implements four transparent, rule-based security detectors:

1. **Repeated Failed Logins (Brute-Force Detection)**
   * **How it works:** Tracks failed login attempts per `(user, ip)` pair using a hash dictionary.
   * **Default Threshold:** `5` failures (configurable).
   * **Severity:** `HIGH`
   * **Security Focus:** Detects automated password guessing attacks.

2. **Unusual Login Times (Off-Hours Activity)**
   * **How it works:** Parses timestamps and flags logins occurring outside normal hours.
   * **Default Window:** `06:00` to `22:00` (6:00 AM – 10:00 PM, configurable).
   * **Severity:** `MEDIUM`
   * **Security Focus:** Highlights off-hours access attempts (suspicious signal, not standalone proof).

3. **New / Unseen IP Logins (Account Compromise Signal)**
   * **How it works:** Maintains a chronological per-user baseline of known IP addresses established **strictly from successful logins**. Flags any successful login from a previously unseen IP for that user.
   * **Baseline Strategy:** Failed attempts do not pollute the baseline. A user's very first successful login establishes their initial known IP.
   * **Severity:** `MEDIUM`
   * **Security Focus:** Identifies potential credential theft or session hijacking.

4. **Username Enumeration (Account Probing Detection)**
   * **How it works:** Tracks the number of distinct failed usernames attempted by a single source IP using `defaultdict(set)`.
   * **Default Threshold:** `3` distinct usernames (configurable).
   * **Severity:** `HIGH`
   * **Security Focus:** Detects attackers probing for valid usernames on the system.

---

## Project Structure

```
MDJahiruddinAhmed_25BAI11468/
├── data/
│   └── auth_sample.log      # Official OpenSSH sample authentication log
├── src/
│   ├── __init__.py
│   ├── parser.py            # OpenSSH syslog regex parser & timestamp normalizer
│   ├── detector.py          # Four security detection rule functions
│   ├── reporter.py          # Terminal report formatter & severity sorter
│   └── main.py              # CLI entry point & execution pipeline
├── tests/
│   ├── __init__.py
│   ├── test_parser.py       # Unit tests for log parser
│   ├── test_detector.py     # Unit tests for 4 detection rules
│   ├── test_reporter.py     # Unit tests for report formatting
│   └── test_main.py         # Integration tests for CLI pipeline
├── .gitignore
├── requirements.txt         # Empty — built using Python 3 standard library only
├── README.md                # Project documentation
└── REPORT.md                # Technical write-up & analysis report
```

---

## How the Log Parser Works

OpenSSH syslog lines omit the year (e.g., `Aug 20 06:00:06 notevault-srv sshd[8397]: Failed password for admin from 185.220.101.47 port 33965 ssh2`).

The parser (`src/parser.py`):
1. Matches OpenSSH syslog events using regular expressions (`re`).
2. Recognizes three primary event types:
   * `Accepted password` ➔ Status `"SUCCESS"`
   * `Failed password` ➔ Status `"FAILED"`
   * `Invalid user` ➔ Status `"FAILED"`
3. Accepts an explicit `default_year=2026` parameter to construct normalized ISO-style timestamps (`%Y-%m-%d %H:%M:%S`).
4. Ignores non-authentication syslog lines safely.

---

## Installation & Requirements

AuthGuard uses **only standard Python built-in modules** (`re`, `datetime`, `collections`, `sys`, `os`, `unittest`). No external packages or `pip install` required.

* **Python Version:** Python 3.8+

---

## Usage

Run the analysis pipeline against an authentication log file:

```bash
python3 src/main.py data/auth_sample.log
```

---

## Running Unit Tests

Run the full automated test suite (38 tests):

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

**Current Test Status:** `38 tests passing cleanly (0 failures, 0 errors)`.

---

## Important Findings from `data/auth_sample.log`

When evaluated against the official sample dataset, AuthGuard identified **40 total alerts**:

* **HIGH Severity Attacks (3 Events):**
  1. **Brute-Force Attack:** IP `185.220.101.47` performed **85 failed password attempts between 06:00:06 and 06:05:31, followed by an accepted password at 06:05:35.**
  2. **Username Enumeration:** IP `185.220.101.47` probed **4 distinct usernames** (`admin`, `deploy`, `git`, `jenkins`).
  3. **Username Enumeration:** IP `45.135.232.19` probed **10 distinct usernames** (`root`, `administrator`, `test`, `ubuntu`, `oracle`, `postgres`, `backup`, `admin2`, `info`, `support`).

* **MEDIUM Severity Signals (37 Events):**
  * Off-hours logins between `00:00` and `06:00` and IP transitions across internal subnets (`10.0.0.x`).

---

## Real-World Security Mitigations

1. **Rate Limiting:** Throttle repeated login requests per IP address to slow down automated brute-force attacks.
2. **Account Lockout:** Temporarily lock accounts after N consecutive failed attempts (e.g., 5 failures).
3. **Generic Error Messages:** Ensure login interfaces return uniform messages (e.g., `"Invalid credentials"`) to prevent username enumeration.
4. **Alerting & MFA on New IPs:** Trigger multi-factor authentication (MFA) or notify users when a login occurs from an unverified IP.

---

## Limitations & False Positives

* **Syslog Year Omission:** Syslog files do not store year values; the parser relies on an explicit `default_year` parameter (default `2026`).
* **DHCP / Mobile Network Flapping:** Internal IP changes or dynamic IP allocation can cause legitimate user logins to trigger `New IP Login` alerts.
* **NAT / Proxy Aggregation:** Multiple legitimate users behind a NAT gateway or corporate proxy share a single IP, which can mimic username enumeration.
* **Shift Work / Time Zones:** Users working night shifts or across time zones may trigger `Unusual Login Time` alerts.
