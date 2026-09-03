# AuthGuard — Technical Analysis & Security Report

**Author:** MD JAHIRUDDIN AHMED  
**Registration Number:** 25BAI11468  
**Club:** Software Development Club, Session 2026–27  
**Track:** Cybersecurity — Intermediate Option C: Log Analysis Tool  
**Repository:** `MDJahiruddinAhmed_25BAI11468`  

---

## 1. Introduction

Authentication logs record every connection attempt made to an organization's servers. In Unix/Linux environments running OpenSSH (`sshd`), these events are captured by the system logging daemon (`syslog`). 

Security Analysts and Incident Responders monitor authentication logs to identify unauthorized access attempts, system probing, and compromised user credentials. However, due to high log volumes, automated log analysis tools are essential for extracting actionable security intelligence.

---

## 2. Objective

The objective of this project is to develop a transparent, rule-based log analysis tool (**AuthGuard**) in Python that:
1. Parses standard OpenSSH authentication logs into structured data records.
2. Detects four critical suspicious authentication patterns:
   * Repeated failed logins from a single source (brute-force attacks).
   * Unusual login times (off-hours authentication).
   * Logins from IP addresses never previously seen for a given user.
   * Patterns indicating username enumeration (account probing).
3. Produces a prioritized terminal report detailing **what** was flagged, **why** it is suspicious, and **what mitigations** should be applied.
4. Operates cleanly without external dependencies using standard Python primitives.

---

## 3. Architecture & Modular Approach

AuthGuard follows a clean, decoupled 4-tier pipeline architecture:

```
[ Raw OpenSSH Log File ]
          │
          ▼
   ┌──────────────┐
   │  parser.py   │  <-- Regex Extraction & Timestamp Normalization
   └──────────────┘
          │ (List of Normalized Dictionaries)
          ▼
   ┌──────────────┐
   │ detector.py  │  <-- 4 Rule-Based Security Functions
   └──────────────┘
          │ (List of Alert Dictionaries)
          ▼
   ┌──────────────┐
   │ reporter.py  │  <-- Severity Sorting & Terminal Formatting
   └──────────────┘
          │ (Formatted Report String)
          ▼
   ┌──────────────┐
   │   main.py    │  <-- CLI Orchestration & Error Handling
   └──────────────┘
```

### Module Responsibilities

* **`src/parser.py`:** Reads raw syslog lines, matches OpenSSH regex patterns, normalizes timestamps, and produces structured log entry dictionaries:
  `{"timestamp": str, "user": str, "ip": str, "status": str}`
* **`src/detector.py`:** Evaluates the normalized entry list against 4 distinct security detection rules and returns structured alert dictionaries containing severity, evidence, explanation, and mitigation guidance.
* **`src/reporter.py`:** Sorts alert dictionaries by severity (`HIGH` ➔ `MEDIUM` ➔ `LOW`), formats evidence key-value pairs, and generates a terminal report.
* **`src/main.py`:** Accepts command-line arguments, validates file existence, executes the pipeline, and prints the report to `stdout`.

---

## 4. Log Parsing & Normalization

OpenSSH syslog records follow standard formats. The parser recognizes three key authentication patterns:

1. **Successful Password Logins:**
   `Aug 20 00:12:00 notevault-srv sshd[5506]: Accepted password for arjun from 10.0.0.7 port 38024 ssh2`
   ➔ Mapped to `status = "SUCCESS"`
2. **Failed Password Attempts:**
   `Aug 20 06:00:06 notevault-srv sshd[8397]: Failed password for admin from 185.220.101.47 port 33965 ssh2`
   ➔ Mapped to `status = "FAILED"`
3. **Invalid User Attempts:**
   `Aug 20 20:00:11 notevault-srv sshd[9099]: Invalid user git from 185.220.101.47 port 43095`
   ➔ Mapped to `status = "FAILED"` *(Authentication attempts for non-existent users represent failed logins and are mapped to `FAILED` so username enumeration rules track them accurately).*

### Syslog Year Handling

Standard syslog entries omit year data (e.g., `Aug 20 00:12:00`). To prevent non-deterministic behavior dependent on host system clock time, `parse_log_file()` accepts an explicit `default_year=2026` parameter to normalize all timestamps into standard `%Y-%m-%d %H:%M:%S` format (`2026-08-20 00:12:00`).

---

## 5. Detection Methodology

### 5.1 Repeated Failed Logins (Brute-Force Detection)
* **Logic:** Accumulates failure counts per `(user, ip)` pair using `defaultdict(int)`.
* **Threshold:** Configurable, default `5` failed attempts.
* **Severity:** `HIGH`
* **Security Rationale:** A single password typo is common; 5+ consecutive failures from one source indicates automated password guessing.

### 5.2 Unusual Login Times (Off-Hours Activity)
* **Logic:** Converts normalized timestamp strings into Python `datetime` objects and checks if `dt.hour` falls outside a normal window.
* **Window:** Configurable, default `06:00` to `22:00` (6 AM to 10 PM).
* **Severity:** `MEDIUM`
* **Security Rationale:** Attackers often operate during off-hours when operational monitoring is lower.

### 5.3 New / Unseen IP Logins (Account Compromise Signal)
* **Logic:** Evaluates entries chronologically and builds a `user_known_ips` lookup using `defaultdict(set)` **strictly from successful logins**. Flags any successful login from an IP not in the user's known set.
* **Baseline Integrity:** Failed attempts are excluded from baseline construction so attackers cannot pollute a user's known IP baseline with failed attempts prior to a breach.
* **Severity:** `MEDIUM`
* **Security Rationale:** A sudden login from a new IP address may indicate stolen credentials.

### 5.4 Username Enumeration (Account Probing Detection)
* **Logic:** Accumulates distinct failed usernames attempted by each source IP using `defaultdict(set)`.
* **Threshold:** Configurable, default `3` distinct failed usernames per IP.
* **Severity:** `HIGH`
* **Security Rationale:** Repeated attempts against multiple usernames from one source IP are unusual for normal individual login behavior and can indicate account probing.

---

## 6. Findings & Analysis (`data/auth_sample.log`)

Execution of AuthGuard on the official dataset (`160 parsed log entries`) yielded **40 total alerts**:

```text
============================================================
AUTHGUARD - LOG ANALYSIS REPORT
============================================================

SUMMARY STATISTICS
--------------------
Total Suspicious Events: 40
  HIGH Severity:   3
  MEDIUM Severity: 37
  LOW Severity:    0
```

### 6.1 Explanation of HIGH-Severity Findings

1. **Brute-Force Attack (`185.220.101.47` targeting `admin`):**
   * **Evidence:** 85 failed password attempts between 06:00:06 and 06:05:31, followed by an accepted password at 06:05:35.
   * **Analysis:** High-volume automated brute-force attack followed by a successful authentication, indicating a potential unauthorized account access.
2. **Username Enumeration (`185.220.101.47`):**
   * **Evidence:** Probed 4 distinct usernames (`admin`, `deploy`, `git`, `jenkins`).
   * **Analysis:** Targeted probing of administrative and CI/CD service accounts.
3. **Username Enumeration (`45.135.232.19`):**
   * **Evidence:** Probed 10 distinct usernames (`root`, `administrator`, `test`, `ubuntu`, `oracle`, `postgres`, `backup`, `admin2`, `info`, `support`).
   * **Analysis:** Automated scan for default database and system administration accounts.

### 6.2 Explanation of MEDIUM-Severity Findings

* **Unusual Login Times (19 Events):** Logins between `00:12:00` and `05:58:00` from internal users (`arjun`, `meera`, `dev`, `priya`, `kiran`). Represent night-shift activity or off-hours maintenance.
* **New IP Logins (18 Events):** Internal IP address shifts across `10.0.0.x` subnets as internal users connected from different DHCP allocations.

---

## 7. Recommended Security Mitigations

1. **Rate Limiting:** Implement IP-level rate limiting using system tools (such as `fail2ban` or `iptables`) to throttle repeated login requests. For example, an organization might enforce a policy blocking IPs that exceed 5 failure attempts per minute.
2. **Account Lockout Policies:** Implement server-side account lockout rules to prevent password guessing. For example, an organization could configure PAM/SSH policies to temporarily lock an account for 15 minutes after 5 consecutive failed login attempts.
3. **Generic Error Response:** Configure SSH/Web login responses to return `"Invalid credentials"` to prevent attackers from confirming username existence during enumeration attacks.
4. **Multi-Factor Authentication (MFA):** Require MFA for all remote SSH logins, especially when connections originate from new or unverified IP addresses.

---

## 8. Limitations & False Positives

* **Syslog Year Omission:** Log files lack year metadata; parser requires explicit year configuration (`default_year=2026`).
* **DHCP / Subnet Mobility:** Internal network IP changes produce benign `New IP Login` alerts.
* **NAT / Proxy Aggregation:** Corporate NAT gateways route multiple users through a single public IP, which can trigger false `Username Enumeration` alerts.
* **Shift Work:** Legitimate off-hours work triggers `Unusual Login Time` alerts.

---

## 9. Automated Testing & Verification

AuthGuard includes a comprehensive test suite built with Python's standard `unittest` framework:

* **`test_parser.py`:** Validates regex extraction, timestamp normalization, invalid user handling, and full parsing of `data/auth_sample.log`.
* **`test_detector.py`:** Validates threshold boundaries, baseline pollution prevention, off-hours logic, and enumeration counting across all 4 rules.
* **`test_reporter.py`:** Validates severity sorting, header generation, and summary statistics.
* **`test_main.py`:** Validates CLI argument parsing and error handling for missing files.

**Test Command:**
```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```
**Results:** `38 tests passing cleanly (0 failures, 0 errors)`.

---

## 10. Conclusion

AuthGuard demonstrates how a small, transparent Python application using standard data structures (`dict`, `set`, `list`) can effectively parse raw authentication logs and identify critical cyber threats such as brute-force attacks and username enumeration. The tool prioritizes explainability and practical security mitigations, making it an effective solution for security log analysis.
