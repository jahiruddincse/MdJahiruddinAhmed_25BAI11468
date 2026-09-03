"""
detector.py — Detection rules for suspicious authentication activity.

Each detection function takes a list of log entry dictionaries and returns
a list of alert dictionaries.  The expected format for each log entry is:

    {
        "timestamp": str,   # raw timestamp from the log
        "user": str,        # username
        "ip": str,          # source IP address
        "status": str,      # "SUCCESS" or "FAILED"
    }

The parser (parser.py) is responsible for converting raw log lines into
this format.  Detection functions never touch the raw log directly.
"""

from collections import defaultdict


def detect_repeated_failed_logins(entries, threshold=5):
    """Detect IP/user pairs with repeated failed login attempts.

    A high number of failed logins from the same IP targeting the same user
    can indicate a brute-force password-guessing attack.

    Args:
        entries: list of log entry dicts (must contain 'user', 'ip', 'status').
        threshold: minimum number of failures to trigger an alert.
                   Default is 5.  This value should be reviewed once the
                   actual log data is available.

    Returns:
        list of alert dicts, one per flagged (user, ip) pair.
    """
    alerts = []

    # Step 1: Count failures per (user, ip) pair.
    # defaultdict(int) starts every new key at 0 automatically.
    failed_counts = defaultdict(int)

    for entry in entries:
        if entry["status"] == "FAILED":
            key = (entry["user"], entry["ip"])
            failed_counts[key] += 1

    # Step 2: Flag pairs that exceed the threshold.
    for (user, ip), count in failed_counts.items():
        if count >= threshold:
            alerts.append({
                "type": "Repeated Failed Login",
                "severity": "HIGH",
                "user": user,
                "ip": ip,
                "details": {
                    "failed_attempts": count,
                    "threshold": threshold,
                },
                "explanation": (
                    f"{count} failed login attempts from {ip} for user "
                    f"'{user}'.  Multiple failures from the same source "
                    f"may indicate a brute-force attack."
                ),
                "mitigation": (
                    "Rate limiting: slow down repeated attempts.  "
                    "Account lockout: temporarily lock the account after "
                    "too many failures.  Alert the security team for "
                    "investigation."
                ),
            })

    return alerts
