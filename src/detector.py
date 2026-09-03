"""
detector.py — Detection rules for suspicious authentication activity.

Each detection function takes a list of log entry dictionaries and returns
a list of alert dictionaries.  The expected format for each log entry is:

    {
        "timestamp": str,   # normalized to "%Y-%m-%d %H:%M:%S"
        "user": str,        # username
        "ip": str,          # source IP address
        "status": str,      # "SUCCESS" or "FAILED"
    }

The parser (parser.py) is responsible for converting raw log lines into
this format and normalizing timestamps to the standard format above.
Detection functions never touch the raw log directly.
"""

from collections import defaultdict
from datetime import datetime

# The parser must produce timestamps in this format.
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


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


def detect_unusual_login_times(entries, normal_start_hour=6,
                               normal_end_hour=22):
    """Detect logins that occur outside normal working hours.

    Logins at unusual times (e.g. 3 AM) can indicate unauthorized access,
    but they can also be legitimate (night shifts, different time zones).
    This is a suspicious *signal*, not proof of an attack.

    Args:
        entries: list of log entry dicts (must contain 'timestamp', 'user',
                 'ip').
        normal_start_hour: start of normal window, inclusive (0-23).
                           Default is 6 (6:00 AM).
        normal_end_hour:   end of normal window, exclusive (0-23).
                           Default is 22 (10:00 PM).
                           Logins at hour 22 or later are flagged.

    Returns:
        list of alert dicts, one per off-hours login.
    """
    alerts = []

    for entry in entries:
        # Parse the normalized timestamp string into a datetime object.
        dt = datetime.strptime(entry["timestamp"], TIMESTAMP_FORMAT)
        hour = dt.hour  # integer 0-23

        # Check if the hour falls outside the normal window.
        if hour < normal_start_hour or hour >= normal_end_hour:
            alerts.append({
                "type": "Unusual Login Time",
                "severity": "MEDIUM",
                "user": entry["user"],
                "ip": entry["ip"],
                "details": {
                    "timestamp": entry["timestamp"],
                    "hour": hour,
                    "normal_window": f"{normal_start_hour}:00–{normal_end_hour}:00",
                },
                "explanation": (
                    f"User '{entry['user']}' logged in at hour {hour}:00, "
                    f"which is outside the normal window "
                    f"({normal_start_hour}:00–{normal_end_hour}:00).  "
                    f"Off-hours activity can indicate unauthorized access, "
                    f"but may also be legitimate."
                ),
                "mitigation": (
                    "Flag for review by the security team.  Combine with "
                    "other signals (e.g. new IP + unusual time) for "
                    "stronger evidence.  Do not block automatically."
                ),
            })

    return alerts
