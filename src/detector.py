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


def detect_new_ip_login(entries):
    """Detect logins from IP addresses not previously seen for a user.

    If a user has logged in before from known IP addresses and then a login
    appears from a new IP, it could indicate account compromise.  However,
    it can also be legitimate (travelling, VPN, new device).

    The function processes entries in chronological order and builds a
    running set of known IPs for each user.  A user's very first login is
    never flagged because there is no baseline to compare against.

    Args:
        entries: list of log entry dicts (must contain 'user', 'ip').
                 Entries must be in chronological order.

    Returns:
        list of alert dicts, one per new-IP login.
    """
    alerts = []

    # Track which IPs we have seen for each user so far.
    # defaultdict(set) gives every new user an empty set automatically.
    user_known_ips = defaultdict(set)

    for entry in entries:
        user = entry["user"]
        ip = entry["ip"]

        if len(user_known_ips[user]) > 0 and ip not in user_known_ips[user]:
            # This user has logged in before, but never from this IP.
            alerts.append({
                "type": "New IP Login",
                "severity": "MEDIUM",
                "user": user,
                "ip": ip,
                "details": {
                    "timestamp": entry["timestamp"],
                    "new_ip": ip,
                    "known_ips": sorted(user_known_ips[user]),
                },
                "explanation": (
                    f"User '{user}' logged in from {ip}, which has not "
                    f"been previously associated with this account.  "
                    f"Known IPs: {sorted(user_known_ips[user])}.  "
                    f"A new source IP can indicate account compromise."
                ),
                "mitigation": (
                    "Alert the user or security team.  Require additional "
                    "verification (e.g. multi-factor authentication).  "
                    "Do not block automatically — the user may be "
                    "travelling or using a new device."
                ),
            })

        # Always add the IP to the known set (whether or not we flagged it).
        # This prevents repeated alerts for the same new IP.
        user_known_ips[user].add(ip)

    return alerts


def detect_username_enumeration(entries, threshold=3):
    """Detect IPs attempting to authenticate with many different usernames.

    If a single IP address tries to log in using multiple distinct usernames
    and fails, it suggests an attacker is probing the system to see which
    accounts exist (username enumeration).

    Args:
        entries: list of log entry dicts (must contain 'user', 'ip', 'status').
        threshold: minimum number of distinct failed usernames from a single
                   IP to trigger an alert. Default is 3.

    Returns:
        list of alert dicts, one per flagged IP.
    """
    alerts = []

    # Track distinct failed usernames per IP.
    ip_failed_users = defaultdict(set)

    for entry in entries:
        if entry["status"] == "FAILED":
            ip_failed_users[entry["ip"]].add(entry["user"])

    for ip, users in ip_failed_users.items():
        if len(users) >= threshold:
            alerts.append({
                "type": "Username Enumeration",
                "severity": "HIGH",
                "user": "MULTIPLE",  # Not tied to a single user
                "ip": ip,
                "details": {
                    "distinct_usernames_tried": len(users),
                    "usernames": sorted(users),
                    "threshold": threshold,
                },
                "explanation": (
                    f"IP {ip} attempted to log in with {len(users)} different "
                    f"usernames. A single source probing multiple accounts "
                    f"suggests username enumeration."
                ),
                "mitigation": (
                    "Rate limit login attempts per IP. Ensure login error "
                    "messages are generic (e.g., 'Invalid credentials') so "
                    "attackers cannot distinguish between invalid usernames "
                    "and invalid passwords. Note: False positives can occur "
                    "from NAT gateways, proxies, or shared computers."
                ),
            })

    return alerts
