"""
parser.py — Parser for OpenSSH authentication log files.

Converts raw OpenSSH syslog lines into normalized dictionaries expected by
detector.py:

    {
        "timestamp": str,  # normalized to "%Y-%m-%d %H:%M:%S"
        "user": str,       # username
        "ip": str,         # source IP address
        "status": str,     # "SUCCESS" or "FAILED"
    }

Note on Year Assumption:
Standard syslog entries (e.g. "Aug 20 00:12:00") do not include the year.
The parser accepts an explicit `default_year` parameter (default: 2026) to
construct complete timestamps rather than relying implicitly on system time.
"""

import re
from datetime import datetime

# Month string to number lookup dictionary
MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

# Regex to match syslog header: Month Day HH:MM:SS Hostname sshd[PID]:
HEADER_REGEX = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+(?P<message>.+)$"
)

# Regex patterns for authentication events
ACCEPTED_PWD_REGEX = re.compile(r"^Accepted password for (?P<user>\S+) from (?P<ip>\S+)")
FAILED_PWD_REGEX = re.compile(r"^Failed password for (?P<user>\S+) from (?P<ip>\S+)")
INVALID_USER_REGEX = re.compile(r"^Invalid user (?P<user>\S+) from (?P<ip>\S+)")


def parse_log_line(line, default_year=2026):
    """Parse a single SSH log line into a normalized dict.

    Args:
        line: str, raw log line.
        default_year: int, year to supply since syslog timestamps omit year.

    Returns:
        dict if the line is a recognized authentication event, else None.
    """
    line = line.strip()
    if not line:
        return None

    header_match = HEADER_REGEX.match(line)
    if not header_match:
        return None

    month_str = header_match.group("month")
    day = int(header_match.group("day"))
    time_str = header_match.group("time")
    message = header_match.group("message")

    month = MONTHS.get(month_str)
    if not month:
        return None

    # Parse time components (HH:MM:SS)
    hour, minute, second = map(int, time_str.split(":"))
    dt = datetime(default_year, month, day, hour, minute, second)
    normalized_timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")

    # Match authentication message patterns
    accepted_match = ACCEPTED_PWD_REGEX.match(message)
    if accepted_match:
        return {
            "timestamp": normalized_timestamp,
            "user": accepted_match.group("user"),
            "ip": accepted_match.group("ip"),
            "status": "SUCCESS",
        }

    failed_match = FAILED_PWD_REGEX.match(message)
    if failed_match:
        return {
            "timestamp": normalized_timestamp,
            "user": failed_match.group("user"),
            "ip": failed_match.group("ip"),
            "status": "FAILED",
        }

    invalid_match = INVALID_USER_REGEX.match(message)
    if invalid_match:
        return {
            "timestamp": normalized_timestamp,
            "user": invalid_match.group("user"),
            "ip": invalid_match.group("ip"),
            "status": "FAILED",
        }

    # Line matched sshd header but was not an authentication event we care about
    return None


def parse_log_file(file_path, default_year=2026):
    """Parse an authentication log file and return a list of entry dicts.

    Args:
        file_path: str, path to log file.
        default_year: int, year to supply for syslog timestamps.

    Returns:
        list of normalized log entry dicts.
    """
    entries = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            entry = parse_log_line(line, default_year=default_year)
            if entry:
                entries.append(entry)
    return entries
