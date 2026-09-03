"""
main.py — AuthGuard CLI entry point.

Executes the complete log analysis pipeline:
    Log File -> Parser -> Detection Rules -> Reporter -> Terminal Output

Usage:
    python3 src/main.py <path_to_auth.log>
"""

import sys
import os

# Add project root directory to path for imports when run directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.parser import parse_log_file
from src.detector import (
    detect_repeated_failed_logins,
    detect_unusual_login_times,
    detect_new_ip_login,
    detect_username_enumeration,
)
from src.reporter import generate_report


def analyze_log_file(file_path, default_year=2026):
    """Run the complete AuthGuard detection pipeline on a log file.

    Args:
        file_path: str, path to the authentication log file.
        default_year: int, year to supply for syslog entries (default 2026).

    Returns:
        str, formatted report string produced by reporter module.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Log file not found: '{file_path}'")

    # Step 1: Parse raw log file into normalized entry dictionaries
    entries = parse_log_file(file_path, default_year=default_year)

    # Step 2: Run all four detection rules on normalized entries
    alerts = []
    alerts.extend(detect_repeated_failed_logins(entries))
    alerts.extend(detect_unusual_login_times(entries))
    alerts.extend(detect_new_ip_login(entries))
    alerts.extend(detect_username_enumeration(entries))

    # Step 3: Format and return final security report
    return generate_report(alerts)


def main():
    """CLI entry point for AuthGuard."""
    if len(sys.argv) < 2:
        print("AuthGuard - Authentication Log Analyzer")
        print("Usage: python3 src/main.py <path_to_auth.log>")
        sys.exit(1)

    log_path = sys.argv[1]

    try:
        report = analyze_log_file(log_path)
        print(report)
    except FileNotFoundError as err:
        print(f"Error: {err}")
        sys.exit(1)
    except Exception as err:
        print(f"Error: An unexpected failure occurred: {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()
