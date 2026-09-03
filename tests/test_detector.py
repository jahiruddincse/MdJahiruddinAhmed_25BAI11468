"""
test_detector.py — Tests for detection rules.

These tests use hardcoded sample data (not the actual log file) to verify
that each detection function works correctly on the internal dict format.
"""

import unittest
import sys
import os

# Add the project root to the path so we can import from src/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.detector import detect_repeated_failed_logins


class TestRepeatedFailedLogins(unittest.TestCase):
    """Tests for the repeated-failed-login detection rule."""

    def test_flags_user_above_threshold(self):
        """Five failures from the same (user, ip) should trigger an alert."""
        entries = [
            {"timestamp": "t1", "user": "bob", "ip": "10.0.0.5", "status": "FAILED"},
            {"timestamp": "t2", "user": "bob", "ip": "10.0.0.5", "status": "FAILED"},
            {"timestamp": "t3", "user": "bob", "ip": "10.0.0.5", "status": "FAILED"},
            {"timestamp": "t4", "user": "bob", "ip": "10.0.0.5", "status": "FAILED"},
            {"timestamp": "t5", "user": "bob", "ip": "10.0.0.5", "status": "FAILED"},
        ]
        alerts = detect_repeated_failed_logins(entries, threshold=5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["user"], "bob")
        self.assertEqual(alerts[0]["ip"], "10.0.0.5")
        self.assertEqual(alerts[0]["details"]["failed_attempts"], 5)
        self.assertEqual(alerts[0]["severity"], "HIGH")

    def test_no_alert_below_threshold(self):
        """Two failures should NOT trigger an alert (threshold is 5)."""
        entries = [
            {"timestamp": "t1", "user": "alice", "ip": "192.168.1.10", "status": "FAILED"},
            {"timestamp": "t2", "user": "alice", "ip": "192.168.1.10", "status": "FAILED"},
        ]
        alerts = detect_repeated_failed_logins(entries, threshold=5)
        self.assertEqual(len(alerts), 0)

    def test_successful_logins_ignored(self):
        """SUCCESS entries should not count toward the failure threshold."""
        entries = [
            {"timestamp": "t1", "user": "carol", "ip": "10.0.0.1", "status": "SUCCESS"},
            {"timestamp": "t2", "user": "carol", "ip": "10.0.0.1", "status": "SUCCESS"},
            {"timestamp": "t3", "user": "carol", "ip": "10.0.0.1", "status": "SUCCESS"},
            {"timestamp": "t4", "user": "carol", "ip": "10.0.0.1", "status": "SUCCESS"},
            {"timestamp": "t5", "user": "carol", "ip": "10.0.0.1", "status": "SUCCESS"},
        ]
        alerts = detect_repeated_failed_logins(entries, threshold=5)
        self.assertEqual(len(alerts), 0)

    def test_different_ips_counted_separately(self):
        """Failures from different IPs for the same user are separate counts."""
        entries = [
            {"timestamp": "t1", "user": "dave", "ip": "10.0.0.1", "status": "FAILED"},
            {"timestamp": "t2", "user": "dave", "ip": "10.0.0.1", "status": "FAILED"},
            {"timestamp": "t3", "user": "dave", "ip": "10.0.0.2", "status": "FAILED"},
            {"timestamp": "t4", "user": "dave", "ip": "10.0.0.2", "status": "FAILED"},
        ]
        # Neither IP has 3 failures by itself
        alerts = detect_repeated_failed_logins(entries, threshold=3)
        self.assertEqual(len(alerts), 0)

    def test_empty_input(self):
        """An empty log should produce zero alerts."""
        alerts = detect_repeated_failed_logins([], threshold=5)
        self.assertEqual(len(alerts), 0)

    def test_custom_threshold(self):
        """A lower threshold should flag smaller counts."""
        entries = [
            {"timestamp": "t1", "user": "eve", "ip": "10.0.0.9", "status": "FAILED"},
            {"timestamp": "t2", "user": "eve", "ip": "10.0.0.9", "status": "FAILED"},
            {"timestamp": "t3", "user": "eve", "ip": "10.0.0.9", "status": "FAILED"},
        ]
        alerts = detect_repeated_failed_logins(entries, threshold=3)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["details"]["failed_attempts"], 3)


if __name__ == "__main__":
    unittest.main()
