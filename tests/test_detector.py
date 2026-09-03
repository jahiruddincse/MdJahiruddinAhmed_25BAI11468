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
from src.detector import detect_unusual_login_times


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


class TestUnusualLoginTimes(unittest.TestCase):
    """Tests for the unusual-login-time detection rule."""

    def test_flags_early_morning_login(self):
        """A login at 3 AM should be flagged (outside 6:00–22:00)."""
        entries = [
            {"timestamp": "2026-09-01 03:15:00", "user": "alice",
             "ip": "10.0.0.1", "status": "SUCCESS"},
        ]
        alerts = detect_unusual_login_times(entries)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "MEDIUM")
        self.assertEqual(alerts[0]["details"]["hour"], 3)

    def test_no_alert_during_normal_hours(self):
        """A login at 10 AM should NOT be flagged."""
        entries = [
            {"timestamp": "2026-09-01 10:30:00", "user": "bob",
             "ip": "10.0.0.2", "status": "SUCCESS"},
        ]
        alerts = detect_unusual_login_times(entries)
        self.assertEqual(len(alerts), 0)

    def test_boundary_start_of_normal(self):
        """A login at exactly 6:00 AM is the start of normal — not flagged."""
        entries = [
            {"timestamp": "2026-09-01 06:00:00", "user": "carol",
             "ip": "10.0.0.3", "status": "SUCCESS"},
        ]
        alerts = detect_unusual_login_times(entries)
        self.assertEqual(len(alerts), 0)

    def test_boundary_end_of_normal(self):
        """A login at exactly 22:00 is outside normal — flagged."""
        entries = [
            {"timestamp": "2026-09-01 22:00:00", "user": "dave",
             "ip": "10.0.0.4", "status": "SUCCESS"},
        ]
        alerts = detect_unusual_login_times(entries)
        self.assertEqual(len(alerts), 1)

    def test_just_before_boundary(self):
        """A login at 5:59 AM is before the normal window — flagged."""
        entries = [
            {"timestamp": "2026-09-01 05:59:00", "user": "eve",
             "ip": "10.0.0.5", "status": "FAILED"},
        ]
        alerts = detect_unusual_login_times(entries)
        self.assertEqual(len(alerts), 1)

    def test_custom_window(self):
        """With a custom window of 9–17, a login at 8 AM should be flagged."""
        entries = [
            {"timestamp": "2026-09-01 08:00:00", "user": "frank",
             "ip": "10.0.0.6", "status": "SUCCESS"},
        ]
        alerts = detect_unusual_login_times(entries, normal_start_hour=9,
                                            normal_end_hour=17)
        self.assertEqual(len(alerts), 1)

    def test_empty_input(self):
        """An empty log should produce zero alerts."""
        alerts = detect_unusual_login_times([])
        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()
