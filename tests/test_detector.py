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
from src.detector import detect_new_ip_login
from src.detector import detect_username_enumeration


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


class TestNewIPLogin(unittest.TestCase):
    """Tests for the new/unseen IP detection rule."""

    def test_first_login_not_flagged(self):
        """A user's very first login should NOT be flagged (no baseline)."""
        entries = [
            {"timestamp": "2026-09-01 09:00:00", "user": "alice",
             "ip": "192.168.1.10", "status": "SUCCESS"},
        ]
        alerts = detect_new_ip_login(entries)
        self.assertEqual(len(alerts), 0)

    def test_second_ip_flagged(self):
        """A second, different IP for the same user should be flagged."""
        entries = [
            {"timestamp": "2026-09-01 09:00:00", "user": "alice",
             "ip": "192.168.1.10", "status": "SUCCESS"},
            {"timestamp": "2026-09-01 14:00:00", "user": "alice",
             "ip": "10.0.0.99", "status": "SUCCESS"},
        ]
        alerts = detect_new_ip_login(entries)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["user"], "alice")
        self.assertEqual(alerts[0]["ip"], "10.0.0.99")
        self.assertEqual(alerts[0]["severity"], "MEDIUM")
        self.assertIn("192.168.1.10", alerts[0]["details"]["known_ips"])

    def test_same_ip_repeated_no_flag(self):
        """Repeated logins from the same known IP should not be flagged."""
        entries = [
            {"timestamp": "2026-09-01 09:00:00", "user": "bob",
             "ip": "192.168.1.11", "status": "SUCCESS"},
            {"timestamp": "2026-09-01 10:00:00", "user": "bob",
             "ip": "192.168.1.11", "status": "SUCCESS"},
            {"timestamp": "2026-09-01 11:00:00", "user": "bob",
             "ip": "192.168.1.11", "status": "SUCCESS"},
        ]
        alerts = detect_new_ip_login(entries)
        self.assertEqual(len(alerts), 0)

    def test_multiple_new_ips_each_flagged_once(self):
        """Each new IP for a user should be flagged exactly once."""
        entries = [
            {"timestamp": "2026-09-01 09:00:00", "user": "alice",
             "ip": "192.168.1.10", "status": "SUCCESS"},
            {"timestamp": "2026-09-01 14:00:00", "user": "alice",
             "ip": "10.0.0.5", "status": "SUCCESS"},
            {"timestamp": "2026-09-01 15:00:00", "user": "alice",
             "ip": "10.0.0.5", "status": "SUCCESS"},  # same as above, no flag
            {"timestamp": "2026-09-01 18:00:00", "user": "alice",
             "ip": "172.16.0.1", "status": "SUCCESS"},
        ]
        alerts = detect_new_ip_login(entries)
        # Two new IPs flagged: 10.0.0.5 and 172.16.0.1
        self.assertEqual(len(alerts), 2)

    def test_different_users_tracked_separately(self):
        """IPs are tracked per user — alice's IP is not bob's baseline."""
        entries = [
            {"timestamp": "2026-09-01 09:00:00", "user": "alice",
             "ip": "192.168.1.10", "status": "SUCCESS"},
            {"timestamp": "2026-09-01 09:05:00", "user": "bob",
             "ip": "192.168.1.20", "status": "SUCCESS"},
            {"timestamp": "2026-09-01 10:00:00", "user": "bob",
             "ip": "192.168.1.10", "status": "SUCCESS"},  # new for bob
        ]
        alerts = detect_new_ip_login(entries)
        # Only bob's second IP is flagged (alice's first login is not)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["user"], "bob")

    def test_new_ip_added_to_known_set(self):
        """After being flagged, a new IP becomes known and is not re-flagged."""
        entries = [
            {"timestamp": "2026-09-01 09:00:00", "user": "carol",
             "ip": "192.168.1.30", "status": "SUCCESS"},
            {"timestamp": "2026-09-01 14:00:00", "user": "carol",
             "ip": "10.0.0.7", "status": "SUCCESS"},  # flagged
            {"timestamp": "2026-09-01 15:00:00", "user": "carol",
             "ip": "10.0.0.7", "status": "SUCCESS"},  # NOT flagged again
        ]
        alerts = detect_new_ip_login(entries)
        self.assertEqual(len(alerts), 1)  # only one alert, not two

    def test_failed_logins_do_not_pollute_baseline(self):
        """Failed attempts from a new IP must NOT establish that IP as known baseline."""
        entries = [
            # Alice's initial baseline established from 192.168.1.10
            {"timestamp": "t1", "user": "alice", "ip": "192.168.1.10", "status": "SUCCESS"},
            # Attacker fails attempts from 10.0.0.99
            {"timestamp": "t2", "user": "alice", "ip": "10.0.0.99", "status": "FAILED"},
            {"timestamp": "t3", "user": "alice", "ip": "10.0.0.99", "status": "FAILED"},
            # Attacker succeeds from 10.0.0.99 -> Should trigger alert because 10.0.0.99 was not in SUCCESS baseline
            {"timestamp": "t4", "user": "alice", "ip": "10.0.0.99", "status": "SUCCESS"},
        ]
        alerts = detect_new_ip_login(entries)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["user"], "alice")
        self.assertEqual(alerts[0]["ip"], "10.0.0.99")
        self.assertIn("192.168.1.10", alerts[0]["details"]["known_ips"])

    def test_empty_input(self):
        """An empty log should produce zero alerts."""
        alerts = detect_new_ip_login([])
        self.assertEqual(len(alerts), 0)


class TestUsernameEnumeration(unittest.TestCase):
    """Tests for the username enumeration detection rule."""

    def test_single_user_multiple_failures_ignored(self):
        """Failures for the SAME user should not trigger enumeration (that's brute force)."""
        entries = [
            {"timestamp": "t1", "user": "admin", "ip": "10.0.0.5", "status": "FAILED"},
            {"timestamp": "t2", "user": "admin", "ip": "10.0.0.5", "status": "FAILED"},
            {"timestamp": "t3", "user": "admin", "ip": "10.0.0.5", "status": "FAILED"},
            {"timestamp": "t4", "user": "admin", "ip": "10.0.0.5", "status": "FAILED"},
        ]
        # Only 1 distinct username tried, well below default threshold of 3.
        alerts = detect_username_enumeration(entries)
        self.assertEqual(len(alerts), 0)

    def test_multiple_users_above_threshold(self):
        """An IP trying 3 or more distinct usernames (and failing) should be flagged."""
        entries = [
            {"timestamp": "t1", "user": "admin", "ip": "10.0.0.5", "status": "FAILED"},
            {"timestamp": "t2", "user": "root", "ip": "10.0.0.5", "status": "FAILED"},
            {"timestamp": "t3", "user": "test", "ip": "10.0.0.5", "status": "FAILED"},
            {"timestamp": "t4", "user": "user1", "ip": "10.0.0.5", "status": "FAILED"},
        ]
        alerts = detect_username_enumeration(entries, threshold=3)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["ip"], "10.0.0.5")
        self.assertEqual(alerts[0]["details"]["distinct_usernames_tried"], 4)
        self.assertEqual(alerts[0]["severity"], "HIGH")

    def test_successful_logins_ignored(self):
        """Successful logins should not count towards enumeration threshold."""
        entries = [
            {"timestamp": "t1", "user": "alice", "ip": "192.168.1.100", "status": "SUCCESS"},
            {"timestamp": "t2", "user": "bob", "ip": "192.168.1.100", "status": "SUCCESS"},
            {"timestamp": "t3", "user": "carol", "ip": "192.168.1.100", "status": "SUCCESS"},
        ]
        alerts = detect_username_enumeration(entries, threshold=3)
        self.assertEqual(len(alerts), 0)

    def test_different_ips_counted_separately(self):
        """Distinct usernames are counted per IP."""
        entries = [
            {"timestamp": "t1", "user": "user1", "ip": "10.0.0.1", "status": "FAILED"},
            {"timestamp": "t2", "user": "user2", "ip": "10.0.0.1", "status": "FAILED"},
            {"timestamp": "t3", "user": "user3", "ip": "10.0.0.2", "status": "FAILED"},
            {"timestamp": "t4", "user": "user4", "ip": "10.0.0.2", "status": "FAILED"},
        ]
        # IP 10.0.0.1 tried 2 users. IP 10.0.0.2 tried 2 users.
        # Threshold is 3. Neither should trigger.
        alerts = detect_username_enumeration(entries, threshold=3)
        self.assertEqual(len(alerts), 0)

    def test_custom_threshold(self):
        """A custom threshold should be respected."""
        entries = [
            {"timestamp": "t1", "user": "admin", "ip": "10.0.0.9", "status": "FAILED"},
            {"timestamp": "t2", "user": "guest", "ip": "10.0.0.9", "status": "FAILED"},
        ]
        # Threshold of 2 should flag this.
        alerts = detect_username_enumeration(entries, threshold=2)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["details"]["distinct_usernames_tried"], 2)

    def test_empty_input(self):
        """An empty log should produce zero alerts."""
        alerts = detect_username_enumeration([])
        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()
