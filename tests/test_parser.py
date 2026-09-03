"""
test_parser.py — Tests for the OpenSSH log parser module.
"""

import unittest
import sys
import os

# Add the project root to the path so we can import from src/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.parser import parse_log_line, parse_log_file


class TestLogParser(unittest.TestCase):
    """Tests for parsing SSH log lines and log files."""

    def test_parse_accepted_password(self):
        """Accepted password line should map to SUCCESS."""
        line = "Aug 20 00:12:00 notevault-srv sshd[5506]: Accepted password for arjun from 10.0.0.7 port 38024 ssh2"
        entry = parse_log_line(line, default_year=2026)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["timestamp"], "2026-08-20 00:12:00")
        self.assertEqual(entry["user"], "arjun")
        self.assertEqual(entry["ip"], "10.0.0.7")
        self.assertEqual(entry["status"], "SUCCESS")

    def test_parse_failed_password(self):
        """Failed password line should map to FAILED."""
        line = "Aug 20 06:00:06 notevault-srv sshd[8397]: Failed password for admin from 185.220.101.47 port 33965 ssh2"
        entry = parse_log_line(line, default_year=2026)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["timestamp"], "2026-08-20 06:00:06")
        self.assertEqual(entry["user"], "admin")
        self.assertEqual(entry["ip"], "185.220.101.47")
        self.assertEqual(entry["status"], "FAILED")

    def test_parse_invalid_user(self):
        """Invalid user line should map to FAILED with username captured."""
        line = "Aug 20 20:00:11 notevault-srv sshd[9099]: Invalid user git from 185.220.101.47 port 43095"
        entry = parse_log_line(line, default_year=2026)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["timestamp"], "2026-08-20 20:00:11")
        self.assertEqual(entry["user"], "git")
        self.assertEqual(entry["ip"], "185.220.101.47")
        self.assertEqual(entry["status"], "FAILED")

    def test_unmatched_or_non_auth_line(self):
        """System messages or non-auth lines should return None."""
        lines = [
            "Aug 20 00:00:01 notevault-srv systemd[1]: Started Periodic Cleanup of Temporary Directories.",
            "Aug 20 00:05:00 notevault-srv sshd[1234]: Connection closed by 10.0.0.1 port 50000",
            "This is a random non-log string",
            "",
        ]
        for line in lines:
            self.assertIsNone(parse_log_line(line))

    def test_custom_year(self):
        """Explicit default_year parameter should be reflected in normalized timestamp."""
        line = "Jan 05 12:30:00 server sshd[100]: Accepted password for dev from 192.168.1.1 port 22 ssh2"
        entry = parse_log_line(line, default_year=2025)
        self.assertEqual(entry["timestamp"], "2025-01-05 12:30:00")

    def test_parse_official_sample_file(self):
        """Parse the official data/auth_sample.log file and verify entry counts."""
        sample_path = os.path.join(os.path.dirname(__file__), "..", "data", "auth_sample.log")
        entries = parse_log_file(sample_path, default_year=2026)
        
        # Verify file is parsed and entries are returned
        self.assertGreater(len(entries), 0)
        
        # Verify all entries have required fields
        for entry in entries:
            self.assertIn("timestamp", entry)
            self.assertIn("user", entry)
            self.assertIn("ip", entry)
            self.assertIn("status", entry)
            self.assertIn(entry["status"], ["SUCCESS", "FAILED"])


if __name__ == "__main__":
    unittest.main()
