"""
test_reporter.py — Tests for the reporter module.
"""

import unittest
import sys
import os

# Add the project root to the path so we can import from src/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.reporter import generate_report


class TestReporter(unittest.TestCase):
    """Tests for report generation logic."""

    def test_empty_alerts(self):
        """Empty alert list should generate a clean 'no findings' report."""
        report = generate_report([])
        self.assertIn("AUTHGUARD - LOG ANALYSIS REPORT", report)
        self.assertIn("No suspicious activity detected", report)
        self.assertNotIn("SUMMARY STATISTICS", report)

    def test_single_alert(self):
        """A single alert should be formatted correctly."""
        alerts = [{
            "type": "Repeated Failed Login",
            "severity": "HIGH",
            "user": "alice",
            "ip": "10.0.0.1",
            "details": {"failed_attempts": 5},
            "explanation": "Test explanation.",
            "mitigation": "Test mitigation."
        }]
        report = generate_report(alerts)
        
        # Check sections
        self.assertIn("SUMMARY STATISTICS", report)
        self.assertIn("Total Suspicious Events: 1", report)
        self.assertIn("HIGH Severity:   1", report)
        
        # Check details
        self.assertIn("[HIGH] Repeated Failed Login", report)
        self.assertIn("User:       alice", report)
        self.assertIn("IP Address: 10.0.0.1", report)
        
        # Check formatting of the details dictionary
        self.assertIn("Failed Attempts: 5", report)
        
        # Check explanation and mitigation
        self.assertIn("Why Suspicious: Test explanation.", report)
        self.assertIn("Mitigation:     Test mitigation.", report)

    def test_sorting_by_severity(self):
        """Alerts should be sorted HIGH, then MEDIUM, then LOW."""
        alerts = [
            {"type": "Alert 1", "severity": "MEDIUM"},
            {"type": "Alert 2", "severity": "LOW"},
            {"type": "Alert 3", "severity": "HIGH"},
        ]
        report = generate_report(alerts)
        
        # Find the index of each event in the generated string
        idx_high = report.find("[HIGH] Alert 3")
        idx_medium = report.find("[MEDIUM] Alert 1")
        idx_low = report.find("[LOW] Alert 2")
        
        # Verify they exist
        self.assertTrue(idx_high > 0)
        self.assertTrue(idx_medium > 0)
        self.assertTrue(idx_low > 0)
        
        # Verify order
        self.assertTrue(idx_high < idx_medium < idx_low)


if __name__ == "__main__":
    unittest.main()
