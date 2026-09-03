"""
test_main.py — Integration tests for AuthGuard main entry point.
"""

import unittest
import sys
import os

# Add the project root to the path so we can import from src/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.main import analyze_log_file


class TestMainPipeline(unittest.TestCase):
    """Integration tests for the main analysis pipeline."""

    def setUp(self):
        self.sample_path = os.path.join(
            os.path.dirname(__file__), "..", "data", "auth_sample.log"
        )

    def test_pipeline_runs_on_official_sample(self):
        """Pipeline should execute cleanly on official data/auth_sample.log."""
        report = analyze_log_file(self.sample_path)
        
        # Verify report contains header and summary
        self.assertIn("AUTHGUARD - LOG ANALYSIS REPORT", report)
        self.assertIn("SUMMARY STATISTICS", report)
        self.assertIn("DETAILED FINDINGS", report)
        
        # Check that alerts were found in the official sample
        self.assertIn("Total Suspicious Events:", report)

    def test_missing_file_raises_error(self):
        """Passing a non-existent file path should raise FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            analyze_log_file("data/non_existent_file.log")


if __name__ == "__main__":
    unittest.main()
