"""
Unit Tests for Text Preprocessing Module
"""

import unittest
from src.preprocessing.cleaner import clean_text, clean_url


class TestPreprocessing(unittest.TestCase):

    def test_clean_text_normal(self):
        """Test normal text cleaning and lowercasing."""
        raw = "   Hello WORLD! This is a test message.   "
        expected = "hello world! this is a test message."
        self.assertEqual(clean_text(raw), expected)

    def test_clean_text_html(self):
        """Test HTML entity unescaping and tag stripping."""
        raw = "<b>URGENT &amp; IMPORTANT!</b> Click <a href='#'>here</a>"
        expected = "urgent & important! click here"
        self.assertEqual(clean_text(raw), expected)

    def test_clean_text_scam_signals_preserved(self):
        """Verify numbers, URLs, and punctuation signals are preserved."""
        raw = "WIN $1000 cash! Call 0800-123-456 or visit http://scam-link.xyz!"
        cleaned = clean_text(raw)
        self.assertIn("1000", cleaned)
        self.assertIn("0800-123-456", cleaned)
        self.assertIn("http://scam-link.xyz!", cleaned)
        self.assertIn("$", cleaned)

    def test_clean_text_null_and_empty(self):
        """Test handling of None and empty inputs."""
        self.assertEqual(clean_text(None), "")
        self.assertEqual(clean_text("   "), "")

    def test_clean_url(self):
        """Test URL cleaning."""
        raw_url = "  HTTP://EXAMPLE.COM/path/  "
        expected = "http://example.com/path"
        self.assertEqual(clean_url(raw_url), expected)
        self.assertEqual(clean_url(None), "")


if __name__ == "__main__":
    unittest.main()
