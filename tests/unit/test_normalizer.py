
import unittest
from datetime import datetime, timezone, timedelta
from src.processors.normalizer import VulnerabilityNormalizer

class TestVulnerabilityNormalizer(unittest.TestCase):
    def test_normalize_includes_age(self):
        # Create a mock raw vulnerability found 10 days ago
        now = datetime.now(timezone.utc)
        ten_days_ago = (now - timedelta(days=10)).isoformat().replace("+00:00", "Z")
        raw_vuln = {
            "asset": {"hostname": "test-host", "uuid": "test-uuid"},
            "plugin": {"id": 123, "name": "Test Plugin"},
            "first_found": ten_days_ago,
            "severity": "high",
            "state": "open"
        }
        
        normalized = VulnerabilityNormalizer.normalize(raw_vuln)
        
        self.assertIn("age_days", normalized)
        # It might be 10 or 11 depending on rounding, but roughly 10
        self.assertIsNotNone(normalized["age_days"])
        self.assertGreaterEqual(normalized["age_days"], 9)
        self.assertLessEqual(normalized["age_days"], 11)

    def test_normalize_handles_missing_first_found(self):
        raw_vuln = {
            "asset": {"hostname": "test-host", "uuid": "test-uuid"},
            "plugin": {"id": 123, "name": "Test Plugin"},
            "severity": "high",
            "state": "open"
        }
        
        normalized = VulnerabilityNormalizer.normalize(raw_vuln)
        
        self.assertIn("age_days", normalized)
        self.assertIsNone(normalized["age_days"])

    def test_map_state(self):
        self.assertEqual(VulnerabilityNormalizer._map_state("open"), "ACTIVE")
        self.assertEqual(VulnerabilityNormalizer._map_state("fixed"), "FIXED")
        self.assertEqual(VulnerabilityNormalizer._map_state("new"), "NEW")
        self.assertEqual(VulnerabilityNormalizer._map_state("unknown"), "UNKNOWN")

if __name__ == "__main__":
    unittest.main()
