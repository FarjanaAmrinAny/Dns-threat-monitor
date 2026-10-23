import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from detect_dns import detect, looks_dga_like, normalize_domain


class TestDNSThreatDetection(unittest.TestCase):

    def test_domain_normalization(self):
        self.assertEqual(
            normalize_domain("API.Example.com."),
            "api.example.com",
        )

    def test_known_domain_is_not_new(self):
        query = {
            "timestamp": datetime(2026, 10, 23, 10, 0, 0),
            "client_id": "test-client",
            "query_name": "api.example.com",
            "query_type": "A",
        }

        findings = detect([query], {"api.example.com"})
        self.assertFalse(findings[0]["new_domain"])

    def test_new_domain_is_flagged(self):
        query = {
            "timestamp": datetime(2026, 10, 23, 10, 0, 0),
            "client_id": "test-client",
            "query_name": "new.example.net",
            "query_type": "A",
        }

        findings = detect([query], {"api.example.com"})
        self.assertTrue(findings[0]["new_domain"])

    def test_high_query_volume_is_flagged(self):
        start = datetime(2026, 10, 23, 10, 0, 0)
        queries = [
            {
                "timestamp": start + timedelta(seconds=i * 5),
                "client_id": "test-client",
                "query_name": "api.example.com",
                "query_type": "A",
            }
            for i in range(5)
        ]

        findings = detect(queries, {"api.example.com"})
        self.assertTrue(findings[-1]["high_query_volume"])

    def test_dga_like_heuristic(self):
        self.assertTrue(
            looks_dga_like("x7q9m2k8p4v6z1.top")
        )
        self.assertFalse(
            looks_dga_like("api.example.com")
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
