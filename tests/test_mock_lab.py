import unittest

from bola_fuzzer.mock_lab import run_mock_lab


class MockLabTest(unittest.TestCase):
    def test_mock_lab_produces_bola_finding(self):
        findings, _ = run_mock_lab()

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "Potential BOLA")
        self.assertEqual(findings[0].severity, "High")


if __name__ == "__main__":
    unittest.main()
