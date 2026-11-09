import unittest

from bola_fuzzer.analyzer import analyze_bola
from bola_fuzzer.models import HttpResult


def make_result(status_code, body):
    return HttpResult(
        method="GET",
        url="http://example.test/items/1",
        status_code=status_code,
        headers={},
        body=body,
        raw_text=str(body),
    )


class AnalyzerTest(unittest.TestCase):
    def test_marks_potential_bola_when_attacker_sees_owner_marker(self):
        owner = make_result(200, {"id": 1, "email": "user-a@example.com"})
        attacker = make_result(200, {"id": 1, "email": "user-a@example.com"})

        status, severity, confidence, reason = analyze_bola(
            owner,
            attacker,
            expected_owner_markers=["user-a@example.com"],
            sensitive_fields=["email"],
            access_policy="private", identity_paths=["$.id"], private_paths=["$.email"],
        )

        self.assertEqual(status, "Potential BOLA")
        self.assertEqual(severity, "High")
        self.assertEqual(confidence, "High")
        self.assertIn("Private object identity", reason)

    def test_marks_no_bola_when_attacker_is_forbidden(self):
        owner = make_result(200, {"id": 1, "email": "user-a@example.com"})
        attacker = make_result(403, {"message": "forbidden"})

        status, severity, confidence, reason = analyze_bola(
            owner,
            attacker,
            expected_owner_markers=["user-a@example.com"],
            sensitive_fields=["email"],
            access_policy="private", identity_paths=["$.id"], private_paths=["$.email"],
        )

        self.assertEqual(status, "No BOLA")
        self.assertEqual(severity, "Info")
        self.assertEqual(confidence, "High")
        self.assertIn("blocked", reason)


if __name__ == "__main__":
    unittest.main()
