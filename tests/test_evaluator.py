import unittest

from bola_fuzzer.evaluator import evaluate_findings
from bola_fuzzer.models import ScanFinding


def finding(endpoint, status):
    return ScanFinding(
        test_name=endpoint,
        endpoint=endpoint,
        object_id="1",
        status=status,
        severity="High",
        confidence="High",
        reason="reason",
        owner_status_code=200,
        attacker_status_code=200,
        poc_curl="curl",
        owner_response_preview="owner",
        attacker_response_preview="attacker",
    )


class EvaluatorTest(unittest.TestCase):
    def test_computes_metrics(self):
        metrics = evaluate_findings(
            [finding("/a/{id}", "Potential BOLA"), finding("/b/{id}", "No BOLA")],
            {"/a/{id}": True, "/b/{id}": False, "/c/{id}": True},
        )

        self.assertEqual(metrics.true_positive, 1)
        self.assertEqual(metrics.false_negative, 0)
        self.assertEqual(metrics.unresolved_cases, ["/c/{id}"])
        self.assertEqual(metrics.true_negative, 1)
        self.assertEqual(metrics.precision, 1.0)
        self.assertEqual(metrics.recall, 1.0)
        self.assertEqual(metrics.operational_recall, 0.5)


if __name__ == "__main__":
    unittest.main()
