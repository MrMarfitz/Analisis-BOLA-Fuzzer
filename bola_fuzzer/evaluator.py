"""Consistent case-based metrics for dashboard and experiments."""
from bola_fuzzer.case_evaluator import evaluate_cases
from bola_fuzzer.models import EvaluationMetrics

def evaluate_findings(findings, ground_truth):
    m = evaluate_cases([{"case_id": f.test_name, "status": f.status} for f in findings], ground_truth)
    return EvaluationMetrics(true_positive=m['TP'], false_positive=m['FP'],
        false_negative=m['FN'], true_negative=m['TN'], precision=m['precision'],
        recall=m['recall'], f1_score=m['f1'], planned_cases=m['planned_cases'],
        completed_cases=m['completed_cases'], unresolved_cases=m['unresolved_cases'],
        case_completion=m['case_completion'], operational_recall=m['operational_recall'])
