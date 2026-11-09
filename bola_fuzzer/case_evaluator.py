"""Case-based evaluation; no implicit negative labels or failed-test TNs."""
def evaluate_cases(rows, truth):
    ids = [r["case_id"] for r in rows]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate case identity")
    tp = fp = tn = fn = 0
    pending = []
    by_id = {r["case_id"]: r for r in rows}
    if set(by_id) - set(truth):
        raise ValueError("Predictions without independent ground truth")
    for case_id, expected in truth.items():
        if type(expected) is not bool:
            raise ValueError("Ground truth must be Boolean")
        row = by_id.get(case_id)
        if row is None or row["status"] not in ("Potential BOLA", "No BOLA"):
            pending.append(case_id)
            continue
        detected = row["status"] == "Potential BOLA"
        if expected and detected: tp += 1
        elif expected: fn += 1
        elif detected: fp += 1
        else: tn += 1
    def div(a, b): return round(a / b, 6) if b else None
    positives = sum(truth.values())
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "precision": div(tp, tp + fp), "recall": div(tp, tp + fn),
            "f1": div(2 * tp, 2 * tp + fp + fn),
            "planned_cases": len(truth), "completed_cases": tp + fp + tn + fn,
            "unresolved_cases": pending, "case_completion": div(tp + fp + tn + fn, len(truth)),
            "operational_recall": div(tp, positives), "planned_positive_cases": positives}
