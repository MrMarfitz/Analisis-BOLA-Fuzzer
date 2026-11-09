from datetime import datetime
from pathlib import Path

from bola_fuzzer.models import EvaluationMetrics, ResourceDependency, ScanFinding, TestCase


def write_academic_report(
    findings: list[ScanFinding],
    tests: list[TestCase],
    dependencies: list[ResourceDependency] | None = None,
    metrics: EvaluationMetrics | None = None,
    output_dir: str | Path = "reports",
) -> Path:
    report_dir = Path(output_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    from uuid import uuid4
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f") + "-" + uuid4().hex[:8]
    path = report_dir / f"academic-bola-report-{stamp}.md"
    path.write_text(render_academic_report(findings, tests, dependencies or [], metrics), encoding="utf-8")
    return path


def render_academic_report(
    findings: list[ScanFinding],
    tests: list[TestCase],
    dependencies: list[ResourceDependency],
    metrics: EvaluationMetrics | None,
) -> str:
    lines = [
        "# Academic BOLA Fuzzer Report",
        "",
        f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Methodology",
        "",
        "The scanner evaluates Broken Object Level Authorization by authenticating two user contexts, collecting an object identifier from the owner context, then replaying the target request with the attacker token and owner object identifier.",
        "",
        "## Test Cases",
        "",
        "| Method | Target Endpoint | Source Endpoint | Object Path | Risk Hint |",
        "| --- | --- | --- | --- | --- |",
    ]
    for test in tests:
        lines.append(
            f"| {test.method} | `{test.target_endpoint}` | `{test.source_endpoint}` | `{test.source_id_path}` | {test.risk_hint} |"
        )

    lines.extend(["", "## Resource Dependency Mapping", ""])
    if dependencies:
        lines.extend(["| Resource | Parent Resource | Parameter | Path |", "| --- | --- | --- | --- |"])
        for dependency in dependencies:
            lines.append(
                f"| {dependency.resource} | {dependency.parent_resource} | `{dependency.parameter}` | `{dependency.path}` |"
            )
    else:
        lines.append("No OpenAPI resource dependencies were supplied for this run.")

    lines.extend(["", "## Findings", ""])
    if findings:
        lines.extend(["| Severity | Status | Endpoint | Object ID | Confidence |", "| --- | --- | --- | --- | --- |"])
        for finding in findings:
            lines.append(
                f"| {finding.severity} | {finding.status} | `{finding.endpoint}` | `{finding.object_id}` | {finding.confidence} |"
            )
    else:
        lines.append("No findings were produced.")

    if metrics:
        lines.extend(
            [
                "",
                "## Evaluation Metrics",
                "",
                f"- True Positive: {metrics.true_positive}",
                f"- False Positive: {metrics.false_positive}",
                f"- False Negative: {metrics.false_negative}",
                f"- True Negative: {metrics.true_negative}",
                f"- Precision: {metrics.precision}",
                f"- Recall: {metrics.recall}",
                f"- F1 Score (completed cases): {metrics.f1_score}",
                f"- Completed/planned cases: {metrics.completed_cases}/{metrics.planned_cases}",
                f"- Inconclusive/missing case IDs: {metrics.unresolved_cases}",
                f"- Case completion: {metrics.case_completion}",
                f"- Operational recall: {metrics.operational_recall}",
                "- Undefined scores are null/None. Inconclusive cases are excluded from TP/FP/TN/FN.",
            ]
        )

    lines.extend(
        [
            "",
            "## Evaluation Scope",
            "",
            "This report records the configured local cases only. It does not establish a comparison with ZAP/OFFAT. Inconclusive cases remain separate from detection errors, and crAPI and control results must be reported separately.",
        ]
    )
    return "\n".join(lines)
