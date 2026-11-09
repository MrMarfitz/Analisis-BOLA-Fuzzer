from dataclasses import asdict

from bola_fuzzer.models import EndpointCandidate, EvaluationMetrics, ResourceDependency, ScanFinding


def finding_to_dict(finding: ScanFinding) -> dict:
    data = asdict(finding)
    if data["status"] == "Potential BOLA":
        data["ui_status"] = "BOLA Leak"
    elif data["status"] == "Suspicious":
        data["ui_status"] = "Review Needed"
    elif data["status"] == "No BOLA":
        data["ui_status"] = "No BOLA observed"
    else:
        data["ui_status"] = data["status"]
    return data


def findings_to_dicts(findings: list[ScanFinding]) -> list[dict]:
    return [finding_to_dict(finding) for finding in findings]


def candidates_to_dicts(candidates: list[EndpointCandidate]) -> list[dict]:
    return [asdict(candidate) for candidate in candidates]


def dependencies_to_dicts(dependencies: list[ResourceDependency]) -> list[dict]:
    return [asdict(dependency) for dependency in dependencies]


def metrics_to_dict(metrics: EvaluationMetrics | None) -> dict | None:
    return asdict(metrics) if metrics else None
