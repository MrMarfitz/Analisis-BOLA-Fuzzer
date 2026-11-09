from bola_fuzzer.analyzer import analyze_bola, preview_body
from bola_fuzzer.models import HttpResult, ScanFinding, TestCase
from bola_fuzzer.reporter import write_reports


OWNER_EMAIL = "user-a@example.com"
ATTACKER_EMAIL = "user-b@example.com"
OWNER_TOKEN = "token-user-a"
ATTACKER_TOKEN = "token-user-b"


def run_mock_lab(output_dir: str = "reports") -> tuple[list[ScanFinding], tuple[object, object]]:
    tests = [
        TestCase(
            name="Mock vehicle detail BOLA",
            method="GET",
            source_endpoint="/workshop/api/vehicles",
            source_id_path="$[0].id",
            target_endpoint="/workshop/api/vehicles/{id}",
            expected_owner_markers=[OWNER_EMAIL],
            sensitive_fields=["owner", "vehicle", "vin", "phone"],
            object_parameter="id",
            risk_hint="Cross-user read candidate",
            access_policy="private", identity_paths=["$.id"], private_paths=["$.vin"],
        )
    ]
    findings = [run_mock_test(tests[0])]
    paths = write_reports(findings, output_dir)
    return findings, paths


def run_mock_test(test: TestCase) -> ScanFinding:
    object_id = "veh_1021"
    endpoint = test.target_endpoint.replace("{id}", object_id)
    url = f"http://127.0.0.1:8888{endpoint}"

    owner_result = HttpResult(
        method=test.method,
        url=url,
        status_code=200,
        headers={"content-type": "application/json"},
        body={
            "id": object_id,
            "owner": OWNER_EMAIL,
            "vehicle": "Sedan",
            "vin": "DEMO-VIN-001",
            "phone": "+62-800-0001",
        },
        raw_text="",
    )
    attacker_result = HttpResult(
        method=test.method,
        url=url,
        status_code=200,
        headers={"content-type": "application/json"},
        body={
            "id": object_id,
            "owner": OWNER_EMAIL,
            "vehicle": "Sedan",
            "vin": "DEMO-VIN-001",
            "phone": "+62-800-0001",
        },
        raw_text="",
    )

    status, severity, confidence, reason = analyze_bola(
        owner_result=owner_result,
        attacker_result=attacker_result,
        expected_owner_markers=test.expected_owner_markers,
        sensitive_fields=test.sensitive_fields,
        access_policy=test.access_policy, identity_paths=test.identity_paths, private_paths=test.private_paths,
    )

    return ScanFinding(
        test_name=test.name,
        endpoint=endpoint,
        object_id=object_id,
        status=status,
        severity=severity,
        confidence=confidence,
        reason=reason,
        owner_status_code=owner_result.status_code,
        attacker_status_code=attacker_result.status_code,
        poc_curl=(
            f'curl -i -X {test.method} "{url}" '
            f'-H "Authorization: Bearer $TOKEN_OTHER"'
        ),
        owner_response_preview=preview_body(owner_result.body),
        attacker_response_preview=preview_body(attacker_result.body),
    )
