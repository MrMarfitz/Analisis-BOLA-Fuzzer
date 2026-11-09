from __future__ import annotations

import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from bola_fuzzer.academic_reporter import write_academic_report
from bola_fuzzer.config import parse_config
from bola_fuzzer.mock_lab import run_mock_lab
from bola_fuzzer.evaluator import evaluate_findings
from bola_fuzzer.openapi_parser import (
    candidates_to_test_cases,
    discover_endpoint_candidates,
    discover_resource_dependencies,
)
from bola_fuzzer.reporter import write_reports
from bola_fuzzer.scanner import BolaScanner
from bola_fuzzer.serializer import candidates_to_dicts, dependencies_to_dicts, findings_to_dicts, metrics_to_dict


ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "web"


class BolaFuzzerHandler(BaseHTTPRequestHandler):
    server_version = "BolaFuzzerLocal/0.1"

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/health":
            self.send_json({"ok": True, "service": "bola-fuzzer"})
            return
        if path == "/api/lab-validation":
            findings, report_paths = run_mock_lab()
            self.send_json(
                {
                    "ok": True,
                    "mode": "lab-validation",
                    "findings": findings_to_dicts(findings),
                    "reports": {
                        "markdown": str(report_paths[0]),
                        "html": str(report_paths[1]),
                    },
                }
            )
            return
        self.serve_static(path)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/openapi/discover":
            self.handle_openapi_discovery()
            return
        if path == "/api/scan":
            self.handle_scan()
            return
        self.send_json({"ok": False, "error": "Not found"}, status=404)

    def handle_openapi_discovery(self) -> None:
        try:
            payload = self.read_json()
            spec = payload.get("openapi_spec") or {}
            if not isinstance(spec, dict):
                raise ValueError("openapi_spec must be a JSON object")
            candidates = discover_endpoint_candidates(spec)
            dependencies = discover_resource_dependencies(spec)
            self.send_json(
                {
                    "ok": True,
                    "candidates": candidates_to_dicts(candidates),
                    "dependencies": dependencies_to_dicts(dependencies),
                }
            )
        except Exception as exc:
            self.send_json({"ok": False, "error": str(exc)}, status=400)

    def handle_scan(self) -> None:
        try:
            payload = self.read_json()
            dependencies = []
            reviewed = {t["target_endpoint"]: t for t in payload.get("tests", [])}
            if payload.get("openapi_spec") and payload.get("auto_discover"):
                candidates = discover_endpoint_candidates(payload["openapi_spec"])
                dependencies = discover_resource_dependencies(payload["openapi_spec"])
                owner_markers = [payload.get("users", {}).get("user_a", {}).get("username", "")]
                payload["tests"] = [
                    {
                        "name": test.name,
                        "method": test.method,
                        "source_endpoint": test.source_endpoint,
                        "source_id_path": test.source_id_path,
                        "target_endpoint": test.target_endpoint,
                        "expected_owner_markers": test.expected_owner_markers,
                        "sensitive_fields": test.sensitive_fields,
                        "object_parameter": test.object_parameter,
                        "risk_hint": test.risk_hint,
                    }
                    for test in candidates_to_test_cases([c for c in candidates if c.method == "GET"], owner_markers, limit=payload.get("max_auto_tests", 20))
                ]

            if payload.get("auto_discover"):
                payload["tests"] = [dict(t, **reviewed.get(t["target_endpoint"], {})) for t in payload["tests"]]
            config = parse_config(payload)
            ground_truth = payload.get("ground_truth") or {}
            if ground_truth:
                evaluate_findings([], ground_truth)  # Validate Boolean labels before network execution.
                if {t.name for t in config.tests} - set(ground_truth):
                    raise ValueError("Ground truth keys must cover all case names; endpoint-keyed labels are not supported")
            findings = BolaScanner(config).run()
            report_paths = write_reports(findings)
            ground_truth = payload.get("ground_truth") or {}
            metrics = evaluate_findings(findings, ground_truth) if ground_truth else None
            academic_report = write_academic_report(findings, config.tests, dependencies, metrics)
            self.send_json(
                {
                    "ok": True,
                    "mode": "target",
                    "findings": findings_to_dicts(findings),
                    "metrics": metrics_to_dict(metrics),
                    "reports": {
                        "markdown": str(report_paths[0]),
                        "html": str(report_paths[1]),
                        "academic": str(academic_report),
                    },
                }
            )
        except Exception as exc:
            self.send_json({"ok": False, "error": str(exc)}, status=400)

    def serve_static(self, request_path: str) -> None:
        if request_path == "/":
            request_path = "/index.html"
        relative = request_path.lstrip("/")
        candidate = (WEB_ROOT / relative).resolve()
        if not candidate.is_relative_to(WEB_ROOT.resolve()) or not candidate.exists() or candidate.is_dir():
            self.send_json({"ok": False, "error": "File not found"}, status=404)
            return

        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        data = candidate.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8")
        return json.loads(raw_body) if raw_body else {}

    def send_json(self, payload: dict, status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args) -> None:
        return


def run(host: str = "127.0.0.1", port: int = 8080) -> None:
    server = ThreadingHTTPServer((host, port), BolaFuzzerHandler)
    print(f"BOLA Fuzzer dashboard running at http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    server.serve_forever()


if __name__ == "__main__":
    run()
