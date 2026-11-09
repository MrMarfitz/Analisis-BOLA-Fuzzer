import argparse
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="bola-fuzzer",
        description="Dual-token context swapping fuzzer for BOLA detection on REST APIs.",
    )
    parser.add_argument("--config", default="config.yaml", help="Path to YAML config file.")
    parser.add_argument("--mock-lab", action="store_true", help="Run the internal in-memory validation lab.")
    parser.add_argument("--discover-openapi", help="Read an OpenAPI JSON/YAML file and print BOLA candidates.")
    parser.add_argument("--output", default="reports", help="Report output directory.")
    args = parser.parse_args()

    try:
        if args.discover_openapi:
            from bola_fuzzer.openapi_parser import (
                discover_endpoint_candidates,
                discover_resource_dependencies,
                load_openapi,
            )

            spec = load_openapi(args.discover_openapi)
            candidates = discover_endpoint_candidates(spec)
            dependencies = discover_resource_dependencies(spec)
            print_discovery(candidates, dependencies)
            return
        if args.mock_lab:
            from bola_fuzzer.mock_lab import run_mock_lab

            findings, paths = run_mock_lab(args.output)
        else:
            from bola_fuzzer.config import load_config
            from bola_fuzzer.reporter import write_reports
            from bola_fuzzer.scanner import BolaScanner

            config_path = Path(args.config)
            if not config_path.exists():
                raise FileNotFoundError(f"Config file not found: {config_path}")
            config = load_config(config_path)
            findings = BolaScanner(config).run()
            paths = write_reports(findings, args.output)
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    markdown_path, html_path = paths
    print_banner(findings, markdown_path, html_path)


def print_banner(findings, markdown_path, html_path) -> None:
    potential = sum(1 for finding in findings if finding.status == "Potential BOLA")
    suspicious = sum(1 for finding in findings if finding.status == "Suspicious")

    print("")
    print("BOLA Fuzzer scan complete")
    print("========================")
    print(f"Total tests      : {len(findings)}")
    print(f"Potential BOLA   : {potential}")
    print(f"Suspicious       : {suspicious}")
    print(f"Markdown report  : {markdown_path}")
    print(f"HTML report      : {html_path}")
    print("")


def print_discovery(candidates, dependencies) -> None:
    print("")
    print("OpenAPI BOLA candidate discovery")
    print("================================")
    print(f"Endpoint candidates : {len(candidates)}")
    print(f"Dependencies        : {len(dependencies)}")
    print("")
    for candidate in candidates:
        print(f"- {candidate.method} {candidate.path}")
        print(f"  source      : {candidate.source_endpoint}")
        print(f"  id path     : {candidate.source_id_path}")
        print(f"  risk hint   : {candidate.risk_hint}")
    print("")
