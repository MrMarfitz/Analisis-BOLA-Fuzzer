"""Reproducible local experiments using the original parser/auth/scanner/analyzer/report modules."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import subprocess
import threading
import time
from dataclasses import asdict
from datetime import datetime, timezone
from bola_fuzzer.config import parse_config
from bola_fuzzer.scanner import BolaScanner, redact
from bola_fuzzer.http_client import HttpClient
from bola_fuzzer.models import TargetConfig
from bola_fuzzer.openapi_parser import discover_endpoint_candidates, discover_resource_dependencies
from bola_fuzzer.reporter import write_reports
from bola_fuzzer.case_evaluator import evaluate_cases

ROOT = Path(__file__).resolve().parent


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def control_prepare():
    from labs.control.service import MODES
    out = ROOT / "experiments/control"
    if (out / "ground-truth-manifest.json").exists():
        verify_inputs(out)
        return json.loads((out / "catalog.json").read_text())
    catalog = []
    # Policy/label definitions follow service branches, before scanner execution.
    for mode in MODES:
        for owner, other in (("A", "B"), ("B", "A")):
            catalog.append({"case_id": f"CTRL-{mode}-{owner}-to-{other}", "mode": mode,
                "owner": owner, "other": other, "object_id": "obj-" + owner,
                "policy": mode if mode in ("public", "shared") else "private",
                "vulnerable": mode in ("vulnerable", "timeout"),
                "expected_execution": "inconclusive" if mode in ("expired", "timeout") else "conclusive",
                "verification": "Artifact review: labs/control/service.py Handler.do_GET; source service SHA256 pinned in manifest.",
                "expected_behavior": {"vulnerable": "Private object is returned to non-owner (deliberate missing ownership check)",
                    "protected": "Non-owner denied 403", "public": "Public read allowed", "shared": "A and B explicitly share read access",
                    "error200": "HTTP 200 error envelope with no object", "other-object": "Returns caller's own object, not owner's",
                    "expired": "401 session failure", "timeout": "3-second delay; private leak exists but request exceeds 1-second budget"}[mode]})
    save(out / "catalog.json", catalog)
    with (out / "catalog.csv").open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(catalog[0])); w.writeheader(); w.writerows(catalog)
    save(out / "ground-truth.json", {c["case_id"]: c["vulnerable"] for c in catalog})
    save(out / "ground-truth-manifest.json", {"established_at": datetime.now(timezone.utc).isoformat(),
        "method": "Source artifact inspection; labels assigned independently before predictions", "service_sha256": sha(ROOT / "labs/control/service.py"),
        "catalog_sha256": sha(out / "catalog.json"), "truth_sha256": sha(out / "ground-truth.json")})
    return catalog


def verify_inputs(folder):
    manifest = json.loads((folder / "ground-truth-manifest.json").read_text())
    for file, key in (("ground-truth.json", "truth_sha256"), ("catalog.json", "catalog_sha256")):
        if sha(folder / file) != manifest[key]: raise ValueError("Frozen input changed: " + file)
    if "service_sha256" in manifest and sha(ROOT / "labs/control/service.py") != manifest["service_sha256"]:
        raise ValueError("Control source differs from frozen ground truth; review before freezing a new dataset")
    for file, digest in manifest.get("artifact_sha256", {}).items():
        if sha(folder / "source-artifacts" / file) != digest:
            raise ValueError("Frozen source artifact changed: " + file)
    return manifest


def run_suite(name, catalog, spec, users, auth, base, repetitions, purpose='pilot', review_path=None):
    import shutil, platform
    inputs = ROOT / "experiments" / name
    manifest = verify_inputs(inputs)
    if purpose == 'main':
        review = json.loads(Path(review_path or inputs/'review.json').read_text(encoding='utf-8'))
        planned_truth = json.loads((inputs/'ground-truth.json').read_text())
        if (review.get('status') != 'approved' or not review.get('reviewer', '').strip()
                or not review.get('reviewed_at', '').strip()
                or review.get('manifest_sha256') != sha(inputs/'ground-truth-manifest.json')
                or set(review.get('case_reviews', {})) != set(planned_truth)
                or any(r.get('accepted') is not True or not r.get('basis', '').strip()
                       for r in review['case_reviews'].values())):
            raise ValueError('Main evaluation requires named human review of every frozen case')
    truth = json.loads((inputs / "ground-truth.json").read_text())
    ids = [c["case_id"] for c in catalog]
    if len(ids) != len(set(ids)) or set(ids) != set(truth):
        raise ValueError("Catalog case identities must match the frozen ground truth exactly")
    if catalog != json.loads((inputs / "catalog.json").read_text()):
        raise ValueError("Catalog is not the frozen input")
    out = inputs / "evaluations" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    out.mkdir(parents=True, exist_ok=False)
    for file in ("catalog.json", "catalog.csv", "ground-truth.json", "ground-truth-manifest.json",
                 "ownership-verification.json", "independent-http-verification.json"):
        if (inputs / file).exists(): shutil.copy2(inputs / file, out / file)
    if (inputs / "source-artifacts").exists():
        shutil.copytree(inputs / "source-artifacts", out / "source-artifacts")
    save(out / "execution.json", {"started_at": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(), "testbed": name, "base_url": base, "repetitions": repetitions,
        "purpose": purpose, "review": review if purpose == 'main' else {'status': 'not asserted; pilot'},
        "scope": "Configured GET object cases; reviewed explicit source/id mappings",
        "code_sha256": {str(p.relative_to(ROOT)): sha(p) for p in sorted(ROOT.glob("bola_fuzzer/*.py"))},
        "harness_sha256": sha(ROOT / "experiment.py")})
    candidates = discover_endpoint_candidates(spec)
    candidates = [c for c in candidates if c.method == "GET"]
    save(out / "discovery.json", {"candidates": [asdict(c) for c in candidates], "dependencies": [asdict(x) for x in discover_resource_dependencies(spec)],
                                  "mapping": "Explicit source/id/path overrides below are verified during fixture setup; no blind source guesses."})
    save(out / "openapi.json", spec)
    truth = json.loads((out / "ground-truth.json").read_text())
    truth_hash = sha(out / "ground-truth.json")
    all_metrics = []
    for rep in range(1, repetitions + 1):
        from bola_fuzzer.baselines import METHODS, baseline_decision, paired_summary
        method_rows = {method: [] for method in METHODS}
        findings = []; rows = []; t0 = time.perf_counter(); requests_total = 0; attempted_templates = set()
        for case in catalog:
            if name == "control":
                mode = case["mode"]
                path = f"/cases/{mode}/objects/{{id}}"
                source = f"/cases/{mode}/objects"
                identity, private = ["$.id"], ["$.private_note"]
                session = "/me"; source_id = "$[0].id"; parameter = "id"
            else:
                path, source = case["path"], case["source"]
                identity, private = case["identity_paths"], case["private_paths"]
                session = "/identity/api/v2/user/dashboard"; source_id = case["source_id_path"]; parameter = case.get("object_parameter", "carId")
            # Every scanned template must be discoverable. Concrete source mapping remains reviewed configuration.
            if not any(c.path == path for c in candidates):
                raise ValueError(f"Not discovered: {path}")
            a, b = users[case["owner"]], users[case["other"]]
            data = {"target": {"name": name, "base_url": base, "timeout_seconds": 1 if name == "control" else 10},
                    "auth": auth, "users": {"user_a": a, "user_b": b}, "tests": [{"name": case["case_id"], "method": "GET",
                    "source_endpoint": source, "source_id_path": source_id, "target_endpoint": path,
                    "object_parameter": parameter, "access_policy": case["policy"], "identity_paths": identity,
                    "private_paths": private, "session_endpoint": session}]}
            scanner = BolaScanner(parse_config(data))
            # Record attempted HTTP traffic, including failed requests, without storing login secrets.
            original = scanner.http.request; trace = []
            def recorded(*args, **kwargs):
                method = kwargs.get("method", args[0] if args else "GET")
                endpoint = kwargs.get("endpoint", args[1] if len(args) > 1 else "")
                entry = {"method": method, "endpoint": endpoint}; trace.append(entry)
                prefix, suffix = path.split("{" + parameter + "}")
                if method.upper() == "GET" and endpoint.startswith(prefix) and endpoint.endswith(suffix) and len(endpoint) > len(prefix)+len(suffix):
                    attempted_templates.add(path)
                try:
                    result = original(*args, **kwargs)
                    entry["status"] = result.status_code
                    if endpoint != auth["login_endpoint"]:
                        entry["body"] = redact(result.body)
                    return result
                except Exception as exc:
                    entry["error"] = type(exc).__name__ + ": " + str(exc); raise
            scanner.http.request = recorded
            start = time.perf_counter()
            result = scanner.run()[0]
            if result.object_id != str(case["object_id"]) and result.object_id != "-":
                result.status, result.severity, result.confidence = "Inconclusive", "Info", "Low"
                result.reason = "Discovered source object differs from the frozen catalog object; review fixture mapping."
            # Local sample accounts and their data only; no auth response body is persisted.
            record = asdict(result)
            record = redact(record, [v["password"] for v in users.values()])
            record.update({"case_id": case["case_id"], "elapsed_seconds": round(time.perf_counter() - start, 6),
                           "attempted_requests": len(trace), "http_trace": trace, "ground_truth_sha256": truth_hash})
            rows.append(record); findings.append(result); requests_total += len(trace)
            save(out / f"run-{rep}/evidence" / (case["case_id"] + ".json"), record)
            observation_hash = sha(out / f"run-{rep}/evidence" / (case["case_id"] + ".json"))
            for method in METHODS:
                method_rows[method].append({'case_id': case['case_id'], 'status': baseline_decision(result, method),
                                            'observation_sha256': observation_hash})
            poc = ["# Fresh login tokens must be set in TOKEN_OWNER and TOKEN_OTHER. No real token is embedded.",
                   "set -eu", ': "${TOKEN_OWNER:?Set fresh owner token}"', ': "${TOKEN_OTHER:?Set fresh other-user token}"']
            for role, var in (("owner", "TOKEN_OWNER"), ("cross_user", "TOKEN_OTHER")):
                evidence = result.evidence.get(role)
                if evidence:
                    poc.append(f'curl --max-time 10 -i "{evidence["request"]["url"]}" -H "Authorization: Bearer $' + var + '"')
            (out / f"run-{rep}/evidence" / (case["case_id"] + ".sh")).write_text("\n".join(poc) + "\n", encoding="utf-8")
        metrics = evaluate_cases(rows, truth)
        for method in METHODS:
            save(out / f'run-{rep}/comparison' / (method+'.json'), method_rows[method])
        save(out / f'run-{rep}/comparison/summary.json', {
            'purpose': purpose, 'same_http_observations': True,
            'metrics': {m: evaluate_cases(method_rows[m], truth) for m in METHODS},
            'paired': {m: paired_summary(method_rows[m], method_rows['contextual-v1'], truth)
                       for m in METHODS if m != 'contextual-v1'},
            'limit': 'Diagnostic decision-rule baselines; no external-tool equivalence or endpoint-independent generalization.'})
        metrics.update({"repetition": rep, "attempted_requests": requests_total, "elapsed_seconds": round(time.perf_counter()-t0, 6),
            "discovered_get_templates": len(candidates), "scoped_templates": len({c.get("path", "/cases/"+c.get("mode", "")+"/objects/{id}") for c in catalog}),
            "templates_attempted": len(attempted_templates), "ground_truth_sha256": truth_hash})
        save(out / f"run-{rep}/results.json", rows); save(out / f"run-{rep}/metrics.json", metrics)
        write_reports(findings, out / f"run-{rep}")
        all_metrics.append(metrics)
        if sha(out / "ground-truth.json") != truth_hash:
            raise ValueError("Ground truth changed during execution")
        verify_inputs(inputs)
        print(name, "run", rep, json.dumps(metrics), flush=True)
    save(out / "metrics.json", all_metrics)
    report(name, catalog, all_metrics, out, purpose)
    save(out / "completion.json", {"completed_at": datetime.now(timezone.utc).isoformat(),
        "completed_repetitions": len(all_metrics), "case_decisions_consistent":
        all([(r["case_id"], r["status"]) for r in json.loads((out / f"run-{i}/results.json").read_text())] ==
            [(r["case_id"], r["status"]) for r in json.loads((out / "run-1/results.json").read_text())]
            for i in range(2, repetitions+1))})
    print("Evaluation saved:", out, flush=True)


def report(name, catalog, metrics, out, purpose='pilot'):
    lines = [f"# Hasil eksperimen {name}", "", f"Tujuan eksekusi: {purpose}. Hasil lokal; bukan bukti generalisasi.",
        "Ground truth dibekukan sebelum scanner dijalankan. Kasus tidak konklusif dikeluarkan dari confusion matrix, tetap masuk denominator cakupan dan recall operasional.",
        "Angka setiap pengulangan dilaporkan sendiri; pengulangan bukan sampel kasus independen tambahan.", "",
        "|Run|TP|FP|TN|FN|Precision|Recall selesai|F1|Kasus selesai/direncanakan|Recall operasional|Permintaan|Detik|",
        "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for m in metrics:
        lines.append("|" + "|".join(str(x) for x in [m["repetition"], m["TP"], m["FP"], m["TN"], m["FN"], m["precision"], m["recall"], m["f1"], f'{m["completed_cases"]}/{m["planned_cases"]}', m["operational_recall"], m["attempted_requests"], m["elapsed_seconds"]]) + "|")
    lines += ["", "`null` berarti pembagi nol atau skor tidak terdefinisi.", "",
              f'Template GET ditemukan: {metrics[0]["discovered_get_templates"]}; memenuhi scope kasus awal: {metrics[0]["scoped_templates"]}. Scope ini subset terkonfigurasi, bukan seluruh endpoint crAPI.', "",
              "|Kasus|Pemilik|Penguji|Objek|Kebijakan|Label acuan|", "|---|---|---|---|---|---|"]
    for c in catalog:
        lines.append(f'|{c["case_id"]}|{c["owner"]}|{c["other"]}|{c["object_id"]}|{c["policy"]}|{c["vulnerable"]}|')
    lines += ["", "Bukti per kasus: `run-N/evidence/`; permintaan pemilik/pengguna silang dan PoC memakai variabel token.",
              "Kasus timeout/401 adalah tidak konklusif; jangan dipresentasikan sebagai endpoint aman."]
    (out / "HASIL-AWAL.md").write_text("\n".join(lines), encoding="utf-8")


def main():
    p = argparse.ArgumentParser(); p.add_argument("suite", choices=["control", "crapi"]); p.add_argument("--repetitions", type=int, default=3)
    p.add_argument('--purpose', choices=['pilot', 'main'], default='pilot')
    p.add_argument('--review', type=Path)
    p.add_argument("--native-control", action="store_true"); args = p.parse_args()
    if args.repetitions < 1: raise ValueError("repetitions >= 1")
    if args.suite == "control":
        server = None
        if args.native_control:
            from labs.control.service import serve
            server = serve(); threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            catalog = control_prepare()
            spec = HttpClient(TargetConfig("control", "http://127.0.0.1:8899")).request("GET", "/openapi.json").body
            users = {u: {"username": u, "password": "control-only-password"} for u in ("A", "B")}
            run_suite("control", catalog, spec, users, {"login_endpoint": "/login"}, "http://127.0.0.1:8899", args.repetitions, args.purpose, args.review)
        finally:
            if server: server.shutdown(); server.server_close()
    else:
        cfg = json.loads((ROOT / "experiments/crapi/fixture.json").read_text())
        catalog = json.loads((ROOT / "experiments/crapi/catalog.json").read_text())
        spec = json.loads((ROOT / "experiments/crapi/openapi.json").read_text())
        run_suite("crapi", catalog, spec, cfg["users"], {"login_endpoint": "/identity/api/auth/login", "username_field": "email"}, cfg["base_url"], args.repetitions, args.purpose, args.review)


if __name__ == "__main__": main()
