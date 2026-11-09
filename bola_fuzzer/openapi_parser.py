import json
import re
from pathlib import Path
from typing import Any

from bola_fuzzer.models import EndpointCandidate, ResourceDependency, TestCase


HTTP_METHODS = {"get", "post", "put", "patch", "delete"}
OBJECT_PARAM_RE = re.compile(r"{([^}/]+)}")
SENSITIVE_FIELD_HINTS = [
    "email",
    "phone",
    "address",
    "vehicle",
    "vin",
    "user_id",
    "owner_id",
    "account",
    "payment",
    "card",
    "order",
]


def load_openapi(path: str | Path) -> dict[str, Any]:
    spec_path = Path(path)
    raw = spec_path.read_text(encoding="utf-8")
    if spec_path.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError("PyYAML is required to read YAML OpenAPI files.") from exc
        return yaml.safe_load(raw)
    return json.loads(raw)


def discover_endpoint_candidates(spec: dict[str, Any]) -> list[EndpointCandidate]:
    candidates: list[EndpointCandidate] = []
    for path, path_item in spec.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        params = OBJECT_PARAM_RE.findall(path)
        if not params:
            continue

        object_parameter = choose_object_parameter(params)
        for method, operation in path_item.items():
            method_lower = method.lower()
            if method_lower not in HTTP_METHODS or method_lower == "post":
                continue
            operation = operation if isinstance(operation, dict) else {}
            candidates.append(
                EndpointCandidate(
                    name=operation.get("summary") or operation.get("operationId") or f"{method_upper(method)} {path}",
                    method=method_upper(method),
                    path=path,
                    object_parameter=object_parameter,
                    source_endpoint=guess_source_endpoint(path),
                    source_id_path=f"$[0].{object_parameter}",
                    risk_hint=guess_risk_hint(method_lower, path),
                    sensitive_fields=guess_sensitive_fields(path, operation),
                )
            )
    return candidates


def discover_resource_dependencies(spec: dict[str, Any]) -> list[ResourceDependency]:
    dependencies: list[ResourceDependency] = []
    for path in spec.get("paths", {}):
        params = OBJECT_PARAM_RE.findall(path)
        parts = [part for part in path.split("/") if part and not part.startswith("{")]
        if len(parts) < 2 or not params:
            continue
        child = normalize_resource(parts[-1])
        parent = normalize_resource(parts[-2])
        dependencies.append(
            ResourceDependency(
                resource=child,
                parent_resource=parent,
                parameter=choose_object_parameter(params),
                path=path,
            )
        )
    return dependencies


def candidates_to_test_cases(
    candidates: list[EndpointCandidate],
    owner_markers: list[str] | None = None,
    limit: int | None = None,
) -> list[TestCase]:
    selected = candidates[:limit] if limit else candidates
    return [
        TestCase(
            name=candidate.name,
            method=candidate.method,
            source_endpoint=candidate.source_endpoint,
            source_id_path=candidate.source_id_path,
            target_endpoint=candidate.path,
            expected_owner_markers=owner_markers or [],
            sensitive_fields=candidate.sensitive_fields,
            object_parameter=candidate.object_parameter,
            risk_hint=candidate.risk_hint,
        )
        for candidate in selected
    ]


def method_upper(method: str) -> str:
    return method.upper()


def choose_object_parameter(params: list[str]) -> str:
    for param in params:
        if param.lower() in {"id", "objectid", "object_id", "vehicleid", "vehicle_id", "userid", "user_id"}:
            return param
    return params[-1]


def guess_source_endpoint(path: str) -> str:
    source = re.sub(r"/{[^}/]+}", "", path)
    source = re.sub(r"//+", "/", source)
    return source or path


def guess_risk_hint(method: str, path: str) -> str:
    if method == "get":
        action = "Cross-user read"
    elif method in {"put", "patch"}:
        action = "Cross-user write"
    elif method == "delete":
        action = "Cross-user delete"
    else:
        action = "Object access"
    return f"{action} candidate for {path}"


def guess_sensitive_fields(path: str, operation: dict[str, Any]) -> list[str]:
    text = json.dumps({"path": path, "operation": operation}, ensure_ascii=False).lower()
    hits = [field for field in SENSITIVE_FIELD_HINTS if field in text]
    return hits or ["email", "user_id", "owner_id", "id"]


def normalize_resource(value: str) -> str:
    return value.strip("/").replace("-", "_").lower()
