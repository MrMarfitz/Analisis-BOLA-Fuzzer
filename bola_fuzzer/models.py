from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class UserCredential:
    label: str
    username: str
    password: str


@dataclass(frozen=True)
class AuthConfig:
    login_endpoint: str
    method: str
    username_field: str
    password_field: str
    token_path: str
    token_prefix: str = "Bearer"


@dataclass(frozen=True)
class TargetConfig:
    name: str
    base_url: str
    timeout_seconds: int = 10


@dataclass(frozen=True)
class TestCase:
    name: str
    method: str
    source_endpoint: str
    source_id_path: str
    target_endpoint: str
    expected_owner_markers: list[str] = field(default_factory=list)
    sensitive_fields: list[str] = field(default_factory=list)
    object_parameter: str = "id"
    risk_hint: str = "Object-level authorization check"
    access_policy: str = "unknown"
    identity_paths: list[str] = field(default_factory=list)
    private_paths: list[str] = field(default_factory=list)
    session_endpoint: str = ""
    session_id_path: str = "$.id"


@dataclass(frozen=True)
class AppConfig:
    target: TargetConfig
    auth: AuthConfig
    user_a: UserCredential
    user_b: UserCredential
    tests: list[TestCase]


@dataclass
class HttpResult:
    method: str
    url: str
    status_code: int
    headers: dict[str, str]
    body: Any
    raw_text: str


@dataclass
class ScanFinding:
    test_name: str
    endpoint: str
    object_id: str
    status: str
    severity: str
    confidence: str
    reason: str
    owner_status_code: int
    attacker_status_code: int
    poc_curl: str
    owner_response_preview: str
    attacker_response_preview: str
    evidence: dict = field(default_factory=dict)


@dataclass(frozen=True)
class EndpointCandidate:
    name: str
    method: str
    path: str
    object_parameter: str
    source_endpoint: str
    source_id_path: str
    risk_hint: str
    sensitive_fields: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ResourceDependency:
    resource: str
    parent_resource: str
    parameter: str
    path: str


@dataclass(frozen=True)
class EvaluationMetrics:
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int
    precision: float | None
    recall: float | None
    f1_score: float | None
    planned_cases: int = 0
    completed_cases: int = 0
    unresolved_cases: list[str] = field(default_factory=list)
    case_completion: float | None = None
    operational_recall: float | None = None
