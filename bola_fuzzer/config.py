from pathlib import Path
from typing import Any
import json
from urllib.parse import urlparse

from bola_fuzzer.models import AppConfig, AuthConfig, TargetConfig, TestCase, UserCredential


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path)
    if config_path.suffix.lower() == ".json":
        with config_path.open("r", encoding="utf-8") as file:
            return parse_config(json.load(file))

    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("PyYAML is required for config files. Run: pip install -r requirements.txt") from exc

    with config_path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    return parse_config(data)


def parse_config(data: dict[str, Any]) -> AppConfig:
    target = TargetConfig(
        name=data["target"].get("name", "Target API"),
        base_url=data["target"]["base_url"].rstrip("/"),
        timeout_seconds=int(data["target"].get("timeout_seconds", 10)),
    )
    auth = AuthConfig(
        login_endpoint=data["auth"]["login_endpoint"],
        method=data["auth"].get("method", "POST").upper(),
        username_field=data["auth"].get("username_field", "username"),
        password_field=data["auth"].get("password_field", "password"),
        token_path=data["auth"].get("token_path", "token"),
        token_prefix=data["auth"].get("token_prefix", "Bearer"),
    )
    user_a = UserCredential(
        label="User A",
        username=data["users"]["user_a"]["username"],
        password=data["users"]["user_a"]["password"],
    )
    user_b = UserCredential(
        label="User B",
        username=data["users"]["user_b"]["username"],
        password=data["users"]["user_b"]["password"],
    )
    tests = [
        TestCase(
            name=item["name"],
            method=item.get("method", "GET").upper(),
            source_endpoint=item["source_endpoint"],
            source_id_path=item["source_id_path"],
            target_endpoint=item["target_endpoint"],
            expected_owner_markers=list(item.get("expected_owner_markers", [])),
            sensitive_fields=list(item.get("sensitive_fields", [])),
            object_parameter=item.get("object_parameter", "id"),
            risk_hint=item.get("risk_hint", "Object-level authorization check"),
            access_policy=item.get("access_policy", "unknown"),
            identity_paths=list(item.get("identity_paths", [])),
            private_paths=list(item.get("private_paths", [])),
            session_endpoint=item.get("session_endpoint", ""),
            session_id_path=item.get("session_id_path", "$.id"),
        )
        for item in data.get("tests", [])
    ]
    url = urlparse(target.base_url)
    if url.scheme not in {'http', 'https'} or not url.hostname or url.username or url.password:
        raise ValueError('Target must be an HTTP(S) URL without embedded credentials')
    if not tests:
        raise ValueError('At least one configured test case is required')
    if not all(u.username.strip() and u.password for u in (user_a, user_b)):
        raise ValueError('Two registered accounts and passwords are required')
    if user_a.username == user_b.username:
        raise ValueError('Two different user accounts are required')
    names = [t.name for t in tests]
    if len(names) != len(set(names)) or any(not n for n in names):
        raise ValueError("Test case names must be unique and nonempty")
    if target.timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    for test in tests:
        if test.method != 'GET':
            raise ValueError('This application supports GET object reads only')
        for endpoint in (auth.login_endpoint, test.source_endpoint, test.target_endpoint, test.session_endpoint):
            if not endpoint.startswith('/') or endpoint.startswith('//') or urlparse(endpoint).netloc:
                raise ValueError('Endpoints must be relative paths on the configured target')
        if test.access_policy not in {"unknown", "private", "public", "shared"}:
            raise ValueError("Invalid access_policy")
        if "{" + test.object_parameter + "}" not in test.target_endpoint:
            raise ValueError("Target endpoint must contain the configured object parameter")
    return AppConfig(target=target, auth=auth, user_a=user_a, user_b=user_b, tests=tests)
