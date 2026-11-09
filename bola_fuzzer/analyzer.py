import json
from typing import Any

from bola_fuzzer.models import HttpResult


SUCCESS_CODES = {200, 201, 202, 206}


def to_searchable_text(body: Any) -> str:
    if isinstance(body, str):
        return body
    return json.dumps(body, ensure_ascii=False, sort_keys=True)


def preview_body(body: Any, limit: int = 700) -> str:
    text = to_searchable_text(body)
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return f"{text[:limit]}..."


def analyze_bola(
    owner_result: HttpResult,
    attacker_result: HttpResult,
    expected_owner_markers: list[str],
    sensitive_fields: list[str],
    access_policy: str = "unknown",
    identity_paths: list[str] | None = None,
    private_paths: list[str] | None = None,
    sessions_valid: bool = True,
    expected_object_id: str | None = None,
) -> tuple[str, str, str, str]:
    from bola_fuzzer.json_path import extract_json_path
    def outcome(status, reason):
        return status, ("High" if status == "Potential BOLA" else "Info"), ("Low" if status == "Inconclusive" else "High"), reason
    if not sessions_valid or owner_result.status_code not in SUCCESS_CODES or attacker_result.status_code == 401:
        return outcome("Inconclusive", "Owner baseline or authenticated session is invalid.")
    if access_policy not in {"private", "public", "shared"}:
        return outcome("Inconclusive", "Object access policy is not configured; access alone cannot establish BOLA.")
    if identity_paths:
        try:
            owner_ids = [extract_json_path(owner_result.body, p) for p in identity_paths]
            if any(type(v) not in (str, int) or v == "" for v in owner_ids):
                return outcome("Inconclusive", "Owner object identity is empty.")
        except (KeyError, IndexError, ValueError, TypeError):
            return outcome("Inconclusive", "Owner baseline does not contain the expected object.")
        if expected_object_id is not None and str(owner_ids[0]) != expected_object_id:
            return outcome("Inconclusive", "Owner baseline identity does not match the requested source object.")
        if attacker_result.status_code in {403, 404}:
            return outcome("No BOLA", "Cross-user request was blocked or object hidden after a valid owner baseline.")
        if attacker_result.status_code not in SUCCESS_CODES:
            return outcome("Inconclusive", "Unexpected cross-user response status.")
        try:
            cross_ids = [extract_json_path(attacker_result.body, p) for p in identity_paths]
        except (KeyError, IndexError, ValueError, TypeError):
            if isinstance(attacker_result.body, dict) and any(k in attacker_result.body for k in ("error", "message", "detail")):
                return outcome("No BOLA", "Successful HTTP envelope contains an error and no requested object.")
            return outcome("Inconclusive", "Cross-user response lacks the configured object identity.")
        if owner_ids != cross_ids:
            return outcome("No BOLA", "Cross-user response refers to a different object.")
        if access_policy in {"public", "shared"}:
            return outcome("No BOLA", "Matching object access is permitted by the configured public/shared policy.")
        if access_policy != "private" or not private_paths:
            return outcome("Inconclusive", "Private object evidence is not fully configured.")
        try:
            matches = [extract_json_path(owner_result.body, p) == extract_json_path(attacker_result.body, p)
                       and extract_json_path(owner_result.body, p) not in (None, "", {}, []) for p in private_paths]
        except (KeyError, IndexError, ValueError, TypeError):
            return outcome("Inconclusive", "Private evidence fields are absent.")
        if all(matches):
            return outcome("Potential BOLA", "Private object identity and configured private fields match across distinct user sessions.")
        return outcome("Inconclusive", "Object matches but private evidence differs.")
    return outcome("Inconclusive", "Configured object identity is required; text markers alone cannot establish BOLA.")
