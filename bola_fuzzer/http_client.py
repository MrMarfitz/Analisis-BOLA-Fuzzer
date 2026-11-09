import json
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from urllib.parse import urljoin

from bola_fuzzer.models import HttpResult, TargetConfig


class HttpClient:
    def __init__(self, target: TargetConfig):
        self.target = target

    def request(
        self,
        method: str,
        endpoint: str,
        token: str | None = None,
        token_prefix: str = "Bearer",
        json_body: dict[str, Any] | None = None,
    ) -> HttpResult:
        headers = {"Accept": "application/json"}
        data = None
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"{token_prefix} {token}".strip()

        url = urljoin(f"{self.target.base_url}/", endpoint.lstrip("/"))
        request = Request(url=url, data=data, headers=headers, method=method.upper())

        try:
            with urlopen(request, timeout=self.target.timeout_seconds) as response:
                status_code = response.status
                response_headers = dict(response.headers.items())
                raw_bytes = response.read()
        except HTTPError as exc:
            status_code = exc.code
            response_headers = dict(exc.headers.items())
            raw_bytes = exc.read()

        raw_text = raw_bytes.decode("utf-8", errors="replace")
        try:
            body: Any = json.loads(raw_text) if raw_text else {}
        except ValueError:
            body = raw_text

        return HttpResult(
            method=method.upper(),
            url=url,
            status_code=status_code,
            headers=response_headers,
            body=body,
            raw_text=raw_text,
        )
