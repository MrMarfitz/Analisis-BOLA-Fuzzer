from bola_fuzzer.http_client import HttpClient
from bola_fuzzer.json_path import extract_json_path
from bola_fuzzer.models import AuthConfig, UserCredential


class AuthManager:
    def __init__(self, http_client: HttpClient, auth_config: AuthConfig):
        self.http_client = http_client
        self.auth_config = auth_config

    def login(self, user: UserCredential) -> str:
        payload = {
            self.auth_config.username_field: user.username,
            self.auth_config.password_field: user.password,
        }
        result = self.http_client.request(
            method=self.auth_config.method,
            endpoint=self.auth_config.login_endpoint,
            json_body=payload,
        )
        if result.status_code >= 400:
            raise RuntimeError(f"Login failed for {user.label}: HTTP {result.status_code}")

        token = extract_json_path(result.body, f"$.{self.auth_config.token_path}")
        if not isinstance(token, str) or not token:
            raise RuntimeError(f"Token not found for {user.label} at path {self.auth_config.token_path}")
        return token
