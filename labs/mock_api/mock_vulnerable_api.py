from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


TOKENS = {
    "user-a@example.com": "token-user-a",
    "user-b@example.com": "token-user-b",
}

VEHICLES = {
    "veh_1021": {
        "id": "veh_1021",
        "owner": "user-a@example.com",
        "vehicle": "Sedan",
        "vin": "DEMO-VIN-001",
        "phone": "+62-800-0001",
    },
    "veh_9881": {
        "id": "veh_9881",
        "owner": "user-b@example.com",
        "vehicle": "SUV",
        "vin": "DEMO-VIN-002",
        "phone": "+62-800-0002",
    },
}


class MockApiHandler(BaseHTTPRequestHandler):
    server_version = "MockBolaApi/0.1"

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/health":
            self.send_json({"ok": True, "service": "mock-vulnerable-api"})
            return
        if path == "/openapi.json":
            self.send_json(openapi_spec())
            return
        if path == "/workshop/api/vehicles":
            user = self.current_user()
            if not user:
                self.send_json({"error": "unauthorized"}, status=401)
                return
            owned = [vehicle for vehicle in VEHICLES.values() if vehicle["owner"] == user]
            self.send_json(owned)
            return
        if path.startswith("/workshop/api/vehicles/"):
            vehicle_id = path.rsplit("/", 1)[-1]
            vehicle = VEHICLES.get(vehicle_id)
            if not vehicle:
                self.send_json({"error": "not found"}, status=404)
                return

            # Intentional BOLA: any authenticated user can read any vehicle by ID.
            if not self.current_user():
                self.send_json({"error": "unauthorized"}, status=401)
                return
            self.send_json(vehicle)
            return
        self.send_json({"error": "not found"}, status=404)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/identity/api/auth/login":
            self.send_json({"error": "not found"}, status=404)
            return

        payload = self.read_json()
        email = payload.get("email")
        password = payload.get("password")
        if password != "password" or email not in TOKENS:
            self.send_json({"error": "invalid credentials"}, status=401)
            return
        self.send_json({"token": TOKENS[email], "email": email})

    def current_user(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        token = auth.replace("Bearer", "").strip()
        for email, known_token in TOKENS.items():
            if token == known_token:
                return email
        return None

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8")
        return json.loads(raw_body) if raw_body else {}

    def send_json(self, payload: dict | list, status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args) -> None:
        return


def openapi_spec() -> dict:
    return {
        "openapi": "3.0.3",
        "info": {"title": "Mock Vulnerable API", "version": "0.1.0"},
        "paths": {
            "/identity/api/auth/login": {
                "post": {
                    "summary": "Login",
                    "responses": {"200": {"description": "JWT token"}},
                }
            },
            "/workshop/api/vehicles": {
                "get": {
                    "summary": "List owned vehicles",
                    "responses": {"200": {"description": "Owned vehicles"}},
                }
            },
            "/workshop/api/vehicles/{id}": {
                "get": {
                    "summary": "Get vehicle by ID",
                    "parameters": [{"name": "id", "in": "path", "required": True}],
                    "responses": {"200": {"description": "Vehicle detail"}},
                }
            },
        },
    }


def run(host: str = "127.0.0.1", port: int = 8888) -> None:
    server = ThreadingHTTPServer((host, port), MockApiHandler)
    print(f"Mock vulnerable API running at http://{host}:{port}")
    print("Login users: user-a@example.com / password, user-b@example.com / password")
    print("OpenAPI spec: http://127.0.0.1:8888/openapi.json")
    print("Press Ctrl+C to stop.")
    server.serve_forever()


if __name__ == "__main__":
    run()
