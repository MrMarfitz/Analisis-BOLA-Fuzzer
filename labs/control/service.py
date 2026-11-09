"""Deterministic local HTTP control service; policy is independent of scanner output."""
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODES = ("vulnerable", "protected", "public", "shared", "error200", "other-object", "expired", "timeout")
TOKENS = {"control-a-valid": "A", "control-b-valid": "B"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send_json(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        if self.path == "/login" and data.get("password") == "control-only-password" and data.get("username") in ("A", "B"):
            return self.send_json(200, {"token": "control-" + data["username"].lower() + "-valid"})
        self.send_json(401, {"error": "invalid credentials"})

    def do_GET(self):
        if self.path == "/health":
            return self.send_json(200, {"status": "ok"})
        if self.path == "/openapi.json":
            return self.send_json(200, {"openapi": "3.0.3", "info": {"title": "BOLA control", "version": "1.0"},
                "paths": {"/cases/" + m + "/objects/{id}": {"get": {"summary": m, "responses": {"200": {"description": "Object or error envelope"}}}} for m in MODES}})
        who = TOKENS.get(self.headers.get("Authorization", "").removeprefix("Bearer "))
        if not who:
            return self.send_json(401, {"error": "invalid or expired token"})
        if self.path == "/me":
            return self.send_json(200, {"id": who})
        parts = self.path.strip("/").split("/")
        if len(parts) not in (3, 4) or parts[0] != "cases" or parts[1] not in MODES or parts[2] != "objects":
            return self.send_json(404, {"error": "route not found"})
        mode = parts[1]
        if len(parts) == 3:
            return self.send_json(200, [{"id": "obj-" + who, "owner_id": who}])
        object_id = parts[3]
        owner = object_id.removeprefix("obj-")
        if owner not in ("A", "B"):
            return self.send_json(404, {"error": "object not found"})
        if who != owner:
            if mode == "protected":
                return self.send_json(403, {"error": "owner-only"})
            if mode == "expired":
                return self.send_json(401, {"error": "session expired during request"})
            if mode == "timeout":
                time.sleep(3)
            if mode == "error200":
                return self.send_json(200, {"error": "access denied", "message": "not authorized"})
            if mode == "other-object":
                object_id, owner = "obj-" + who, who
        self.send_json(200, {"id": object_id, "owner_id": owner, "private_note": "synthetic-private-" + owner})


def serve(port=8899):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server


if __name__ == "__main__":
    import os
    port = int(os.environ.get("CONTROL_PORT", "8899"))
    # Container binding is internal; published host port is loopback-only.
    server = ThreadingHTTPServer((os.environ.get("CONTROL_BIND", "127.0.0.1"), port), Handler)
    server.daemon_threads = True
    server.serve_forever()
