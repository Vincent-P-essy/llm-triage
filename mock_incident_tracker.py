#!/usr/bin/env python3
"""Small local incident tracker API for demos and development."""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


INCIDENTS = {
    "INC-001": {
        "id": "INC-001",
        "title": "Suspicious login from TOR exit node",
        "description": "Multiple failed logins followed by a successful login from a TOR exit node.",
        "source_ip": "198.51.100.42",
        "severity": "MEDIUM",
        "status": "open",
        "created_at": "2026-06-14T08:23:45Z",
    },
    "INC-002": {
        "id": "INC-002",
        "title": "SQL Injection attempt",
        "description": "Anomalous SQL payload detected in the online banking login form.",
        "source_ip": "10.10.0.5",
        "severity": "HIGH",
        "status": "open",
        "created_at": "2026-06-14T09:04:10Z",
    },
    "INC-003": {
        "id": "INC-003",
        "title": "Payment data exfiltration alert",
        "description": "Possible exfiltration of payment records from a PCI-scoped database.",
        "source_ip": "203.0.113.77",
        "severity": "CRITICAL",
        "status": "open",
        "created_at": "2026-06-14T10:15:00Z",
    },
}


class IncidentTrackerHandler(BaseHTTPRequestHandler):
    """HTTP handler implementing the incident tracker contract used by llm-triage."""

    server_version = "MockIncidentTracker/0.1"

    def _send_json(self, status: int, payload: object) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: int, message: str) -> None:
        self._send_json(status, {"error": message})

    def _incident_id_from_path(self) -> str | None:
        prefix = "/api/incidents/"
        if self.path.startswith(prefix):
            return self.path[len(prefix):].split("?", 1)[0]
        return None

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)

        if parsed.path == "/api/incidents":
            query = parse_qs(parsed.query)
            status_filter = query.get("status", [None])[0]
            incidents = list(INCIDENTS.values())
            if status_filter:
                incidents = [
                    incident
                    for incident in incidents
                    if incident.get("status") == status_filter
                ]
            self._send_json(200, incidents)
            return

        incident_id = self._incident_id_from_path()
        if incident_id:
            incident = INCIDENTS.get(incident_id)
            if incident is None:
                self._send_error(404, f"Incident {incident_id} not found")
                return
            self._send_json(200, incident)
            return

        self._send_error(404, "Not found")

    def do_PATCH(self) -> None:  # noqa: N802
        incident_id = self._incident_id_from_path()
        if not incident_id:
            self._send_error(404, "Not found")
            return

        incident = INCIDENTS.get(incident_id)
        if incident is None:
            self._send_error(404, f"Incident {incident_id} not found")
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length) if content_length else b"{}"

        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError:
            self._send_error(400, "Invalid JSON body")
            return

        incident.update(payload)
        self._send_json(200, incident)

    def log_message(self, format: str, *args: object) -> None:
        print(f"{self.address_string()} - {format % args}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a local mock incident tracker API.")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to.")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind to.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    server = ThreadingHTTPServer((args.host, args.port), IncidentTrackerHandler)
    print(f"Mock incident tracker running at http://{args.host}:{args.port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping mock incident tracker.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
