from __future__ import annotations

import json
import os
import re
import uuid
from collections.abc import Mapping
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .audit import AuditLedger
from .compiler import compile_policy
from .engine import AuthorizationEngine
from .models import AuthorizationRequest, Decision, Principal, Resource
from .store import PolicyFileStore

MAX_BODY_BYTES = 1_048_576
_POLICY_PATH = re.compile(r"^/v1/tenants/([a-zA-Z0-9][a-zA-Z0-9._-]{0,63})/policy$")


class PolicyForgeApplication:
    def __init__(self, data_directory: Path, audit_key: bytes) -> None:
        self.store = PolicyFileStore(data_directory / "policies")
        self.audit = AuditLedger(data_directory / "audit.jsonl", audit_key)
        self.engine = AuthorizationEngine(decision_sink=self.audit)
        for document in self.store.load_all():
            self.engine.publish(compile_policy(document))

    def publish(self, tenant_id: str, document: Mapping[str, Any]) -> int:
        policy = compile_policy(document)
        if policy.tenant_id != tenant_id:
            raise ValueError("path tenant and policy tenant_id must match")
        self.engine.publish(policy)
        self.store.save(tenant_id, document)
        return policy.version


class Handler(BaseHTTPRequestHandler):
    server: "PolicyForgeServer"

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health/live":
            self._json(HTTPStatus.OK, {"status": "ok"})
            return
        if self.path == "/health/ready":
            entries = self.server.application.audit.verify()
            self._json(HTTPStatus.OK, {"status": "ready", "audit_entries": entries})
            return
        self._json(HTTPStatus.NOT_FOUND, _error("not_found", "route was not found"))

    def do_PUT(self) -> None:  # noqa: N802
        match = _POLICY_PATH.fullmatch(self.path)
        if match is None:
            self._json(HTTPStatus.NOT_FOUND, _error("not_found", "route was not found"))
            return
        self._handle(lambda: self._publish(match.group(1)))

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/decisions":
            self._json(HTTPStatus.NOT_FOUND, _error("not_found", "route was not found"))
            return
        self._handle(self._decide)

    def log_message(self, format: str, *args: object) -> None:
        message = format % args
        print(json.dumps({"level": "info", "client": self.client_address[0], "message": message}))

    def _publish(self, tenant_id: str) -> None:
        document = self._read_json()
        version = self.server.application.publish(tenant_id, document)
        self._json(HTTPStatus.OK, {"tenant_id": tenant_id, "version": version})

    def _decide(self) -> None:
        request = _authorization_request(self._read_json())
        decision = self.server.application.engine.authorize(request)
        self._json(HTTPStatus.OK, _decision_document(decision))

    def _handle(self, operation: Any) -> None:
        try:
            operation()
        except (KeyError, TypeError, ValueError) as error:
            self._json(HTTPStatus.BAD_REQUEST, _error("invalid_request", str(error)))
        except Exception:
            self._json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                _error("internal_error", "an unexpected error occurred"),
            )

    def _read_json(self) -> dict[str, Any]:
        if not self.headers.get("Content-Type", "").lower().startswith("application/json"):
            raise ValueError("content-type must be application/json")
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise ValueError("content-length is required")
        length = int(raw_length)
        if not 0 < length <= MAX_BODY_BYTES:
            raise ValueError("request body must contain between 1 byte and 1 MiB")
        document = json.loads(self.rfile.read(length))
        if not isinstance(document, dict):
            raise TypeError("request body must be a JSON object")
        return document

    def _json(self, status: HTTPStatus, document: Mapping[str, Any]) -> None:
        body = (json.dumps(document, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)


class PolicyForgeServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], application: PolicyForgeApplication) -> None:
        self.application = application
        super().__init__(address, Handler)


def main() -> None:
    audit_key = os.environ.get("POLICYFORGE_AUDIT_KEY")
    if audit_key is None or len(audit_key.encode()) < 32:
        raise SystemExit("POLICYFORGE_AUDIT_KEY must contain at least 32 bytes")
    data_directory = Path(os.environ.get("POLICYFORGE_DATA", ".policyforge"))
    port = int(os.environ.get("PORT", "8080"))
    if not 1 <= port <= 65_535:
        raise SystemExit("PORT must be between 1 and 65535")
    server = PolicyForgeServer(("0.0.0.0", port), PolicyForgeApplication(data_directory, audit_key.encode()))
    print(json.dumps({"level": "info", "message": "policyforge ready", "port": port}))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def _authorization_request(document: Mapping[str, Any]) -> AuthorizationRequest:
    principal = _object(document, "principal")
    resource = _object(document, "resource")
    roles = principal.get("roles", [])
    if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
        raise TypeError("principal.roles must be a string array")
    return AuthorizationRequest(
        request_id=_string(document, "request_id", default=str(uuid.uuid4())),
        action=_string(document, "action"),
        principal=Principal(
            principal_id=_string(principal, "id"),
            tenant_id=_string(principal, "tenant_id"),
            roles=frozenset(roles),
            attributes=_object(principal, "attributes", default={}),
        ),
        resource=Resource(
            resource_type=_string(resource, "type"),
            resource_id=_string(resource, "id"),
            tenant_id=_string(resource, "tenant_id"),
            attributes=_object(resource, "attributes", default={}),
        ),
        environment=_object(document, "environment", default={}),
    )


def _decision_document(decision: Decision) -> dict[str, Any]:
    return {
        "request_id": decision.request_id,
        "allowed": decision.allowed,
        "reason": decision.reason,
        "policy_version": decision.policy_version,
        "matched_rule_ids": list(decision.matched_rule_ids),
        "obligations": dict(decision.obligations),
        "cache_hit": decision.cache_hit,
    }


def _object(
    document: Mapping[str, Any], field: str, *, default: Mapping[str, Any] | None = None
) -> Mapping[str, Any]:
    value = document.get(field, default)
    if not isinstance(value, Mapping):
        raise TypeError(f"{field} must be an object")
    return value


def _string(document: Mapping[str, Any], field: str, *, default: str | None = None) -> str:
    value = document.get(field, default)
    if not isinstance(value, str) or not value or len(value) > 200:
        raise TypeError(f"{field} must be a non-empty string of at most 200 characters")
    return value


def _error(code: str, message: str) -> dict[str, Any]:
    return {"error": {"code": code, "message": message}}


if __name__ == "__main__":
    main()
