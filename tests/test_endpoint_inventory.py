"""Executable security inventory and request-boundary regressions."""

import asyncio
import json

from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
import pytest

from app.main import MAX_REQUEST_BODY_BYTES, app
from app.security import _credentials
from app.rate_limit import limiter


def _registered_api_routes(application):
    for included in application.routes:
        if isinstance(included, APIRoute):
            yield included
            continue
        original_router = getattr(included, "original_router", None)
        if original_router is None:
            continue
        yield from (route for route in original_router.routes if isinstance(route, APIRoute))


def test_registered_routes_have_explicit_security_inventory():
    routes = {
        (method, route.path)
        for route in _registered_api_routes(app)
        if route.path.startswith("/audit")
        for method in route.methods
    }
    assert routes == {
        ("POST", "/audit/events"),
        ("GET", "/audit/events"),
        ("GET", "/audit/verify"),
        ("POST", "/audit/retention/apply"),
        ("POST", "/audit/redact"),
        ("GET", "/audit/export"),
        ("GET", "/audit/compliance/client-access"),
    }
    for route in _registered_api_routes(app):
        if not route.path.startswith("/audit"):
            continue
        dependency_names = {getattr(dependency.call, "__name__", "") for dependency in route.dependant.dependencies}
        assert "enforce_authenticated_limit" in dependency_names, route.path
        assert "dependency" in dependency_names, route.path  # require_roles(...) closure

    assert {("GET", "/health"), ("GET", "/ready")} <= {
        (method, route.path) for route in _registered_api_routes(app)
        for method in route.methods
    }


def test_directly_registered_api_routes_are_visible_to_inventory():
    application = FastAPI()

    @application.get("/audit/direct-test")
    def direct_route():
        return {"ok": True}

    assert any(route.path == "/audit/direct-test" for route in _registered_api_routes(application))


def test_protected_routes_reject_missing_or_invalid_credentials(client):
    assert client.get("/audit/events", headers={"X-API-Key": "not-valid"}).status_code == 401
    assert client.get("/audit/verify", headers={"X-API-Key": "not-valid"}).status_code == 401
    assert client.get("/audit/export?resourceId=client-a", headers={"X-API-Key": "not-valid"}).status_code == 401
    assert client.get("/audit/compliance/client-access?clientId=client-a", headers={"X-API-Key": "not-valid"}).status_code == 401


def test_state_changing_route_requires_role_and_resource_scope(monkeypatch, client):
    monkeypatch.setenv(
        "AUDIT_API_KEYS",
        json.dumps({
            "reader-key": {
                "subject": "reader",
                "roles": ["reader"],
                "credentialId": "reader-credential",
            },
            "writer-key": {
                "subject": "alice",
                "roles": ["writer"],
                "credentialId": "writer-credential",
                "tenantGrants": [{
                    "tenantId": "tenant-a",
                    "actions": ["write"],
                    "resourceScopes": [{"resourceType": "CLIENT_ACCOUNT", "resourceIds": ["client-a"]}],
                }],
            },
        }),
    )
    monkeypatch.setenv("AUDIT_RESOURCE_OWNERSHIP", '{"CLIENT_ACCOUNT:client-a":"tenant-a"}')
    from app.authorization import clear_authorization_caches
    clear_authorization_caches()
    _credentials.cache_clear()
    body = {
        "eventType": "ACCOUNT_VIEWED",
        "actorId": "alice",
        "resourceType": "CLIENT_ACCOUNT",
        "resourceId": "client-a",
        "tenantId": "tenant-a",
        "payload": {"justification": "security test"},
        "timestamp": "2026-01-01T00:00:00Z",
    }
    assert client.post("/audit/events", json=body, headers={"X-API-Key": "reader-key"}).status_code == 403
    foreign = {**body, "resourceId": "client-b"}
    assert client.post("/audit/events", json=foreign, headers={"X-API-Key": "writer-key"}).status_code == 403


def test_request_body_limit_accepts_boundary_and_rejects_declared_oversize(client):
    boundary = b"x" * MAX_REQUEST_BODY_BYTES
    assert client.request("GET", "/health", content=boundary).status_code == 200
    oversized = b"x" * (MAX_REQUEST_BODY_BYTES + 1)
    response = client.post("/audit/events", content=oversized, headers={"Content-Type": "application/json"})
    assert response.status_code == 413
    assert response.json() == {"detail": "Request body too large"}


def test_request_body_limit_rejects_oversize_stream_and_allows_followup(client):
    from app.main import RequestBodyLimitMiddleware

    messages = [
        {"type": "http.request", "body": b"x" * (MAX_REQUEST_BODY_BYTES // 2), "more_body": True},
        {"type": "http.request", "body": b"y" * (MAX_REQUEST_BODY_BYTES // 2 + 1), "more_body": False},
    ]
    sent = []

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    async def downstream(scope, receive, send):
        while (await receive()).get("more_body"):
            pass

    middleware = RequestBodyLimitMiddleware(downstream)
    asyncio.run(middleware({"type": "http", "headers": []}, receive, send))
    assert sent[0]["status"] == 413
    assert client.get("/health").status_code == 200


def test_overflow_after_response_start_forwards_complete_downstream_response():
    from app.main import RequestBodyLimitMiddleware

    messages = [{"type": "http.request", "body": b"x" * (MAX_REQUEST_BODY_BYTES + 1), "more_body": False}]
    sent = []

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    async def downstream(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        message = await receive()
        assert message["type"] == "http.disconnect"
        await send({"type": "http.response.body", "body": b"downstream-complete", "more_body": False})

    asyncio.run(RequestBodyLimitMiddleware(downstream)({"type": "http", "headers": []}, receive, send))
    assert sent == [
        {"type": "http.response.start", "status": 200, "headers": []},
        {"type": "http.response.body", "body": b"downstream-complete", "more_body": False},
    ]


def test_duplicate_response_start_is_rejected_without_forwarding_second_event():
    from app.main import RequestBodyLimitMiddleware

    sent = []

    async def receive():
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    async def downstream(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.start", "status": 500, "headers": []})

    with pytest.raises(RuntimeError, match="response.start sent more than once"):
        asyncio.run(RequestBodyLimitMiddleware(downstream)({"type": "http", "headers": []}, receive, send))
    assert sent == [{"type": "http.response.start", "status": 200, "headers": []}]


def test_full_application_stream_overflow_returns_413(client):
    from app.runtime_state import set_state

    set_state("healthy")
    messages = [
        {"type": "http.request", "body": b"x" * (MAX_REQUEST_BODY_BYTES // 2), "more_body": True},
        {"type": "http.request", "body": b"y" * (MAX_REQUEST_BODY_BYTES // 2 + 1), "more_body": False},
    ]
    sent = []

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    async def invoke():
        await app({
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/audit/events",
            "raw_path": b"/audit/events",
            "query_string": b"",
            "headers": [(b"content-type", b"application/json")],
            "client": ("127.0.0.1", 1),
            "server": ("127.0.0.1", 8000),
        }, receive, send)

    asyncio.run(invoke())
    assert [message.get("status") for message in sent if message["type"] == "http.response.start"] == [413]
    assert sent[-1]["body"] == b'{"detail":"Request body too large"}'
    assert client.get("/health").status_code == 200


def test_protected_endpoint_returns_429_after_controlled_limit(monkeypatch, client):
    monkeypatch.setenv("AUDIT_RATE_LIMIT_CAPACITY", "1")
    monkeypatch.setenv("AUDIT_RATE_LIMIT_WINDOW_SECONDS", "60")
    limiter.clear()
    assert client.get("/audit/events?limit=1").status_code == 200
    assert client.get("/audit/events?limit=1").status_code == 429
    limiter.clear()


def test_valid_small_request_remains_usable_after_body_guard(client):
    body = {
        "eventType": "ACCOUNT_VIEWED",
        "actorId": "local-development",
        "resourceType": "CLIENT_ACCOUNT",
        "resourceId": "client-a",
        "payload": {"justification": "body-limit regression"},
        "timestamp": "2026-01-01T00:00:00Z",
    }
    response = client.post("/audit/events", json=body)
    assert response.status_code == 201
