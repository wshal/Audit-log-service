"""Regression tests for the bounded API abuse limiter."""

import json

import pytest

from app.rate_limit import limiter


@pytest.fixture(autouse=True)
def reset_limiter(monkeypatch):
    limiter.clear()
    monkeypatch.setenv("AUDIT_RATE_LIMIT_CAPACITY", "2")
    monkeypatch.setenv("AUDIT_RATE_LIMIT_WINDOW_SECONDS", "60")
    monkeypatch.setenv("AUDIT_RATE_LIMIT_MAX_KEYS", "8")
    yield
    limiter.clear()


def test_authenticated_requests_are_limited_with_429_and_no_secret(client):
    assert client.get("/health").status_code == 200
    assert client.get("/audit/events?limit=1").status_code == 200
    assert client.get("/audit/events?limit=1").status_code == 200
    response = client.get("/audit/events?limit=1", headers={"X-API-Key": "development-only-audit-key"})
    assert response.status_code == 429
    assert "development-only-audit-key" not in response.text


def test_limiter_keys_are_bounded_and_expire(monkeypatch):
    from app.rate_limit import ProcessRateLimiter

    local = ProcessRateLimiter()
    for index in range(20):
        local.allow(f"key-{index}", capacity=1, window=60, now=0)
    assert len(local._windows) <= 8
    assert local.allow("key-0", capacity=1, window=60, now=61)


def test_unauthenticated_audit_abuse_is_bounded(client):
    # The IP limiter runs before authentication and therefore also protects
    # invalid-key traffic without trusting caller-supplied identity headers.
    assert client.get("/audit/events", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/audit/events", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/audit/events", headers={"X-API-Key": "wrong"}).status_code == 429
