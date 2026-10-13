"""Required Redis-backed rate-limit integration tests.

These tests intentionally use independent limiter objects against one real
Redis-compatible service; the in-memory unit tests do not prove distribution.
"""

from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest

from app.rate_limit import ConfiguredRateLimiter, RateLimitBackendUnavailable, RedisRateLimiter


@pytest.fixture
def redis_limiters():
    url = os.getenv("AUDIT_RATE_LIMIT_REDIS_URL", "").strip()
    required = os.getenv("AUDIT_RATE_LIMIT_REQUIRED", "0") == "1"
    if not url:
        if required:
            pytest.fail("AUDIT_RATE_LIMIT_REDIS_URL is required for distributed rate-limit tests")
        pytest.skip("Redis rate-limit integration is not configured")
    prefix = f"audit:test:ratelimit:{uuid4().hex}"
    try:
        first = RedisRateLimiter(url, prefix=prefix, connect_timeout=1.0, pool_size=8)
        second = RedisRateLimiter(url, prefix=prefix, connect_timeout=1.0, pool_size=8)
    except RateLimitBackendUnavailable as exc:
        if required:
            pytest.fail(str(exc))
        pytest.skip("Redis rate-limit integration is unavailable")
    yield first, second
    for client in (first, second):
        for key in client._client.scan_iter(match=f"{prefix}:*"):
            client._client.delete(key)


def test_independent_instances_enforce_one_combined_quota(redis_limiters):
    first, second = redis_limiters
    identity = "credential-id:tenant-a:GET:/audit/events"
    assert first.allow(identity, capacity=3, window=60)
    assert second.allow(identity, capacity=3, window=60)
    assert first.allow(identity, capacity=3, window=60)
    assert not second.allow(identity, capacity=3, window=60)
    key = next(first._client.scan_iter(match=f"{first._prefix}:*"))
    assert identity.encode() not in key


def test_concurrent_independent_instances_do_not_exceed_quota(redis_limiters):
    first, second = redis_limiters
    identity = "credential-id:tenant-a:POST:/audit/events"
    limiters = [first, second] * 10
    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(lambda limiter: limiter.allow(identity, capacity=5, window=60), limiters))
    assert sum(results) == 5


def test_distinct_authenticated_identities_have_independent_expiring_keys(redis_limiters):
    first, _ = redis_limiters
    assert first.allow("credential-a:tenant-a:GET:/audit/events", capacity=1, window=60)
    assert first.allow("credential-b:tenant-a:GET:/audit/events", capacity=1, window=60)
    assert first.ttl("credential-a:tenant-a:GET:/audit/events") > 0
    assert first.ttl("credential-b:tenant-a:GET:/audit/events") > 0


def test_shared_active_key_cardinality_is_bounded(redis_limiters):
    first, _ = redis_limiters
    bounded = RedisRateLimiter(
        os.environ["AUDIT_RATE_LIMIT_REDIS_URL"],
        prefix=f"{first._prefix}:bounded",
        connect_timeout=1.0,
        pool_size=4,
        max_keys=1,
    )
    assert bounded.allow("credential-a:tenant-a:GET:/audit/events", capacity=1, window=60)
    assert not bounded.allow("credential-b:tenant-a:GET:/audit/events", capacity=1, window=60)
    for key in bounded._client.scan_iter(match=f"{bounded._prefix}:*"):
        bounded._client.delete(key)


def test_expired_shared_window_allows_next_request(redis_limiters):
    first, _ = redis_limiters
    identity = "credential-a:tenant-a:GET:/audit/verify"
    assert first.allow(identity, capacity=1, window=1)
    assert not first.allow(identity, capacity=1, window=1)
    time.sleep(1.1)
    assert first.allow(identity, capacity=1, window=1)


def test_production_never_falls_back_to_process_local(monkeypatch):
    monkeypatch.setenv("AUDIT_ENV", "production")
    monkeypatch.setenv("AUDIT_RATE_LIMIT_BACKEND", "memory")
    with pytest.raises(RateLimitBackendUnavailable):
        ConfiguredRateLimiter().allow("credential-a", capacity=1, window=60)


def test_shared_backend_outage_is_reported(monkeypatch):
    monkeypatch.setenv("AUDIT_ENV", "production")
    monkeypatch.setenv("AUDIT_RATE_LIMIT_BACKEND", "redis")
    monkeypatch.setenv("AUDIT_RATE_LIMIT_REDIS_URL", "redis://127.0.0.1:6399/15")
    monkeypatch.setenv("AUDIT_RATE_LIMIT_REDIS_TIMEOUT_SECONDS", "0.05")
    with pytest.raises(RateLimitBackendUnavailable):
        ConfiguredRateLimiter().allow("credential-a", capacity=1, window=60)
