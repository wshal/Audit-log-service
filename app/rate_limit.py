"""Shared request rate limiting with an explicit local-development mode.

Production deployments must configure the Redis backend. The process-local
implementation remains available only when explicitly selected outside
production, so a missing shared backend can never silently degrade global
enforcement.
"""

from __future__ import annotations

import hashlib
import os
import time
from collections import OrderedDict
from threading import Lock

from fastapi import Depends, HTTPException, Request, status

from app.security import Principal, authenticated_principal


class RateLimitBackendUnavailable(RuntimeError):
    """The authoritative distributed limiter could not be used."""


def _positive_int(name: str, default: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(1, min(value, maximum))


def _positive_float(name: str, default: float, maximum: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(0.05, min(value, maximum))


class ProcessRateLimiter:
    """Bounded process-local limiter for development and deterministic tests."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._windows: OrderedDict[str, tuple[int, float]] = OrderedDict()

    def allow(self, key: str, *, capacity: int, window: float, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            count, started = self._windows.get(key, (0, now))
            if now - started >= window:
                count, started = 0, now
            count += 1
            self._windows[key] = (count, started)
            self._windows.move_to_end(key)
            maximum_entries = _positive_int("AUDIT_RATE_LIMIT_MAX_KEYS", 4096, 100_000)
            while len(self._windows) > maximum_entries:
                self._windows.popitem(last=False)
            return count <= capacity

    def clear(self) -> None:
        with self._lock:
            self._windows.clear()


class RedisRateLimiter:
    """Atomic fixed-window limiter backed by a Redis-compatible server."""

    _REGISTRY_CLEANUP_LIMIT = 128

    _INCREMENT_SCRIPT = """
    local member = KEYS[1]
    local registry = KEYS[2]
    local legacy_registry = KEYS[3]
    local max_keys = tonumber(ARGV[2])
    local cleanup_limit = tonumber(ARGV[3])
    local now = tonumber(redis.call('TIME')[1])
    local legacy_type = redis.call('TYPE', legacy_registry).ok
    if legacy_type ~= 'none' and legacy_type ~= 'set' then
        error('unexpected legacy rate-limit registry type')
    end
    if legacy_type == 'set' then
        local legacy_members = redis.call('SMEMBERS', legacy_registry)
        for _, legacy_member in ipairs(legacy_members) do
            if redis.call('EXISTS', legacy_member) == 1 then
                local ttl = redis.call('TTL', legacy_member)
                local expiry = now + tonumber(ARGV[1])
                if ttl > 0 then
                    expiry = now + ttl
                end
                redis.call('ZADD', registry, expiry, legacy_member)
            end
        end
        redis.call('DEL', legacy_registry)
    end
    local stale = redis.call('ZRANGEBYSCORE', registry, '-inf', now, 'LIMIT', 0, cleanup_limit)
    for _, stale_member in ipairs(stale) do
        redis.call('ZREM', registry, stale_member)
        redis.call('DEL', stale_member)
    end
    if redis.call('EXISTS', member) == 0 then
        if redis.call('ZCARD', registry) >= max_keys then
            return -1
        end
        redis.call('ZADD', registry, now + tonumber(ARGV[1]), member)
    end
    local current = redis.call('INCR', member)
    if current == 1 then
        redis.call('EXPIRE', member, ARGV[1])
    end
    return current
    """

    def __init__(self, url: str, *, prefix: str, connect_timeout: float, pool_size: int, max_keys: int = 4096) -> None:
        try:
            import redis
        except ImportError as exc:  # pragma: no cover - deployment dependency check
            raise RateLimitBackendUnavailable("Redis rate limiting dependency is unavailable") from exc
        try:
            self._client = redis.Redis.from_url(
                url,
                decode_responses=False,
                socket_connect_timeout=connect_timeout,
                socket_timeout=connect_timeout,
                max_connections=pool_size,
                health_check_interval=30,
            )
            self._client.ping()
        except Exception as exc:
            raise RateLimitBackendUnavailable("Rate-limit backend unavailable") from exc
        self._prefix = prefix
        self._max_keys = max_keys

    @staticmethod
    def _safe_component(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", "strict")).hexdigest()

    def _key(self, identity: str) -> str:
        # Never put API keys, raw tenant identifiers, or paths in Redis keys.
        return f"{self._prefix}:{self._safe_component(identity)}"

    def _registry(self) -> str:
        # Version the registry key because earlier releases used a Redis Set.
        # Reusing that key would make the sorted-set script fail with WRONGTYPE
        # during a rolling deployment.
        return f"{self._prefix}:registry:v2"

    def _legacy_registry(self) -> str:
        return f"{self._prefix}:registry"

    def allow(self, identity: str, *, capacity: int, window: float) -> bool:
        try:
            window_seconds = max(1, int(window))
            count = self._client.eval(
                self._INCREMENT_SCRIPT,
                3,
                self._key(identity),
                self._registry(),
                self._legacy_registry(),
                window_seconds,
                self._max_keys,
                self._REGISTRY_CLEANUP_LIMIT,
            )
            count = int(count)
            return count != -1 and count <= capacity
        except Exception as exc:
            raise RateLimitBackendUnavailable("Rate-limit backend unavailable") from exc

    def ttl(self, identity: str) -> int:
        try:
            return int(self._client.ttl(self._key(identity)))
        except Exception as exc:
            raise RateLimitBackendUnavailable("Rate-limit backend unavailable") from exc


class ConfiguredRateLimiter:
    """Select an explicit backend and fail closed when production is misconfigured."""

    def __init__(self) -> None:
        self._local = ProcessRateLimiter()
        self._redis: RedisRateLimiter | None = None
        self._redis_config: tuple[str, str, float, int, int] | None = None
        self._lock = Lock()

    def _backend(self) -> ProcessRateLimiter | RedisRateLimiter:
        environment = os.getenv("AUDIT_ENV", "development").lower()
        backend = os.getenv("AUDIT_RATE_LIMIT_BACKEND", "memory").lower()
        if environment == "production" and backend != "redis":
            raise RateLimitBackendUnavailable("Distributed rate limiting is required in production")
        if backend == "memory":
            if environment == "production":
                raise RateLimitBackendUnavailable("Distributed rate limiting is required in production")
            return self._local
        if backend != "redis":
            raise RateLimitBackendUnavailable("Unsupported rate-limit backend")
        url = os.getenv("AUDIT_RATE_LIMIT_REDIS_URL", "").strip()
        if not url:
            raise RateLimitBackendUnavailable("Rate-limit backend is not configured")
        prefix = os.getenv("AUDIT_RATE_LIMIT_REDIS_PREFIX", "audit:ratelimit:v1").strip()
        timeout = _positive_float("AUDIT_RATE_LIMIT_REDIS_TIMEOUT_SECONDS", 0.5, 10.0)
        pool_size = _positive_int("AUDIT_RATE_LIMIT_REDIS_MAX_CONNECTIONS", 16, 256)
        max_keys = _positive_int("AUDIT_RATE_LIMIT_REDIS_MAX_KEYS", 4096, 100_000)
        config = (url, prefix, timeout, pool_size, max_keys)
        with self._lock:
            if self._redis is None or self._redis_config != config:
                self._redis = RedisRateLimiter(
                    url,
                    prefix=prefix,
                    connect_timeout=timeout,
                    pool_size=pool_size,
                    max_keys=max_keys,
                )
                self._redis_config = config
            return self._redis

    def allow(self, key: str, *, capacity: int, window: float, now: float | None = None) -> bool:
        backend = self._backend()
        if isinstance(backend, ProcessRateLimiter):
            return backend.allow(key, capacity=capacity, window=window, now=now)
        return backend.allow(key, capacity=capacity, window=window)

    def clear(self) -> None:
        self._local.clear()


limiter = ConfiguredRateLimiter()


def _limits() -> tuple[int, float]:
    capacity = _positive_int("AUDIT_RATE_LIMIT_CAPACITY", 1000, 1_000_000)
    window = _positive_float("AUDIT_RATE_LIMIT_WINDOW_SECONDS", 60.0, 86_400.0)
    return capacity, window


def _client_key(request: Request) -> str:
    client = request.client
    return client.host if client and client.host else "unknown-client"


def _reject_or_unavailable(
    key: str,
    *,
    capacity: int,
    window: float,
    backend: ConfiguredRateLimiter,
) -> None:
    try:
        allowed = backend.allow(key, capacity=capacity, window=window)
    except RateLimitBackendUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate-limit service unavailable",
        ) from exc
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(max(1, int(window)))},
        )


def _request_limiter(request: Request) -> ConfiguredRateLimiter:
    """Use the limiter owned by the ASGI application, when provided."""
    return getattr(request.app.state, "rate_limiter", limiter)


def enforce_ip_limit(request: Request) -> None:
    capacity, window = _limits()
    _reject_or_unavailable(
        f"ip:{_client_key(request)}",
        capacity=capacity,
        window=window,
        backend=_request_limiter(request),
    )


def enforce_authenticated_limit(
    request: Request,
    principal: Principal = Depends(authenticated_principal),
) -> Principal:
    capacity, window = _limits()
    # credential_id is an authenticated manifest/configuration value. Do not
    # use caller-supplied identity headers or API-key material in the key.
    identity = principal.credential_id or principal.subject
    operation = f"{request.method}:{request.url.path}"
    _reject_or_unavailable(
        f"principal:{identity}:{operation}",
        capacity=capacity,
        window=window,
        backend=_request_limiter(request),
    )
    return principal
