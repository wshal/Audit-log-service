"""Bounded process-local request rate limiting.

This limiter is deliberately not presented as a distributed/global quota. A
deployment with multiple workers must provide a shared limiter if global
enforcement is required.
"""

from __future__ import annotations

import os
import time
from collections import OrderedDict
from threading import Lock

from fastapi import Depends, HTTPException, Request, status

from app.security import Principal, authenticated_principal


def _positive_int(name: str, default: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(1, min(value, maximum))


class ProcessRateLimiter:
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


limiter = ProcessRateLimiter()


def _limits() -> tuple[int, float]:
    capacity = _positive_int("AUDIT_RATE_LIMIT_CAPACITY", 1000, 1_000_000)
    try:
        window = float(os.getenv("AUDIT_RATE_LIMIT_WINDOW_SECONDS", "60"))
    except ValueError:
        window = 60.0
    return capacity, max(1.0, min(window, 86_400.0))


def _client_key(request: Request) -> str:
    client = request.client
    return client.host if client and client.host else "unknown-client"


def enforce_ip_limit(request: Request) -> None:
    capacity, window = _limits()
    if not limiter.allow(f"ip:{_client_key(request)}", capacity=capacity, window=window):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")


def enforce_authenticated_limit(
    request: Request,
    principal: Principal = Depends(authenticated_principal),
) -> Principal:
    capacity, window = _limits()
    # credential_id is an authenticated manifest/configuration value. Do not
    # use caller-supplied identity headers or API-key material in the key.
    identity = principal.credential_id or principal.subject
    operation = f"{request.method}:{request.url.path}"
    if not limiter.allow(f"principal:{identity}:{operation}", capacity=capacity, window=window):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")
    return principal
