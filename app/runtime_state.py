"""Process readiness state shared by HTTP and direct service entry points."""

from contextlib import contextmanager
from contextvars import ContextVar
from threading import Lock
from fastapi import HTTPException

_lock = Lock()
_state = "uninitialized"
_PREFLIGHT_TOKEN = object()
_internal_scope: ContextVar[object | None] = ContextVar("audit_internal_scope", default=None)


def get_state() -> str:
    with _lock:
        return _state


def set_state(value: str) -> None:
    global _state
    with _lock:
        _state = value


def ensure_ready(*, internal_token=None) -> None:
    if internal_token is _PREFLIGHT_TOKEN or _internal_scope.get() is _PREFLIGHT_TOKEN:
        return
    if get_state() != "healthy":
        raise HTTPException(status_code=503, detail="Audit service is not ready")


@contextmanager
def preflight_scope():
    """Narrow internal escape hatch used only around read-only startup verification."""
    reset = _internal_scope.set(_PREFLIGHT_TOKEN)
    try:
        yield _PREFLIGHT_TOKEN
    finally:
        _internal_scope.reset(reset)
