"""
FastAPI application entrypoint for Schwab Tamper-Evident Audit Log Service.
"""

from contextlib import asynccontextmanager
import os
import hashlib
import json
import tempfile
from pathlib import Path
from threading import Lock
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routers.audit import router as audit_router
from app.routers.lifecycle import router as lifecycle_router
from app.routers.compliance import router as compliance_router
from app.storage.database import get_engine, get_session_factory, init_db, initialize_ledger_state
from app.security import Principal
from app.services.verifier import ChainVerificationService
from app.runtime_state import get_state, set_state, preflight_scope
from app.rate_limit import enforce_ip_limit
from app.crypto.signer import validate_signing_configuration


MAX_REQUEST_BODY_BYTES = 256 * 1024


class RequestBodyLimitMiddleware:
    """Reject oversized HTTP bodies before application parsing buffers them."""

    def __init__(self, app, max_bytes: int = MAX_REQUEST_BODY_BYTES):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        content_length = next(
            (value for key, value in scope.get("headers", []) if key.lower() == b"content-length"),
            None,
        )
        if content_length is not None:
            try:
                if int(content_length) > self.max_bytes:
                    await self._reject(send)
                    return
            except ValueError:
                # Let normal request validation handle malformed framing.
                pass

        received = 0
        response_started = False
        overflowed = False
        rejection_sent = False

        async def limited_receive():
            nonlocal received, overflowed, response_started, rejection_sent
            if overflowed:
                return {"type": "http.disconnect"}
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    overflowed = True
                    if not response_started:
                        await self._reject(send)
                        response_started = True
                        rejection_sent = True
                    return {"type": "http.disconnect"}
            return message

        async def tracked_send(message):
            nonlocal response_started
            if rejection_sent:
                return
            if message.get("type") == "http.response.start":
                if response_started:
                    raise RuntimeError("ASGI response.start sent more than once")
                response_started = True
            await send(message)

        await self.app(scope, limited_receive, tracked_send)

    async def _reject(self, send):
        body = b'{"detail":"Request body too large"}'
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({"type": "http.response.body", "body": body})

# Engine and session creation
engine = get_engine(settings.DATABASE_URL)
SessionLocal = get_session_factory(engine)
_state_lock = Lock()
# Kept as a compatibility mirror; runtime_state is authoritative for guards.
service_state = "uninitialized"


def _quarantine_marker() -> Path:
    return Path(os.getenv("AUDIT_QUARANTINE_MARKER", "local_data/audit-quarantine.flag"))


def _persist_marker(reason: str) -> None:
    """Atomically persist quarantine state; failure is itself a quarantine condition."""
    marker = _quarantine_marker()
    marker.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{marker.name}.", dir=str(marker.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(reason + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, marker)
        try:
            directory_fd = os.open(str(marker.parent), os.O_DIRECTORY)
        except (AttributeError, OSError):
            directory_fd = None
        if directory_fd is not None:
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _recovery_consumed_path() -> Path:
    marker = _quarantine_marker()
    return marker.with_name(marker.name + ".recovery-consumed")


def _fsync_directory(directory: Path) -> bool:
    """Durably flush a directory entry where the platform supports it.

    Windows and filesystems without ``O_DIRECTORY`` cannot provide this
    guarantee; callers receive ``False`` and must document that limitation.
    Actual open/fsync failures are raised so recovery remains fail-closed.
    """
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if directory_flag is None:
        return False
    directory_fd = os.open(str(directory), directory_flag)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return True


def _consume_recovery_token() -> bool:
    """Atomically consume one recovery token on the configured filesystem.

    O_EXCL is the ownership decision: only one process can create the durable
    reservation. A reservation is intentionally retained if writing its outcome
    fails, preventing a failed attempt from making the token reusable.
    """
    token = os.getenv("AUDIT_QUARANTINE_RECOVERY_TOKEN", "")
    if not token:
        return False
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    consumed = _recovery_consumed_path()
    consumed.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(consumed), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(json.dumps({"tokenHash": digest, "outcome": "attempted"}) + "\n")
            stream.flush(); os.fsync(stream.fileno())
        _fsync_directory(consumed.parent)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    return True


def _record_recovery_outcome(outcome: str) -> None:
    if outcome not in {"attempted", "failed", "successful"}:
        raise ValueError("invalid recovery outcome")
    path = _recovery_consumed_path()
    current = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(current, dict)
        or not isinstance(current.get("tokenHash"), str)
        or not current["tokenHash"]
        or current.get("outcome") not in {"attempted", "failed", "successful"}
    ):
        raise ValueError("invalid recovery reservation state")
    current["outcome"] = outcome
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    try:
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(json.dumps(current) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def run_integrity_preflight() -> bool:
    """Verify the persisted ledger without changing any ledger rows."""
    global service_state
    with _state_lock:
        service_state = "validating"
    set_state("validating")
    marker = _quarantine_marker()
    try:
        marker_exists = marker.exists()
    except OSError:
        set_state("quarantined")
        return False
    if marker_exists:
        try:
            recovery = _consume_recovery_token()
        except OSError:
            recovery = False
        if not recovery:
            set_state("quarantined")
            return False
    session = None
    try:
        session = SessionLocal()
        with preflight_scope() as token:
            result = ChainVerificationService.verify_ledger(
                session,
                principal=Principal("startup-preflight", frozenset({"global_auditor"}), "internal-preflight"),
            )
        if not result.intact:
            _persist_marker("integrity preflight failed")
            if marker_exists:
                try:
                    _record_recovery_outcome("failed")
                except Exception:
                    pass
            set_state("quarantined")
            return False
    except Exception:
        try:
            _persist_marker("integrity preflight indeterminate")
        except Exception:
            pass
        if marker_exists:
            try:
                _record_recovery_outcome("failed")
            except Exception:
                pass
        set_state("quarantined")
        return False
    finally:
        if session is not None:
            session.close()
    if marker_exists:
        try:
            _record_recovery_outcome("successful")
            marker.unlink()
        except Exception:
            set_state("quarantined")
            return False
    with _state_lock:
        service_state = "healthy"
    set_state("healthy")
    return True


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Schema migration must complete before the read-only integrity preflight.
    try:
        init_db(engine)
        initialize_ledger_state(engine)
        validate_signing_configuration()
        run_integrity_preflight()
    except Exception:
        try:
            _persist_marker("startup migration/preflight failed")
        except Exception:
            # Marker storage failure is itself indeterminate; keep the process
            # quarantined without allowing startup to report a false healthy state.
            pass
        finally:
            set_state("quarantined")
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Production-grade, tamper-evident audit log microservice with cryptographic hash chaining, "
        "structured redaction, configurable retention policies, and compliance reporting."
    ),
    lifespan=lifespan,
)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    """Return safe validation details without echoing non-finite payloads."""
    details = [
        {"loc": list(error.get("loc", ())), "msg": error.get("msg", "Invalid request"), "type": error.get("type", "value_error")}
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": details})


@app.middleware("http")
async def quarantine_gate(request: Request, call_next):
    if request.url.path.startswith("/audit") and get_state() != "healthy":
        return JSONResponse(status_code=503, content={"detail": "Audit service is not ready"})
    if request.url.path.startswith("/audit"):
        try:
            enforce_ip_limit(request)
        except Exception as exc:
            if getattr(exc, "status_code", None) == 429:
                return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
            raise
    return await call_next(request)

# Enable CORS for frontend/dashboard access
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in settings.CORS_ORIGINS.split(",") if origin.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Keep this application-level guard in addition to any deployment-proxy limit.
# It protects requests whose body length is not declared by Content-Length.
app.add_middleware(RequestBodyLimitMiddleware, max_bytes=MAX_REQUEST_BODY_BYTES)

# Register routers
app.include_router(audit_router)
app.include_router(lifecycle_router)
app.include_router(compliance_router)


@app.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy" if get_state() == "healthy" else "quarantined",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }


@app.get("/ready", tags=["Health"])
def readiness_check():
    if get_state() != "healthy":
        return JSONResponse(status_code=503, content={"status": "not_ready"})
    return {"status": "ready"}
