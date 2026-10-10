"""
Shared test database fixtures.
Ensures tables are created and dependency overrides cleanly point to the active test database.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_module
from app.crypto.signer import _private_key, public_key_ring
from app.routers.audit import get_db
from app.security import _credentials
from app.storage.database import Base
from app.runtime_state import set_state

@pytest.fixture(autouse=True)
def isolated_test_application(tmp_path, monkeypatch):
    """Bind app startup, request sessions, auth, and signing to one fresh DB."""
    database_file = tmp_path / "audit-test.db"
    database_url = f"sqlite:///{database_file.as_posix()}"
    engine = create_engine(database_url, connect_args={"check_same_thread": False})
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    monkeypatch.setenv("AUDIT_ENV", "development")
    monkeypatch.delenv("AUDIT_API_KEYS", raising=False)
    monkeypatch.delenv("AUDIT_SIGNING_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("AUDIT_SIGNING_PUBLIC_KEYS", raising=False)
    monkeypatch.setenv("AUDIT_DEVELOPMENT_KEY_PATH", str(tmp_path / "test-signing.key"))
    monkeypatch.setenv("AUDIT_QUARANTINE_MARKER", str(tmp_path / "quarantine.flag"))
    monkeypatch.delenv("AUDIT_QUARANTINE_RECOVERY", raising=False)
    monkeypatch.delenv("AUDIT_QUARANTINE_RECOVERY_TOKEN", raising=False)
    set_state("healthy")
    _credentials.cache_clear()
    _private_key.cache_clear()
    public_key_ring.cache_clear()

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr(main_module, "engine", engine)
    monkeypatch.setattr(main_module, "SessionLocal", session_factory)
    main_module.app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=engine)

    yield {"engine": engine, "session_factory": session_factory}

    main_module.app.dependency_overrides.clear()
    _credentials.cache_clear()
    _private_key.cache_clear()
    public_key_ring.cache_clear()
    engine.dispose()
    set_state("uninitialized")


@pytest.fixture
def client():
    with TestClient(main_module.app, headers={"X-API-Key": "development-only-audit-key"}) as test_client:
        yield test_client


@pytest.fixture
def db_session(isolated_test_application):
    db = isolated_test_application["session_factory"]()
    try:
        yield db
    finally:
        db.close()
