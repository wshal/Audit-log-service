import os
from urllib.parse import urlparse

import pytest
from sqlalchemy import create_engine, text


def _database_url() -> str | None:
    value = os.getenv("POSTGRES_TEST_DATABASE_URL")
    if not value:
        return None
    parsed = urlparse(value)
    if parsed.scheme != "postgresql+psycopg":
        raise RuntimeError("POSTGRES_TEST_DATABASE_URL must use postgresql+psycopg")
    if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise RuntimeError("PostgreSQL tests refuse non-local hosts")
    if parsed.path.lstrip("/") != "audit_test":
        raise RuntimeError("PostgreSQL tests require the isolated audit_test database")
    return value


@pytest.fixture()
def postgres_engine():
    url = _database_url()
    if not url:
        if os.getenv("POSTGRES_TEST_REQUIRED") == "1":
            pytest.fail("POSTGRES_TEST_DATABASE_URL is required for the PostgreSQL CI job")
        pytest.skip("POSTGRES_TEST_DATABASE_URL is not configured")
    engine = create_engine(url, pool_pre_ping=True)
    try:
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
        yield engine
    finally:
        engine.dispose()
