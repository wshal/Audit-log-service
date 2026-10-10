import pytest

from tests.postgres.conftest import _database_url


@pytest.mark.parametrize(
    "value",
    [
        "postgresql://audit:audit@localhost:5432/audit_test",
        "sqlite:///audit_test.db",
        "postgresql+asyncpg://audit:audit@localhost:5432/audit_test",
    ],
)
def test_postgres_url_rejects_unsupported_scheme(monkeypatch, value):
    monkeypatch.setenv("POSTGRES_TEST_DATABASE_URL", value)
    with pytest.raises(RuntimeError, match=r"postgresql\+psycopg"):
        _database_url()


def test_postgres_url_accepts_declared_driver(monkeypatch):
    value = "postgresql+psycopg://audit:audit@localhost:5432/audit_test"
    monkeypatch.setenv("POSTGRES_TEST_DATABASE_URL", value)
    assert _database_url() == value


@pytest.mark.parametrize(
    "value, message",
    [
        ("postgresql+psycopg://audit:audit@example.invalid:5432/audit_test", "non-local"),
        ("postgresql+psycopg://audit:audit@localhost:5432/production", "isolated"),
    ],
)
def test_postgres_url_rejects_unsafe_target(monkeypatch, value, message):
    monkeypatch.setenv("POSTGRES_TEST_DATABASE_URL", value)
    with pytest.raises(RuntimeError, match=message):
        _database_url()
