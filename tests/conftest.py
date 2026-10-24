"""Keep unit tests away from the real security database."""

import pytest

from app.db.security_store import get_security_store
from app.security.service import get_security_service


@pytest.fixture(autouse=True)
def isolated_security_db(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_DATABASE_PATH", str(tmp_path / "security.sqlite3"))
    get_security_store.cache_clear()
    get_security_service.cache_clear()
    yield
    get_security_store.cache_clear()
    get_security_service.cache_clear()
