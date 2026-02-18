"""Database connectivity tests."""
import pytest
from sqlalchemy import text


def test_db_connection(db_session):
    """Test database connection is working."""
    result = db_session.execute(text("SELECT 1"))
    assert result.scalar() == 1


def test_db_session_factory(db_session):
    """Test database session factory works."""
    assert db_session is not None
    # Should be able to execute queries
    result = db_session.execute(text("SELECT 1 + 1 as sum"))
    assert result.scalar() == 2
