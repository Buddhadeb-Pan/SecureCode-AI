"""
Database configuration and session management for SecureCode AI.
Compatible with SQLAlchemy 2.x and MySQL (via PyMySQL).
"""

import os
from typing import Generator
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session

# Ensure backend/.env is located reliably
env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
if os.path.exists(env_path):
    load_dotenv(dotenv_path=env_path, override=True)
else:
    load_dotenv(override=True)

DATABASE_URL = os.getenv("DATABASE_URL")



class Base(DeclarativeBase):
    """Base class for all SQLAlchemy declarative models."""
    pass


# Global engine and session factory holders
_main_engine = None
_main_sessionmaker = None
_test_engine = None
_test_sessionmaker = None

engine = None
SessionLocal = None


def is_test_environment() -> bool:
    """Returns True if test isolation is active via USE_TEST_DB environment variable."""
    return os.getenv("USE_TEST_DB", "").strip().lower() in ("1", "true", "yes")


def get_database_url() -> str:
    """
    Returns the appropriate database URL depending on whether test mode is active.
    Test mode points to TEST_DATABASE_URL (securecode_ai_test).
    Standard mode points to DATABASE_URL (securecode_ai).
    """
    if is_test_environment():
        test_url = os.getenv("TEST_DATABASE_URL")
        if test_url and test_url.strip():
            return test_url.strip()
        raise RuntimeError(
            "TEST_DATABASE_URL environment variable is not configured. "
            "Please set TEST_DATABASE_URL in your .env file."
        )

    url = os.getenv("DATABASE_URL")
    if not url or not url.strip():
        raise RuntimeError(
            "DATABASE_URL environment variable is not configured. "
            "Please set DATABASE_URL in your .env file. "
            "Expected format: dialect+driver://username:password@host:3306/database_name"
        )
    return url.strip()


def get_engine():
    """
    Initializes and returns the SQLAlchemy engine.
    Ensures correct isolation between main database and test database.
    Uses pool_pre_ping=True for resilient connection health checks.
    """
    global engine, SessionLocal, _main_engine, _main_sessionmaker, _test_engine, _test_sessionmaker

    if is_test_environment():
        if _test_engine is not None:
            return _test_engine
        test_url = get_database_url()
        _test_engine = create_engine(test_url, pool_pre_ping=True)
        _test_sessionmaker = sessionmaker(autocommit=False, autoflush=False, bind=_test_engine)
        # Automatically ensure test database tables exist
        try:
            from .models import User, PasswordResetToken, GuestTrial  # noqa: F401
            Base.metadata.create_all(bind=_test_engine)
        except Exception as e:
            print(f"[DB TEST WARNING] Table initialization on test DB: {e}")
        return _test_engine
    else:
        if _main_engine is not None:
            engine = _main_engine
            return _main_engine
        url = get_database_url()
        _main_engine = create_engine(url, pool_pre_ping=True)
        _main_sessionmaker = sessionmaker(autocommit=False, autoflush=False, bind=_main_engine)
        engine = _main_engine
        SessionLocal = _main_sessionmaker
        try:
            from .models import User, PasswordResetToken, GuestTrial  # noqa: F401
            Base.metadata.create_all(bind=_main_engine)
        except Exception as e:
            print(f"[DB INIT WARNING] Table initialization on main DB: {e}")
        return _main_engine


def get_session_factory():
    """Returns the configured session maker for the active database environment."""
    global SessionLocal, _main_sessionmaker, _test_sessionmaker
    if is_test_environment():
        if _test_sessionmaker is not None:
            return _test_sessionmaker
        get_engine()
        return _test_sessionmaker
    else:
        if _main_sessionmaker is not None:
            SessionLocal = _main_sessionmaker
            return _main_sessionmaker
        get_engine()
        SessionLocal = _main_sessionmaker
        return _main_sessionmaker


# Pre-initialize main engine if not in test mode
if not is_test_environment() and DATABASE_URL and DATABASE_URL.strip():
    try:
        get_engine()
    except Exception:
        # Avoid crashing imports if URL string has driver issues at import time
        pass


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that yields a database session per request
    and guarantees proper session teardown upon completion.
    """
    session_factory = get_session_factory()
    db = session_factory()
    try:
        yield db
    finally:
        db.close()
