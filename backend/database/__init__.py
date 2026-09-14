"""
Database foundation package for SecureCode AI.
Exports core declarative Base, engine, SessionLocal, get_db dependency, and User model.
"""

from .database import Base, engine, SessionLocal, get_db, get_engine
from .models import User, PasswordResetToken, GuestTrial

__all__ = [
    "Base",
    "engine",
    "SessionLocal",
    "get_db",
    "get_engine",
    "User",
    "PasswordResetToken",
    "GuestTrial",
]

