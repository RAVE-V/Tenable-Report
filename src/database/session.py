"""Database session management"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from contextlib import contextmanager

from src.config import Config
from src.database.models import Base

# Create engine
engine = create_engine(
    Config.DATABASE_URL,
    echo=False,  # Set to True for SQL query logging
    pool_pre_ping=True,  # Verify connections before using
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Thread-safe session
Session = scoped_session(SessionLocal)


def init_db():
    """Initialize database - create all tables"""
    Base.metadata.create_all(bind=engine)


def drop_db():
    """Drop all tables - WARNING: Use with caution!"""
    Base.metadata.drop_all(bind=engine)


@contextmanager
def get_db_session():
    """
    Context manager for database sessions.
    Ensures proper session cleanup.
    
    Usage:
        with get_db_session() as session:
            # Use session
            session.query(Server).all()
    """
    session = Session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
