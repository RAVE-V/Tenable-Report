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


def run_migrations():
    """Run all database migrations from migrations directory"""
    import os
    import importlib.util
    from pathlib import Path
    
    # Get project root (parent of src)
    project_root = Path(__file__).parent.parent.parent
    migrations_dir = project_root / "migrations"
    
    if not migrations_dir.exists():
        return
    
    # Get all .py files in migrations directory, sorted
    migration_files = sorted([f for f in migrations_dir.glob("*.py") if not f.name.startswith("__")])
    
    for migration_file in migration_files:
        module_name = f"migrations.{migration_file.stem}"
        spec = importlib.util.spec_from_file_location(module_name, migration_file)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            if hasattr(module, 'upgrade'):
                print(f"Running migration: {migration_file.name}")
                module.upgrade()


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
