"""Database migration: Add system_owner field to applications table"""

from sqlalchemy import text
from src.database.session import get_db_session


def upgrade():
    """Add system_owner column to applications table"""
    with get_db_session() as session:
        try:
            # Check if column already exists
            result = session.execute(text("PRAGMA table_info(applications)"))
            columns = [row[1] for row in result.fetchall()]
            
            if 'system_owner' not in columns:
                # Add the column
                session.execute(text("ALTER TABLE applications ADD COLUMN system_owner VARCHAR(255)"))
                session.commit()
                print("[OK] Added system_owner column to applications table")
            else:
                print("[OK] system_owner column already exists")
        except Exception as e:
            session.rollback()
            print(f"[ERR] Migration failed: {e}")
            raise


def downgrade():
    """Remove system_owner column from applications table (not supported in SQLite)"""
    print("[WARN] SQLite doesn't support DROP COLUMN. Manual migration required.")
    print("   To remove system_owner: Recreate table without the column")


if __name__ == "__main__":
    print("Running migration: Add system_owner to applications table")
    upgrade()
    print("Migration complete")
