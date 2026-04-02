"""Database migration: Add age_days field to vulnerabilities table"""

from sqlalchemy import text
from src.database.session import get_db_session

def upgrade():
    """Add age_days column to vulnerabilities table"""
    with get_db_session() as session:
        try:
            # Check if column already exists
            result = session.execute(text("PRAGMA table_info(vulnerabilities)"))
            columns = [row[1] for row in result.fetchall()]
            
            if 'age_days' not in columns:
                # Add the column
                session.execute(text("ALTER TABLE vulnerabilities ADD COLUMN age_days INTEGER"))
                session.commit()
                print("✓ Added age_days column to vulnerabilities table")
            else:
                print("✓ age_days column already exists")
        except Exception as e:
            session.rollback()
            print(f"✗ Migration failed: {e}")
            raise

def downgrade():
    """Remove age_days column from vulnerabilities table (not supported in SQLite)"""
    print("⚠️  SQLite doesn't support DROP COLUMN. Manual migration required.")

if __name__ == "__main__":
    print("Running migration: Add age_days to vulnerabilities table")
    upgrade()
    print("Migration complete")
