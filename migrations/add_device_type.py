"""Database migration: Add device_type field to servers table"""

from sqlalchemy import text
from src.database.session import get_db_session

def upgrade():
    """Add device_type column to servers table"""
    with get_db_session() as session:
        try:
            # Check if column already exists
            result = session.execute(text("PRAGMA table_info(servers)"))
            columns = [row[1] for row in result.fetchall()]
            
            if 'device_type' not in columns:
                # Add the column
                session.execute(text("ALTER TABLE servers ADD COLUMN device_type VARCHAR(50) DEFAULT 'unknown'"))
                session.commit()
                print("✓ Added device_type column to servers table")
            else:
                print("✓ device_type column already exists")
        except Exception as e:
            session.rollback()
            print(f"✗ Migration failed: {e}")
            raise

def downgrade():
    """Remove device_type column from servers table (not supported in SQLite)"""
    print("⚠️  SQLite doesn't support DROP COLUMN. Manual migration required.")
    print("   To remove device_type: Recreate table without the column")

if __name__ == "__main__":
    print("Running migration: Add device_type to servers table")
    upgrade()
    print("Migration complete")
