"""Database migration: Update device_type for servers from vulnerability data"""

from sqlalchemy import text
from src.database.session import get_db_session
from src.database.models import Server, Vulnerability


def upgrade():
    """Update server device_type from vulnerability data"""
    with get_db_session() as session:
        try:
            # Get all servers with unknown device_type
            servers = session.query(Server).filter(
                (Server.device_type == 'unknown') | (Server.device_type == None)
            ).all()
            
            updated_count = 0
            for server in servers:
                # Try to find device_type from vulnerability data
                # Match by hostname or asset_uuid
                vuln = session.query(Vulnerability.device_type).filter(
                    (Vulnerability.hostname == server.hostname) |
                    (Vulnerability.asset_uuid == server.asset_uuid)
                ).filter(
                    Vulnerability.device_type != None,
                    Vulnerability.device_type != ''
                ).first()
                
                if vuln and vuln.device_type:
                    server.device_type = vuln.device_type
                    updated_count += 1
                    print(f"  [UPD] {server.hostname}: {vuln.device_type}")
            
            session.commit()
            print(f"\n[OK] Updated device_type for {updated_count} servers")
            
        except Exception as e:
            session.rollback()
            print(f"[ERR] Migration failed: {e}")
            raise


if __name__ == "__main__":
    print("Running migration: Sync server device_type from vulnerability data")
    upgrade()
    print("Migration complete")
