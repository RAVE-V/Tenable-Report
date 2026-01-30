import sys
import os
import logging
from datetime import datetime

# Add src to path
sys.path.append(os.getcwd())

from src.database.models import Base, Vulnerability
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

def test_integrity_error():
    # Setup in-memory SQLite db
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # Create dummy data with duplicates
    vuln1 = {
        "asset_uuid": "asset-1",
        "plugin_id": "1001",
        "vuln_id": "v1",
        "severity": "High",
        "state": "ACTIVE"
    }
    
    # Duplicate of vuln1 (same asset_uuid + plugin_id)
    vuln2 = {
        "asset_uuid": "asset-1",
        "plugin_id": "1001",
        "vuln_id": "v2",
        "severity": "Medium", # Different severity to show it's a different record
        "state": "ACTIVE"
    }

    print("Attempting to insert duplicate vulnerabilities...")
    try:
        v1 = Vulnerability(**vuln1)
        v2 = Vulnerability(**vuln2)
        session.add(v1)
        session.add(v2)
        session.commit()
        print("❌ FAILED: Duplicate inserted successfully (unexpected)")
    except Exception as e:
        print(f"✅ SUCCESS: Caught expected error: {e}")

if __name__ == "__main__":
    test_integrity_error()
