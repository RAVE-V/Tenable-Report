import sys
import os
import unittest
from unittest.mock import MagicMock, patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add src to path
sys.path.append(os.getcwd())

from src.database.models import Base, Vulnerability
from src.services.sync_manager import SyncManager

class TestSyncFix(unittest.TestCase):
    def setUp(self):
        # Setup in-memory DB
        self.engine = create_engine('sqlite:///:memory:')
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    @patch('src.services.sync_manager.get_db_session')
    @patch('src.services.sync_manager.TenableExporter')
    @patch('src.services.sync_manager.Config')
    @patch('src.processors.vendor_detector.VendorDetector')
    @patch('src.services.sync_manager.DeviceTypeDetector')
    @patch('src.services.sync_manager.VulnerabilityNormalizer')
    def test_sync_deduplication(self, MockNormalizer, MockDeviceDetector, MockVendor, MockConfig, MockExporter, MockGetSession):
        print("\nRunning test_sync_deduplication...")
        
        # Setup Mocks
        session = self.Session()
        # Mock get_db_session context manager
        MockGetSession.return_value.__enter__.return_value = session
        
        # Mock API returning duplicate raw data (content doesn't matter much as Normalizer is mocked)
        mock_client = MockExporter.return_value
        mock_client.export_vulnerabilities.return_value = [{"id": 1}, {"id": 2}] 
        
        # Mock Normalizer to return duplicates
        # The code iterates over the list returned by normalize_batch
        
        vuln_data_1 = {
            'asset_uuid': 'asset-1',
            'plugin_id': '1001', # Same ID
            'plugin_name': 'Test Plugin',
            'severity': 'High',
            'state': 'ACTIVE',
            'vuln_id': 'v1'
        }
        
        vuln_data_2 = {
            'asset_uuid': 'asset-1', # Same asset
            'plugin_id': '1001',     # Same ID -> DUPLICATE
            'plugin_name': 'Test Plugin',
            'severity': 'Medium',    # Different data to verify which one is kept
            'state': 'ACTIVE',
            'vuln_id': 'v2'
        }
        
        MockNormalizer.normalize_batch.return_value = [vuln_data_1, vuln_data_2]
        
        # Mock Detectors
        MockDeviceDetector.return_value.detect_device_type.return_value = 'server'
        MockVendor.return_value.detect.return_value = None 
        
        # Run sync
        try:
            print("Calling SyncManager.sync_vulnerabilities()...")
            SyncManager.sync_vulnerabilities(fresh=True)
            print("Sync completed without error.")
        except Exception as e:
            self.fail(f"SyncManager raised exception: {e}")

        # Verify DB content
        vulns = session.query(Vulnerability).all()
        print(f"Stored {len(vulns)} vulnerabilities in DB")
        
        self.assertEqual(len(vulns), 1, "Should have deduplicated to 1 vulnerability")
        self.assertEqual(vulns[0].plugin_id, '1001')
        self.assertEqual(vulns[0].asset_uuid, 'asset-1')
        
        # Check which one survived (the first one according to our logic: if key in unique_map... continue)
        # So vuln_data_1 should be kept.
        self.assertEqual(vulns[0].severity, 'High', "Should have kept the first occurrence")
        print("✅ Verification passed: Duplicates removed, IntegrityError avoided.")

if __name__ == '__main__':
    unittest.main()
