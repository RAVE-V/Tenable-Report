
import unittest
from datetime import datetime, timezone
from src.database.models import Server, Application, ServerApplicationMap, Vulnerability, AppStatsSnapshot
from src.database.session import get_db_session, init_db
from src.services.report_manager import ReportManager
from unittest.mock import patch, MagicMock
from pathlib import Path

class TestReportGenerationFix(unittest.TestCase):
    def setUp(self):
        init_db()
        
    def test_generate_report_vpr_mode(self):
        # 1. Setup DB with mock data
        with get_db_session() as session:
            # Clear tables
            session.query(ServerApplicationMap).delete()
            session.query(Server).delete()
            session.query(Application).delete()
            session.query(Vulnerability).delete()
            session.query(AppStatsSnapshot).delete()
            
            # App and Server
            app = Application(app_name="TestApp", owner_team="BlueTeam")
            srv = Server(asset_uuid="uuid-1", hostname="host-1", last_seen=datetime.now(timezone.utc))
            session.add_all([app, srv])
            session.flush()
            
            mapping = ServerApplicationMap(server_id=srv.server_id, app_id=app.app_id)
            session.add(mapping)
            
            # Vulns
            v1 = Vulnerability(
                asset_uuid="uuid-1", hostname="host-1", 
                plugin_id="1", plugin_name="Critical Vuln", severity="Critical", state="ACTIVE",
                device_type="server", vpr_score=9.5
            )
            session.add(v1)
            session.commit()
            
        # 2. Run report generation in VPR mode
        # Mocking HTML generator to avoid actual file write in test, but we want to see if ReportManager fails
        with patch('src.report_generator.HTMLReportGenerator.generate') as MockGenerate:
            with patch('src.config.Config.validate', return_value=True):
                try:
                    ReportManager.generate_report(from_db=True, mode="vpr", format="html")
                    print("✓ ReportManager.generate_report executed successfully")
                except Exception as e:
                    self.fail(f"ReportManager.generate_report failed with {type(e).__name__}: {e}")
                
                # Verify that generate was called
                self.assertTrue(MockGenerate.called)
                args, kwargs = MockGenerate.call_args
                self.assertIn('app_priorities', kwargs)
                self.assertIn('metadata', kwargs)
                self.assertEqual(kwargs['metadata']['mode'], 'vpr')
                print("✓ Mock HTML generator called with correct arguments")

if __name__ == "__main__":
    unittest.main()
