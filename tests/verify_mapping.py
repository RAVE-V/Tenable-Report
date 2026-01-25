import json
import sys
from unittest.mock import patch
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent))

from src.cli import cli
from click.testing import CliRunner

def test_mapping_workflow():
    runner = CliRunner()
    
    # Load mock data
    with open("tests/mock_data.json", "r") as f:
        mock_vulns = json.load(f)
    
    # Mock TenableExporter
    with patch("src.cli.TenableExporter") as MockExporter:
        instance = MockExporter.return_value
        instance.export_vulnerabilities.return_value = mock_vulns
        
        # 1. Sync DB
        print("Running sync-db...")
        result_sync = runner.invoke(cli, ["sync-db"])
        print(f"Sync output: {result_sync.output}")
        assert result_sync.exit_code == 0
        
        # 2. Map Server
        print("Running map-server...")
        result_map = runner.invoke(cli, ["map-server", "--hostname", "prod-web-01.example.com", "--app", "Payment-Gateway"])
        print(f"Map output: {result_map.output}")
        assert result_map.exit_code == 0
        
        # 3. List Mappings
        print("Running list-mappings...")
        result_list = runner.invoke(cli, ["list-mappings"])
        print(f"List output: {result_list.output}")
        assert result_list.exit_code == 0
        assert "prod-web-01.example.com" in result_list.output
        assert "Payment-Gateway" in result_list.output

if __name__ == "__main__":
    test_mapping_workflow()
