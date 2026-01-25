import json
import sys
from unittest.mock import patch
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent))

from src.cli import cli
from click.testing import CliRunner

def test_generate_report():
    runner = CliRunner()
    
    # Load mock data
    with open("tests/mock_data.json", "r") as f:
        mock_vulns = json.load(f)
    
    # Mock TenableExporter.export_vulnerabilities
    with patch("src.cli.TenableExporter") as MockExporter:
        instance = MockExporter.return_value
        instance.export_vulnerabilities.return_value = mock_vulns
        
        # Run init first
        result_init = runner.invoke(cli, ["init"])
        print(f"Init output: {result_init.output}")
        
        # Run generate-report
        result = runner.invoke(cli, ["generate-report", "--format", "xlsx", "--output", "./reports_test"])
        
        print(f"Report output: {result.output}")
        if result.exception:
            print(f"Exception: {result.exception}")
            import traceback
            traceback.print_exception(type(result.exception), result.exception, result.exception.__traceback__)
        
        assert result.exit_code == 0
        assert "Report generation complete" in result.output
        
        # Check if file was created
        report_files = list(Path("./reports_test").glob("Tenable_Report*.xlsx"))
        assert len(report_files) > 0
        print(f"Success! Report created: {report_files[0]}")

if __name__ == "__main__":
    test_generate_report()
