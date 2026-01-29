import json
import sys
from unittest.mock import patch
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent))

from src.cli import cli
from click.testing import CliRunner

def test_milestone2_e2e():
    """End-to-end test for Milestone 2 integration"""
    runner = CliRunner()
    
    # Load mock data
    with open("tests/mock_data.json", "r") as f:
        mock_vulns = json.load(f)
    
    # Mock TenableExporter
    with patch("src.cli.TenableExporter") as MockExporter:
        instance = MockExporter.return_value
        instance.export_vulnerabilities.return_value = mock_vulns
        
        # Test HTML report generation
        print("Testing HTML report generation via CLI...")
        result = runner.invoke(cli, ["generate-report", "--format", "html", "--output", "./reports_test", "--fresh"])
        
        print(result.output)
        
        if result.exception:
            print(f"Exception: {result.exception}")
            import traceback
            traceback.print_exception(type(result.exception), result.exception, result.exception.__traceback__)
        
        assert result.exit_code == 0
        assert "Detecting vendors and products" in result.output
        assert "Detecting quick wins" in result.output
        assert "Grouping by vendor and product" in result.output
        assert "HTML report saved" in result.output
        
        # Verify HTML file was created
        html_files = list(Path("./reports_test").glob("Tenable_Report*.html"))
        assert len(html_files) > 0
        
        print("\n✓ Milestone 2 E2E test passed!")
        print(f"  HTML report: {html_files[-1]}")
        
        # Test BOTH format
        print("\nTesting BOTH format (HTML + XLSX)...")
        result_both = runner.invoke(cli, ["generate-report", "--format", "both", "--output", "./reports_test", "--fresh"])
        
        assert result_both.exit_code == 0
        assert "XLSX report saved" in result_both.output
        assert "HTML report saved" in result_both.output
        
        print("✓ Both formats generated successfully!")

if __name__ == "__main__":
    test_milestone2_e2e()
