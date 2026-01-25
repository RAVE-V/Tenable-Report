import json
import sys
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.append(str(Path(__file__).parent.parent))

from src.processors.normalizer import VulnerabilityNormalizer
from src.processors.vendor_detector import VendorDetector
from src.processors.quick_wins_detector import QuickWinsDetector
from src.processors.grouper import VulnerabilityGrouper
from src.report_generator import HTMLReportGenerator

def test_html_report():
    """Test HTML report generation with full pipeline"""
    
    # Load mock data
    print("Loading mock data...")
    with open("tests/mock_data.json", "r") as f:
        raw_vulns = json.load(f)
    
    # Step 1: Normalize
    print("Normalizing vulnerability data...")
    vulns = VulnerabilityNormalizer.normalize_batch(raw_vulns)
    
    # Step 2: Vendor Detection
    print("Detecting vendors...")
    VendorDetector.seed_database_rules()
    vendor_detector = VendorDetector()
    vulns = vendor_detector.enrich_vulnerabilities(vulns)
    
    # Step 3: Quick Wins Detection
    print("Detecting quick wins...")
    quick_wins_detector = QuickWinsDetector()
    quick_wins = quick_wins_detector.detect_quick_wins(vulns)
    
    # Step 4: Hierarchical Grouping
    print("Grouping by vendor and product...")
    grouper = VulnerabilityGrouper()
    sorted_vendors, vendor_stats = grouper.group_and_sort(vulns)
    
    # Step 5: Generate HTML Report
    print("Generating HTML report...")
    
    output_path = Path("./reports_test/Tenable_Report_HTML.html")
    
    metadata = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_vulns": len(vulns),
        "total_assets": len(set(v["asset_uuid"] for v in vulns if v.get("asset_uuid"))),
        "filters": {}
    }
    
    html_gen = HTMLReportGenerator()
    html_gen.generate(
        output_path=output_path,
        grouped_vulns=sorted_vendors,
        vendor_stats=vendor_stats,
        quick_wins=quick_wins,
        metadata=metadata
    )
    
    print(f"\n✓ HTML report generated: {output_path}")
    print(f"  Total Vulnerabilities: {metadata['total_vulns']}")
    print(f"  Total Assets: {metadata['total_assets']}")
    print(f"  Quick Wins: {quick_wins['total_quick_wins']}")
    print(f"  Vendors: {len(sorted_vendors)}")
    
    print("\nOpen the report in your browser:")
    print(f"  file:///{output_path.absolute()}")

if __name__ == "__main__":
    test_html_report()
