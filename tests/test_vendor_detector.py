import json
import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent))

from src.processors.vendor_detector import VendorDetector
from src.processors.normalizer import VulnerabilityNormalizer

def test_vendor_detection():
    """Test vendor detection engine with mock data"""
    
    # Load mock data
    with open("tests/mock_data.json", "r") as f:
        raw_vulns = json.load(f)
    
    # Normalize data
    print("Normalizing vulnerability data...")
    vulns = VulnerabilityNormalizer.normalize_batch(raw_vulns)
    
    # Seed database with default rules
    print("Seeding database with vendor detection rules...")
    VendorDetector.seed_database_rules()
    
    # Initialize detector
    print("Initializing vendor detector...")
    detector = VendorDetector()
    
    # Enrich vulnerabilities
    print("\nDetecting vendors and products...\n")
    enriched_vulns = detector.enrich_vulnerabilities(vulns)
    
    # Display results
    print("=" * 80)
    print("VENDOR DETECTION RESULTS")
    print("=" * 80)
    
    for i, vuln in enumerate(enriched_vulns, 1):
        print(f"\n[{i}] {vuln['plugin_name']}")
        print(f"    Hostname: {vuln['hostname']}")
        print(f"    Severity: {vuln['severity']}")
        print(f"    Vendor: {vuln.get('vendor', 'Not detected')}")
        print(f"    Product: {vuln.get('product_family', 'Not detected')}")
        print(f"    Confidence: {vuln.get('vendor_confidence', 'N/A')}")
    
    print("\n" + "=" * 80)
    print("SUMMARY BY VENDOR")
    print("=" * 80)
    
    # Group by vendor
    vendor_counts = {}
    for vuln in enriched_vulns:
        vendor = vuln.get('vendor', 'Unknown')
        vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1
    
    for vendor, count in sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{vendor}: {count} vulnerabilities")
    
    print("\n✓ Vendor detection test complete!")

if __name__ == "__main__":
    test_vendor_detection()
