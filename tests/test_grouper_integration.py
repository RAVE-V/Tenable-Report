import json
import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent))

from src.processors.grouper import VulnerabilityGrouper
from src.processors.vendor_detector import VendorDetector
from src.processors.normalizer import VulnerabilityNormalizer

def test_grouper_with_mock_data():
    """Test hierarchical grouper with realistic mock data"""
    
    # Load mock data
    with open("tests/mock_data.json", "r") as f:
        raw_vulns = json.load(f)
    
    # Normalize data
    print("Normalizing vulnerability data...")
    vulns = VulnerabilityNormalizer.normalize_batch(raw_vulns)
    
    # Detect vendors
    print("Detecting vendors...")
    VendorDetector.seed_database_rules()
    detector = VendorDetector()
    vulns = detector.enrich_vulnerabilities(vulns)
    
    # Group vulnerabilities
    print("Grouping vulnerabilities by vendor and product...\n")
    grouper = VulnerabilityGrouper()
    sorted_vendors, stats = grouper.group_and_sort(vulns)
    
    # Display results
    print("=" * 80)
    print("HIERARCHICAL GROUPING RESULTS")
    print("=" * 80)
    
    for vendor, products in sorted_vendors:
        vendor_stats = stats[vendor]
        print(f"\n📦 {vendor}")
        print(f"   Total: {vendor_stats['total_vulns']} | Critical: {vendor_stats['critical']} | High: {vendor_stats['high']} | Medium: {vendor_stats['medium']}")
        
        for product, product_vulns in products.items():
            product_display = product if product else "(General)"
            print(f"\n   └─ {product_display} ({len(product_vulns)} vulnerabilities)")
            
            for vuln in product_vulns:
                severity_icon = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🔵"
                }.get(vuln['severity'].lower(), "⚪")
                
                print(f"      {severity_icon} {vuln['plugin_name'][:70]}")
                print(f"         Host: {vuln['hostname']}")
    
    print("\n" + "=" * 80)
    print("VENDOR STATISTICS SUMMARY")
    print("=" * 80)
    
    print(f"\n{'Vendor':<20} {'Total':<8} {'Critical':<10} {'High':<8} {'Medium':<8} {'Products'}")
    print("-" * 80)
    
    for vendor, products in sorted_vendors:
        s = stats[vendor]
        products_str = ", ".join(s['products']) if s['products'] else "(None)"
        print(f"{vendor:<20} {s['total_vulns']:<8} {s['critical']:<10} {s['high']:<8} {s['medium']:<8} {products_str[:30]}")
    
    print("\n✓ Hierarchical grouping test complete!")

if __name__ == "__main__":
    test_grouper_with_mock_data()
