import json
import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent))

from src.processors.quick_wins_detector import QuickWinsDetector
from src.processors.normalizer import VulnerabilityNormalizer

def test_quick_wins_with_mock_data():
    """Test quick wins detection with realistic mock data"""
    
    # Load mock data
    with open("tests/mock_data.json", "r") as f:
        raw_vulns = json.load(f)
    
    # Normalize data
    print("Normalizing vulnerability data...")
    vulns = VulnerabilityNormalizer.normalize_batch(raw_vulns)
    
    # Initialize detector
    print("Initializing Quick Wins Detector...")
    detector = QuickWinsDetector()
    
    # Detect quick wins
    print("\nDetecting quick wins...\n")
    quick_wins = detector.detect_quick_wins(vulns)
    
    # Display results
    print("=" * 80)
    print("QUICK WINS DETECTION RESULTS")
    print("=" * 80)
    print(f"\nTotal Quick Wins: {quick_wins['total_quick_wins']}")
    print(f"  - Version-Threshold: {len(quick_wins['version_threshold'])}")
    print(f"  - Unsupported Products: {len(quick_wins['unsupported_product'])}")
    
    if quick_wins['version_threshold']:
        print("\n" + "=" * 80)
        print("VERSION-THRESHOLD QUICK WINS")
        print("=" * 80)
        for i, vuln in enumerate(quick_wins['version_threshold'], 1):
            print(f"\n[{i}] {vuln['plugin_name']}")
            print(f"    Hostname: {vuln['hostname']}")
            print(f"    Severity: {vuln['severity']}")
            print(f"    Solution: {vuln['solution'][:100]}...")
    
    if quick_wins['unsupported_product']:
        print("\n" + "=" * 80)
        print("UNSUPPORTED PRODUCT QUICK WINS")
        print("=" * 80)
        for i, vuln in enumerate(quick_wins['unsupported_product'], 1):
            print(f"\n[{i}] {vuln['plugin_name']}")
            print(f"    Hostname: {vuln['hostname']}")
            print(f"    Severity: {vuln['severity']}")
            print(f"    Solution: {vuln['solution'][:100]}...")
    
    # Get summary statistics
    summary = detector.get_quick_wins_summary(vulns)
    
    print("\n" + "=" * 80)
    print("SUMMARY STATISTICS")
    print("=" * 80)
    print(f"Total Quick Wins: {summary['total_quick_wins']}")
    print("\nVersion-Threshold:")
    print(f"  Total: {summary['version_threshold']['count']}")
    print(f"  Critical: {summary['version_threshold']['critical']}")
    print(f"  High: {summary['version_threshold']['high']}")
    print("\nUnsupported Products:")
    print(f"  Total: {summary['unsupported_product']['count']}")
    print(f"  Critical: {summary['unsupported_product']['critical']}")
    print(f"  High: {summary['unsupported_product']['high']}")
    
    print("\n✓ Quick wins detection test complete!")

if __name__ == "__main__":
    test_quick_wins_with_mock_data()
