import pytest
import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.processors.grouper import VulnerabilityGrouper


def test_group_by_vendor_product():
    """Test basic vendor-product grouping"""
    grouper = VulnerabilityGrouper()
    
    vulns = [
        {"vendor": "Microsoft", "product_family": "Windows Server", "severity": "critical"},
        {"vendor": "Microsoft", "product_family": "SQL Server", "severity": "high"},
        {"vendor": "Apache", "product_family": "HTTP Server", "severity": "high"},
        {"vendor": "Apache", "product_family": "HTTP Server", "severity": "medium"},
        {"vendor": "Other", "product_family": None, "severity": "low"}
    ]
    
    grouped = grouper.group_by_vendor_product(vulns)
    
    assert "Microsoft" in grouped
    assert "Apache" in grouped
    assert "Other" in grouped
    
    assert "Windows Server" in grouped["Microsoft"]
    assert "SQL Server" in grouped["Microsoft"]
    assert "HTTP Server" in grouped["Apache"]
    
    assert len(grouped["Microsoft"]["Windows Server"]) == 1
    assert len(grouped["Microsoft"]["SQL Server"]) == 1
    assert len(grouped["Apache"]["HTTP Server"]) == 2


def test_calculate_vendor_severity_score():
    """Test severity score calculation"""
    grouper = VulnerabilityGrouper()
    
    vulns = [
        {"severity": "critical"},  # 10 points
        {"severity": "critical"},  # 10 points
        {"severity": "high"},      # 5 points
        {"severity": "medium"},    # 2 points
        {"severity": "low"}        # 1 point
    ]
    
    score = grouper.calculate_vendor_severity_score(vulns)
    assert score == 28  # 10 + 10 + 5 + 2 + 1


def test_sort_vendors_by_severity():
    """Test vendor sorting by severity"""
    grouper = VulnerabilityGrouper()
    
    vulns = [
        {"vendor": "Apache", "product_family": "HTTP Server", "severity": "medium"},
        {"vendor": "Microsoft", "product_family": "Windows Server", "severity": "critical"},
        {"vendor": "Microsoft", "product_family": "SQL Server", "severity": "critical"},
        {"vendor": "Other", "product_family": None, "severity": "critical"},
        {"vendor": "Oracle", "product_family": "Java", "severity": "high"}
    ]
    
    grouped = grouper.group_by_vendor_product(vulns)
    sorted_vendors = grouper.sort_vendors_by_severity(grouped)
    
    vendor_names = [vendor for vendor, _ in sorted_vendors]
    
    # Microsoft should be first (2 critical = 20 points)
    assert vendor_names[0] == "Microsoft"
    
    # Other should be last (always)
    assert vendor_names[-1] == "Other"
    
    # Oracle (5 points) should be before Apache (2 points)
    assert vendor_names.index("Oracle") < vendor_names.index("Apache")


def test_get_vendor_statistics():
    """Test vendor statistics calculation"""
    grouper = VulnerabilityGrouper()
    
    vulns = [
        {"vendor": "Microsoft", "product_family": "Windows Server", "severity": "critical"},
        {"vendor": "Microsoft", "product_family": "Windows Server", "severity": "high"},
        {"vendor": "Microsoft", "product_family": "SQL Server", "severity": "medium"},
        {"vendor": "Apache", "product_family": "HTTP Server", "severity": "high"}
    ]
    
    grouped = grouper.group_by_vendor_product(vulns)
    stats = grouper.get_vendor_statistics(grouped)
    
    assert stats["Microsoft"]["total_vulns"] == 3
    assert stats["Microsoft"]["critical"] == 1
    assert stats["Microsoft"]["high"] == 1
    assert stats["Microsoft"]["medium"] == 1
    assert "Windows Server" in stats["Microsoft"]["products"]
    assert "SQL Server" in stats["Microsoft"]["products"]
    
    assert stats["Apache"]["total_vulns"] == 1
    assert stats["Apache"]["high"] == 1


def test_group_and_sort():
    """Test combined group_and_sort method"""
    grouper = VulnerabilityGrouper()
    
    vulns = [
        {"vendor": "Apache", "product_family": "HTTP Server", "severity": "high"},
        {"vendor": "Microsoft", "product_family": "Windows Server", "severity": "critical"},
        {"vendor": "Other", "product_family": None, "severity": "low"}
    ]
    
    sorted_vendors, stats = grouper.group_and_sort(vulns)
    
    # Check sorting
    vendor_names = [vendor for vendor, _ in sorted_vendors]
    assert vendor_names[0] == "Microsoft"
    assert vendor_names[-1] == "Other"
    
    # Check stats
    assert stats["Microsoft"]["critical"] == 1
    assert stats["Apache"]["high"] == 1
    assert stats["Other"]["low"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
