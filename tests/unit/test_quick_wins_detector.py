import pytest
import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.processors.quick_wins_detector import QuickWinsDetector


def test_version_threshold_detection():
    """Test detection of version-threshold quick wins"""
    detector = QuickWinsDetector()
    
    # Version threshold vulnerability
    vuln1 = {
        "plugin_name": "Apache HTTP Server 2.4.x < 2.4.54",
        "description": "The version is prior to 2.4.54",
        "solution": "Upgrade to Apache 2.4.54 or later",
        "has_patch": True
    }
    
    assert detector.is_version_threshold(vuln1)
    
    # Another version threshold pattern
    vuln2 = {
        "plugin_name": "OpenSSL Update",
        "description": "OpenSSL before 3.0.2 is vulnerable",
        "solution": "Update to version 3.0.2",
        "has_patch": True
    }
    
    assert detector.is_version_threshold(vuln2)
    
    # Not a version threshold
    vuln3 = {
        "plugin_name": "Configuration Issue",
        "description": "The service is misconfigured",
        "solution": "Reconfigure the service",
        "has_patch": False
    }
    
    assert not detector.is_version_threshold(vuln3)


def test_unsupported_product_detection():
    """Test detection of unsupported product quick wins"""
    detector = QuickWinsDetector()
    
    # Unsupported product
    vuln1 = {
        "plugin_name": "Windows Server 2008 End of Life",
        "description": "Windows Server 2008 has reached end of life and is no longer supported",
        "solution": "Migrate to a supported version",
        "synopsis": "The remote host is running an unsupported operating system"
    }
    
    assert detector.is_unsupported_product(vuln1)
    
    # EOL product
    vuln2 = {
        "plugin_name": "PHP 5.x EOL",
        "description": "PHP 5.x is deprecated and obsolete",
        "solution": "Upgrade to PHP 8.x",
        "synopsis": "EOL software detected"
    }
    
    assert detector.is_unsupported_product(vuln2)
    
    # Not unsupported
    vuln3 = {
        "plugin_name": "Apache Update",
        "description": "Apache has a security patch available",
        "solution": "Apply the patch",
        "synopsis": "Security update available"
    }
    
    assert not detector.is_unsupported_product(vuln3)


def test_detect_quick_wins_batch():
    """Test batch quick wins detection"""
    detector = QuickWinsDetector()
    
    vulns = [
        {
            "plugin_name": "Apache < 2.4.54",
            "description": "Version prior to 2.4.54",
            "solution": "Upgrade to 2.4.54",
            "has_patch": True,
            "severity": "critical"
        },
        {
            "plugin_name": "Windows 2008 EOL",
            "description": "Unsupported operating system",
            "solution": "Migrate to Windows Server 2022",
            "synopsis": "End of life detected",
            "has_patch": False,
            "severity": "high"
        },
        {
            "plugin_name": "SSL Certificate",
            "description": "Certificate is expiring soon",
            "solution": "Renew the certificate",
            "has_patch": False,
            "severity": "medium"
        }
    ]
    
    quick_wins = detector.detect_quick_wins(vulns)
    
    assert quick_wins["total_quick_wins"] == 2
    assert len(quick_wins["version_threshold"]) == 1
    assert len(quick_wins["unsupported_product"]) == 1
    
    # Verify categorization
    assert vulns[0]["quick_win_category"] == "version_threshold"
    assert vulns[1]["quick_win_category"] == "unsupported_product"
    assert vulns[2]["quick_win_category"] is None


def test_quick_wins_summary():
    """Test quick wins summary statistics"""
    detector = QuickWinsDetector()
    
    vulns = [
        {
            "plugin_name": "Apache < 2.4.54",
            "description": "Version prior to 2.4.54",
            "solution": "Upgrade to 2.4.54",
            "has_patch": True,
            "severity": "critical"
        },
        {
            "plugin_name": "Nginx < 1.20.1",
            "description": "Version before 1.20.1",
            "solution": "Update to 1.20.1",
            "has_patch": True,
            "severity": "high"
        },
        {
            "plugin_name": "Windows 2008 EOL",
            "description": "Unsupported OS",
            "solution": "Migrate",
            "synopsis": "End of life",
            "has_patch": False,
            "severity": "critical"
        }
    ]
    
    summary = detector.get_quick_wins_summary(vulns)
    
    assert summary["total_quick_wins"] == 3
    assert summary["version_threshold"]["count"] == 2
    assert summary["version_threshold"]["critical"] == 1
    assert summary["version_threshold"]["high"] == 1
    assert summary["unsupported_product"]["count"] == 1
    assert summary["unsupported_product"]["critical"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
