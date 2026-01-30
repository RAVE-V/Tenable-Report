"""Quick Wins detector for vulnerability data"""

import re
import logging
from typing import Dict, List

from src.processors.enums import QuickWinCategory

logger = logging.getLogger(__name__)


class QuickWinsDetector:
    """
    Detects "Quick Win" vulnerabilities that can be resolved with simple actions:
    1. Version-threshold: Simple version upgrade (e.g., "< 2.4.54")
    2. Unsupported products: EOL/deprecated products to decommission
    """
    
    # Regex patterns for version-threshold detection
    VERSION_PATTERNS = [
        r'<\s*\d+\.\d+',  # < 2.4.54
        r'prior to\s+\d+\.\d+',  # prior to 2.4.54
        r'before\s+\d+\.\d+',  # before 2.4.54
        r'less than\s+\d+\.\d+',  # less than 2.4.54
        r'earlier than\s+\d+\.\d+',  # earlier than 2.4.54
        r'below\s+\d+\.\d+',  # below 2.4.54
        r'upgrade to\s+\d+\.\d+',  # upgrade to 2.4.54
        r'update to\s+\d+\.\d+',  # update to 2.4.54
    ]
    
    # Keywords for unsupported product detection
    UNSUPPORTED_KEYWORDS = [
        'unsupported',
        'end of life',
        'end-of-life',
        'eol',
        'deprecated',
        'no longer supported',
        'not supported',
        'reached end of support',
        'extended support ended',
        'obsolete',
        'discontinued',
    ]
    
    def __init__(self):
        self.version_regex = re.compile('|'.join(self.VERSION_PATTERNS), re.IGNORECASE)
    
    def is_version_threshold(self, vuln: Dict) -> bool:
        """
        Check if vulnerability is a version-threshold quick win
        
        Args:
            vuln: Normalized vulnerability dictionary
        
        Returns:
            True if this is a version-threshold vulnerability
        """
        plugin_name = vuln.get("plugin_name", "").lower()
        description = vuln.get("description", "")
        if description is None:
            description = ""
        description = description.lower()
        solution = vuln.get("solution", "")
        if solution is None:
            solution = ""
        solution = solution.lower()
        
        combined_text = f"{plugin_name} {description} {solution}"
        
        # Check for version patterns
        if self.version_regex.search(combined_text):
            # Additional validation: should have patch available
            if vuln.get("has_patch", False):
                return True
        
        return False
    
    def is_unsupported_product(self, vuln: Dict) -> bool:
        """
        Check if vulnerability is an unsupported-product quick win
        
        Args:
            vuln: Normalized vulnerability dictionary
        
        Returns:
            True if this is an unsupported product vulnerability
        """
        plugin_name = vuln.get("plugin_name", "").lower()
        description = vuln.get("description", "")
        if description is None:
            description = ""
        description = description.lower()
        solution = vuln.get("solution", "")
        if solution is None:
            solution = ""
        solution = solution.lower()
        synopsis = vuln.get("synopsis", "")
        if synopsis is None:
            synopsis = ""
        synopsis = synopsis.lower()
        
        combined_text = f"{plugin_name} {description} {solution} {synopsis}"
        
        # Check for unsupported keywords
        for keyword in self.UNSUPPORTED_KEYWORDS:
            if keyword in combined_text:
                return True
        
        return False
    
    def detect_quick_wins(self, vulns: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Detect and categorize quick win vulnerabilities
        
        Args:
            vulns: List of normalized vulnerability dictionaries
        
        Returns:
            Dictionary with categorized quick wins:
            {
                "version_threshold": [vuln1, vuln2, ...],
                "unsupported_product": [vuln3, vuln4, ...],
                "total_quick_wins": count
            }
        """
        version_threshold = []
        unsupported_product = []
        
        for vuln in vulns:
            # Check version threshold first (more specific)
            if self.is_version_threshold(vuln):
                version_threshold.append(vuln)
                vuln["quick_win_category"] = QuickWinCategory.VERSION_THRESHOLD.value
                logger.debug(f"Version-threshold quick win: {vuln.get('plugin_name')}")
            # Then check unsupported (less specific, might overlap)
            elif self.is_unsupported_product(vuln):
                unsupported_product.append(vuln)
                vuln["quick_win_category"] = QuickWinCategory.UNSUPPORTED_PRODUCT.value
                logger.debug(f"Unsupported product quick win: {vuln.get('plugin_name')}")
            else:
                vuln["quick_win_category"] = None
        
        total_quick_wins = len(version_threshold) + len(unsupported_product)
        logger.info(f"Detected {total_quick_wins} quick wins: {len(version_threshold)} version-threshold, {len(unsupported_product)} unsupported")
        
        return {
            "version_threshold": version_threshold,
            "unsupported_product": unsupported_product,
            "total_quick_wins": total_quick_wins
        }
    
    def enrich_vulnerabilities(self, vulns: List[Dict]) -> List[Dict]:
        """
        Enrich vulnerabilities with quick win detection
        
        Args:
            vulns: List of normalized vulnerability dictionaries
        
        Returns:
            Same list with quick_win_category field populated
        """
        self.detect_quick_wins(vulns)
        return vulns
    
    def get_quick_wins_summary(self, vulns: List[Dict]) -> Dict:
        """
        Get summary statistics for quick wins
        
        Args:
            vulns: List of normalized vulnerability dictionaries
        
        Returns:
            Dictionary with summary statistics
        """
        quick_wins = self.detect_quick_wins(vulns)
        
        # Calculate severity breakdown
        version_threshold_critical = sum(
            1 for v in quick_wins["version_threshold"] 
            if v.get("severity", "").lower() == "critical"
        )
        version_threshold_high = sum(
            1 for v in quick_wins["version_threshold"] 
            if v.get("severity", "").lower() == "high"
        )
        
        unsupported_critical = sum(
            1 for v in quick_wins["unsupported_product"] 
            if v.get("severity", "").lower() == "critical"
        )
        unsupported_high = sum(
            1 for v in quick_wins["unsupported_product"] 
            if v.get("severity", "").lower() == "high"
        )
        
        return {
            "total_quick_wins": quick_wins["total_quick_wins"],
            "version_threshold": {
                "count": len(quick_wins["version_threshold"]),
                "critical": version_threshold_critical,
                "high": version_threshold_high
            },
            "unsupported_product": {
                "count": len(quick_wins["unsupported_product"]),
                "critical": unsupported_critical,
                "high": unsupported_high
            }
        }
