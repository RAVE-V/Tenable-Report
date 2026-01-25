"""Data normalizer for Tenable export data"""

import logging
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class VulnerabilityNormalizer:
    """Normalize raw Tenable export data into consistent structure"""
    
    @staticmethod
    def normalize(raw_vuln: Dict) -> Dict:
        """
        Normalize a single vulnerability record
        
        Args:
            raw_vuln: Raw vulnerability data from Tenable export
        
        Returns:
            Normalized vulnerability dictionary
        """
        if not raw_vuln:
            logger.warning("Received empty vulnerability record")
            return {}
        
        asset = raw_vuln.get("asset") or {}
        plugin = raw_vuln.get("plugin") or {}
        
        return {
            # Asset details
            "asset_uuid": asset.get("uuid"),
            "hostname": asset.get("hostname") or "unknown",
            "ipv4": asset.get("ipv4"),
            "operating_system": asset.get("operating_system"),
            
            # Plugin details
            "plugin_id": str(plugin.get("id", "")),
            "plugin_name": plugin.get("name", ""),
            "description": plugin.get("description", ""),
            "solution": plugin.get("solution", ""),
            "synopsis": plugin.get("synopsis", ""),
            "see_also": plugin.get("see_also") or [],
            "cve": plugin.get("cve") or [],
            "exploit_available": plugin.get("exploit_available", False),
            "has_patch": plugin.get("has_patch", False),
            
            # Detection details
            "severity": raw_vuln.get("severity", "info").capitalize(),
            "state": raw_vuln.get("state", "unknown"),
            "first_found": VulnerabilityNormalizer._parse_date(raw_vuln.get("first_found")),
            "last_found": VulnerabilityNormalizer._parse_date(raw_vuln.get("last_found")),
            
            # For processing
            "vendor": None,  # To be populated by vendor detector
            "product_family": None,  # To be populated by vendor detector
            "application": None,  # To be populated by enricher
        }
    
    @staticmethod
    def normalize_batch(raw_vulns: List[Dict]) -> List[Dict]:
        """
        Normalize a batch of vulnerabilities
        
        Args:
            raw_vulns: List of raw vulnerability records
        
        Returns:
            List of normalized vulnerability dictionaries
        """
        return [VulnerabilityNormalizer.normalize(vuln) for vuln in raw_vulns]
    
    @staticmethod
    def _parse_date(date_str: Optional[str]) -> Optional[str]:
        """Parse date string from Tenable format"""
        if not date_str:
            return None
        
        try:
            # Tenable typically returns ISO format dates
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, AttributeError):
            return date_str
