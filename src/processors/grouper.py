"""Hierarchical grouper for vulnerability data"""

import logging
from typing import Dict, List, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


class VulnerabilityGrouper:
    """
    Groups vulnerabilities into hierarchical structure: Vendor → Product → Vulnerabilities
    Prioritizes vendors by severity (Critical/High count)
    """
    
    def group_by_vendor_product(self, vulns: List[Dict]) -> Dict[str, Dict[str, List[Dict]]]:
        """
        Group vulnerabilities by Vendor → Product hierarchy
        
        Args:
            vulns: List of normalized, enriched vulnerabilities
        
        Returns:
            Nested dictionary:
            {
                "Microsoft": {
                    "Windows Server": [vuln1, vuln2, ...],
                    "SQL Server": [vuln3, ...]
                },
                "Apache": {
                    "HTTP Server": [vuln4, ...]
                },
                ...
            }
        """
        # Create nested defaultdict
        grouped = defaultdict(lambda: defaultdict(list))
        
        for vuln in vulns:
            vendor = vuln.get("vendor", "Other")
            product = vuln.get("product_family")  # Can be None
            
            # Use vendor as primary key, product as secondary
            grouped[vendor][product].append(vuln)
        
        # Convert to regular dict
        result = {vendor: dict(products) for vendor, products in grouped.items()}
        logger.info(f"Grouped {len(vulns)} vulnerabilities into {len(result)} vendors")
        return result
    
    def calculate_vendor_severity_score(self, vulns: List[Dict]) -> int:
        """
        Calculate severity score for a vendor (used for sorting)
        Critical = 10 points, High = 5 points, Medium = 2 points, Low = 1 point
        
        Args:
            vulns: List of vulnerabilities for a vendor
        
        Returns:
            Integer severity score
        """
        score = 0
        for vuln in vulns:
            severity = vuln.get("severity", "").lower()
            if severity == "critical":
                score += 10
            elif severity == "high":
                score += 5
            elif severity == "medium":
                score += 2
            elif severity == "low":
                score += 1
        
        return score
    
    def sort_vendors_by_severity(self, grouped_vulns: Dict[str, Dict[str, List[Dict]]]) -> List[Tuple[str, Dict[str, List[Dict]]]]:
        """
        Sort vendors by severity score (highest first)
        "Other" is always last
        
        Args:
            grouped_vulns: Grouped vulnerabilities from group_by_vendor_product()
        
        Returns:
            List of (vendor_name, products_dict) tuples, sorted by severity
        """
        scored_vendors = []
        
        for vendor, products in grouped_vulns.items():
            # Flatten all vulnerabilities for this vendor
            all_vendor_vulns = []
            for product_vulns in products.values():
                all_vendor_vulns.extend(product_vulns)
            
            score = self.calculate_vendor_severity_score(all_vendor_vulns)
            scored_vendors.append((vendor, products, score))
        
        # Sort by score (descending), but "Other" always last
        sorted_vendors = sorted(
            scored_vendors,
            key=lambda x: (x[0] == "Other", -x[2])  # Other=True sorts last, then by negative score
        )
        
        return [(vendor, products) for vendor, products, _ in sorted_vendors]
    
    def get_vendor_statistics(self, grouped_vulns: Dict[str, Dict[str, List[Dict]]]) -> Dict[str, Dict]:
        """
        Get statistics for each vendor including affected assets and product breakdown
        
        Args:
            grouped_vulns: Grouped vulnerabilities
        
        Returns:
            Dictionary with vendor statistics
        """
        stats = {}
        
        for vendor, products in grouped_vulns.items():
            # Flatten vulnerabilities and track assets
            all_vulns = []
            vendor_assets = set()
            product_stats = {}
            
            for product, product_vulns in products.items():
                all_vulns.extend(product_vulns)
                
                # Product level stats
                prod_assets = set(v.get("asset_uuid") for v in product_vulns if v.get("asset_uuid"))
                vendor_assets.update(prod_assets)
                
                product_stats[product] = {
                    "total_vulns": len(product_vulns),
                    "affected_assets": len(prod_assets)
                }
            
            # Count by severity
            severity_counts = {
                "critical": sum(1 for v in all_vulns if v.get("severity", "").lower() == "critical"),
                "high": sum(1 for v in all_vulns if v.get("severity", "").lower() == "high"),
                "medium": sum(1 for v in all_vulns if v.get("severity", "").lower() == "medium"),
                "low": sum(1 for v in all_vulns if v.get("severity", "").lower() == "low")
            }
            
            stats[vendor] = {
                "total_vulns": len(all_vulns),
                "affected_assets": len(vendor_assets),
                "critical": severity_counts["critical"],
                "high": severity_counts["high"],
                "medium": severity_counts["medium"],
                "low": severity_counts["low"],
                "prod_stats": product_stats,
                "products": [p for p in products.keys() if p is not None]
            }
        
        return stats
    
    def group_and_sort(self, vulns: List[Dict]) -> Tuple[List[Tuple[str, Dict[str, List[Dict]]]], Dict[str, Dict]]:
        """
        Convenience method: group, sort, and get statistics in one call
        
        Args:
            vulns: List of normalized, enriched vulnerabilities
        
        Returns:
            Tuple of (sorted_vendors, vendor_statistics)
        """
        grouped = self.group_by_vendor_product(vulns)
        sorted_vendors = self.sort_vendors_by_severity(grouped)
        stats = self.get_vendor_statistics(grouped)
        
        return sorted_vendors, stats
