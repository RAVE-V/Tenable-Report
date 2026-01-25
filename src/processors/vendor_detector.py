"""Vendor and Product detection engine for vulnerability data"""

import re
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

from src.database.session import get_db_session
from src.database.models import VendorProductRule
from src.processors.enums import ConfidenceLevel
from src.utils import measure_performance

logger = logging.getLogger(__name__)


@dataclass
class VendorProduct:
    """Detected vendor and product information"""
    vendor: str
    product_family: Optional[str] = None
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM


class VendorDetector:
    """
    Detects vendor and product from vulnerability plugin names and descriptions.
    Uses database-backed rules with priority ordering.
    """
    
    def __init__(self):
        self.rules: List[VendorProductRule] = []
        self._compiled_patterns: Dict[int, re.Pattern] = {}
        self._load_rules()
        logger.info(f"Vendor detector initialized with {len(self.rules)} rules")
    
    def _load_rules(self):
        """Load detection rules from database ordered by priority"""
        try:
            with get_db_session() as session:
                self.rules = session.query(VendorProductRule)\
                    .filter_by(enabled=True)\
                    .order_by(VendorProductRule.priority.desc())\
                    .all()
                
                # Pre-compile regex patterns
                for rule in self.rules:
                    if rule.regex_pattern:
                        try:
                            self._compiled_patterns[id(rule)] = re.compile(rule.regex_pattern, re.IGNORECASE)
                        except re.error as e:
                            logger.warning(f"Invalid regex pattern in rule {rule.rule_id}: {e}")
                
                # Detach from session to use outside context
                session.expunge_all()
        except Exception as e:
            logger.error(f"Failed to load vendor detection rules: {e}")
            # Continue with empty rules list - will fall back to heuristics
            self.rules = []
    
    def detect(self, vuln: Dict) -> VendorProduct:
        """
        Detect vendor and product from vulnerability data
        
        Args:
            vuln: Normalized vulnerability dictionary
        
        Returns:
            VendorProduct with detected vendor and product family
        """
        plugin_name = vuln.get("plugin_name", "").lower()
        description = vuln.get("description", "").lower()
        solution = vuln.get("solution", "").lower()
        
        # Combine text for analysis
        combined_text = f"{plugin_name} {description} {solution}"
        
        # Try database rules first (priority-ordered)
        for rule in self.rules:
            if rule.regex_pattern:
                # Use pre-compiled pattern
                pattern = self._compiled_patterns.get(id(rule))
                if pattern and pattern.search(combined_text):
                    logger.debug(f"Matched vendor {rule.vendor_name} via regex: {rule.regex_pattern}")
                    return VendorProduct(
                        vendor=rule.vendor_name,
                        product_family=rule.product_family,
                        confidence=ConfidenceLevel.HIGH
                    )
            
            if rule.keyword:
                if rule.keyword.lower() in combined_text:
                    logger.debug(f"Matched vendor {rule.vendor_name} via keyword: {rule.keyword}")
                    return VendorProduct(
                        vendor=rule.vendor_name,
                        product_family=rule.product_family,
                        confidence=ConfidenceLevel.MEDIUM
                    )
        
        # Fallback to built-in heuristics
        return self._heuristic_detection(plugin_name, combined_text)
    
    def _heuristic_detection(self, plugin_name: str, text: str) -> VendorProduct:
        """
        Built-in heuristic rules for common patterns
        These are fallback rules when no DB rules match
        """
        # Windows/Microsoft patterns
        if any(keyword in text for keyword in ["microsoft", "windows", "ms ", ".net", "azure", "iis"]):
            if "windows server" in text or "server 20" in text:
                return VendorProduct("Microsoft", "Windows Server", ConfidenceLevel.HIGH)
            elif "windows" in text:
                return VendorProduct("Microsoft", "Windows", ConfidenceLevel.HIGH)
            elif "office" in text:
                return VendorProduct("Microsoft", "Office", ConfidenceLevel.MEDIUM)
            return VendorProduct("Microsoft", None, ConfidenceLevel.MEDIUM)
        
        # Linux distributions
        if "ubuntu" in text:
            return VendorProduct("Canonical", "Ubuntu", ConfidenceLevel.HIGH)
        if "debian" in text:
            return VendorProduct("Debian", "Debian", ConfidenceLevel.HIGH)
        if "red hat" in text or "rhel" in text:
            return VendorProduct("Red Hat", "RHEL", ConfidenceLevel.HIGH)
        if "centos" in text:
            return VendorProduct("CentOS", "CentOS", ConfidenceLevel.HIGH)
        if "fedora" in text:
            return VendorProduct("Fedora", "Fedora", ConfidenceLevel.HIGH)
        if "suse" in text or "sles" in text:
            return VendorProduct("SUSE", "SUSE Linux", ConfidenceLevel.HIGH)
        
        # Apache ecosystem
        if "apache " in text:
            if "tomcat" in text:
                return VendorProduct("Apache", "Tomcat", ConfidenceLevel.HIGH)
            elif "http server" in text or "httpd" in text:
                return VendorProduct("Apache", "HTTP Server", ConfidenceLevel.HIGH)
            return VendorProduct("Apache", None, ConfidenceLevel.MEDIUM)
        
        # Oracle
        if "oracle" in text:
            if "database" in text or "db" in text:
                return VendorProduct("Oracle", "Database", ConfidenceLevel.HIGH)
            elif "java" in text or "jdk" in text or "jre" in text:
                return VendorProduct("Oracle", "Java", ConfidenceLevel.HIGH)
            return VendorProduct("Oracle", None, ConfidenceLevel.MEDIUM)
        
        # VMware
        if "vmware" in text:
            if "esxi" in text:
                return VendorProduct("VMware", "ESXi", ConfidenceLevel.HIGH)
            elif "vcenter" in text:
                return VendorProduct("VMware", "vCenter", ConfidenceLevel.HIGH)
            return VendorProduct("VMware", None, ConfidenceLevel.MEDIUM)
        
        # Cisco
        if "cisco" in text:
            if "ios" in text and "cisco ios" in text:
                return VendorProduct("Cisco", "IOS", ConfidenceLevel.HIGH)
            elif "asa" in text:
                return VendorProduct("Cisco", "ASA", ConfidenceLevel.HIGH)
            return VendorProduct("Cisco", None, ConfidenceLevel.MEDIUM)
        
        # PHP
        if "php" in text:
            return VendorProduct("PHP", "PHP", ConfidenceLevel.HIGH)
        
        # Python
        if "python" in text:
            return VendorProduct("Python", "Python", ConfidenceLevel.HIGH)
        
        # Node.js
        if "node.js" in text or "nodejs" in text:
            return VendorProduct("Node.js", "Node.js", ConfidenceLevel.HIGH)
        
        # Docker
        if "docker" in text:
            return VendorProduct("Docker", "Docker", ConfidenceLevel.HIGH)
        
        # Kubernetes
        if "kubernetes" in text or "k8s" in text:
            return VendorProduct("Kubernetes", "Kubernetes", ConfidenceLevel.HIGH)
        
        # Nginx
        if "nginx" in text:
            return VendorProduct("Nginx", "Nginx", ConfidenceLevel.HIGH)
        
        # PostgreSQL
        if "postgresql" in text or "postgres" in text:
            return VendorProduct("PostgreSQL", "PostgreSQL", ConfidenceLevel.HIGH)
        
        # MySQL
        if "mysql" in text:
            return VendorProduct("MySQL", "MySQL", ConfidenceLevel.HIGH)
        
        # MariaDB
        if "mariadb" in text:
            return VendorProduct("MariaDB", "MariaDB", ConfidenceLevel.HIGH)
        
        # MongoDB
        if "mongodb" in text or "mongo" in text:
            return VendorProduct("MongoDB", "MongoDB", ConfidenceLevel.HIGH)
        
        # Redis
        if "redis" in text:
            return VendorProduct("Redis", "Redis", ConfidenceLevel.HIGH)
        
        # SSL/TLS (OpenSSL, LibreSSL, etc.)
        if "openssl" in text:
            return VendorProduct("OpenSSL", "OpenSSL", ConfidenceLevel.HIGH)
        if "libressl" in text:
            return VendorProduct("LibreSSL", "LibreSSL", ConfidenceLevel.HIGH)
        
        # Default to "Other" if no match
        return VendorProduct("Other", None, ConfidenceLevel.LOW)
    
    @measure_performance
    def enrich_vulnerabilities(self, vulns: List[Dict]) -> List[Dict]:
        """
        Enrich a list of vulnerabilities with vendor/product detection
        
        Args:
            vulns: List of normalized vulnerability dictionaries
        
        Returns:
            Same list with vendor and product_family fields populated
        """
        for vuln in vulns:
            detection = self.detect(vuln)
            vuln["vendor"] = detection.vendor
            vuln["product_family"] = detection.product_family
            vuln["vendor_confidence"] = detection.confidence
        
        return vulns
    
    @staticmethod
    def seed_database_rules():
        """
        Seed database with initial vendor detection rules
        Call this during initial setup to populate the rules table
        """
        default_rules = [
            # High-priority exact matches
            {"vendor": "Microsoft", "product": "Windows Server", "regex": r"Windows Server 20\d{2}", "priority": 100},
            {"vendor": "Microsoft", "product": "Exchange", "regex": r"Microsoft Exchange", "priority": 100},
            {"vendor": "Microsoft", "product": "SQL Server", "regex": r"Microsoft SQL Server|MS SQL", "priority": 100},
            {"vendor": "Microsoft", "product": "SharePoint", "regex": r"Microsoft SharePoint", "priority": 100},
            
            # Adobe
            {"vendor": "Adobe", "product": "Acrobat", "regex": r"Adobe (Acrobat|Reader)", "priority": 90},
            {"vendor": "Adobe", "product": "Flash", "keyword": "adobe flash", "priority": 90},
            
            # Google
            {"vendor": "Google", "product": "Chrome", "keyword": "google chrome", "priority": 90},
            {"vendor": "Google", "product": "Android", "keyword": "android", "priority": 90},
            
            # Apple
            {"vendor": "Apple", "product": "macOS", "keyword": "macos", "priority": 90},
            {"vendor": "Apple", "product": "iOS", "regex": r"\biOS\b", "priority": 90},
            
            # Atlassian
            {"vendor": "Atlassian", "product": "Jira", "keyword": "jira", "priority": 85},
            {"vendor": "Atlassian", "product": "Confluence", "keyword": "confluence", "priority": 85},
            
            # Jenkins
            {"vendor": "Jenkins", "product": "Jenkins", "keyword": "jenkins", "priority": 85},
            
            # GitLab
            {"vendor": "GitLab", "product": "GitLab", "keyword": "gitlab", "priority": 85},
            
            # Generic SSL/TLS
            {"vendor": "SSL/TLS", "product": None, "keyword": "ssl certificate", "priority": 50},
            {"vendor": "SSL/TLS", "product": None, "keyword": "tls", "priority": 50},
        ]
        
        with get_db_session() as session:
            for rule_data in default_rules:
                # Check if rule already exists
                existing = session.query(VendorProductRule).filter_by(
                    vendor_name=rule_data["vendor"],
                    product_family=rule_data.get("product")
                ).first()
                
                if not existing:
                    rule = VendorProductRule(
                        vendor_name=rule_data["vendor"],
                        product_family=rule_data.get("product"),
                        regex_pattern=rule_data.get("regex"),
                        keyword=rule_data.get("keyword"),
                        priority=rule_data["priority"],
                        enabled=True,
                        updated_by="system_seed"
                    )
                    session.add(rule)
            
            session.commit()
