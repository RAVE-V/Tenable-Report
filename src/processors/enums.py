"""Enums for processors"""

from enum import Enum


class ConfidenceLevel(str, Enum):
    """Vendor detection confidence levels"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class QuickWinCategory(str, Enum):
    """Quick wins categorization"""
    VERSION_THRESHOLD = "version_threshold"
    UNSUPPORTED_PRODUCT = "unsupported_product"


class SeverityLevel(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
