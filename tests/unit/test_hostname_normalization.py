"""Unit tests for hostname case normalization across the pipeline"""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent.parent))

from src.processors.normalizer import VulnerabilityNormalizer
from src.processors.server_grouper import ServerGrouper


class TestHostnameNormalization:
    """Verify hostnames are normalized to lowercase everywhere"""

    def test_normalizer_lowercases_hostname(self):
        """Normalizer should lowercase the hostname field"""
        raw = {
            "asset": {"hostname": "SERVER-01.DOMAIN.COM", "uuid": "abc"},
            "output": "", "plugin": {}, "port": {}, "severity_id": 3
        }
        result = VulnerabilityNormalizer.normalize(raw)
        assert result["hostname"] == "server-01.domain.com"

    def test_normalizer_handles_none_hostname(self):
        """None hostname should become 'unknown' (lowercase)"""
        raw = {
            "asset": {"hostname": None, "uuid": "abc"},
            "output": "", "plugin": {}, "port": {}, "severity_id": 2
        }
        result = VulnerabilityNormalizer.normalize(raw)
        assert result["hostname"] == "unknown"

    def test_normalizer_handles_empty_hostname(self):
        """Empty string hostname should become 'unknown'"""
        raw = {
            "asset": {"hostname": "", "uuid": "abc"},
            "output": "", "plugin": {}, "port": {}, "severity_id": 1
        }
        result = VulnerabilityNormalizer.normalize(raw)
        assert result["hostname"] == "unknown"

    def test_grouper_merges_case_variants(self):
        """ServerGrouper should merge SERVER01, Server01, server01 into one entry"""
        vulns = [
            {"hostname": "SERVER01", "severity": "Critical", "operating_system": "Windows Server 2019",
             "plugin_name": "vuln1", "plugin_id": 1, "solution": "fix", "state": "ACTIVE"},
            {"hostname": "server01", "severity": "High", "operating_system": "Windows Server 2019",
             "plugin_name": "vuln2", "plugin_id": 2, "solution": "fix", "state": "ACTIVE"},
            {"hostname": "Server01", "severity": "Medium", "operating_system": "Windows Server 2019",
             "plugin_name": "vuln3", "plugin_id": 3, "solution": "fix", "state": "ACTIVE"},
        ]
        grouper = ServerGrouper(servers_only=False)
        grouped = grouper.group_by_server(vulns)
        
        # All three should merge into one entry keyed "server01"
        assert "server01" in grouped
        assert len(grouped) == 1
        assert grouped["server01"]["total_vulns"] == 3

    def test_grouper_case_insensitive_severity_counts(self):
        """Severity counts should be correct after merging case variants"""
        vulns = [
            {"hostname": "WEB-SRV", "severity": "Critical", "operating_system": "Linux",
             "plugin_name": "v1", "plugin_id": 1, "solution": "s", "state": "ACTIVE"},
            {"hostname": "web-srv", "severity": "High", "operating_system": "Linux",
             "plugin_name": "v2", "plugin_id": 2, "solution": "s", "state": "ACTIVE"},
        ]
        grouper = ServerGrouper(servers_only=False)
        grouped = grouper.group_by_server(vulns)
        
        assert "web-srv" in grouped
        assert grouped["web-srv"]["severity_counts"]["critical"] == 1
        assert grouped["web-srv"]["severity_counts"]["high"] == 1
        assert grouped["web-srv"]["total_vulns"] == 2
