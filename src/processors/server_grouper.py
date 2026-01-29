"""Server-focused grouping for vulnerability reports"""

from typing import Dict, List
from collections import defaultdict


class ServerGrouper:
    """Group vulnerabilities by server/hostname"""
    
    def group_by_server(self, vulns: List[Dict]) -> Dict[str, Dict]:
        """
        Group vulnerabilities by server hostname
        
        Args:
            vulns: List of normalized vulnerability dictionaries
            
        Returns:
            Dictionary with server-level grouping:
            {
                "server1.company.com": {
                    "hostname": "server1.company.com",
                    "ipv4": "192.168.1.100",
                    "os": "Windows Server 2019",
                    "vulnerabilities": [...],
                    "severity_counts": {"critical": 5, "high": 12, ...},
                    "total_vulns": 25,
                    "quick_wins": 3
                },
                ...
            }
        """
        servers = defaultdict(lambda: {
            "hostname": None,
            "ipv4": None,
            "os": None,
            "vulnerabilities": [],
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "total_vulns": 0,
            "quick_wins": 0
        })
        
        for vuln in vulns:
            hostname = vuln.get("hostname", "Unknown")
            
            # Initialize server info if first time seeing this server
            if servers[hostname]["hostname"] is None:
                servers[hostname]["hostname"] = hostname
                servers[hostname]["ipv4"] = vuln.get("ipv4")
                servers[hostname]["os"] = vuln.get("operating_system")
            
            # Add vulnerability
            servers[hostname]["vulnerabilities"].append(vuln)
            servers[hostname]["total_vulns"] += 1
            
            # Count severity
            severity = vuln.get("severity", "").lower()
            if severity in servers[hostname]["severity_counts"]:
                servers[hostname]["severity_counts"][severity] += 1
            
            # Count quick wins
            if vuln.get("quick_win_category"):
                servers[hostname]["quick_wins"] += 1
        
        return dict(servers)
    
    def sort_servers(self, servers: Dict[str, Dict], sort_by: str = "critical") -> List[tuple]:
        """
        Sort servers by severity count
        
        Args:
            servers: Dictionary of server data
            sort_by: Sort key - "critical", "high", "total", "hostname"
            
        Returns:
            List of (hostname, server_data) tuples sorted by specified key
        """
        if sort_by == "hostname":
            return sorted(servers.items(), key=lambda x: x[0])
        elif sort_by == "total":
            return sorted(servers.items(), key=lambda x: x[1]["total_vulns"], reverse=True)
        else:
            # Sort by severity (critical, high, medium, low)
            return sorted(
                servers.items(),
                key=lambda x: (
                    x[1]["severity_counts"]["critical"],
                    x[1]["severity_counts"]["high"],
                    x[1]["severity_counts"]["medium"],
                    x[1]["severity_counts"]["low"]
                ),
                reverse=True
            )
    
    def get_server_stats(self, servers: Dict[str, Dict]) -> Dict:
        """
        Calculate overall statistics across all servers
        
        Returns:
            Dictionary with aggregate stats
        """
        total_servers = len(servers)
        total_vulns = sum(s["total_vulns"] for s in servers.values())
        total_quick_wins = sum(s["quick_wins"] for s in servers.values())
        
        severity_totals = {
            "critical": sum(s["severity_counts"]["critical"] for s in servers.values()),
            "high": sum(s["severity_counts"]["high"] for s in servers.values()),
            "medium": sum(s["severity_counts"]["medium"] for s in servers.values()),
            "low": sum(s["severity_counts"]["low"] for s in servers.values())
        }
        
        return {
            "total_servers": total_servers,
            "total_vulns": total_vulns,
            "total_quick_wins": total_quick_wins,
            "severity_totals": severity_totals
        }
