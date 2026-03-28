"""HTML Report Generator for vulnerability data"""

from pathlib import Path
from typing import Dict, List, Tuple
from jinja2 import Environment, FileSystemLoader, select_autoescape


class HTMLReportGenerator:
    """Generate interactive HTML vulnerability reports"""
    
    def __init__(self):
        # Setup Jinja2 environment
        template_dir = Path(__file__).parent / "templates"
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(['html', 'xml'])
        )
    
    def generate(
        self,
        output_path: Path,
        grouped_vulns: List = None,
        vendor_stats: Dict = None,
        quick_wins: Dict = None,
        metadata: Dict = None,
        exploitable_vulns: List[Dict] = None,
        grouped_by_app: List = None,
        app_stats: Dict = None,
        server_stats: Dict = None,
        grouped_by_team: List = None,
        team_stats: Dict = None,
        team_app_stats: Dict = None,
        unassigned_apps: List = None,
        servers_in_focus: List = None,
        focused_grouped_by_team: List = None,
        focused_team_stats: Dict = None,
        focused_team_app_stats: Dict = None
    ):
        """Generate HTML report"""
        if not output_path:
            raise ValueError("Output path is required")

        # Load template
        template = self.env.get_template("report_template.html")

        # Render HTML
        html_content = template.render(
            grouped_vulns=grouped_vulns or [],
            vendor_stats=vendor_stats or {},
            quick_wins=quick_wins or {},
            metadata=metadata or {},
            exploitable_vulns=exploitable_vulns or [],
            grouped_by_app=grouped_by_app or [],
            app_stats=app_stats or {},
            server_stats=server_stats or {},
            grouped_by_team=grouped_by_team or [],
            team_stats=team_stats or {},
            team_app_stats=team_app_stats or {},
            unassigned_apps=unassigned_apps or [],
            servers_in_focus=servers_in_focus or [],
            focused_grouped_by_team=focused_grouped_by_team or [],
            focused_team_stats=focused_team_stats or {},
            focused_team_app_stats=focused_team_app_stats or {}
        )

        
        # Write to file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
    
    def generate_server_report(
        self,
        output_path: Path,
        server_data: List[Tuple[str, Dict]],
        stats: Dict,
        metadata: Dict = None
    ):
        """Generate HTML report for server patch data.
        
        Args:
            output_path: Path to write the HTML file
            server_data: List of (hostname, data_dict) tuples
            stats: Overall statistics from ServerGrouper.get_server_stats()
            metadata: Optional metadata dict (timestamp, etc.)
        """
        if not output_path:
            raise ValueError("Output path is required")
        
        from datetime import datetime
        if metadata is None:
            metadata = {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        
        template = self.env.get_template("server_report_template.html")
        
        html_content = template.render(
            server_data=server_data,
            stats=stats,
            metadata=metadata
        )
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

    @staticmethod
    def get_vendor_advisory_link(vendor: str, cve: str = None) -> str:
        """
        Generate vendor security advisory URL
        
        Args:
            vendor: Vendor name
            cve: Optional CVE identifier
        
        Returns:
            URL to vendor security advisories
        """
        vendor_lower = vendor.lower()
        
        if cve:
            # NVD links for CVEs
            return f"https://nvd.nist.gov/vuln/detail/{cve}"
        
        # Vendor-specific security pages
        vendor_links = {
            "microsoft": "https://msrc.microsoft.com/update-guide",
            "oracle": "https://www.oracle.com/security-alerts/",
            "apache": "https://httpd.apache.org/security/vulnerabilities_24.html",
            "canonical": "https://ubuntu.com/security/notices",
            "debian": "https://www.debian.org/security/",
            "red hat": "https://access.redhat.com/security/security-updates/",
            "centos": "https://www.centos.org/security/",
            "docker": "https://docs.docker.com/engine/release-notes/",
            "vmware": "https://www.vmware.com/security/advisories.html",
            "cisco": "https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
            "nginx": "http://nginx.org/en/security_advisories.html",
            "postgresql": "https://www.postgresql.org/support/security/",
            "mysql": "https://www.mysql.com/support/security.html",
        }
        
        return vendor_links.get(vendor_lower, "#")
