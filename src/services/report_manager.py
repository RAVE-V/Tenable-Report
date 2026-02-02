"""ReportManager service for handling report generation"""

import sys
import time
import logging
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Optional

from src.config import Config
from src.database.session import get_db_session
from src.database.models import Vulnerability, Server, Application, ServerApplicationMap

from src.tenable_client import TenableExporter, TenableAPIError
from src.processors.normalizer import VulnerabilityNormalizer
from src.processors.vendor_detector import VendorDetector
from src.processors.quick_wins_detector import QuickWinsDetector
from src.processors.grouper import VulnerabilityGrouper
from src.processors.server_grouper import ServerGrouper
from src.report_generator import HTMLReportGenerator
from src.xlsx_generator import XLSXReportGenerator
from src.cache import VulnCache
from src.utils.device_detector import DeviceTypeDetector

logger = logging.getLogger(__name__)


class ReportManager:
    """Manages report generation logic"""

    @staticmethod
    def generate_report(
        tag: Optional[str] = None,
        severity: Optional[str] = None,
        state: Optional[str] = None,
        format: str = "html",
        output: str = "./reports",
        servers_only: bool = True,
        fresh: bool = False,
        use_cache: bool = False,
        from_db: bool = False
    ) -> None:
        """Generate vulnerability report"""
        start_time = time.time()
        
        try:
            Config.validate()
            Config.ensure_reports_dir()
            
            # Parse filters
            filters = {}
            if tag:
                try:
                    category, value = tag.split(":", 1)
                    filters[f"tag.{category}"] = [value]
                    print(f"Filter: tag.{category} = {value}")
                except ValueError:
                    print("✗ Invalid tag format. Use Category:Value", file=sys.stderr)
                    sys.exit(1)
            
            severity_list = [s.strip().lower() for s in severity.split(",")] if severity else ["critical", "high", "medium", "low"]
            filters["severity"] = severity_list
            if severity:
                print(f"Filter: severity = {severity_list}")
            else:
                print(f"Filter: severity = {severity_list} (default, excludes Info)")
            
            state_list = [s.strip().upper() for s in state.split(",")] if state else ["ACTIVE", "RESURFACED"]
            if state:
                print(f"Filter: state = {state_list}")
            else:
                print(f"Filter: state = {state_list} (default)")
            
            vulns = []
            
            # === Database Mode (--from-db) ===
            if from_db:
                print("\n⚡ Using pre-processed data from database...")
                
                with get_db_session() as session:
                    query = session.query(Vulnerability)
                    
                    if servers_only:
                        query = query.filter(Vulnerability.device_type == 'server')
                        print("  Filter: device_type = server")
                    
                    if severity_list:
                        severity_upper = [s.capitalize() for s in severity_list]
                        query = query.filter(Vulnerability.severity.in_(severity_upper))
                        print(f"  Filter: severity in {severity_upper}")
                    
                    if state_list:
                        query = query.filter(Vulnerability.state.in_(state_list))
                        print(f"  Filter: state in {state_list}")
                    
                    db_vulns = query.all()
                    
                    if not db_vulns:
                        print("✗ No vulnerabilities found in database matching filters")
                        print("  Tip: Run 'sync-all' first to populate the database")
                        sys.exit(0)
                    
                    # Convert to dict format
                    vulns = [v.to_dict() for v in db_vulns]
                    print(f"✓ Loaded {len(vulns)} vulnerabilities from database")
                    
                    elapsed = time.time() - start_time
                    print(f"  ⏱️  Data load time: {elapsed:.2f}s")
            
            # === Normal Mode (API/Cache) ===
            else:
                cache = VulnCache()
                raw_vulns = None
                used_cache = False
                
                if not fresh:
                    cache_info = cache.get_info(filters)
                    if cache_info:
                        print(f"\n💾 Cached data found (Age: {cache_info['age_hours']:.1f} hours)")
                        if use_cache or (not cache_info['is_stale']): # Simplified non-interactive check for lib use
                            cached_data = cache.get(filters)
                            if cached_data:
                                raw_vulns = cached_data['vulnerabilities']
                                used_cache = True
                                print("✓ Using cached data")
                
                if raw_vulns is None:
                    print("Fetching vulnerabilities from Tenable...")
                    client = TenableExporter()
                    raw_vulns = client.export_vulnerabilities(filters)
                    print("💾 Caching vulnerability data for future use...")
                    cache.set(filters, raw_vulns)
                
                if not raw_vulns:
                    print("✗ No vulnerabilities found matching filters")
                    sys.exit(0)
                
                print(f"✓ {'Using' if used_cache else 'Fetched'} {len(raw_vulns)} vulnerabilities")
                print("Normalizing vulnerability data...")
                vulns = VulnerabilityNormalizer.normalize_batch(raw_vulns)
                
                # Filter by device type
                if servers_only:
                    detector = DeviceTypeDetector()
                    vulns = [v for v in vulns if detector.is_server(v.get('operating_system'))]
                
                # Filter by state
                if state_list:
                    vulns = [v for v in vulns if v.get('state', '').upper() in state_list]
            
            if not vulns:
                print("✗ No vulnerabilities found matching filters")
                sys.exit(0)
            
            # Determine Vendor/Product (if not from DB)
            if not from_db:
                print("Detecting vendors and products...")
                detector = VendorDetector()
                vulns = detector.enrich_vulnerabilities(vulns)
            
            # Quick Wins
            print("Detecting quick wins...")
            quick_wins_detector = QuickWinsDetector()
            quick_wins = quick_wins_detector.detect_quick_wins(vulns)
            
            # Grouping
            print("Grouping by vendor and product...")
            grouper = VulnerabilityGrouper()
            sorted_vendors, vendor_stats = grouper.group_and_sort(vulns)
            
            exploitable_vulns = [v for v in vulns if v.get("exploit_available")]
            
            # Enrich with Application Mappings (including team data)
            print("Enriching with application and team data...")
            hostname_to_app_info = {}
            with get_db_session() as session:
                query = session.query(
                    Server.hostname, 
                    Application.app_name, 
                    Application.owner_team,
                    Application.system_owner
                ).join(
                    ServerApplicationMap, Server.server_id == ServerApplicationMap.server_id
                ).join(
                    Application, Application.app_id == ServerApplicationMap.app_id
                )
                for hostname, app_name, owner_team, system_owner in query.all():
                    hostname_to_app_info[hostname] = {
                        "app_name": app_name,
                        "owner_team": owner_team or "Unassigned Team",
                        "system_owner": system_owner
                    }
            
            # Group by Application (existing)
            grouped_by_app = defaultdict(lambda: defaultdict(list))
            # Group by Team -> App -> Server (new)
            grouped_by_team = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
            
            for v in vulns:
                hostname = v.get("hostname", "Unknown")
                app_info = hostname_to_app_info.get(hostname, {
                    "app_name": "Unassigned",
                    "owner_team": "Unassigned Team",
                    "system_owner": None
                })
                app_name = app_info["app_name"]
                team = app_info["owner_team"]
                
                v["application"] = app_name
                v["owner_team"] = team
                
                grouped_by_app[app_name][hostname].append(v)
                grouped_by_team[team][app_name][hostname].append(v)
            
            sorted_apps = sorted(grouped_by_app.items(), key=lambda x: (x[0] == "Unassigned", x[0]))
            sorted_teams = sorted(grouped_by_team.items(), key=lambda x: (x[0] == "Unassigned Team", x[0]))
            
            # Calculate Application Stats
            app_stats = {}
            server_stats = {} 
            
            for app_name, servers in grouped_by_app.items():
                stats = {
                    "server_count": len(servers),
                    "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0
                }
                for hostname, host_vulns in servers.items():
                    first_vuln = host_vulns[0] if host_vulns else {}
                    h_stats = {
                        "os": first_vuln.get("operating_system") or "Unknown OS",
                        "ipv4": first_vuln.get("ipv4") or "N/A",
                        "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0
                    }
                    for v in host_vulns:
                        stats["total"] += 1
                        sev = v.get("severity", "").lower()
                        if sev in stats: stats[sev] += 1
                        
                        h_stats["total"] += 1
                        if sev in h_stats: h_stats[sev] += 1
                    
                    server_stats[hostname] = h_stats
                app_stats[app_name] = stats
            
            # Calculate Team Stats
            team_stats = {}
            for team_name, apps in grouped_by_team.items():
                team_stats[team_name] = {
                    "app_count": len(apps),
                    "server_count": sum(len(servers) for servers in apps.values()),
                    "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0
                }
                for app_name, servers in apps.items():
                    for hostname, host_vulns in servers.items():
                        for v in host_vulns:
                            team_stats[team_name]["total"] += 1
                            sev = v.get("severity", "").lower()
                            if sev in team_stats[team_name]:
                                team_stats[team_name][sev] += 1
            
            # Generate outputs
            output_dir = Path(output)
            output_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            tag_suffix = f"_{tag.replace(':', '_')}" if tag else ""
            severity_suffix = f"_{'_'.join(severity_list)}" if severity else ""
            
            severity_counts = Counter(v.get("severity", "").lower() for v in vulns)
            
            metadata = {
                "filters": filters,
                "total_vulns": len(vulns),
                "total_assets": len(set(v["asset_uuid"] for v in vulns if v["asset_uuid"])),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "severity_counts": dict(severity_counts),
                "mapped_servers": sum(len(servers) for app, servers in grouped_by_app.items() if app != "Unassigned"),
                "total_teams": len([t for t in grouped_by_team.keys() if t != "Unassigned Team"])
            }
            
            if format in ["xlsx", "both"]:
                xlsx_path = output_dir / f"Tenable_Report{tag_suffix}{severity_suffix}_{timestamp}.xlsx"
                print(f"Generating XLSX report: {xlsx_path}")
                xlsx_gen = XLSXReportGenerator()
                xlsx_gen.generate(vulns, xlsx_path, metadata)
                print(f"✓ XLSX report saved: {xlsx_path}")
            
            if format in ["html", "both"]:
                html_path = output_dir / f"Tenable_Report{tag_suffix}{severity_suffix}_{timestamp}.html"
                print(f"Generating HTML report: {html_path}")
                html_gen = HTMLReportGenerator()
                html_gen.generate(
                    output_path=html_path,
                    grouped_vulns=sorted_vendors,
                    vendor_stats=vendor_stats,
                    quick_wins=quick_wins,
                    metadata=metadata,
                    exploitable_vulns=exploitable_vulns,
                    grouped_by_app=sorted_apps,
                    app_stats=app_stats,
                    server_stats=server_stats,
                    grouped_by_team=sorted_teams,
                    team_stats=team_stats
                )
                print(f"✓ HTML report saved: {html_path}")
                
            print("✓ Report generation complete")

        except TenableAPIError as e:
            print(f"✗ Tenable API error: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"✗ Error: {e}", file=sys.stderr)
            logger.exception("generate-report failed")
            sys.exit(1)

    @staticmethod
    def server_report(
        severity: Optional[str] = None,
        state: Optional[str] = None,
        format: str = "xlsx",
        output: str = "./reports",
        sort_by: str = "critical",
        min_vulns: int = 0,
        servers_only: bool = False,
        fresh: bool = False,
        use_cache: bool = False
    ) -> None:
        """Generate server-focused report"""
        start_time = time.time()
        try:
            Config.validate()
            Config.ensure_reports_dir()
            
            # Parse filters
            filters = {}
            if severity:
                severity_list = [s.strip().lower() for s in severity.split(",")]
                filters["severity"] = severity_list
                print(f"Filter: severity = {severity_list}")
            
            state_list = ["ACTIVE"]
            if state:
                state_list = [s.strip().upper() for s in state.split(",")]
                print(f"Filter: state = {state_list}")
            
            # Fetch & Normalize (Duplicated from generate_report for independence)
            cache = VulnCache()
            raw_vulns = None
            
            if not fresh:
                cached_data = cache.get(filters)
                if cached_data:
                    raw_vulns = cached_data['vulnerabilities']
                    print(f"✓ Using cached data ({len(raw_vulns)} vulnerabilities)")
            
            if not raw_vulns:
                print("Fetching data from Tenable API...")
                client = TenableExporter()
                raw_vulns = client.export_vulnerabilities(filters)
                cache.set(filters, raw_vulns)
            
            vulns = VulnerabilityNormalizer.normalize_batch(raw_vulns)
            
            # Filter by device type
            if servers_only:
                detector = DeviceTypeDetector()
                vulns = [v for v in vulns if detector.is_server(v.get('operating_system'))]
            
            # Filter by state
            if state_list:
                vulns = [v for v in vulns if v.get('state', '').upper() in state_list]
            
            if not vulns:
                print("✗ No vulnerabilities found matching filters")
                sys.exit(0)
                
            # Group by Server
            print("Grouping by server...")
            grouper = ServerGrouper()
            server_data = grouper.group_by_server(vulns)
            
            # Filter by min vulns
            if min_vulns > 0:
                server_data = [s for s in server_data if s[1]['total_vulns'] >= min_vulns] # server_data is list of tuples
                print(f"Filtered to {len(server_data)} servers with >= {min_vulns} vulnerabilities")
            
            # Sort
            server_data = grouper.sort_servers(server_data, sort_by=sort_by)
            
            # Get Stats
            stats = grouper.get_server_stats(dict(server_data))
            
            # Generate Report
            output_dir = Path(output)
            output_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if format in ["xlsx", "both"]:
                xlsx_path = output_dir / f"Server_Report_{timestamp}.xlsx"
                xlsx_gen = XLSXReportGenerator()
                xlsx_gen.generate_server_report(xlsx_path, server_data, stats)
                print(f"✓ Server report saved: {xlsx_path}")
            
            if format in ["html", "both"]:
                 print("⚠️  HTML format for server reports coming on next release.")

        except Exception as e:
            print(f"✗ Error: {e}", file=sys.stderr)
            sys.exit(1)
