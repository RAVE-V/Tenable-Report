"""ReportManager service for handling report generation"""

import sys
import time
import logging
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Tuple, Union

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
        from_db: bool = False,
        focus_servers: Optional[str] = None,
        focus_app: Optional[str] = None
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

            # Robust focus parsing
            def parse_focus_names(name_str: Optional[str]) -> List[str]:
                if not name_str:
                    return []
                return [n.strip().strip("'\"").lower() for n in name_str.split(",") if n.strip()]

            requested_servers = parse_focus_names(focus_servers)
            requested_apps = parse_focus_names(focus_app)
            
            matched_servers = set()
            matched_apps = set()
            
            vulns = []
            hostname_to_app_info = {}
            unassigned_apps = []

            # Pre-fetch mapping data from DB regardless of mode
            with get_db_session() as session:
                mappings = session.query(
                    Server.hostname, 
                    Application.app_name, 
                    Application.owner_team,
                    Application.system_owner
                ).join(
                    ServerApplicationMap, Server.server_id == ServerApplicationMap.server_id
                ).join(
                    Application, Application.app_id == ServerApplicationMap.app_id
                )
                for hostname, app_name, owner_team, system_owner in mappings.all():
                    hostname_to_app_info[hostname.lower()] = {
                        "app_name": app_name,
                        "owner_team": owner_team or "Unassigned Team",
                        "system_owner": system_owner
                    }

            # === Database Mode (--from-db) ===
            if from_db:
                print("\n[DB] Using pre-processed data from database...")
                with get_db_session() as session:
                    query = session.query(Vulnerability)
                    if servers_only:
                        query = query.filter(Vulnerability.device_type == 'server')
                    if severity_list:
                        severity_upper = [s.capitalize() for s in severity_list]
                        query = query.filter(Vulnerability.severity.in_(severity_upper))
                    if state_list:
                        query = query.filter(Vulnerability.state.in_(state_list))
                    
                    db_vulns = query.all()
                    if not db_vulns:
                        print("[ERR] No vulnerabilities found in database matching filters")
                        sys.exit(0)
                    vulns = [v.to_dict() for v in db_vulns]
                    print(f"[OK] Loaded {len(vulns)} vulnerabilities from database")
            
            # === Normal Mode (API/Cache) ===
            else:
                cache = VulnCache()
                raw_vulns = None
                used_cache = False
                if not fresh:
                    cache_info = cache.get_info(filters)
                    if cache_info and (use_cache or not cache_info['is_stale']):
                        cached_data = cache.get(filters)
                        if cached_data:
                            raw_vulns = cached_data['vulnerabilities']
                            used_cache = True
                
                if raw_vulns is None:
                    print("Fetching vulnerabilities from Tenable...")
                    client = TenableExporter()
                    raw_vulns = client.export_vulnerabilities(filters)
                    cache.set(filters, raw_vulns)
                
                if not raw_vulns:
                    print("[ERR] No vulnerabilities found matching filters")
                    sys.exit(0)
                
                vulns = VulnerabilityNormalizer.normalize_batch(raw_vulns)
                if servers_only:
                    detector = DeviceTypeDetector()
                    vulns = [v for v in vulns if detector.is_server(v.get('operating_system'))]
                if state_list:
                    vulns = [v for v in vulns if v.get('state', '').upper() in state_list]

            if not vulns:
                print("[ERR] No vulnerabilities found matching filters")
                sys.exit(0)

            # Determine Vendor/Product (if not from DB)
            if not from_db:
                detector = VendorDetector()
                vulns = detector.enrich_vulnerabilities(vulns)
            
            # Quick Wins
            quick_wins_detector = QuickWinsDetector()
            quick_wins = quick_wins_detector.detect_quick_wins(vulns)
            
            # Grouping
            grouper = VulnerabilityGrouper()
            sorted_vendors, vendor_stats = grouper.group_and_sort(vulns)
            exploitable_vulns = [v for v in vulns if v.get("exploit_available")]
            
            # === Final Grouping and Focus Logic ===
            grouped_by_app = defaultdict(lambda: defaultdict(list))
            grouped_by_team = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
            focused_grouped_by_team = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
            
            for v in vulns:
                hostname = (v.get("hostname") or "unknown").lower()
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
                
                # Apply Focus
                is_focused = False
                if hostname in requested_servers:
                    is_focused = True
                    matched_servers.add(hostname)
                if app_name.lower() in requested_apps:
                    is_focused = True
                    matched_apps.add(app_name.lower())
                
                if is_focused:
                    focused_grouped_by_team[team][app_name][hostname].append(v)

            # Validation Warnings
            for s in requested_servers:
                if s not in matched_servers:
                    print(f"[WARN] Requested focus server '{s}' not found in data")
            for a in requested_apps:
                if a not in matched_apps:
                    print(f"[WARN] Requested focus application '{a}' not found in data")

            # Sorting
            sorted_apps = sorted(grouped_by_app.items(), key=lambda x: (x[0] == "Unassigned", x[0]))
            sorted_teams = sorted(grouped_by_team.items(), key=lambda x: (x[0] == "Unassigned Team", x[0]))
            sorted_focused_teams = sorted(focused_grouped_by_team.items(), key=lambda x: (x[0] == "Unassigned Team", x[0]))
            
            # Stats calculation
            server_stats = {}
            for v in vulns:
                h = (v.get("hostname") or "unknown").lower()
                if h not in server_stats:
                    server_stats[h] = {"ipv4": v.get("ipv4", "N/A"), "os": v.get("operating_system", "Unknown"), 
                                     "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
                server_stats[h]["total"] += 1
                sev = v.get("severity", "").lower()
                if sev in server_stats[h]: server_stats[h][sev] += 1

            app_stats = {}
            for app_name, servers in grouped_by_app.items():
                first_h = list(servers.keys())[0] if servers else None
                info = hostname_to_app_info.get(first_h, {}) if first_h else {}
                stats = {"server_count": len(servers), "owner_team": info.get("owner_team", "Unassigned Team"),
                        "system_owner": info.get("system_owner", "Unknown"), "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
                for h, h_vulns in servers.items():
                    for v in h_vulns:
                        stats["total"] += 1
                        sev = v.get("severity", "").lower()
                        if sev in stats: stats[sev] += 1
                app_stats[app_name] = stats

            def calculate_team_stats(group_dict):
                t_stats = {}
                t_app_stats = {}
                for team_name, apps in group_dict.items():
                    team_owner = None
                    for app_name, servers in apps.items():
                        for h in servers:
                            info = hostname_to_app_info.get(h, {})
                            if info.get("system_owner"): team_owner = info["system_owner"]; break
                        if team_owner: break
                    
                    t_stats[team_name] = {"app_count": len(apps), "server_count": sum(len(s) for s in apps.values()),
                                        "team_owner": team_owner, "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
                    t_app_stats[team_name] = {}
                    for app_name, servers in apps.items():
                        app_sev = {"server_count": len(servers), "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
                        for h, h_vulns in servers.items():
                            for v in h_vulns:
                                t_stats[team_name]["total"] += 1
                                app_sev["total"] += 1
                                sev = v.get("severity", "").lower()
                                if sev in t_stats[team_name]: t_stats[team_name][sev] += 1
                                if sev in app_sev: app_sev[sev] += 1
                        t_app_stats[team_name][app_name] = app_sev
                return t_stats, t_app_stats

            team_stats, team_app_stats = calculate_team_stats(grouped_by_team)
            focused_team_stats, focused_team_app_stats = calculate_team_stats(focused_grouped_by_team)

            # Servers in focus (Top 10) only if no specific focus is requested
            servers_in_focus = []
            if not requested_servers and not requested_apps:
                for h, s_stats in server_stats.items():
                    if s_stats["critical"] > 0 or s_stats["high"] > 0:
                        servers_in_focus.append({"hostname": h, **s_stats})
                servers_in_focus.sort(key=lambda s: (s["critical"], s["high"], s["medium"], s["total"]), reverse=True)
                servers_in_focus = servers_in_focus[:10]

            # Fetch unassigned apps
            with get_db_session() as session:
                unassigned_apps = []
                all_apps = session.query(Application).all()
                for app in all_apps:
                    if not app.mappings:
                        unassigned_apps.append({"app_name": app.app_name, "app_type": app.app_type or "Unknown",
                                              "owner_team": app.owner_team or "Unassigned Team", "system_owner": app.system_owner or "Unknown"})

            # Metadata
            severity_counts = Counter(v.get("severity", "").lower() for v in vulns)
            metadata = {
                "filters": filters,
                "total_vulns": len(vulns),
                "total_assets": len(set(v["asset_uuid"] for v in vulns if v["asset_uuid"])),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "severity_counts": dict(severity_counts),
                "mapped_servers": sum(len(servers) for app, servers in grouped_by_app.items() if app != "Unassigned"),
                "total_teams": len([t for t in grouped_by_team.keys() if t != "Unassigned Team"]),
                "total_linux": sum(1 for s in server_stats.values() if "linux" in str(s.get("os", "")).lower()),
                "total_windows": sum(1 for s in server_stats.values() if "windows" in str(s.get("os", "")).lower())
            }

            # Outputs
            output_dir = Path(output)
            output_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            tag_suffix = f"_{tag.replace(':', '_')}" if tag else ""
            
            if format in ["xlsx", "both"]:
                xlsx_path = output_dir / f"Tenable_Report{tag_suffix}_{timestamp}.xlsx"
                XLSXReportGenerator().generate(vulns, xlsx_path, metadata)
                print(f"[OK] XLSX report saved: {xlsx_path}")
            
            if format in ["html", "both"]:
                html_path = output_dir / f"Tenable_Report{tag_suffix}_{timestamp}.html"
                HTMLReportGenerator().generate(
                    output_path=html_path, grouped_vulns=sorted_vendors, vendor_stats=vendor_stats,
                    quick_wins=quick_wins, metadata=metadata, exploitable_vulns=exploitable_vulns,
                    grouped_by_app=sorted_apps, app_stats=app_stats, server_stats=server_stats,
                    grouped_by_team=sorted_teams, team_stats=team_stats, team_app_stats=team_app_stats,
                    unassigned_apps=unassigned_apps, servers_in_focus=servers_in_focus,
                    focused_grouped_by_team=sorted_focused_teams, focused_team_stats=focused_team_stats,
                    focused_team_app_stats=focused_team_app_stats
                )
                print(f"[OK] HTML report saved: {html_path}")
                
            print("[OK] Report generation complete")

        except TenableAPIError as e:
            print(f"[ERR] Tenable API error: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"[ERR] Error: {e}", file=sys.stderr)
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
            
            state_list = ["ACTIVE"]
            if state:
                state_list = [s.strip().upper() for s in state.split(",")]
            
            cache = VulnCache()
            raw_vulns = None
            if not fresh:
                cached_data = cache.get(filters)
                if cached_data:
                    raw_vulns = cached_data['vulnerabilities']
            
            if not raw_vulns:
                client = TenableExporter()
                raw_vulns = client.export_vulnerabilities(filters)
                cache.set(filters, raw_vulns)
            
            vulns = VulnerabilityNormalizer.normalize_batch(raw_vulns)
            if servers_only:
                detector = DeviceTypeDetector()
                vulns = [v for v in vulns if detector.is_server(v.get('operating_system'))]
            if state_list:
                vulns = [v for v in vulns if v.get('state', '').upper() in state_list]
            
            if not vulns:
                print("✗ No vulnerabilities found matching filters")
                sys.exit(0)
                
            grouper = ServerGrouper()
            server_data = grouper.group_by_server(vulns)
            server_data = grouper.sort_servers(server_data, sort_by=sort_by)
            
            if min_vulns > 0:
                server_data = [(hostname, data) for hostname, data in server_data if data['total_vulns'] >= min_vulns]
            
            stats = grouper.get_server_stats(dict(server_data))
            
            output_dir = Path(output)
            output_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if format in ["xlsx", "both"]:
                xlsx_path = output_dir / f"Server_Report_{timestamp}.xlsx"
                XLSXReportGenerator().generate_server_report(xlsx_path, server_data, stats)
                print(f"✓ Server report saved: {xlsx_path}")
            
            if format in ["html", "both"]:
                 html_path = output_dir / f"Server_Report_{timestamp}.html"
                 HTMLReportGenerator().generate_server_report(
                     html_path, server_data, stats,
                     metadata={"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                 )
                 print(f"✓ Server HTML report saved: {html_path}")

        except Exception as e:
            print(f"✗ Error: {e}", file=sys.stderr)
            sys.exit(1)
