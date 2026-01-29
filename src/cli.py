"""CLI interface for Tenable Report Generator"""

import click
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.config import Config
from src.database.session import get_db_session, init_db
from src.database.models import Server, Application, ServerApplicationMap, ConfidenceLevel
from src.tenable_client import TenableExporter, TenableAPIError
from src.processors.normalizer import VulnerabilityNormalizer
from src.xlsx_generator import XLSXReportGenerator

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """Tenable Patch & Vulnerability Report Generator"""
    pass


@cli.command()
def init():
    """Initialize database (create tables)"""
    try:
        click.echo("Initializing database...")
        init_db()
        click.echo("✓ Database initialized successfully")
    except Exception as e:
        click.echo(f"✗ Error initializing database: {e}", err=True)
        sys.exit(1)


@cli.group()
def classify():
    """Manage device type classifications (server/workstation/network/unknown)"""
    pass


@classify.command("add")
@click.argument("os_pattern")
@click.argument("device_type", type=click.Choice(["server", "workstation", "network", "unknown"]))
def classify_add(os_pattern, device_type):
    """Add a custom OS pattern -> device type mapping
    
    Example: classify add "my custom os" server
    """
    from src.utils.device_detector import DeviceTypeDetector
    
    if DeviceTypeDetector.add_override(os_pattern, device_type):
        click.echo(f"✓ Added: '{os_pattern}' -> {device_type}")
    else:
        click.echo(f"✗ Failed to add override", err=True)


@classify.command("remove")
@click.argument("os_pattern")
def classify_remove(os_pattern):
    """Remove a custom OS pattern mapping
    
    Example: classify remove "my custom os"
    """
    from src.utils.device_detector import DeviceTypeDetector
    
    if DeviceTypeDetector.remove_override(os_pattern):
        click.echo(f"✓ Removed: '{os_pattern}'")
    else:
        click.echo(f"✗ Pattern not found: '{os_pattern}'", err=True)


@classify.command("list")
def classify_list():
    """List all custom OS pattern mappings"""
    from src.utils.device_detector import DeviceTypeDetector
    
    overrides = DeviceTypeDetector.list_overrides()
    
    if not overrides:
        click.echo("No custom overrides defined.")
        click.echo("Use 'classify add <pattern> <type>' to add one.")
        return
    
    click.echo(f"\n📋 Custom Device Type Overrides ({len(overrides)} total)")
    click.echo("-" * 50)
    for pattern, device_type in overrides.items():
        click.echo(f"  '{pattern}' -> {device_type}")
    click.echo()


@classify.command("test")
@click.argument("os_string")
def classify_test(os_string):
    """Test how an OS string would be classified
    
    Example: classify test "Windows Server 2022 Datacenter"
    """
    from src.utils.device_detector import DeviceTypeDetector
    
    device_type = DeviceTypeDetector.detect_device_type(os_string)
    click.echo(f"'{os_string}' -> {device_type}")



@cli.command()
@click.option("--limit", type=int, default=None, help="Limit assets per chunk for testing (e.g., 10 for quick test)")
@click.option("--days", type=int, default=None, help="Only fetch vulnerabilities from last N days (e.g., 7)")
def sync_db(limit, days):
    """Sync assets from Tenable to local database"""
    try:
        Config.validate()
        
        click.echo("Connecting to Tenable...")
        client = TenableExporter()
        
        # Build filters for limiting data
        filters = {}
        
        if days:
            cutoff_date = datetime.now() - timedelta(days=days)
            # Tenable uses Unix timestamps
            filters["last_found"] = int(cutoff_date.timestamp())
            click.echo(f"Filter: Only vulnerabilities from last {days} days")
        
        # Fetch vulnerabilities (with optional limit)
        click.echo("Fetching vulnerability data to extract assets...")
        if limit:
            click.echo(f"⚠️  TEST MODE: Limiting to {limit} assets per chunk for faster testing")
            # Temporarily override the config
            original_limit = Config.EXPORT_MAX_ASSETS_PER_CHUNK
            Config.EXPORT_MAX_ASSETS_PER_CHUNK = limit
            vulns = client.export_vulnerabilities(filters)
            Config.EXPORT_MAX_ASSETS_PER_CHUNK = original_limit
        else:
            vulns = client.export_vulnerabilities(filters)
        
        # Extract unique assets
        assets_map = {}
        for vuln in vulns:
            asset_uuid = vuln.get("asset", {}).get("uuid")
            if asset_uuid and asset_uuid not in assets_map:
                asset = vuln.get("asset", {})
                
                # Helper function to convert list fields to strings
                def to_string(value):
                    """Convert list to comma-separated string, or return as-is"""
                    if isinstance(value, list):
                        return ", ".join(str(v) for v in value if v) if value else None
                    return value
                
                assets_map[asset_uuid] = {
                    "asset_uuid": asset_uuid,
                    "hostname": to_string(asset.get("hostname")),
                    "ipv4": to_string(asset.get("ipv4")),
                    "operating_system": to_string(asset.get("operating_system")),
                    "last_seen": datetime.now(timezone.utc)
                }
        
        click.echo(f"Found {len(assets_map)} unique assets")
        
        # Sync to database
        with get_db_session() as session:
            for asset_data in assets_map.values():
                # Check if server exists
                server = session.query(Server).filter_by(
                    asset_uuid=asset_data["asset_uuid"]
                ).first()
                
                if server:
                    # Update existing
                    server.hostname = asset_data["hostname"]
                    server.ipv4 = asset_data["ipv4"]
                    server.operating_system = asset_data["operating_system"]
                    server.last_seen = asset_data["last_seen"]
                else:
                    # Create new
                    server = Server(**asset_data)
                    session.add(server)
            
            session.commit()
            click.echo(f"✓ Synced {len(assets_map)} servers to database")
    
    except TenableAPIError as e:
        click.echo(f"✗ Tenable API error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)
        logger.exception("sync-db failed")
        sys.exit(1)


@cli.command()
@click.option("--fresh", is_flag=True, help="Force fresh download from Tenable API (ignore cache)")
def sync_all(fresh):
    """Sync all vulnerabilities to database with pre-computed classifications
    
    This command fetches vulnerabilities from Tenable, normalizes the data,
    classifies devices (server/workstation/network), detects vendors, and
    stores everything in the database for instant report generation.
    """
    import time
    from src.database.models import Vulnerability
    from src.utils.device_detector import DeviceTypeDetector
    from src.processors.vendor_detector import VendorDetector
    from src.cache import VulnCache
    
    start_time = time.time()
    
    try:
        Config.validate()
        
        # Step 1: Fetch vulnerabilities (from cache or API)
        click.echo("📥 Step 1/4: Fetching vulnerability data...")
        cache = VulnCache()
        filters = {}
        
        if fresh:
            click.echo("   Fresh mode: Ignoring cache, fetching from API...")
            client = TenableExporter()
            raw_vulns = client.export_vulnerabilities(filters)
            # Save to cache for future use
            cache.save(filters, raw_vulns, None)
        else:
            cached = cache.get(filters)
            if cached:
                raw_vulns = cached.get('vulnerabilities', [])
                click.echo(f"   ✓ Using cached data ({len(raw_vulns)} vulnerabilities)")
            else:
                click.echo("   Cache miss, fetching from Tenable API...")
                client = TenableExporter()
                raw_vulns = client.export_vulnerabilities(filters)
                cache.save(filters, raw_vulns, None)
        
        click.echo(f"   ✓ {len(raw_vulns)} raw vulnerabilities fetched")
        click.echo("   💾 Data cached - if errors occur, rerun without --fresh")
        
        # Step 2: Normalize data
        click.echo("🔄 Step 2/4: Normalizing vulnerability data...")
        vulns = VulnerabilityNormalizer.normalize_batch(raw_vulns)
        click.echo(f"   ✓ {len(vulns)} vulnerabilities normalized")
        
        # Step 3: Classify and process
        click.echo("🏷️  Step 3/4: Classifying devices and detecting vendors...")
        detector = DeviceTypeDetector()
        vendor_detector = VendorDetector()
        
        processed = []
        for v in vulns:
            os_val = v.get('operating_system')
            device_type = detector.detect_device_type(os_val)
            vendor_result = vendor_detector.detect(v)
            vendor = vendor_result.vendor if vendor_result else 'Other'
            product = vendor_result.product_family if vendor_result else None
            
            processed.append({
                'asset_uuid': v.get('asset_uuid'),
                'hostname': v.get('hostname'),
                'ipv4': v.get('ipv4'),
                'operating_system': os_val[:255] if os_val else None,
                'device_type': device_type,
                'plugin_id': v.get('plugin_id'),
                'plugin_name': v.get('plugin_name', '')[:500] if v.get('plugin_name') else None,
                'severity': v.get('severity'),
                'state': v.get('state'),
                'cve': v.get('cve') if isinstance(v.get('cve'), list) else [],
                'vpr_score': v.get('vpr_score'),
                'cvss_score': v.get('cvss_score'),
                'exploit_available': v.get('exploit_available', False),
                'vendor': vendor,
                'product': product,
                'solution': v.get('solution', '')[:2000] if v.get('solution') else None,
                'description': v.get('description', '')[:2000] if v.get('description') else None,
                'first_found': v.get('first_found'),
                'last_found': v.get('last_found'),
                'raw_data': v,
            })
        
        # Count device types
        from collections import Counter
        device_counts = Counter(p['device_type'] for p in processed)
        for dtype, count in device_counts.items():
            click.echo(f"   • {dtype}: {count} vulnerabilities")
        
        # Step 4: Store in database
        click.echo("💾 Step 4/4: Storing in database...")
        with get_db_session() as session:
            # Clear existing vulnerabilities (full refresh)
            deleted = session.query(Vulnerability).delete()
            click.echo(f"   Cleared {deleted} existing records")
            
            # Bulk insert new data
            for p in processed:
                vuln = Vulnerability(**p)
                session.add(vuln)
            
            session.commit()
            click.echo(f"   ✓ Stored {len(processed)} vulnerabilities")
        
        elapsed = time.time() - start_time
        click.echo(f"\n✅ Sync complete in {elapsed:.1f} seconds!")
        click.echo(f"   Now run: generate-report --from-db")
        
    except TenableAPIError as e:
        click.echo(f"✗ Tenable API error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)
        logger.exception("sync-all failed")
        sys.exit(1)


@cli.command()
@click.option("--fresh", is_flag=True, help="Fetch fresh data from API instead of using cache")
def inspect_data(fresh):
    """Inspect available filter values in your Tenable data"""
    try:
        Config.validate()
        
        from src.tenable_client import TenableExporter
        from src.processors.normalizer import VulnerabilityNormalizer
        from src.cache import VulnCache
        from src.utils.device_detector import DeviceTypeDetector
        from collections import Counter
        
        click.echo("🔍 Inspecting Tenable vulnerability data...\n")
        
        # Load data (from cache or API)
        cache = VulnCache()
        raw_vulns = None
        
        if not fresh:
            cache_info = cache.get_info({})
            if cache_info:
                cached_data = cache.get({})
                if cached_data:
                    raw_vulns = cached_data['vulnerabilities']
                    click.echo(f"✓ Using cached data ({len(raw_vulns)} vulnerabilities)\n")
        
        if raw_vulns is None:
            click.echo("Fetching data from Tenable API...")
            client = TenableExporter()
            raw_vulns = client.export_vulnerabilities({})
            cache.set({}, raw_vulns)
            click.echo(f"✓ Fetched {len(raw_vulns)} vulnerabilities\n")
        
        if not raw_vulns:
            click.echo("✗ No data found!")
            return
        
        # Normalize
        vulns = VulnerabilityNormalizer.normalize_batch(raw_vulns)
        
        # Analyze available filters
        click.echo("=" * 60)
        click.echo("AVAILABLE FILTER VALUES")
        click.echo("=" * 60)
        
        # States
        states = Counter(v.get('state', 'UNKNOWN') for v in vulns)
        click.echo(f"\n📌 STATES (total: {len(vulns)} vulnerabilities)")
        for state, count in states.most_common():
            click.echo(f"   {state}: {count}")
        
        # Severities
        severities = Counter(v.get('severity', 'Unknown') for v in vulns)
        click.echo(f"\n🔥 SEVERITIES")
        for sev, count in severities.most_common():
            click.echo(f"   {sev}: {count}")
        
        # Operating Systems (handle both strings and lists)
        os_values = []
        for v in vulns:
            os_val = v.get('operating_system')
            if os_val:
                # Handle if it's a list
                if isinstance(os_val, list):
                    os_values.extend(os_val)
                else:
                    os_values.append(os_val)
        os_list = Counter(os_values)
        
        # Also count unique devices per OS
        from collections import defaultdict
        os_to_devices = defaultdict(set)
        for v in vulns:
            os_val = v.get('operating_system')
            asset_uuid = v.get('asset_uuid')
            if os_val and asset_uuid:
                if isinstance(os_val, list):
                    for os_item in os_val:
                        os_to_devices[os_item].add(asset_uuid)
                else:
                    os_to_devices[os_val].add(asset_uuid)
        
        click.echo(f"\n💻 ALL OPERATING SYSTEMS ({len(os_list)} unique OS types)")
        click.echo(f"{'Operating System':<50} {'Devices':<10} {'Vulns':<10}")
        click.echo("-" * 70)
        for os, vuln_count in sorted(os_list.items(), key=lambda x: len(os_to_devices.get(x[0], set())), reverse=True):
            device_count = len(os_to_devices.get(os, set()))
            click.echo(f"{os:<50} {device_count:<10} {vuln_count:<10}")

        
        # Device Type Detection
        detector = DeviceTypeDetector()
        device_types = {}
        for v in vulns:
            device_type = detector.detect_device_type(v.get('operating_system'))
            device_types[device_type] = device_types.get(device_type, 0) + 1
        
        click.echo(f"\n🖥️  DEVICE CLASSIFICATION")
        for dtype in ['server', 'workstation', 'network', 'unknown']:
            count = device_types.get(dtype, 0)
            if count > 0:
                click.echo(f"   {dtype.capitalize()}: {count} vulnerabilities")
        
        # Unique assets
        unique_assets = len(set(v.get('asset_uuid') for v in vulns if v.get('asset_uuid')))
        click.echo(f"\n📊 UNIQUE ASSETS: {unique_assets}")
        
        click.echo("\n" + "=" * 60)
        click.echo("💡 TIP: Use these values with --state and --severity filters")
        click.echo("=" * 60 + "\n")
        
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)
        logger.exception("inspect-data failed")
        sys.exit(1)



@cli.command()
@click.option("--tag", help="Filter by tag (format: Category:Value)")
@click.option("--severity", help="Filter by severity (comma-separated: Critical,High,Medium,Low). Default: ALL")
@click.option("--state", help="Filter by state (comma-separated: ACTIVE,RESURFACED,NEW). Default: ALL")
@click.option("--format", type=click.Choice(["xlsx", "html", "both"]), default="html", help="Output format (default: html)")
@click.option("--output", type=click.Path(), default="./reports", help="Output directory")
@click.option("--servers-only/--all-devices", default=True, help="Device scope: servers-only (default) or all-devices (includes workstations, printers, etc.)")
@click.option("--fresh", is_flag=True, help="Force fresh download from Tenable API (ignore cache)")
@click.option("--use-cache", is_flag=True, help="Use cached data if available (skip freshness check)")
@click.option("--from-db", is_flag=True, help="Use pre-processed data from database (fastest, requires sync-all first)")
def generate_report(tag, severity, state, format, output, servers_only, fresh, use_cache, from_db):
    """Generate vulnerability report"""
    import time
    start_time = time.time()
    
    try:
        Config.validate()
        Config.ensure_reports_dir()
        
        # Import modules
        from src.processors.vendor_detector import VendorDetector
        from src.processors.quick_wins_detector import QuickWinsDetector
        from src.processors.grouper import VulnerabilityGrouper
        from src.report_generator import HTMLReportGenerator
        from src.cache import VulnCache
        
        # Parse filters

        filters = {}
        
        if tag:
            try:
                category, value = tag.split(":", 1)
                filters[f"tag.{category}"] = [value]
                click.echo(f"Filter: tag.{category} = {value}")
            except ValueError:
                click.echo("✗ Invalid tag format. Use Category:Value", err=True)
                sys.exit(1)
        
        # Parse severity filter - default excludes Info
        if severity:
            severity_list = [s.strip().lower() for s in severity.split(",")]
            filters["severity"] = severity_list
            click.echo(f"Filter: severity = {severity_list}")
        else:
            # Default: exclude Info severity (usually noise)
            severity_list = ["critical", "high", "medium", "low"]
            filters["severity"] = severity_list
            click.echo(f"Filter: severity = {severity_list} (default, excludes Info)")
        
        # Parse state filter - default to ACTIVE and RESURFACED (most common states)
        if state:
            state_list = [s.strip().upper() for s in state.split(",")]
            click.echo(f"Filter: state = {state_list}")
        else:
            state_list = ["ACTIVE", "RESURFACED"]  # Default: current active vulnerabilities
            click.echo(f"Filter: state = {state_list} (default)")
        
        # === Database Mode (--from-db) ===
        if from_db:
            click.echo("\n⚡ Using pre-processed data from database...")
            from src.database.models import Vulnerability
            
            with get_db_session() as session:
                query = session.query(Vulnerability)
                
                # Apply filters
                if servers_only:
                    query = query.filter(Vulnerability.device_type == 'server')
                    click.echo("  Filter: device_type = server")
                
                if severity_list:
                    severity_upper = [s.capitalize() for s in severity_list]
                    query = query.filter(Vulnerability.severity.in_(severity_upper))
                    click.echo(f"  Filter: severity in {severity_upper}")
                
                if state_list:
                    query = query.filter(Vulnerability.state.in_(state_list))
                    click.echo(f"  Filter: state in {state_list}")
                
                db_vulns = query.all()
                
                if not db_vulns:
                    click.echo("✗ No vulnerabilities found in database matching filters")
                    click.echo("  Tip: Run 'sync-all' first to populate the database")
                    sys.exit(0)
                
                # Convert to dict format
                vulns = [v.to_dict() for v in db_vulns]
                click.echo(f"✓ Loaded {len(vulns)} vulnerabilities from database")
                
                # Skip directly to processing (data is already normalized and classified)
                elapsed = time.time() - start_time
                click.echo(f"  ⏱️  Data load time: {elapsed:.2f}s")
        
        # === Normal Mode (API/Cache) ===
        else:
            # Check cache
            cache = VulnCache()
            raw_vulns = None
            used_cache = False
            
            if not fresh:
                cache_info = cache.get_info(filters)
                
                if cache_info:
                    age_hours = cache_info['age_hours']
                    count = cache_info['count']
                    timestamp = cache_info['timestamp']
                    
                    click.echo("\n💾 Cached data found:")
                    click.echo(f"   Date: {timestamp}")
                    click.echo(f"   Age: {age_hours:.1f} hours")
                    click.echo(f"   Count: {count} vulnerabilities")
                    
                    if use_cache or (not cache_info['is_stale'] and click.confirm("Use cached data?", default=True)):
                        cached_data = cache.get(filters)
                        if cached_data:
                            raw_vulns = cached_data['vulnerabilities']
                            used_cache = True
                            click.echo("✓ Using cached data")
            
            # Fetch from API if not using cache
            if raw_vulns is None:
                click.echo("Fetching vulnerabilities from Tenable...")
                client = TenableExporter()
                raw_vulns = client.export_vulnerabilities(filters)
                
                # Cache the data
                click.echo("💾 Caching vulnerability data for future use...")
                cache.set(filters, raw_vulns)
            
            if not raw_vulns:
                click.echo("✗ No vulnerabilities found matching filters")
                sys.exit(0)
                

            
            click.echo(f"✓ {'Using' if used_cache else 'Fetched'} {len(raw_vulns)} vulnerabilities")
            
            # Normalize data
            click.echo("Normalizing vulnerability data...")
            vulns = VulnerabilityNormalizer.normalize_batch(raw_vulns)
            click.echo(f"  ➜ After normalization: {len(vulns)} vulnerabilities")
        
        # Filter by device type and state (skip if using --from-db, already filtered)
        if not from_db:
            # Filter by device type (servers only by default)
            if servers_only:
                from src.utils.device_detector import DeviceTypeDetector
                detector = DeviceTypeDetector()
                original_count = len(vulns)
                vulns = [v for v in vulns if detector.is_server(v.get('operating_system'))]
                filtered_count = original_count - len(vulns)
                click.echo(f"  ➜ After servers-only filter: {len(vulns)} vulnerabilities (removed {filtered_count})")
                if len(vulns) == 0:
                    click.echo(f"  ⚠️  WARNING: No servers detected! Your OS values might not match server patterns.")
                    click.echo(f"  💡 Try running with --all-devices to see all data")
                    # Show sample OS values for debugging
                    from collections import Counter
                    raw_os_values = [v.get('operating_system') for v in VulnerabilityNormalizer.normalize_batch(raw_vulns)]
                    unique_os = Counter(str(os) for os in raw_os_values if os)
                    click.echo(f"\n  📋 Sample OS values in your data (top 5):")
                    for os_val, cnt in unique_os.most_common(5):
                        device_type = detector.detect_device_type(os_val)
                        click.echo(f"     '{os_val}' -> classified as: {device_type} ({cnt} vulns)")

            
            
            # Apply state filtering on normalized data
            if state_list:
                original_count = len(vulns)
                vulns = [v for v in vulns if v.get('state', '').upper() in state_list]
                filtered_count = original_count - len(vulns)
                click.echo(f"  ➜ After state filter: {len(vulns)} vulnerabilities (removed {filtered_count})")
                if len(vulns) == 0:
                    click.echo(f"  ⚠️  WARNING: State filter removed all data!")
                    click.echo(f"  💡 Available states: run 'inspect-data' to see what states exist")
        
        if not vulns:
            click.echo("✗ No vulnerabilities found matching filters")
            if servers_only:
                click.echo("  Tip: Try --all-devices to include workstations")
            if state_list:
                click.echo("  Tip: Remove --state filter or use different state values")
            sys.exit(0)
        
        # Vendor Detection (skip if using --from-db, already enriched)
        if not from_db:
            click.echo("Detecting vendors and products...")
            detector = VendorDetector()
            vulns = detector.enrich_vulnerabilities(vulns)
        
        # Quick Wins Detection
        click.echo("Detecting quick wins...")
        quick_wins_detector = QuickWinsDetector()
        quick_wins = quick_wins_detector.detect_quick_wins(vulns)
        click.echo(f"  Found {quick_wins['total_quick_wins']} quick wins")
        
        # Hierarchical Grouping
        click.echo("Grouping by vendor and product...")
        grouper = VulnerabilityGrouper()
        sorted_vendors, vendor_stats = grouper.group_and_sort(vulns)
        
        # Identify exploitable vulnerabilities
        exploitable_vulns = [v for v in vulns if v.get("exploit_available")]
        click.echo(f"  Found {len(exploitable_vulns)} exploitable vulnerabilities")
        
        # Enrich with Application Mappings
        click.echo("Enriching with application data...")
        from src.database.session import get_db_session
        from src.database.models import Server, Application, ServerApplicationMap
        
        hostname_to_app = {}
        try:
            with get_db_session() as session:
                query = session.query(Server.hostname, Application.app_name)\
                    .join(ServerApplicationMap, Server.server_id == ServerApplicationMap.server_id)\
                    .join(Application, Application.app_id == ServerApplicationMap.app_id)
                hostname_to_app = {h: a for h, a in query.all()}
                click.echo(f"  Loaded {len(hostname_to_app)} server-application mappings")
        except Exception as e:
            click.echo(f"⚠ Warning: Could not fetch application mappings: {e}")
            
        # Enrich vulns and build App grouping
        from collections import defaultdict
        grouped_by_app = defaultdict(lambda: defaultdict(list))
        
        for v in vulns:
            hostname = v.get("hostname", "Unknown")
            app_name = hostname_to_app.get(hostname, "Unassigned")
            v["application"] = app_name
            grouped_by_app[app_name][hostname].append(v)
            
        # Sort apps by name (Unassigned last)
        sorted_apps = sorted(grouped_by_app.items(), key=lambda x: (x[0] == "Unassigned", x[0]))

        # Calculate Application Stats
        app_stats = {}
        server_stats = {}  # New: hostname -> {os, ipv4, critical, high, medium, low, total}
        
        for app_name, servers in grouped_by_app.items():
            stats = {
                "server_count": len(servers),
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "total": 0
            }
            for hostname, host_vulns in servers.items():
                # Get host info from first vuln (assuming consistent per host)
                first_vuln = host_vulns[0] if host_vulns else {}
                h_stats = {
                    "os": first_vuln.get("operating_system") or "Unknown OS",
                    "ipv4": first_vuln.get("ipv4") or "N/A",
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "total": 0
                }
                
                for v in host_vulns:
                    # Update App Stats
                    stats["total"] += 1
                    sev = v.get("severity", "").lower()
                    if sev in stats:
                        stats[sev] += 1
                    
                    # Update Server Stats
                    h_stats["total"] += 1
                    if sev in h_stats:
                        h_stats[sev] += 1
                
                server_stats[hostname] = h_stats
                
            app_stats[app_name] = stats
        
        # Generate reports
        output_dir = Path(output)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        tag_suffix = f"_{tag.replace(':', '_')}" if tag else ""
        severity_suffix = f"_{'_'.join(severity_list)}" if severity else ""
        
        # Calculate severity counts for stats row
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in vulns:
            sev = v.get("severity", "").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        metadata = {
            "filters": filters,
            "total_vulns": len(vulns),
            "total_assets": len(set(v["asset_uuid"] for v in vulns if v["asset_uuid"])),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "severity_counts": severity_counts
        }
        
        if format in ["xlsx", "both"]:
            xlsx_path = output_dir / f"Tenable_Report{tag_suffix}{severity_suffix}_{timestamp}.xlsx"
            click.echo(f"Generating XLSX report: {xlsx_path}")
            
            xlsx_gen = XLSXReportGenerator()
            xlsx_gen.generate(vulns, xlsx_path, metadata)
            
            click.echo(f"✓ XLSX report saved: {xlsx_path}")
        
        if format in ["html", "both"]:
            html_path = output_dir / f"Tenable_Report{tag_suffix}{severity_suffix}_{timestamp}.html"
            click.echo(f"Generating HTML report: {html_path}")
            
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
                server_stats=server_stats
            )
            
            click.echo(f"✓ HTML report saved: {html_path}")
        
        click.echo("✓ Report generation complete")
    
    except TenableAPIError as e:
        click.echo(f"✗ Tenable API error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)
        logger.exception("generate-report failed")
        sys.exit(1)


@cli.command()
@click.option("--severity", help="Filter by severity (comma-separated: Critical,High,Medium,Low)")
@click.option("--state", help="Filter by state (comma-separated: ACTIVE,RESURFACED,NEW). Default: ACTIVE only")
@click.option("--format", type=click.Choice(["xlsx", "html", "both"]), default="xlsx", help="Output format")
@click.option("--output", type=click.Path(), default="./reports", help="Output directory")
@click.option("--sort-by", type=click.Choice(["critical", "high", "total", "hostname"]), default="critical", help="Sort servers by")
@click.option("--min-vulns", type=int, default=0, help="Only show servers with at least N vulnerabilities")
@click.option("--servers-only/--all-devices", default=False, help="Only include servers or all devices (default: all devices for testing)")
@click.option("--fresh", is_flag=True, help="Force fresh download from Tenable API (ignore cache)")
@click.option("--use-cache", is_flag=True, help="Use cached data if available (skip freshness check)")
def server_report(severity, state, format, output, sort_by, min_vulns, servers_only, fresh, use_cache):
    """Generate server-focused vulnerability report"""
    try:
        Config.validate()
        Config.ensure_reports_dir()
        
        # Import modules
        from src.processors.vendor_detector import VendorDetector
        from src.processors.quick_wins_detector import QuickWinsDetector
        from src.processors.server_grouper import ServerGrouper
        from src.cache import VulnCache
        from src.xlsx_generator import XLSXReportGenerator
        
        # Parse filters
        filters = {}
        
        # Parse severity filter
        if severity:
            severity_list = [s.strip().lower() for s in severity.split(",")]
            filters["severity"] = severity_list
            click.echo(f"Filter: severity = {severity_list}")
        else:
            click.echo("Filter: severity = ALL")
        
        # Parse state filter - default to ACTIVE, RESURFACED, NEW
        if state:
            state_list = [s.strip().upper() for s in state.split(",")]
            click.echo(f"Filter: state = {state_list}")
        else:
            state_list = ["ACTIVE", "RESURFACED", "NEW"]  # Default includes all active vulnerabilities
            click.echo(f"Filter: state = {state_list} (default)")
        
        # Check cache
        cache = VulnCache()
        raw_vulns = None
        used_cache = False
        
        if not fresh:
            cache_info = cache.get_info(filters)
            
            if cache_info:
                age_hours = cache_info['age_hours']
                count = cache_info['count']
                timestamp = cache_info['timestamp']
                
                click.echo("\n💾 Cached data found:")
                click.echo(f"   Date: {timestamp}")
                click.echo(f"   Age: {age_hours:.1f} hours")
                click.echo(f"   Count: {count} vulnerabilities")
                
                if use_cache or (not cache_info['is_stale'] and click.confirm("Use cached data?", default=True)):
                    cached_data = cache.get(filters)
                    if cached_data:
                        raw_vulns = cached_data['vulnerabilities']
                        used_cache = True
                        click.echo("✓ Using cached data")
        
        # Fetch from API if not using cache
        if raw_vulns is None:
            click.echo("Fetching vulnerabilities from Tenable...")
            client = TenableExporter()
            raw_vulns = client.export_vulnerabilities(filters)
            
            # Cache the data
            click.echo("💾 Caching vulnerability data for future use...")
            cache.set(filters, raw_vulns)
        
        if not raw_vulns:
            click.echo("✗ No vulnerabilities found matching filters")
            sys.exit(0)
        
        click.echo(f"✓ {'Using' if used_cache else 'Fetched'} {len(raw_vulns)} vulnerabilities")
        
        # Normalize data
        click.echo("Normalizing vulnerability data...")
        vulns = VulnerabilityNormalizer.normalize_batch(raw_vulns)
        
        # Filter by device type (servers only by default)
        if servers_only:
            from src.utils.device_detector import DeviceTypeDetector
            detector = DeviceTypeDetector()
            original_count = len(vulns)
            vulns = [v for v in vulns if detector.is_server(v.get('operating_system'))]
            filtered_count = original_count - len(vulns)
            if filtered_count > 0:
                click.echo(f"✓ Filtered {filtered_count} non-server devices (servers only)")
        
        # Apply state filtering on normalized data
        if state_list:
            original_count = len(vulns)
            vulns = [v for v in vulns if v.get('state', '').upper() in state_list]
            filtered_count = original_count - len(vulns)
            if filtered_count > 0:
                click.echo(f"✓ Filtered {filtered_count} vulnerabilities by state (keeping {state_list})")
        
        if not vulns:
            click.echo("✗ No vulnerabilities found matching filters")
            if servers_only:
                click.echo("  Tip: Try --all-devices to include workstations")
            sys.exit(0)
        
        # Vendor Detection
        click.echo("Detecting vendors and products...")
        detector = VendorDetector()
        vulns = detector.enrich_vulnerabilities(vulns)
        
        # Quick Wins Detection
        click.echo("Detecting quick wins...")
        quick_wins_detector = QuickWinsDetector()
        quick_wins_detector.detect_quick_wins(vulns)
        
        # Group by Server (no additional filtering - already filtered above)
        device_filter = "servers only" if servers_only else "all devices"
        click.echo(f"Grouping by device ({device_filter}, sort by: {sort_by})...")
        server_grouper = ServerGrouper(servers_only=False)  # Don't re-filter, already filtered
        servers = server_grouper.group_by_server(vulns)
        
        # Filter by minimum vulnerabilities
        if min_vulns > 0:
            servers = {k: v for k, v in servers.items() if v["total_vulns"] >= min_vulns}
            click.echo(f"✓ Filtered to servers with >= {min_vulns} vulnerabilities")
        
        # Sort servers
        sorted_servers = server_grouper.sort_servers(servers, sort_by=sort_by)
        
        # Get statistics
        stats = server_grouper.get_server_stats(servers)
        
        # Count device types
        device_types = {}
        for _, server_data in servers.items():
            dtype = server_data.get("device_type", "unknown")
            device_types[dtype] = device_types.get(dtype, 0) + 1
        
        click.echo("\n📊 Server Report Summary:")
        click.echo(f"   Total Devices: {stats['total_servers']}")
        if device_types:
            for dtype, count in sorted(device_types.items()):
                click.echo(f"   - {dtype.capitalize()}: {count}")
        click.echo(f"   Total Vulnerabilities: {stats['total_vulns']}")
        click.echo(f"   Critical: {stats['severity_totals']['critical']}")
        click.echo(f"   High: {stats['severity_totals']['high']}")
        click.echo(f"   Quick Wins: {stats['total_quick_wins']}")
        
        # Generate reports
        output_dir = Path(output)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Metadata
        metadata = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_servers": stats['total_servers'],
            "total_vulns": stats['total_vulns'],
            "filters": filters,
            "sort_by": sort_by
        }
        
        if format in ["xlsx", "both"]:
            xlsx_path = output_dir / f"Server_Report_{timestamp}.xlsx"
            click.echo("\nGenerating Excel report...")
            
            xlsx_gen = XLSXReportGenerator()
            xlsx_gen.generate_server_report(
                output_path=xlsx_path,
                servers=sorted_servers,
                stats=stats,
                metadata=metadata
            )
            
            click.echo(f"✓ Excel report generated: {xlsx_path}")
        
        if format in ["html", "both"]:
            # HTML server report would go here
            click.echo("\n⚠️  HTML format for server reports coming soon!")
            click.echo("   Use --format xlsx for now")
        
        click.echo("\n✓ Server report generation complete!")
    
    except TenableAPIError as e:
        click.echo(f"✗ Tenable API error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)
        logger.exception("server-report failed")
        sys.exit(1)




@cli.command()
def list_tags():
    """List available tags from Tenable"""
    try:
        Config.validate()
        
        click.echo("Fetching tags from Tenable...")
        client = TenableExporter()
        tags = client.list_tags()
        
        if not tags:
            click.echo("No tags found")
            return
        
        click.echo(f"\nAvailable Tags ({len(tags)}):")
        click.echo("=" * 60)
        
        # Group by category
        tags_by_category = {}
        for tag in tags:
            category = tag.get("category_name", "Unknown")
            value = tag.get("value", "")
            
            if category not in tags_by_category:
                tags_by_category[category] = []
            tags_by_category[category].append(value)
        
        for category, values in sorted(tags_by_category.items()):
            click.echo(f"\n{category}:")
            for value in sorted(values):
                click.echo(f"  - {category}:{value}")
    
    except TenableAPIError as e:
        click.echo(f"✗ Tenable API error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option("--hostname", required=True, help="Server hostname")
@click.option("--app", required=True, help="Application name")
@click.option("--confidence", type=click.Choice(["manual", "auto", "inferred"]), default="manual")
@click.option("--source", default="cli", help="Mapping source")
@click.option("--user", default="cli-user", help="User making the change")
def map_server(hostname, app, confidence, source, user):
    """Map server to application"""
    try:
        with get_db_session() as session:
            # Find or create server
            server = session.query(Server).filter_by(hostname=hostname).first()
            if not server:
                click.echo(f"✗ Server '{hostname}' not found. Run 'sync-db' first.", err=True)
                sys.exit(1)
            
            # Find or create application
            application = session.query(Application).filter_by(app_name=app).first()
            if not application:
                click.echo(f"Creating new application: {app}")
                application = Application(app_name=app)
                session.add(application)
                session.flush()
            
            # Check if mapping exists
            existing = session.query(ServerApplicationMap).filter_by(
                server_id=server.server_id,
                app_id=application.app_id
            ).first()
            
            if existing:
                click.echo(f"✗ Mapping already exists: {hostname} → {app}", err=True)
                sys.exit(1)
            
            # Create mapping
            mapping = ServerApplicationMap(
                server_id=server.server_id,
                app_id=application.app_id,
                confidence=ConfidenceLevel[confidence.upper()],
                source=source,
                updated_by=user
            )
            session.add(mapping)
            session.commit()
            
            click.echo(f"✓ Mapped {hostname} → {app} (confidence: {confidence})")
    
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option("--server", help="Filter by server hostname")
@click.option("--app", help="Filter by application name")
def list_mappings(server, app):
    """List server-application mappings"""
    try:
        with get_db_session() as session:
            query = session.query(ServerApplicationMap).join(Server).join(Application)
            
            if server:
                query = query.filter(Server.hostname.like(f"%{server}%"))
            if app:
                query = query.filter(Application.app_name.like(f"%{app}%"))
            
            mappings = query.all()
            
            if not mappings:
                click.echo("No mappings found")
                return
            
            click.echo(f"\nServer-Application Mappings ({len(mappings)}):")
            click.echo("=" * 80)
            
            for mapping in mappings:
                click.echo(f"{mapping.server.hostname:30} → {mapping.application.app_name:30} [{mapping.confidence.value}]")
    
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
def seed_vendor_rules():
    """Seed database with default vendor detection rules"""
    try:
        from src.processors.vendor_detector import VendorDetector
        click.echo("Seeding default vendor detection rules...")
        VendorDetector.seed_database_rules()
        click.echo("✓ Database rules seeded successfully")
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("excel_file", type=click.Path(exists=True))
@click.option("--dry-run", is_flag=True, help="Validate without saving to database")
def import_mappings(excel_file, dry_run):
    """Import server-to-application mappings from Excel file"""
    try:
        from pathlib import Path
        from src.import_mappings import MappingImporter
        
        click.echo(f"📂 Importing mappings from: {excel_file}\n")
        
        importer = MappingImporter()
        stats = importer.import_from_excel(Path(excel_file), dry_run=dry_run)
        
        # Print summary
        click.echo("\n" + "="*60)
        click.echo("📊 IMPORT SUMMARY")
        click.echo("="*60)
        click.echo(f"Total rows processed: {stats['total_rows']}")
        click.echo(f"Servers created: {stats['servers_created']}")
        click.echo(f"Servers found: {stats['servers_found']}")
        click.echo(f"Applications created: {stats['apps_created']}")
        click.echo(f"Applications found: {stats['apps_found']}")
        click.echo(f"Mappings created: {stats['mappings_created']}")
        click.echo(f"Mappings updated: {stats['mappings_updated']}")
        
        if stats['errors']:
            click.echo(f"\n⚠️  Errors: {len(stats['errors'])}")
            for error in stats['errors']:
                click.echo(f"  - {error}")
        else:
            click.echo("\n✓ All rows imported successfully!")
        
    except ValueError as e:
        click.echo(f"✗ Validation error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)
        logger.exception("import-mappings failed")
        sys.exit(1)


@cli.command()
@click.option("--output", type=click.Path(), default="./server_app_mapping_template.xlsx", help="Output file path")
def export_mapping_template(output):
    """Export an Excel template for server-application mappings"""
    try:
        from pathlib import Path
        from src.import_mappings import MappingImporter
        
        click.echo("📋 Exporting template...")
        
        importer = MappingImporter()
        importer.export_template(Path(output))
        
        click.echo("\n✓ Template ready! Fill it out and import using:")
        click.echo(f"   python -m src.cli import-mappings {output}")
        
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)
        logger.exception("export-mapping-template failed")
        sys.exit(1)


if __name__ == "__main__":
    cli()
