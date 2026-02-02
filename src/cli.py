"""CLI interface for Tenable Report Generator"""

import click
import logging
import sys
from datetime import datetime, timezone

from src.config import Config
from src.database.session import get_db_session, init_db
from src.database.models import Server, Application, ServerApplicationMap, ConfidenceLevel
from src.services.sync_manager import SyncManager
from src.services.report_manager import ReportManager
# Keep imports needed for remaining commands:
from src.utils.device_detector import DeviceTypeDetector
from src.tenable_client import TenableExporter, TenableAPIError
from src.processors.normalizer import VulnerabilityNormalizer
from src.cache import VulnCache

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def safe_echo(msg, err=False):
    """Echo message with fallback for Windows encoding issues"""
    # Map of common emoji to ASCII-safe alternatives
    emoji_map = {
        "✓": "[OK]", "✗": "[ERR]", "⚠️": "[WARN]", "⚠": "[WARN]",
        "📋": "[EXPORT]", "📂": "[FILE]", "📊": "[STATS]", "📝": "[NOTE]",
        "✨": "[*]", "💾": "[SAVE]", "⏱️": "[TIME]", "ℹ️": "[INFO]",
        "↻": "[UPD]", "🔍": "[DRY]", "👥": "[TEAM]", "📦": "[APP]",
        "🖥️": "[SRV]", "🛡️": "[SEC]"
    }
    try:
        click.echo(msg, err=err)
    except UnicodeEncodeError:
        safe_msg = msg
        for emoji, replacement in emoji_map.items():
            safe_msg = safe_msg.replace(emoji, replacement)
        click.echo(safe_msg, err=err)



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
    """Add a custom OS pattern -> device type mapping"""
    if DeviceTypeDetector.add_override(os_pattern, device_type):
        click.echo(f"✓ Added: '{os_pattern}' -> {device_type}")
    else:
        click.echo(f"✗ Failed to add override", err=True)


@classify.command("remove")
@click.argument("os_pattern")
def classify_remove(os_pattern):
    """Remove a custom OS pattern mapping"""
    if DeviceTypeDetector.remove_override(os_pattern):
        click.echo(f"✓ Removed: '{os_pattern}'")
    else:
        click.echo(f"✗ Pattern not found: '{os_pattern}'", err=True)


@classify.command("list")
def classify_list():
    """List all custom OS pattern mappings"""
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
    """Test how an OS string would be classified"""
    device_type = DeviceTypeDetector.detect_device_type(os_string)
    click.echo(f"'{os_string}' -> {device_type}")


@cli.command()
@click.option("--limit", type=int, default=None, help="Limit assets per chunk for testing")
@click.option("--days", type=int, default=None, help="Only fetch vulnerabilities from last N days")
def sync_db(limit, days):
    """Sync assets from Tenable to local database"""
    SyncManager.sync_assets(limit, days)


@cli.command()
@click.option("--fresh", is_flag=True, help="Force fresh download from Tenable API (ignore cache)")
def sync_all(fresh):
    """Sync all vulnerabilities to database with pre-computed classifications"""
    SyncManager.sync_vulnerabilities(fresh)


@cli.command()
@click.option("--fresh", is_flag=True, help="Fetch fresh data from API instead of using cache")
def inspect_data(fresh):
    """Inspect available filter values in your Tenable data"""
    from collections import Counter
    try:
        Config.validate()
        click.echo("🔍 Inspecting Tenable vulnerability data...\n")
        
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
        
        vulns = VulnerabilityNormalizer.normalize_batch(raw_vulns)
        
        click.echo("=" * 60)
        click.echo("AVAILABLE FILTER VALUES")
        click.echo("=" * 60)
        
        states = Counter(v.get('state', 'UNKNOWN') for v in vulns)
        click.echo(f"\n📌 STATES (total: {len(vulns)} vulnerabilities)")
        for state, count in states.most_common():
            click.echo(f"   {state}: {count}")
        
        severities = Counter(v.get('severity', 'Unknown') for v in vulns)
        click.echo(f"\n🔥 SEVERITIES")
        for sev, count in severities.most_common():
            click.echo(f"   {sev}: {count}")
        
        os_values = []
        for v in vulns:
            os_val = v.get('operating_system')
            if os_val:
                if isinstance(os_val, list):
                    os_values.extend(os_val)
                else:
                    os_values.append(os_val)
        os_list = Counter(os_values)
        
        click.echo(f"\n💻 OPERATING SYSTEMS (Top 30)")
        for os, count in os_list.most_common(30):
            click.echo(f"   {os}: {count}")

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

    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option("--tag", help="Filter by tag (format: Category:Value)")
@click.option("--severity", help="Filter by severity (comma-separated: Critical,High,Medium,Low)")
@click.option("--state", help="Filter by state (comma-separated: ACTIVE,RESURFACED,NEW)")
@click.option("--format", type=click.Choice(["xlsx", "html", "both"]), default="html", help="Output format")
@click.option("--output", type=click.Path(), default="./reports", help="Output directory")
@click.option("--servers-only/--all-devices", default=True, help="Device scope: servers-only or all-devices")
@click.option("--fresh", is_flag=True, help="Force fresh download from Tenable API")
@click.option("--use-cache", is_flag=True, help="Use cached data if available")
@click.option("--from-db", is_flag=True, help="Use pre-processed data from database")
def generate_report(tag, severity, state, format, output, servers_only, fresh, use_cache, from_db):
    """Generate vulnerability report"""
    ReportManager.generate_report(tag, severity, state, format, output, servers_only, fresh, use_cache, from_db)


@cli.command()
@click.option("--severity", help="Filter by severity (comma-separated: Critical,High,Medium,Low)")
@click.option("--state", help="Filter by state (comma-separated: ACTIVE,RESURFACED,NEW)")
@click.option("--format", type=click.Choice(["xlsx", "html", "both"]), default="xlsx", help="Output format")
@click.option("--output", type=click.Path(), default="./reports", help="Output directory")
@click.option("--sort-by", type=click.Choice(["critical", "high", "total", "hostname"]), default="critical", help="Sort servers by")
@click.option("--min-vulns", type=int, default=0, help="Only show servers with at least N vulnerabilities")
@click.option("--servers-only/--all-devices", default=False, help="Only include servers or all devices")
@click.option("--fresh", is_flag=True, help="Force fresh download from Tenable API")
@click.option("--use-cache", is_flag=True, help="Use cached data if available")
def server_report(severity, state, format, output, sort_by, min_vulns, servers_only, fresh, use_cache):
    """Generate server-focused vulnerability report"""
    ReportManager.server_report(severity, state, format, output, sort_by, min_vulns, servers_only, fresh, use_cache)


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
    
    except TenableAPIError:
        click.echo("ℹ️  Tags feature not supported by this API key or endpoint.", err=True)
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)


@cli.command("list-mappings")
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


@cli.command("import-mappings")
@click.argument("excel_file", type=click.Path(exists=True))
@click.option("--type", "import_type", type=click.Choice(["servers", "apps"]), default="servers", help="Template type: servers (server-app mappings) or apps (application metadata)")
@click.option("--dry-run", is_flag=True, help="Validate without saving to database")
def import_mappings(excel_file, import_type, dry_run):
    """Import mappings from Excel file
    
    Types:
      servers - Server-to-application mappings (default)
      apps    - Application metadata (name, type, owner_team, system_owner)
    """
    try:
        from pathlib import Path
        from src.import_mappings import MappingImporter
        
        importer = MappingImporter()
        
        if import_type == "apps":
            click.echo(f"📂 Importing application metadata from: {excel_file}\n")
            stats = importer.import_apps_from_excel(Path(excel_file), dry_run=dry_run)
            
            click.echo("\n" + "="*60)
            click.echo("📊 IMPORT SUMMARY (Applications)")
            click.echo("="*60)
            click.echo(f"Total rows: {stats['total_rows']}")
            click.echo(f"Applications created: {stats['apps_created']}")
            click.echo(f"Applications updated: {stats['apps_updated']}")
        else:
            click.echo(f"📂 Importing server mappings from: {excel_file}\n")
            stats = importer.import_from_excel(Path(excel_file), dry_run=dry_run)
            
            click.echo("\n" + "="*60)
            click.echo("📊 IMPORT SUMMARY (Server Mappings)")
            click.echo("="*60)
            click.echo(f"Total rows: {stats['total_rows']}")
            click.echo(f"Mappings created: {stats['mappings_created']}")
            click.echo(f"Mappings updated: {stats['mappings_updated']}")
        
        if stats['errors']:
            click.echo(f"\n⚠️  Errors: {len(stats['errors'])}")
        else:
            click.echo("\n✓ All rows imported successfully!")
            
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)


@cli.group("export-template")
def export_template():
    """Export Excel templates for mappings"""
    pass


@export_template.command("servers")
@click.option("--output", type=click.Path(), default="./server_app_mapping_template.xlsx", help="Output file path")
@click.option("--servers-only", is_flag=True, help="Export only servers (device_type=server), exclude workstations/network devices")
def export_servers_template(output, servers_only):
    """Export server-to-application mapping template
    
    Exports all assets with columns: server_name, application_name, confidence, source
    Use --servers-only to filter to only server device types.
    """
    try:
        from pathlib import Path
        from src.import_mappings import MappingImporter
        
        safe_echo("[EXPORT] Exporting servers template...")
        if servers_only:
            safe_echo("  Filter: device_type = server only")
        
        importer = MappingImporter()
        importer.export_template(Path(output), servers_only=servers_only)
        safe_echo(f"\n[NOTE] Import with: python -m src.cli import-mappings {output}")
    except Exception as e:
        safe_echo(f"[ERR] Error: {e}", err=True)
        sys.exit(1)


@export_template.command("apps")
@click.option("--output", type=click.Path(), default="./applications_template.xlsx", help="Output file path")
def export_apps_template(output):
    """Export applications catalog template
    
    Exports all applications with columns: application_name, app_type, description, system_owner, owner_team
    Fill in system_owner and owner_team, then import with --type apps.
    """
    try:
        from pathlib import Path
        from src.import_mappings import MappingImporter
        
        safe_echo("[EXPORT] Exporting applications template...")
        importer = MappingImporter()
        importer.export_apps_template(Path(output))
    except Exception as e:
        safe_echo(f"[ERR] Error: {e}", err=True)
        sys.exit(1)


# Keep old command for backward compatibility (deprecated)
@cli.command("export-mapping-template", hidden=True)
@click.option("--output", type=click.Path(), default="./server_app_mapping_template.xlsx", help="Output file path")
def export_mapping_template_legacy(output):
    """[DEPRECATED] Use 'export-template servers' instead"""
    try:
        from pathlib import Path
        from src.import_mappings import MappingImporter
        safe_echo("[WARN] This command is deprecated. Use 'export-template servers' instead.\n")
        safe_echo("[EXPORT] Exporting template...")
        importer = MappingImporter()
        importer.export_template(Path(output))
        safe_echo(f"\n[OK] Template ready: {output}")
        safe_echo(f"   python -m src.cli import-mappings {output}")
    except Exception as e:
        safe_echo(f"[ERR] Error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    cli()

