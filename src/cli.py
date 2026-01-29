"""CLI interface for Tenable Report Generator"""

import click
import logging
import sys
from datetime import datetime, timedelta
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
                assets_map[asset_uuid] = {
                    "asset_uuid": asset_uuid,
                    "hostname": asset.get("hostname"),
                    "ipv4": asset.get("ipv4"),
                    "operating_system": asset.get("operating_system"),
                    "last_seen": datetime.utcnow()
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
@click.option("--tag", help="Filter by tag (format: Category:Value)")
@click.option("--severity", help="Filter by severity (comma-separated: Critical,High,Medium,Low)")
@click.option("--format", type=click.Choice(["xlsx", "html", "both"]), default="xlsx", help="Output format")
@click.option("--output", type=click.Path(), default="./reports", help="Output directory")
def generate_report(tag, severity, format, output):
    """Generate vulnerability report"""
    try:
        Config.validate()
        Config.ensure_reports_dir()
        
        # Import Milestone 2 processors
        from src.processors.vendor_detector import VendorDetector
        from src.processors.quick_wins_detector import QuickWinsDetector
        from src.processors.grouper import VulnerabilityGrouper
        from src.report_generator import HTMLReportGenerator
        
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
        
        if severity:
            severity_list = [s.strip().lower() for s in severity.split(",")]
            filters["severity"] = severity_list
            click.echo(f"Filter: severity = {severity_list}")
        
        # Fetch vulnerabilities
        click.echo("Fetching vulnerabilities from Tenable...")
        client = TenableExporter()
        raw_vulns = client.export_vulnerabilities(filters)
        
        if not raw_vulns:
            click.echo("✗ No vulnerabilities found matching filters")
            sys.exit(0)
        
        click.echo(f"✓ Fetched {len(raw_vulns)} vulnerabilities")
        
        # Normalize data
        click.echo("Normalizing vulnerability data...")
        vulns = VulnerabilityNormalizer.normalize_batch(raw_vulns)
        
        # Vendor Detection
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
        
        # Generate reports
        output_dir = Path(output)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        tag_suffix = f"_{tag.replace(':', '_')}" if tag else ""
        severity_suffix = f"_{'_'.join(severity_list)}" if severity else ""
        
        metadata = {
            "filters": filters,
            "total_vulns": len(vulns),
            "total_assets": len(set(v["asset_uuid"] for v in vulns if v["asset_uuid"])),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
                metadata=metadata
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


if __name__ == "__main__":
    cli()
