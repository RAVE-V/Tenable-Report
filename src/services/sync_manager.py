"""SyncManager service for handling database synchronization"""

import time
import logging
import sys
from datetime import datetime, timedelta, timezone
from collections import Counter
from typing import Dict, List, Optional

from src.config import Config
from src.database.session import get_db_session
from src.database.models import Server, Vulnerability
from src.tenable_client import TenableExporter, TenableAPIError
from src.processors.normalizer import VulnerabilityNormalizer
from src.utils.device_detector import DeviceTypeDetector
from src.processors.vendor_detector import VendorDetector
from src.cache import VulnCache

logger = logging.getLogger(__name__)


class SyncManager:
    """Manages synchronization between Tenable API and local database"""

    @staticmethod
    def sync_assets(limit: Optional[int] = None, days: Optional[int] = None) -> None:
        """
        Sync assets from Tenable to local database
        
        Args:
            limit: Limit assets per chunk (for testing)
            days: Only fetch assets seen in last N days
        """
        try:
            Config.validate()
            
            print("Connecting to Tenable...")
            client = TenableExporter()
            
            # Build filters for limiting data
            filters = {}
            if days:
                cutoff_date = datetime.now() - timedelta(days=days)
                filters["last_found"] = int(cutoff_date.timestamp())
                print(f"Filter: Only vulnerabilities from last {days} days")
            
            # Fetch vulnerabilities
            print("Fetching vulnerability data to extract assets...")
            if limit:
                print(f"⚠️  TEST MODE: Limiting to {limit} assets per chunk for faster testing")
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
                    
                    def to_string(value):
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
            
            print(f"Found {len(assets_map)} unique assets")
            
            # Bulk Sync to database
            with get_db_session() as session:
                existing_servers = session.query(Server).filter(
                    Server.asset_uuid.in_(assets_map.keys())
                ).all()
                existing_server_map = {s.asset_uuid: s for s in existing_servers}
                
                new_servers_count = 0
                updated_servers_count = 0
                
                for asset_uuid, asset_data in assets_map.items():
                    if asset_uuid in existing_server_map:
                        server = existing_server_map[asset_uuid]
                        server.hostname = asset_data["hostname"]
                        server.ipv4 = asset_data["ipv4"]
                        server.operating_system = asset_data["operating_system"]
                        server.last_seen = asset_data["last_seen"]
                        updated_servers_count += 1
                    else:
                        server = Server(**asset_data)
                        session.add(server)
                        new_servers_count += 1
                
                session.commit()
                print(f"✓ Synced {len(assets_map)} servers to database ({new_servers_count} new, {updated_servers_count} updated)")

        except TenableAPIError as e:
            print(f"✗ Tenable API error: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"✗ Error: {e}", file=sys.stderr)
            logger.exception("sync-db failed")
            sys.exit(1)

    @staticmethod
    def sync_vulnerabilities(fresh: bool = False) -> None:
        """
        Sync all vulnerabilities to database with classifications
        
        Args:
            fresh: Force fresh download from API
        """
        start_time = time.time()
        
        try:
            Config.validate()
            
            # Step 0: Seed vendor rules if not already done
            print("🔧 Ensuring vendor detection rules are seeded...")
            from src.processors.vendor_detector import VendorDetector
            VendorDetector.seed_database_rules()
            
            # Step 1: Fetch
            print("📥 Step 1/4: Fetching vulnerability data...")
            cache = VulnCache()
            filters = {}
            
            if fresh:
                print("   Fresh mode: Ignoring cache, fetching from API...")
                client = TenableExporter()
                raw_vulns = client.export_vulnerabilities(filters)
                cache.save(filters, raw_vulns, None)
            else:
                cached = cache.get(filters)
                if cached:
                    raw_vulns = cached.get('vulnerabilities', [])
                    print(f"   ✓ Using cached data ({len(raw_vulns)} vulnerabilities)")
                else:
                    print("   Cache miss, fetching from Tenable API...")
                    client = TenableExporter()
                    raw_vulns = client.export_vulnerabilities(filters)
                    cache.save(filters, raw_vulns, None)
            
            print(f"   ✓ {len(raw_vulns)} raw vulnerabilities fetched")
            print("   💾 Data cached - if errors occur, rerun without --fresh")
            
            # Step 2: Normalize
            print("🔄 Step 2/4: Normalizing vulnerability data...")
            vulns = VulnerabilityNormalizer.normalize_batch(raw_vulns)
            print(f"   ✓ {len(vulns)} vulnerabilities normalized")
            
            # Step 3: Classify and process
            print("🏷️  Step 3/4: Classifying devices and detecting vendors...")
            detector = DeviceTypeDetector()
            vendor_detector = VendorDetector()
            
            processed_objects = []
            for i, v in enumerate(vulns):
                # Get usage of raw data
                raw_v = raw_vulns[i] if raw_vulns and i < len(raw_vulns) else {}

                # Ensure date fields are datetime objects or None (Handled by Normalizer fix now)
                
                os_val = v.get('operating_system')
                device_type = detector.detect_device_type(os_val)
                vendor_result = vendor_detector.detect(v)
                vendor = vendor_result.vendor if vendor_result else 'Other'
                product = vendor_result.product_family if vendor_result else None
                
                processed_objects.append({
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
                    'raw_data': raw_v, # Use original raw data (JSON serializable) instead of normalized dict with datetimes
                })
            
            # Count device types
            device_counts = Counter(p['device_type'] for p in processed_objects)
            for dtype, count in device_counts.items():
                print(f"   • {dtype}: {count} vulnerabilities")
            
            # Step 4: Store in database
            print("💾 Step 4/4: Storing in database...")
            with get_db_session() as session:
                # Clear existing vulnerabilities (full refresh)
                deleted = session.query(Vulnerability).delete()
                print(f"   Cleared {deleted} existing records")
                
                # Bulk insert new data
                # Using SQLAlchemy Bulk Insert for better performance
                session.bulk_insert_mappings(Vulnerability, processed_objects)
                
                session.commit()
                print(f"   ✓ Stored {len(processed_objects)} vulnerabilities")
            
            elapsed = time.time() - start_time
            print(f"\n✅ Sync complete in {elapsed:.1f} seconds!")
            print(f"   Now run: generate-report --from-db")
            
        except TenableAPIError as e:
            print(f"✗ Tenable API error: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"✗ Error: {e}", file=sys.stderr)
            logger.exception("sync-all failed")
            sys.exit(1)
