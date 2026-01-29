"""Import server-to-application mappings from Excel"""

import pandas as pd
from pathlib import Path
from typing import Dict, List
import click

from src.database.models import Server, Application, ServerApplicationMap, ConfidenceLevel
from src.database.connection import get_db_session


class MappingImporter:
    """Import server-application mappings from Excel files"""
    
    REQUIRED_COLUMNS = ['server_name', 'application_name']
    OPTIONAL_COLUMNS = ['confidence', 'source', 'updated_by']
    
    def __init__(self):
        pass
    
    def validate_excel(self, df: pd.DataFrame) -> List[str]:
        """Validate Excel structure and return list of errors"""
        errors = []
        
        # Check required columns exist
        missing_cols = set(self.REQUIRED_COLUMNS) - set(df.columns)
        if missing_cols:
            errors.append(f"Missing required columns: {', '.join(missing_cols)}")
        
        # Check for empty required columns
        if not errors:
            for col in self.REQUIRED_COLUMNS:
                if df[col].isna().any():
                    empty_rows = df[df[col].isna()].index.tolist()
                    errors.append(f"Column '{col}' has empty values in rows: {empty_rows}")
        
        return errors
    
    def import_from_excel(self, excel_path: Path, dry_run: bool = False) -> Dict:
        """
        Import mappings from Excel file
        
        Args:
            excel_path: Path to Excel file
            dry_run: If True, validate but don't save to database
            
        Returns:
            Dict with import statistics
        """
        # Read Excel
        try:
            df = pd.read_excel(excel_path)
        except Exception as e:
            raise ValueError(f"Failed to read Excel file: {e}")
        
        # Validate
        errors = self.validate_excel(df)
        if errors:
            raise ValueError(f"Excel validation failed:\n" + "\n".join(f"  - {err}" for err in errors))
        
        stats = {
            'total_rows': len(df),
            'servers_created': 0,
            'servers_found': 0,
            'apps_created': 0,
            'apps_found': 0,
            'mappings_created': 0,
            'mappings_updated': 0,
            'errors': []
        }
        
        if dry_run:
            click.echo("🔍 DRY RUN - No changes will be saved to database")
        
        with get_db_session() as session:
            for idx, row in df.iterrows():
                try:
                    server_name = str(row['server_name']).strip()
                    app_name = str(row['application_name']).strip()
                    
                    # Get or create Server
                    server = session.query(Server).filter(
                        (Server.hostname == server_name) | (Server.asset_uuid == server_name)
                    ).first()
                    
                    if not server:
                        # Create new server
                        server = Server(hostname=server_name)
                        session.add(server)
                        session.flush()  # Get server_id
                        stats['servers_created'] += 1
                        click.echo(f"  ✓ Created server: {server_name}")
                    else:
                        stats['servers_found'] += 1
                    
                    # Get or create Application
                    app = session.query(Application).filter_by(app_name=app_name).first()
                    
                    if not app:
                        # Create new application
                        app = Application(app_name=app_name)
                        session.add(app)
                        session.flush()  # Get app_id
                        stats['apps_created'] += 1
                        click.echo(f"  ✓ Created application: {app_name}")
                    else:
                        stats['apps_found'] += 1
                    
                    # Check if mapping exists
                    mapping = session.query(ServerApplicationMap).filter_by(
                        server_id=server.server_id,
                        app_id=app.app_id
                    ).first()
                    
                    # Parse optional fields
                    confidence = ConfidenceLevel.MANUAL  # Default for manual imports
                    if 'confidence' in row and pd.notna(row['confidence']):
                        conf_str = str(row['confidence']).upper()
                        if conf_str in ['HIGH', 'MEDIUM', 'LOW', 'AUTO', 'MANUAL']:
                            confidence = ConfidenceLevel[conf_str]
                    
                    source = 'excel_import'
                    if 'source' in row and pd.notna(row['source']):
                        source = str(row['source']).strip()
                    
                    updated_by = None
                    if 'updated_by' in row and pd.notna(row['updated_by']):
                        updated_by = str(row['updated_by']).strip()
                    
                    if mapping:
                        # Update existing mapping
                        mapping.confidence = confidence
                        mapping.source = source
                        mapping.updated_by = updated_by
                        stats['mappings_updated'] += 1
                        click.echo(f"  ↻ Updated mapping: {server_name} → {app_name}")
                    else:
                        # Create new mapping
                        mapping = ServerApplicationMap(
                            server_id=server.server_id,
                            app_id=app.app_id,
                            confidence=confidence,
                            source=source,
                            updated_by=updated_by
                        )
                        session.add(mapping)
                        stats['mappings_created'] += 1
                        click.echo(f"  ✓ Created mapping: {server_name} → {app_name}")
                
                except Exception as e:
                    error_msg = f"Row {idx + 2}: {str(e)}"
                    stats['errors'].append(error_msg)
                    click.echo(f"  ✗ Error on row {idx + 2}: {e}", err=True)
            
            if not dry_run:
                session.commit()
                click.echo("\n✓ Changes committed to database")
            else:
                click.echo("\n🔍 DRY RUN - No changes saved")
        
        return stats
    
    def export_template(self, output_path: Path):
        """Export an Excel template with example data"""
        template_data = {
            'server_name': [
                'web-prod-01.company.com',
                'db-prod-02.company.com',
                'app-prod-03.company.com'
            ],
            'application_name': [
                'Payment Gateway',
                'Customer Portal',
                'Internal CRM'
            ],
            'confidence': [
                'MANUAL',
                'MANUAL',
                'HIGH'
            ],
            'source': [
                'IT Team',
                'IT Team',
                'CMDB'
            ],
            'updated_by': [
                'john.doe',
                'john.doe',
                'jane.smith'
            ]
        }
        
        df = pd.DataFrame(template_data)
        df.to_excel(output_path, index=False, sheet_name='Server-App Mappings')
        
        click.echo(f"✓ Template exported to: {output_path}")
