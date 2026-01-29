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
            raise ValueError("Excel validation failed:\n" + "\n".join(f"  - {err}" for err in errors))
        
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
    
    def export_template(self, output_path: Path, include_existing: bool = True):
        """Export an Excel template with actual servers and existing mappings
        
        Args:
            output_path: Path for output Excel file
            include_existing: If True, include existing mappings from database
        """
        import openpyxl
        from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
        
        # Get existing servers and mappings from database
        servers_data = []
        
        with get_db_session() as session:
            # Get all servers
            servers = session.query(Server).all()
            
            for server in servers:
                # Check for existing mappings
                mappings = session.query(ServerApplicationMap).filter_by(
                    server_id=server.server_id
                ).all()
                
                if mappings and include_existing:
                    # Server has existing mappings
                    for mapping in mappings:
                        app = session.query(Application).filter_by(
                            app_id=mapping.app_id
                        ).first()
                        servers_data.append({
                            'server_name': server.hostname,
                            'application_name': app.app_name if app else '',
                            'confidence': mapping.confidence.name if mapping.confidence else 'MANUAL',
                            'source': mapping.source or 'database',
                            'updated_by': mapping.updated_by or ''
                        })
                else:
                    # Server has no mapping - add with empty application
                    servers_data.append({
                        'server_name': server.hostname,
                        'application_name': '',
                        'confidence': 'MANUAL',
                        'source': '',
                        'updated_by': ''
                    })
        
        # If no servers in DB, create example template
        if not servers_data:
            servers_data = [
                {
                    'server_name': 'web-prod-01.company.com',
                    'application_name': 'Payment Gateway',
                    'confidence': 'MANUAL',
                    'source': 'IT Team',
                    'updated_by': 'john.doe'
                },
                {
                    'server_name': 'db-prod-02.company.com',
                    'application_name': '',
                    'confidence': 'MANUAL',
                    'source': '',
                    'updated_by': ''
                }
            ]
            click.echo("ℹ️  No servers in database. Creating example template.")
        
        # Create DataFrame
        df = pd.DataFrame(servers_data)
        
        # Sort: unmapped servers first (easier to fill), then by server name
        df['has_mapping'] = df['application_name'].apply(lambda x: 0 if x else 1)
        df = df.sort_values(['has_mapping', 'server_name'], ascending=[False, True])
        df = df.drop('has_mapping', axis=1)
        
        # Write to Excel with formatting
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Server-App Mappings')
            
            # Access the worksheet to add formatting
            ws = writer.sheets['Server-App Mappings']
            
            # Style header row
            header_fill = PatternFill(start_color='1E3A8A', end_color='1E3A8A', fill_type='solid')
            header_font = Font(color='FFFFFF', bold=True)
            
            for cell in ws[1]:
                cell.fill = header_fill
                cell.font = header_font
                cell.alignment = Alignment(horizontal='center')
            
            # Highlight rows without application mapping (to be filled)
            highlight_fill = PatternFill(start_color='FEF3C7', end_color='FEF3C7', fill_type='solid')
            for row_idx, row in enumerate(ws.iter_rows(min_row=2, max_row=ws.max_row), start=2):
                # Column B is application_name
                if not row[1].value:  # No application name
                    for cell in row:
                        cell.fill = highlight_fill
            
            # Auto-adjust column widths
            for column in ws.columns:
                max_length = 0
                column_letter = column[0].column_letter
                for cell in column:
                    try:
                        if len(str(cell.value)) > max_length:
                            max_length = len(str(cell.value))
                    except:
                        pass
                ws.column_dimensions[column_letter].width = min(max_length + 2, 50)
        
        # Count stats
        total = len(df)
        mapped = len(df[df['application_name'] != ''])
        unmapped = total - mapped
        
        click.echo(f"✓ Template exported to: {output_path}")
        click.echo(f"   Total servers: {total}")
        click.echo(f"   Already mapped: {mapped} (existing mappings preserved)")
        click.echo(f"   Needs mapping: {unmapped} (highlighted in yellow)")
        click.echo(f"\n📝 Fill in the 'application_name' column for highlighted rows, then import:")
        click.echo(f"   python -m src.cli import-mappings {output_path}")
