"""XLSX report generator"""

import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict
import pandas as pd
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter

logger = logging.getLogger(__name__)


class XLSXReportGenerator:
    """Generate XLSX reports from vulnerability data"""
    
    SEVERITY_COLORS = {
        "Critical": "FFE74C3C",  # Red
        "High": "FFE67E22",      # Orange
        "Medium": "FFF39C12",    # Yellow
        "Low": "FF3498DB",       # Blue
        "Info": "FF95A5A6"       # Gray
    }
    
    def generate(self, vulnerabilities: List[Dict], output_path: Path, metadata: Dict = None):
        """
        Generate XLSX report
        
        Args:
            vulnerabilities: List of normalized vulnerability dictionaries
            output_path: Path to save XLSX file
            metadata: Optional metadata (filters, timestamp, etc.)
        """
        logger.info(f"Generating XLSX report with {len(vulnerabilities)} vulnerabilities")
        
        # Convert to DataFrame
        df = pd.DataFrame(vulnerabilities)
        
        # Select and order columns (matching reference implementation)
        columns = [
            "asset_uuid",
            "hostname",
            "ipv4",
            "operating_system",
            "plugin_id",
            "plugin_name",
            "description",
            "cve",
            "solution",
            "synopsis",
            "see_also",
            "exploit_available",
            "has_patch",
            "severity",
            "state",
            "first_found",
            "last_found"
        ]
        
        # Ensure all columns exist
        for col in columns:
            if col not in df.columns:
                df[col] = None
        
        df = df[columns]
        
        # Format CVE lists as strings
        if "cve" in df.columns:
            df["cve"] = df["cve"].apply(lambda x: ", ".join(x) if isinstance(x, list) else x)
        
        # Format see_also lists as strings
        if "see_also" in df.columns:
            df["see_also"] = df["see_also"].apply(lambda x: ", ".join(x) if isinstance(x, list) else x)
        
        # Create Excel file with formatting
        with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
            df.to_excel(writer, sheet_name="Vulnerabilities", index=False)
            
            # Get workbook and worksheet
            workbook = writer.book
            worksheet = writer.sheets["Vulnerabilities"]
            
            # Format header row
            header_fill = PatternFill(start_color="FF34495E", end_color="FF34495E", fill_type="solid")
            header_font = Font(bold=True, color="FFFFFFFF")
            
            for col_num in range(1, len(columns) + 1):
                cell = worksheet.cell(row=1, column=col_num)
                cell.fill = header_fill
                cell.font = header_font
                cell.alignment = Alignment(horizontal="center", vertical="center")
            
            # Format severity cells with color coding
            if "severity" in df.columns:
                severity_col = columns.index("severity") + 1
                for row_num in range(2, len(df) + 2):
                    cell = worksheet.cell(row=row_num, column=severity_col)
                    severity = cell.value
                    if severity in self.SEVERITY_COLORS:
                        cell.fill = PatternFill(
                            start_color=self.SEVERITY_COLORS[severity],
                            end_color=self.SEVERITY_COLORS[severity],
                            fill_type="solid"
                        )
                        cell.font = Font(bold=True, color="FFFFFFFF")
            
            # Auto-adjust column widths
            for col_num, column in enumerate(columns, start=1):
                col_letter = get_column_letter(col_num)
                
                # Calculate max width based on column name and content
                max_width = len(str(column)) + 2
                for row in worksheet.iter_rows(min_row=2, max_row=len(df) + 1, min_col=col_num, max_col=col_num):
                    cell_value = str(row[0].value) if row[0].value else ""
                    max_width = max(max_width, min(len(cell_value), 50))  # Cap at 50
                
                worksheet.column_dimensions[col_letter].width = max_width
            
            # Freeze header row
            worksheet.freeze_panes = "A2"
            
            # Add metadata sheet if provided
            if metadata:
                self._add_metadata_sheet(workbook, metadata)
        
        logger.info(f"XLSX report saved to {output_path}")
    
    def _add_metadata_sheet(self, workbook: Workbook, metadata: Dict):
        """Add metadata sheet to workbook"""
        ws = workbook.create_sheet("Report Metadata")
        
        # Add metadata rows
        ws.append(["Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
        ws.append(["Filters", str(metadata.get("filters", {}))])
        ws.append(["Total Vulnerabilities", metadata.get("total_vulns", 0)])
        ws.append(["Total Assets", metadata.get("total_assets", 0)])
        ws.append(["Runtime (seconds)", metadata.get("runtime_seconds", 0)])
        
        # Format
        for row in ws.iter_rows(min_row=1, max_row=5):
            row[0].font = Font(bold=True)
            row[0].fill = PatternFill(start_color="FFECF0F1", end_color="FFECF0F1", fill_type="solid")
        
        ws.column_dimensions["A"].width = 25
        ws.column_dimensions["B"].width = 60
