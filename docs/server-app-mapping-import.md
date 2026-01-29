# Server-Application Mapping Import

This document describes how to import server-to-application mappings from an Excel file.

## Overview

The `import-mappings` command allows you to bulk import server-to-application relationships from an Excel spreadsheet. This is useful for:
- Initial setup of your server inventory
- Importing data from CMDB or asset management systems
- Bulk updates to application assignments
- Maintaining server-application relationships

## Quick Start

### 1. Export Template

Generate an Excel template with example data:

```bash
python -m src.cli export-mapping-template
```

This creates `server_app_mapping_template.xlsx` with the correct format and sample data.

### 2. Fill Out Template

Open the Excel file and add your server-application mappings.

### 3. Import Data

Import the completed file:

```bash
# Preview changes without saving (recommended first)
python -m src.cli import-mappings server_app_mapping_template.xlsx --dry-run

# Actually import to database
python -m src.cli import-mappings server_app_mapping_template.xlsx
```

## Excel Template Format

### Required Columns

| Column Name | Description | Example |
|-------------|-------------|---------|
| `server_name` | Hostname or Asset UUID of the server | `web-prod-01.company.com` |
| `application_name` | Name of the application/service | `Payment Gateway` |

### Optional Columns

| Column Name | Description | Valid Values | Default |
|-------------|-------------|--------------|---------|
| `confidence` | Confidence level of the mapping | `MANUAL`, `HIGH`, `MEDIUM`, `LOW`, `AUTO` | `MANUAL` |
| `source` | Where this mapping came from | Any text (e.g., `CMDB`, `IT Team`) | `excel_import` |
| `updated_by` | Who created/updated this mapping | Username or email | `null` |

### Example Template

```
| server_name              | application_name  | confidence | source   | updated_by  |
|--------------------------|-------------------|------------|----------|-------------|
| web-prod-01.company.com  | Payment Gateway   | MANUAL     | IT Team  | john.doe    |
| db-prod-02.company.com   | Customer Portal   | MANUAL     | IT Team  | john.doe    |
| app-prod-03.company.com  | Internal CRM      | HIGH       | CMDB     | jane.smith  |
```

## How It Works

### 1. Server Matching

The import process looks for existing servers by:
- Matching `server_name` to `hostname` in the database
- Matching `server_name` to `asset_uuid` in the database

If no match is found, a new server record is created.

### 2. Application Matching

The import process looks for existing applications by:
- Matching `application_name` to `app_name` in the database

If no match is found, a new application record is created.

### 3. Mapping Creation/Update

- If a mapping already exists between the server and application, it is **updated**
- If no mapping exists, a new one is **created**

## Usage Examples

### Basic Import

```bash
python -m src.cli import-mappings my_servers.xlsx
```

### Dry Run (Preview Changes)

Test the import without making changes to the database:

```bash
python -m src.cli import-mappings my_servers.xlsx --dry-run
```

### Custom Template Location

```bash
python -m src.cli export-mapping-template --output /path/to/custom_template.xlsx
```

## Output Example

```
📂 Importing mappings from: server_app_mapping_template.xlsx

  ✓ Created server: web-prod-01.company.com
  ✓ Created application: Payment Gateway
  ✓ Created mapping: web-prod-01.company.com → Payment Gateway
  ✓ Created server: db-prod-02.company.com
  ✓ Created application: Customer Portal
  ✓ Created mapping: db-prod-02.company.com → Customer Portal

✓ Changes committed to database

============================================================
📊 IMPORT SUMMARY
============================================================
Total rows processed: 3
Servers created: 3
Servers found: 0
Applications created: 3
Applications found: 0
Mappings created: 3
Mappings updated: 0

✓ All rows imported successfully!
```

## Validation Rules

The import process validates:

1. **Required columns exist**: `server_name` and `application_name` must be present
2. **No empty values**: Required columns cannot have blank cells
3. **Valid confidence levels**: If provided, must be one of the valid enum values
4. **File format**: Must be a valid Excel file (.xlsx)

If validation fails, the import is aborted and no changes are made.

## Error Handling

If errors occur:
- Errors are reported for each problematic row
- Row numbers correspond to the Excel sheet (accounting for header row)
- The import continues processing other rows
- A summary of errors is displayed at the end

Example error output:

```
  ✗ Error on row 5: Server name cannot be empty

⚠️  Errors: 1
  - Row 5: Server name cannot be empty
```

## Best Practices

1. **Use dry-run first**: Always test with `--dry-run` before committing changes
2. **Keep source tracking**: Fill in the `source` column to track where mappings came from
3. **Use confidence levels**: Set appropriate confidence for different sources
   - `MANUAL` for IT team manual entries
   - `HIGH` for CMDB imports
   - `MEDIUM` for auto-detected mappings that need verification
4. **Regular updates**: Re-import periodically to sync with your CMDB
5. **Version control**: Keep your Excel files in version control for audit trail

## Integration with Reports

Once mappings are imported:
- Reports will group vulnerabilities by application
- Application summary tables will show server counts
- Server lists will display their assigned applications

## Troubleshooting

### "Server not found" warnings
These are normal if you're adding new servers. They will be created automatically.

### "Validation failed" errors
Check that:
- Column names match exactly (case-sensitive)
- Required columns have values in all rows
- Excel file is not corrupted

### "Mapping already exists"
If you see "Updated mapping" instead of "Created mapping", it means the server-application relationship already exists and is being updated with new values.

## Database Schema Reference

Mappings are stored in the `server_application_maps` table with:
- `server_id` → Foreign key to `servers.server_id`
- `app_id` → Foreign key to `applications.app_id`
- `confidence` → Enum: MANUAL, HIGH, MEDIUM, LOW, AUTO
- `source` → String describing the mapping source
- `updated_by` → Username/email of the person who updated
- `last_updated` → Timestamp of last update

## Related Commands

- `sync-db` - Sync vulnerabilities and assets from Tenable
- `generate-report` - Generate reports using the mappings
- `export-mapping-template` - Export Excel template
