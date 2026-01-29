# Getting Started with Tenable Report Generator

## 🚀 Quick Start Guide

This guide will walk you through your first use of the Tenable Report Generator.

---

## Prerequisites

1. **Python 3.8+** installed
2. **Tenable.io account** with API access
3. **API Keys** (Access Key and Secret Key)

---

## Step 1: Installation

### Clone the Repository
```bash
git clone https://github.com/RAVE-V/Tenable-Report.git
cd Tenable-Report
```

### Create Virtual Environment
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

---

## Step 2: Configuration

### Create `.env` File
Copy the example environment file:
```bash
cp .env.example .env
```

### Edit `.env` with Your Credentials
```env
# Tenable API Credentials
TENABLE_ACCESS_KEY=your_access_key_here
TENABLE_SECRET_KEY=your_secret_key_here
TENABLE_BASE_URL=https://cloud.tenable.com

# Optional: Adjust these if needed
EXPORT_MAX_ASSETS_PER_CHUNK=5000
CACHE_MAX_AGE_HOURS=24
```

**Where to get API keys:**
1. Log in to Tenable.io
2. Go to Settings → My Account → API Keys
3. Click "Generate" to create new keys

---

## Step 3: Initialize Database

```bash
python -m src.cli init
```

**What this does:**
- Creates SQLite database (`tenable_reports.db`)
- Sets up tables for servers, applications, mappings, etc.

**Expected output:**
```
✓ Database initialized successfully
```

---

## Step 4: Sync Data from Tenable (Optional)

This step downloads asset data to your local database. **This is optional** - you can skip to Step 5 to generate reports directly.

```bash
# Quick test with limited data
python -m src.cli sync-db --limit 10 --days 7

# Full sync (may take several minutes)
python -m src.cli sync-db
```

**What this does:**
- Downloads vulnerabilities from Tenable
- Extracts unique assets (servers)
- Stores in local database

**Expected output:**
```
Fetching vulnerabilities from Tenable...
✓ Fetched 1,247 vulnerabilities
Found 43 unique assets
✓ Synced 43 assets to database
```

---

## Step 5: Generate Your First Report

### Option A: HTML Report (Recommended for first run)

```bash
python -m src.cli generate-report --severity Critical,High --format html
```

**What happens:**
1. Downloads vulnerabilities from Tenable API
2. Filters for Critical and High severity
3. Filters for ACTIVE state only (default)
4. Detects vendors and products
5. Identifies Quick Wins
6. Generates HTML report in `./reports/` directory

**Expected output:**
```
Filter: severity = ['critical', 'high']
Filter: state = ['ACTIVE']
Fetching vulnerabilities from Tenable...
💾 Caching vulnerability data for future use...
✓ Fetched 523 vulnerabilities
Normalizing vulnerability data...
Detecting vendors and products...
Detecting quick wins...
  Found 47 quick wins
Grouping by vendor and product...
Generating HTML report...
✓ Report generated: ./reports/Tenable_Report_20260129_120000.html
```

### Option B: Excel Report

```bash
python -m src.cli generate-report --severity Critical,High --format xlsx
```

### Option C: Both Formats

```bash
python -m src.cli generate-report --severity Critical,High --format both
```

---

## Step 6: View Your Report

### HTML Report
- Open the generated HTML file in your browser
- Navigate using the sticky navigation bar
- Explore Quick Wins section
- Drill down into vendor/product details

### Excel Report
- Open in Microsoft Excel or Google Sheets
- Multiple worksheets for different views
- Filterable and sortable data

---

## Common Commands Reference

### Generate Reports

```bash
# Critical and High vulnerabilities only
python -m src.cli generate-report --severity Critical,High

# All severities, HTML format
python -m src.cli generate-report --format html

# Include RESURFACED vulnerabilities
python -m src.cli generate-report --state ACTIVE,RESURFACED

# Filter by tag
python -m src.cli generate-report --tag Application:PaymentGateway

# Use cached data (faster, no API call)
python -m src.cli generate-report --use-cache

# Force fresh download
python -m src.cli generate-report --fresh
```

### Server-Application Mapping

```bash
# Export template
python -m src.cli export-mapping-template

# Import mappings (dry-run first)
python -m src.cli import-mappings server_app_mapping_template.xlsx --dry-run

# Import for real
python -m src.cli import-mappings server_app_mapping_template.xlsx

# List current mappings
python -m src.cli list-mappings

# Map a single server
python -m src.cli map-server web-prod-01.company.com "Payment Gateway"
```

### Database Management

```bash
# Initialize database
python -m src.cli init

# Sync assets from Tenable
python -m src.cli sync-db

# Quick test sync (limited data)
python -m src.cli sync-db --limit 10 --days 7

# Seed vendor detection rules
python -m src.cli seed-vendor-rules
```

### Utility Commands

```bash
# List available tags from Tenable
python -m src.cli list-tags

# Show all available commands
python -m src.cli --help

# Show help for specific command
python -m src.cli generate-report --help
```

---

## Understanding the Output

### HTML Report Sections

1. **Summary**
   - Total vulnerabilities
   - Total assets
   - Generation timestamp

2. **Quick Wins** ⚡
   - Version-Threshold: Simple upgrades
   - Unsupported Products: EOL systems
   - High-impact, low-effort fixes

3. **Drill-Down**
   - Grouped by vendor/product
   - Collapsible sections
   - CVE links
   - State badges (ACTIVE/RESURFACED/NEW)

4. **By Vendor**
   - Traditional vendor-based view
   - Severity counts
   - Product breakdown

### State Filtering (Default: ACTIVE)

By default, reports only show **ACTIVE** vulnerabilities:
- **ACTIVE**: Currently detected and confirmed
- **RESURFACED**: Previously fixed, detected again
- **NEW**: First time detected

To include other states:
```bash
python -m src.cli generate-report --state ACTIVE,RESURFACED,NEW
```

---

## Caching Behavior

### First Run
```bash
python -m src.cli generate-report --severity Critical,High
```
- Downloads data from Tenable API
- Caches data in `.cache/` directory
- Generates report

### Second Run (Same Filters)
```bash
python -m src.cli generate-report --severity Critical,High
```
- Detects cached data
- Shows: "Cached data found (2 hours old). Use it? [Y/n]"
- If yes: Uses cache (instant)
- If no: Downloads fresh data

### Force Fresh Data
```bash
python -m src.cli generate-report --severity Critical,High --fresh
```
- Ignores cache
- Always downloads from API

### Always Use Cache
```bash
python -m src.cli generate-report --severity Critical,High --use-cache
```
- Never prompts
- Always uses cache if available

---

## Troubleshooting

### "No module named 'click'"
**Solution**: Activate virtual environment
```bash
# Windows
.\venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

### "No vulnerabilities found with state: ACTIVE"
**Solution**: Include all states or use fresh data
```bash
# Option 1: Include all states
python -m src.cli generate-report --state ACTIVE,RESURFACED,NEW

# Option 2: Fresh download
python -m src.cli generate-report --fresh
```

### "Configuration errors: TENABLE_ACCESS_KEY is required"
**Solution**: Check your `.env` file
- Ensure `.env` exists in project root
- Verify API keys are set correctly
- No quotes needed around values

### "Error binding parameter: type list is not supported"
**Solution**: This is fixed in latest version
```bash
git pull origin main
```

### Cache Issues
**Solution**: Clear cache directory
```bash
# Windows
Remove-Item -Recurse -Force .cache/

# Linux/Mac
rm -rf .cache/
```

---

## Next Steps

### 1. Import Server-Application Mappings
See: [Server-Application Mapping Import](server-app-mapping-import.md)

### 2. Understand Quick Wins
See: [Quick Wins & Filtering](quick-wins-and-filtering.md)

### 3. Customize Vendor Detection
```bash
python -m src.cli seed-vendor-rules
```

### 4. Schedule Regular Reports
Create a cron job (Linux) or Task Scheduler (Windows) to run:
```bash
python -m src.cli generate-report --severity Critical,High --format both
```

---

## Best Practices

1. **Start with Quick Wins**
   - Review Quick Wins section first
   - Plan version upgrades
   - Schedule EOL replacements

2. **Use State Filtering**
   - Default (ACTIVE only) for action planning
   - Add RESURFACED for trend analysis
   - Use NEW for weekly delta reports

3. **Leverage Caching**
   - Download once, generate multiple reports
   - Experiment with different filters
   - Save API calls

4. **Regular Syncing**
   - Run `sync-db` weekly to update local database
   - Keep server-application mappings current
   - Review and update vendor rules

5. **Version Control**
   - Keep `.env` in `.gitignore` (already configured)
   - Track server-application mapping Excel files
   - Document custom vendor rules

---

## Support & Documentation

- **Full Documentation**: See `docs/` directory
- **Issues**: GitHub Issues
- **API Reference**: Tenable.io API Documentation

---

## Quick Reference Card

```bash
# First time setup
python -m venv venv
.\venv\Scripts\activate  # Windows
pip install -r requirements.txt
cp .env.example .env      # Edit with your API keys
python -m src.cli init

# Generate report (most common)
python -m src.cli generate-report --severity Critical,High --format html

# Import server mappings
python -m src.cli export-mapping-template
# (Edit the Excel file)
python -m src.cli import-mappings server_app_mapping_template.xlsx

# Sync from Tenable
python -m src.cli sync-db --limit 10 --days 7

# Get help
python -m src.cli --help
python -m src.cli generate-report --help
```
