# Tenable Vulnerability Report Generator

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A production-grade, automated vulnerability reporting tool for **Tenable.io** that transforms raw vulnerability data into actionable, executive-ready reports. Features intelligent Quick Wins detection, vendor/product grouping, device classification, and blazing-fast database-driven report generation.

![Report Preview](docs/images/report-preview.png)

---

## 🌟 Key Features

| Feature | Description |
|---------|-------------|
| ⚡ **Instant Reports** | Generate reports in <1 second using pre-processed database |
| 🎯 **Quick Wins Detection** | Automatically identify easy-to-fix vulnerabilities |
| 🏢 **Device Classification** | Smart server/workstation/network detection with custom overrides |
| 📊 **Multiple Formats** | HTML (dark theme) and Excel outputs |
| 🔍 **Advanced Filtering** | Filter by severity, state, device type, and more |
| 💾 **Smart Caching** | Intelligent data caching to minimize API calls |
| 📦 **Vendor Grouping** | Hierarchical organization by vendor → product → vulnerability |
| 🗺️ **Server-App Mapping** | Import and manage application ownership via Excel |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Tenable.io account with API access
- API Access Key and Secret Key ([Generate here](https://cloud.tenable.com/api-keys))

### Installation

```bash
# Clone the repository
git clone https://github.com/RAVE-V/Tenable-Report.git
cd Tenable-Report

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your Tenable API credentials

# Initialize database
python -m src.cli init
```

### Generate Your First Report

```bash
# Standard report (from API/cache)
python -m src.cli generate-report

# High-speed report from database
python -m src.cli sync-all          # Run once to populate database
python -m src.cli generate-report --from-db   # Instant reports!
```

---

## 📖 CLI Command Reference

All commands are executed via:
```bash
python -m src.cli [COMMAND] [OPTIONS]
```

### Command Tree

```
src.cli
├── init                     # Initialize database
├── sync-all                 # Sync vulnerabilities to database (recommended)
├── sync-db                  # Sync assets only
│
├── generate-report          # Generate HTML/Excel vulnerability report
│   ├── --severity           # Filter: Critical,High,Medium,Low
│   ├── --state              # Filter: ACTIVE,RESURFACED,NEW,FIXED
│   ├── --tag                # Filter by Tenable tag
│   ├── --format             # Output: html, xlsx, both
│   ├── --output             # Output directory
│   ├── --fresh              # Force API refresh
│   ├── --use-cache          # Use cached data silently
│   ├── --from-db            # Use pre-synced database (fastest)
│   └── --all-devices        # Include workstations/network devices
│
├── server-report            # Server-focused report with drill-down
│   ├── --severity           # Filter by severity
│   ├── --state              # Filter by state
│   ├── --format             # Output: html, xlsx, both
│   ├── --sort-by            # Sort: total_vulns, critical, hostname
│   ├── --min-vulns          # Minimum vulns to include
│   └── --all-devices        # Include all device types
│
├── classify                 # Manage device type classifications
│   ├── add [pattern] [type] # Add custom OS → device type rule
│   ├── remove [pattern]     # Remove custom rule
│   ├── list                 # List all custom rules
│   └── test [os_string]     # Test classification for an OS string
│
├── export-mapping-template  # Export Excel for server-app mapping
│   └── --output             # Output file path
│
├── import-mappings          # Import server-app mappings from Excel
│   └── --dry-run            # Validate without saving
│
├── inspect-data             # Inspect available filter values
    └── --fresh              # Force refresh from API
```

---

---

## 🚀 Quick Start Workflows

### First-Time Setup
```bash
# 1. Initialize database tables
python -m src.cli init

# 2. Sync all data from Tenable (automatically seeds vendor rules)
python -m src.cli sync-all

# 4. Generate your first report
python -m src.cli generate-report --from-db
```

### Daily Report Generation (Fastest)
```bash
# Option 1: Use pre-synced database (<1 second)
python -m src.cli generate-report --from-db

# Option 2: Critical/High only
python -m src.cli generate-report --from-db --severity Critical,High

# Option 3: Both HTML and Excel
python -m src.cli generate-report --from-db --format both
```

### Server Mapping Workflow
```bash
# 1. Export server list to Excel (includes existing mappings)
python -m src.cli export-mapping-template --output server_mappings.xlsx

# 2. Fill in 'application_name' column in Excel (yellow = needs mapping)

# 3. Validate import (dry run)
python -m src.cli import-mappings server_mappings.xlsx --dry-run

# 4. Import mappings
python -m src.cli import-mappings server_mappings.xlsx

# 5. Generate report with application grouping
python -m src.cli generate-report --from-db
```

### Device Classification
```bash
# Test how an OS is classified
python -m src.cli classify test "Windows Server 2022 Datacenter"
# Output: server

# Add custom rule for unrecognized OS
python -m src.cli classify add "My Custom Appliance" network

# View all custom rules
python -m src.cli classify list
```

---

## 📊 Report Generation Options

### Filtering Examples
```bash
# By severity
python -m src.cli generate-report --severity Critical,High

# By state (default: ACTIVE,RESURFACED)
python -m src.cli generate-report --state ACTIVE,RESURFACED,NEW

# By Tenable tag
python -m src.cli generate-report --tag "Production Servers"

# Include all devices (not just servers)
python -m src.cli generate-report --all-devices

# Combine filters
python -m src.cli generate-report --from-db --severity Critical --state ACTIVE
```

### Output Formats
```bash
# HTML only (default)
python -m src.cli generate-report --format html

# Excel only
python -m src.cli generate-report --format xlsx

# Both HTML and Excel
python -m src.cli generate-report --format both

# Custom output directory
python -m src.cli generate-report --output ./my-reports/
```

### Data Source Options
```bash
# From database (fastest, <1 second)
python -m src.cli generate-report --from-db

# From cache (no prompts)
python -m src.cli generate-report --use-cache

# Force fresh from API
python -m src.cli generate-report --fresh
```


---

## 📊 Report Features

### HTML Report Highlights

- **Dark Theme Design** - Professional, eye-friendly aesthetic
- **Sticky Navigation** - Quick access to all sections
- **Collapsible Sections** - Expandable drill-down by application and server
- **Quick Wins Panel** - Grouped by vulnerability type with device counts
- **Exploitable Vulnerabilities** - Highlighted section for critical exploits
- **Severity Badges** - Color-coded Critical/High/Medium/Low indicators
- **CVE Links** - Direct links to NVD for each CVE
- **Search Functionality** - Filter vulnerabilities in real-time
- **Responsive Design** - Works on desktop and tablet

### Quick Wins Detection

Automatically identifies remediation opportunities:

| Category | Description |
|----------|-------------|
| **Version Threshold** | Simple version upgrades (e.g., "Apache < 2.4.58") |
| **Unsupported Products** | End-of-life or deprecated systems |

### State Filtering

| State | Description |
|-------|-------------|
| `ACTIVE` | Currently detected (default) |
| `RESURFACED` | Previously fixed, detected again |
| `NEW` | First time detected |
| `FIXED` | No longer detected |

---

## 🗂️ Project Structure

```
Tenable-Report/
├── src/
│   ├── cli.py                    # Main CLI interface
│   ├── tenable_client.py         # Tenable API client
│   ├── normalizer.py             # Data normalization
│   ├── cache.py                  # Intelligent caching
│   ├── report_generator.py       # HTML report generation
│   ├── xlsx_generator.py         # Excel report generation
│   ├── database/
│   │   ├── __init__.py           # Database session management
│   │   └── models.py             # SQLAlchemy ORM models
│   ├── processors/
│   │   ├── vendor_detector.py    # Vendor/product detection
│   │   ├── quick_wins_detector.py # Quick wins identification
│   │   └── grouper.py            # Hierarchical grouping
│   ├── utils/
│   │   ├── device_detector.py    # Device type classification
│   │   └── vendor_detection.py   # Vendor pattern matching
│   └── templates/
│       └── report_template.html  # Jinja2 HTML template
├── tests/
│   ├── unit/                     # Unit tests
│   └── integration/              # Integration tests
├── docs/
│   ├── GETTING_STARTED.md        # Setup guide
│   ├── quick-wins-and-filtering.md
│   └── server-app-mapping-import.md
├── reports/                      # Generated reports (gitignored)
├── .cache/                       # Cached data (gitignored)
├── .env.example                  # Environment template
├── requirements.txt              # Python dependencies
└── README.md
```

---

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# Required - Tenable API Credentials
TENABLE_ACCESS_KEY=your_access_key_here
TENABLE_SECRET_KEY=your_secret_key_here
TENABLE_BASE_URL=https://cloud.tenable.com

# Optional - Performance Tuning
EXPORT_MAX_ASSETS_PER_CHUNK=5000    # Assets per API chunk
CACHE_MAX_AGE_HOURS=24              # Cache expiry (hours)
REPORTS_OUTPUT_DIR=./reports        # Report output directory
DB_PATH=./data/tenable_report.db    # Database file path
```

### Database Schema

The application uses SQLite with the following tables:

| Table | Purpose |
|-------|---------|
| `servers` | Asset inventory |
| `applications` | Application catalog |
| `server_application_map` | Server-to-app mappings |
| `vendor_product_rules` | Vendor detection rules |
| `vulnerabilities` | Pre-processed vulnerability data |
| `report_runs` | Report generation audit trail |

---

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/unit/test_tenable_client.py -v

# Run specific test
pytest tests/unit/test_device_detector.py::test_server_detection -v
```

---

## 🐛 Troubleshooting

### No vulnerabilities found

```bash
# Check what data is available
python -m src.cli inspect-data

# Try including all states
python -m src.cli generate-report --state ACTIVE,RESURFACED,NEW

# Include all device types
python -m src.cli generate-report --all-devices

# Force fresh data
python -m src.cli generate-report --fresh
```

### No servers detected

```bash
# Check device classification
python -m src.cli inspect-data

# Test specific OS strings
python -m src.cli classify test "Your OS String"

# Add custom classification
python -m src.cli classify add "Your OS Pattern" server
```

### Module not found errors

```bash
# Ensure virtual environment is activated
# Windows:
.\venv\Scripts\activate

# Linux/macOS:
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

### Clear all cached data

```bash
# Windows PowerShell
Remove-Item -Recurse -Force .cache/

# Linux/macOS
rm -rf .cache/

# Re-sync database
python -m src.cli sync-all --fresh
```

### Database issues

```bash
# Reinitialize database
python -m src.cli init

# Full resync
python -m src.cli sync-all --fresh
```

---

## 📈 Performance Tips

1. **Use `sync-all` for daily syncs** - Run as a scheduled task to keep database fresh
2. **Use `--from-db` for instant reports** - Skip API calls and processing
3. **Use `--use-cache` for repeat runs** - Avoid prompts when data is fresh
4. **Limit severity for faster processing** - `--severity Critical,High`

### Benchmarks

| Mode | Time | Use Case |
|------|------|----------|
| `--from-db` | <1 second | Pre-synced data |
| `--use-cache` | 2-5 seconds | Cached API data |
| `--fresh` | 30-120 seconds | Full API fetch |

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`pytest`)
5. Run linting (`flake8 src/`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Development Setup

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests with coverage
pytest --cov=src --cov-report=term-missing

# Format code
black src/

# Lint code
flake8 src/
```

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [Tenable.io API](https://developer.tenable.com/) - Vulnerability data source
- [Click](https://click.palletsprojects.com/) - CLI framework
- [Jinja2](https://jinja.palletsprojects.com/) - Template engine
- [SQLAlchemy](https://www.sqlalchemy.org/) - Database ORM
- [OpenPyXL](https://openpyxl.readthedocs.io/) - Excel file handling

---

## 📞 Support

- **Documentation**: See `docs/` directory
- **Issues**: [GitHub Issues](https://github.com/RAVE-V/Tenable-Report/issues)
- **API Docs**: [Tenable.io API Documentation](https://developer.tenable.com/docs)

---

<p align="center">
  <strong>Made with ❤️ for Security Teams</strong>
</p>
