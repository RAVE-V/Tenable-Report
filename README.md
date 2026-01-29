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

## 📖 Usage Guide

### Report Generation

```bash
# Default: HTML report, servers only, ACTIVE + RESURFACED states
python -m src.cli generate-report

# Filter by severity
python -m src.cli generate-report --severity Critical,High

# Include all devices (workstations, printers, etc.)
python -m src.cli generate-report --all-devices

# Excel format
python -m src.cli generate-report --format xlsx

# Both HTML and Excel
python -m src.cli generate-report --format both

# Use cached data without prompts
python -m src.cli generate-report --use-cache

# Force fresh data from API
python -m src.cli generate-report --fresh
```

### ⚡ High-Speed Mode (Database)

For instant report generation, use the database-driven workflow:

```bash
# Step 1: Sync all data to database (run once, or schedule daily)
python -m src.cli sync-all

# Step 2: Generate reports instantly (<1 second)
python -m src.cli generate-report --from-db
python -m src.cli generate-report --from-db --severity Critical,High
python -m src.cli generate-report --from-db --all-devices
```

**What `sync-all` does:**
1. Fetches vulnerabilities from Tenable API (uses cache if available)
2. Normalizes and validates all data
3. Classifies devices (server/workstation/network)
4. Detects vendors and products
5. Stores pre-processed data in SQLite database

### Device Classification

```bash
# Test how an OS string is classified
python -m src.cli classify test "Windows Server 2022 Datacenter"

# Add custom classification rule
python -m src.cli classify add "My Custom OS" server

# List all custom rules
python -m src.cli classify list

# Remove a custom rule
python -m src.cli classify remove "My Custom OS"
```

### Server-Application Mapping

```bash
# Export template Excel file
python -m src.cli export-mapping-template

# Import mappings from Excel
python -m src.cli import-mappings server_app_mapping.xlsx

# Dry run (preview without saving)
python -m src.cli import-mappings server_app_mapping.xlsx --dry-run

# List current mappings
python -m src.cli list-mappings
python -m src.cli list-mappings --server "web-server-01"
```

### Data Inspection

```bash
# Inspect available filter values
python -m src.cli inspect-data

# Force fresh inspection
python -m src.cli inspect-data --fresh
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
