# Tenable Patch & Vulnerability Report Generator

A powerful, automated tool for generating comprehensive vulnerability reports from Tenable.io with advanced features like Quick Wins detection, vendor/product grouping, and server-application mapping.

## ✨ Features

- 🎯 **Quick Wins Detection** - Automatically identifies easy-to-fix vulnerabilities
- 📊 **Multiple Report Formats** - HTML (dark theme) and Excel outputs
- 🔄 **Smart Caching** - Avoid redundant API calls with intelligent data caching
- 🏢 **Server-Application Mapping** - Import and manage server-to-application relationships via Excel
- 🎨 **Modern HTML Reports** - Dark theme with collapsible drill-down sections
- 🔍 **State Filtering** - Focus on ACTIVE vulnerabilities or include RESURFACED/NEW
- 📦 **Vendor/Product Grouping** - Hierarchical organization of vulnerabilities
- 💾 **Local Database** - SQLite database for asset management

## 🚀 Quick Start

```bash
# 1. Clone and setup
git clone https://github.com/RAVE-V/Tenable-Report.git
cd Tenable-Report
python -m venv venv
.\venv\Scripts\activate  # Windows: .\venv\Scripts\activate
pip install -r requirements.txt

# 2. Configure
cp .env.example .env
# Edit .env with your Tenable API keys

# 3. Initialize
python -m src.cli init

# 4. Generate your first report
python -m src.cli generate-report --severity Critical,High --format html
```

**📖 Full Guide**: See [Getting Started](docs/GETTING_STARTED.md)

## 📋 Requirements

- Python 3.8+
- Tenable.io account with API access
- API Access Key and Secret Key

## 🎯 What Does `--format html` Do?

When you run:
```bash
python -m src.cli generate-report --format html
```

**The tool will:**
1. Download vulnerabilities from Tenable API (or use cache)
2. Filter for ACTIVE state by default
3. Detect vendors and products
4. Identify Quick Wins (easy fixes)
5. Generate a modern HTML report with:
   - Dark theme design (#0b1220 background)
   - Sticky navigation bar
   - Quick Wins section
   - Collapsible vendor/product drill-down
   - CVE links to NVD
   - State badges (ACTIVE/RESURFACED/NEW)
   - Severity badges (Critical/High/Medium/Low)

**Output**: `./reports/Tenable_Report_YYYYMMDD_HHMMSS.html`

## 📚 Common Commands

### Generate Reports

```bash
# HTML report with Critical and High vulnerabilities
python -m src.cli generate-report --severity Critical,High --format html

# Excel report
python -m src.cli generate-report --severity Critical,High --format xlsx

# Both formats
python -m src.cli generate-report --severity Critical,High --format both

# Include RESURFACED vulnerabilities
python -m src.cli generate-report --state ACTIVE,RESURFACED

# Use cached data (faster)
python -m src.cli generate-report --use-cache

# Force fresh download
python -m src.cli generate-report --fresh
```

### Server-Application Mapping

```bash
# Export template
python -m src.cli export-mapping-template

# Import mappings
python -m src.cli import-mappings server_app_mapping_template.xlsx

# List mappings
python -m src.cli list-mappings
```

### Database Management

```bash
# Initialize database
python -m src.cli init

# Sync assets from Tenable
python -m src.cli sync-db

# Quick test sync (limited data)
python -m src.cli sync-db --limit 10 --days 7
```

### Get Help

```bash
# Show all commands
python -m src.cli --help

# Help for specific command
python -m src.cli generate-report --help
```

## 📊 Report Features

### Quick Wins ⚡
Automatically identifies:
- **Version-Threshold**: Simple version upgrades (e.g., "Apache < 2.4.58")
- **Unsupported Products**: EOL/deprecated systems

### State Filtering 🎯
- **ACTIVE** (default): Currently detected vulnerabilities
- **RESURFACED**: Previously fixed, detected again
- **NEW**: First time detected

### Smart Caching 💾
- Caches vulnerability data after first download
- Shows cache age and prompts to reuse
- Separate cache per filter combination
- Default expiry: 24 hours

## 🗂️ Project Structure

```
Tenable-Report/
├── src/
│   ├── cli.py                  # Command-line interface
│   ├── tenable_client.py       # Tenable API client
│   ├── cache.py                # Caching system
│   ├── import_mappings.py      # Excel import
│   ├── report_generator.py     # HTML reports
│   ├── xlsx_generator.py       # Excel reports
│   ├── database/               # Database models
│   ├── processors/             # Vendor detection, Quick Wins
│   └── templates/              # HTML templates
├── docs/                       # Documentation
│   ├── GETTING_STARTED.md
│   ├── quick-wins-and-filtering.md
│   └── server-app-mapping-import.md
├── tests/                      # Unit tests
├── .env.example                # Environment template
└── requirements.txt            # Python dependencies
```

## 🔧 Configuration

Edit `.env` file:

```env
# Required
TENABLE_ACCESS_KEY=your_access_key
TENABLE_SECRET_KEY=your_secret_key
TENABLE_BASE_URL=https://cloud.tenable.com

# Optional
EXPORT_MAX_ASSETS_PER_CHUNK=5000
CACHE_MAX_AGE_HOURS=24
REPORTS_OUTPUT_DIR=./reports
```

## 📖 Documentation

- **[Getting Started Guide](docs/GETTING_STARTED.md)** - Step-by-step setup and first report
- **[Quick Wins & Filtering](docs/quick-wins-and-filtering.md)** - Understanding Quick Wins and state filtering
- **[Server-App Mapping Import](docs/server-app-mapping-import.md)** - Excel import guide

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src

# Run specific test
pytest tests/unit/test_tenable_client.py
```

## 🐛 Troubleshooting

### No vulnerabilities found with state: ACTIVE
```bash
# Solution 1: Include all states
python -m src.cli generate-report --state ACTIVE,RESURFACED,NEW

# Solution 2: Force fresh download
python -m src.cli generate-report --fresh
```

### Module not found errors
```bash
# Ensure virtual environment is activated
.\venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac
```

### Clear cache
```bash
# Windows
Remove-Item -Recurse -Force .cache/

# Linux/Mac
rm -rf .cache/
```

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest`
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License.

## 🙏 Acknowledgments

- Built with [Tenable.io API](https://developer.tenable.com/)
- Uses [Click](https://click.palletsprojects.com/) for CLI
- Reports powered by [Jinja2](https://jinja.palletsprojects.com/)

## 📞 Support

- **Documentation**: See `docs/` directory
- **Issues**: [GitHub Issues](https://github.com/RAVE-V/Tenable-Report/issues)
- **API Docs**: [Tenable.io API Documentation](https://developer.tenable.com/docs)

---

**Made with ❤️ for security teams**
