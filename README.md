# Tenable Patch & Vulnerability Report Generator

An enterprise-grade vulnerability reporting tool that transforms Tenable.io vulnerability data into actionable, intelligently-grouped HTML and XLSX reports.

## Features

- 🚀 **Quick Wins Detection**: Automatically identifies version-threshold and unsupported-product findings
- 🏢 **Vendor Detection Engine**: Intelligent Vendor → Product categorization with database rules and regex heuristics
- 🌳 **Hierarchical Grouping**: Dynamic reporting structure based on Vendor > Product > Server > Vulnerability
- 🔄 **Automated Export**: Native Tenable.io bulk export API integration
- 📊 **Interactive HTML Reports**: Collapsible sections, severity color-coding, and vendor advisory links
- 📈 **Performance Insights**: Built-in execution profiling for API and processing layers
- 💾 **Database-Backed Mapping**: Manage server-application relationships without code changes

## Quick Start

### Prerequisites

- Python 3.9+
- PostgreSQL 13+ or SQLite
- Tenable.io API keys with `scan.read` and `vulns.read` permissions

### Installation

```bash
# Clone the repository
git clone <repository_url>
cd "Tenable Report"

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your Tenable API keys

# Initialize database
alembic upgrade head
```

### Usage

```bash
# Sync assets from Tenable to local database
python -m src.cli sync-db

# Generate report for a specific tag
python -m src.cli generate-report --tag Environment:Production --severity Critical,High --format html

# Generate XLSX report
python -m src.cli generate-report --tag Environment:Production --format xlsx

# List available tags
python -m src.cli list-tags

# Manage server-application mappings
python -m src.cli map-server --hostname prod-web-01 --app WebApp-Frontend
python -m src.cli list-mappings

# Seed initial vendor detection rules
python -m src.cli seed-vendor-rules
```

## Documentation

- [Product Requirements Document](./docs/prd.md)
- [Technical Implementation Plan](./docs/implementation_plan.md)
- [CLI Reference](./docs/cli_reference.md)
- [Mapping Workflow](./docs/mapping_workflow.md)

## Project Structure

```
tenable-report/
├── src/
│   ├── __init__.py
│   ├── cli.py                    # CLI entry point
│   ├── config.py                 # Configuration management
│   ├── tenable_client.py         # Tenable API client
│   ├── report_generator.py       # HTML/XLSX report generation
│   ├── database/
│   │   ├── __init__.py
│   │   ├── models.py             # SQLAlchemy ORM models
│   │   └── session.py            # Database session management
│   ├── processors/
│   │   ├── __init__.py
│   │   ├── normalizer.py         # Data normalization
│   │   ├── enricher.py           # Data enrichment
│   │   ├── vendor_detector.py    # Vendor/product detection
│   │   ├── quick_wins_detector.py # Quick Wins algorithm
│   │   └── grouper.py            # Hierarchical grouping
│   └── templates/
│       └── report_template.html  # Jinja2 HTML template
├── tests/
│   ├── unit/
│   └── integration/
├── alembic/
│   └── versions/                 # Database migrations
├── reports/                      # Generated reports (gitignored)
├── requirements.txt
├── .env.example
└── README.md
```

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please see CONTRIBUTING.md for guidelines.
