# CLI Reference

## Installation & Setup

### 1. Install Dependencies

```bash
cd "Tenable Report"
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` and add your Tenable API keys:

```
TENABLE_ACCESS_KEY=your_access_key_here
TENABLE_SECRET_KEY=your_secret_key_here
```

### 3. Initialize Database

```bash
python -m src.cli init
```

## Commands

### `init`

Initialize database (create all tables).

```bash
python -m src.cli init
```

---

### `sync-db`

Sync assets from Tenable to local database.

```bash
python -m src.cli sync-db
```

**What it does:**
- Fetches all vulnerabilities from Tenable
- Extracts unique assets
- Creates or updates servers in local database

**Example:**
```bash
$ python -m src.cli sync-db
Connecting to Tenable...
Fetching vulnerability data to extract assets...
Found 150 unique assets
✓ Synced 150 servers to database
```

---

### `generate-report`

Generate vulnerability report from Tenable data.

**Options:**
- `--tag`: Filter by tag (format: `Category:Value`)
- `--severity`: Filter by severity (comma-separated: `Critical,High,Medium,Low`)
- `--format`: Output format (`xlsx`, `html`, or `both`) - default: `xlsx`
- `--output`: Output directory - default: `./reports`

**Examples:**

Generate XLSX report for Production servers with Critical/High severity:
```bash
python -m src.cli generate-report \
  --tag Environment:Production \
  --severity Critical,High \
  --format xlsx \
  --output ./reports
```

Generate report for all vulnerabilities:
```bash
python -m src.cli generate-report --format xlsx
```

Generate both HTML and XLSX reports (HTML requires Milestone 2):
```bash
python -m src.cli generate-report --format both
```

---

### `list-tags`

List available tags from Tenable.

```bash
python -m src.cli list-tags
```

**Example Output:**
```
Available Tags (12):
============================================================

Environment:
  - Environment:Production
  - Environment:Staging
  - Environment:Development

Location:
  - Location:AWS-US-EAST-1
  - Location:AWS-EU-WEST-1
```

---

### `map-server`

Map a server to an application.

**Options:**
- `--hostname`: Server hostname (required)
- `--app`: Application name (required)
- `--confidence`: Confidence level (`manual`, `auto`, `inferred`) - default: `manual`
- `--source`: Mapping source - default: `cli`
- `--user`: User making the change - default: `cli-user`

**Examples:**

Map server to application:
```bash
python -m src.cli map-server \
  --hostname prod-web-01 \
  --app WebApp-Frontend \
  --confidence manual
```

**Note:** Server must exist in database (run `sync-db` first).

---

### `list-mappings`

List server-application mappings.

**Options:**
- `--server`: Filter by server hostname (pattern match)
- `--app`: Filter by application name (pattern match)

**Examples:**

List all mappings:
```bash
python -m src.cli list-mappings
```

Filter by server:
```bash
python -m src.cli list-mappings --server prod-web
```

Filter by application:
```bash
python -m src.cli list-mappings --app WebApp
```

**Example Output:**
```
Server-Application Mappings (3):
================================================================================
prod-web-01                    → WebApp-Frontend              [manual]
prod-api-01                    → API-Backend                  [manual]
prod-db-01                     → Database-PostgreSQL          [auto]
```

---

## Workflow Example

### First-Time Setup & Report Generation

```bash
# 1. Initialize database
python -m src.cli init

# 2. Sync assets from Tenable
python -m src.cli sync-db

# 3. (Optional) Create server-application mappings
python -m src.cli map-server --hostname prod-web-01 --app WebApp-Frontend
python -m src.cli map-server --hostname prod-api-01 --app API-Backend

# 4. Generate report
python -m src.cli generate-report \
  --tag Environment:Production \
  --severity Critical,High \
  --format xlsx \
  --output ./reports

# 5. View generated report
ls -lh ./reports/
```

---

## Testing

Run unit tests:

```bash
pytest tests/unit/ -v
```

Run with coverage:

```bash
pytest tests/unit/ --cov=src --cov-report=html
open htmlcov/index.html
```

---

## Troubleshooting

### "API keys are required" error

Ensure `.env` file exists and contains valid Tenable API keys:

```bash
TENABLE_ACCESS_KEY=abc123...
TENABLE_SECRET_KEY=xyz789...
```

### "Server not found" when mapping

Run `sync-db` first to populate the servers table:

```bash
python -m src.cli sync-db
```

### Rate limiting

If you encounter rate limiting, the client will automatically retry with exponential backoff. Reduce concurrent chunks if needed by setting `EXPORT_MAX_CONCURRENT_CHUNKS=3` in `.env`.

---

## Database Management

### View database schema

```bash
python -m alembic revision --autogenerate -m "Initial schema"
```

### Reset database (CAUTION: deletes all data)

```bash
rm tenable_reports.db
python -m src.cli init
```
