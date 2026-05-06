# AuditCrawl

AuditCrawl is an educational, safe-by-default web application security scanner for academic mini-projects.

## Safety and Ethics

- Scan only systems you own or have explicit written permission to test.
- Keep scans non-destructive and low impact.
- Respect robots.txt and target rate limits.
- Do not perform data exfiltration, destructive actions, or real command execution.

All generated PoCs include this notice:

> This POC is for educational use; do not run on real systems without permission.

## Features

- Domain-limited crawler with depth/page caps and robots.txt support
- Modular vulnerability checks:
  - Reflected XSS with baseline/context verification
  - Stored XSS with multi-step submit-then-fetch correlation
  - SQLi symptom checks (error-based; optional time-based for lab only)
  - SSRF exposure checks (warning-only for real-world mode)
  - Basic auth/session checks
  - RCE surface pattern checks (no command execution)
- Audit trail logging (`scan.log`, optional SQLite extension point)
- Report outputs:
  - `report.pdf`
  - `report.html`
  - `report.md`

## Installation

```bash
python -m venv .venv
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

For the FastAPI backend UI, install its own dependencies too:

```bash
pip install -r backend/requirements.txt
```

For the Vite frontend:

```bash
cd frontend
npm install
```

## Usage

```bash
python main.py \
  --base-url http://localhost:5000 \
  --target-domain localhost \
  --lab-mode \
  --max-depth 3 \
  --max-pages 100 \
  --output-dir output
```

## Run Services

**Quick Start** (everything on same machine):

```bash
# Terminal 1: Backend
uvicorn backend.app.main:app --reload

# Terminal 2: Frontend  
cd frontend
npm run dev
```

Then open `http://localhost:5173/` in your browser.

**For running on different machines**, see [SETUP_GUIDE.md](SETUP_GUIDE.md) for environment configuration options.

Backend API (detailed):

```bash
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

Frontend dev server (detailed):

```bash
cd frontend
npm run dev
```

Enable only selected modules (otherwise all are enabled by default):

```bash
python main.py --base-url http://localhost:5000 --target-domain localhost --xss --sqli
```

## Output

- Console summary
- `output/report.pdf`
- `output/report.html`
- `output/report.md`
- `output/scan.log`

## Unit Tests

```bash
python -m unittest discover -s tests -v
```

## Recent Updates (Last 2 Months)

### Yesterday & Today
- **UI/UX Improvements**
  - Fixed Vite build error by removing stale batch scan component imports from Scanner.jsx
  - Enhanced severity badge color distinction for better visual clarity:
    - Critical: Red (#ff3355)
    - High: Dark Orange (#ff8c00) — improved from light orange
    - Medium: Bright Gold (#ffd700) — improved from golden-orange
    - Low: Blue (#40aaff)
  - Colors now clearly distinguishable at a glance for quick severity assessment

- **Codebase Cleanup**
  - Removed 7 unused legacy files to reduce bloat (2174 lines deleted):
    - `main.py` — Old CLI entry point
    - `safe_site.py` — Deprecated demo site
    - `lab_app.py` — Legacy Flask labs server
    - `backend/api.py` — Replaced by FastAPI implementation
    - `auditcrawl/poc.py` — Unused PoC generator
    - `auditcrawl/report.py` — Unused report generator
    - `auditcrawl/scanners.py` — Unused scanner module
  - Removed batch scan frontend components while preserving backend infrastructure
  - All functionality verified working; no impact to active features

### Previous Updates (Last 2 Months)
- Individual scan functionality with job queue management
- Real-time job status tracking and cancellation
- PDF/JSON/XML export formats with full vulnerability details
- Finding severity classification (Critical/High/Medium/Low)
- Interactive findings viewer with filtering and ROI calculation
- Archive system for historical scan tracking
- Database persistence with SQLAlchemy ORM
- FastAPI backend with Vite + React frontend
- Batch scan orchestration with distributed scanning support
- Comprehensive logging and debug output

## Notes on Accuracy

The scanner aims to reduce false positives with baseline comparisons and conservative confirmations, but findings should still be manually verified.
