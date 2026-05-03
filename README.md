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

Backend API:

```bash
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Frontend dev server:

```bash
cd frontend
npm run dev -- --host 127.0.0.1
```

Open `http://127.0.0.1:3000/` in your browser after the frontend starts.

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

## Notes on Accuracy

The scanner aims to reduce false positives with baseline comparisons and conservative confirmations, but findings should still be manually verified.
