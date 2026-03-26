# AuditCrawl Backend (FastAPI)

## Stack
- FastAPI
- SQLAlchemy + aiosqlite (SQLite)
- BeautifulSoup4 + lxml
- Selenium (optional dynamic scanning toggle)
- Gemini API integration (optional summary)

## Run
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

## API
- `POST /api/scan`
- `GET /api/scan/{run_id}`
- `GET /output/run_{id}.pdf`

## Sample Request
```json
{
  "target_url": "http://127.0.0.1:5000",
  "scan_level": "2",
  "use_selenium": false
}
```
