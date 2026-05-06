# AuditCrawl Setup Guide

## Quick Start (Same Machine)

Run everything on localhost and it just works:

```bash
# Terminal 1: Backend
cd backend
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
uvicorn app.main:app --reload

# Terminal 2: Frontend
cd frontend
npm install
npm run dev
```

Visit `http://localhost:5173` in your browser.

---

## Running on Different Machines

### Setup Scenario: Backend on Machine A (192.168.1.100), Frontend on Machine B (192.168.1.101)

#### Step 1: Backend Machine (192.168.1.100)

1. Create or update `backend/.env`:
```bash
# Allow the frontend machine to connect
ALLOWED_ORIGINS=http://192.168.1.101:5173
```

2. Run backend:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

#### Step 2: Frontend Machine (192.168.1.101)

1. Create or update `frontend/.env`:
```bash
# Point to backend machine
VITE_API_BASE=http://192.168.1.100:8000/api
```

2. Run frontend:
```bash
npm run dev
```

Visit `http://localhost:5173` in your browser.

---

## Configuration Options

### Frontend Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `VITE_API_BASE` | Full backend API URL | Auto-detected from hostname |
| `VITE_BACKEND_PORT` | Backend port (used for auto-detection) | `8000` |
| `VITE_PORT` | Frontend dev server port | `5173` |

### Backend Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `ALLOWED_ORIGINS` | Comma-separated CORS origins | `http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000` |
| `GEMINI_API_KEY` | Google Gemini API key | (empty) |

---

## Troubleshooting

### Frontend can't connect to backend
- **Same machine?** Make sure backend is running on `localhost:8000`
- **Different machine?** Set `VITE_API_BASE` to the correct IP and port
- **Firewall?** Ensure port 8000 is not blocked

### CORS error in browser console
- **Backend needs to know about frontend's origin**
- Add frontend URL to `ALLOWED_ORIGINS` env var in backend
- Restart backend after changing

### Port already in use
- **Backend:** Use `--port 9000` flag: `uvicorn app.main:app --port 9000 --host 0.0.0.0`
- **Frontend:** Use `VITE_PORT=5174` npm run dev`

---

## Docker (Optional - Future)

For truly easy deployment across machines, consider containerizing with Docker.
