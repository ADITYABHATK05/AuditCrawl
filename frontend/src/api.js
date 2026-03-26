import axios from 'axios'

/* ── FastAPI backend (port 8000) ─────────────────────────────── */
export const fastApi = axios.create({
  baseURL: 'http://127.0.0.1:8000',
  timeout: 120_000,
})

export async function enqueueScan(payload) {
  const { data } = await fastApi.post('/api/scan', payload)
  return data
}

export async function getJobStatus(jobId) {
  const { data } = await fastApi.get(`/api/jobs/${jobId}`)
  return data
}

export async function cancelJob(jobId) {
  const { data } = await fastApi.post(`/api/jobs/${jobId}/cancel`)
  return data
}

export async function getScanResult(runId) {
  const { data } = await fastApi.get(`/api/scan/${runId}`)
  return data
}

/* ── Flask lab backend (port 5000) ───────────────────────────── */
export const flaskApi = axios.create({
  baseURL: 'http://127.0.0.1:5000',
  timeout: 30_000,
  withCredentials: true,           // needed for Flask session cookie
})

// Scanner endpoints (Flask proxies to FastAPI internally)
export async function flaskStartScan(payload) {
  const { data } = await flaskApi.post('/scanner/start', payload)
  return data
}

export async function flaskGetJobStatus(jobId) {
  const { data } = await flaskApi.get(`/scanner/status/${jobId}`)
  return data
}

export async function flaskStopScan(jobId) {
  const { data } = await flaskApi.post(`/scanner/stop/${jobId}`)
  return data
}

// Lab pages — data-only endpoints (Flask returns JSON where possible,
// otherwise we call Flask HTML routes and parse; for pure data we use
// dedicated JSON-producing routes or fall back to the existing HTML API)

export async function postGuestbook(comment) {
  // Flask /guestbook POST redirects; we POST with form data
  const form = new URLSearchParams({ comment })
  await flaskApi.post('/guestbook', form, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    maxRedirects: 0,
  }).catch(() => {}) // redirect is expected
}

export async function loginFlask(username, password) {
  const form = new URLSearchParams({ username, password })
  const resp = await flaskApi.post('/login', form, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    maxRedirects: 0,
    validateStatus: s => s < 500,
  })
  return resp
}

export async function logoutFlask() {
  await flaskApi.get('/logout', { maxRedirects: 0 }).catch(() => {})
}