import axios from 'axios'

export const api = axios.create({
  baseURL: 'http://127.0.0.1:8000',
  timeout: 120000,
})

export async function enqueueScan(payload) {
  const { data } = await api.post('/api/scan', payload)
  return data
}

export async function getJobStatus(jobId) {
  const { data } = await api.get(`/api/jobs/${jobId}`)
  return data
}
