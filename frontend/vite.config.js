import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // FastAPI backend (job queue, scan results)
      '/api': { target: 'http://127.0.0.1:8000', changeOrigin: true },
      // FastAPI static output files
      '/output': { target: 'http://127.0.0.1:8000', changeOrigin: true },
      // Flask backend (lab routes: guestbook, xss, sqli, ssrf, login, etc.)
      '/guestbook':      { target: 'http://127.0.0.1:5000', changeOrigin: true },
      '/sqli':           { target: 'http://127.0.0.1:5000', changeOrigin: true },
      '/ssrf':           { target: 'http://127.0.0.1:5000', changeOrigin: true },
      '/login':          { target: 'http://127.0.0.1:5000', changeOrigin: true },
      '/logout':         { target: 'http://127.0.0.1:5000', changeOrigin: true },
      '/backend-output': { target: 'http://127.0.0.1:5000', changeOrigin: true },
      '/scan-result':    { target: 'http://127.0.0.1:5000', changeOrigin: true },
      '/scanner':        { target: 'http://127.0.0.1:5000', changeOrigin: true },
    }
  },
})