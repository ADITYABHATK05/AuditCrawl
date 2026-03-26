from __future__ import annotations

from flask import Flask, Response, request

app = Flask(__name__)


@app.after_request
def add_security_headers(resp: Response) -> Response:
    # Keep this site intentionally "boring": no cookies, no forms, no dynamic reflection.
    # Add strong baseline headers so the scanner has nothing to flag.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'none'; "
        "img-src 'self'; "
        "style-src 'self'; "
        "script-src 'none'"
    )
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

    # Only meaningful over HTTPS, but we run this site as HTTPS by default.
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    # Best-effort: reduce stack/server fingerprinting noise.
    # (Some servers may still append their own Server header.)
    resp.headers["Server"] = ""
    resp.headers["X-Powered-By"] = ""

    return resp


@app.get("/")
def home():
    html = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Safe Local Site</title>
  </head>
  <body>
    <h1>Safe Local Site</h1>
    <p>This site is intentionally static: no forms, no query parameters, no state.</p>
  </body>
</html>
"""
    return Response(html, mimetype="text/html")


@app.get("/health")
def health():
    return {"ok": True, "path": request.path}


if __name__ == "__main__":
    # HTTPS (self-signed) so HSTS makes sense and scanners can test TLS sites locally.
    # Use a non-5000 port to avoid conflicting with lab_app.py.
    app.run(host="127.0.0.1", port=5443, ssl_context="adhoc", debug=False)

