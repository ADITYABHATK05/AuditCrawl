from __future__ import annotations


def fix_snippet_for(vulnerability_type: str) -> str:
    if vulnerability_type == "Reflected XSS":
        return (
            "# Flask/Jinja2 safe output\n"
            "from markupsafe import escape\n"
            "safe_value = escape(user_input)\n"
            "return render_template('page.html', value=safe_value)\n"
        )
    if vulnerability_type == "SQL Injection":
        return (
            "# SQLAlchemy parameterized query\n"
            "result = session.execute(text('SELECT * FROM users WHERE id = :id'), {'id': user_id})\n"
        )
    if vulnerability_type == "Potential SSRF":
        return (
            "# Allowlist and block private IP ranges\n"
            "if parsed.hostname not in TRUSTED_HOSTS:\n"
            "    raise ValueError('Blocked outbound host')\n"
        )
    if vulnerability_type == "IDOR (Insecure Direct Object Reference)":
        return (
            "# Enforce object-level authorization before returning records\n"
            "record = session.get(Record, record_id)\n"
            "if record.owner_id != current_user.id:\n"
            "    raise HTTPException(status_code=403, detail='Forbidden')\n"
        )
    if vulnerability_type == "Open Redirect":
        return (
            "# Allowlist redirect destinations\n"
            "allowed_paths = {'/dashboard', '/profile'}\n"
            "if next_url not in allowed_paths:\n"
            "    raise HTTPException(status_code=400, detail='Invalid redirect target')\n"
        )
    if vulnerability_type == "CORS Misconfiguration":
        return (
            "# Validate the Origin header against a whitelist\n"
            "ALLOWED_ORIGINS = ['https://example.com', 'https://app.example.com']\n"
            "origin = request.headers.get('Origin')\n"
            "if origin in ALLOWED_ORIGINS:\n"
            "    response.headers['Access-Control-Allow-Origin'] = origin\n"
            "    response.headers['Access-Control-Allow-Credentials'] = 'true'\n"
        )
    if vulnerability_type == "Path Traversal / LFI":
        return (
            "# Use a whitelist of allowed files or directories\n"
            "import os\n"
            "ALLOWED_FILES = {'report.pdf', 'summary.txt'}\n"
            "requested_file = request.args.get('file')\n"
            "if requested_file not in ALLOWED_FILES:\n"
            "    return 'Access denied', 403\n"
            "safe_path = os.path.join('/safe/dir', requested_file)\n"
            "return send_file(safe_path)\n"
        )
    if vulnerability_type == "XXE Injection":
        return (
            "# Disable XML external entity processing\n"
            "from xml.etree import ElementTree as ET\n"
            "parser = ET.XMLParser()\n"
            "parser.entity = {}  # Disable entity processing\n"
            "tree = ET.parse(xml_file, parser)\n"
            "# Or use defusedxml library\n"
            "from defusedxml import ElementTree as DefET\n"
            "tree = DefET.parse(xml_file)\n"
        )
    if vulnerability_type == "JWT Vulnerabilities":
        return (
            "# Use strong, random secrets and proper algorithms\n"
            "import secrets\n"
            "import jwt\n"
            "SECRET_KEY = secrets.token_urlsafe(32)  # Strong random secret\n"
            "payload = {'user_id': user.id, 'exp': datetime.utcnow() + timedelta(hours=1)}\n"
            "token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')\n"
            "# Verify with exp validation\n"
            "decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])\n"
        )
    if vulnerability_type == "DOM-based XSS":
        return (
            "# Use textContent instead of innerHTML, and DOMPurify for rich content\n"
            "# For plain text:\n"
            "element.textContent = userInput;  // Safe: treats as text\n"
            "# For rich HTML, sanitize first:\n"
            "import DOMPurify from 'dompurify';\n"
            "const cleanHTML = DOMPurify.sanitize(userInput);\n"
            "element.innerHTML = cleanHTML;\n"
            "# Avoid dangerous sinks entirely:\n"
            "// DON'T: eval(userInput)\n"
            "// DON'T: element.innerHTML = userInput\n"
        )
    if vulnerability_type == "API Misconfiguration":
        return (
            "# Implement proper API security practices\n"
            "# 1. Require API authentication\n"
            "from fastapi import Depends, HTTPException, Header\n"
            "async def verify_api_key(x_api_key: str = Header(...)):\n"
            "    if x_api_key != VALID_API_KEY:\n"
            "        raise HTTPException(status_code=401)\n"
            "# 2. Add security headers\n"
            "response.headers['X-Content-Type-Options'] = 'nosniff'\n"
            "response.headers['X-Frame-Options'] = 'DENY'\n"
            "response.headers['Strict-Transport-Security'] = 'max-age=31536000'\n"
            "# 3. Generic error messages\n"
            "except Exception:\n"
            "    return {'error': 'Invalid request'}, 400\n"
        )
    return (
        "# Generic remediation\n"
        "validate_input(user_input)\n"
        "apply_output_encoding(user_input)\n"
    )
