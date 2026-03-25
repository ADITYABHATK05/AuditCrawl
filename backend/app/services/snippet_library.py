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
    return (
        "# Generic remediation\n"
        "validate_input(user_input)\n"
        "apply_output_encoding(user_input)\n"
    )
