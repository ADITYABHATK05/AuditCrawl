from .config import ScanConfig
from .orchestrator import Scanner

# Import modules from the correct subdirectory
from .modules import xss, sqli, ssrf, idor, csrf, headers, auth, rce
from .modules import open_redirect as open_redirect  # Ensure naming matches your filenames

__all__ = [
    "ScanConfig", 
    "Scanner", 
    "xss", 
    "sqli", 
    "ssrf", 
    "idor", 
    "csrf", 
    "headers", 
    "open_redirect", 
    "auth", 
    "rce"
]