import re
from typing import List, Dict


class LeakedAssetDetector:
    """Detects potentially leaked sensitive information in response bodies."""

    # Regex patterns for different types of leaked assets
    PATTERNS = {
        "AWS Access Key": [
            re.compile(r'AKIA[0-9A-Z]{16}'),  # AWS Access Key ID
        ],
        "AWS Secret Key": [
            re.compile(r'(?i)aws_secret_access_key["\']?\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']?'),
        ],
        "Stripe API Key": [
            re.compile(r'sk_(?:test|live)_[0-9a-zA-Z]{24}'),  # Stripe Secret Key
            re.compile(r'pk_(?:test|live)_[0-9a-zA-Z]{24}'),  # Stripe Publishable Key
        ],
        "GitHub Token": [
            re.compile(r'ghp_[0-9a-zA-Z]{36}'),  # GitHub Personal Access Token
            re.compile(r'github_pat_[0-9a-zA-Z_]{22,255}'),  # GitHub PAT
        ],
        "Slack Token": [
            re.compile(r'xox[baprs]-[0-9a-zA-Z-]{10,}'),  # Slack Bot/User Token
        ],
        "Google API Key": [
            re.compile(r'AIza[0-9A-Za-z-_]{35}'),  # Google API Key
        ],
        "Email Address": [
            re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        ],
        "Phone Number": [
            re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),  # US phone numbers
            re.compile(r'\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,4}'),  # International
        ],
        "Internal IP Address": [
            re.compile(r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),  # 10.0.0.0/8
            re.compile(r'\b172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b'),  # 172.16.0.0/12
            re.compile(r'\b192\.168\.\d{1,3}\.\d{1,3}\b'),  # 192.168.0.0/16
        ],
        "Database Connection String": [
            re.compile(r'(?i)(?:mysql|postgresql|mongodb|redis)://[^\s"\'<>]+'),
            re.compile(r'(?i)jdbc:[a-z]+://[^\s"\'<>]+'),
        ],
        "JWT Token": [
            re.compile(r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.]+'),  # JWT format
        ],
        "Private Key": [
            re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
            re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
        ],
    }

    @classmethod
    def detect_leaked_assets(cls, text: str, url: str) -> List[Dict[str, str]]:
        """Scan text for leaked assets and return findings."""
        findings = []

        for asset_type, patterns in cls.PATTERNS.items():
            for pattern in patterns:
                matches = pattern.findall(text)
                for match in matches:
                    # Skip obvious test/example values
                    if cls._is_likely_test_value(match, asset_type):
                        continue

                    findings.append({
                        "type": asset_type,
                        "value": match,
                        "url": url,
                        "severity": cls._get_severity(asset_type),
                    })

        return findings

    @staticmethod
    def _is_likely_test_value(value: str, asset_type: str) -> bool:
        """Check if the matched value is likely a test/example."""
        test_indicators = [
            'test', 'example', 'sample', 'demo', 'fake', 'placeholder',
            'your-', 'xxx', '123456', 'abcdef'
        ]

        value_lower = value.lower()
        for indicator in test_indicators:
            if indicator in value_lower:
                return True

        # Specific checks for certain types
        if asset_type == "Email Address":
            if any(domain in value_lower for domain in ['example.com', 'test.com', 'domain.com']):
                return True

        if asset_type in ["AWS Access Key", "AWS Secret Key"]:
            if 'test' in value_lower or 'example' in value_lower:
                return True

        return False

    @staticmethod
    def _get_severity(asset_type: str) -> str:
        """Determine severity based on asset type."""
        high_severity = [
            "AWS Secret Key", "Stripe API Key", "GitHub Token",
            "Slack Token", "Private Key", "Database Connection String"
        ]
        medium_severity = [
            "AWS Access Key", "Google API Key", "JWT Token"
        ]

        if asset_type in high_severity:
            return "High"
        elif asset_type in medium_severity:
            return "Medium"
        else:
            return "Low"