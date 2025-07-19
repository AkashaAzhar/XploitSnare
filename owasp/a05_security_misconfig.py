# owasp/a05_security_misconfig.py

import requests
from utils.result import ScanResult
from utils.logger import setup_logger

class Scanner:
    def run(self, target):
        logger = setup_logger("A05_SecurityMisconfig")
        try:
            response = requests.get(target, timeout=5)
            headers = response.headers
            missing_headers = []

            required_headers = [
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "Referrer-Policy",
                "Permissions-Policy"
            ]

            for header in required_headers:
                if header not in headers:
                    missing_headers.append(header)

            logger.info(f"Response headers from {target}: {headers}")
            if missing_headers:
                return ScanResult(
                    "A05: Security Misconfiguration",
                    "Vulnerable",
                    f"Missing headers: {missing_headers}"
                )
            else:
                return ScanResult(
                    "A05: Security Misconfiguration",
                    "Safe",
                    "All recommended security headers are present."
                )

        except Exception as e:
            logger.error(f"Error during security misconfiguration check: {str(e)}")
            return ScanResult("A05: Security Misconfiguration", "Error", str(e))
