# owasp/a06_vulnerable_components.py

import requests
import re
from utils.result import ScanResult
from utils.logger import setup_logger

class Scanner:
    def run(self, target):
        logger = setup_logger("A06_VulnerableComponents")

        try:
            response = requests.get(target, timeout=5)
            headers = response.headers
            exposed_info = {}

            for header in ['Server', 'X-Powered-By']:
                if header in headers:
                    exposed_info[header] = headers[header]

            logger.info(f"Received headers from {target}: {exposed_info}")

            # Try to identify version numbers
            version_pattern = r"\d+\.\d+(\.\d+)?"
            findings = []

            for key, value in exposed_info.items():
                if re.search(version_pattern, value):
                    findings.append(f"{key}: {value}")

            if findings:
                return ScanResult(
                    "A06: Vulnerable and Outdated Components",
                    "Potentially Vulnerable",
                    f"Software version exposure detected: {findings}"
                )
            elif exposed_info:
                return ScanResult(
                    "A06: Vulnerable and Outdated Components",
                    "Warning",
                    f"Technology disclosure without version: {exposed_info}"
                )
            else:
                return ScanResult(
                    "A06: Vulnerable and Outdated Components",
                    "Safe",
                    "No server or technology version information exposed."
                )

        except Exception as e:
            logger.error(f"Error during outdated components check: {str(e)}")
            return ScanResult("A06: Vulnerable and Outdated Components", "Error", str(e))
