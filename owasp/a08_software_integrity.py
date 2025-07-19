# owasp/a08_software_integrity.py

import requests
from utils.result import ScanResult
from utils.logger import setup_logger

class Scanner:
    def run(self, target):
        logger = setup_logger("A08_SoftwareIntegrity")
        known_sensitive_paths = [
            "/.git/config",
            "/.env",
            "/.DS_Store",
            "/composer.lock",
            "/yarn.lock",
            "/package-lock.json",
            "/docker-compose.yml",
            "/.github/workflows/",
            "/.gitlab-ci.yml"
        ]

        exposed_files = []

        try:
            for path in known_sensitive_paths:
                url = target.rstrip("/") + path
                response = requests.get(url, timeout=5)
                if response.status_code == 200 and len(response.text.strip()) > 10:
                    exposed_files.append(f"{url} (status {response.status_code})")

            logger.info(f"Checked for exposed CICD/files: {exposed_files}")

            if exposed_files:
                return ScanResult(
                    "A08: Software and Data Integrity Failures",
                    "Vulnerable",
                    f"Exposed deployment/config files found: {exposed_files}"
                )
            else:
                return ScanResult(
                    "A08: Software and Data Integrity Failures",
                    "Safe",
                    "No exposed source or CI/CD configuration files found."
                )

        except Exception as e:
            logger.error(f"Error checking software integrity: {str(e)}")
            return ScanResult("A08: Software and Data Integrity Failures", "Error", str(e))
