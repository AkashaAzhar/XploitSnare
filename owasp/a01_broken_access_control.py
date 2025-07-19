# owasp/a01_broken_access_control.py

import requests
from utils.result import ScanResult
from utils.logger import setup_logger

class Scanner:
    def run(self, target):
        logger = setup_logger("A01_BrokenAccess")
        test_paths = ["/admin", "/dashboard", "/config", "/settings", "/controlpanel"]
        vulnerable_paths = []

        try:
            for path in test_paths:
                url = target.rstrip("/") + path
                response = requests.get(url, timeout=5)
                logger.info(f"Tested {url} - Status: {response.status_code}")

                if response.status_code == 200 and "login" not in response.text.lower():
                    vulnerable_paths.append(url)

            if vulnerable_paths:
                return ScanResult("A01: Broken Access Control", "Vulnerable", f"Accessible paths: {vulnerable_paths}")
            else:
                return ScanResult("A01: Broken Access Control", "Safe", "No unprotected admin paths found.")

        except Exception as e:
            logger.error(f"Error during scanning: {str(e)}")
            return ScanResult("A01: Broken Access Control", "Error", str(e))
