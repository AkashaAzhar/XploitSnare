# owasp/a07_auth_failures.py

import requests
from utils.result import ScanResult
from utils.logger import setup_logger

class Scanner:
    def run(self, target):
        logger = setup_logger("A07_AuthFailures")
        paths_to_test = ["/login", "/admin", "/user/login"]
        basic_auth_url = target if target.startswith("http") else "http://" + target
        weak_auth_detected = []

        try:
            # Basic auth test
            response = requests.get(basic_auth_url, auth=('admin', 'admin'), timeout=5)
            if response.status_code == 200 and "logout" in response.text.lower():
                weak_auth_detected.append("Default credential 'admin:admin' successful")

            # Login pages test
            for path in paths_to_test:
                full_url = basic_auth_url.rstrip("/") + path
                res = requests.get(full_url, timeout=5)
                if res.status_code == 200 and any(field in res.text.lower() for field in ["password", "username", "login"]):
                    weak_auth_detected.append(f"Login page found at: {full_url}")

            logger.info(f"Authentication results: {weak_auth_detected}")

            if weak_auth_detected:
                return ScanResult("A07: Identification and Authentication Failures", "Vulnerable", weak_auth_detected)
            else:
                return ScanResult("A07: Identification and Authentication Failures", "Safe", "No weak authentication endpoints found.")

        except Exception as e:
            logger.error(f"Error in authentication test: {str(e)}")
            return ScanResult("A07: Identification and Authentication Failures", "Error", str(e))
