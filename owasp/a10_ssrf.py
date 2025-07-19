# owasp/a10_ssrf.py

import requests
from urllib.parse import urljoin
from utils.result import ScanResult
from utils.logger import setup_logger

class Scanner:
    def run(self, target):
        logger = setup_logger("A10_SSRF")

        ssrf_test_paths = [
            "/fetch?url=http://127.0.0.1", 
            "/load?url=http://localhost", 
            "/api?path=http://169.254.169.254",  # AWS metadata IP
        ]

        triggered = []

        try:
            for path in ssrf_test_paths:
                test_url = urljoin(target, path)
                response = requests.get(test_url, timeout=5)
                
                if response.status_code == 200 and any(ip in response.text for ip in ["127.0.0.1", "localhost", "169.254"]):
                    triggered.append(f"Possible SSRF triggered at: {test_url}")

            if triggered:
                return ScanResult(
                    "A10: Server-Side Request Forgery (SSRF)",
                    "Vulnerable",
                    f"SSRF indicators found: {triggered}"
                )
            else:
                return ScanResult(
                    "A10: Server-Side Request Forgery (SSRF)",
                    "Safe",
                    "No signs of SSRF vulnerability from standard URL patterns."
                )

        except Exception as e:
            logger.error(f"SSRF test failed: {str(e)}")
            return ScanResult("A10: Server-Side Request Forgery (SSRF)", "Error", str(e))
