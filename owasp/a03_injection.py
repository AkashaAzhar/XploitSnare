# owasp/a03_injection.py

import requests
from urllib.parse import urljoin
from utils.result import ScanResult
from utils.logger import setup_logger

class Scanner:
    def run(self, target):
        logger = setup_logger("A03_Injection")
        payloads = ["' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--"]
        vulnerable = []

        test_params = ["id", "user", "name", "search"]

        try:
            for param in test_params:
                for payload in payloads:
                    test_url = f"{target}?{param}={payload}"
                    response = requests.get(test_url, timeout=5)

                    logger.info(f"Testing URL: {test_url} - Status: {response.status_code}")

                    if any(keyword in response.text.lower() for keyword in [
                        "sql syntax", "mysql", "warning", "unclosed quotation", "odbc", "jdbc", "sqlite"
                    ]):
                        vulnerable.append(test_url)

            if vulnerable:
                return ScanResult("A03: Injection", "Vulnerable", f"Potential SQL injection points: {vulnerable}")
            else:
                return ScanResult("A03: Injection", "Safe", "No SQLi patterns detected in GET parameters.")

        except Exception as e:
            logger.error(f"Error during injection test: {str(e)}")
            return ScanResult("A03: Injection", "Error", str(e))
