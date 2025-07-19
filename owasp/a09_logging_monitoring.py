# owasp/a09_logging_monitoring.py

import requests
from utils.result import ScanResult
from utils.logger import setup_logger

class Scanner:
    def run(self, target):
        logger = setup_logger("A09_LoggingMonitoring")
        suspicious_behavior_detected = []

        try:
            # Send malformed requests to simulate attack patterns
            for i in range(3):
                response = requests.get(f"{target}/invalidpath{i}", timeout=5)
                if response.status_code in [500, 502, 503]:
                    suspicious_behavior_detected.append(f"Uncaught server error at /invalidpath{i}: {response.status_code}")

            # Basic login brute-force simulation
            login_endpoint = f"{target}/login"
            for _ in range(3):
                resp = requests.post(login_endpoint, data={"username": "admin", "password": "wrong"}, timeout=5)
                if resp.status_code == 200 and "logout" in resp.text.lower():
                    suspicious_behavior_detected.append("Login succeeded with invalid credentials (unexpected behavior)")

            if suspicious_behavior_detected:
                return ScanResult(
                    "A09: Security Logging and Monitoring Failures",
                    "Potential Issue",
                    f"Suspicious behavior not logged/blocked: {suspicious_behavior_detected}"
                )
            else:
                return ScanResult(
                    "A09: Security Logging and Monitoring Failures",
                    "Safe",
                    "No signs of logging or monitoring failure detected from surface scans."
                )

        except Exception as e:
            logger.error(f"Logging/Monitoring check error: {str(e)}")
            return ScanResult("A09: Security Logging and Monitoring Failures", "Error", str(e))
