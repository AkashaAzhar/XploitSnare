# owasp/a02_cryptographic_failures.py

import ssl
import socket
from urllib.parse import urlparse
from utils.result import ScanResult
from utils.logger import setup_logger

class Scanner:
    def run(self, target):
        logger = setup_logger("A02_Crypto")
        parsed = urlparse(target)
        hostname = parsed.hostname
        port = 443

        try:
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=hostname) as sock:
                sock.settimeout(5)
                sock.connect((hostname, port))
                cert = sock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                valid_from = cert['notBefore']
                valid_to = cert['notAfter']

                logger.info(f"Connected to {hostname}. Cert subject: {subject}, issuer: {issuer}")
                details = (
                    f"Issued To: {subject.get('commonName')}\n"
                    f"Issuer: {issuer.get('commonName')}\n"
                    f"Valid From: {valid_from}\n"
                    f"Valid To: {valid_to}"
                )
                return ScanResult("A02: Cryptographic Failures", "Safe", details)

        except ssl.SSLError as e:
            logger.warning(f"SSL error: {str(e)}")
            return ScanResult("A02: Cryptographic Failures", "Vulnerable", f"SSL error: {str(e)}")
        except Exception as e:
            logger.error(f"Connection failed: {str(e)}")
            return ScanResult("A02: Cryptographic Failures", "Error", str(e))
