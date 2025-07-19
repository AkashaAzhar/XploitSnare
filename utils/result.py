# utils/result.py

class ScanResult:
    def __init__(self, module_name, status, details):
        self.module_name = module_name
        self.status = status  # e.g., 'Safe', 'Vulnerable', 'Error'
        self.details = details

    def to_dict(self):
        return {
            "module": self.module_name,
            "status": self.status,
            "details": self.details
        }
