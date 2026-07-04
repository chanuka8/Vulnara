import subprocess
import shutil
from typing import Any, Dict
from vulnara.core.base_module import BaseModule

class NmapScanner(BaseModule):
    """Wrapper for Nmap to perform network recon."""

    def __init__(self, arguments: str = "-sV -T4") -> None:
        self.arguments = arguments
        self.binary = shutil.which("nmap")

    def run(self, target: Any) -> Dict[str, Any]:
        if not self.binary:
            return self.get_skipped_result("nmap binary not found in system path.")

        try:
            # Running Nmap as a sub-process
            command = [self.binary] + self.arguments.split() + [target.hostname]
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            
            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr,
                "command": " ".join(command)
            }
        except Exception as e:
            return {"success": False, "error": str(e)}