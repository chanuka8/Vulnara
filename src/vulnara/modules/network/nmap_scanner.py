import subprocess
import tempfile
from typing import List, Dict, Any
from vulnara.modules.network.base_scanner import NetworkScanner

class NmapScanner(NetworkScanner):
    def scan(self, target: str) -> List[Dict[str, Any]]:
        results = []
        
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            subprocess.run(
                ["nmap", "-sV", "-oX", tmp_path, target], 
                check=True, capture_output=True
            )
            
            results.append({
                "target": target,
                "status": "completed",
                "tool": "nmap",
                "output_path": tmp_path
            })
            
        except subprocess.CalledProcessError:
            pass
            
        return results