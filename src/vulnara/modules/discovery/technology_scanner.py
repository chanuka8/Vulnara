import requests
import urllib3
from typing import List

from vulnara.models.asset import Asset

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class TechnologyScanner:
    def __init__(self, target_domain: str) -> None:
        self.target_url = f"https://{target_domain}"

    def run(self) -> List[Asset]:
        assets: List[Asset] = []
        technologies = []
        
        try:
            response = requests.get(self.target_url, timeout=10, verify=False)
            
            server = response.headers.get("Server")
            if server:
                technologies.append(f"Server: {server}")
                
            x_powered = response.headers.get("X-Powered-By")
            if x_powered:
                technologies.append(f"Framework: {x_powered}")
                
            body = response.text.lower()
            if "wp-content" in body or "wordpress" in body:
                technologies.append("CMS: WordPress")
            if "react" in body or "data-reactroot" in body:
                technologies.append("Library: React")
            if "next.js" in body or "_next" in body:
                technologies.append("Framework: Next.js")
                
            if technologies:
                asset = Asset(
                    asset_type="TechStack",
                    value=self.target_url,
                    source="TechnologyScanner",
                    attributes={"technologies": technologies}
                )
                assets.append(asset)
                
        except Exception:
            pass

        return assets