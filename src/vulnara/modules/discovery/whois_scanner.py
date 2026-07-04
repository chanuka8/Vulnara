import whois
from typing import List

from vulnara.models.asset import Asset


class WhoisScanner:
    def __init__(self, target_domain: str) -> None:
        self.target_domain = target_domain

    def run(self) -> List[Asset]:
        assets: List[Asset] = []
        
        try:
            w = whois.whois(self.target_domain)
            
            registrar = w.get("registrar", "Unknown") if isinstance(w.get("registrar"), str) else "Multiple/Unknown"
            
            asset = Asset(
                asset_type="WHOIS_Record",
                value=self.target_domain,
                source="WhoisScanner",
                attributes={
                    "registrar": registrar
                }
            )
            assets.append(asset)
            
        except Exception:
            pass

        return assets