import socket
from typing import List

from vulnara.models.asset import Asset


class DNSScanner:
    def __init__(self, target_domain: str) -> None:
        self.target_domain = target_domain

    def run(self) -> List[Asset]:
        assets: List[Asset] = []
        
        try:
            ip_address = socket.gethostbyname(self.target_domain)
            
            asset = Asset(
                asset_type="IPv4",
                value=ip_address,
                source="DNSScanner",
                attributes={"hostname": self.target_domain}
            )
            assets.append(asset)
            
        except socket.gaierror:
            pass

        return assets