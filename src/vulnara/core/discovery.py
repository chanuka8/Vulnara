import json
from pathlib import Path
from typing import List

from vulnara.models.asset import Asset
from vulnara.modules.discovery.dns_scanner import DNSScanner
from vulnara.modules.discovery.whois_scanner import WhoisScanner
from vulnara.modules.discovery.technology_scanner import TechnologyScanner


class DiscoveryEngine:
    def __init__(self, target_domain: str, output_dir: Path) -> None:
        self.target_domain = target_domain
        self.output_dir = output_dir

    def run(self) -> List[Asset]:
        assets: List[Asset] = []
        
        dns_scanner = DNSScanner(self.target_domain)
        assets.extend(dns_scanner.run())
        
        whois_scanner = WhoisScanner(self.target_domain)
        assets.extend(whois_scanner.run())
        
        tech_scanner = TechnologyScanner(self.target_domain)
        assets.extend(tech_scanner.run())
        
        self._save_assets(assets)
        
        return assets

    def _save_assets(self, assets: List[Asset]) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        output_file = self.output_dir / "assets.json"
        
        data = [
            {
                "asset_type": a.asset_type,
                "value": a.value,
                "source": a.source,
                "discovered_at": a.discovered_at,
                "attributes": a.attributes,
                "is_in_scope": a.is_in_scope
            }
            for a in assets
        ]
        
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)