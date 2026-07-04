from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any

def current_utc() -> str:
    return datetime.now(timezone.utc).isoformat()

@dataclass
class Asset:
    asset_type: str
    value: str
    source: str
    discovered_at: str = field(default_factory=current_utc)
    attributes: Dict[str, Any] = field(default_factory=dict)
    is_in_scope: bool = True