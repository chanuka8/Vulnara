from abc import ABC, abstractmethod
from typing import List, Dict, Any

class NetworkScanner(ABC):
    @abstractmethod
    def scan(self, target: str) -> List[Dict[str, Any]]:
        pass