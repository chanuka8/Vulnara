from abc import ABC, abstractmethod
from typing import Any, Dict

class BaseModule(ABC):
    """Abstract interface for all Vulnara modules."""

    @abstractmethod
    def run(self, target: Any) -> Dict[str, Any]:
        """Execute the module logic."""
        pass

    def get_skipped_result(self, reason: str) -> Dict[str, Any]:
        return {
            "success": False,
            "skipped": True,
            "reason": reason,
            "data": {}
        }