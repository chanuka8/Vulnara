from pathlib import Path
from typing import Any

import yaml

from vulnara.core.exceptions import ConfigurationError


class ConfigLoader:
    """Loads Vulnara YAML configuration files from the project root."""

    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root

    def load_settings(self) -> dict[str, Any]:
        return self._load_yaml(self.project_root / "config" / "settings.yaml")

    def load_scan_profiles(self) -> dict[str, Any]:
        return self._load_yaml(self.project_root / "config" / "scan_profiles.yaml")

    def _load_yaml(self, path: Path) -> dict[str, Any]:
        if not path.exists():
            raise ConfigurationError(f"Configuration file not found: {path}")

        with path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file) or {}

        if not isinstance(data, dict):
            raise ConfigurationError(f"Invalid YAML structure: {path}")

        return data
