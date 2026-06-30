from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vulnara.models.finding import Finding
from vulnara.models.target import Target


@dataclass(frozen=True)
class ScanResult:
    """Represents the completed output of a Vulnara scan workflow."""

    target: Target
    http_result: dict[str, Any]
    header_result: dict[str, Any]
    findings: list[Finding]
    evidence_path: Path
    report_path: Path
    passive_results: dict[str, Any] = field(default_factory=dict)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": {
                "original_url": self.target.original_url,
                "base_url": self.target.base_url,
                "hostname": self.target.hostname,
                "authorized_domain": self.target.authorized_domain,
                "scheme": self.target.scheme,
            },
            "http_result": self.http_result,
            "header_result": self.header_result,
            "passive_results": self.passive_results,
            "findings": [finding.to_dict() for finding in self.findings],
            "evidence_path": str(self.evidence_path),
            "report_path": str(self.report_path),
            "finding_count": self.finding_count,
        }