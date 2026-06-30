import json
from pathlib import Path
from typing import Any

from vulnara.models.finding import Finding
from vulnara.models.target import Target
from vulnara.utils.file_utils import ensure_directory, safe_path_name
from vulnara.utils.time_utils import utc_iso_timestamp, utc_timestamp


class EvidenceStore:
    """Persists assessment evidence in a structured local directory."""

    def __init__(self, evidence_root: Path) -> None:
        self.evidence_root = evidence_root

    def create_scan_directory(self, target: Target, scan_id: str | None = None) -> Path:
        resolved_scan_id = scan_id or utc_timestamp()
        target_directory = safe_path_name(target.hostname)

        return ensure_directory(self.evidence_root / target_directory / resolved_scan_id)

    def save_scan_evidence(
        self,
        target: Target,
        http_result: dict[str, Any],
        header_result: dict[str, Any],
        findings: list[Finding],
        passive_results: dict[str, Any] | None = None,
        cookie_result: dict[str, Any] | None = None,
        scan_id: str | None = None,
    ) -> Path:
        scan_directory = self.create_scan_directory(target=target, scan_id=scan_id)
        resolved_passive_results = passive_results or {}
        resolved_cookie_result = cookie_result or {}

        target_payload = {
            "original_url": target.original_url,
            "scheme": target.scheme,
            "hostname": target.hostname,
            "authorized_domain": target.authorized_domain,
            "base_url": target.base_url,
            "saved_at": utc_iso_timestamp(),
        }

        finding_payload = [finding.to_dict() for finding in findings]

        evidence_files = [
            "target.json",
            "http_probe.json",
            "headers.json",
            "cookies.json",
            "findings.json",
            "summary.json",
        ]

        self._write_json(scan_directory / "target.json", target_payload)
        self._write_json(scan_directory / "http_probe.json", http_result)
        self._write_json(scan_directory / "headers.json", header_result)
        self._write_json(scan_directory / "cookies.json", resolved_cookie_result)
        self._write_json(scan_directory / "findings.json", finding_payload)

        for module_name, payload in resolved_passive_results.items():
            file_name = f"{safe_path_name(module_name)}.json"
            evidence_files.append(file_name)
            self._write_json(scan_directory / file_name, payload)

        summary_payload = {
            "target": {
                "hostname": target.hostname,
                "base_url": target.base_url,
                "authorized_domain": target.authorized_domain,
            },
            "finding_count": len(findings),
            "severity_counts": self._count_findings_by_severity(findings),
            "passive_modules": sorted(resolved_passive_results.keys()),
            "cookie_count": int(resolved_cookie_result.get("cookie_count", 0)),
            "cookies_with_missing_attributes": len(
                resolved_cookie_result.get("cookies_with_missing_attributes", [])
            ),
            "saved_at": utc_iso_timestamp(),
            "evidence_files": evidence_files,
        }

        self._write_json(scan_directory / "summary.json", summary_payload)

        return scan_directory

    def _count_findings_by_severity(self, findings: list[Finding]) -> dict[str, int]:
        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in findings:
            severity = finding.severity.lower()
            counts[severity] = counts.get(severity, 0) + 1

        return counts

    def _write_json(self, path: Path, payload: Any) -> None:
        ensure_directory(path.parent)

        with path.open("w", encoding="utf-8") as file:
            json.dump(payload, file, indent=2, ensure_ascii=False, default=str)
