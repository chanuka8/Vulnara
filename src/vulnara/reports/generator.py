from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from vulnara.models.finding import Finding
from vulnara.models.target import Target
from vulnara.utils.file_utils import ensure_directory, safe_path_name
from vulnara.utils.time_utils import utc_iso_timestamp, utc_timestamp


class ReportGenerator:
    """Generates local assessment reports from normalized scan results."""

    def __init__(self, reports_root: Path, template_path: Path) -> None:
        self.reports_root = reports_root
        self.template_path = template_path

    def generate_html_report(
        self,
        target: Target,
        http_result: dict[str, Any],
        header_result: dict[str, Any],
        findings: list[Finding],
        evidence_path: Path,
        scan_id: str | None = None,
    ) -> Path:
        resolved_scan_id = scan_id or utc_timestamp()
        report_directory = ensure_directory(
            self.reports_root / safe_path_name(target.hostname) / resolved_scan_id
        )

        template = self._load_template()
        report_path = report_directory / "report.html"

        payload = {
            "project_name": "Vulnara",
            "edition": "Terminal Edition",
            "generated_at": utc_iso_timestamp(),
            "target": {
                "original_url": target.original_url,
                "base_url": target.base_url,
                "hostname": target.hostname,
                "authorized_domain": target.authorized_domain,
                "scheme": target.scheme,
            },
            "http": http_result,
            "headers": header_result,
            "findings": [finding.to_dict() for finding in findings],
            "severity_counts": self._count_findings_by_severity(findings),
            "evidence_path": str(evidence_path),
            "scan_id": resolved_scan_id,
        }

        report_path.write_text(template.render(**payload), encoding="utf-8")
        return report_path

    def _load_template(self):
        environment = Environment(
            loader=FileSystemLoader(str(self.template_path.parent)),
            autoescape=select_autoescape(enabled_extensions=("html", "xml")),
        )

        return environment.get_template(self.template_path.name)

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