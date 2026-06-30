from pathlib import Path
from typing import Any

from vulnara.core.evidence import EvidenceStore
from vulnara.core.exceptions import ScanExecutionError, ScanProfileError
from vulnara.core.scope import ScopeValidator
from vulnara.findings.rules import FindingRuleEngine
from vulnara.models.scan_result import ScanResult
from vulnara.modules.recon.headers import HeaderScanner
from vulnara.modules.recon.http_probe import HttpProbe
from vulnara.reports.generator import ReportGenerator


class ScanOrchestrator:
    """Coordinates the full authorized assessment workflow."""

    def __init__(
        self,
        project_root: Path,
        settings: dict[str, Any],
        scan_profiles: dict[str, Any],
    ) -> None:
        self.project_root = project_root
        self.settings = settings
        self.scan_profiles = scan_profiles

    def run(
        self,
        target_url: str,
        authorized_domain: str,
        profile_name: str = "passive_recon",
    ) -> ScanResult:
        self.resolve_scan_profile(profile_name)

        target = ScopeValidator().validate_target(
            target_url=target_url,
            authorized_domain=authorized_domain,
        )

        network_settings = self._get_section("network")
        timeout_seconds = int(network_settings.get("timeout_seconds", 10))
        follow_redirects = bool(network_settings.get("follow_redirects", True))
        user_agent = str(network_settings.get("user_agent", "Vulnara/0.1"))

        http_result = HttpProbe(
            timeout_seconds=timeout_seconds,
            follow_redirects=follow_redirects,
            user_agent=user_agent,
        ).run(target)

        if not http_result.get("success"):
            raise ScanExecutionError(
                f"HTTP probe failed: {http_result.get('error', 'unknown error')}"
            )

        header_result = HeaderScanner().run(http_result)

        raw_results = {
            "http_probe": http_result,
            "headers": header_result,
        }

        findings = FindingRuleEngine().build_findings(
            target=target,
            raw_results=raw_results,
        )

        storage_settings = self._get_section("storage")
        evidence_root = self._resolve_project_path(
            str(storage_settings.get("evidence_dir", "storage/evidence"))
        )
        reports_root = self._resolve_project_path(
            str(storage_settings.get("reports_dir", "output/reports"))
        )
        template_path = (
            self.project_root
            / "src"
            / "vulnara"
            / "reports"
            / "templates"
            / "report.html"
        )

        evidence_path = EvidenceStore(evidence_root=evidence_root).save_scan_evidence(
            target=target,
            http_result=http_result,
            header_result=header_result,
            findings=findings,
        )

        report_path = ReportGenerator(
            reports_root=reports_root,
            template_path=template_path,
        ).generate_html_report(
            target=target,
            http_result=http_result,
            header_result=header_result,
            findings=findings,
            evidence_path=evidence_path,
            scan_id=evidence_path.name,
        )

        return ScanResult(
            target=target,
            http_result=http_result,
            header_result=header_result,
            findings=findings,
            evidence_path=evidence_path,
            report_path=report_path,
        )

    def resolve_scan_profile(self, profile_name: str) -> dict[str, Any]:
        profiles = self.scan_profiles.get("profiles", {})

        if not isinstance(profiles, dict):
            raise ScanProfileError("Invalid scan profiles configuration.")

        profile = profiles.get(profile_name)

        if not isinstance(profile, dict):
            available_profiles = ", ".join(sorted(profiles.keys())) or "none"
            raise ScanProfileError(
                f"Scan profile '{profile_name}' was not found. "
                f"Available profiles: {available_profiles}"
            )

        return profile

    def _get_section(self, section_name: str) -> dict[str, Any]:
        section = self.settings.get(section_name, {})

        if not isinstance(section, dict):
            return {}

        return section

    def _resolve_project_path(self, path_value: str) -> Path:
        path = Path(path_value)

        if path.is_absolute():
            return path

        return self.project_root / path