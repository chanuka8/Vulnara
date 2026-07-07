from pathlib import Path
from typing import Any, Dict

from vulnara.core.evidence import EvidenceStore
from vulnara.core.exceptions import ScanExecutionError, ScanProfileError
from vulnara.core.scope import ScopeValidator
from vulnara.core.logger import ConsoleLogger
from vulnara.findings.rules import FindingRuleEngine
from vulnara.models.scan_result import ScanResult
from vulnara.models.target import Target
from vulnara.modules.recon.headers import HeaderScanner
from vulnara.modules.recon.http_probe import HttpProbe
from vulnara.modules.recon.robots import RobotsTxtScanner
from vulnara.modules.recon.sitemap import SitemapScanner
from vulnara.modules.vuln_scan.cookie_scan import CookieSecurityScanner
from vulnara.modules.network.nmap_scanner import NmapScanner
from vulnara.reports.generator import ReportGenerator

from vulnara.ai_engine.provider import OpenRouterProvider, AIProviderError
from vulnara.ai_engine.analyzer import AIAnalyzer


class ScanOrchestrator:
    """Coordinates the full authorized assessment workflow."""

    def __init__(self, project_root: Path, settings: dict[str, Any], scan_profiles: dict[str, Any]) -> None:
        self.project_root = project_root
        self.settings = settings
        self.scan_profiles = scan_profiles
        self.logger = ConsoleLogger()

    def run(
        self, 
        target_url: str, 
        authorized_domain: str, 
        profile_name: str = "passive_recon",
        ai_enabled: bool = False
    ) -> ScanResult:
        profile = self.resolve_scan_profile(profile_name)

        if not self.is_module_enabled(profile, "http_probe"):
            raise ScanProfileError(f"Scan profile {profile_name} cannot run because http_probe is disabled.")

        target = ScopeValidator().validate_target(target_url=target_url, authorized_domain=authorized_domain)

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
            error_message = str(http_result.get("error", "unknown error"))
            raise ScanExecutionError(f"HTTP probe failed: {error_message}")

        header_result = HeaderScanner().run(http_result) if self.is_module_enabled(profile, "headers") else self.build_skipped_header_result()
        
        network_result = self.run_network_module(profile, target)

        passive_results = self.run_passive_recon_modules(
            profile=profile,
            target=target,
            timeout_seconds=timeout_seconds,
            follow_redirects=follow_redirects,
            user_agent=user_agent,
        )

        cookie_result = self.run_cookie_security_module(profile=profile, http_result=http_result)

        raw_results = {
            "http_probe": http_result,
            "headers": header_result,
            "network": network_result,
            "passive": passive_results,
            "cookies": cookie_result,
        }

        findings = FindingRuleEngine().build_findings(target=target, raw_results=raw_results)

        storage_settings = self._get_section("storage")
        evidence_root = self._resolve_project_path(str(storage_settings.get("evidence_dir", "storage/evidence")))
        reports_root = self._resolve_project_path(str(storage_settings.get("reports_dir", "output/reports")))
        template_path = self.project_root / "src" / "vulnara" / "reports" / "templates" / "report.html"

        evidence_path = EvidenceStore(evidence_root=evidence_root).save_scan_evidence(
            target=target,
            http_result=http_result,
            header_result=header_result,
            findings=findings,
            passive_results=passive_results,
            cookie_result=cookie_result,
        )

        ai_summary = None
        if ai_enabled:
            self.logger.info("Generating AI Executive Summary using OpenRouter...")
            try:
                provider = OpenRouterProvider()
                analyzer = AIAnalyzer(provider)
                ai_summary = analyzer.generate_executive_summary(findings, raw_results)
                self.logger.success("AI Executive Summary generated successfully.")
            except AIProviderError as e:
                self.logger.error(f"AI Engine failed: {str(e)}")
                ai_summary = "AI analysis failed due to an API error."
            except Exception as e:
                self.logger.error(f"Unexpected error during AI analysis: {str(e)}")
                ai_summary = "AI analysis failed due to an unexpected system error."

        report_path = ReportGenerator(reports_root=reports_root, template_path=template_path).generate_html_report(
            target=target,
            http_result=http_result,
            header_result=header_result,
            findings=findings,
            evidence_path=evidence_path,
            passive_results=passive_results,
            cookie_result=cookie_result,
            scan_id=evidence_path.name,
            ai_summary=ai_summary,
        )

        return ScanResult(
            target=target,
            http_result=http_result,
            header_result=header_result,
            passive_results=passive_results,
            cookie_result=cookie_result,
            findings=findings,
            evidence_path=evidence_path,
            report_path=report_path,
        )

    def run_network_module(self, profile: dict[str, Any], target: Target) -> Dict[str, Any]:
        if self.is_module_enabled(profile, "network_scan"):
            self.logger.info("Running Nmap scan...")
            return NmapScanner().run(target)
        return self.build_skipped_module_result("network_scan")

    def run_passive_recon_modules(
        self,
        profile: dict[str, Any],
        target: Target,
        timeout_seconds: int,
        follow_redirects: bool,
        user_agent: str,
    ) -> dict[str, Any]:
        results: dict[str, Any] = {}

        if self.is_module_enabled(profile, "robots"):
            results["robots"] = RobotsTxtScanner(timeout_seconds, follow_redirects, user_agent).run(target)
        else:
            results["robots"] = self.build_skipped_module_result("robots")

        if self.is_module_enabled(profile, "sitemap"):
            results["sitemap"] = SitemapScanner(timeout_seconds, follow_redirects, user_agent).run(target)
        else:
            results["sitemap"] = self.build_skipped_module_result("sitemap")

        return results

    def run_cookie_security_module(self, profile: dict[str, Any], http_result: dict[str, Any]) -> dict[str, Any]:
        if self.is_module_enabled(profile, "cookies"):
            return CookieSecurityScanner().run(http_result)

        return {
            "enabled": False,
            "checked": False,
            "skipped": True,
            "reason": "cookies module is disabled.",
            "cookie_count": 0,
            "raw_set_cookie_count": 0,
            "cookies": [],
            "cookies_with_missing_attributes": [],
            "error": "",
        }

    def resolve_scan_profile(self, profile_name: str) -> dict[str, Any]:
        profiles = self.scan_profiles.get("profiles", {})
        if not isinstance(profiles, dict):
            raise ScanProfileError("Invalid scan profiles configuration.")
        profile = profiles.get(profile_name)
        if not isinstance(profile, dict):
            available = ", ".join(sorted(profiles.keys())) or "none"
            raise ScanProfileError(f"Scan profile {profile_name} not found. Available: {available}")
        return profile

    def is_module_enabled(self, profile: dict[str, Any], module_name: str) -> bool:
        return bool(profile.get(module_name, False))

    def build_skipped_header_result(self) -> dict[str, Any]:
        return {
            "checked_headers": [],
            "missing_headers": [],
            "present_headers": {},
            "server_header": "",
            "skipped": True,
            "reason": "Security header analysis disabled.",
        }

    def build_skipped_module_result(self, module_name: str) -> dict[str, Any]:
        base_result: dict[str, Any] = {
            "enabled": False,
            "skipped": True,
            "reason": f"{module_name} module disabled.",
        }
        if module_name == "robots":
            return {**base_result, "url": "", "status_code": 0, "found": False, "entries": {"user_agent": [], "allow": [], "disallow": [], "sitemap": []}, "error": ""}
        if module_name == "sitemap":
            return {**base_result, "url": "", "status_code": 0, "found": False, "url_count": 0, "urls": [], "error": ""}
        if module_name == "network_scan":
            return {**base_result, "output": "", "error": ""}
        return base_result

    def _get_section(self, section_name: str) -> dict[str, Any]:
        section = self.settings.get(section_name, {})
        return section if isinstance(section, dict) else {}

    def _resolve_project_path(self, path_value: str) -> Path:
        path = Path(path_value)
        return path if path.is_absolute() else self.project_root / path