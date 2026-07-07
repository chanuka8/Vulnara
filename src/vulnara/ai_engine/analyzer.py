import json
from typing import Any, Dict, Optional

from vulnara.ai_engine.prompts import EXECUTIVE_SUMMARY_SYSTEM_PROMPT
from vulnara.ai_engine.provider import OpenRouterProvider
from vulnara.models.finding import Finding


class AIAnalyzer:
    """Analyzes security findings using an external LLM."""

    def __init__(self, provider: OpenRouterProvider) -> None:
        self.provider = provider

    def generate_executive_summary(
        self,
        findings: list[Finding],
        raw_results: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Transforms raw findings and scan data into a summarized Markdown report.
        
        Args:
            findings: Structured security findings from the rule engine.
            raw_results: Combined raw output from all scan modules (network,
                passive recon, headers, cookies, http_probe). When provided,
                the AI receives additional infrastructure context for deeper
                cross-module analysis.
        """

        if not findings and not raw_results:
            return "No vulnerabilities or misconfigurations were detected during this assessment."

        # --- Build findings payload ---
        findings_payload = [
            {
                "title": finding.title,
                "severity": str(finding.severity),
                "category": finding.category,
            }
            for finding in findings
        ]

        user_data_parts: list[str] = []

        if findings_payload:
            user_data_parts.append(
                f"Scan Findings:\n{json.dumps(findings_payload, indent=2)}"
            )

        # --- Build raw scan data payload ---
        if raw_results:
            scan_data = self._sanitize_raw_results(raw_results)
            if scan_data:
                user_data_parts.append(
                    f"Raw Scan Data:\n{json.dumps(scan_data, indent=2)}"
                )

        user_data = "\n\n".join(user_data_parts)

        return self.provider.generate_completion(
            system_prompt=EXECUTIVE_SUMMARY_SYSTEM_PROMPT,
            user_data=user_data,
        )

    def _sanitize_raw_results(self, raw_results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare raw results for LLM consumption by extracting key fields
        and removing verbose/redundant data to stay within token limits."""

        sanitized: Dict[str, Any] = {}

        # Network scan — extract port/service summary
        network = raw_results.get("network", {})
        if network and not network.get("skipped"):
            sanitized["network"] = {
                "open_ports": network.get("open_ports", []),
                "services": network.get("services", []),
                "os_detection": network.get("os_detection", ""),
                "scan_summary": network.get("output", "")[:2000],
            }

        # Passive recon modules
        passive = raw_results.get("passive", {})
        if passive:
            passive_summary: Dict[str, Any] = {}

            robots = passive.get("robots", {})
            if robots and not robots.get("skipped"):
                passive_summary["robots_txt"] = {
                    "found": robots.get("found", False),
                    "disallow_entries": robots.get("entries", {}).get("disallow", []),
                    "allow_entries": robots.get("entries", {}).get("allow", []),
                }

            sitemap = passive.get("sitemap", {})
            if sitemap and not sitemap.get("skipped"):
                passive_summary["sitemap"] = {
                    "found": sitemap.get("found", False),
                    "url_count": sitemap.get("url_count", 0),
                }

            if passive_summary:
                sanitized["passive_recon"] = passive_summary

        # Headers — include present and missing
        headers = raw_results.get("headers", {})
        if headers and not headers.get("skipped"):
            sanitized["security_headers"] = {
                "missing_headers": headers.get("missing_headers", []),
                "present_headers": headers.get("present_headers", {}),
                "server_header": headers.get("server_header", ""),
            }

        # Cookies — include flagged cookies only
        cookies = raw_results.get("cookies", {})
        if cookies and not cookies.get("skipped"):
            sanitized["cookie_security"] = {
                "cookie_count": cookies.get("cookie_count", 0),
                "cookies_with_missing_attributes": cookies.get("cookies_with_missing_attributes", []),
            }

        return sanitized