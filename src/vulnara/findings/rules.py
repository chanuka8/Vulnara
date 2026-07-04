from typing import Any

from vulnara.findings.recommendations import get_header_recommendation
from vulnara.findings.severity import Severity
from vulnara.models.finding import Finding
from vulnara.models.target import Target


class FindingRuleEngine:
    """Converts normalized scan output into security findings."""

    def build_findings(self, target: Target, raw_results: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []

        findings.extend(self._build_header_findings(raw_results.get("headers", {})))
        findings.extend(self._build_cookie_findings(raw_results.get("cookies", {})))
        findings.extend(self._build_server_disclosure_findings(raw_results.get("headers", {})))
        findings.extend(self._build_transport_findings(target))
        findings.extend(self._build_network_findings(raw_results.get("network", {})))

        return self._sort_findings(findings)

    def _build_header_findings(self, header_result: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        missing_headers = header_result.get("missing_headers", [])
        if not isinstance(missing_headers, list):
            return findings

        for header in missing_headers:
            if not isinstance(header, str):
                continue
            findings.append(
                Finding(
                    title=f"Missing security header: {header}",
                    severity=self._header_severity(header).value,
                    description=(
                        f"The HTTP response does not include the {header} security header. "
                        "Missing browser security controls can increase exposure."
                    ),
                    recommendation=get_header_recommendation(header),
                    evidence=f"Header {header} was not present.",
                    category="web_configuration",
                )
            )
        return findings

    def _build_cookie_findings(self, cookie_result: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        weak_cookies = cookie_result.get("cookies_with_missing_attributes", [])
        if not isinstance(weak_cookies, list):
            return findings

        for cookie in weak_cookies:
            if not isinstance(cookie, dict):
                continue
            cookie_name = str(cookie.get("name", "unknown")).strip()
            missing_attrs = cookie.get("missing_attributes", [])
            if not isinstance(missing_attrs, list) or not missing_attrs:
                continue

            findings.append(
                Finding(
                    title=f"Cookie missing attributes: {cookie_name}",
                    severity=Severity.LOW.value,
                    description="Cookie is missing one or more security attributes.",
                    recommendation="Set Secure, HttpOnly, and SameSite attributes.",
                    evidence=f"Missing: {', '.join(map(str, missing_attrs))}",
                    category="web_configuration",
                )
            )
        return findings

    def _build_server_disclosure_findings(self, header_result: dict[str, Any]) -> list[Finding]:
        server = str(header_result.get("server_header", "")).strip()
        if not server:
            return []
        return [
            Finding(
                title="Server header disclosure",
                severity=Severity.INFO.value,
                description="Server header discloses platform information.",
                recommendation="Reduce or standardize the Server header value.",
                evidence=f"Server: {server}",
                category="information_disclosure",
            )
        ]

    def _build_network_findings(self, network_result: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        if not network_result.get("success") or network_result.get("skipped"):
            return findings

        output = network_result.get("output", "")
        # Heuristic rules for common insecure ports
        insecure_map = {
            "21/tcp": "FTP",
            "23/tcp": "Telnet",
            "3306/tcp": "MySQL"
        }

        for port, service in insecure_map.items():
            if f"{port} open" in output:
                findings.append(
                    Finding(
                        title=f"Insecure service detected: {service}",
                        severity=Severity.HIGH.value,
                        description=f"Port {port} is exposed. This service communicates in cleartext.",
                        recommendation=f"Disable {service} or block access via firewall.",
                        evidence=f"Port {port} is open.",
                        category="network_vulnerability",
                    )
                )
        return findings

    def _build_transport_findings(self, target: Target) -> list[Finding]:
        if target.scheme == "https":
            return []
        return [
            Finding(
                title="Target is using HTTP",
                severity=Severity.MEDIUM.value,
                description="Traffic is not encrypted.",
                recommendation="Use HTTPS.",
                evidence=target.original_url,
                category="transport_security",
            )
        ]

    def _header_severity(self, header: str) -> Severity:
        medium = {"content-security-policy", "strict-transport-security", "x-frame-options"}
        return Severity.MEDIUM if header in medium else Severity.LOW

    def _sort_findings(self, findings: list[Finding]) -> list[Finding]:
        order = {
            Severity.CRITICAL.value: 5,
            Severity.HIGH.value: 4,
            Severity.MEDIUM.value: 3,
            Severity.LOW.value: 2,
            Severity.INFO.value: 1,
        }
        return sorted(findings, key=lambda f: order.get(f.severity, 0), reverse=True)