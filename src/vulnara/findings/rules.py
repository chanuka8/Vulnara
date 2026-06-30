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
                        "Missing browser security controls can increase exposure to client-side "
                        "and transport-related risks depending on the application context."
                    ),
                    recommendation=get_header_recommendation(header),
                    evidence=f"Header {header} was not present in the HTTP response.",
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

            cookie_name = str(cookie.get("name", "unknown")).strip() or "unknown"
            missing_attributes = cookie.get("missing_attributes", [])

            if not isinstance(missing_attributes, list) or not missing_attributes:
                continue

            normalized_missing = [str(attribute) for attribute in missing_attributes]
            missing_text = ", ".join(normalized_missing)

            findings.append(
                Finding(
                    title=f"Cookie missing security attributes: {cookie_name}",
                    severity=Severity.LOW.value,
                    description=(
                        "The HTTP response sets a cookie that is missing one or more common "
                        "security attributes. Missing cookie attributes can increase exposure "
                        "to client-side access, insecure transport, or cross-site request risks "
                        "depending on application context."
                    ),
                    recommendation=(
                        "Set Secure, HttpOnly, and SameSite attributes on sensitive cookies where "
                        "appropriate. Use Secure for HTTPS-only transport, HttpOnly to reduce "
                        "client-side script access, and SameSite to help control cross-site usage."
                    ),
                    evidence=f"Cookie {cookie_name} missing attributes: {missing_text}",
                    category="web_configuration",
                )
            )

        return findings

    def _build_server_disclosure_findings(self, header_result: dict[str, Any]) -> list[Finding]:
        server_header = str(header_result.get("server_header", "")).strip()

        if not server_header:
            return []

        return [
            Finding(
                title="Server header disclosure",
                severity=Severity.INFO.value,
                description=(
                    "The HTTP response includes a Server header. This may disclose server "
                    "or platform information that is not required by normal users."
                ),
                recommendation=(
                    "Avoid exposing detailed server version information in production responses. "
                    "Where possible, reduce or standardize the Server header value."
                ),
                evidence=f"Server: {server_header}",
                category="information_disclosure",
            )
        ]

    def _build_transport_findings(self, target: Target) -> list[Finding]:
        if target.scheme == "https":
            return []

        return [
            Finding(
                title="Target is using HTTP",
                severity=Severity.MEDIUM.value,
                description=(
                    "The target URL uses HTTP instead of HTTPS. Traffic sent over HTTP can be "
                    "observed or modified by network-level attackers."
                ),
                recommendation=(
                    "Use HTTPS with a valid TLS certificate and redirect HTTP traffic to HTTPS."
                ),
                evidence=target.original_url,
                category="transport_security",
            )
        ]

    def _header_severity(self, header: str) -> Severity:
        medium_headers = {
            "content-security-policy",
            "strict-transport-security",
            "x-frame-options",
        }

        if header in medium_headers:
            return Severity.MEDIUM

        return Severity.LOW

    def _sort_findings(self, findings: list[Finding]) -> list[Finding]:
        order = {
            Severity.CRITICAL.value: 5,
            Severity.HIGH.value: 4,
            Severity.MEDIUM.value: 3,
            Severity.LOW.value: 2,
            Severity.INFO.value: 1,
        }

        return sorted(findings, key=lambda finding: order.get(finding.severity, 0), reverse=True)
