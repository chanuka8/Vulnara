from typing import Any


class HeaderScanner:
    """Analyzes HTTP response headers for common security controls."""

    SECURITY_HEADERS = [
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ]

    def run(self, http_probe_result: dict[str, Any]) -> dict[str, Any]:
        headers = http_probe_result.get("headers", {})

        if not isinstance(headers, dict):
            headers = {}

        normalized_headers = {
            str(key).lower(): str(value)
            for key, value in headers.items()
        }

        missing_headers = [
            header for header in self.SECURITY_HEADERS
            if header not in normalized_headers
        ]

        present_headers = {
            header: normalized_headers[header]
            for header in self.SECURITY_HEADERS
            if header in normalized_headers
        }

        return {
            "checked_headers": self.SECURITY_HEADERS,
            "missing_headers": missing_headers,
            "present_headers": present_headers,
            "server_header": normalized_headers.get("server", ""),
        }