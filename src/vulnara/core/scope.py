from urllib.parse import urlparse

from vulnara.core.exceptions import ScopeValidationError
from vulnara.models.target import Target


class ScopeValidator:
    """Enforces target authorization before any assessment module runs."""

    def validate_target(self, target_url: str, authorized_domain: str) -> Target:
        parsed = urlparse(target_url)

        if parsed.scheme not in {"http", "https"}:
            raise ScopeValidationError("Target URL must start with http:// or https://")

        if not parsed.netloc:
            raise ScopeValidationError("Target URL must include a valid hostname.")

        hostname = parsed.hostname or ""
        normalized_hostname = hostname.strip().lower()
        normalized_authorized_domain = authorized_domain.strip().lower()

        if not normalized_authorized_domain:
            raise ScopeValidationError("Authorized domain cannot be empty.")

        if not self._is_domain_in_scope(
            hostname=normalized_hostname,
            authorized_domain=normalized_authorized_domain,
        ):
            raise ScopeValidationError(
                f"Target hostname '{hostname}' is outside authorized domain '{authorized_domain}'."
            )

        return Target(
            original_url=target_url,
            scheme=parsed.scheme,
            hostname=normalized_hostname,
            authorized_domain=normalized_authorized_domain,
        )

    def _is_domain_in_scope(self, hostname: str, authorized_domain: str) -> bool:
        return hostname == authorized_domain or hostname.endswith(f".{authorized_domain}")
