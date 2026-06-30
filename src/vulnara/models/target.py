from dataclasses import dataclass


@dataclass(frozen=True)
class Target:
    """Represents a validated assessment target."""

    original_url: str
    scheme: str
    hostname: str
    authorized_domain: str

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.hostname}"
