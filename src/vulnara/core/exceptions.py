class VulnaraError(Exception):
    """Base exception for Vulnara application errors."""


class ConfigurationError(VulnaraError):
    """Raised when a configuration file is missing or invalid."""


class ScopeValidationError(VulnaraError):
    """Raised when a target is outside the authorized assessment scope."""


class ScanProfileError(VulnaraError):
    """Raised when a requested scan profile is unavailable or invalid."""


class ScanExecutionError(VulnaraError):
    """Raised when a scan workflow step cannot be completed."""