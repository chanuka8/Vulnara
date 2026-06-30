import pytest

from vulnara.core.exceptions import ScopeValidationError
from vulnara.core.scope import ScopeValidator


def test_scope_accepts_exact_domain() -> None:
    validator = ScopeValidator()

    target = validator.validate_target(
        target_url="https://example.com",
        authorized_domain="example.com",
    )

    assert target.hostname == "example.com"
    assert target.base_url == "https://example.com"


def test_scope_accepts_subdomain() -> None:
    validator = ScopeValidator()

    target = validator.validate_target(
        target_url="https://app.example.com",
        authorized_domain="example.com",
    )

    assert target.hostname == "app.example.com"
    assert target.base_url == "https://app.example.com"


def test_scope_rejects_out_of_scope_domain() -> None:
    validator = ScopeValidator()

    with pytest.raises(ScopeValidationError):
        validator.validate_target(
            target_url="https://evil-example.com",
            authorized_domain="example.com",
        )


def test_scope_rejects_missing_scheme() -> None:
    validator = ScopeValidator()

    with pytest.raises(ScopeValidationError):
        validator.validate_target(
            target_url="example.com",
            authorized_domain="example.com",
        )
