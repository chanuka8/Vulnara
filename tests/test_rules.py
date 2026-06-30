from vulnara.findings.rules import FindingRuleEngine
from vulnara.models.target import Target


def test_missing_security_header_generates_finding() -> None:
    target = Target(
        original_url="https://example.com",
        scheme="https",
        hostname="example.com",
        authorized_domain="example.com",
    )

    raw_results = {
        "headers": {
            "missing_headers": ["content-security-policy"],
            "server_header": "",
        }
    }

    findings = FindingRuleEngine().build_findings(target=target, raw_results=raw_results)

    assert len(findings) == 1
    assert findings[0].title == "Missing security header: content-security-policy"
    assert findings[0].severity == "medium"


def test_server_header_generates_info_finding() -> None:
    target = Target(
        original_url="https://example.com",
        scheme="https",
        hostname="example.com",
        authorized_domain="example.com",
    )

    raw_results = {
        "headers": {
            "missing_headers": [],
            "server_header": "ExampleServer",
        }
    }

    findings = FindingRuleEngine().build_findings(target=target, raw_results=raw_results)

    assert len(findings) == 1
    assert findings[0].title == "Server header disclosure"
    assert findings[0].severity == "info"


def test_http_target_generates_transport_finding() -> None:
    target = Target(
        original_url="http://example.com",
        scheme="http",
        hostname="example.com",
        authorized_domain="example.com",
    )

    raw_results = {
        "headers": {
            "missing_headers": [],
            "server_header": "",
        }
    }

    findings = FindingRuleEngine().build_findings(target=target, raw_results=raw_results)

    assert len(findings) == 1
    assert findings[0].title == "Target is using HTTP"
    assert findings[0].severity == "medium"


def test_multiple_findings_are_sorted_by_severity() -> None:
    target = Target(
        original_url="http://example.com",
        scheme="http",
        hostname="example.com",
        authorized_domain="example.com",
    )

    raw_results = {
        "headers": {
            "missing_headers": ["permissions-policy"],
            "server_header": "ExampleServer",
        }
    }

    findings = FindingRuleEngine().build_findings(target=target, raw_results=raw_results)

    assert findings[0].severity == "medium"
    assert findings[1].severity == "low"
    assert findings[2].severity == "info"