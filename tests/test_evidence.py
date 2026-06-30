import json

from vulnara.core.evidence import EvidenceStore
from vulnara.models.finding import Finding
from vulnara.models.target import Target


def test_evidence_store_writes_expected_files(tmp_path) -> None:
    target = Target(
        original_url="https://example.com",
        scheme="https",
        hostname="example.com",
        authorized_domain="example.com",
    )

    finding = Finding(
        title="Missing security header: content-security-policy",
        severity="medium",
        description="The header is missing.",
        recommendation="Add the header.",
        evidence="Header was not present.",
        category="web_configuration",
    )

    scan_directory = EvidenceStore(evidence_root=tmp_path).save_scan_evidence(
        target=target,
        http_result={"success": True, "status_code": 200},
        header_result={"missing_headers": ["content-security-policy"]},
        findings=[finding],
        scan_id="20260701_120000",
    )

    assert (scan_directory / "target.json").exists()
    assert (scan_directory / "http_probe.json").exists()
    assert (scan_directory / "headers.json").exists()
    assert (scan_directory / "findings.json").exists()
    assert (scan_directory / "summary.json").exists()

    summary = json.loads((scan_directory / "summary.json").read_text(encoding="utf-8"))
    findings = json.loads((scan_directory / "findings.json").read_text(encoding="utf-8"))

    assert summary["target"]["hostname"] == "example.com"
    assert summary["finding_count"] == 1
    assert summary["severity_counts"]["medium"] == 1
    assert findings[0]["title"] == "Missing security header: content-security-policy"


def test_evidence_store_uses_safe_target_directory(tmp_path) -> None:
    target = Target(
        original_url="https://app.example.com",
        scheme="https",
        hostname="app.example.com",
        authorized_domain="example.com",
    )

    scan_directory = EvidenceStore(evidence_root=tmp_path).create_scan_directory(
        target=target,
        scan_id="scan_001",
    )

    assert scan_directory == tmp_path / "app.example.com" / "scan_001"