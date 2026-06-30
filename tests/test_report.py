from pathlib import Path

from vulnara.models.finding import Finding
from vulnara.models.target import Target
from vulnara.reports.generator import ReportGenerator


def test_report_generator_writes_html_report(tmp_path) -> None:
    template_directory = tmp_path / "templates"
    template_directory.mkdir()

    template_path = template_directory / "report.html"
    template_path.write_text(
        """
        <html>
          <body>
            <h1>{{ project_name }}</h1>
            <p>{{ target.hostname }}</p>
            <p>{{ findings[0].title }}</p>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

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

    report_path = ReportGenerator(
        reports_root=tmp_path / "reports",
        template_path=template_path,
    ).generate_html_report(
        target=target,
        http_result={"success": True, "status_code": 200},
        header_result={"missing_headers": ["content-security-policy"]},
        findings=[finding],
        evidence_path=Path("storage/evidence/example.com/scan_001"),
        scan_id="scan_001",
    )

    assert report_path.exists()
    assert report_path.name == "report.html"

    content = report_path.read_text(encoding="utf-8")

    assert "Vulnara" in content
    assert "example.com" in content
    assert "Missing security header: content-security-policy" in content


def test_report_generator_uses_safe_target_directory(tmp_path) -> None:
    template_directory = tmp_path / "templates"
    template_directory.mkdir()

    template_path = template_directory / "report.html"
    template_path.write_text("<html>{{ target.hostname }}</html>", encoding="utf-8")

    target = Target(
        original_url="https://app.example.com",
        scheme="https",
        hostname="app.example.com",
        authorized_domain="example.com",
    )

    report_path = ReportGenerator(
        reports_root=tmp_path / "reports",
        template_path=template_path,
    ).generate_html_report(
        target=target,
        http_result={},
        header_result={},
        findings=[],
        evidence_path=Path("storage/evidence/app.example.com/scan_001"),
        scan_id="scan_001",
    )

    assert report_path == tmp_path / "reports" / "app.example.com" / "scan_001" / "report.html"