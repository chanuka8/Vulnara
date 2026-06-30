import pytest

from vulnara.core.exceptions import ScanProfileError
from vulnara.core.orchestrator import ScanOrchestrator


def test_orchestrator_resolves_existing_scan_profile(tmp_path) -> None:
    orchestrator = ScanOrchestrator(
        project_root=tmp_path,
        settings={},
        scan_profiles={
            "profiles": {
                "passive_recon": {
                    "http_probe": True,
                    "headers": True,
                }
            }
        },
    )

    profile = orchestrator.resolve_scan_profile("passive_recon")

    assert profile["http_probe"] is True
    assert profile["headers"] is True


def test_orchestrator_rejects_unknown_scan_profile(tmp_path) -> None:
    orchestrator = ScanOrchestrator(
        project_root=tmp_path,
        settings={},
        scan_profiles={
            "profiles": {
                "passive_recon": {}
            }
        },
    )

    with pytest.raises(ScanProfileError):
        orchestrator.resolve_scan_profile("aggressive_scan")


def test_orchestrator_checks_enabled_module_flag(tmp_path) -> None:
    orchestrator = ScanOrchestrator(
        project_root=tmp_path,
        settings={},
        scan_profiles={},
    )

    profile = {
        "http_probe": True,
        "headers": False,
    }

    assert orchestrator.is_module_enabled(profile, "http_probe") is True
    assert orchestrator.is_module_enabled(profile, "headers") is False
    assert orchestrator.is_module_enabled(profile, "robots") is False


def test_orchestrator_builds_skipped_header_result(tmp_path) -> None:
    orchestrator = ScanOrchestrator(
        project_root=tmp_path,
        settings={},
        scan_profiles={},
    )

    result = orchestrator.build_skipped_header_result()

    assert result["skipped"] is True
    assert result["missing_headers"] == []
    assert result["server_header"] == ""
    assert "disabled" in result["reason"]