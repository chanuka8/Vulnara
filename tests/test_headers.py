from vulnara.modules.recon.headers import HeaderScanner


def test_header_scanner_detects_missing_headers() -> None:
    scanner = HeaderScanner()

    result = scanner.run(
        {
            "headers": {
                "server": "ExampleServer",
                "x-frame-options": "DENY",
            }
        }
    )

    assert "content-security-policy" in result["missing_headers"]
    assert "strict-transport-security" in result["missing_headers"]
    assert result["server_header"] == "ExampleServer"


def test_header_scanner_handles_empty_headers() -> None:
    scanner = HeaderScanner()

    result = scanner.run({"headers": {}})

    assert len(result["missing_headers"]) == len(scanner.SECURITY_HEADERS)