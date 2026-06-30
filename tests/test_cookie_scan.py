from vulnara.modules.vuln_scan.cookie_scan import CookieSecurityScanner


def test_cookie_scanner_returns_empty_result_without_set_cookie_header() -> None:
    scanner = CookieSecurityScanner()

    result = scanner.run({"headers": {"content-type": "text/html"}})

    assert result["checked"] is True
    assert result["cookie_count"] == 0
    assert result["cookies"] == []


def test_cookie_scanner_detects_secure_cookie_attributes() -> None:
    scanner = CookieSecurityScanner()

    result = scanner.run(
        {
            "headers": {
                "set-cookie": "sessionid=abc123; Secure; HttpOnly; SameSite=Lax"
            }
        }
    )

    cookie = result["cookies"][0]

    assert result["cookie_count"] == 1
    assert cookie["name"] == "sessionid"
    assert cookie["has_secure"] is True
    assert cookie["has_http_only"] is True
    assert cookie["has_same_site"] is True
    assert cookie["same_site"] == "Lax"
    assert cookie["missing_attributes"] == []


def test_cookie_scanner_detects_missing_cookie_attributes() -> None:
    scanner = CookieSecurityScanner()

    result = scanner.run({"headers": {"set-cookie": "sessionid=abc123"}})

    cookie = result["cookies"][0]

    assert cookie["missing_attributes"] == ["Secure", "HttpOnly", "SameSite"]
    assert result["cookies_with_missing_attributes"] == [cookie]


def test_cookie_scanner_supports_multiple_set_cookie_values() -> None:
    scanner = CookieSecurityScanner()

    result = scanner.run(
        {
            "headers": {
                "set-cookie": [
                    "sessionid=abc123; Secure; HttpOnly; SameSite=Lax",
                    "tracking=yes",
                ]
            }
        }
    )

    assert result["cookie_count"] == 2
    assert result["cookies"][0]["missing_attributes"] == []
    assert result["cookies"][1]["missing_attributes"] == ["Secure", "HttpOnly", "SameSite"]
