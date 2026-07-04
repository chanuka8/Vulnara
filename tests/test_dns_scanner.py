from unittest.mock import patch
from vulnara.modules.discovery.dns_scanner import DNSScanner

@patch("socket.gethostbyname")
def test_dns_scanner_success(mock_gethostbyname):
    mock_gethostbyname.return_value = "93.184.216.34"
    scanner = DNSScanner("example.com")
    assets = scanner.run()
    
    assert len(assets) == 1
    assert assets[0].asset_type == "IPv4"
    assert assets[0].value == "93.184.216.34"
    assert assets[0].attributes["hostname"] == "example.com"

@patch("socket.gethostbyname")
def test_dns_scanner_failure(mock_gethostbyname):
    import socket
    mock_gethostbyname.side_effect = socket.gaierror
    scanner = DNSScanner("invalid.domain.local")
    assets = scanner.run()
    
    assert len(assets) == 0