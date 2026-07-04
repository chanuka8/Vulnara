from unittest.mock import patch, MagicMock
from vulnara.modules.discovery.technology_scanner import TechnologyScanner

@patch("requests.get")
def test_technology_scanner_success(mock_get):
    mock_response = MagicMock()
    mock_response.headers = {"Server": "nginx", "X-Powered-By": "PHP/8.1"}
    mock_response.text = '<html><body><div id="wp-content"></div></body></html>'
    mock_get.return_value = mock_response

    scanner = TechnologyScanner("testsite.com")
    assets = scanner.run()
    
    assert len(assets) == 1
    assert assets[0].asset_type == "TechStack"
    
    techs = assets[0].attributes["technologies"]
    assert "Server: nginx" in techs
    assert "Framework: PHP/8.1" in techs
    assert "CMS: WordPress" in techs

@patch("requests.get")
def test_technology_scanner_no_tech(mock_get):
    mock_response = MagicMock()
    mock_response.headers = {}
    mock_response.text = '<html><body>Basic Site</body></html>'
    mock_get.return_value = mock_response

    scanner = TechnologyScanner("plain-site.com")
    assets = scanner.run()
    
    assert len(assets) == 0