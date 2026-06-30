from vulnara.modules.recon.robots import RobotsTxtScanner
from vulnara.modules.recon.sitemap import SitemapScanner


def test_robots_txt_parser_extracts_supported_directives() -> None:
    scanner = RobotsTxtScanner(
        timeout_seconds=10,
        follow_redirects=True,
        user_agent="Vulnara-Test",
    )

    result = scanner.parse_robots_txt(
        """
        User-agent: *
        Disallow: /admin
        Allow: /public
        Sitemap: https://example.com/sitemap.xml
        """
    )

    assert result["user_agent"] == ["*"]
    assert result["disallow"] == ["/admin"]
    assert result["allow"] == ["/public"]
    assert result["sitemap"] == ["https://example.com/sitemap.xml"]


def test_robots_txt_parser_ignores_comments_and_invalid_lines() -> None:
    scanner = RobotsTxtScanner(
        timeout_seconds=10,
        follow_redirects=True,
        user_agent="Vulnara-Test",
    )

    result = scanner.parse_robots_txt(
        """
        # comment
        invalid line
        Disallow: /private
        """
    )

    assert result["disallow"] == ["/private"]
    assert result["allow"] == []
    assert result["sitemap"] == []


def test_sitemap_parser_extracts_loc_values() -> None:
    scanner = SitemapScanner(
        timeout_seconds=10,
        follow_redirects=True,
        user_agent="Vulnara-Test",
    )

    result = scanner.parse_sitemap_xml(
        """
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <url>
            <loc>https://example.com/</loc>
          </url>
          <url>
            <loc>https://example.com/about</loc>
          </url>
        </urlset>
        """
    )

    assert result == [
        "https://example.com/",
        "https://example.com/about",
    ]


def test_sitemap_parser_returns_empty_list_for_invalid_xml() -> None:
    scanner = SitemapScanner(
        timeout_seconds=10,
        follow_redirects=True,
        user_agent="Vulnara-Test",
    )

    result = scanner.parse_sitemap_xml("<not-valid")

    assert result == []