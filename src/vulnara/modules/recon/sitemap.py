from typing import Any
from xml.etree import ElementTree

import httpx

from vulnara.models.target import Target


class SitemapScanner:
    """Collects and parses sitemap.xml metadata from a validated target."""

    def __init__(self, timeout_seconds: int, follow_redirects: bool, user_agent: str) -> None:
        self.timeout_seconds = timeout_seconds
        self.follow_redirects = follow_redirects
        self.user_agent = user_agent

    def run(self, target: Target) -> dict[str, Any]:
        url = f"{target.base_url.rstrip('/')}/sitemap.xml"
        headers = {"User-Agent": self.user_agent}

        try:
            with httpx.Client(
                timeout=self.timeout_seconds,
                follow_redirects=self.follow_redirects,
                headers=headers,
            ) as client:
                response = client.get(url)
        except httpx.HTTPError as error:
            return {
                "enabled": True,
                "url": url,
                "status_code": 0,
                "found": False,
                "url_count": 0,
                "urls": [],
                "raw_excerpt": "",
                "error": str(error),
            }

        text = response.text if response.status_code == 200 else ""
        urls = self.parse_sitemap_xml(text) if text else []

        return {
            "enabled": True,
            "url": str(response.url),
            "status_code": response.status_code,
            "found": response.status_code == 200 and bool(urls),
            "url_count": len(urls),
            "urls": urls[:100],
            "raw_excerpt": text[:4000],
            "error": "",
        }

    def parse_sitemap_xml(self, content: str) -> list[str]:
        try:
            root = ElementTree.fromstring(content)
        except ElementTree.ParseError:
            return []

        urls: list[str] = []

        for element in root.iter():
            tag_name = element.tag.split("}", 1)[-1].lower()

            if tag_name == "loc" and element.text:
                url = element.text.strip()

                if url and url not in urls:
                    urls.append(url)

        return urls