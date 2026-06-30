from typing import Any

import httpx
from bs4 import BeautifulSoup

from vulnara.models.target import Target


class HttpProbe:
    """Collects basic HTTP metadata from a validated target."""

    def __init__(self, timeout_seconds: int, follow_redirects: bool, user_agent: str) -> None:
        self.timeout_seconds = timeout_seconds
        self.follow_redirects = follow_redirects
        self.user_agent = user_agent

    def run(self, target: Target) -> dict[str, Any]:
        headers = {"User-Agent": self.user_agent}

        try:
            with httpx.Client(
                timeout=self.timeout_seconds,
                follow_redirects=self.follow_redirects,
                headers=headers,
            ) as client:
                response = client.get(target.base_url)
        except httpx.HTTPError as error:
            return {
                "success": False,
                "url": target.base_url,
                "error": str(error),
            }

        return {
            "success": True,
            "url": str(response.url),
            "status_code": response.status_code,
            "reason_phrase": response.reason_phrase,
            "headers": dict(response.headers),
            "title": self._extract_title(response.text),
            "redirect_history": [str(item.url) for item in response.history],
        }

    def _extract_title(self, html: str) -> str:
        soup = BeautifulSoup(html, "html.parser")
        title = soup.find("title")

        if title and title.text:
            return title.text.strip()

        return ""