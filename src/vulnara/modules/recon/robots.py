from typing import Any

import httpx

from vulnara.models.target import Target


class RobotsTxtScanner:
    """Collects and parses robots.txt metadata from a validated target."""

    def __init__(self, timeout_seconds: int, follow_redirects: bool, user_agent: str) -> None:
        self.timeout_seconds = timeout_seconds
        self.follow_redirects = follow_redirects
        self.user_agent = user_agent

    def run(self, target: Target) -> dict[str, Any]:
        url = f"{target.base_url.rstrip('/')}/robots.txt"
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
                "entries": self.empty_entries(),
                "raw_excerpt": "",
                "error": str(error),
            }

        text = response.text if response.status_code == 200 else ""
        found = response.status_code == 200 and bool(text.strip())

        return {
            "enabled": True,
            "url": str(response.url),
            "status_code": response.status_code,
            "found": found,
            "entries": self.parse_robots_txt(text) if found else self.empty_entries(),
            "raw_excerpt": text[:4000],
            "error": "",
        }

    def parse_robots_txt(self, content: str) -> dict[str, list[str]]:
        entries = self.empty_entries()

        for raw_line in content.splitlines():
            line = raw_line.strip()

            if not line or line.startswith("#") or ":" not in line:
                continue

            key, value = line.split(":", 1)
            normalized_key = key.strip().lower()
            normalized_value = value.strip()

            if normalized_key == "user-agent":
                entries["user_agent"].append(normalized_value)
            elif normalized_key == "allow":
                entries["allow"].append(normalized_value)
            elif normalized_key == "disallow":
                entries["disallow"].append(normalized_value)
            elif normalized_key == "sitemap":
                entries["sitemap"].append(normalized_value)

        return entries

    def empty_entries(self) -> dict[str, list[str]]:
        return {
            "user_agent": [],
            "allow": [],
            "disallow": [],
            "sitemap": [],
        }