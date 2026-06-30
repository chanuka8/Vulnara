from typing import Any


class CookieSecurityScanner:
    """Analyzes Set-Cookie headers for common safe security attributes."""

    def run(self, http_result: dict[str, Any]) -> dict[str, Any]:
        headers = http_result.get("headers", {})
        raw_cookie_headers = self.extract_set_cookie_headers(headers)

        cookies: list[dict[str, Any]] = []

        for raw_cookie_header in raw_cookie_headers:
            cookie = self.analyze_cookie_header(raw_cookie_header)

            if cookie:
                cookies.append(cookie)

        return {
            "enabled": True,
            "checked": True,
            "cookie_count": len(cookies),
            "raw_set_cookie_count": len(raw_cookie_headers),
            "cookies": cookies,
            "cookies_with_missing_attributes": [
                cookie for cookie in cookies if cookie.get("missing_attributes")
            ],
            "error": "",
        }

    def extract_set_cookie_headers(self, headers: Any) -> list[str]:
        if not isinstance(headers, dict):
            return []

        values: list[str] = []

        for key, value in headers.items():
            if str(key).lower() != "set-cookie":
                continue

            if isinstance(value, str) and value.strip():
                values.append(value.strip())
            elif isinstance(value, list | tuple):
                values.extend(str(item).strip() for item in value if str(item).strip())

        return values

    def analyze_cookie_header(self, raw_cookie_header: str) -> dict[str, Any]:
        parts = [part.strip() for part in raw_cookie_header.split(";") if part.strip()]

        if not parts or "=" not in parts[0]:
            return {}

        cookie_name = parts[0].split("=", 1)[0].strip()
        attribute_parts = parts[1:]
        attribute_names = {part.split("=", 1)[0].strip().lower() for part in attribute_parts}

        has_secure = "secure" in attribute_names
        has_http_only = "httponly" in attribute_names
        same_site = self.extract_same_site_value(attribute_parts)
        has_same_site = bool(same_site)

        missing_attributes: list[str] = []

        if not has_secure:
            missing_attributes.append("Secure")

        if not has_http_only:
            missing_attributes.append("HttpOnly")

        if not has_same_site:
            missing_attributes.append("SameSite")

        return {
            "name": cookie_name,
            "has_secure": has_secure,
            "has_http_only": has_http_only,
            "has_same_site": has_same_site,
            "same_site": same_site,
            "missing_attributes": missing_attributes,
            "raw_excerpt": raw_cookie_header[:500],
        }

    def extract_same_site_value(self, attribute_parts: list[str]) -> str:
        for part in attribute_parts:
            if "=" not in part:
                continue

            key, value = part.split("=", 1)

            if key.strip().lower() == "samesite":
                return value.strip()

        return ""
