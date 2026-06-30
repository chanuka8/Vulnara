HEADER_RECOMMENDATIONS = {
    "content-security-policy": (
        "Define a Content-Security-Policy header that restricts script, style, frame, "
        "and resource loading to trusted sources."
    ),
    "strict-transport-security": (
        "Enable Strict-Transport-Security for HTTPS deployments to instruct browsers "
        "to only connect over secure transport."
    ),
    "x-frame-options": (
        "Set X-Frame-Options to DENY or SAMEORIGIN unless framing is intentionally required."
    ),
    "x-content-type-options": (
        "Set X-Content-Type-Options to nosniff to reduce MIME type confusion risks."
    ),
    "referrer-policy": (
        "Set a Referrer-Policy value that limits unnecessary referrer information leakage."
    ),
    "permissions-policy": (
        "Configure Permissions-Policy to restrict browser features that are not required."
    ),
}


DEFAULT_HEADER_RECOMMENDATION = (
    "Review the web server or application configuration and add the missing security header "
    "with values appropriate for the application."
)


def get_header_recommendation(header_name: str) -> str:
    return HEADER_RECOMMENDATIONS.get(header_name, DEFAULT_HEADER_RECOMMENDATION)