import json

from vulnara.ai_engine.prompts import EXECUTIVE_SUMMARY_SYSTEM_PROMPT
from vulnara.ai_engine.provider import OpenRouterProvider
from vulnara.models.finding import Finding


class AIAnalyzer:
    """Analyzes security findings using an external LLM."""

    def __init__(self, provider: OpenRouterProvider) -> None:
        self.provider = provider

    def generate_executive_summary(self, findings: list[Finding]) -> str:
        """Transforms raw findings into a summarized Markdown report."""
        
        if not findings:
            return "No vulnerabilities or misconfigurations were detected during this assessment."

        payload = [
            {
                "title": finding.title,
                "severity": str(finding.severity),
                "category": finding.category,
            }
            for finding in findings
        ]

        user_data = f"Scan Findings:\n{json.dumps(payload, indent=2)}"

        return self.provider.generate_completion(
            system_prompt=EXECUTIVE_SUMMARY_SYSTEM_PROMPT,
            user_data=user_data,
        )