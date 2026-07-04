from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


class HtmlReportRenderer:
    def __init__(self, template_path: Path) -> None:
        self._template_path = template_path

    def render(self, payload: dict) -> str:
        environment = Environment(
            loader=FileSystemLoader(str(self._template_path.parent)),
            autoescape=select_autoescape(enabled_extensions=("html", "xml")),
        )

        template = environment.get_template(self._template_path.name)
        return template.render(**payload)