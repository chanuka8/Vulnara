import json


class JsonReportExporter:
    def render(self, payload: dict) -> str:
        return json.dumps(payload, indent=2, ensure_ascii=False)