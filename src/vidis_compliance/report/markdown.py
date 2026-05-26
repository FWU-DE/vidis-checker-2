from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

from jinja2 import Environment

from .data import ReportDocument, build_report_document
from ..models import JobResult


def generate_markdown(
    result: JobResult,
    output_md: Path,
    *,
    raw_capture: dict | None = None,
) -> None:
    document = build_report_document(result, raw_capture=raw_capture)
    output_md.write_text(render_markdown(document), encoding="utf-8")


def render_markdown(document: ReportDocument) -> str:
    counts = {"PASS": 0, "FAIL": 0, "MANUELL": 0}
    for report in document.criteria_reports:
        counts[report.finding.status] = counts.get(report.finding.status, 0) + 1

    template_text = resources.files("vidis_compliance.report.templates").joinpath("report.md.j2").read_text(encoding="utf-8")
    env = Environment(autoescape=False, trim_blocks=True, lstrip_blocks=True)
    env.filters["table_escape"] = _escape_table
    template = env.from_string(template_text)
    raw_capture_json = ""
    if document.raw_capture:
        raw_capture_json = json.dumps(document.raw_capture, ensure_ascii=False, indent=2, default=str)
    return template.render(document=document, counts=counts, raw_capture_json=raw_capture_json)


def _escape_table(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")
