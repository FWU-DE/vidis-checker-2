from __future__ import annotations

import json
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from ..models import JobResult
from .data import ReportDocument, build_report_document


def generate_pdf(
    result: JobResult,
    output_pdf: Path,
    *,
    raw_capture: dict | None = None,
) -> None:
    document = build_report_document(result, raw_capture=raw_capture)
    render_pdf(document, output_pdf)


def render_pdf(document: ReportDocument, output_pdf: Path) -> None:
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(
        str(output_pdf),
        pagesize=A4,
        rightMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        topMargin=1.4 * cm,
        bottomMargin=1.4 * cm,
        title=document.title,
    )
    story = []
    story.append(Paragraph(document.title, styles["Title"]))
    story.append(Paragraph(f"Job: {document.result.job_id}", styles["Normal"]))
    story.append(Paragraph(f"Erstellt: {document.generated_at}", styles["Normal"]))
    story.append(Spacer(1, 0.35 * cm))

    counts = {"PASS": 0, "FAIL": 0, "MANUELL": 0}
    for report in document.criteria_reports:
        counts[report.finding.status] = counts.get(report.finding.status, 0) + 1
    summary = Table(
        [["Status", "Anzahl"], ["PASS", counts.get("PASS", 0)], ["FAIL", counts.get("FAIL", 0)], ["MANUELL", counts.get("MANUELL", 0)]],
        colWidths=[6 * cm, 3 * cm],
    )
    summary.setStyle(_table_style())
    story.append(Paragraph("Zusammenfassung", styles["Heading1"]))
    story.append(summary)
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph("Kriterienbewertung", styles["Heading1"]))
    for report in document.criteria_reports:
        criterion = report.criterion
        finding = report.finding
        story.append(Paragraph(f"{criterion.code}: {criterion.name}", styles["Heading2"]))
        meta = (
            f"Bereich: {criterion.area} · Verbindlichkeit: "
            f"{'MUSS' if criterion.must else 'SOLL'} · Status: <b>{finding.status}</b>"
        )
        story.append(Paragraph(meta, styles["Normal"]))
        if criterion.description.strip():
            story.append(Paragraph("Kriteriumstext", styles["Heading3"]))
            story.append(Paragraph(_xml_escape(criterion.description.strip()), styles["BodyText"]))
        story.append(Paragraph("Bewertungstext", styles["Heading3"]))
        story.append(Paragraph(_xml_escape(report.text), styles["BodyText"]))
        story.append(Paragraph("Nachweise", styles["Heading3"]))
        table_rows = [["Nachweis", "Wert"]]
        table_rows.extend([[item.label, _truncate(item.value, 500)] for item in report.evidence])
        evidence = Table(table_rows, colWidths=[5 * cm, 11 * cm], repeatRows=1)
        evidence.setStyle(_table_style())
        story.append(evidence)
        story.append(Spacer(1, 0.35 * cm))

    story.append(PageBreak())
    story.append(Paragraph("Anhang: Rohdaten der Erfassung", styles["Heading1"]))
    raw_text = "Keine Rohdaten übergeben."
    if document.raw_capture:
        raw_text = json.dumps(document.raw_capture, ensure_ascii=False, indent=2, default=str)
    for chunk in _chunk_text(raw_text, 2200):
        story.append(Paragraph(f"<font name='Courier'>{_xml_escape(chunk).replace(chr(10), '<br/>')}</font>", styles["Code"]))
        story.append(Spacer(1, 0.2 * cm))

    doc.build(story)


def _table_style() -> TableStyle:
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eeeeee")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#999999")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]
    )


def _xml_escape(value: str) -> str:
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _truncate(value: str, limit: int) -> str:
    text = str(value)
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _chunk_text(value: str, chunk_size: int) -> list[str]:
    return [value[i : i + chunk_size] for i in range(0, len(value), chunk_size)] or [""]
