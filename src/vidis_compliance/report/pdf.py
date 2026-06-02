from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from ..models import JobResult
from ..coverage_matrix import build_coverage_matrix
from .data import ReportDocument, build_report_document
from .markdown import _sanitize_raw_capture


PAGE_WIDTH, PAGE_HEIGHT = A4
SCREENSHOT_HORIZONTAL_MARGIN_CM = 1.1
SCREENSHOT_MAX_HEIGHT_CM = 20.8


def screenshot_slot_width_points() -> float:
    return PAGE_WIDTH - (2 * SCREENSHOT_HORIZONTAL_MARGIN_CM * cm)


def screenshot_slot_height_points() -> float:
    return SCREENSHOT_MAX_HEIGHT_CM * cm


def _scaled_screenshot_image(path: Path) -> Image:
    image = Image(str(path))
    max_width = screenshot_slot_width_points()
    max_height = screenshot_slot_height_points()
    scale = min(max_width / image.imageWidth, max_height / image.imageHeight)
    image.drawWidth = image.imageWidth * scale
    image.drawHeight = image.imageHeight * scale
    return image


def generate_pdf(
    result: JobResult,
    output_pdf: Path,
    *,
    raw_capture: dict | None = None,
) -> None:
    document = build_report_document(result, raw_capture=raw_capture)
    render_pdf(document, output_pdf)


def render_pdf(document: ReportDocument, output_pdf: Path) -> None:
    styles = _styles()
    doc = SimpleDocTemplate(
        str(output_pdf),
        pagesize=A4,
        rightMargin=1.35 * cm,
        leftMargin=1.35 * cm,
        topMargin=1.25 * cm,
        bottomMargin=1.25 * cm,
        title=document.title,
    )
    story = []
    counts = _status_counts(document)

    story.extend(_cover(document, counts, styles))
    story.extend(_screenshot_overview(document, styles))
    story.extend(_cookie_storage_overview(document, styles))
    story.append(Paragraph("Kriterienbewertung", styles["SectionTitle"]))
    for report in document.criteria_reports:
        criterion = report.criterion
        finding = report.finding
        badge = _status_badge(finding.status)
        title = Paragraph(f"{criterion.code}: {_xml_escape(criterion.name)}", styles["CriterionTitle"])
        meta = Paragraph(
            f"Bereich: {criterion.area} · Verbindlichkeit: "
            f"{'MUSS' if criterion.must else 'SOLL'} · Status: {badge}",
            styles["SmallMuted"],
        )
        parts = [title, meta]
        if report.should_show_criterion_text:
            parts.append(Paragraph("Kriterium", styles["MiniHeading"]))
            parts.append(Paragraph(_xml_escape(_compact_text(criterion.description.strip(), 900)), styles["BodyText"]))
        parts.append(Paragraph("Bewertung", styles["MiniHeading"]))
        parts.append(Paragraph(_xml_escape(_compact_report_text(report.text, 650)), styles["BodyText"]))
        parts.append(Paragraph("Nachweise", styles["MiniHeading"]))
        parts.append(_evidence_table(report.evidence))
        parts.append(Spacer(1, 0.3 * cm))
        story.append(KeepTogether(parts))

    screenshot_pages = _screenshot_pages(document, styles)
    if screenshot_pages:
        story.append(PageBreak())
        story.extend(screenshot_pages)

    story.append(PageBreak())
    story.extend(_coverage_matrix_pages(styles))

    story.append(PageBreak())
    story.append(Paragraph("Anhang: Rohdaten der Erfassung", styles["SectionTitle"]))
    raw_text = "Keine Rohdaten übergeben."
    if document.raw_capture:
        raw_text = json.dumps(_sanitize_raw_capture(document.raw_capture), ensure_ascii=False, indent=2, default=str)
    for chunk in _chunk_text(raw_text, 1800):
        story.append(Paragraph(_xml_escape(chunk).replace("\n", "<br/>"), styles["CodeBlock"]))
        story.append(Spacer(1, 0.18 * cm))

    doc.build(story)


def _styles():
    styles = getSampleStyleSheet()
    styles["Title"].fontName = "Helvetica-Bold"
    styles["Title"].fontSize = 22
    styles["Title"].leading = 26
    styles["BodyText"].fontSize = 9.2
    styles["BodyText"].leading = 12.2
    styles["BodyText"].spaceAfter = 4
    styles.add(ParagraphStyle("Subtitle", parent=styles["Normal"], fontSize=10.5, leading=14, textColor=colors.HexColor("#4b5563")))
    styles.add(ParagraphStyle("SectionTitle", parent=styles["Heading1"], fontSize=15, leading=18, spaceBefore=8, spaceAfter=8, textColor=colors.HexColor("#111827")))
    styles.add(ParagraphStyle("CriterionTitle", parent=styles["Heading2"], fontSize=11.5, leading=14, spaceBefore=8, spaceAfter=3, textColor=colors.HexColor("#111827")))
    styles.add(ParagraphStyle("MiniHeading", parent=styles["Heading3"], fontSize=9.2, leading=11, spaceBefore=4, spaceAfter=2, textColor=colors.HexColor("#374151")))
    styles.add(ParagraphStyle("SmallMuted", parent=styles["Normal"], fontSize=8.2, leading=10.5, textColor=colors.HexColor("#6b7280")))
    styles.add(ParagraphStyle("Disclaimer", parent=styles["Normal"], fontSize=8.4, leading=11, textColor=colors.HexColor("#92400e"), backColor=colors.HexColor("#fffbeb"), borderColor=colors.HexColor("#f59e0b"), borderWidth=0.25, borderPadding=5, spaceAfter=4))
    styles.add(ParagraphStyle("KpiNumber", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=20, leading=23, alignment=TA_LEFT))
    styles.add(ParagraphStyle("KpiLabel", parent=styles["Normal"], fontSize=8, leading=10, textColor=colors.HexColor("#6b7280")))
    styles.add(ParagraphStyle("CodeBlock", parent=styles["Code"], fontName="Courier", fontSize=6.5, leading=8, backColor=colors.HexColor("#f8fafc"), borderColor=colors.HexColor("#e5e7eb"), borderWidth=0.25, borderPadding=4))
    return styles


def _cover(document: ReportDocument, counts: dict[str, int], styles) -> list:
    flow = [
        Paragraph(document.title, styles["Title"]),
        Paragraph(f"Job: {document.result.job_id} · Erstellt: {document.generated_at}", styles["Subtitle"]),
        Spacer(1, 0.35 * cm),
        _kpi_table(counts),
        Spacer(1, 0.45 * cm),
        Paragraph("Kurzüberblick", styles["SectionTitle"]),
        Paragraph(
            "Der Report fasst automatisierte VIDIS-Prüfsignale, Nachweise und manuell zu prüfende Punkte zusammen. "
            "Screenshots werden im Anhang eingebettet, sofern der Lauf Bildnachweise erzeugt hat.",
            styles["BodyText"],
        ),
        Spacer(1, 0.2 * cm),
    ]
    if document.semantic_disclaimer:
        flow.extend(
            [
                Paragraph("Hinweis zu inhaltlichen Bewertungen", styles["MiniHeading"]),
                Paragraph(_xml_escape(_ascii_pdf_text(document.semantic_disclaimer)), styles["Disclaimer"]),
                Spacer(1, 0.25 * cm),
            ]
        )
    flow.append(Spacer(1, 0.15 * cm))
    url = (document.raw_capture or {}).get("url") if document.raw_capture else None
    if url:
        flow.append(Paragraph(f"Geprüfte Start-URL: {_xml_escape(str(url))}", styles["SmallMuted"]))
        flow.append(Spacer(1, 0.25 * cm))
    return flow


def _kpi_table(counts: dict[str, int]) -> Table:
    rows = [[_kpi_cell("PASS", counts.get("PASS", 0)), _kpi_cell("FAIL", counts.get("FAIL", 0)), _kpi_cell("MANUELL", counts.get("MANUELL", 0))]]
    table = Table(rows, colWidths=[5.1 * cm, 5.1 * cm, 5.1 * cm])
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e5e7eb")),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f9fafb")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return table


def _kpi_cell(label: str, value: int) -> list:
    styles = _styles()
    return [Paragraph(str(value), styles["KpiNumber"]), Paragraph(label, styles["KpiLabel"])]


def _screenshot_overview(document: ReportDocument, styles) -> list:
    screenshots = _screenshots(document)
    if not screenshots:
        return []
    return [
        Paragraph("Screenshot-Nachweise", styles["SectionTitle"]),
        Paragraph(
            f"{len(screenshots)} Screenshot(s) wurden als Bildnachweise erfasst. Die ersten Screenshots sind im Anhang eingebettet; "
            "authentifizierte/local-only Screenshots werden nur als lokale Artefakte referenziert.",
            styles["BodyText"],
        ),
        _screenshot_index_table(screenshots),
        Spacer(1, 0.45 * cm),
    ]


def _cookie_storage_overview(document: ReportDocument, styles) -> list:
    evidence = document.cookie_storage_evidence
    if not evidence:
        return []
    return [
        Paragraph("Gemeinsame Cookie- und Browser-Storage-Bewertung", styles["SectionTitle"]),
        Paragraph(
            "Diese Übersicht fasst Cookies, localStorage und sessionStorage für die betroffenen CUC-Kriterien zusammen. "
            "Storage-Werte werden nicht ausgegeben.",
            styles["BodyText"],
        ),
        _evidence_table(evidence),
        Spacer(1, 0.45 * cm),
    ]


def _evidence_table(items) -> Table:
    rows = [[Paragraph("Nachweis", _small_bold()), Paragraph("Wert", _small_bold())]]
    for item in items:
        label = str(item.label)
        value = str(item.value)
        if label == "Screenshot-Nachweise":
            value = f"{max(1, value.count(';') + 1)} Screenshot(s), siehe Screenshot-Anhang."
        elif label == "Vision-Review":
            value = "Optionale Sichtprüfung; Details im Screenshot-Anhang bzw. in den Artefakten."
        rows.append([
            Paragraph(_xml_escape(label), _small()),
            Paragraph(_xml_escape(_compact_evidence_value(value)), _small()),
        ])
    table = Table(rows, colWidths=[4.4 * cm, 11.0 * cm], repeatRows=1, hAlign="LEFT")
    table.setStyle(_table_style())
    return table


def _screenshot_index_table(screenshots: list[dict]) -> Table:
    rows = [[Paragraph("Screenshot", _small_bold()), Paragraph("URL", _small_bold()), Paragraph("Datei", _small_bold())]]
    for screenshot in screenshots[:10]:
        rows.append([
            Paragraph(_xml_escape(str(screenshot.get("label") or "Screenshot")), _small()),
            Paragraph(_xml_escape(_compact_url(str(screenshot.get("url") or "—"), 90)), _small()),
            Paragraph(_xml_escape(str(screenshot.get("filename") or screenshot.get("path") or "—")), _small()),
        ])
    table = Table(rows, colWidths=[3.2 * cm, 8.4 * cm, 3.8 * cm], repeatRows=1, hAlign="LEFT")
    table.setStyle(_table_style())
    return table


def _screenshot_pages(document: ReportDocument, styles) -> list:
    flow = [Paragraph("Anhang: Screenshots", styles["SectionTitle"])]
    usable = []
    for screenshot in _screenshots(document):
        path = Path(str(screenshot.get("path") or ""))
        if path.exists() and path.suffix.lower() in {".png", ".jpg", ".jpeg"} and not screenshot.get("local_only"):
            usable.append((screenshot, path))
    if not usable:
        flow.append(Paragraph("Keine einbettbaren Screenshot-Dateien vorhanden.", styles["BodyText"]))
        return flow
    for index, (screenshot, path) in enumerate(usable[:6], start=1):
        label = str(screenshot.get("label") or f"Screenshot {index}")
        url = str(screenshot.get("url") or "")
        flow.append(Paragraph(f"{index}. {_xml_escape(label)}", styles["CriterionTitle"]))
        if url:
            flow.append(Paragraph(_xml_escape(_compact_url(url, 130)), styles["SmallMuted"]))
        flow.append(_scaled_screenshot_image(path))
        flow.append(Spacer(1, 0.25 * cm))
        if index != min(len(usable), 6):
            flow.append(PageBreak())
    if len(usable) > 6:
        flow.append(Paragraph(f"Weitere {len(usable) - 6} Screenshot(s) liegen als Artefakte im Ergebnisordner.", styles["BodyText"]))
    return flow


def _coverage_matrix_pages(styles) -> list:
    matrix = build_coverage_matrix()
    rows = [row for row in matrix["rows"] if row.get("kind") == "criterion"]
    gap_rows = [row for row in matrix["rows"] if row.get("kind") == "platform_gap"]
    flow = [
        Paragraph("Anhang: Coverage Matrix", styles["SectionTitle"]),
        Paragraph(
            "Die Matrix zeigt, welche VIDIS-Prüfkriterien und Plattformfähigkeiten automatisiert, teilweise automatisiert oder manuell abgedeckt sind. "
            "Spalten: Code, Name, Implementation status, Automation level.",
            styles["BodyText"],
        ),
        _coverage_table(rows),
    ]
    if gap_rows:
        flow.append(Spacer(1, 0.35 * cm))
        flow.append(Paragraph("Plattformfähigkeiten", styles["MiniHeading"]))
        flow.append(Paragraph(_xml_escape(", ".join(str(row.get("code")) for row in gap_rows)), styles["BodyText"]))
        flow.append(_coverage_table(gap_rows))
    return flow


def _coverage_table(rows: list[dict]) -> Table:
    header = ["Code", "Name", "Implementation status", "Automation level"]
    table_rows = [[Paragraph(cell, _small_bold()) for cell in header]]
    for row in rows:
        table_rows.append(
            [
                Paragraph(_xml_escape(str(row.get("code", "—"))), _small()),
                Paragraph(_xml_escape(_compact_text(str(row.get("name", "—")), 90)), _small()),
                Paragraph(_xml_escape(str(row.get("implementation_status", "—"))), _small()),
                Paragraph(_xml_escape(_compact_text(str(row.get("automation_level", "—")), 120)), _small()),
            ]
        )
    table = Table(table_rows, colWidths=[3.7 * cm, 4.7 * cm, 3.0 * cm, 4.0 * cm], repeatRows=1, hAlign="LEFT")
    table.setStyle(_table_style())
    return table


def _screenshots(document: ReportDocument) -> list[dict]:
    if not document.raw_capture:
        return []
    screenshots = document.raw_capture.get("screenshots") or []
    return [s for s in screenshots if isinstance(s, dict)]


def _status_counts(document: ReportDocument) -> dict[str, int]:
    counts = {"PASS": 0, "FAIL": 0, "MANUELL": 0}
    for report in document.criteria_reports:
        counts[report.finding.status] = counts.get(report.finding.status, 0) + 1
    return counts


def _status_badge(status: str) -> str:
    color = {"PASS": "#166534", "FAIL": "#991b1b", "MANUELL": "#92400e"}.get(status, "#374151")
    return f"<font color='{color}'><b>{_xml_escape(status)}</b></font>"


def _table_style() -> TableStyle:
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#111827")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.6),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ])


def _small() -> ParagraphStyle:
    return ParagraphStyle("EvidenceSmall", fontName="Helvetica", fontSize=7.2, leading=9.2)


def _small_bold() -> ParagraphStyle:
    return ParagraphStyle("EvidenceSmallBold", fontName="Helvetica-Bold", fontSize=7.3, leading=9.3)


def _xml_escape(value: str) -> str:
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _ascii_pdf_text(value: str) -> str:
    return (
        str(value)
        .replace("ä", "ae")
        .replace("ö", "oe")
        .replace("ü", "ue")
        .replace("Ä", "Ae")
        .replace("Ö", "Oe")
        .replace("Ü", "Ue")
        .replace("ß", "ss")
    )


def _compact_text(value: str, limit: int) -> str:
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _compact_evidence_value(value: str) -> str:
    text = _compact_report_text(value, 520)
    # Markdown links are noisy in PDFs; keep only readable label and URL-ish target shortened.
    if "](" in text:
        text = text.replace("](", " — ").replace("[", "").replace(")", "")
    return _compact_url(text, 520)


def _compact_report_text(value: str, limit: int) -> str:
    text = _compact_text(value, limit * 2)
    tokens = [_short_url(token, 92) if token.startswith(("http://", "https://")) else token for token in text.split()]
    compact = " ".join(tokens)
    return compact if len(compact) <= limit else compact[: limit - 1] + "…"


def _compact_url(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    pieces = []
    for token in value.split(", "):
        pieces.append(_short_url(token.strip(), 120))
    shortened = ", ".join(pieces)
    return shortened if len(shortened) <= limit else shortened[: limit - 1] + "…"


def _short_url(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        compact = urlunparse((parsed.scheme, parsed.netloc, parsed.path[:42] + ("…" if len(parsed.path) > 42 else ""), "", "", ""))
        return compact if len(compact) <= limit else compact[: limit - 1] + "…"
    return value[: limit - 1] + "…"


def _chunk_text(value: str, chunk_size: int) -> list[str]:
    return [value[i : i + chunk_size] for i in range(0, len(value), chunk_size)] or [""]
