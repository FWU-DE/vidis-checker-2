from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from ..models import CheckFinding, CriteriaIndex, JobResult, VidisCriterion

HERE = Path(__file__).resolve().parents[1]
CRITERIA_PATH = HERE / "criteria" / "vidis_v0_2.yaml"


@dataclass(frozen=True)
class EvidenceItem:
    label: str
    value: str


@dataclass(frozen=True)
class CriterionReport:
    criterion: VidisCriterion
    finding: CheckFinding
    text: str
    evidence: list[EvidenceItem] = field(default_factory=list)

    @property
    def should_show_criterion_text(self) -> bool:
        return self.finding.status == "MANUELL" and bool(self.criterion.description.strip())


@dataclass(frozen=True)
class ReportDocument:
    result: JobResult
    criteria: CriteriaIndex
    criteria_reports: list[CriterionReport]
    raw_capture: dict[str, Any] | None
    generated_at: str
    title: str = "VIDIS Prüfkriterien V0.2 — Automatisierter Vorab-Check"


def load_criteria(path: Path = CRITERIA_PATH) -> CriteriaIndex:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    items: dict[str, VidisCriterion] = {}
    for code, spec in data.items():
        items[code] = VidisCriterion(code=code, **spec)
    return CriteriaIndex(items=items)


def build_report_document(
    result: JobResult,
    *,
    criteria: CriteriaIndex | None = None,
    raw_capture: dict[str, Any] | None = None,
) -> ReportDocument:
    criteria = criteria or load_criteria()
    reports: list[CriterionReport] = []
    findings_by_criterion = {finding.criterion: finding for finding in result.findings}
    ordered_findings = [
        _normalize_report_finding(
            findings_by_criterion.get(
                code,
                CheckFinding(
                    criterion=code,
                    status="MANUELL",
                    note="Dieses Prüfkriterium wurde im Lauf nicht automatisiert getestet.",
                ),
            )
        )
        for code in criteria.items.keys()
    ]
    ordered_findings.extend(
        _normalize_report_finding(finding)
        for finding in result.findings
        if finding.criterion not in criteria.items
    )
    for finding in ordered_findings:
        criterion = criteria.items.get(
            finding.criterion,
            VidisCriterion(
                code=finding.criterion,
                name="Unbekanntes Kriterium",
                description="",
                area="RDS",
                must=True,
            ),
        )
        reports.append(
            CriterionReport(
                criterion=criterion,
                finding=finding,
                text=_explain_finding(criterion, finding),
                evidence=_evidence_for_finding(finding, raw_capture),
            )
        )
    return ReportDocument(
        result=result,
        criteria=criteria,
        criteria_reports=reports,
        raw_capture=raw_capture,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


def _normalize_report_finding(finding: CheckFinding) -> CheckFinding:
    if finding.status == "MANUELL" and finding.note.strip() == "Not yet implemented":
        return CheckFinding(
            criterion=finding.criterion,
            status="MANUELL",
            note="Dieses Prüfkriterium wurde im Lauf nicht automatisiert getestet.",
        )
    return finding


def _status_german(status: str) -> str:
    return {
        "PASS": "erfüllt",
        "FAIL": "nicht erfüllt",
        "MANUELL": "manuell zu prüfen",
    }.get(status, status)


def _explain_finding(criterion: VidisCriterion, finding: CheckFinding) -> str:
    status_text = _status_german(finding.status)
    obligation = "MUSS" if criterion.must else "SOLL"
    note = finding.note.strip() or "Es liegen keine weiteren automatischen Hinweise vor."
    return (
        f"Das {obligation}-Kriterium \"{criterion.name}\" wurde im automatisierten Lauf "
        f"als {status_text} bewertet. Grundlage der Bewertung ist der erhobene Hinweis: {note}"
    )


def _evidence_for_finding(
    finding: CheckFinding,
    raw_capture: dict[str, Any] | None,
) -> list[EvidenceItem]:
    evidence = [
        EvidenceItem("Status", finding.status),
        EvidenceItem("Automatischer Hinweis", finding.note or "—"),
    ]
    if not raw_capture:
        return evidence

    if finding.criterion in {"RDS-CUC-371", "RDS-CUC-372", "RDS-CUC-453"}:
        cookies = raw_capture.get("cookies") or []
        local_storage = raw_capture.get("local_storage") or {}
        session_storage = raw_capture.get("session_storage") or {}
        evidence.append(EvidenceItem("Anzahl Cookies", str(len(cookies))))
        if cookies:
            names = sorted({str(c.get("name", "")) for c in cookies if c.get("name")})
            evidence.append(EvidenceItem("Cookie-Namen", ", ".join(names[:20]) or "—"))
        evidence.append(EvidenceItem("LocalStorage-Schlüssel", ", ".join(sorted(local_storage.keys())) or "—"))
        evidence.append(EvidenceItem("SessionStorage-Schlüssel", ", ".join(sorted(session_storage.keys())) or "—"))
        if finding.criterion == "RDS-CUC-453":
            cuc_453 = raw_capture.get("rds_cuc_453") or {}
            if cuc_453.get("observed"):
                evidence.append(EvidenceItem("RDS-CUC-453 Inventar", ", ".join(cuc_453["observed"])))
            if cuc_453.get("present"):
                evidence.append(EvidenceItem("Beschriebene Cookies/Speicher", ", ".join(cuc_453["present"])))
            if cuc_453.get("missing"):
                evidence.append(EvidenceItem("Fehlende Beschreibungen", ", ".join(cuc_453["missing"])))
    if finding.criterion == "RDS-CUC-373":
        requests = raw_capture.get("requests") or []
        scripts = raw_capture.get("scripts") or []
        evidence.append(EvidenceItem("Netzwerkanfragen", str(len(requests))))
        evidence.append(EvidenceItem("Skriptquellen", str(len(scripts))))
    if finding.criterion == "RDS-CUC-374":
        local_storage = raw_capture.get("local_storage") or {}
        session_storage = raw_capture.get("session_storage") or {}
        evidence.append(EvidenceItem("LocalStorage-Schlüssel", ", ".join(local_storage.keys()) or "—"))
        evidence.append(EvidenceItem("SessionStorage-Schlüssel", ", ".join(session_storage.keys()) or "—"))
    if finding.criterion in {"RDS-CUC-375", "RDS-CUC-376", "RDS-CUC-377"}:
        browser_signals = raw_capture.get("browser_signals") or {}
        device_storage = browser_signals.get("device_storage") or []
        fingerprinting = browser_signals.get("fingerprinting") or []
        if finding.criterion == "RDS-CUC-375":
            evidence.append(EvidenceItem("Device-/Browser-Storage-APIs", _api_signal_summary(device_storage)))
        if finding.criterion in {"RDS-CUC-376", "RDS-CUC-377"}:
            evidence.append(EvidenceItem("Fingerprinting-/Entropy-APIs", _api_signal_summary(fingerprinting)))
        if finding.criterion == "RDS-CUC-377":
            cookies = raw_capture.get("cookies") or []
            local_storage = raw_capture.get("local_storage") or {}
            session_storage = raw_capture.get("session_storage") or {}
            requests = raw_capture.get("requests") or []
            scripts = raw_capture.get("scripts") or []
            document_capture = raw_capture.get("document_capture") or {}
            evidence.append(EvidenceItem("Cookie-Namen", ", ".join(sorted({str(c.get("name", "")) for c in cookies if c.get("name")})) or "—"))
            evidence.append(EvidenceItem("LocalStorage-Schlüssel", ", ".join(sorted(local_storage.keys())) or "—"))
            evidence.append(EvidenceItem("SessionStorage-Schlüssel", ", ".join(sorted(session_storage.keys())) or "—"))
            evidence.append(EvidenceItem("Netzwerkanfragen", str(len(requests))))
            evidence.append(EvidenceItem("Skriptquellen", str(len(scripts))))
            snippets = (document_capture.get("evidence") or {}).get("RDS-CUC-377") if isinstance(document_capture, dict) else None
            if snippets:
                evidence.append(EvidenceItem("Produkt-/Dokument-Evidenz RDS-CUC-377", " | ".join(str(snippet) for snippet in snippets[:3])))
    if finding.criterion in {"ITS-ENC-359", "ITS-ENC-360"}:
        if raw_capture.get("url"):
            evidence.append(EvidenceItem("Erfasste URL", str(raw_capture["url"])))
    if finding.criterion in {"RDS-IPF-364", "RDS-IPF-366"}:
        ipf = raw_capture.get("ipf") or {}
        if ipf.get("impressum_url"):
            evidence.append(EvidenceItem("Impressum-URL", str(ipf["impressum_url"])))
        visited = ipf.get("visited_urls") or []
        if visited:
            evidence.append(EvidenceItem("Besuchte IPF-URLs", ", ".join(str(url) for url in visited)))
    if finding.criterion in {"RDS-IPF-365", "RDS-IPF-367"}:
        ipf = raw_capture.get("ipf") or {}
        if ipf.get("privacy_url"):
            evidence.append(EvidenceItem("Datenschutzerklärung-URL", str(ipf["privacy_url"])))
        visited = ipf.get("visited_urls") or []
        if visited:
            evidence.append(EvidenceItem("Besuchte IPF-URLs", ", ".join(str(url) for url in visited)))
    _append_external_audit_evidence(evidence, raw_capture)
    _append_screenshot_evidence(evidence, raw_capture, finding.criterion)
    return evidence


def _append_external_audit_evidence(evidence: list[EvidenceItem], raw_capture: dict[str, Any]) -> None:
    lighthouse = raw_capture.get("lighthouse") or {}
    if lighthouse:
        scores = lighthouse.get("scores") or {}
        if scores:
            formatted = []
            for name, score in scores.items():
                if isinstance(score, int | float):
                    formatted.append(f"{name} {round(float(score) * 100)}%")
            evidence.append(EvidenceItem("Lighthouse", ", ".join(formatted) or "—"))
        links = []
        if lighthouse.get("json"):
            links.append(f"[JSON]({lighthouse['json']})")
        if lighthouse.get("html"):
            links.append(f"[HTML]({lighthouse['html']})")
        if links:
            evidence.append(EvidenceItem("Lighthouse-Artefakte", ", ".join(links)))
        elif lighthouse.get("note"):
            evidence.append(EvidenceItem("Lighthouse", str(lighthouse["note"])))
    webinspector = raw_capture.get("webinspector") or {}
    if webinspector:
        links = []
        if webinspector.get("network"):
            links.append(f"[Network]({webinspector['network']})")
        if webinspector.get("console"):
            links.append(f"[Console]({webinspector['console']})")
        if webinspector.get("storage"):
            links.append(f"[Storage]({webinspector['storage']})")
        if links:
            evidence.append(EvidenceItem("WebInspector-Exporte", ", ".join(links)))


def _append_screenshot_evidence(evidence: list[EvidenceItem], raw_capture: dict[str, Any], criterion: str) -> None:
    screenshots = raw_capture.get("screenshots") or []
    if screenshots:
        values = []
        for screenshot in screenshots[:8]:
            label = str(screenshot.get("label") or screenshot.get("filename") or "Screenshot")
            filename = str(screenshot.get("filename") or "")
            url = str(screenshot.get("url") or "")
            local_note = " (lokal/authentifiziert)" if screenshot.get("local_only") else ""
            link = f"[{label}]({filename})" if filename and not screenshot.get("local_only") else label
            values.append(f"{link} — {url}{local_note}".strip())
        if len(screenshots) > 8:
            values.append(f"+{len(screenshots) - 8} weitere")
        evidence.append(EvidenceItem("Screenshot-Nachweise", "; ".join(values)))
    vision_reviews = raw_capture.get("vision_reviews") or []
    matching_reviews = [
        review
        for review in vision_reviews
        if not review.get("criterion_suggestions") or criterion in review.get("criterion_suggestions", [])
    ]
    if matching_reviews:
        values = []
        for review in matching_reviews[:8]:
            label = str(review.get("label") or "Screenshot")
            status = str(review.get("status") or "MANUELL")
            note = str(review.get("note") or "—")
            values.append(f"{label}: {status} — {note}")
        evidence.append(EvidenceItem("Vision-Review", "; ".join(values)))


def _api_signal_summary(items: list[dict[str, Any]], limit: int = 12) -> str:
    if not items:
        return "—"
    values = []
    for item in items[:limit]:
        api = str(item.get("api") or "")
        count = item.get("count")
        if api:
            values.append(f"{api} ({count}×)" if count else api)
    if len(items) > limit:
        values.append(f"+{len(items) - limit} weitere")
    return ", ".join(values) or "—"
