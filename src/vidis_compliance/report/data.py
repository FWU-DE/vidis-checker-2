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


@dataclass(frozen=True)
class ReportDocument:
    result: JobResult
    criteria: CriteriaIndex
    criteria_reports: list[CriterionReport]
    raw_capture: dict[str, Any] | None
    generated_at: str
    title: str = "VIDIS Prüfkriterien V0.2 — Compliance Report"


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
    for finding in result.findings:
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
    _append_screenshot_evidence(evidence, raw_capture, finding.criterion)
    return evidence


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
