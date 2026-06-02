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
        evidence.append(EvidenceItem("Anzahl Cookies", str(len(cookies))))
        if cookies:
            names = sorted({str(c.get("name", "")) for c in cookies if c.get("name")})
            evidence.append(EvidenceItem("Cookie-Namen", ", ".join(names[:20]) or "—"))
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
    return evidence
