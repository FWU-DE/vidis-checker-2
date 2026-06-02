from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from ..checks.site.cookies import _classify_name
from ..checks.site.cookie_db import get_default_cookie_database
from ..models import CheckFinding, CriteriaIndex, JobResult, VidisCriterion

HERE = Path(__file__).resolve().parents[1]
CRITERIA_PATH = HERE / "criteria" / "vidis_v0_2.yaml"
SEMANTIC_EVALUATION_DISCLAIMER = (
    "Dieser Report enthält bei Impressum, Datenschutzerklärung, AGB/AVV, "
    "Werbung, Jugendmedienschutz und vergleichbaren inhaltlichen Bewertungen "
    "eine KI-gestützte erste Einschätzung. Sie ersetzt keine rechtliche oder "
    "datenschutzfachliche Prüfung durch qualifizierte Personen."
)
SEMANTIC_EVALUATION_PREFIXES = ("RDS-IPF-", "RDS-AGB-", "RDS-WER-", "RDS-VIN-")
SEMANTIC_EVALUATION_CODES = {"RDS-DSO-383", "RDS-DEV-380", "RDS-DEV-466", "RDS-SPE-370", "RDS-CUC-453"}
COOKIE_STORAGE_SECTION_CRITERIA = {"RDS-CUC-371", "RDS-CUC-372", "RDS-CUC-374", "RDS-CUC-377", "RDS-CUC-453"}
COOKIE_STORAGE_SECTION_ORDER = ("RDS-CUC-371", "RDS-CUC-372", "RDS-CUC-374", "RDS-CUC-377", "RDS-CUC-453")


@dataclass(frozen=True)
class EvidenceItem:
    label: str
    value: str


@dataclass(frozen=True)
class CriterionReport:
    criterion: VidisCriterion
    finding: CheckFinding
    text: str
    beginner_explanation: list[EvidenceItem] = field(default_factory=list)
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

    @property
    def semantic_disclaimer(self) -> str:
        if any(_is_semantic_evaluation(report.criterion.code) for report in self.criteria_reports):
            return SEMANTIC_EVALUATION_DISCLAIMER
        return ""

    @property
    def cookie_storage_evidence(self) -> list[EvidenceItem]:
        if not self.raw_capture:
            return []
        covered = sorted(
            {finding.criterion for finding in self.result.findings if finding.criterion in COOKIE_STORAGE_SECTION_CRITERIA},
            key=lambda code: COOKIE_STORAGE_SECTION_ORDER.index(code),
        )
        if not covered:
            covered = [code for code in COOKIE_STORAGE_SECTION_ORDER if code in self.criteria.items]
        evidence = [EvidenceItem("Betroffene Kriterien", ", ".join(covered))]
        evidence.extend(_cookie_storage_inventory_evidence(self.raw_capture))
        cuc_453 = self.raw_capture.get("rds_cuc_453") or {}
        if cuc_453.get("observed"):
            evidence.append(EvidenceItem("RDS-CUC-453 Inventar", ", ".join(cuc_453["observed"])))
        if cuc_453.get("present"):
            evidence.append(EvidenceItem("Beschriebene Cookies/Speicher", ", ".join(cuc_453["present"])))
        if cuc_453.get("missing"):
            evidence.append(EvidenceItem("Fehlende Beschreibungen", ", ".join(cuc_453["missing"])))
        return evidence


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
                beginner_explanation=_beginner_explanation(criterion, finding),
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


def _is_semantic_evaluation(code: str) -> bool:
    return code in SEMANTIC_EVALUATION_CODES or code.startswith(SEMANTIC_EVALUATION_PREFIXES)


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


def _beginner_explanation(criterion: VidisCriterion, finding: CheckFinding) -> list[EvidenceItem]:
    status_meaning = {
        "PASS": "Dieses Kriterium wirkt aktuell erfüllt. Trotzdem sollte der Nachweis bei wichtigen Beschaffungs- oder Datenschutzentscheidungen kurz fachlich gegengeprüft werden.",
        "FAIL": "Dieses Kriterium wirkt aktuell nicht erfüllt oder unvollständig. Der Report zeigt, welche Signale gefunden wurden und welche Punkte fehlen oder problematisch wirken.",
        "MANUELL": "Hier ist eine fachliche oder technische Klärung nötig. Der automatische Lauf hat entweder keine belastbare Entscheidung getroffen oder das Kriterium benötigt grundsätzlich Kontextwissen.",
    }.get(finding.status, "Der Status stammt aus dem automatisierten Lauf und sollte bei Unklarheiten manuell eingeordnet werden.")
    why = _why_text(criterion)
    next_steps = _next_steps_text(criterion, finding)
    return [
        EvidenceItem("Was bedeutet das?", status_meaning),
        EvidenceItem("Warum ist das relevant?", why),
        EvidenceItem("Nächste Schritte", next_steps),
    ]


def _why_text(criterion: VidisCriterion) -> str:
    code = criterion.code
    if code.startswith("RDS-IPF-"):
        if code in {"RDS-IPF-364", "RDS-IPF-366"}:
            return "Für Anfänger: Ein Impressum ist die gesetzliche Anbieterkennzeichnung. Es hilft Nutzenden, Schulen und Trägern zu erkennen, wer für das Angebot verantwortlich ist und wie der Anbieter erreichbar ist."
        return "Für Anfänger: Die Datenschutzerklärung erklärt, wer Daten verarbeitet, zu welchem Zweck, auf welcher Rechtsgrundlage und welche Rechte betroffene Personen haben. Sie ist eine zentrale Entscheidungsgrundlage für Datenschutzprüfung und Beschaffung."
    if code == "RDS-DSO-383":
        return "Für Anfänger: Ein Datenschutzbeauftragter ist eine fachliche Kontaktstelle für Datenschutzfragen. Wenn er bestellt ist, müssen seine Kontaktdaten in den Datenschutzinformationen auffindbar sein."
    if code.startswith("ITS-ENC-"):
        return "Für Anfänger: Transportverschlüsselung schützt Daten auf dem Weg zwischen Browser und Anbieter. Ohne HTTPS können Inhalte oder Anmeldedaten leichter mitgelesen oder manipuliert werden."
    if code.startswith("RDS-CUC-"):
        return "Für Anfänger: Cookies und Browser-Speicher können technisch notwendig sein, aber auch Tracking oder Profilbildung ermöglichen. Deshalb müssen Zweck, Notwendigkeit und Einwilligung besonders nachvollziehbar sein."
    if code.startswith("RDS-AGB-"):
        return "Für Anfänger: AGB und Nutzungsbedingungen regeln, was Anbieter, Schulen und Nutzende dürfen oder müssen. Unklare oder problematische Klauseln können rechtliche und organisatorische Risiken erzeugen."
    if code.startswith("RDS-DEV-") or code.startswith("RDS-DSO-"):
        return "Für Anfänger: Diese Datenschutz- und Betreiberpflichten zeigen, ob Verantwortlichkeiten, Auftragsverarbeitung und Schutzmaßnahmen nachvollziehbar dokumentiert sind."
    if code.startswith("RDS-WER-") or code.startswith("RDS-VIN-"):
        return "Für Anfänger: Werbung, Beeinflussung und jugendgefährdende Inhalte sind im Bildungskontext besonders kritisch, weil Schülerinnen und Schüler besonders schutzbedürftig sind."
    return f"Für Anfänger: Dieses VIDIS-Kriterium beschreibt eine Anforderung im Bereich {criterion.area}. Es hilft, technische, rechtliche oder organisatorische Risiken systematisch sichtbar zu machen."


def _next_steps_text(criterion: VidisCriterion, finding: CheckFinding) -> str:
    note = finding.note.strip()
    if criterion.code == "RDS-IPF-366":
        missing = _note_part(note, "fehlend")
        detail = f" Fehlende Punkte laut Report: {missing}." if missing else ""
        return "Prüfe die genannten fehlenden Punkte im Impressum und ergänze sie auf der öffentlich erreichbaren Impressumsseite oder kläre mit dem Anbieter, warum sie nicht erforderlich sind." + detail
    if criterion.code == "RDS-IPF-367":
        missing = _note_part(note, "fehlend")
        detail = f" Fehlende Punkte laut Report: {missing}." if missing else ""
        return "Prüfe die Datenschutzerklärung gegen die Art.-13-DSGVO-Pflichtinformationen und fordere fehlende Angaben beim Anbieter nach." + detail
    if criterion.code == "RDS-DSO-383":
        return "Prüfe, ob ein Datenschutzbeauftragter bestellt ist. Falls ja, müssen dessen Kontaktdaten in der Datenschutzerklärung leicht auffindbar sein; falls nein, sollte die Begründung fachlich geprüft werden."
    if finding.status == "PASS":
        return "Dokumentiere den Nachweis und prüfe stichprobenartig, ob die Aussage auch für Login-Bereiche, mobile Ansichten und produktive Mandanten gilt."
    if finding.status == "FAIL":
        return "Priorisiere die Behebung vor Freigabe oder Beschaffung. Nutze die Nachweise im Report, um Anbieter, Technik oder Datenschutzstelle gezielt um Korrektur oder Erklärung zu bitten."
    if finding.status == "MANUELL":
        return "Lies den Kriteriumstext und die Nachweise, prüfe die betroffenen Seiten/Dokumente manuell und dokumentiere eine fachliche Entscheidung mit Begründung."
    return "Prüfe die Nachweise und dokumentiere die fachliche Entscheidung."


def _note_part(note: str, label: str) -> str:
    marker = f"{label}:"
    if marker not in note:
        return ""
    value = note.split(marker, 1)[1]
    for next_marker in ("; gefunden:", "; fehlend:", "; manuell zu prüfen:"):
        if next_marker in value:
            value = value.split(next_marker, 1)[0]
    return value.strip().rstrip(".")


def _classification_text(name: str) -> str:
    database = get_default_cookie_database()
    bucket, detail = _classify_name(name, database)
    status = {
        "essential": "essenziell",
        "non_essential": "nicht essenziell",
        "unknown": "manuell prüfen",
    }.get(bucket, "manuell prüfen")
    cookie_info = database.get_cookie_info(name)
    if cookie_info is not None:
        source = f"{cookie_info.platform} / {cookie_info.category}"
        if cookie_info.retention_period:
            source += f"; Speicherdauer: {cookie_info.retention_period}"
        if cookie_info.description:
            source += f"; {cookie_info.description}"
        return f"{status} — {source}"
    if "Heuristik:" in detail:
        return f"{status} — {detail.split('(', 1)[-1].rstrip(')')}"
    if "Allowlist-Präfix" in detail:
        return f"{status} — Allowlist-Präfix"
    return f"{status} — Keine Einstufung in cookie_db.json/Heuristik"


def _cookie_storage_inventory_evidence(
    raw_capture: dict[str, Any],
    *,
    include_cookies: bool = True,
) -> list[EvidenceItem]:
    evidence: list[EvidenceItem] = []
    if include_cookies:
        cookies = raw_capture.get("cookies") or []
        cookie_names = sorted({str(cookie.get("name") or "").strip() for cookie in cookies if isinstance(cookie, dict) and str(cookie.get("name") or "").strip()}, key=str.lower)
        evidence.append(EvidenceItem("Anzahl Cookies", str(len(cookie_names))))
        if cookie_names:
            for name in cookie_names:
                evidence.append(EvidenceItem(f"Cookie: {name}", _classification_text(name)))
        else:
            evidence.append(EvidenceItem("Cookie", "—"))
    for label, capture_key in (("LocalStorage", "local_storage"), ("SessionStorage", "session_storage")):
        values = raw_capture.get(capture_key) or {}
        keys = sorted({str(key).strip() for key in values.keys() if str(key).strip()}, key=str.lower) if isinstance(values, dict) else []
        if keys:
            for key in keys:
                evidence.append(EvidenceItem(f"{label}: {key}", _classification_text(key)))
        else:
            evidence.append(EvidenceItem(label, "—"))
    return evidence


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
        evidence.append(EvidenceItem("Gemeinsamer Abschnitt", "Cookie- und Browser-Storage-Bewertung siehe Zusammenfassung vor der Kriterienbewertung."))
        if finding.criterion == "RDS-CUC-453":
            cuc_453 = raw_capture.get("rds_cuc_453") or {}
            if cuc_453.get("missing"):
                evidence.append(EvidenceItem("Fehlende Beschreibungen", ", ".join(cuc_453["missing"])))
    if finding.criterion == "RDS-CUC-373":
        requests = raw_capture.get("requests") or []
        scripts = raw_capture.get("scripts") or []
        evidence.append(EvidenceItem("Netzwerkanfragen", str(len(requests))))
        evidence.append(EvidenceItem("Skriptquellen", str(len(scripts))))
    if finding.criterion == "RDS-CUC-374":
        evidence.append(EvidenceItem("Gemeinsamer Abschnitt", "Cookie- und Browser-Storage-Bewertung siehe Zusammenfassung vor der Kriterienbewertung."))
    if finding.criterion in {"RDS-CUC-375", "RDS-CUC-376", "RDS-CUC-377"}:
        browser_signals = raw_capture.get("browser_signals") or {}
        device_storage = browser_signals.get("device_storage") or []
        fingerprinting = browser_signals.get("fingerprinting") or []
        if finding.criterion == "RDS-CUC-375":
            evidence.append(EvidenceItem("Device-/Browser-Storage-APIs", _api_signal_summary(device_storage)))
        if finding.criterion in {"RDS-CUC-376", "RDS-CUC-377"}:
            evidence.append(EvidenceItem("Fingerprinting-/Entropy-APIs", _api_signal_summary(fingerprinting)))
        if finding.criterion == "RDS-CUC-377":
            requests = raw_capture.get("requests") or []
            scripts = raw_capture.get("scripts") or []
            document_capture = raw_capture.get("document_capture") or {}
            evidence.append(EvidenceItem("Gemeinsamer Abschnitt", "Cookie- und Browser-Storage-Bewertung siehe Zusammenfassung vor der Kriterienbewertung."))
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
        _append_ipf_evidence(evidence, ipf, "impressum", "Impressum")
        visited = ipf.get("visited_urls") or []
        if visited:
            evidence.append(EvidenceItem("Besuchte IPF-URLs", ", ".join(str(url) for url in visited)))
    if finding.criterion in {"RDS-IPF-365", "RDS-IPF-367"}:
        ipf = raw_capture.get("ipf") or {}
        if ipf.get("privacy_url"):
            evidence.append(EvidenceItem("Datenschutzerklärung-URL", str(ipf["privacy_url"])))
        _append_ipf_evidence(evidence, ipf, "privacy", "Datenschutzerklärung")
        visited = ipf.get("visited_urls") or []
        if visited:
            evidence.append(EvidenceItem("Besuchte IPF-URLs", ", ".join(str(url) for url in visited)))
    if finding.criterion == "RDS-DSO-383":
        ipf = raw_capture.get("ipf") or {}
        if ipf.get("privacy_url"):
            evidence.append(EvidenceItem("Datenschutzerklärung-URL", str(ipf["privacy_url"])))
        _append_dso_383_evidence(evidence, ipf)
    _append_external_audit_evidence(evidence, raw_capture)
    _append_screenshot_evidence(evidence, raw_capture, finding.criterion)
    return evidence


def _append_ipf_evidence(evidence: list[EvidenceItem], ipf: dict[str, Any], key: str, label: str) -> None:
    found = ipf.get(f"{key}_found") or []
    missing = ipf.get(f"{key}_missing") or []
    manual = ipf.get(f"{key}_manual") or []
    if found:
        evidence.append(EvidenceItem(f"{label}: gefunden", "; ".join(str(item) for item in found)))
    if missing:
        evidence.append(EvidenceItem(f"{label}: fehlend", "; ".join(str(item) for item in missing)))
    if manual:
        evidence.append(EvidenceItem(f"{label}: manuell zu prüfen", "; ".join(str(item) for item in manual)))


def _append_dso_383_evidence(evidence: list[EvidenceItem], ipf: dict[str, Any]) -> None:
    found = [str(item) for item in ipf.get("privacy_found") or []]
    missing = [str(item) for item in ipf.get("privacy_missing") or []]
    dpo_found = next((item for item in found if "Datenschutzbeauftrag" in item or "Art. 13 Abs. 1 lit. b" in item), "")
    dpo_missing = next((item for item in missing if "Datenschutzbeauftrag" in item or "Art. 13 Abs. 1 lit. b" in item), "")
    if dpo_found:
        evidence.append(EvidenceItem("Datenschutzbeauftragter-Signal", dpo_found))
    elif dpo_missing:
        evidence.append(EvidenceItem("Datenschutzbeauftragter-Signal", f"fehlend: {dpo_missing}"))
    if ipf.get("privacy_dpo_absent_declared"):
        evidence.append(EvidenceItem("DSB-Negativangabe", "Datenschutzerklärung erklärt, dass kein Datenschutzbeauftragter benannt/bestellt ist."))
    evidence.append(
        EvidenceItem(
            "Gesetzliche Grundlage",
            "Art. 13 Abs. 1 lit. b DSGVO — Kontaktdaten des Datenschutzbeauftragten, falls vorhanden; https://dejure.org/gesetze/DSGVO/13.html",
        )
    )


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
