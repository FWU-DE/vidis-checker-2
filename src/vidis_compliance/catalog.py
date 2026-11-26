"""Catalog of the automated checks this platform can run.

Single source of truth for which check covers which VIDIS criterion and which
inputs it needs. The API discovery endpoint and the coverage matrix both read
from here, so they cannot drift apart.
"""

from __future__ import annotations

import shutil
from dataclasses import asdict, dataclass, field
from typing import Literal

from .sources.agentic import DEFAULT_AGENT_TASKS
from .sources.documents.analyze import DOCUMENT_CRITERIA

Source = Literal["site", "code", "documents", "agentic", "evidence"]


@dataclass(frozen=True)
class CheckDefinition:
    id: str
    name: str
    description: str
    source: Source
    requires: tuple[str, ...]
    criteria: tuple[str, ...] = ()
    enabled_by: str | None = None
    options: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["requires"] = list(self.requires)
        data["criteria"] = list(self.criteria)
        data["runs"] = "on request" if self.enabled_by else "automatically when the required inputs are present"
        data["outcomes"] = outcomes_for(self.id)
        data["evidence_keys"] = list(EVIDENCE_KEYS.get(self.id, ()))
        return data


_SITE = ("target_url",)
_DOCS = ("target_url (AGB, Datenschutzerklärung und AVV werden auf der Website gesucht) | agb_url | privacy_url | avv_url | document_paths",)

CHECKS: tuple[CheckDefinition, ...] = (
    CheckDefinition(
        id="site.cookies",
        name="Cookies",
        description="Klassifiziert gesetzte Cookies gegen die Open Cookie Database und die Zielgruppe.",
        source="site",
        requires=_SITE,
        criteria=("RDS-CUC-371", "RDS-CUC-372"),
    ),
    CheckDefinition(
        id="site.tracking_pixel",
        name="Trackingpixel",
        description="Erkennt Trackingpixel in Netzwerkanfragen und eingebundenen Ressourcen.",
        source="site",
        requires=_SITE,
        criteria=("RDS-CUC-373",),
    ),
    CheckDefinition(
        id="site.browser_storage",
        name="Local/Session Storage",
        description="Prüft Schlüssel im Local und Session Storage.",
        source="site",
        requires=_SITE,
        criteria=("RDS-CUC-374",),
    ),
    CheckDefinition(
        id="site.device_storage",
        name="Weitere Endgeräte-Speicher",
        description="Sammelt IndexedDB-, Cache-Storage- und Service-Worker-Zugriffe.",
        source="site",
        requires=_SITE,
        criteria=("RDS-CUC-375",),
    ),
    CheckDefinition(
        id="site.fingerprinting",
        name="Browserfingerprints",
        description="Erkennt Fingerprinting-APIs wie Canvas, WebGL und AudioContext.",
        source="site",
        requires=_SITE,
        criteria=("RDS-CUC-376",),
    ),
    CheckDefinition(
        id="site.tracking_mechanisms",
        name="Trackingmechanismen",
        description="Fasst Tracker-Signale zusammen; mit Produktdokumenten auch den pädagogischen Zweck.",
        source="site",
        requires=_SITE,
        criteria=("RDS-CUC-377",),
    ),
    CheckDefinition(
        id="site.cookie_descriptions",
        name="Cookie-Beschreibungen",
        description="Gleicht gefundene Cookies und Storage-Keys mit der Datenschutzerklärung ab.",
        source="site",
        requires=_SITE,
        criteria=("RDS-CUC-453",),
    ),
    CheckDefinition(
        id="site.advertising",
        name="Werbung",
        description="Erkennt Werbenetzwerke und Werbeflächen.",
        source="site",
        requires=_SITE,
        criteria=("RDS-WER-384",),
    ),
    CheckDefinition(
        id="site.outbound_ad_links",
        name="Externe Werbelinks",
        description="Erkennt Affiliate- und Werbelinks auf externe Angebote.",
        source="site",
        requires=_SITE,
        criteria=("RDS-WER-385",),
    ),
    CheckDefinition(
        id="site.youth_protection",
        name="Jugendmedienschutz",
        description="Sucht Hinweise auf jugendgefährdende Inhalte und Altersfreigaben.",
        source="site",
        requires=_SITE,
        criteria=("RDS-VIN-354",),
    ),
    CheckDefinition(
        id="site.transport",
        name="HTTPS und TLS",
        description="Prüft HTTPS-Erreichbarkeit, Weiterleitung von HTTP und die TLS-Konfiguration.",
        source="site",
        requires=_SITE,
        criteria=("ITS-ENC-359", "ITS-ENC-360", "ITS-ENC-361"),
    ),
    CheckDefinition(
        id="site.legal_pages",
        name="Impressum und Datenschutzerklärung",
        description="Findet Impressum und Datenschutzerklärung und prüft deren Pflichtangaben.",
        source="site",
        requires=_SITE,
        criteria=("RDS-IPF-364", "RDS-IPF-365", "RDS-IPF-366", "RDS-IPF-367"),
    ),
    CheckDefinition(
        id="code.inspection",
        name="Quellcode-Inspektion",
        description="Sucht im Quellcode nach Trackern, Storage-Zugriffen, CDNs, Rechtsseiten und Drittanbietern.",
        source="code",
        requires=("code_path",),
        criteria=(
            "RDS-CDN-379",
            "RDS-CUC-371",
            "RDS-CUC-372",
            "RDS-CUC-373",
            "RDS-CUC-374",
            "RDS-CUC-375",
            "RDS-CUC-376",
            "RDS-CUC-377",
            "RDS-DEV-380",
            "RDS-IPF-364",
            "RDS-IPF-365",
        ),
    ),
    CheckDefinition(
        id="documents.analysis",
        name="AGB, Datenschutz und AVV",
        description=(
            "Wertet AGB, Datenschutzerklärung und AVV aus; PASS nur bei ausdrücklichem Beleg. "
            "Mit einer URL zusätzlich Abgleich der gefundenen Cookies mit der Datenschutzerklärung."
        ),
        source="documents",
        requires=_DOCS,
        criteria=(*DOCUMENT_CRITERIA, "RDS-CUC-453"),
    ),
    CheckDefinition(
        id="agentic.persona_crawl",
        name="Angemeldeter Persona-Crawl",
        description=(
            "Meldet sich (optional über VIDIS) an und folgt Klickpfaden als Schüler oder Lehrkraft. "
            "Ergänzt die Website-Prüfungen um Belege aus dem angemeldeten Bereich."
        ),
        source="agentic",
        requires=("target_url", "agent_username + agent_password for logged-in areas (API: always per job)"),
        criteria=(
            "RDS-CUC-371",
            "RDS-CUC-372",
            "RDS-CUC-373",
            "RDS-CUC-374",
            "RDS-CUC-375",
            "RDS-CUC-376",
            "RDS-CUC-377",
            "RDS-CUC-453",
            "RDS-WER-384",
            "RDS-WER-385",
            "RDS-VIN-354",
            "RDS-IPF-364",
            "RDS-IPF-365",
            "RDS-IPF-366",
            "RDS-IPF-367",
            "RDS-DSO-383",
        ),
        enabled_by="agentic",
        options={"agent_tasks": list(DEFAULT_AGENT_TASKS)},
    ),
    CheckDefinition(
        id="evidence.lighthouse",
        name="Lighthouse-Audit",
        description="Legt einen Lighthouse-Bericht als zusätzliches Beweisstück ab.",
        source="evidence",
        requires=_SITE,
        enabled_by="lighthouse",
    ),
    CheckDefinition(
        id="evidence.webinspector",
        name="WebInspector-Export",
        description="Exportiert Netzwerk-, Konsolen- und Storage-Daten als JSON; abrufbar unter /jobs/<id>/artifacts/webinspector/network.json, console.json und storage.json.",
        source="evidence",
        requires=_SITE,
        enabled_by="webinspector_export",
    ),
)


def criteria_for_source(source: Source) -> set[str]:
    return {code for check in CHECKS if check.source == source for code in check.criteria}


def checks_for_criterion(code: str) -> list[str]:
    return [check.id for check in CHECKS if code in check.criteria]


def runtime_availability() -> dict[str, bool]:
    """Report optional tools that are installed where the service runs."""
    return {"evidence.lighthouse": shutil.which("lighthouse") is not None}


CHECK_IDS: tuple[str, ...] = tuple(check.id for check in CHECKS)

# Site checks that fetch their own pages and need no browser crawl.
CRAWL_FREE_SITE_CHECKS = frozenset({"site.transport", "site.legal_pages"})

# Checks that are switched on by a request flag rather than by an input alone.
FLAG_CHECKS = {
    "agentic": "agentic.persona_crawl",
    "lighthouse": "evidence.lighthouse",
    "webinspector_export": "evidence.webinspector",
}


def get_check(check_id: str) -> CheckDefinition | None:
    return next((check for check in CHECKS if check.id == check_id), None)


def resolve_check_selection(
    checks: list[str] | tuple[str, ...] | None,
    *,
    has_url: bool,
    has_code: bool,
    has_documents: bool,
    flags: dict[str, bool] | None = None,
) -> frozenset[str] | None:
    """Validate a requested subset of checks; ``None`` means run everything the inputs allow.

    Flags such as ``agentic`` add their check to an explicit selection, so
    ``checks=["site.cookies"], agentic=True`` checks cookies with a logged-in crawl.
    Raises ``ValueError`` for unknown checks or missing inputs.
    """
    if not checks:
        return None
    unknown = [check_id for check_id in checks if get_check(check_id) is None]
    if unknown:
        raise ValueError(f"unknown check(s): {', '.join(unknown)}; valid ids are listed at GET /discovery")
    selected = set(checks)
    for flag, check_id in FLAG_CHECKS.items():
        if (flags or {}).get(flag):
            selected.add(check_id)
    available = {"site": has_url, "agentic": has_url, "evidence": has_url, "code": has_code, "documents": has_documents or has_url}
    for check_id in sorted(selected):
        check = get_check(check_id)
        assert check is not None
        if not available[check.source]:
            raise ValueError(f"check {check_id} requires {' and '.join(check.requires)}")
    return frozenset(selected)


def criteria_for_checks(check_ids: frozenset[str] | set[str]) -> set[str]:
    return {code for check in CHECKS if check.id in check_ids for code in check.criteria}


# What each check can report: (status, reason, when). Kept next to the checks so
# /discovery, /checks and the manual describe exactly what the code returns.
_REVIEW = "needs_review"
OUTCOMES: dict[str, tuple[tuple[str, str, str], ...]] = {
    "site.cookies": (
        ("PASS", "automated", "Alle Cookies und Storage-Einträge sind laut Open Cookie Database oder Allowlist technisch notwendig."),
        ("FAIL", "automated", "Nicht notwendige Cookies bei Zielgruppe SuS oder beide."),
        ("MANUELL", _REVIEW, "Nicht notwendige Cookies bei Zielgruppe Lehrkräfte (Einwilligung?), unbekannte Cookies oder gar keine Cookies erkannt."),
    ),
    "site.tracking_pixel": (
        ("PASS", "automated", "Keine bekannten Tracker in den Anfragen."),
        ("FAIL", "automated", "Tracker erkannt bei Zielgruppe SuS oder beide."),
        ("MANUELL", _REVIEW, "Tracker erkannt bei Zielgruppe Lehrkräfte (Einwilligung?)."),
    ),
    "site.browser_storage": (
        ("PASS", "automated", "Kein Local/Session Storage, oder alle Schlüssel sind als notwendig bekannt."),
        ("FAIL", "automated", "Nicht notwendige Schlüssel bei Zielgruppe SuS oder beide."),
        ("MANUELL", _REVIEW, "Unbekannte Schlüssel, oder nicht notwendige bei Zielgruppe Lehrkräfte."),
    ),
    "site.device_storage": (
        ("PASS", "automated", "Keine oder nur technisch nötige Zugriffe auf IndexedDB, Cache Storage, Service Worker."),
        ("FAIL", "automated", "Tracking-Zugriffe bei Zielgruppe SuS oder beide."),
        ("MANUELL", _REVIEW, "Zweck der Zugriffe nicht bestimmbar, oder Tracking bei Zielgruppe Lehrkräfte."),
    ),
    "site.fingerprinting": (
        ("PASS", "automated", "Keine Fingerprinting-APIs (Canvas, WebGL, AudioContext …) aufgerufen."),
        ("MANUELL", _REVIEW, "Solche APIs wurden aufgerufen; ob zum Fingerprinting, muss ein Mensch beurteilen."),
    ),
    "site.tracking_mechanisms": (
        ("PASS", "automated", "Keine Trackingmechanismen, oder die Produktdokumente nennen einen pädagogischen Zweck."),
        ("FAIL", "automated", "Tracking ohne belegten pädagogischen Zweck bei Zielgruppe SuS oder beide."),
        ("MANUELL", _REVIEW, "Tracking bei Zielgruppe Lehrkräfte oder Zweck unklar."),
    ),
    "site.cookie_descriptions": (
        ("PASS", "automated", "Jedes gefundene Cookie und jeder Storage-Schlüssel steht in der Datenschutzerklärung."),
        ("FAIL", "automated", "Mindestens eines fehlt in der Datenschutzerklärung (in evidence.missing)."),
        ("MANUELL", _REVIEW, "Keine Cookies oder Storage-Einträge gefunden, also nichts abzugleichen."),
        ("MANUELL", "missing_input", "Keine Datenschutzerklärung gefunden oder mitgegeben (privacy_url)."),
    ),
    "site.advertising": (
        ("PASS", "automated", "Keine Werbenetzwerke, Anzeigen-Widgets oder Sponsoring-Hinweise."),
        ("FAIL", "automated", "Werbesignale erkannt."),
    ),
    "site.outbound_ad_links": (
        ("PASS", "automated", "Keine Affiliate- oder Werbelinks erkannt."),
        ("MANUELL", _REVIEW, "Mögliche Werbelinks; Ziel prüfen."),
    ),
    "site.youth_protection": (
        ("PASS", "automated", "Keine 18+-, Glücksspiel-, Gewalt- oder riskanten Embed-Signale."),
        ("FAIL", "automated", "Risikosignale erkannt."),
        ("MANUELL", _REVIEW, "Eingebettete Inhalte, die ein Mensch ansehen muss."),
    ),
    "site.transport": (
        ("PASS", "automated", "HTTPS erreichbar, HTTP leitet um oder ist zu, alte TLS-Versionen abgelehnt."),
        ("FAIL", "automated", "HTTP liefert Inhalte ohne Umleitung, HTTPS fehlt oder alte TLS-Versionen werden angenommen."),
        ("MANUELL", _REVIEW, "TLS-Versionen ließen sich nicht prüfen (ITS-ENC-361)."),
    ),
    "site.legal_pages": (
        ("PASS", "automated", "Impressum/Datenschutzerklärung gefunden, erreichbar und mit den Pflichtangaben."),
        ("FAIL", "automated", "Nicht gefunden, nicht erreichbar oder Pflichtangaben fehlen (in evidence.*_missing)."),
    ),
    "code.inspection": (
        ("PASS", "automated", "Keine einschlägigen Signale im Quellcode."),
        ("FAIL", "automated", "Einschlägige Signale gefunden, oder der Code-Pfad existiert nicht."),
        ("MANUELL", _REVIEW, "Signale gefunden, deren Zweck ein Mensch beurteilen muss."),
    ),
    "documents.analysis": (
        ("PASS", "automated", "Ausdrückliche Regelung im Dokument gefunden (Textstellen in evidence.snippets)."),
        ("FAIL", "automated", "Das Dokument widerspricht dem Kriterium."),
        ("MANUELL", _REVIEW, "Dokument gelesen, aber keine ausdrückliche Regelung gefunden."),
        ("MANUELL", "missing_input", "Keine AGB, Datenschutzerklärung oder AVV gefunden; URL mitgeben."),
    ),
    "agentic.persona_crawl": (
        ("PASS", "automated", "Belege aus dem angemeldeten Bereich bestätigen das Kriterium."),
        ("FAIL", "automated", "Belege aus dem angemeldeten Bereich widersprechen ihm."),
        ("MANUELL", _REVIEW, "Belege gesammelt, ein Mensch muss sie beurteilen."),
    ),
    "evidence.lighthouse": (),
    "evidence.webinspector": (),
}

# Keys that can appear in finding.evidence, per check.
EVIDENCE_KEYS: dict[str, tuple[str, ...]] = {
    "site.cookies": ("pages", "cookies"),
    "site.tracking_pixel": ("pages", "third_party_hosts", "requests"),
    "site.browser_storage": ("pages", "local_storage_keys", "session_storage_keys"),
    "site.device_storage": ("pages", "browser_signals"),
    "site.fingerprinting": ("pages", "browser_signals"),
    "site.tracking_mechanisms": ("pages", "third_party_hosts", "requests"),
    "site.cookie_descriptions": ("pages", "observed", "present", "missing"),
    "site.advertising": ("pages", "vision_reviews"),
    "site.outbound_ad_links": ("pages", "external_links", "vision_reviews"),
    "site.youth_protection": ("pages", "vision_reviews"),
    "site.transport": ("pages",),
    "site.legal_pages": ("impressum_url", "privacy_url", "impressum_found", "impressum_missing", "impressum_manual", "privacy_found", "privacy_missing", "privacy_manual", "privacy_dpo_absent_declared", "visited_urls"),
    "code.inspection": ("files_scanned",),
    "documents.analysis": ("documents", "snippets", "discovery", "skipped"),
    "agentic.persona_crawl": ("visited_urls",),
}

REASONS = {
    "automated": "PASS oder FAIL wurde automatisch entschieden.",
    "needs_review": "Die Prüfung lief, der Befund ist nicht eindeutig: ein Mensch entscheidet anhand von evidence, review_hint und artifacts.",
    "not_automated": "Für das Kriterium gibt es keine automatische Prüfung; es ist immer manuell zu bewerten.",
    "missing_input": "Eine Eingabe fehlte (etwa Dokument-URL oder Login), oder die zuständige Prüfung war nicht ausgewählt; die Notiz nennt was.",
    "not_reachable": "Eine Seite oder ein Dokument war nicht abrufbar.",
}


def outcomes_for(check_id: str) -> list[dict[str, str]]:
    return [{"status": status, "reason": reason, "when": when} for status, reason, when in OUTCOMES.get(check_id, ())]


# site.cookie_descriptions looks up the privacy policy itself, so this criterion
# does not need documents.analysis on top.
_DOCUMENTS_NOT_NEEDED = {"RDS-CUC-453"}


def checks_needed_for(code: str) -> dict[str, object]:
    """Which checks to call for one criterion when only the site URL is known.

    ``required``: call these (with ``target_url``) to get an automatic result.
    ``optional``: they add evidence but need another input (source code, login).
    """
    covering = [check for check in CHECKS if code in check.criteria]
    site = [check.id for check in covering if check.source == "site"]
    documents = [check.id for check in covering if check.source == "documents"]
    required = site + ([] if site and code in _DOCUMENTS_NOT_NEEDED else documents)
    optional = [
        {"check": check.id, "needs": list(check.requires)}
        for check in covering
        if check.id not in required and check.source in {"code", "agentic", "documents"}
    ]
    return {"required": required, "optional": optional}
