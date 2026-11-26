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
        return data


_SITE = ("target_url",)
_DOCS = ("document_paths | agb_url | privacy_url | avv_url",)

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
        requires=("target_url", "agent_username + agent_password (or VIDIS_AGENT_* on the server)"),
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
        description="Exportiert Netzwerk-, Konsolen- und Storage-Daten als JSON.",
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
    available = {"site": has_url, "agentic": has_url, "evidence": has_url, "code": has_code, "documents": has_documents}
    for check_id in sorted(selected):
        check = get_check(check_id)
        assert check is not None
        if not available[check.source]:
            raise ValueError(f"check {check_id} requires {' and '.join(check.requires)}")
    return frozenset(selected)


def criteria_for_checks(check_ids: frozenset[str] | set[str]) -> set[str]:
    return {code for check in CHECKS if check.id in check_ids for code in check.criteria}
