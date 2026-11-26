"""Make each finding self-explanatory for a reviewer or a test suite.

Every finding gets:

- ``reason``: ``automated`` for PASS/FAIL; for MANUELL whether a person has
  to judge collected evidence (``needs_review``), no automatic check exists
  (``not_automated``), an input is missing (``missing_input``) or a page or
  document could not be loaded (``not_reachable``);
- ``check``: the catalog check that produced it;
- ``evidence``: the data behind it, bounded in size;
- ``review_hint``: what to look at when it is MANUELL;
- ``artifacts``: names of the files with the full evidence.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from .catalog import CHECKS, get_check
from .models import CheckFinding

MAX_ITEMS = 50
MAX_TEXT = 300

NOT_AUTOMATED_NOTE = "Für dieses Kriterium gibt es keine automatische Prüfung; manuell bewerten."

# Site checks by criterion; the legal-pages check also reports the DPO criterion.
SITE_CHECK_FOR = {code: check.id for check in CHECKS if check.source == "site" for code in check.criteria}
SITE_CHECK_FOR.setdefault("RDS-DSO-383", "site.legal_pages")

REVIEW_HINTS = {
    "site.cookies": "Zweck der gelisteten Cookies klären: technisch notwendig oder Einwilligung nötig (Tracking, Statistik, Marketing)?",
    "site.tracking_pixel": "Anfragen an Drittanbieter auf Zählpixel oder Tracking-Endpunkte prüfen.",
    "site.browser_storage": "Zweck der Storage-Schlüssel klären: funktional oder Tracking/Profilbildung?",
    "site.device_storage": "Zugriffe auf IndexedDB, Cache Storage und Service Worker prüfen: Zweck und Inhalt.",
    "site.fingerprinting": "Aufrufe von Canvas, WebGL oder AudioContext prüfen: Darstellung der Seite oder Fingerprinting?",
    "site.tracking_mechanisms": "Drittanbieter und Tracker-Signale prüfen; mit der Datenschutzerklärung abgleichen, ob ein pädagogischer Zweck angegeben ist.",
    "site.cookie_descriptions": "Abgleichen, ob jedes gefundene Cookie und jeder Storage-Schlüssel in der Datenschutzerklärung beschrieben ist.",
    "site.advertising": "Screenshots und KI-Hinweise auf Werbung, Banner oder gesponserte Inhalte prüfen.",
    "site.outbound_ad_links": "Externe Links auf Werbe-, Shop- oder Affiliate-Ziele prüfen.",
    "site.youth_protection": "Screenshots und Inhalte auf jugendgefährdende Inhalte und Altersfreigaben prüfen.",
    "site.transport": "HTTPS-Erreichbarkeit, Weiterleitung von HTTP und TLS-Versionen prüfen.",
    "site.legal_pages": "Impressum und Datenschutzerklärung öffnen und die Pflichtangaben prüfen.",
    "documents.analysis": "Die gefundenen Textstellen im Dokument nachlesen; fehlt eine Regelung, gilt das Kriterium als nicht erfüllt.",
    "code.inspection": "Die gefundenen Stellen im Quellcode prüfen.",
    "agentic.persona_crawl": "Belege aus dem angemeldeten Bereich (Schritte, Screenshots auf dem Server) prüfen.",
}

VISION_CRITERIA_CHECKS = {"site.advertising", "site.outbound_ad_links", "site.youth_protection"}


def tag(findings: list[CheckFinding], check_id: str) -> list[CheckFinding]:
    """Set ``check`` on findings that do not have one yet."""
    for finding in findings:
        if finding.check is None:
            finding.check = check_id
    return findings


def tag_site(findings: list[CheckFinding]) -> None:
    for finding in findings:
        if finding.check is None and finding.criterion in SITE_CHECK_FOR:
            finding.check = SITE_CHECK_FOR[finding.criterion]


def placeholder(criterion: str, *, inputs: dict[str, bool]) -> CheckFinding:
    """MANUELL for a criterion no check of this run covered, saying why."""
    candidates = [
        check for check in CHECKS if criterion in check.criteria and check.source in {"site", "documents", "code"}
    ]
    if not candidates:
        return CheckFinding(criterion=criterion, status="MANUELL", note=NOT_AUTOMATED_NOTE, reason="not_automated",
                            review_hint="Kriterium anhand der VIDIS-Prüfkriterien manuell bewerten.")
    runnable = [check for check in candidates if inputs.get(check.source)]
    if runnable:
        names = ", ".join(check.id for check in runnable)
        note = f"In diesem Lauf nicht geprüft; dafür {names} mit derselben Eingabe aufrufen."
        hint = f"Prüfung {names} ausführen oder das Kriterium manuell bewerten."
    else:
        needs = "; ".join(f"{check.id}: {' / '.join(check.requires)}" for check in candidates)
        note = f"Für die automatische Prüfung fehlt eine Eingabe ({needs})."
        hint = "Fehlende Eingabe ergänzen oder das Kriterium manuell bewerten."
    return CheckFinding(criterion=criterion, status="MANUELL", note=note, reason="missing_input", review_hint=hint,
                        evidence={"checks": [check.id for check in candidates]})


def annotate(
    findings: list[CheckFinding],
    *,
    raw_capture: dict[str, Any] | None,
    document_capture: dict[str, Any] | None,
    code_capture: dict[str, Any] | None,
    agent_capture: dict[str, Any] | None,
) -> None:
    raw = raw_capture or {}
    for finding in findings:
        if finding.reason is None:
            finding.reason = "automated" if finding.status in {"PASS", "FAIL"} else _manual_reason(finding)
        if finding.check and not finding.evidence:
            finding.evidence = _evidence(finding, raw, document_capture or {}, code_capture or {}, agent_capture or {})
        if finding.status == "MANUELL" and finding.review_hint is None and finding.check:
            finding.review_hint = REVIEW_HINTS.get(finding.check)
        if finding.check and not finding.artifacts:
            finding.artifacts = _artifacts(finding.check, raw, document_capture, code_capture, agent_capture)


def _manual_reason(finding: CheckFinding) -> str:
    note = finding.note.casefold()
    if any(marker in note for marker in ("nicht erreichbar", "nicht abrufbar", "startseite http")):
        return "not_reachable"
    if "datenschutzerklärungstext fehlt" in note:
        return "missing_input"
    if finding.check is None:
        return "not_automated"
    return "needs_review"


def _evidence(finding: CheckFinding, raw: dict, documents: dict, code: dict, agent: dict) -> dict[str, Any]:
    check = finding.check or ""
    evidence: dict[str, Any] = {}
    if check.startswith("site."):
        pages = raw.get("visited_urls") or ([raw["url"]] if raw.get("url") else [])
        if pages:
            evidence["pages"] = _cap(pages)
    if check == "site.cookies":
        evidence["cookies"] = _cap(
            [{"name": c.get("name"), "domain": c.get("domain")} for c in raw.get("cookies") or [] if isinstance(c, dict)]
        )
    elif check == "site.browser_storage":
        evidence["local_storage_keys"] = _cap(sorted((raw.get("local_storage") or {}).keys()))
        evidence["session_storage_keys"] = _cap(sorted((raw.get("session_storage") or {}).keys()))
    elif check in {"site.device_storage", "site.fingerprinting"}:
        signals = raw.get("browser_signals") or {}
        evidence["browser_signals"] = {
            group: _cap(sorted({str(item.get("api") or item.get("name") or item) for item in items if item}))
            for group, items in signals.items()
            if isinstance(items, list) and items
        }
    elif check in {"site.tracking_pixel", "site.tracking_mechanisms"}:
        evidence["third_party_hosts"] = _third_party_hosts(raw)
        evidence["requests"] = len(raw.get("requests") or [])
    elif check == "site.cookie_descriptions":
        evidence.update({key: value for key, value in (raw.get("rds_cuc_453") or {}).items() if key != "privacy_text"})
    elif check == "site.outbound_ad_links":
        evidence["external_links"] = _external_links(raw)
    elif check == "site.legal_pages":
        ipf = raw.get("ipf") or {}
        evidence.update({key: value for key, value in ipf.items() if key != "agentic"})
    elif check == "documents.analysis":
        evidence["documents"] = [
            {"location": d.get("location"), "kind": d.get("kind")} for d in documents.get("documents") or [] if isinstance(d, dict)
        ]
        snippets = (documents.get("evidence") or {}).get(finding.criterion)
        if snippets:
            evidence["snippets"] = _cap([_text(s) for s in snippets], 5)
        if documents.get("discovery"):
            evidence["discovery"] = {k: documents["discovery"].get(k) for k in ("found", "missing")}
        if documents.get("skipped"):
            evidence["skipped"] = documents["skipped"]
    elif check == "code.inspection":
        evidence["files_scanned"] = code.get("files_scanned")
    elif check == "agentic.persona_crawl":
        evidence["visited_urls"] = _cap(agent.get("visited_urls") or [])
    if check in VISION_CRITERIA_CHECKS:
        reviews = [
            {"label": r.get("label"), "status": r.get("status"), "note": _text(r.get("note"))}
            for r in raw.get("vision_reviews") or []
            if isinstance(r, dict) and (not r.get("criterion_suggestions") or finding.criterion in r.get("criterion_suggestions"))
            and r.get("model")
        ]
        if reviews:
            evidence["vision_reviews"] = _cap(reviews, 8)
    return {key: value for key, value in evidence.items() if value not in (None, [], {})}


def _artifacts(check: str, raw: dict, documents: dict | None, code: dict | None, agent: dict | None) -> list[str]:
    names: list[str] = []
    source = (get_check(check).source if get_check(check) else "")
    if source == "site" and raw:
        names.append("capture.json")
        if check in VISION_CRITERIA_CHECKS:
            names.extend(
                f"screenshots/{shot['filename']}"
                for shot in raw.get("screenshots") or []
                if isinstance(shot, dict) and shot.get("filename") and not shot.get("authenticated") and not shot.get("local_only")
            )
    elif source == "documents" and documents is not None:
        names.append("document_capture.json")
    elif source == "code" and code is not None:
        names.append("code_capture.json")
    elif source == "agentic" and agent is not None:
        names.append("agent_capture.json")
    return names[:12]


def _third_party_hosts(raw: dict) -> list[str]:
    site = _host(raw.get("url") or "")
    hosts = {_host(str(url)) for url in raw.get("requests") or []}
    return _cap(sorted(host for host in hosts if host and site and not _same_site(host, site)))


def _external_links(raw: dict) -> list[str]:
    site = _host(raw.get("url") or "")
    links = []
    for link in raw.get("links") or []:
        href = str(link.get("href") if isinstance(link, dict) else link)
        host = _host(href)
        if host and site and not _same_site(host, site):
            links.append(href[:MAX_TEXT])
    return _cap(sorted(set(links)))


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _same_site(host: str, site: str) -> bool:
    strip = lambda h: h[4:] if h.startswith("www.") else h  # noqa: E731
    host, site = strip(host), strip(site)
    return host == site or host.endswith("." + site)


def _text(value: Any) -> str:
    return " ".join(str(value or "").split())[:MAX_TEXT]


def _cap(items: list, limit: int = MAX_ITEMS) -> list:
    return list(items)[:limit]
