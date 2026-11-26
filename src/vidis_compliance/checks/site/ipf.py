from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import urldefrag, urljoin, urlparse


from ...models import CheckFinding
from ...net import safe_get

MAX_PAGE_BYTES = 3 * 1024 * 1024

UserAgent = "vidis-compliance/0.1 (+https://fwu.de)"
DSO_383_SIGNAL = "Datenschutzbeauftragter-Kontakt, falls bestellt (Art. 13 Abs. 1 lit. b DSGVO)"
DSO_383_LEGAL_BASIS = "Art. 13 Abs. 1 lit. b DSGVO — Kontaktdaten des Datenschutzbeauftragten, falls vorhanden"
DSO_383_LEGAL_URL = "https://dejure.org/gesetze/DSGVO/13.html"
FetchResult = tuple[int, str]
Fetcher = Callable[[str], FetchResult]


@dataclass(frozen=True)
class LegalPageResult:
    kind: str
    url: str = ""
    reachable: bool = False
    status_code: int | None = None
    found_signals: list[str] = field(default_factory=list)
    missing_signals: list[str] = field(default_factory=list)
    manual_signals: list[str] = field(default_factory=list)
    dpo_absent_declared: bool = False
    error: str = ""


@dataclass(frozen=True)
class IpfSiteAnalysis:
    source_url: str
    visited_urls: list[str]
    impressum: LegalPageResult
    privacy: LegalPageResult


class _AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._href: str | None = None
        self._text_parts: list[str] = []
        self.anchors: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        for name, value in attrs:
            if name.lower() == "href" and value:
                self._href = value
                self._text_parts = []
                return

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._href is not None:
            self.anchors.append((self._href, " ".join(self._text_parts)))
            self._href = None
            self._text_parts = []


def _normalize_start_url(url: str) -> str:
    value = url.strip()
    if not re.match(r"^https?://", value, flags=re.I):
        value = "https://" + value
    return value


def _legal_url(base_url: str, href: str) -> str | None:
    href = href.strip()
    if not href:
        return None
    parsed = urlparse(href)
    if parsed.scheme.lower() in {"mailto", "tel", "javascript", "data"}:
        return None
    absolute, _fragment = urldefrag(urljoin(base_url, href))
    parsed_absolute = urlparse(absolute)
    if parsed_absolute.scheme not in {"http", "https"}:
        return None
    if _site_host(parsed_absolute.netloc) != _site_host(urlparse(base_url).netloc):
        return None
    return absolute


def _site_host(netloc: str) -> str:
    """Same site with and without ``www.``: www.example.org often redirects to example.org."""
    host = netloc.lower()
    return host[4:] if host.startswith("www.") else host


def _anchor_score(kind: str, text: str, href: str) -> int:
    haystack = f"{text} {href}".casefold()
    if kind == "impressum":
        strong = ["impressum", "imprint"]
        weak = ["anbieterkennzeichnung"]
    elif kind == "agb":
        strong = ["agb", "allgemeine geschäftsbedingungen", "allgemeine geschaeftsbedingungen", "nutzungsbedingungen", "terms of use", "terms of service", "terms and conditions"]
        weak = ["geschäftsbedingungen", "bedingungen", "terms"]
    elif kind == "avv":
        strong = ["auftragsverarbeitung", "auftragsverarbeitungsvertrag", "avv", "data processing agreement"]
        weak = ["auftragsdatenverarbeitung", "adv-vertrag"]
    else:
        strong = ["datenschutzerklärung", "datenschutzerklaerung", "privacy policy", "privacy"]
        weak = ["datenschutz", "data protection"]
    if any(term in haystack for term in strong):
        return 2
    if any(term in haystack for term in weak):
        return 1
    return 0


def discover_legal_links(base_url: str, html: str, kinds: tuple[str, ...] = ("impressum", "privacy")) -> dict[str, str]:
    """Return same-origin live-legal-page candidates discovered in homepage HTML."""
    parser = _AnchorParser()
    parser.feed(html)
    best: dict[str, tuple[int, str]] = {}
    for href, text in parser.anchors:
        url = _legal_url(base_url, href)
        if not url:
            continue
        for kind in kinds:
            score = _anchor_score(kind, text, href)
            if score and (kind not in best or (score, url) > best[kind]):
                best[kind] = (score, url)
    return {kind: url for kind, (_score, url) in best.items()}


DOCUMENT_KINDS = ("agb", "privacy", "avv")


def discover_document_links(url: str, *, fetch: Fetcher | None = None, wanted: tuple[str, ...] = DOCUMENT_KINDS) -> dict[str, object]:
    """Find AGB, privacy policy and AVV links on a site, for the document checks.

    Looks at the start page first, then at the legal pages found there
    (Impressum, privacy policy, AGB), because an AVV is often linked only
    from those. Same-site links only; at most five pages are fetched.
    """
    fetch = fetch or _default_fetch
    start_url = _normalize_start_url(url)
    found: dict[str, str] = {}
    searched: list[str] = []
    errors: list[str] = []
    queue = [start_url]
    while queue and len(searched) < 5 and any(kind not in found for kind in wanted):
        page_url = queue.pop(0)
        if page_url in searched:
            continue
        searched.append(page_url)
        try:
            status_code, html = fetch(page_url)
        except Exception as exc:
            errors.append(f"{page_url}: {type(exc).__name__}")
            continue
        if not (200 <= status_code < 400):
            errors.append(f"{page_url}: HTTP {status_code}")
            continue
        links = discover_legal_links(page_url, html, kinds=(*wanted, "impressum"))
        for kind in wanted:
            if kind not in found and links.get(kind):
                found[kind] = links[kind]
        if page_url == start_url:
            queue.extend(link for kind, link in links.items() if link not in queue)
    return {"found": found, "missing": [kind for kind in wanted if kind not in found], "searched": searched, "errors": errors}


def _default_fetch(url: str) -> FetchResult:
    response = safe_get(url, timeout=15, max_bytes=MAX_PAGE_BYTES, headers={"User-Agent": UserAgent})
    return response.status_code, response.text


def _page_text(html: str) -> str:
    without_scripts = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html)
    without_tags = re.sub(r"(?s)<[^>]+>", " ", without_scripts)
    return re.sub(r"\s+", " ", without_tags).strip().casefold()


def _has_email_or_phone(text: str) -> bool:
    return bool(re.search(r"[\w.+-]+@[\w.-]+\.[a-z]{2,}", text, flags=re.I)) or bool(
        re.search(r"(?:telefon|tel\.?|phone|fax)\s*[:\d/+() -]{5,}", text, flags=re.I)
    )


def _contains_any(text: str, terms: list[str]) -> bool:
    return any(term.casefold() in text for term in terms)


def _contains_regex(text: str, pattern: str) -> bool:
    return bool(re.search(pattern, text, flags=re.I | re.S))


def _declares_no_dpo(text: str) -> bool:
    return _contains_regex(
        text,
        r"(?:kein(?:e|en|er)?|nicht)\s+(?:datenschutzbeauftrag(?:ter|te|ten|tenstelle)?|dsb)\s+(?:benannt|bestellt|vorhanden|erforderlich)",
    ) or _contains_regex(
        text,
        r"(?:datenschutzbeauftrag(?:ter|te|ten)?|dsb)\s+(?:ist|wurde)\s+(?:nicht|kein(?:e|en|er)?)\s+(?:benannt|bestellt|erforderlich|vorhanden)",
    )


def _impressum_signals(text: str) -> dict[str, bool]:
    has_identity = _contains_any(text, ["diensteanbieter", "anbieter", "impressum", "gmbh", "ug", "ag", "e.v.", "inhaber"])
    has_address = bool(re.search(r"\b\d{5}\b", text)) or _contains_any(text, ["straße", "strasse", "platz", "weg", "allee", "anschrift", "sitz"])
    return {
        "Name und Anschrift (§ 5 Abs. 1 S. 1 DDG)": has_identity and has_address,
        "Rechtsform/Vertretungsberechtigte (§ 5 Abs. 1 S. 1 DDG)": _contains_any(
            text,
            ["gmbh", "ug", "ag", "e.v.", "rechtsform", "vertreten durch", "geschäftsführ", "geschaeftsfuehr", "vorstand", "inhaber"],
        ),
        "Kontaktangaben inkl. E-Mail (§ 5 Abs. 1 S. 2 DDG)": _has_email_or_phone(text) or _contains_any(text, ["kontakt", "e-mail", "email"]),
        "Registerangaben (§ 5 Abs. 1 S. 4 DDG)": _contains_regex(text, r"\b(?:hrb|hra|vr|pr)\s*\d+")
        or _contains_any(text, ["handelsregister", "vereinsregister", "partnerschaftsregister", "registergericht", "registernummer"]),
        "Steuer-ID/Wirtschafts-ID (§ 5 Abs. 1 S. 6 DDG)": _contains_any(
            text,
            ["umsatzsteuer-id", "ust-id", "ustid", "ust-idnr", "wirtschafts-identifikationsnummer", "wirtschafts-id", "steuer-id"],
        ),
        "Aktueller Rechtsverweis DDG statt TMG": "tmg" not in text and ("ddg" in text or "digitale-dienste-gesetz" in text or "digitale dienste gesetz" in text),
    }


def _impressum_manual_signals(text: str) -> list[str]:
    signals: list[str] = []
    if not _contains_any(text, ["aufsichtsbehörde", "aufsichtsbehoerde", "regulierungsbehörde", "regulierungsbehoerde", "zulassung"]):
        signals.append("Aufsichtsbehörde bei zulassungspflichtiger Tätigkeit (§ 5 Abs. 1 S. 3 DDG) — optional/manuell")
    if not _contains_any(text, ["audiovisueller mediendienst", "medienstaatsvertrag", "mstv", "sitzland", "landesmedienanstalt"]):
        signals.append("Audiovisuelle Mediendienste/Sitzland und Regulierungsbehörde (§ 5 Abs. 1 S. 8 DDG) — optional/manuell")
    return signals


def _privacy_signals(text: str) -> dict[str, bool]:
    return {
        "Name und Kontaktdaten des Verantwortlichen (Art. 13 Abs. 1 lit. a DSGVO)": _contains_any(text, ["verantwortlich", "controller", "anbieter", "betreiber"])
        and (_has_email_or_phone(text) or _contains_any(text, ["anschrift", "straße", "strasse", "kontakt"])),
        DSO_383_SIGNAL: _contains_any(
            text,
            ["datenschutzbeauftrag", "data protection officer", "datenschutz@", "dsb@"],
        ),
        "Verarbeitungszwecke (Art. 13 Abs. 1 lit. c DSGVO)": _contains_any(text, ["zweck", "purposes", "verarbeiten", "verarbeitung"]),
        "Rechtsgrundlagen (Art. 13 Abs. 1 lit. c DSGVO)": _contains_any(text, ["rechtsgrundlage", "art. 6", "artikel 6", "legitimate", "einwilligung"]),
        "Empfänger/Kategorien (Art. 13 Abs. 1 lit. e DSGVO)": _contains_any(text, ["empfänger", "recipient", "auftragsverarbeiter", "processor", "dritte"]),
        "Speicherdauer/Kriterien (Art. 13 Abs. 2 lit. a DSGVO)": _contains_any(text, ["speicherdauer", "löschung", "loeschung", "retention", "aufbewahrung"]),
        "Betroffenenrechte inkl. Beschwerde/Widerruf (Art. 13 Abs. 2 lit. b-d DSGVO)": _contains_any(
            text,
            ["betroffenenrechte", "auskunft", "berichtigung", "löschung", "loeschung", "widerspruch", "datenübertragbarkeit", "beschwerde", "widerruf"],
        ),
        "Bereitstellungspflicht/Folgen (Art. 13 Abs. 2 lit. e DSGVO)": _contains_any(
            text,
            ["bereitstellung", "vertraglich vorgeschrieben", "gesetzlich vorgeschrieben", "vertragsabschluss", "nichtbereitstellung", "ohne bereitstellung"],
        ),
        "Automatisierte Entscheidungsfindung/Profiling (Art. 13 Abs. 2 lit. f DSGVO)": _contains_any(
            text,
            ["automatisierte entscheidungsfindung", "profiling", "artikel 22", "art. 22", "keine automatisierte"],
        ),
    }


def _result_for_page(kind: str, url: str, fetch: Fetcher) -> LegalPageResult:
    try:
        status_code, html = fetch(url)
    except Exception as exc:
        return LegalPageResult(kind=kind, url=url, error=f"{type(exc).__name__}: {exc}")
    if not (200 <= status_code < 400):
        return LegalPageResult(kind=kind, url=url, status_code=status_code)

    text = _page_text(html)
    signals = _impressum_signals(text) if kind == "impressum" else _privacy_signals(text)
    found = [name for name, present in signals.items() if present]
    missing = [name for name, present in signals.items() if not present]
    manual = _impressum_manual_signals(text) if kind == "impressum" else []
    return LegalPageResult(
        kind=kind,
        url=url,
        reachable=True,
        status_code=status_code,
        found_signals=found,
        missing_signals=missing,
        manual_signals=manual,
        dpo_absent_declared=kind == "privacy" and _declares_no_dpo(text),
    )


def analyze_ipf_site(url: str, *, fetch: Fetcher = _default_fetch) -> IpfSiteAnalysis:
    start_url = _normalize_start_url(url)
    visited = [start_url]
    try:
        status_code, home_html = fetch(start_url)
    except Exception as exc:
        error = f"Startseite nicht abrufbar: {type(exc).__name__}: {exc}"
        missing_imp = LegalPageResult(kind="impressum", error=error)
        missing_privacy = LegalPageResult(kind="privacy", error=error)
        return IpfSiteAnalysis(start_url, visited, missing_imp, missing_privacy)

    if not (200 <= status_code < 400):
        error = f"Startseite HTTP {status_code}"
        return IpfSiteAnalysis(
            start_url,
            visited,
            LegalPageResult(kind="impressum", error=error),
            LegalPageResult(kind="privacy", error=error),
        )

    links = discover_legal_links(start_url, home_html)
    impressum_url = links.get("impressum", "")
    privacy_url = links.get("privacy", "")
    impressum = (
        _result_for_page("impressum", impressum_url, fetch)
        if impressum_url
        else LegalPageResult(kind="impressum", error="Kein Impressum-Link auf der Startseite gefunden")
    )
    privacy = (
        _result_for_page("privacy", privacy_url, fetch)
        if privacy_url
        else LegalPageResult(kind="privacy", error="Keine Datenschutzerklärung auf der Startseite gefunden")
    )
    for page_url in (impressum.url, privacy.url):
        if page_url and page_url not in visited:
            visited.append(page_url)
    return IpfSiteAnalysis(start_url, visited, impressum, privacy)


def _reachability_finding(criterion: str, label: str, page: LegalPageResult) -> CheckFinding:
    if page.reachable:
        return CheckFinding(criterion=criterion, status="PASS", note=f"{label} erreichbar: {page.url} (HTTP {page.status_code})")
    if page.url and page.status_code is not None:
        note = f"{label} nicht erreichbar: {page.url} (HTTP {page.status_code})"
    elif page.url and page.error:
        note = f"{label} nicht erreichbar: {page.url} ({page.error})"
    else:
        note = page.error or f"{label} nicht gefunden"
    return CheckFinding(criterion=criterion, status="FAIL", note=note)


def _completeness_finding(criterion: str, label: str, page: LegalPageResult) -> CheckFinding:
    if not page.reachable:
        return CheckFinding(criterion=criterion, status="FAIL", note=f"{label} nicht bewertbar: {page.error or page.url or 'nicht gefunden'}")
    if page.missing_signals:
        found = ", ".join(page.found_signals) or "keine Pflichtsignale"
        missing = ", ".join(page.missing_signals)
        note = f"{label} unvollständig: {page.url}; gefunden: {found}; fehlend: {missing}"
        if page.manual_signals:
            note += f"; manuell zu prüfen: {', '.join(page.manual_signals)}"
        return CheckFinding(
            criterion=criterion,
            status="FAIL",
            note=note,
        )
    manual = f"; manuell zu prüfen: {', '.join(page.manual_signals)}" if page.manual_signals else ""
    return CheckFinding(
        criterion=criterion,
        status="PASS",
        note=f"{label} vollständig wirkend: {page.url}; Signale: {', '.join(page.found_signals)}{manual}",
    )


def _dpo_finding(page: LegalPageResult) -> CheckFinding:
    if not page.reachable:
        return CheckFinding(
            criterion="RDS-DSO-383",
            status="MANUELL",
            note=f"Datenschutzbeauftragter nicht bewertbar: {page.error or page.url or 'Datenschutzerklärung nicht gefunden'}; Herleitung: {DSO_383_LEGAL_BASIS}; Gesetz: {DSO_383_LEGAL_URL}",
        )
    if page.dpo_absent_declared:
        return CheckFinding(
            criterion="RDS-DSO-383",
            status="FAIL",
            note=f"Datenschutzerklärung erklärt, dass kein Datenschutzbeauftragter benannt/bestellt ist: {page.url}; Herleitung: {DSO_383_LEGAL_BASIS}; Gesetz: {DSO_383_LEGAL_URL}",
        )
    if DSO_383_SIGNAL in page.found_signals:
        return CheckFinding(
            criterion="RDS-DSO-383",
            status="PASS",
            note=f"Datenschutzbeauftragter-Kontakt gefunden: {page.url}; Herleitung: {DSO_383_LEGAL_BASIS}; Gesetz: {DSO_383_LEGAL_URL}",
        )
    return CheckFinding(
        criterion="RDS-DSO-383",
        status="MANUELL",
        note=f"Kein eindeutig benannter Datenschutzbeauftragter mit Kontakt gefunden: {page.url}; Herleitung: {DSO_383_LEGAL_BASIS}; Gesetz: {DSO_383_LEGAL_URL}",
    )


def findings_from_ipf_analysis(analysis: IpfSiteAnalysis) -> list[CheckFinding]:
    return [
        _reachability_finding("RDS-IPF-364", "Impressum", analysis.impressum),
        _reachability_finding("RDS-IPF-365", "Datenschutzerklärung", analysis.privacy),
        _completeness_finding("RDS-IPF-366", "Impressum", analysis.impressum),
        _completeness_finding("RDS-IPF-367", "Datenschutzerklärung", analysis.privacy),
        _dpo_finding(analysis.privacy),
    ]


def check_links_present(url: str) -> tuple[bool, bool, str, str]:
    """Backward-compatible wrapper for older callers."""
    analysis = analyze_ipf_site(url)
    return (
        analysis.impressum.reachable,
        analysis.privacy.reachable,
        analysis.impressum.url,
        analysis.privacy.url,
    )
