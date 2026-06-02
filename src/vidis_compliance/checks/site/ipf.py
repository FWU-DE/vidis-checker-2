from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import urldefrag, urljoin, urlparse

import httpx

from ...models import CheckFinding

UserAgent = "vidis-compliance/0.1 (+https://fwu.de)"
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
    if parsed_absolute.netloc != urlparse(base_url).netloc:
        return None
    return absolute


def _anchor_score(kind: str, text: str, href: str) -> int:
    haystack = f"{text} {href}".casefold()
    if kind == "impressum":
        strong = ["impressum", "imprint"]
        weak = ["anbieterkennzeichnung"]
    else:
        strong = ["datenschutzerklärung", "datenschutzerklaerung", "privacy policy", "privacy"]
        weak = ["datenschutz", "data protection"]
    if any(term in haystack for term in strong):
        return 2
    if any(term in haystack for term in weak):
        return 1
    return 0


def discover_legal_links(base_url: str, html: str) -> dict[str, str]:
    """Return same-origin live-legal-page candidates discovered in homepage HTML."""
    parser = _AnchorParser()
    parser.feed(html)
    best: dict[str, tuple[int, str]] = {}
    for href, text in parser.anchors:
        url = _legal_url(base_url, href)
        if not url:
            continue
        for kind in ("impressum", "privacy"):
            score = _anchor_score(kind, text, href)
            if score and (kind not in best or (score, url) > best[kind]):
                best[kind] = (score, url)
    return {kind: url for kind, (_score, url) in best.items()}


def _default_fetch(url: str) -> FetchResult:
    with httpx.Client(timeout=15, headers={"User-Agent": UserAgent}) as client:
        response = client.get(url, follow_redirects=True)
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


def _impressum_signals(text: str) -> dict[str, bool]:
    return {
        "Anbieter/Identität": _contains_any(
            text,
            ["diensteanbieter", "anbieter", "vertreten durch", "gmbh", "ug", "ag", "e.v.", "inhaber"],
        ),
        "Anschrift": bool(re.search(r"\b\d{5}\b", text))
        or _contains_any(text, ["straße", "strasse", "platz", "weg", "allee", "anschrift", "sitz"]),
        "Kontakt": _has_email_or_phone(text) or _contains_any(text, ["kontakt", "e-mail", "email"]),
    }


def _privacy_signals(text: str) -> dict[str, bool]:
    return {
        "Verantwortlicher": _contains_any(text, ["verantwortlich", "controller", "anbieter", "betreiber"]),
        "DSB/Kontakt": _contains_any(
            text,
            ["datenschutzbeauftrag", "data protection officer", "datenschutz@", "dsb@"],
        )
        or _has_email_or_phone(text),
        "Zwecke": _contains_any(text, ["zweck", "purposes", "verarbeiten", "verarbeitung"]),
        "Rechtsgrundlagen": _contains_any(text, ["rechtsgrundlage", "art. 6", "artikel 6", "legitimate", "einwilligung"]),
        "Empfänger": _contains_any(text, ["empfänger", "recipient", "auftragsverarbeiter", "processor", "dritte"]),
        "Speicherdauer": _contains_any(text, ["speicherdauer", "löschung", "loeschung", "retention", "aufbewahrung"]),
        "Betroffenenrechte": _contains_any(
            text,
            ["betroffenenrechte", "auskunft", "berichtigung", "löschung", "loeschung", "widerspruch", "datenübertragbarkeit"],
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
    return LegalPageResult(
        kind=kind,
        url=url,
        reachable=True,
        status_code=status_code,
        found_signals=found,
        missing_signals=missing,
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
        return CheckFinding(
            criterion=criterion,
            status="FAIL",
            note=f"{label} unvollständig: {page.url}; gefunden: {found}; fehlend: {missing}",
        )
    return CheckFinding(
        criterion=criterion,
        status="PASS",
        note=f"{label} vollständig wirkend: {page.url}; Signale: {', '.join(page.found_signals)}",
    )


def findings_from_ipf_analysis(analysis: IpfSiteAnalysis) -> list[CheckFinding]:
    return [
        _reachability_finding("RDS-IPF-364", "Impressum", analysis.impressum),
        _reachability_finding("RDS-IPF-365", "Datenschutzerklärung", analysis.privacy),
        _completeness_finding("RDS-IPF-366", "Impressum", analysis.impressum),
        _completeness_finding("RDS-IPF-367", "Datenschutzerklärung", analysis.privacy),
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
