from __future__ import annotations

import html
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

import httpx
from bs4 import BeautifulSoup

from ...models import CheckFinding, Status

DOCUMENT_CRITERIA = (
    "RDS-DEV-380",
    "RDS-DEV-381",
    "RDS-DEV-466",
    "RDS-DSO-383",
    "RDS-AGB-368",
    "RDS-AGB-369",
)


@dataclass(frozen=True)
class DocumentInput:
    location: str
    kind: str = "document"


@dataclass(frozen=True)
class DocumentEvidence:
    location: str
    kind: str
    content_type: str
    text_length: int
    snippets: dict[str, list[str]]


@dataclass(frozen=True)
class EvidenceRule:
    pass_patterns: tuple[str, ...]
    fail_patterns: tuple[str, ...]
    gap_note: str


RULES: dict[str, EvidenceRule] = {
    "RDS-DEV-380": EvidenceRule(
        pass_patterns=(
            r"personenbezogene\s+daten.{0,120}(verarbeit|erheb|dsgvo|zweck)",
            r"(verarbeit|erheb).{0,120}personenbezogene\s+daten",
            r"datenschutzerkl(?:ä|ae)rung",
        ),
        fail_patterns=(
            r"personenbezogene\s+daten.{0,80}ohne\s+(?:zweck|rechtsgrundlage|einwilligung)",
        ),
        gap_note="Keine belastbare Beschreibung der Datenerhebung und -verarbeitung gefunden.",
    ),
    "RDS-DEV-381": EvidenceRule(
        pass_patterns=(
            r"(?:vertragsende|beendigung|ende\s+der\s+(?:zusammenarbeit|laufzeit)).{0,160}(?:gelöscht|geloescht|zurückgegeben|zurueckgegeben|rückgabe|rueckgabe)",
            r"(?:gelöscht|geloescht|zurückgegeben|zurueckgegeben|rückgabe|rueckgabe).{0,160}(?:vertragsende|beendigung|ende\s+der\s+(?:zusammenarbeit|laufzeit))",
        ),
        fail_patterns=(
            r"(?:vertragsende|beendigung).{0,120}(?:dauerhaft|unbegrenzt|nicht\s+gelöscht|nicht\s+geloescht)",
        ),
        gap_note="Keine explizite Regelung zu Löschung oder Rückgabe nach Vertragsende gefunden.",
    ),
    "RDS-DEV-466": EvidenceRule(
        pass_patterns=(
            r"(?:technische\s+und\s+organisatorische\s+ma(?:ß|ss)nahmen|\bTOMs?\b).{0,220}(?:verschlüsselung|verschluesselung|zugriffskontrolle|sicher)",
            r"(?:verschlüsselung|verschluesselung|zugriffskontrolle).{0,220}(?:technische\s+und\s+organisatorische\s+ma(?:ß|ss)nahmen|\bTOMs?\b|sichere\s+datenverarbeitung)",
            r"sichere\s+datenverarbeitung",
        ),
        fail_patterns=(
            r"keine\s+(?:technischen\s+und\s+organisatorischen\s+ma(?:ß|ss)nahmen|\bTOMs?\b|verschlüsselung|verschluesselung)",
        ),
        gap_note="Keine ausreichenden Angaben zu TOMs oder sicherer Verarbeitung gefunden.",
    ),
    "RDS-DSO-383": EvidenceRule(
        pass_patterns=(
            r"datenschutzbeauftrag(?:te|ter|ten|r).{0,180}[\w.+-]+@[\w.-]+\.[a-z]{2,}",
            r"[\w.+-]+@[\w.-]+\.[a-z]{2,}.{0,180}datenschutzbeauftrag(?:te|ter|ten|r)",
            r"\bdsb\b.{0,120}[\w.+-]+@[\w.-]+\.[a-z]{2,}",
        ),
        fail_patterns=(
            r"kein\s+datenschutzbeauftrag(?:ter|te|ten|r)\s+benannt",
        ),
        gap_note="Kein eindeutig benannter Datenschutzbeauftragter mit Kontakt gefunden.",
    ),
    "RDS-AGB-368": EvidenceRule(
        pass_patterns=(
            r"(?:datenschutzerkl(?:ä|ae)rung|datenschutz).{0,180}(?:dsgvo|personenbezogene\s+daten|rechtsgrundlage)",
            r"(?:dsgvo|personenbezogene\s+daten|rechtsgrundlage).{0,180}(?:datenschutzerkl(?:ä|ae)rung|datenschutz)",
        ),
        fail_patterns=(
            r"agb.{0,120}(?:abweichend\s+von\s+der\s+datenschutzerkl(?:ä|ae)rung|widerspricht\s+der\s+datenschutzerkl(?:ä|ae)rung)",
        ),
        gap_note="Keine hinreichenden Hinweise auf Datenschutzkonformität von AGB/Datenschutzhinweisen gefunden.",
    ),
    "RDS-AGB-369": EvidenceRule(
        pass_patterns=(
            r"(?:auftragsverarbeitungsvertrag|\bavv\b|art\.?\s*28\s+dsgvo)",
            r"auftragnehmer.{0,180}auftraggeber",
        ),
        fail_patterns=(
            r"(?:kein|ohne)\s+(?:auftragsverarbeitungsvertrag|\bavv\b)",
        ),
        gap_note="Kein eindeutiger AVV-/Art.-28-DSGVO-Nachweis gefunden.",
    ),
}


def build_document_inputs(
    documents: Iterable[Path | str] = (),
    agb_url: str | None = None,
    privacy_url: str | None = None,
    avv_url: str | None = None,
) -> list[DocumentInput]:
    inputs = [DocumentInput(location=str(path), kind="document") for path in documents]
    if agb_url:
        inputs.append(DocumentInput(location=agb_url, kind="agb"))
    if privacy_url:
        inputs.append(DocumentInput(location=privacy_url, kind="privacy"))
    if avv_url:
        inputs.append(DocumentInput(location=avv_url, kind="avv"))
    return inputs


def fetch_document(document: DocumentInput | str | Path) -> tuple[bytes, str, str, str]:
    if isinstance(document, DocumentInput):
        location = document.location
        kind = document.kind
    else:
        location = str(document)
        kind = "document"
    if re.match(r"https?://", location):
        response = httpx.get(location, timeout=20, follow_redirects=True)
        response.raise_for_status()
        content_type = response.headers.get("content-type", "")
        return response.content, content_type, location, kind
    path = Path(location)
    suffix = path.suffix.lower()
    content_type = {
        ".html": "text/html",
        ".htm": "text/html",
        ".txt": "text/plain",
        ".md": "text/markdown",
        ".pdf": "application/pdf",
    }.get(suffix, "text/plain")
    return path.read_bytes(), content_type, str(path), kind


def extract_text(content: bytes, content_type: str = "", location: str = "") -> str:
    lowered_type = content_type.lower()
    lowered_location = location.lower()
    if "pdf" in lowered_type or lowered_location.endswith(".pdf"):
        parsed = _extract_pdf_text_with_pypdf(content)
        return parsed or _extract_pdf_literal_strings(content)
    decoded = _decode_bytes(content)
    if "html" in lowered_type or lowered_location.endswith((".html", ".htm")):
        soup = BeautifulSoup(decoded, "html.parser")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        return _normalize_text(soup.get_text(" "))
    return _normalize_text(decoded)


def analyze_documents(documents: Iterable[DocumentInput | str | Path]) -> tuple[list[CheckFinding], dict]:
    evidence_items: list[DocumentEvidence] = []
    all_text = ""
    for document in documents:
        content, content_type, location, kind = fetch_document(document)
        text = extract_text(content, content_type=content_type, location=location)
        snippets = {code: _matching_snippets(text, RULES[code].pass_patterns + RULES[code].fail_patterns) for code in DOCUMENT_CRITERIA}
        evidence_items.append(
            DocumentEvidence(
                location=location,
                kind=kind,
                content_type=content_type,
                text_length=len(text),
                snippets={code: values for code, values in snippets.items() if values},
            )
        )
        all_text = f"{all_text}\n{text}"

    findings = [_classify_criterion(code, all_text) for code in DOCUMENT_CRITERIA]
    capture = {
        "documents": [asdict(item) for item in evidence_items],
        "evidence": {code: _matching_snippets(all_text, RULES[code].pass_patterns + RULES[code].fail_patterns) for code in DOCUMENT_CRITERIA},
    }
    return findings, capture


def _classify_criterion(code: str, text: str) -> CheckFinding:
    rule = RULES[code]
    fail_snippets = _matching_snippets(text, rule.fail_patterns)
    if fail_snippets:
        return CheckFinding(criterion=code, status="FAIL", note=_note("Widerspruch gefunden", fail_snippets))
    pass_snippets = _matching_snippets(text, rule.pass_patterns)
    if pass_snippets:
        return CheckFinding(criterion=code, status="PASS", note=_note("Explizite Dokument-Evidenz", pass_snippets))
    return CheckFinding(criterion=code, status="MANUELL", note=rule.gap_note)


def _matching_snippets(text: str, patterns: Iterable[str]) -> list[str]:
    snippets: list[str] = []
    for pattern in patterns:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE | re.DOTALL):
            snippets.append(_snippet(text, match.start(), match.end()))
            if len(snippets) >= 5:
                return snippets
    return snippets


def _snippet(text: str, start: int, end: int) -> str:
    prefix = max(0, start - 70)
    suffix = min(len(text), end + 70)
    return _normalize_text(text[prefix:suffix])


def _note(prefix: str, snippets: list[str]) -> str:
    return f"{prefix}: " + " | ".join(snippets[:3])


def _decode_bytes(content: bytes) -> str:
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return content.decode(encoding)
        except UnicodeDecodeError:
            continue
    return content.decode("utf-8", errors="ignore")


def _normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def _extract_pdf_text_with_pypdf(content: bytes) -> str:
    try:
        from pypdf import PdfReader  # type: ignore[import-not-found]
    except Exception:
        return ""
    try:
        import io

        reader = PdfReader(io.BytesIO(content))
        return _normalize_text("\n".join(page.extract_text() or "" for page in reader.pages))
    except Exception:
        return ""


def _extract_pdf_literal_strings(content: bytes) -> str:
    decoded = content.decode("latin-1", errors="ignore")
    literals = []
    for match in re.finditer(r"\((.*?)\)", decoded, flags=re.DOTALL):
        literal = match.group(1)
        literal = literal.replace(r"\(", "(").replace(r"\)", ")").replace(r"\\", "\\")
        literals.append(literal)
    return _normalize_text(" ".join(literals) or decoded)
