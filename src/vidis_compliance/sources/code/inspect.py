from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from vidis_compliance.checks.site.cookies import _is_sus_audience
from vidis_compliance.models import CheckFinding

TEXT_EXTENSIONS = {
    ".astro",
    ".css",
    ".ejs",
    ".go",
    ".hbs",
    ".html",
    ".htm",
    ".jinja",
    ".jinja2",
    ".js",
    ".jsx",
    ".md",
    ".mjs",
    ".php",
    ".py",
    ".rb",
    ".svelte",
    ".ts",
    ".tsx",
    ".twig",
    ".vue",
}

SKIP_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "vendor",
}

TRACKING_PATTERNS = {
    "Google Tag Manager": "googletagmanager.com",
    "Google Analytics": "google-analytics.com",
    "Google gtag": "gtag(",
    "Facebook Pixel": "connect.facebook.net",
    "Hotjar": "hotjar.com",
    "Segment": "cdn.segment.com",
    "Mixpanel": "mixpanel",
    "Matomo/Piwik": "matomo",
    "Microsoft Clarity": "clarity.ms",
    "Plausible": "plausible.io/js",
}

EXTERNAL_URL_RE = re.compile(r"https?://[^\s'\"<>)+]+", re.IGNORECASE)
SCRIPT_SRC_RE = re.compile(r"<script\b[^>]*\bsrc=[\"']([^\"']+)[\"']", re.IGNORECASE)
PRIVACY_RE = re.compile(r"(datenschutz|privacy|privacy-policy|privacypolicy|dse)", re.IGNORECASE)
IMPRESSUM_RE = re.compile(r"(impressum|legal notice|anbieterkennzeichnung)", re.IGNORECASE)
COOKIE_RE = re.compile(r"(document\.cookie|setCookie\s*\(|cookies?\.set\s*\(|response\.set_cookie\s*\()", re.IGNORECASE)
LOCAL_STORAGE_RE = re.compile(r"\b(localStorage|sessionStorage)\b", re.IGNORECASE)
DEVICE_STORAGE_PATTERNS = {
    "indexedDB.open": "indexedDB.open",
    "caches.open": "caches.open",
    "serviceWorker.register": "serviceWorker.register",
}
FINGERPRINTING_PATTERNS = {
    "canvas.toDataURL": "toDataURL",
    "canvas.getContext": "getContext('2d'",
    "WebGLRenderingContext.getParameter": "getParameter",
    "AudioContext": "AudioContext",
    "navigator.mediaDevices.enumerateDevices": "enumerateDevices",
    "navigator.hardwareConcurrency": "hardwareConcurrency",
    "navigator.userAgentData.getHighEntropyValues": "getHighEntropyValues",
}
FINGERPRINTING_LIBRARY_PATTERNS = {
    "FingerprintJS": "fingerprintjs",
    "ClientJS": "clientjs",
    "ThumbmarkJS": "thumbmarkjs",
    "CreepJS": "creepjs",
}


@dataclass
class CodeEvidence:
    file: str
    line: int
    value: str


@dataclass
class CodeInspection:
    files_scanned: int = 0
    privacy_links: list[CodeEvidence] = field(default_factory=list)
    impressum_links: list[CodeEvidence] = field(default_factory=list)
    tracking: list[CodeEvidence] = field(default_factory=list)
    storage: list[CodeEvidence] = field(default_factory=list)
    cookies: list[CodeEvidence] = field(default_factory=list)
    external_scripts: list[CodeEvidence] = field(default_factory=list)
    device_storage: list[CodeEvidence] = field(default_factory=list)
    fingerprinting: list[CodeEvidence] = field(default_factory=list)
    fingerprinting_libraries: list[CodeEvidence] = field(default_factory=list)


def inspect_code_path(path: str | Path, audience: str = "beide") -> tuple[list[CheckFinding], dict]:
    """Scan a source tree for deterministic VIDIS-relevant frontend signals."""
    root = Path(path).expanduser().resolve()
    if not root.exists():
        return [CheckFinding(criterion="RDS-DEV-380", status="FAIL", note=f"Code-Pfad existiert nicht: {root}")], {
            "root": str(root),
            "files_scanned": 0,
            "signals": _inspection_to_dict(CodeInspection()),
        }

    inspection = CodeInspection()
    for file_path in _iter_source_files(root):
        inspection.files_scanned += 1
        rel_path = str(file_path.relative_to(root))
        for line_no, line in enumerate(_read_lines(file_path), start=1):
            _collect_line_signals(inspection, rel_path, line_no, line)

    findings = _findings_from_inspection(inspection, audience)
    capture = {
        "root": str(root),
        "files_scanned": inspection.files_scanned,
        "signals": _inspection_to_dict(inspection),
    }
    return findings, capture


def _iter_source_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        if _is_scannable_file(root):
            yield root
        return

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if _is_scannable_file(path):
            yield path


def _is_scannable_file(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTENSIONS and path.stat().st_size <= 512_000


def _read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []


def _collect_line_signals(inspection: CodeInspection, rel_path: str, line_no: int, line: str) -> None:
    lowered = line.lower()
    if PRIVACY_RE.search(line):
        inspection.privacy_links.append(CodeEvidence(rel_path, line_no, _compact(line)))
    if IMPRESSUM_RE.search(line):
        inspection.impressum_links.append(CodeEvidence(rel_path, line_no, _compact(line)))

    for label, needle in TRACKING_PATTERNS.items():
        if needle.lower() in lowered:
            inspection.tracking.append(CodeEvidence(rel_path, line_no, f"{label}: {_compact(line)}"))

    if LOCAL_STORAGE_RE.search(line):
        inspection.storage.append(CodeEvidence(rel_path, line_no, _compact(line)))
    for label, needle in DEVICE_STORAGE_PATTERNS.items():
        if needle.lower() in lowered:
            inspection.device_storage.append(CodeEvidence(rel_path, line_no, f"{label}: {_compact(line)}"))
    for label, needle in FINGERPRINTING_PATTERNS.items():
        if needle.lower() in lowered:
            inspection.fingerprinting.append(CodeEvidence(rel_path, line_no, f"{label}: {_compact(line)}"))
    for label, needle in FINGERPRINTING_LIBRARY_PATTERNS.items():
        if needle.lower() in lowered:
            evidence = CodeEvidence(rel_path, line_no, f"{label}: {_compact(line)}")
            inspection.fingerprinting_libraries.append(evidence)
            inspection.fingerprinting.append(evidence)
    if COOKIE_RE.search(line):
        inspection.cookies.append(CodeEvidence(rel_path, line_no, _compact(line)))

    for script_src in SCRIPT_SRC_RE.findall(line):
        if script_src.startswith("http://") or script_src.startswith("https://"):
            inspection.external_scripts.append(CodeEvidence(rel_path, line_no, script_src))
    for url in EXTERNAL_URL_RE.findall(line):
        if _looks_like_script_asset(url):
            inspection.external_scripts.append(CodeEvidence(rel_path, line_no, url))


def _findings_from_inspection(inspection: CodeInspection, audience: str) -> list[CheckFinding]:
    tracking_status = "FAIL" if inspection.tracking and _is_sus_audience(audience) else "MANUELL"
    storage_status = "FAIL" if inspection.storage and _is_sus_audience(audience) else "MANUELL"

    findings = [
        CheckFinding(
            criterion="RDS-IPF-364",
            status="PASS" if inspection.impressum_links else "MANUELL",
            note=_evidence_note("Impressum-Hinweise im Quellcode", inspection.impressum_links)
            if inspection.impressum_links
            else "Kein Impressum-Hinweis im Quellcode gefunden",
        ),
        CheckFinding(
            criterion="RDS-IPF-365",
            status="PASS" if inspection.privacy_links else "MANUELL",
            note=_evidence_note("Datenschutz-Hinweise im Quellcode", inspection.privacy_links)
            if inspection.privacy_links
            else "Keine Datenschutzerklärung im Quellcode gefunden",
        ),
        CheckFinding(
            criterion="RDS-CUC-373",
            status=tracking_status if inspection.tracking else "PASS",
            note=_evidence_note("Tracking-/Analytics-SDKs im Quellcode", inspection.tracking)
            if inspection.tracking
            else "Keine offensichtlichen Tracking-/Analytics-SDKs im Quellcode gefunden",
        ),
        CheckFinding(
            criterion="RDS-CUC-374",
            status=storage_status if inspection.storage else "MANUELL",
            note=_evidence_note("localStorage/sessionStorage-Nutzung im Quellcode", inspection.storage)
            if inspection.storage
            else "Keine localStorage/sessionStorage-Nutzung im Quellcode gefunden",
        ),
        CheckFinding(
            criterion="RDS-CUC-375",
            status="MANUELL" if inspection.device_storage else "PASS",
            note=_evidence_note("Device-/Browser-Storage-APIs im Quellcode", inspection.device_storage)
            if inspection.device_storage
            else "Keine IndexedDB/Cache/Service-Worker-Storage-Nutzung im Quellcode gefunden",
        ),
        CheckFinding(
            criterion="RDS-CUC-376",
            status="FAIL" if inspection.fingerprinting_libraries and _is_sus_audience(audience) else ("MANUELL" if inspection.fingerprinting else "PASS"),
            note=_evidence_note("Browserfingerprinting-Signale im Quellcode", inspection.fingerprinting)
            if inspection.fingerprinting
            else "Keine Browserfingerprinting-Signale im Quellcode gefunden",
        ),
        CheckFinding(
            criterion="RDS-CUC-377",
            status="FAIL" if inspection.fingerprinting_libraries and _is_sus_audience(audience) else ("MANUELL" if inspection.fingerprinting else "PASS"),
            note=_evidence_note("Fingerprinting-/Trackingmechanismen im Quellcode", inspection.fingerprinting_libraries or inspection.fingerprinting)
            if (inspection.fingerprinting_libraries or inspection.fingerprinting)
            else "Keine Fingerprinting-/Trackingmechanismen im Quellcode gefunden",
        ),
        CheckFinding(
            criterion="RDS-CUC-371",
            status="MANUELL" if inspection.cookies else "PASS",
            note=_evidence_note("Cookie-Schreibzugriffe im Quellcode", inspection.cookies)
            if inspection.cookies
            else "Keine offensichtlichen Cookie-Schreibzugriffe im Quellcode gefunden",
        ),
        CheckFinding(
            criterion="RDS-CUC-372",
            status="MANUELL" if inspection.cookies else "PASS",
            note=_evidence_note("Cookie-Schreibzugriffe im Quellcode", inspection.cookies)
            if inspection.cookies
            else "Keine offensichtlichen Cookie-Schreibzugriffe im Quellcode gefunden",
        ),
        CheckFinding(
            criterion="RDS-CDN-379",
            status="MANUELL" if inspection.external_scripts else "PASS",
            note=_external_scripts_note(inspection.external_scripts),
        ),
    ]
    return findings


def _looks_like_script_asset(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.path.lower().endswith(".js") or "/js" in parsed.path.lower()


def _compact(value: str, max_len: int = 160) -> str:
    compacted = " ".join(value.strip().split())
    if len(compacted) > max_len:
        return compacted[: max_len - 1] + "…"
    return compacted


def _evidence_note(prefix: str, evidence: list[CodeEvidence], limit: int = 5) -> str:
    samples = [f"{item.file}:{item.line} {item.value}" for item in evidence[:limit]]
    suffix = "" if len(evidence) <= limit else f" (+{len(evidence) - limit} weitere)"
    return f"{prefix}: " + "; ".join(samples) + suffix


def _external_scripts_note(evidence: list[CodeEvidence]) -> str:
    if not evidence:
        return "Keine externen Script-URLs im Quellcode gefunden"
    domains = sorted({urlparse(item.value).netloc for item in evidence if urlparse(item.value).netloc})
    domain_note = ", ".join(domains[:10])
    if len(domains) > 10:
        domain_note += f" (+{len(domains) - 10} weitere)"
    return _evidence_note(f"Externe Script-Domains manuell prüfen ({domain_note})", evidence)


def _inspection_to_dict(inspection: CodeInspection) -> dict:
    return {
        "privacy_links": [_evidence_to_dict(item) for item in inspection.privacy_links],
        "impressum_links": [_evidence_to_dict(item) for item in inspection.impressum_links],
        "tracking": [_evidence_to_dict(item) for item in inspection.tracking],
        "storage": [_evidence_to_dict(item) for item in inspection.storage],
        "cookies": [_evidence_to_dict(item) for item in inspection.cookies],
        "external_scripts": [_evidence_to_dict(item) for item in inspection.external_scripts],
        "device_storage": [_evidence_to_dict(item) for item in inspection.device_storage],
        "fingerprinting": [_evidence_to_dict(item) for item in inspection.fingerprinting],
        "fingerprinting_libraries": [
            _evidence_to_dict(item) for item in inspection.fingerprinting_libraries
        ],
    }


def _evidence_to_dict(item: CodeEvidence) -> dict:
    return {"file": item.file, "line": item.line, "value": item.value}
