from __future__ import annotations
from typing import Dict, Any, List, Tuple

from ...models import Status
from .cookie_db import CookieDatabase, get_default_cookie_database

# Minimal known tracker heuristics
TRACKER_SCRIPT_SNIPPETS = [
    'googletagmanager.com', 'gtag/js', 'google-analytics.com/analytics.js',
    'www.googletagservices.com', 'connect.facebook.net/en_US/fbevents.js',
    'static.hotjar.com', 'cdn.segment.com', 'cdn.mxpnl.com', 'matomo', 'piwik',
    'plausible.io/js', 'clarity.ms', 'tag.aticdn.net', 'script.tapfiliate.com'
]

TRACKER_COOKIE_PREFIXES = [
    '_ga', '_gid', '_gat', '_hj', 'fbp', 'fbc', 'mp_', 'amplitude_', 'ajs_', 'pll_language'
]

STORAGE_TRACKER_KEYS = [
    'ga:', 'ajs:', 'amplitude', 'mixpanel', 'hj-session', 'fb', 'clarity', 'matomo', 'piwik', '_ga'
]

RDS_CUC_377_CRITERION_INFO = (
    "RDS-CUC-377 Trackingmechanismen zu nicht pädagogischen Zwecken: "
    "Es werden keine Trackingmechanismen eingesetzt, wenn sich ein Angebot an Schülerinnen und Schüler richtet, "
    "es sei denn, das Nutzerverhalten wird aus pädagogischen Gründen getrackt, wie z. B. bei adaptiven Lernsystemen notwendig. "
    "Richtet sich das Angebot an Lehrkräfte, wird dafür eine entsprechende Einwilligung eingeholt."
)

RDS_CUC_377_REVIEW_QUESTIONS = (
    "Fehlende Nachweise: Welche Zielgruppe nutzt die geprüfte Oberfläche? "
    "Welche pädagogische Notwendigkeit rechtfertigt diese Signale? "
    "Welche Produkt-/Dokument-Evidenz belegt adaptive Lernfunktionen oder eine Lehrkräfte-Einwilligung?"
)

PEDAGOGICAL_PURPOSE_TERMS = (
    "adaptives lernsystem",
    "adaptive lern",
    "lernstandsdiagnose",
    "lernstand",
    "lernfortschritt",
    "pädagogische anpassung",
    "paedagogische anpassung",
    "pädagogischen gründen",
    "paedagogischen gruenden",
    "didaktisch",
)

ALLOWED_STORAGE_PREFIXES = [
    'cookieconsent',
    'cookiebot',
    'cookie_consent',
    'consent',
    'csrf',
    'xsrf',
    'session',
    'phpsessid',
    'jsessionid',
]


def _is_sus_audience(audience: str) -> bool:
    return audience.lower() in ('sus', 'schueler', 'schüler', 'schuelerinnen', 'beide')


def _storage_key_allowed_by_prefix(key: str) -> bool:
    lowered = key.lower()
    return any(lowered == prefix or lowered.startswith(prefix) for prefix in ALLOWED_STORAGE_PREFIXES)


def _classify_name(name: str, database: CookieDatabase) -> tuple[str, str]:
    """Return (bucket, detail) where bucket is essential/non_essential/unknown."""
    db_result = database.is_cookie_essential(name)
    if db_result is not None:
        is_essential, cookie_info = db_result
        detail = f"{name} ({cookie_info.platform}, {cookie_info.category})"
        return ("essential" if is_essential else "non_essential", detail)

    fallback_hit = next(
        (prefix for prefix in TRACKER_COOKIE_PREFIXES if name.lower().startswith(prefix.lower())),
        None,
    )
    if fallback_hit is not None:
        return "non_essential", f"{name} (Heuristik: Tracker-Präfix {fallback_hit})"
    if _storage_key_allowed_by_prefix(name):
        return "essential", f"{name} (Allowlist-Präfix)"
    if any(needle in name.lower() for needle in STORAGE_TRACKER_KEYS):
        return "non_essential", f"{name} (Heuristik: Tracking-/Analyse-Storage)"
    return "unknown", name


def _append_storage_classification(
    *,
    values: Dict[str, Any],
    label: str,
    database: CookieDatabase,
    essential_details: list[str],
    non_essential_details: list[str],
    unknown_details: list[str],
) -> None:
    for key in sorted({str(k).strip() for k in values.keys() if str(k).strip()}):
        bucket, detail = _classify_name(key, database)
        prefixed = f"{label}: {detail}"
        if bucket == "essential":
            essential_details.append(prefixed)
        elif bucket == "non_essential":
            non_essential_details.append(prefixed)
        else:
            unknown_details.append(prefixed)


def classify_cookies(
    data: Dict[str, Any],
    audience: str,
    cookie_database: CookieDatabase | None = None,
) -> Tuple[Status, str]:
    """
    RDS-CUC-371/372:
    - RDS-CUC-371 identifies non-essential cookies and browser storage.
    - RDS-CUC-372 maps Functional/Security categories and storage allowlist
      prefixes to essential storage; Analytics/Marketing or tracking-like names
      are non-essential.
    - Unknown cookies/storage keys remain MANUELL because essentiality cannot be asserted.
    """
    cookies: List[Dict[str, Any]] = data.get('cookies', [])
    database = cookie_database or get_default_cookie_database()
    essential_details: list[str] = []
    non_essential_details: list[str] = []
    unknown_details: list[str] = []

    for c in cookies:
        name = str(c.get('name') or '').strip()
        if not name:
            continue
        bucket, detail = _classify_name(name, database)
        if bucket == "essential":
            essential_details.append(detail)
        elif bucket == "non_essential":
            non_essential_details.append(detail)
        else:
            unknown_details.append(detail)

    _append_storage_classification(
        values=data.get('local_storage') or {},
        label='LocalStorage',
        database=database,
        essential_details=essential_details,
        non_essential_details=non_essential_details,
        unknown_details=unknown_details,
    )
    _append_storage_classification(
        values=data.get('session_storage') or {},
        label='SessionStorage',
        database=database,
        essential_details=essential_details,
        non_essential_details=non_essential_details,
        unknown_details=unknown_details,
    )

    note_parts = ["RDS-CUC-371/372 cookie_db.json + Storage-Allowlist"]
    non_essential_cookies = [d for d in non_essential_details if not d.startswith(('LocalStorage:', 'SessionStorage:'))]
    non_essential_local = [d.removeprefix('LocalStorage: ') for d in non_essential_details if d.startswith('LocalStorage:')]
    non_essential_session = [d.removeprefix('SessionStorage: ') for d in non_essential_details if d.startswith('SessionStorage:')]
    essential_cookies = [d for d in essential_details if not d.startswith(('LocalStorage:', 'SessionStorage:'))]
    essential_local = [d.removeprefix('LocalStorage: ') for d in essential_details if d.startswith('LocalStorage:')]
    essential_session = [d.removeprefix('SessionStorage: ') for d in essential_details if d.startswith('SessionStorage:')]
    unknown_cookies = [d for d in unknown_details if not d.startswith(('LocalStorage:', 'SessionStorage:'))]
    unknown_local = [d.removeprefix('LocalStorage: ') for d in unknown_details if d.startswith('LocalStorage:')]
    unknown_session = [d.removeprefix('SessionStorage: ') for d in unknown_details if d.startswith('SessionStorage:')]

    if non_essential_cookies:
        note_parts.append("Nicht essenzielle Cookies: " + ", ".join(sorted(set(non_essential_cookies))))
    if non_essential_local:
        note_parts.append("Nicht essenzieller LocalStorage: " + ", ".join(sorted(set(non_essential_local))))
    if non_essential_session:
        note_parts.append("Nicht essenzieller SessionStorage: " + ", ".join(sorted(set(non_essential_session))))
    if essential_cookies:
        note_parts.append("Essenzielle Cookies: " + ", ".join(sorted(set(essential_cookies))))
    if essential_local:
        note_parts.append("Erlaubter LocalStorage: " + ", ".join(sorted(set(essential_local))))
    if essential_session:
        note_parts.append("Erlaubter SessionStorage: " + ", ".join(sorted(set(essential_session))))
    if unknown_cookies:
        note_parts.append("Unbekannte Cookies: " + ", ".join(sorted(set(unknown_cookies))))
    if unknown_local:
        note_parts.append("Unbekannter LocalStorage: " + ", ".join(sorted(set(unknown_local))))
    if unknown_session:
        note_parts.append("Unbekannter SessionStorage: " + ", ".join(sorted(set(unknown_session))))

    note = "; ".join(note_parts)
    if non_essential_details:
        if _is_sus_audience(audience):
            return 'FAIL', note
        return 'MANUELL', "Einwilligung erforderlich? " + note
    if unknown_details:
        return 'MANUELL', note
    if essential_details:
        return 'PASS', "Alle erkannten Cookies/Speicher-Einträge sind laut cookie_db.json/Allowlist essenziell; " + note
    return 'MANUELL', 'Keine Cookies oder Browser-Storage-Einträge zur Bewertung nach RDS-CUC-371/372 erkannt'


def classify_tracking_pixel(data: Dict[str, Any], audience: str) -> Tuple[Status, str]:
    """
    RDS-CUC-373:
    - If network requests or script src match known trackers → FAIL for SuS, MANUELL otherwise
    """
    scripts: List[str] = data.get('scripts', [])
    requests: List[str] = data.get('requests', [])
    hits = []
    for s in scripts:
        if any(snippet in s for snippet in TRACKER_SCRIPT_SNIPPETS):
            hits.append(s)
    for u in requests:
        if any(snippet in u for snippet in TRACKER_SCRIPT_SNIPPETS):
            hits.append(u)
    if hits:
        uniq = sorted(set(hits))[:10]
        if _is_sus_audience(audience):
            return 'FAIL', f"Tracker erkannt: {', '.join(uniq)}"
        return 'MANUELL', f"Tracker erkannt (Einwilligung nötig?): {', '.join(uniq)}"
    return 'PASS', 'Keine offensichtlichen Tracker gefunden'


def classify_local_storage(data: Dict[str, Any], audience: str) -> Tuple[Status, str]:
    """
    RDS-CUC-374:
    - localStorage/sessionStorage entries are evaluated against the same
      cookie database and storage allowlist used by RDS-CUC-371/372.
    """
    database = get_default_cookie_database()
    essential_details: list[str] = []
    non_essential_details: list[str] = []
    unknown_details: list[str] = []
    _append_storage_classification(
        values=data.get('local_storage') or {},
        label='LocalStorage',
        database=database,
        essential_details=essential_details,
        non_essential_details=non_essential_details,
        unknown_details=unknown_details,
    )
    _append_storage_classification(
        values=data.get('session_storage') or {},
        label='SessionStorage',
        database=database,
        essential_details=essential_details,
        non_essential_details=non_essential_details,
        unknown_details=unknown_details,
    )
    if non_essential_details:
        keys = ", ".join(sorted({item.split(': ', 1)[-1] for item in non_essential_details}))
        if _is_sus_audience(audience):
            return 'FAIL', f"Nicht essenzieller Browser-Storage: {keys}"
        return 'MANUELL', f"Browser-Storage erfordert Einwilligung?: {keys}"
    if unknown_details:
        keys = ", ".join(sorted({item.split(': ', 1)[-1] for item in unknown_details}))
        return 'MANUELL', f"Unbekannter Browser-Storage: {keys}"
    if essential_details:
        keys = ", ".join(sorted({item.split(': ', 1)[-1] for item in essential_details}))
        return 'PASS', f"Alle erkannten Browser-Storage-Schlüssel sind laut cookie_db.json/Allowlist essenziell: {keys}"
    return 'MANUELL', 'Keine LocalStorage-/SessionStorage-Schlüssel erkannt'


def _signal_api_names(data: Dict[str, Any], group: str) -> list[str]:
    signals = data.get('browser_signals') or {}
    return sorted({str(item.get('api') or '') for item in signals.get(group, []) if item.get('api')})


def classify_device_storage_access(data: Dict[str, Any], audience: str) -> Tuple[Status, str]:
    """RDS-CUC-375: IndexedDB/Cache/Service-Worker storage access is evidence, not automatically prohibited."""
    hits = _signal_api_names(data, 'device_storage')
    if hits:
        return 'MANUELL', f"Device-/Browser-Storage-APIs genutzt: {', '.join(hits[:10])}"
    return 'PASS', 'Keine IndexedDB/Cache/Service-Worker-Storage-Zugriffe erkannt'


def classify_browser_fingerprinting(data: Dict[str, Any], audience: str) -> Tuple[Status, str]:
    """RDS-CUC-376: generic entropy/fingerprinting API use is manual evidence."""
    hits = _signal_api_names(data, 'fingerprinting')
    if hits:
        return 'MANUELL', f"Browserfingerprinting-/Entropy-APIs genutzt: {', '.join(hits[:10])}"
    return 'PASS', 'Keine Browserfingerprinting-/Entropy-API-Nutzung erkannt'


def _short_signal(value: str, max_len: int = 96) -> str:
    value = " ".join(str(value).strip().split())
    return value if len(value) <= max_len else value[: max_len - 1] + "…"


def _signal_api_summaries_for_377(data: Dict[str, Any], group: str) -> list[str]:
    signals = data.get('browser_signals') or {}
    summaries: list[str] = []
    for item in signals.get(group, []):
        if not isinstance(item, dict):
            continue
        api = str(item.get('api') or '').strip()
        if not api:
            continue
        count = item.get('count')
        summaries.append(f"{api} ({count}×)" if count else api)
    return sorted(set(summaries))


def _non_essential_inventory_for_377(data: Dict[str, Any]) -> list[str]:
    database = get_default_cookie_database()
    hits: list[str] = []
    for cookie in data.get('cookies') or []:
        if not isinstance(cookie, dict):
            continue
        name = str(cookie.get('name') or '').strip()
        if not name:
            continue
        bucket, detail = _classify_name(name, database)
        if bucket == "non_essential":
            hits.append("Cookie: " + detail)
    for label, values in (("LocalStorage", data.get('local_storage') or {}), ("SessionStorage", data.get('session_storage') or {})):
        if not isinstance(values, dict):
            continue
        for key in sorted({str(k).strip() for k in values.keys() if str(k).strip()}):
            bucket, detail = _classify_name(key, database)
            if bucket == "non_essential":
                hits.append(f"{label}: {detail}")
    return sorted(set(hits))


def _known_tracker_hits_for_377(data: Dict[str, Any]) -> list[str]:
    hits: list[str] = []
    values = [str(value) for value in (data.get('scripts') or [])] + [str(value) for value in (data.get('requests') or [])]
    values += [str(resource.get('url') or '') for resource in (data.get('resources') or []) if isinstance(resource, dict)]
    for value in values:
        lowered = value.lower()
        if any(snippet in lowered for snippet in TRACKER_SCRIPT_SNIPPETS):
            hits.append(_short_signal(value))
    return sorted(set(hits))


def _pedagogical_context_snippet_for_377(data: Dict[str, Any]) -> str:
    candidates = [
        data.get("product_context"),
        data.get("tracking_purpose"),
        data.get("pedagogical_purpose"),
    ]
    document_capture = data.get("document_capture") or {}
    if isinstance(document_capture, dict):
        candidates.extend(str(snippet) for snippets in (document_capture.get("evidence") or {}).values() for snippet in (snippets or []))
    for candidate in candidates:
        text = str(candidate or "").strip()
        lowered = text.lower()
        if text and any(term in lowered for term in PEDAGOGICAL_PURPOSE_TERMS):
            return text[:240]
    return ""


def classify_tracking_mechanisms(data: Dict[str, Any], audience: str) -> Tuple[Status, str]:
    """RDS-CUC-377: aggregate tracker evidence and require explicit pedagogical-purpose context."""
    tracker_hits = _known_tracker_hits_for_377(data)
    non_essential_hits = _non_essential_inventory_for_377(data)
    fingerprinting_hits = _signal_api_summaries_for_377(data, 'fingerprinting')
    purpose = _pedagogical_context_snippet_for_377(data)
    tracking_evidence = tracker_hits + non_essential_hits

    if tracking_evidence and purpose:
        return (
            'PASS',
            f"{RDS_CUC_377_CRITERION_INFO}; expliziter pädagogischer Zweck belegt: {purpose}; "
            f"technische Tracking-Signale: {', '.join(tracking_evidence[:10])}",
        )
    if tracking_evidence:
        note = (
            f"{RDS_CUC_377_CRITERION_INFO}; nicht pädagogische Trackingmechanismen ohne belastbare Zweck-Evidenz: "
            + ", ".join(tracking_evidence[:12])
            + "; "
            + RDS_CUC_377_REVIEW_QUESTIONS
        )
        if _is_sus_audience(audience):
            return 'FAIL', note
        return 'MANUELL', note + " Lehrkräfte-Kontext: Einwilligung dokumentiert nachweisen."
    if fingerprinting_hits:
        return (
            'MANUELL',
            f"{RDS_CUC_377_CRITERION_INFO}; potenzielle Tracking-/Fingerprintingmechanismen: "
            + ", ".join(fingerprinting_hits[:10])
            + "; "
            + RDS_CUC_377_REVIEW_QUESTIONS,
        )
    return 'PASS', f"{RDS_CUC_377_CRITERION_INFO}; Keine Trackingmechanismen aus Cookies, Requests, Skripten, Storage oder Fingerprinting-Signalen erkannt"
