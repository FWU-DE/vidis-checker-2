from __future__ import annotations
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple
from urllib.parse import urlsplit

from ...models import Status
from .cookie_db import COOKIE_DATABASE_SOURCE_NAME, CookieDatabase, get_default_cookie_database

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
    # Functional keys of common frameworks, no tracking:
    'wpemojisettingssupports',  # WordPress core: which emoji the browser can render
    'htmx-',  # htmx: history cache and current path for back/forward navigation
]


def _is_sus_audience(audience: str) -> bool:
    return audience.lower() in ('sus', 'schueler', 'schüler', 'schuelerinnen', 'beide')


def _storage_key_allowed_by_prefix(key: str) -> bool:
    lowered = key.lower()
    return any(lowered == prefix or lowered.startswith(prefix) for prefix in ALLOWED_STORAGE_PREFIXES)


def classify_name(name: str, database: CookieDatabase | None = None) -> dict[str, str]:
    """Classify one cookie name or storage key.

    Returns ``classification`` (essential/non_essential/unknown), ``basis``
    (cookie_database, tracker_prefix, allowlist, storage_heuristic or none) and,
    for a database match, ``category``, ``platform`` and the matched ``pattern``.
    """
    database = database or get_default_cookie_database()
    db_result = database.is_cookie_essential(name)
    if db_result is not None:
        is_essential, info = db_result
        return {
            "classification": "essential" if is_essential else "non_essential",
            "basis": "cookie_database",
            "category": info.category,
            "platform": info.platform,
            "pattern": info.cookie,
        }
    lowered = name.lower()
    prefix = next((p for p in TRACKER_COOKIE_PREFIXES if lowered.startswith(p.lower())), None)
    if prefix is not None:
        return {"classification": "non_essential", "basis": "tracker_prefix", "pattern": prefix}
    if _storage_key_allowed_by_prefix(name):
        return {"classification": "essential", "basis": "allowlist"}
    needle = next((n for n in STORAGE_TRACKER_KEYS if n in lowered), None)
    if needle is not None:
        return {"classification": "non_essential", "basis": "storage_heuristic", "pattern": needle}
    return {"classification": "unknown", "basis": "none"}


def _classify_name(name: str, database: CookieDatabase) -> tuple[str, str]:
    """Return (bucket, detail) where bucket is essential/non_essential/unknown."""
    result = classify_name(name, database)
    basis = result["basis"]
    if basis == "cookie_database":
        detail = f"{name} ({result['platform']}, {result['category']})"
    elif basis == "tracker_prefix":
        detail = f"{name} (Heuristik: Tracker-Präfix {result['pattern']})"
    elif basis == "allowlist":
        detail = f"{name} (Allowlist-Präfix)"
    elif basis == "storage_heuristic":
        detail = f"{name} (Heuristik: Tracking-/Analyse-Storage)"
    else:
        detail = name
    return result["classification"], detail


def _site_host(url: str) -> str:
    host = (urlsplit(url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def _is_third_party(cookie_domain: str, site: str) -> bool | None:
    domain = cookie_domain.lstrip(".").lower()
    domain = domain[4:] if domain.startswith("www.") else domain
    if not domain or not site:
        return None
    # Same registrable site, roughly: one is a subdomain of the other.
    return not (domain == site or site.endswith("." + domain) or domain.endswith("." + site))


def _expiry(cookie: Dict[str, Any]) -> dict[str, Any]:
    expires = cookie.get("expires")
    try:
        value = float(expires)
    except (TypeError, ValueError):
        return {}
    if value <= 0:
        return {"session": True}
    return {
        "session": False,
        "expires": datetime.fromtimestamp(value, tz=timezone.utc).isoformat(timespec="seconds"),
    }


def cookie_inventory(data: Dict[str, Any], cookie_database: CookieDatabase | None = None) -> dict[str, Any]:
    """Every observed cookie and storage key with its classification, never with values.

    This is the machine-readable form of what ``classify_cookies`` and
    ``classify_local_storage`` decide on.
    """
    database = cookie_database or get_default_cookie_database()
    site = _site_host(str(data.get("url") or ""))
    cookies: list[dict[str, Any]] = []
    for cookie in data.get("cookies") or []:
        if not isinstance(cookie, dict):
            continue
        name = str(cookie.get("name") or "").strip()
        if not name:
            continue
        domain = str(cookie.get("domain") or "")
        item: dict[str, Any] = {"name": name, "domain": domain, "path": cookie.get("path")}
        item.update(classify_name(name, database))
        item["third_party"] = _is_third_party(domain, site)
        item.update(_expiry(cookie))
        for source, target in (("secure", "secure"), ("httpOnly", "http_only"), ("sameSite", "same_site"),
                               ("first_seen_url", "first_seen_url"), ("before_consent_click", "before_consent_click")):
            if source in cookie:
                item[target] = cookie[source]
        cookies.append({key: value for key, value in item.items() if value is not None})
    cookies.sort(key=lambda c: (c["name"].lower(), c.get("domain", "")))

    def storage(values: Any) -> list[dict[str, Any]]:
        if not isinstance(values, dict):
            return []
        keys = sorted({str(k).strip() for k in values.keys() if str(k).strip()}, key=str.lower)
        return [{"key": key, **classify_name(key, database)} for key in keys]

    local, session = storage(data.get("local_storage")), storage(data.get("session_storage"))
    counts = {"essential": 0, "non_essential": 0, "unknown": 0}
    for item in cookies + local + session:
        counts[item["classification"]] += 1
    return {"cookies": cookies, "local_storage": local, "session_storage": session, "counts": counts}


def tracker_hits(data: Dict[str, Any]) -> list[dict[str, str]]:
    """Script, request and resource URLs matching a known tracker, with the matched pattern."""
    hits: dict[str, dict[str, str]] = {}
    sources = [("script", v) for v in data.get("scripts") or []] + [("request", v) for v in data.get("requests") or []]
    sources += [("resource", r.get("url")) for r in data.get("resources") or [] if isinstance(r, dict)]
    for kind, value in sources:
        url = str(value or "")
        lowered = url.lower()
        match = next((snippet for snippet in TRACKER_SCRIPT_SNIPPETS if snippet.lower() in lowered), None)
        if match and url not in hits:
            hits[url] = {"url": url, "host": (urlsplit(url).hostname or "").lower(), "kind": kind, "pattern": match}
    return sorted(hits.values(), key=lambda h: h["url"])


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

    note_parts = [f"RDS-CUC-371/372 {COOKIE_DATABASE_SOURCE_NAME} + Storage-Allowlist"]
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
        return 'PASS', f"Alle erkannten Cookies/Speicher-Einträge sind laut {COOKIE_DATABASE_SOURCE_NAME}/Allowlist essenziell; " + note
    return 'MANUELL', 'Keine Cookies oder Browser-Storage-Einträge zur Bewertung nach RDS-CUC-371/372 erkannt'


def _observed_cookie_storage_inventory(data: Dict[str, Any]) -> list[tuple[str, str]]:
    inventory: list[tuple[str, str]] = []
    for cookie in data.get('cookies') or []:
        name = str(cookie.get('name') or '').strip()
        if name:
            inventory.append(('Cookie', name))
    for label, key in (('LocalStorage', 'local_storage'), ('SessionStorage', 'session_storage')):
        values = data.get(key) or {}
        for storage_key in sorted({str(k).strip() for k in values.keys() if str(k).strip()}):
            inventory.append((label, storage_key))
    return sorted(set(inventory), key=lambda item: (item[0], item[1].lower()))


def _inventory_label(kind: str, name: str) -> str:
    return f"{kind}: {name}"


def _normalize_for_match(text: str) -> str:
    return re.sub(r"[^a-z0-9äöüß]+", "", text.lower())


def _privacy_text_mentions(name: str, privacy_text: str, database: CookieDatabase) -> bool:
    normalized_name = _normalize_for_match(name)
    normalized_text = _normalize_for_match(privacy_text)
    if normalized_name and normalized_name in normalized_text:
        return True
    cookie_info = database.get_cookie_info(name)
    if cookie_info is None:
        return False
    candidates = [
        cookie_info.cookie,
        cookie_info.platform,
        cookie_info.category,
        cookie_info.description,
        cookie_info.retention_period,
    ]
    return any(
        _normalize_for_match(candidate) and _normalize_for_match(candidate) in normalized_text
        for candidate in candidates
    )


def classify_cookie_description_completeness(
    data: Dict[str, Any],
    *,
    privacy_text: str | None,
    cookie_database: CookieDatabase | None = None,
) -> tuple[Status, str, dict[str, list[str]]]:
    """RDS-CUC-453: privacy text describes every observed cookie/storage key without exposing values."""
    database = cookie_database or get_default_cookie_database()
    inventory = _observed_cookie_storage_inventory(data)
    observed = [_inventory_label(kind, name) for kind, name in inventory]
    evidence = {"observed": observed, "present": [], "missing": []}
    if not inventory:
        return "MANUELL", "Keine Cookies oder Browser-Storage-Einträge für RDS-CUC-453 erkannt", evidence
    if not (privacy_text or "").strip():
        return (
            "MANUELL",
            "Datenschutzerklärungstext fehlt; Cookie-/Storage-Beschreibungen können nicht abgeglichen werden: "
            + ", ".join(observed),
            evidence,
        )

    for kind, name in inventory:
        label = _inventory_label(kind, name)
        if _privacy_text_mentions(name, privacy_text or "", database):
            evidence["present"].append(label)
        else:
            evidence["missing"].append(label)

    present = ", ".join(evidence["present"]) or "—"
    missing = ", ".join(evidence["missing"])
    if evidence["missing"]:
        return "FAIL", f"Fehlende Beschreibung: {missing}; Beschrieben: {present}", evidence
    return "PASS", f"Beschrieben: {present}", evidence


def classify_tracking_pixel(data: Dict[str, Any], audience: str) -> Tuple[Status, str]:
    """
    RDS-CUC-373:
    - If network requests or script src match known trackers → FAIL for SuS, MANUELL otherwise
    """
    hits = [hit["url"] for hit in tracker_hits(data) if hit["kind"] in {"script", "request"}]
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
        return 'PASS', f"Alle erkannten Browser-Storage-Schlüssel sind laut {COOKIE_DATABASE_SOURCE_NAME}/Allowlist essenziell: {keys}"
    return 'PASS', 'Keine LocalStorage-/SessionStorage-Schlüssel erkannt'


def _signal_api_names(data: Dict[str, Any], group: str) -> list[str]:
    signals = data.get('browser_signals') or {}
    return sorted({str(item.get('api') or '') for item in signals.get(group, []) if item.get('api')})


def classify_device_storage_access(data: Dict[str, Any], audience: str) -> Tuple[Status, str]:
    from .device_storage import classify_device_storage_access as _classify_device_storage_access

    return _classify_device_storage_access(data, audience)


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
    return sorted({_short_signal(hit["url"]) for hit in tracker_hits(data)})


def pedagogical_purpose_snippet(data: Dict[str, Any]) -> str:
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
    purpose = pedagogical_purpose_snippet(data)
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
