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
    'ga:', 'ajs:', 'amplitude', 'mixpanel', 'hj-session', 'fb', 'clarity'
]


def _is_sus_audience(audience: str) -> bool:
    return audience.lower() in ('sus', 'schueler', 'schüler', 'schuelerinnen', 'beide')


def classify_cookies(
    data: Dict[str, Any],
    audience: str,
    cookie_database: CookieDatabase | None = None,
) -> Tuple[Status, str]:
    """
    RDS-CUC-371/372:
    - RDS-CUC-371 identifies non-essential cookies via vidis-checker cookie_db.json.
    - RDS-CUC-372 maps Functional/Security categories to essential cookies and
      Analytics/Marketing categories to non-essential cookies.
    - Unknown cookies remain MANUELL because essentiality cannot be asserted.
    """
    cookies: List[Dict[str, Any]] = data.get('cookies', [])
    database = cookie_database or get_default_cookie_database()
    essential_details = []
    non_essential_details = []
    unknown_details = []

    for c in cookies:
        name = str(c.get('name') or '').strip()
        if not name:
            continue

        db_result = database.is_cookie_essential(name)
        if db_result is None:
            fallback_hit = next(
                (prefix for prefix in TRACKER_COOKIE_PREFIXES if name.lower().startswith(prefix.lower())),
                None,
            )
            if fallback_hit is not None:
                non_essential_details.append(f"{name} (Heuristik: Tracker-Präfix {fallback_hit})")
            else:
                unknown_details.append(name)
            continue

        is_essential, cookie_info = db_result
        detail = f"{name} ({cookie_info.platform}, {cookie_info.category})"
        if is_essential:
            essential_details.append(detail)
        else:
            non_essential_details.append(detail)

    note_parts = ["RDS-CUC-371/372 cookie_db.json"]
    if non_essential_details:
        note_parts.append("Nicht essenzielle Cookies: " + ", ".join(sorted(set(non_essential_details))))
    if essential_details:
        note_parts.append("Essenzielle Cookies: " + ", ".join(sorted(set(essential_details))))
    if unknown_details:
        note_parts.append("Unbekannte Cookies: " + ", ".join(sorted(set(unknown_details))))

    note = "; ".join(note_parts)
    if non_essential_details:
        if _is_sus_audience(audience):
            return 'FAIL', note
        return 'MANUELL', "Einwilligung erforderlich? " + note
    if unknown_details:
        return 'MANUELL', note
    if essential_details:
        return 'PASS', "Alle erkannten Cookies sind laut cookie_db.json essenziell; " + note
    return 'MANUELL', 'Keine Cookies zur Bewertung nach RDS-CUC-371/372 erkannt'


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
    - If localStorage/sessionStorage contain known tracker keys → FAIL (SuS), MANUELL otherwise
    - Else MANUELL (cannot decide essentiality)
    """
    ls: Dict[str, str] = data.get('local_storage', {})
    ss: Dict[str, str] = data.get('session_storage', {})
    keys = list(ls.keys()) + list(ss.keys())
    hits = []
    for k in keys:
        for needle in STORAGE_TRACKER_KEYS:
            if needle in k.lower():
                hits.append(k)
                break
    if hits:
        if _is_sus_audience(audience):
            return 'FAIL', f"Tracker-Storage: {', '.join(sorted(set(hits)))}"
        return 'MANUELL', f"Storage erfordert Einwilligung?: {', '.join(sorted(set(hits)))}"
    return 'MANUELL', 'Keine bekannten Tracker-Storage-Schlüssel erkannt'


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


def classify_tracking_mechanisms(data: Dict[str, Any], audience: str) -> Tuple[Status, str]:
    """RDS-CUC-377: known tracker requests remain FAIL for SuS; generic fingerprinting APIs stay MANUELL."""
    tracker_status, tracker_note = classify_tracking_pixel(data, audience)
    if tracker_status == 'FAIL':
        return tracker_status, tracker_note
    fp_hits = _signal_api_names(data, 'fingerprinting')
    if fp_hits:
        return 'MANUELL', f"Potenzielle Tracking-/Fingerprintingmechanismen: {', '.join(fp_hits[:10])}"
    return tracker_status, tracker_note
