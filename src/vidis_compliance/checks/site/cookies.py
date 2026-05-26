from __future__ import annotations
from typing import Dict, Any, List, Tuple

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
) -> Tuple[str, str]:
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


def classify_tracking_pixel(data: Dict[str, Any], audience: str) -> Tuple[str, str]:
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


def classify_local_storage(data: Dict[str, Any], audience: str) -> Tuple[str, str]:
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
