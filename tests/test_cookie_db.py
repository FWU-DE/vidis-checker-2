from __future__ import annotations

import json
from pathlib import Path

from vidis_compliance.checks.site.cookie_db import CookieDatabase
from vidis_compliance.checks.site.cookies import classify_cookies


def _write_cookie_db(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "Cookiebot": [
                    {
                        "id": "functional-1",
                        "category": "Functional",
                        "cookie": "CookieConsent",
                        "domain": "",
                        "description": "Stores consent state",
                        "retentionPeriod": "1 year",
                        "dataController": "Cookiebot",
                        "privacyLink": "https://example.test/privacy",
                        "wildcardMatch": "0",
                    },
                    {
                        "id": "analytics-1",
                        "category": "Analytics",
                        "cookie": "_ga",
                        "domain": "",
                        "description": "Analytics cookie",
                        "retentionPeriod": "2 years",
                        "dataController": "Google",
                        "privacyLink": "https://example.test/privacy",
                        "wildcardMatch": "1",
                    },
                ],
                "SecurityTool": [
                    {
                        "id": "security-1",
                        "category": "Security",
                        "cookie": "csrf_token",
                        "domain": "",
                        "description": "CSRF protection",
                        "retentionPeriod": "session",
                        "dataController": "Example",
                        "privacyLink": "",
                        "wildcardMatch": "0",
                    }
                ],
                "AdNetwork": [
                    {
                        "id": "marketing-1",
                        "category": "Marketing",
                        "cookie": "IDE",
                        "domain": "doubleclick.net",
                        "description": "Ad targeting",
                        "retentionPeriod": "1 year",
                        "dataController": "Google",
                        "privacyLink": "",
                        "wildcardMatch": "0",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_cookie_database_maps_categories_to_essentiality(tmp_path: Path) -> None:
    db_path = tmp_path / "cookie_db.json"
    _write_cookie_db(db_path)
    database = CookieDatabase(db_path)

    assert database.is_cookie_essential("CookieConsent")[0] is True
    assert database.is_cookie_essential("csrf_token")[0] is True
    assert database.is_cookie_essential("_ga")[0] is False
    assert database.is_cookie_essential("IDE")[0] is False


def test_cookie_database_supports_wildcard_cookie_names(tmp_path: Path) -> None:
    db_path = tmp_path / "cookie_db.json"
    _write_cookie_db(db_path)
    database = CookieDatabase(db_path)

    is_essential, cookie_info = database.is_cookie_essential("_ga_ABC123")

    assert is_essential is False
    assert cookie_info.cookie == "_ga"
    assert cookie_info.category == "Analytics"


def test_classify_cookies_uses_cookie_database_for_non_essential_sus(tmp_path: Path) -> None:
    db_path = tmp_path / "cookie_db.json"
    _write_cookie_db(db_path)
    database = CookieDatabase(db_path)

    status, note = classify_cookies(
        {"cookies": [{"name": "CookieConsent"}, {"name": "_ga_ABC123"}]},
        "sus",
        cookie_database=database,
    )

    assert status == "FAIL"
    assert "RDS-CUC-371/372" in note
    assert "Nicht essenzielle Cookies" in note
    assert "_ga_ABC123" in note
    assert "Analytics" in note
    assert "Essenzielle Cookies" in note
    assert "CookieConsent" in note


def test_classify_cookies_passes_when_database_confirms_all_cookies_essential(tmp_path: Path) -> None:
    db_path = tmp_path / "cookie_db.json"
    _write_cookie_db(db_path)
    database = CookieDatabase(db_path)

    status, note = classify_cookies(
        {"cookies": [{"name": "CookieConsent"}, {"name": "csrf_token"}]},
        "sus",
        cookie_database=database,
    )

    assert status == "PASS"
    assert "Alle erkannten Cookies sind laut cookie_db.json essenziell" in note
    assert "RDS-CUC-371/372" in note


def test_classify_cookies_keeps_manual_status_for_unknown_cookies(tmp_path: Path) -> None:
    db_path = tmp_path / "cookie_db.json"
    _write_cookie_db(db_path)
    database = CookieDatabase(db_path)

    status, note = classify_cookies(
        {"cookies": [{"name": "unknown_cookie"}]},
        "sus",
        cookie_database=database,
    )

    assert status == "MANUELL"
    assert "Unbekannte Cookies" in note
    assert "unknown_cookie" in note
