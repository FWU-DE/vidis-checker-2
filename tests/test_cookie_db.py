from __future__ import annotations

import json
from pathlib import Path

from vidis_compliance.checks.site.cookie_db import CookieDatabase
from vidis_compliance.checks.site.cookies import (
    classify_cookie_description_completeness,
    classify_cookies,
)


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
    assert "Alle erkannten Cookies/Speicher-Einträge sind laut cookie_db.json/Allowlist essenziell" in note
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



def test_classify_cookies_evaluates_cookies_local_and_session_storage_together(tmp_path: Path) -> None:
    db_path = tmp_path / "cookie_db.json"
    _write_cookie_db(db_path)
    database = CookieDatabase(db_path)

    status, note = classify_cookies(
        {
            "cookies": [{"name": "CookieConsent"}, {"name": "_ga_ABC123"}],
            "local_storage": {"CookieConsentBulkSetting-abc": "1", "matomo.id": "visitor"},
            "session_storage": {"csrf_token": "redacted", "IDE": "ad"},
        },
        "sus",
        cookie_database=database,
    )

    assert status == "FAIL"
    assert "Nicht essenzielle Cookies" in note
    assert "_ga_ABC123" in note
    assert "Nicht essenzieller LocalStorage" in note
    assert "matomo.id" in note
    assert "Nicht essenzieller SessionStorage" in note
    assert "IDE" in note
    assert "Erlaubter LocalStorage" in note
    assert "CookieConsentBulkSetting-abc" in note
    assert "Erlaubter SessionStorage" in note
    assert "csrf_token" in note
    assert "visitor" not in note
    assert "redacted" not in note


def test_classify_cookies_reports_unknown_storage_keys_for_manual_review(tmp_path: Path) -> None:
    db_path = tmp_path / "cookie_db.json"
    _write_cookie_db(db_path)
    database = CookieDatabase(db_path)

    status, note = classify_cookies(
        {"cookies": [], "local_storage": {"unknownLocal": "secret"}, "session_storage": {"unknownSession": "secret"}},
        "sus",
        cookie_database=database,
    )

    assert status == "MANUELL"
    assert "Unbekannter LocalStorage" in note
    assert "unknownLocal" in note
    assert "Unbekannter SessionStorage" in note
    assert "unknownSession" in note
    assert "secret" not in note



def test_rds_cuc_453_passes_when_privacy_text_describes_all_observed_entries(tmp_path: Path) -> None:
    db_path = tmp_path / "cookie_db.json"
    _write_cookie_db(db_path)
    database = CookieDatabase(db_path)

    status, note, evidence = classify_cookie_description_completeness(
        {
            "cookies": [{"name": "CookieConsent"}, {"name": "_ga_ABC123"}],
            "local_storage": {"matomo.id": "visitor"},
            "session_storage": {"csrf_token": "secret"},
        },
        privacy_text=(
            "Datenschutzerklärung Cookies: CookieConsent speichert Ihre Cookie-Einwilligung "
            "für ein Jahr. Google Analytics verwendet _ga_ABC123 zu Statistikzwecken "
            "mit Speicherdauer zwei Jahre. LocalStorage matomo.id dient der Reichweitenmessung. "
            "SessionStorage csrf_token schützt Formulare gegen CSRF-Angriffe."
        ),
        cookie_database=database,
    )

    assert status == "PASS"
    assert "Beschrieben" in note
    assert "CookieConsent" in note
    assert "_ga_ABC123" in note
    assert "matomo.id" in note
    assert "csrf_token" in note
    assert "visitor" not in note
    assert "secret" not in note
    assert evidence["missing"] == []


def test_rds_cuc_453_fails_when_observed_cookie_is_not_described(tmp_path: Path) -> None:
    db_path = tmp_path / "cookie_db.json"
    _write_cookie_db(db_path)
    database = CookieDatabase(db_path)

    status, note, evidence = classify_cookie_description_completeness(
        {"cookies": [{"name": "CookieConsent"}, {"name": "IDE"}]},
        privacy_text="Datenschutzerklärung: CookieConsent speichert Ihre Cookie-Einwilligung für ein Jahr.",
        cookie_database=database,
    )

    assert status == "FAIL"
    assert "Fehlende Beschreibung" in note
    assert "IDE" in note
    assert "CookieConsent" in note
    assert evidence["missing"] == ["Cookie: IDE"]
    assert evidence["present"] == ["Cookie: CookieConsent"]


def test_rds_cuc_453_is_manual_when_privacy_text_is_missing(tmp_path: Path) -> None:
    db_path = tmp_path / "cookie_db.json"
    _write_cookie_db(db_path)
    database = CookieDatabase(db_path)

    status, note, evidence = classify_cookie_description_completeness(
        {"cookies": [{"name": "CookieConsent"}]},
        privacy_text="",
        cookie_database=database,
    )

    assert status == "MANUELL"
    assert "Datenschutzerklärungstext fehlt" in note
    assert evidence["observed"] == ["Cookie: CookieConsent"]


def test_rds_cuc_453_checks_storage_keys_without_storage_values(tmp_path: Path) -> None:
    db_path = tmp_path / "cookie_db.json"
    _write_cookie_db(db_path)
    database = CookieDatabase(db_path)

    status, note, evidence = classify_cookie_description_completeness(
        {"local_storage": {"appTheme": "dark", "matomo.id": "visitor"}},
        privacy_text="Datenschutzerklärung: LocalStorage appTheme speichert die Darstellungseinstellung.",
        cookie_database=database,
    )

    assert status == "FAIL"
    assert "LocalStorage: appTheme" in note
    assert "LocalStorage: matomo.id" in note
    assert "dark" not in note
    assert "visitor" not in note
    assert evidence["present"] == ["LocalStorage: appTheme"]
    assert evidence["missing"] == ["LocalStorage: matomo.id"]
