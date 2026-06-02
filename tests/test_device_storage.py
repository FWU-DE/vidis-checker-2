from __future__ import annotations

from vidis_compliance.checks.site.device_storage import classify_device_storage_access


def test_rds_cuc_375_site_no_signal_passes() -> None:
    status, note = classify_device_storage_access(
        {"browser_signals": {"device_storage": []}},
        audience="SuS",
    )

    assert status == "PASS"
    assert "Keine IndexedDB/Cache/Service-Worker" in note


def test_rds_cuc_375_site_known_tracker_identifier_fails_for_sus() -> None:
    status, note = classify_device_storage_access(
        {
            "url": "https://example.test/app",
            "browser_signals": {
                "device_storage": [
                    {"api": "indexedDB.open", "count": 1, "name": "fingerprintjs-visitor-profiles"},
                    {"api": "caches.open", "count": 1, "name": "analytics-beacon-cache"},
                ]
            },
        },
        audience="SuS",
    )

    assert status == "FAIL"
    assert "fingerprintjs-visitor-profiles" in note
    assert "analytics-beacon-cache" in note
    assert "Device-Identifier" in note or "Analytics" in note


def test_rds_cuc_375_site_technical_storage_passes() -> None:
    status, note = classify_device_storage_access(
        {
            "browser_signals": {
                "device_storage": [
                    {"api": "serviceWorker.register", "count": 1, "name": "service-worker-app-shell"},
                    {"api": "caches.open", "count": 1, "name": "offline-app-shell-v1"},
                    {"api": "indexedDB.open", "count": 1, "name": "csrf-token-store"},
                ]
            }
        },
        audience="SuS",
    )

    assert status == "PASS"
    assert "technisch erforderliche" in note
    assert "offline-app-shell-v1" in note
    assert "csrf-token-store" in note


def test_rds_cuc_375_site_unresolved_generic_api_is_manual_with_questions_and_url() -> None:
    status, note = classify_device_storage_access(
        {
            "url": "https://example.test/learn",
            "browser_signals": {
                "device_storage": [{"api": "indexedDB.open", "count": 2, "name": "learning-content"}]
            },
        },
        audience="SuS",
    )

    assert status == "MANUELL"
    assert "RDS-CUC-375" in note
    assert "Es werden keine sonstigen Informationen auf der Endeinrichtung" in note
    assert "indexedDB.open (2×)" in note
    assert "learning-content" in note
    assert "https://example.test/learn" in note
    assert "Zu klären" in note
