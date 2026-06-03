from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from vidis_compliance.cli import app
from vidis_compliance.sources.code.inspect import inspect_code_path


runner = CliRunner()


def _write_frontend_fixture(project: Path) -> None:
    src = project / "src"
    src.mkdir(parents=True)
    (src / "index.html").write_text(
        """
        <!doctype html>
        <html>
          <head>
            <script src="https://www.googletagmanager.com/gtag/js?id=G-123"></script>
            <script src="https://cdn.example-cdn.test/widget.js"></script>
          </head>
          <body>
            <a href="/impressum">Impressum</a>
            <a href="/datenschutz">Datenschutzerklärung</a>
            <script>
              localStorage.setItem('ga:client', 'abc');
              document.cookie = "_ga=abc";
            </script>
          </body>
        </html>
        """,
        encoding="utf-8",
    )


def test_inspect_code_path_maps_frontend_signals_to_vidis_findings(tmp_path: Path) -> None:
    project = tmp_path / "fixture-app"
    _write_frontend_fixture(project)

    findings, capture = inspect_code_path(project, audience="SuS")
    by_code = {finding.criterion: finding for finding in findings}

    assert by_code["RDS-IPF-364"].status == "PASS"
    assert "impressum" in by_code["RDS-IPF-364"].note.lower()
    assert by_code["RDS-IPF-365"].status == "PASS"
    assert "datenschutz" in by_code["RDS-IPF-365"].note.lower()
    assert by_code["RDS-CUC-373"].status == "FAIL"
    assert "googletagmanager.com" in by_code["RDS-CUC-373"].note
    assert by_code["RDS-CUC-374"].status == "FAIL"
    assert "localStorage" in by_code["RDS-CUC-374"].note
    assert by_code["RDS-CDN-379"].status == "MANUELL"
    assert "cdn.example-cdn.test" in by_code["RDS-CDN-379"].note
    assert capture["files_scanned"] == 1
    assert capture["signals"]["tracking"]


def test_inspect_code_path_maps_device_storage_and_fingerprinting_signals(tmp_path: Path) -> None:
    project = tmp_path / "fingerprint-app"
    src = project / "src"
    src.mkdir(parents=True)
    (src / "fingerprint.js").write_text(
        """
        import FingerprintJS from '@fingerprintjs/fingerprintjs';

        const fpPromise = FingerprintJS.load();
        const canvas = document.createElement('canvas');
        canvas.getContext('2d').fillText('vidis', 1, 1);
        canvas.toDataURL();
        new AudioContext().createOscillator();
        navigator.mediaDevices.enumerateDevices();
        navigator.hardwareConcurrency;
        navigator.userAgentData.getHighEntropyValues(['platformVersion']);

        indexedDB.open('vidis-cache');
        caches.open('asset-cache');
        navigator.serviceWorker.register('/sw.js');
        """,
        encoding="utf-8",
    )

    findings, capture = inspect_code_path(project, audience="SuS")
    by_code = {finding.criterion: finding for finding in findings}

    assert by_code["RDS-CUC-375"].status == "MANUELL"
    assert "indexedDB.open" in by_code["RDS-CUC-375"].note
    assert "serviceWorker.register" in by_code["RDS-CUC-375"].note
    assert by_code["RDS-CUC-376"].status == "FAIL"
    assert "FingerprintJS" in by_code["RDS-CUC-376"].note
    assert "canvas.toDataURL" in by_code["RDS-CUC-376"].note
    assert by_code["RDS-CUC-377"].status == "FAIL"
    assert "FingerprintJS" in by_code["RDS-CUC-377"].note
    assert capture["signals"]["device_storage"]
    assert capture["signals"]["fingerprinting"]
    assert capture["signals"]["fingerprinting_libraries"]


def test_rds_cuc_375_fails_for_known_tracker_device_identifier_for_sus(tmp_path: Path) -> None:
    project = tmp_path / "tracker-storage-app"
    src = project / "src"
    src.mkdir(parents=True)
    (src / "main.js").write_text(
        """
        indexedDB.open('fingerprintjs-visitor-profiles');
        caches.open('analytics-beacon-cache');
        """,
        encoding="utf-8",
    )

    findings, capture = inspect_code_path(project, audience="SuS")
    by_code = {finding.criterion: finding for finding in findings}

    finding = by_code["RDS-CUC-375"]
    assert finding.status == "FAIL"
    assert "FingerprintJS" in finding.note or "fingerprint" in finding.note.lower()
    assert "analytics" in finding.note.lower()
    assert "stored value" not in str(capture).lower()


def test_rds_cuc_375_allows_consent_free_technical_storage(tmp_path: Path) -> None:
    project = tmp_path / "offline-security-app"
    src = project / "src"
    src.mkdir(parents=True)
    (src / "main.js").write_text(
        """
        navigator.serviceWorker.register('/sw.js');
        caches.open('offline-app-shell-v1');
        indexedDB.open('csrf-token-store');
        """,
        encoding="utf-8",
    )

    findings, _capture = inspect_code_path(project, audience="SuS")
    by_code = {finding.criterion: finding for finding in findings}

    finding = by_code["RDS-CUC-375"]
    assert finding.status == "PASS"
    assert "technisch" in finding.note.lower()
    assert "offline-app-shell" in finding.note


def test_rds_cuc_375_passes_when_no_device_storage_signal_is_found(tmp_path: Path) -> None:
    project = tmp_path / "plain-app"
    src = project / "src"
    src.mkdir(parents=True)
    (src / "main.js").write_text("console.log('no browser storage APIs here');", encoding="utf-8")

    findings, capture = inspect_code_path(project, audience="SuS")
    by_code = {finding.criterion: finding for finding in findings}

    assert by_code["RDS-CUC-375"].status == "PASS"
    assert "Keine IndexedDB/Cache/Service-Worker-Storage-Nutzung" in by_code["RDS-CUC-375"].note
    assert capture["signals"]["device_storage"] == []


def test_rds_cuc_375_unresolved_generic_api_is_manual_with_full_criterion_text(tmp_path: Path) -> None:
    project = tmp_path / "generic-storage-app"
    src = project / "src"
    src.mkdir(parents=True)
    (src / "main.js").write_text("indexedDB.open('learning-content');", encoding="utf-8")

    findings, _capture = inspect_code_path(project, audience="SuS")
    by_code = {finding.criterion: finding for finding in findings}

    finding = by_code["RDS-CUC-375"]
    assert finding.status == "MANUELL"
    assert "Es werden keine sonstigen Informationen auf der Endeinrichtung" in finding.note
    assert "indexedDB.open" in finding.note
    assert "learning-content" in finding.note
    assert "Zu klären" in finding.note


def test_cli_check_code_path_outputs_provider_code_review_report_section(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "fixture-app"
    _write_frontend_fixture(project)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        [
            "check",
            "--code-path",
            str(project),
            "--output",
            "codejob-report",
            "--audience",
            "SuS",
            "--ai-model",
            "openai:gpt-4.1-mini",
            "--md",
            "results/codejob-report/report.md",
            "--pdf",
            "results/codejob-report/report.pdf",
        ],
    )

    assert result.exit_code == 0, result.output
    result_path = tmp_path / "results" / "codejob-report" / "result.json"
    code_capture_path = tmp_path / "results" / "codejob-report" / "code_capture.json"
    report_md = tmp_path / "results" / "codejob-report" / "report.md"
    report_pdf = tmp_path / "results" / "codejob-report" / "report.pdf"
    assert result_path.exists()
    assert code_capture_path.exists()
    text = report_md.read_text(encoding="utf-8")
    assert "## KI-Modell-Transparenz" in text
    assert "| VIDIS KI-Bewertungen | openai | gpt-4.1-mini | vom CLI übergeben |" in text
    assert "## Code-Durchsicht für Anbieter" in text
    assert "kein Audit" in text
    assert "keine Zertifizierung" in text
    assert "| Gescannte Dateien | 1 |" in text
    assert "googletagmanager.com" in text
    assert report_pdf.stat().st_size > 1000
