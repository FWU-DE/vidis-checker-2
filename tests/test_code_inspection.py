from __future__ import annotations

import json
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


def test_cli_check_code_path_outputs_non_placeholder_findings(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "fixture-app"
    _write_frontend_fixture(project)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        ["check", "--code-path", str(project), "--output", "codejob", "--audience", "SuS"],
    )

    assert result.exit_code == 0, result.output
    output_path = tmp_path / "results" / "codejob" / "result.json"
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    by_code = {finding["criterion"]: finding for finding in payload["findings"]}
    assert by_code["RDS-IPF-364"]["status"] == "PASS"
    assert by_code["RDS-IPF-365"]["status"] == "PASS"
    assert by_code["RDS-CUC-373"]["status"] == "FAIL"
    assert by_code["RDS-CUC-373"]["note"] != "Not yet implemented"
    assert by_code["RDS-CUC-374"]["status"] == "FAIL"
    assert by_code["RDS-CDN-379"]["status"] == "MANUELL"
    capture_path = tmp_path / "results" / "codejob" / "code_capture.json"
    assert capture_path.exists()
